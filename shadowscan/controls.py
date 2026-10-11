"""Control evidence: what one or more scan reports hold for each control.

``shadowscan controls`` reads JSON reports (several are merged as ``shadowscan
merge`` merges them) and, for every entry of the selected control catalogs
(NIST AI RMF, ISO/IEC 42001, EU AI Act and AIUC-1 by default), counts the
findings whose control references name it, split by risk level, with the
highest-risk findings as examples. Each control also says how complete the
evidence behind it is: a control no finding references reads "not observed"
only when every report is complete and no finding could reference it through a
fact the reports do not hold (shadow status without an inventory, a risk class
no card declares), and "unknown" otherwise.

The references are the author mappings of :mod:`shadowscan.mappings`, derived
from the findings again with the packaged catalogs. They are evidence
references, not compliance determinations: nothing here says a control is met
or applies, and there is no score.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from shadowscan import __version__
from shadowscan.comparison import _complete, _summary_matches_findings
from shadowscan.fleet import merge_reports
from shadowscan.governance import DECLARED_GOVERNANCE_KEY, GOVERNANCE_FIELDS, valid_declared_governance
from shadowscan.mappings import MappingIndex, load_mappings
from shadowscan.mappings.schema import (
    CONTROL_KINDS,
    REVIEW_STATEMENTS,
    Catalog,
    Condition,
    FindingFacts,
    Rule,
)
from shadowscan.models import Finding, ScanResult
from shadowscan.reporters._publication import publication_stats
from shadowscan.utils.redaction import sanitize

SCHEMA = "shadowscan.control-evidence/v1"
NOTICE = "Evidence references, not compliance determinations."
MAX_EXAMPLES = 10
RISK_LEVELS = ("critical", "high", "medium", "low", "info")

# What the evidence says about one control.
REFERENCED = "referenced"
REFERENCED_INCOMPLETE = "referenced (scan incomplete)"
NOT_OBSERVED = "not observed"
UNKNOWN_INCOMPLETE = "unknown (scan incomplete)"
UNKNOWN_NO_INVENTORY = "unknown (inventory not supplied)"
UNKNOWN_NOT_DECLARED = "unknown (risk class not declared)"
NOT_MAPPED = "not mapped"
EVIDENCE_STATUSES = (
    REFERENCED,
    REFERENCED_INCOMPLETE,
    NOT_OBSERVED,
    UNKNOWN_INCOMPLETE,
    UNKNOWN_NO_INVENTORY,
    UNKNOWN_NOT_DECLARED,
    NOT_MAPPED,
)

# A scan-level fact that is itself evidence for these controls, not through a finding:
# whether a sanctioned inventory was supplied (inventory mechanisms and resource documentation).
INVENTORY_REFS = ("nist-ai-rmf-1.0:GOVERN-1.6", "iso-iec-42001-2023:A.4.2")


class ControlSelectionError(ValueError):
    """``--framework`` named no packaged control catalog."""


def control_catalogs(frameworks: Sequence[str] = (), index: MappingIndex | None = None) -> list[Catalog]:
    """The control catalogs to report on: all of them, or those named by prefix or framework id.

    ``eu-ai-act-2024`` names one edition and ``eu-ai-act`` every packaged edition. A
    name that matches no control catalog raises :class:`ControlSelectionError`.
    """
    index = index if index is not None else load_mappings()
    available = sorted((c for c in index.catalogs if c.kind in CONTROL_KINDS), key=lambda c: c.prefix)
    wanted = set(frameworks)
    if not wanted:
        return available
    names = {name for catalog in available for name in (catalog.prefix, catalog.framework)}
    if not wanted <= names:
        # The operator's value is not echoed back; the valid names are.
        raise ControlSelectionError(
            "--framework must name a control catalog: "
            + ", ".join(f"{c.prefix} ({c.framework})" for c in available)
        )
    return [c for c in available if c.prefix in wanted or c.framework in wanted]


def check_sources(reports: Sequence[tuple[str, Mapping[str, Any]]]) -> None:
    """Refuse a report that ``shadowscan merge`` produced; raises ``ValueError``.

    A merged report records a finding seen without an inventory as shadow and no
    longer says which source had an inventory, so its shadow and inventory evidence
    cannot be told apart from a real reconciliation.
    """
    for name, report in reports:
        scope = report.get("collection_scope") if isinstance(report, Mapping) else None
        if isinstance(scope, Mapping) and "fleet" in scope:
            raise ValueError(f"{name}: an already merged report; pass the source reports instead")


def _source_has_inventory(report: Mapping[str, Any]) -> bool:
    """Whether a source report was reconciled with an inventory.

    The report's own ``inventory_present`` and ``inventory_size`` decide; shadow
    values count only in a report from before ``inventory_present`` existed.
    """
    size = report.get("inventory_size")
    present = report.get("inventory_present")
    if isinstance(present, bool):
        return present or (type(size) is int and size > 0)
    return (type(size) is int and size > 0) or any(
        isinstance(record.get("shadow"), bool) for record in report["findings"]
    )


def _merged_shadow(reports: Sequence[tuple[str, Mapping[str, Any]]]) -> dict[str, bool | None]:
    """Each finding's shadow status across its sources.

    Shadow when a source reconciled with an inventory says so, registered when every
    source says so, and unknown otherwise: a source without an inventory knows nothing
    about registration and must not make a finding look shadow or registered.
    """
    votes: dict[str, list[Any]] = {}
    for _, report in reports:
        inventoried = _source_has_inventory(report)
        for record in report["findings"]:
            votes.setdefault(record["id"], []).append(record.get("shadow") if inventoried else None)
    merged: dict[str, bool | None] = {}
    for finding_id, values in votes.items():
        if any(value is True for value in values):
            merged[finding_id] = True
        elif all(value is False for value in values):
            merged[finding_id] = False
        else:
            merged[finding_id] = None
    return merged


def _undetermined(condition: Condition, facts: FindingFacts) -> str | None:
    """Why ``condition`` is undetermined for a finding it does not match, or None when it is false.

    It is undetermined when a fact it reads is unknown and some value of that fact
    would make it match: the shadow status of a finding no inventory reconciled, or
    the risk class of a finding no card declares one for (``unknown`` included).
    """
    shadow, declared = facts.shadow, facts.declared_risk_class
    if condition.shadow is not None and shadow is None:
        shadow = condition.shadow
    if condition.declared_risk_class_any is not None and declared in (None, "unknown"):
        declared = min(condition.declared_risk_class_any)
    if (shadow, declared) == (facts.shadow, facts.declared_risk_class):
        return None
    if not condition.matches(replace(facts, shadow=shadow, declared_risk_class=declared)):
        return None
    # Without an inventory a finding has neither a shadow status nor declared facts.
    return UNKNOWN_NO_INVENTORY if facts.shadow is None else UNKNOWN_NOT_DECLARED


def _status(count: int, rules: Sequence[Rule], complete: bool, undetermined: set[str]) -> str:
    if count:
        return REFERENCED if complete else REFERENCED_INCOMPLETE
    if not rules:
        return NOT_MAPPED
    if not complete:
        return UNKNOWN_INCOMPLETE
    for status in (UNKNOWN_NO_INVENTORY, UNKNOWN_NOT_DECLARED):
        if status in undetermined:
            return status
    return NOT_OBSERVED


def _inventory_fact(sources: Sequence[Mapping[str, Any]], size: int) -> tuple[str, str]:
    """``(value, statement)`` for whether a sanctioned inventory was supplied."""
    supplied = sum(1 for source in sources if source["inventory"])
    if supplied and supplied == len(sources):
        if len(sources) == 1:
            return "supplied", f"Sanctioned inventory supplied ({size} registered agents)."
        return "supplied", f"Sanctioned inventory supplied for every report (largest: {size} agents)."
    if supplied:
        return (
            "partial",
            f"Sanctioned inventory supplied for {supplied} of {len(sources)} reports; findings seen only"
            " in the others have unknown shadow status.",
        )
    return "not supplied", "No sanctioned inventory supplied; shadow status is unknown."


def _example(finding: Finding, basis: str) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "risk_level": finding.risk.level.value,
        "risk_score": finding.risk.score,
        "basis": basis,
    }


def build_control_evidence(
    result: ScanResult,
    reports: Sequence[tuple[str, Mapping[str, Any]]],
    *,
    catalogs: Sequence[Catalog] | None = None,
    index: MappingIndex | None = None,
) -> dict[str, Any]:
    """The ``shadowscan.control-evidence/v1`` document for ``result``, merged from ``reports``.

    ``result`` is :func:`shadowscan.fleet.merge_reports` of ``reports`` (a single report
    too), which supplies the merged findings and connector statistics; the raw reports
    supply per-source completeness and inventory status. Findings' shadow status is
    recomputed from the sources (see :func:`_merged_shadow`). A merged report is
    refused (see :func:`check_sources`). Sanitizer limit errors propagate, so an
    unpublishable document fails instead of being partly checked.
    """
    check_sources(reports)
    index = index if index is not None else load_mappings()
    catalogs = list(catalogs) if catalogs is not None else control_catalogs(index=index)
    shadow = _merged_shadow(reports)
    for finding in result.findings:
        finding.shadow = shadow.get(finding.id, finding.shadow)
    sources = [
        {
            "name": name,
            "complete": _complete(dict(report)) and _summary_matches_findings(dict(report)),
            "inventory": _source_has_inventory(report),
        }
        for name, report in reports
    ]
    complete = result.complete and all(source["complete"] for source in sources)
    inventory_value, inventory_statement = _inventory_fact(sources, result.inventory_size)

    control_rules = [rule for rule in index.rules if rule.kind in CONTROL_KINDS]
    # ref -> finding id -> how the finding references the control (observed evidence or declared facts).
    bases: dict[str, dict[str, set[str]]] = {}
    # ref -> why a finding that does not reference the control might (see _undetermined).
    undetermined: dict[str, set[str]] = {}
    by_id: dict[str, Finding] = {}
    for finding in result.findings:
        by_id[finding.id] = finding
        state = FindingFacts.of(finding)
        for rule in control_rules:
            if rule.when.matches(state):
                basis = "declared" if rule.when.declared_risk_class_any is not None else "observed"
                for ref in rule.refs:
                    bases.setdefault(ref, {}).setdefault(finding.id, set()).add(basis)
            elif (reason := _undetermined(rule.when, state)) is not None:
                for ref in rule.refs:
                    undetermined.setdefault(ref, set()).add(reason)
    rules_by_ref: dict[str, list[Rule]] = {}
    for rule in control_rules:
        for ref in rule.refs:
            rules_by_ref.setdefault(ref, []).append(rule)

    selected_refs = {entry.ref for catalog in catalogs for entry in catalog.entries}
    frameworks = []
    for catalog in catalogs:
        controls = []
        for entry in catalog.entries:
            hits = [
                (by_id[finding_id], "observed" if "observed" in kinds else "declared")
                for finding_id, kinds in bases.get(entry.ref, {}).items()
            ]
            hits.sort(key=lambda hit: (-hit[0].risk.score, -hit[0].risk.danger_score, hit[0].id))
            by_level = dict.fromkeys(RISK_LEVELS, 0)
            for finding, _ in hits:
                by_level[finding.risk.level.value] = by_level.get(finding.risk.level.value, 0) + 1
            rules = rules_by_ref.get(entry.ref, [])
            controls.append(
                {
                    "ref": entry.ref,
                    "control_id": entry.id,
                    "title": entry.title,
                    "evidence": _status(len(hits), rules, complete, undetermined.get(entry.ref, set())),
                    "findings": len(hits),
                    "declared_findings": sum(1 for _, basis in hits if basis == "declared"),
                    "by_risk_level": by_level,
                    "examples": [_example(finding, basis) for finding, basis in hits[:MAX_EXAMPLES]],
                    "rules": [rule.id for rule in rules],
                    "scan_evidence": [inventory_statement] if entry.ref in INVENTORY_REFS else [],
                }
            )
        frameworks.append(
            {
                "prefix": catalog.prefix,
                "framework": catalog.framework,
                "name": catalog.name,
                "edition": catalog.edition,
                "verification": catalog.verification,
                "review": catalog.review,
                "review_statement": REVIEW_STATEMENTS[catalog.review],
                "source_url": catalog.source_url,
                "controls": controls,
            }
        )

    declared = []
    for finding in result.findings:
        block = finding.metadata.get(DECLARED_GOVERNANCE_KEY)
        if finding.shadow is False and isinstance(block, dict) and valid_declared_governance(block):
            facts = {key: block[key] for key in GOVERNANCE_FIELDS if key in block}
            declared.append(
                {"finding": finding.id, "title": finding.title, "source": block["source"], **facts}
            )
    declared.sort(key=lambda item: (item["source"], item["finding"]))

    reviews = sorted({catalog.review for catalog in catalogs})
    unfinished = sorted(
        {
            stat["connector"]
            for stat in publication_stats(result)
            if stat["errors"] or stat["skipped"] or stat["incomplete"]
        }
    )
    # Each record is sanitized on its own: a large fleet's document as a whole can exceed the
    # sanitizer's node bound, which would fail publication although every record is publishable.
    return {
        "schema": SCHEMA,
        "notice": " ".join([NOTICE, *(REVIEW_STATEMENTS[review] for review in reviews)]),
        "generator": {"name": "ShadowScan", "version": __version__},
        # The reports' own time, never the time of this run: the same reports give the same document.
        "report_finished_at": sanitize(result.finished_at),
        "evidence_scope": {
            "status": "complete" if complete else "incomplete",
            "complete": complete,
            "reports": [sanitize(source) for source in sources],
            "incomplete_connectors": unfinished,
            "inventory": inventory_value,
            "inventory_size": result.inventory_size,
            "findings": len(result.findings),
        },
        "scan_evidence": [
            {
                "fact": "inventory",
                "value": inventory_value,
                "statement": inventory_statement,
                "refs": [ref for ref in INVENTORY_REFS if ref in selected_refs],
            }
        ],
        "frameworks": [sanitize(framework) for framework in frameworks],
        "declared_governance": [sanitize(item) for item in declared],
    }


def control_evidence(
    reports: Sequence[tuple[str, dict[str, Any]]], *, frameworks: Sequence[str] = ()
) -> dict[str, Any]:
    """Merge ``(name, report)`` pairs and build their control evidence; raises ``ValueError`` on bad input."""
    catalogs = control_catalogs(frameworks)
    check_sources(reports)
    return build_control_evidence(merge_reports(list(reports)), reports, catalogs=catalogs)
