"""The fleet inventory behind ``shadowscan dashboard`` and its ``shadowscan.inventory/v1`` export.

:func:`build_inventory` turns a scan or fleet :class:`~shadowscan.models.ScanResult` into one
JSON document: coverage per source and connector first, then counts, autonomy tier against
shadow status, vendor registry reconciliation, threat and control reference counts, drift
against a baseline, history and one record per AI system. The dashboard page
(:mod:`shadowscan.reporters.dashboard`) renders exactly this document, and
``--inventory-json`` writes it for BI and SIEM tools.

Missing data stays visible. A connector a source did not run is ``not-collected``, a source
from an older fleet report has ``unknown`` coverage, a report without an inventory is
``no-inventory``, and a finding of a kind the autonomy scale describes but without an interval
is ``not-classified`` (unknown), never a zero or a clean state. Coverage cells are stored only
for the connectors a source ran, so the document grows with its input, not with sources times
connectors. Nothing in the document is a compliance determination: threat and control
references are evidence references.

Credential findings (``secret`` and ``token``) are counted and left out. Records carry no
evidence snippets, evidence attributes, permissions or raw metadata. Every finding passes its
own sanitizer first, so each record is a projection of an already sanitized finding; sources,
diagnostics and history come from report files and are sanitized here.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.autonomy import LEVELS, applicable, valid_autonomy
from shadowscan.comparison import (
    _complete,
    _summary_matches_findings,
    compare_reports,
    drift_counts,
    load_report_with_digest,
)
from shadowscan.fleet import (
    CONNECTOR_STATUSES,
    MAX_SOURCES,
    connector_status,
    legacy_fleet,
    shows_inventory,
)
from shadowscan.mappings import describe, finding_references
from shadowscan.models import Finding, Kind, RiskLevel, ScanResult
from shadowscan.registries import RECONCILIATION_KEY, RECONCILIATION_STATUSES, RECORD_KEY, registry_record
from shadowscan.reporters._publication import has_inventory
from shadowscan.utils.files import require_no_symlinks
from shadowscan.utils.redaction import sanitize, sanitize_text

INVENTORY_SCHEMA = "shadowscan.inventory/v1"
NOT_COLLECTED = "not-collected"
UNKNOWN = "unknown"
INVENTORY_STATUSES = ("shadow", "sanctioned", "no-inventory")
# An AI system's autonomy: an interval, a kind the scale describes but no interval (unknown), or a
# kind the scale does not describe.
AUTONOMY_STATUSES = ("classified", "not-classified", "not-applicable")
# Autonomy floor from which an unregistered system is the priority quadrant.
PRIORITY_FLOOR = 4
# Two years of weekly reports; more are counted and left out, never silently.
MAX_HISTORY = 104
MAX_HISTORY_FILES = 1_000
MAX_DIAGNOSTICS = 500
MAX_DIAGNOSTIC_MESSAGES = 20
REFERENCE_NOTE = "Evidence references, not compliance determinations."
_EXCLUDED_KINDS = frozenset({Kind.SECRET, Kind.TOKEN})
_EXCLUDED_KIND_VALUES = frozenset(kind.value for kind in _EXCLUDED_KINDS)
_LEVEL_VALUES = frozenset(level.value for level in RiskLevel)
# A cell shows the least complete of a source's runs of one connector.
_STATUS_RANK = {"complete": 0, "cached": 1, "skipped": 2, "incomplete": 3}
# Scan-level records (``engine.fleet`` and the like) are not connectors, as for ``diff`` coverage: they
# still make a source incomplete and appear in diagnostics, but are not coverage columns.
_ENGINE_PREFIX = "engine."
# Sources sanitized together: well inside the sanitizer's node bound.
_SANITIZE_CHUNK = 200


class HistoryError(ValueError):
    """The history directory cannot be used; the message is fixed text, safe to print."""


@dataclass(frozen=True, slots=True)
class _HistoryEntry:
    point: dict[str, Any]
    instant: datetime | None
    path: Path


def parse_instant(value: Any) -> datetime | None:
    """A timezone-aware time from an ISO 8601 string; None when missing, invalid or without an offset."""
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.utcoffset() is not None else None


def inventory_status(shadow: bool | None) -> str:
    """``shadow``, ``sanctioned`` or ``no-inventory`` for a finding's three-valued ``shadow``."""
    if shadow is None:
        return "no-inventory"
    return "shadow" if shadow else "sanctioned"


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _source_connectors(value: Any) -> list[dict[str, str]] | None:
    """A fleet source's connector runs; None for a source from a fleet report that predates them."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("fleet source connectors must be an array")
    runs = []
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("connector"), str)
            or not item["connector"].strip()
            or item.get("status") not in CONNECTOR_STATUSES
        ):
            raise ValueError("fleet source connector entries are malformed")
        runs.append({"connector": item["connector"], "status": item["status"]})
    return runs


def _fleet_sources(scope: Any) -> list[dict[str, Any]] | None:
    """The sources a fleet report lists, validated; None when the report is not a fleet merge."""
    fleet = scope.get("fleet") if isinstance(scope, dict) else None
    if fleet is None:
        return None
    entries = fleet.get("sources") if isinstance(fleet, dict) else None
    if not isinstance(entries, list) or not entries or len(entries) > MAX_SOURCES:
        raise ValueError("fleet report sources are malformed")
    sources = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or type(entry.get("complete")) is not bool
        ):
            raise ValueError("fleet report sources are malformed")
        findings = entry.get("findings")
        if findings is not None and (type(findings) is not int or findings < 0):
            raise ValueError("fleet report sources are malformed")
        present = entry.get("inventory_present")
        sources.append(
            {
                "name": entry["name"],
                "version": _text(entry.get("version")),
                "complete": entry["complete"],
                "findings": findings,
                "started_at": _text(entry.get("started_at")),
                "finished_at": _text(entry.get("finished_at")),
                "inventory_present": present if type(present) is bool else None,
                "connectors": _source_connectors(entry.get("connectors")),
            }
        )
    return sources


def _single_source(result: ScanResult, name: str) -> dict[str, Any]:
    return {
        "name": name,
        "version": result.version or None,
        "complete": result.complete,
        "findings": len(result.findings),
        "started_at": result.started_at or None,
        "finished_at": result.finished_at,
        "inventory_present": has_inventory(result),
        "connectors": [{"connector": st.connector, "status": connector_status(st)} for st in result.stats],
    }


def _sanitized(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitize report-supplied entries in bounded chunks; limit errors propagate (fail closed)."""
    out: list[dict[str, Any]] = []
    for start in range(0, len(items), _SANITIZE_CHUNK):
        out.extend(sanitize(items[start : start + _SANITIZE_CHUNK]))
    return out


def _last_scanned(source: dict[str, Any]) -> datetime | None:
    return parse_instant(source.get("finished_at")) or parse_instant(source.get("started_at"))


def coverage_cell(source: dict[str, Any], connector: str) -> str:
    """A source's status for one of ``coverage.connectors``; without a cell, not collected or unknown."""
    cell = source["coverage"].get(connector)
    if cell is not None:
        return str(cell)
    return UNKNOWN if source["connectors"] is None else NOT_COLLECTED


def _coverage(sources: list[dict[str, Any]], reference: datetime | None) -> dict[str, Any]:
    """Add each source's coverage cells and staleness; return the coverage summary.

    Only the connectors a source ran get a cell, so the cells grow with the runs listed rather
    than with sources times connector names; :func:`coverage_cell` reads the others.
    """
    names: set[str] = set()
    for source in sources:
        cells: dict[str, str] = {}
        for run in source["connectors"] or []:
            name = run["connector"]
            if name.startswith(_ENGINE_PREFIX):
                continue
            current = cells.get(name)
            if current is None or _STATUS_RANK[run["status"]] > _STATUS_RANK[current]:
                cells[name] = run["status"]
        names.update(cells)
        source["coverage"] = cells
        moment = _last_scanned(source)
        source["staleness_days"] = (
            (reference - moment) // timedelta(days=1)
            if reference is not None and moment is not None
            else None
        )
    return {
        "connectors": sorted(names),
        "sources": len(sources),
        "complete_sources": sum(1 for source in sources if source["complete"]),
        "incomplete_sources": sum(1 for source in sources if not source["complete"]),
        "unknown_coverage_sources": sum(1 for source in sources if source["connectors"] is None),
    }


def _diagnostics(result: ScanResult) -> tuple[list[dict[str, Any]], int]:
    """Connector runs that did not complete cleanly, sanitized one by one; and how many were left out."""
    problems = [
        st for st in result.stats if st.errors or st.warnings or st.skip_reason or st.skipped or st.incomplete
    ]
    entries = [
        sanitize(
            {
                "connector": st.connector,
                "status": connector_status(st),
                "errors": list(st.errors[:MAX_DIAGNOSTIC_MESSAGES]),
                "errors_total": len(st.errors),
                "warnings": list(st.warnings[:MAX_DIAGNOSTIC_MESSAGES]),
                "warnings_total": len(st.warnings),
                "skip_reason": st.skip_reason,
            }
        )
        for st in problems[:MAX_DIAGNOSTICS]
    ]
    return entries, max(0, len(problems) - MAX_DIAGNOSTICS)


def _registry(finding: Finding) -> dict[str, Any] | None:
    if RECORD_KEY not in finding.metadata:
        return None
    record = registry_record(finding)
    if record is None:
        return {"malformed": True}
    return {
        "registry": record.registry,
        "registry_id": record.registry_id,
        "record_id": record.record_id,
        "status": record.status,
        "descriptor_type": record.descriptor_type,
        "approval_mode": record.approval_mode,
        "listing_complete": record.listing_complete,
        "listing_scope": record.listing_scope,
        "publisher": record.publisher,
        "updated_at": record.updated_at,
        # Binding resources are exact, already sanitized finding identities.
        "bindings": [
            {
                "resource": binding.resource,
                "provider": binding.provider,
                "account": binding.account,
                "region": binding.region,
                "coverage": binding.coverage,
            }
            for binding in record.bindings
        ],
    }


def _reconciliation(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("status") not in RECONCILIATION_STATUSES:
        return None
    block: dict[str, Any] = {"status": value["status"]}
    for key in ("records", "observed"):
        if key in value:
            block[key] = _strings(value[key])
    if "registries" in value:
        listed = value["registries"] if isinstance(value["registries"], list) else []
        block["registries"] = [
            {"registry": item["registry"], "registry_id": item["registry_id"]}
            for item in listed
            if isinstance(item, dict)
            and isinstance(item.get("registry"), str)
            and isinstance(item.get("registry_id"), str)
        ]
    if isinstance(value.get("reason"), str):
        block["reason"] = value["reason"]
    return block


def _autonomy(value: Any) -> dict[str, Any] | None:
    if not valid_autonomy(value):
        return None
    return {**value, "basis": [dict(item) for item in value["basis"]]}


def _autonomy_status(finding: Finding, block: dict[str, Any] | None) -> str:
    if block is not None:
        return "classified"
    # A missing or malformed interval on a kind the scale describes is unknown, not "does not apply".
    return "not-classified" if applicable(finding) else "not-applicable"


# registry_match_reason of a finding that inventories matched to different agents.
AMBIGUOUS_REGISTRATION = "ambiguous-resource-approval"


def _agent(finding: Finding) -> dict[str, Any]:
    threats, controls = finding_references(finding)
    autonomy = _autonomy(finding.metadata.get("autonomy"))
    merged_from = _strings(finding.metadata.get("merged_from"))
    # Inventories that matched the finding to different agents (shadowscan.fleet): shadow.
    ambiguous = finding.metadata.get("registry_match_reason") == AMBIGUOUS_REGISTRATION
    return {
        "id": finding.id,
        "title": finding.title,
        "kind": finding.kind.value,
        "surface": finding.surface.value,
        "connector": finding.connector,
        "resource": finding.resource,
        "resource_type": finding.resource_type,
        "provider": finding.provider,
        "account": finding.account,
        "region": finding.region,
        "owner": finding.owner,
        "shadow": finding.shadow,
        "inventory_status": inventory_status(finding.shadow),
        "ambiguous_registration": ambiguous,
        "registry_match": finding.registry_match,
        "risk": {
            "level": finding.risk.level.value,
            "score": finding.risk.score,
            "danger_score": finding.risk.danger_score,
        },
        "confidence": finding.confidence,
        "likelihood": finding.likelihood.value,
        "frameworks": list(finding.frameworks),
        "model_providers": list(finding.model_providers),
        "models": list(finding.models),
        "capabilities": list(finding.capabilities),
        "tags": list(finding.tags),
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "merged_from": merged_from,
        "threats": threats,
        "controls": controls,
        "autonomy": autonomy,
        "autonomy_status": _autonomy_status(finding, autonomy),
        "registry": _registry(finding),
        "registry_reconciliation": _reconciliation(finding.metadata.get(RECONCILIATION_KEY)),
    }


def _number(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _by_level(counter: Counter[str | None]) -> list[dict[str, Any]]:
    """Every risk level, most severe first, then any level the scale does not know."""
    known = [{"value": level.value, "count": counter.get(level.value, 0)} for level in RiskLevel]
    return known + [row for row in _ranked(counter) if row["value"] not in _LEVEL_VALUES]


def _ranked(counter: Counter[str | None]) -> list[dict[str, Any]]:
    """``{value, count}`` rows, most frequent first; a missing value is ``null``, never dropped."""
    rows = sorted(counter.items(), key=lambda item: (-item[1], item[0] is None, item[0] or ""))
    return [{"value": value, "count": count} for value, count in rows]


def _counts(agents: list[dict[str, Any]], excluded: int) -> dict[str, Any]:
    statuses = Counter(agent["inventory_status"] for agent in agents)
    return {
        "ai_systems": len(agents),
        "excluded_credentials": excluded,
        "inventory_status": {status: statuses.get(status, 0) for status in INVENTORY_STATUSES},
        "ambiguous_registration": sum(1 for agent in agents if agent["ambiguous_registration"]),
        "unowned": sum(1 for agent in agents if not agent["owner"]),
        "by_surface": _ranked(Counter(agent["surface"] for agent in agents)),
        "by_kind": _ranked(Counter(agent["kind"] for agent in agents)),
        "by_provider": _ranked(Counter(agent["provider"] for agent in agents)),
        "by_account": _ranked(Counter(agent["account"] for agent in agents)),
        "by_owner": _ranked(Counter(agent["owner"] for agent in agents)),
        "by_risk_level": _by_level(Counter(agent["risk"]["level"] for agent in agents)),
    }


def _floor(agent: dict[str, Any]) -> int | None:
    autonomy = agent["autonomy"]
    return int(autonomy["floor"]) if autonomy is not None else None


def _autonomy_matrix(agents: list[dict[str, Any]]) -> dict[str, Any]:
    cells: Counter[tuple[int | None, str, str]] = Counter(
        (_floor(agent), agent["autonomy_status"], agent["inventory_status"]) for agent in agents
    )
    keys: list[tuple[int | None, str, str]] = [(level.number, "classified", level.title) for level in LEVELS]
    keys += [(None, "not-classified", "not classified"), (None, "not-applicable", "not applicable")]
    rows = []
    for tier, autonomy_status, label in keys:
        row: dict[str, Any] = {"tier": tier, "autonomy_status": autonomy_status, "label": label}
        row.update({status: cells.get((tier, autonomy_status, status), 0) for status in INVENTORY_STATUSES})
        row["total"] = sum(row[status] for status in INVENTORY_STATUSES)
        rows.append(row)
    return {
        "basis": "floor",
        "rows": rows,
        "priority_floor": PRIORITY_FLOOR,
        "priority": sum(1 for agent in agents if is_priority(agent)),
        # Their floor is unknown: any of them could belong to the priority quadrant.
        "not_classified": sum(1 for agent in agents if agent["autonomy_status"] == "not-classified"),
    }


def is_priority(agent: dict[str, Any]) -> bool:
    """A shadow AI system whose autonomy floor is at least L4: the priority quadrant."""
    floor = _floor(agent)
    return agent["inventory_status"] == "shadow" and floor is not None and floor >= PRIORITY_FLOOR


def _registries(agents: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[tuple[str, str], dict[str, Any]] = {}

    def entry(registry: str, registry_id: str) -> dict[str, Any]:
        return summary.setdefault(
            (registry, registry_id),
            {
                "registry": registry,
                "registry_id": registry_id,
                "records": 0,
                **dict.fromkeys(RECONCILIATION_STATUSES, 0),
                "unreconciled": 0,
                "approved": 0,
                "not_approved": 0,
                "auto_approved": 0,
                "listing_complete": True,
            },
        )

    malformed = 0
    for agent in agents:
        record, block = agent["registry"], agent["registry_reconciliation"]
        if record is not None and record.get("malformed"):
            malformed += 1
        elif record is not None:
            row = entry(record["registry"], record["registry_id"])
            row["records"] += 1
            # Statuses of the record itself; observed-not-registered never applies to a record.
            row[block["status"] if block is not None else "unreconciled"] += 1
            approved = record["status"] == "approved"
            row["approved" if approved else "not_approved"] += 1
            row["auto_approved"] += approved and record["approval_mode"] == "auto"
            row["listing_complete"] = row["listing_complete"] and record["listing_complete"]
        elif block is not None and block["status"] == "observed-not-registered":
            for ref in block.get("registries", []):
                entry(ref["registry"], ref["registry_id"])["observed-not-registered"] += 1
    rows = sorted(summary.values(), key=lambda row: (row["registry"], row["registry_id"]))
    for row in rows:
        # A registry seen only through observed findings' references has no listing to vouch for.
        row["listing_complete"] = row["listing_complete"] and row["records"] > 0
    return {"registries": rows, "malformed_records": malformed}


def _references(agents: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    counts = Counter(ref for agent in agents for ref in agent[key])
    rows = []
    for ref, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        entry = describe(ref)
        rows.append(
            {
                "ref": ref,
                "title": entry.title if entry else None,
                "framework": entry.framework_name if entry else None,
                "edition": entry.edition if entry else None,
                "count": count,
            }
        )
    return rows


def _ids(records: Iterable[dict[str, Any]]) -> list[str]:
    return [record["id"] for record in records]


def _drift(baseline: dict[str, Any], current: dict[str, Any], reference: datetime | None) -> dict[str, Any]:
    """Drift against a baseline by :func:`compare_reports`; missing findings are unknown unless comparable."""
    comparison = compare_reports(baseline, current, now=reference)
    started = parse_instant(baseline.get("started_at"))
    local = comparison["not_comparable"]
    return {
        "comparable": comparison["comparable"],
        "reasons": list(comparison["reasons"]),
        "baseline_started_at": _text(baseline.get("started_at")),
        "baseline_age_days": (
            (reference - started) // timedelta(days=1)
            if reference is not None and started is not None
            else None
        ),
        "counts": {
            "new": len(comparison["new"]),
            "resolved": len(comparison["resolved"]),
            "unknown": len(comparison["unknown"]),
            "changed": len(comparison["changed"]),
            "not_comparable": len(local["baseline"]) + len(local["current"]),
        },
        "classes": dict(comparison["drift_summary"]),
        "adverse": dict(comparison["adverse"]),
        "new": _ids(comparison["new"]),
        "resolved": _ids(comparison["resolved"]),
        "unknown": _ids(comparison["unknown"]),
        "changed": [change["after"]["id"] for change in comparison["changed"]],
    }


def _scope_reasons(scope: Any) -> list[str]:
    if not isinstance(scope, dict) or scope.get("comparable") is True:
        return []
    reason = scope.get("reason")
    return [
        sanitize_text(reason) if isinstance(reason, str) and reason else "collection scope is not comparable"
    ]


def build_inventory(
    result: ScanResult,
    *,
    name: str = "report",
    baseline: dict[str, Any] | None = None,
    current: dict[str, Any] | None = None,
    history: dict[str, Any] | None = None,
    as_of: str | None = None,
) -> dict[str, Any]:
    """The ``shadowscan.inventory/v1`` document for ``result``.

    ``name`` names the result's only source when it is not a fleet merge. With ``baseline``
    (a report as :func:`~shadowscan.comparison.load_report` reads it), ``drift`` compares it
    with ``current``, the report ``result`` was read from (by default ``result`` exported
    again). ``history`` is :func:`load_history` output. Staleness is measured against
    ``as_of`` (ISO 8601 with an offset), by default the newest source's last scan, so the
    document never depends on the wall clock. Raises ``ValueError`` on malformed input,
    including a sanitizer limit.
    """
    reference = parse_instant(as_of) if as_of is not None else None
    if as_of is not None and reference is None:
        raise ValueError("as_of must be an ISO 8601 time with a UTC offset")
    for finding in result.findings:
        finding.sanitize()
    listed = _fleet_sources(result.collection_scope)
    sources = _sanitized(listed if listed is not None else [_single_source(result, name)])
    if reference is None:
        reference = max(filter(None, (_last_scanned(source) for source in sources)), default=None)
    coverage = _coverage(sources, reference)
    diagnostics, omitted = _diagnostics(result)
    agents = [_agent(finding) for finding in result.findings if finding.kind not in _EXCLUDED_KINDS]
    agents.sort(key=lambda agent: (-_number(agent["risk"]["score"]), agent["resource"], agent["id"]))
    complete = result.complete and all(source["complete"] for source in sources)
    header = sanitize(
        {
            "generated_at": result.finished_at or result.started_at or None,
            "report_version": result.version or None,
            "reasons": _scope_reasons(result.collection_scope),
        }
    )
    return {
        "schema": INVENTORY_SCHEMA,
        "generator": {"name": "ShadowScan", "version": __version__},
        "generated_at": header["generated_at"],
        "report_version": header["report_version"],
        "as_of": reference.isoformat() if reference is not None else None,
        "complete": complete,
        "status": "complete" if complete else "incomplete",
        "comparable": isinstance(result.collection_scope, dict)
        and result.collection_scope.get("comparable") is True,
        "reasons": header["reasons"],
        # A fleet merge from an earlier version may count unreconciled AI systems as shadow.
        "legacy_fleet": legacy_fleet(result.collection_scope),
        "coverage": coverage,
        "sources": sources,
        "diagnostics": diagnostics,
        "diagnostics_omitted": omitted,
        "counts": _counts(agents, len(result.findings) - len(agents)),
        "autonomy": _autonomy_matrix(agents),
        "registries": _registries(agents),
        "references": {
            "note": REFERENCE_NOTE,
            "threats": _references(agents, "threats"),
            "controls": _references(agents, "controls"),
        },
        "drift": (
            _drift(baseline, current if current is not None else result.to_dict(), reference)
            if baseline is not None
            else None
        ),
        "history": sanitize(history) if history is not None else None,
        "agents": agents,
    }


def render_inventory_json(inventory: dict[str, Any]) -> str:
    """The document as JSON with sorted keys; ASCII only, so controls and lone surrogates stay escaped."""
    return json.dumps(inventory, indent=2, sort_keys=True, allow_nan=False)


def _history_point(name: str, report: dict[str, Any], digest: str) -> dict[str, Any]:
    findings = [item for item in report["findings"] if item.get("kind") not in _EXCLUDED_KIND_VALUES]
    # Read as the dashboard reads a report: an earlier fleet merge's shadow values alone are not
    # evidence of an inventory.
    inventory = shows_inventory(report)
    blocks = [
        item["metadata"]["autonomy"]
        for item in findings
        if isinstance(item.get("metadata"), dict) and valid_autonomy(item["metadata"].get("autonomy"))
    ]
    return {
        "name": name,
        "sha256": digest,
        "started_at": _text(report.get("started_at")),
        "finished_at": _text(report.get("finished_at")),
        "complete": _complete(report) and _summary_matches_findings(report),
        "ai_systems": len(findings),
        # Without an inventory nothing was reconciled, and without autonomy blocks nothing was
        # classified: both are unknown, not zero.
        "shadow": sum(1 for item in findings if item.get("shadow") is True) if inventory else None,
        "l4_plus": sum(1 for block in blocks if block["floor"] >= PRIORITY_FLOOR) if blocks else None,
    }


def _history_pair(
    before: _HistoryEntry, after: _HistoryEntry, old: dict[str, Any], new: dict[str, Any]
) -> dict[str, Any]:
    pair: dict[str, Any] = {"from": before.point["name"], "to": after.point["name"]}
    try:
        # Only counts are published, so no finding is exported: a pair costs a validation pass,
        # not a sanitized copy of every record.
        comparison = drift_counts(old, new, now=after.instant)
    except (ValueError, TypeError, RecursionError):
        return {**pair, "comparable": False, "reasons": 1, "classes": None, "counts": None}
    if not comparison["comparable"]:
        # A gap in the series: no counts, so nothing reads as zero drift.
        return {
            **pair,
            "comparable": False,
            "reasons": len(comparison["reasons"]),
            "classes": None,
            "counts": None,
        }
    return {
        **pair,
        "comparable": True,
        "reasons": 0,
        "classes": dict(comparison["drift_summary"]),
        "counts": {key: comparison["counts"][key] for key in ("new", "resolved", "changed")},
    }


def _history_paths(directory: Path) -> list[Path]:
    try:
        root = require_no_symlinks(directory)
    except ValueError:
        raise HistoryError("the history directory path must not traverse symbolic links") from None
    if not root.is_dir():
        raise HistoryError("the history path must be a directory")
    paths: list[Path] = []
    with os.scandir(root) as entries:
        for item in entries:
            if not item.name.lower().endswith(".json"):
                continue
            if item.is_symlink():
                raise HistoryError("the history directory contains a symbolic link")
            if not item.is_file(follow_symlinks=False):
                raise HistoryError("the history directory contains a report that is not a regular file")
            paths.append(Path(item.path))
            if len(paths) > MAX_HISTORY_FILES:
                raise HistoryError(f"the history directory holds more than {MAX_HISTORY_FILES} reports")
    return sorted(paths, key=lambda path: path.name)


def load_history(directory: str | Path) -> dict[str, Any]:
    """Per-report totals and drift between consecutive reports of a directory of JSON reports.

    Every ``*.json`` file directly in ``directory`` is read with the bounded report loader;
    a symbolic link or special file is refused. Reports are ordered by ``started_at``; one
    without a valid timezone-aware start is listed as undated, outside the series. At most
    :data:`MAX_HISTORY` of the newest reports are kept, and how many were left out is
    recorded. Drift class counts are recorded only for comparable consecutive pairs; any
    other pair is a gap with the number of reasons. Files are read twice, holding at most
    two reports at a time, and the second read must have the first read's SHA-256.
    """
    entries: list[_HistoryEntry] = []
    for path in _history_paths(Path(directory)):
        report, digest = load_report_with_digest(path)
        point = _history_point(path.name, report, digest)
        entries.append(_HistoryEntry(point, parse_instant(point["started_at"]), path))
    dated = sorted(
        (entry for entry in entries if entry.instant is not None),
        key=lambda entry: (entry.instant, entry.point["name"]),
    )
    kept = dated[-MAX_HISTORY:]
    pairs: list[dict[str, Any]] = []
    previous: tuple[_HistoryEntry, dict[str, Any]] | None = None
    for entry in kept:
        report, _ = load_report_with_digest(entry.path, expected_sha256=entry.point["sha256"])
        if previous is not None:
            pairs.append(_history_pair(previous[0], entry, previous[1], report))
        previous = (entry, report)
    summary = {
        "reports": len(entries),
        "shown": len(kept),
        "omitted": len(dated) - len(kept),
        "limit": MAX_HISTORY,
        "undated": [entry.point["name"] for entry in entries if entry.instant is None],
        "points": [entry.point for entry in kept],
        "pairs": pairs,
    }
    cleaned: dict[str, Any] = sanitize(summary)
    return cleaned
