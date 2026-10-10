"""Combine ShadowScan JSON reports from several machines or scans into one report.

A fleet report is the union of its sources. Findings with the same identity
(the same object seen by the same connector, for example one workstation
scanned twice) merge exactly as repeated observations do inside one scan:
evidence and technologies union, the earliest ``first_seen`` and latest
``last_seen`` survive, the first report's metadata wins. The autonomy interval
(``metadata.autonomy``) is the exception: it is classified again from the merged
finding and widened to admit whatever any source's validated block admits, so
evidence from a later source is never hidden behind the first source's interval.
Findings from different machines keep their own resources because the endpoint
label prefixes every resource. Registration counts only from sources that
reconciled against an inventory (``inventory_present: true``: ``--inventory``,
the configuration's ``inventory:`` key or trusted registries). A finding is
shadow when any such source found it unregistered, registered when such
sources matched it to one agent, ambiguous (shadow, with
``registry_match_reason: ambiguous-resource-approval``) when they matched it
to different agents, as two matching inventory entries are in one scan, and
unassessed when no such source reported it, even if other sources were given
an inventory. A ``shadow: false`` that names no match is not a registration.

The merged report is comparable with ``shadowscan diff`` only when every
source is complete and carries a comparable collection scope; its fingerprint
is then derived from the sources' fingerprints, so two fleet reports of the
same machines with the same scanner and signatures compare, and anything else
is reported as not comparable rather than guessed.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from dataclasses import fields
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.autonomy import merge_autonomy, valid_autonomy
from shadowscan.comparison import _SCHEMA as _SCOPE_SCHEMA
from shadowscan.comparison import _complete, _findings, _scope_digest, _summary_matches_findings
from shadowscan.merge import merge
from shadowscan.models import FINDING_IDENTITY_SCHEMA, Finding, Risk, ScanResult, ScanStats, now_iso
from shadowscan.registry import clear_match_state

MAX_SOURCES = 10_000
_STATS_FIELDS = {f.name for f in fields(ScanStats)}


def _check(report: Any, name: str) -> dict[str, Any]:
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError(f"{name}: not a ShadowScan JSON report")
    if report.get("finding_identity_schema") != FINDING_IDENTITY_SCHEMA:
        raise ValueError(f"{name}: finding identity schema differs from this version; rescan before merging")
    for finding in report["findings"]:
        if not isinstance(finding, dict) or finding.get("identity_schema") != FINDING_IDENTITY_SCHEMA:
            raise ValueError(f"{name}: a finding does not carry the current identity schema")
        metadata = finding.get("metadata")
        # The merged interval admits at least what every source's block admits, so a block the
        # merge cannot read is refused rather than ignored.
        if isinstance(metadata, dict) and "autonomy" in metadata and not valid_autonomy(metadata["autonomy"]):
            raise ValueError(f"{name}: a finding has malformed autonomy metadata; rescan before merging")
    _findings(report)
    return report


def _stats(report: dict[str, Any]) -> list[ScanStats]:
    entries = report.get("stats")
    if not isinstance(entries, list) or not entries:
        return []
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("report stats entries must be objects")
        for key in ("connector", "started_at"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ValueError("report stats identity is malformed")
        for key in ("errors", "warnings"):
            value = entry.get(key, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError("report stats diagnostics must be arrays of strings")
        for key in ("skipped", "incomplete", "cached"):
            if key in entry and type(entry[key]) is not bool:
                raise ValueError("report stats completion flags must be booleans")
        for key in ("findings", "objects_examined"):
            if key in entry and (type(entry[key]) is not int or entry[key] < 0):
                raise ValueError("report stats counts must be nonnegative integers")
        out.append(ScanStats(**{k: v for k, v in entry.items() if k in _STATS_FIELDS}))
    return out


def source_names(paths: Sequence[str]) -> list[str]:
    """A name for each report file: its path below the files' common directory.

    Reports collected as ``<host>/report.json`` keep their host directory, so
    provenance and incomplete-source reasons say which machine they describe;
    files in one directory keep their base name.
    """
    absolute = [os.path.abspath(path) for path in paths]
    try:
        parent = os.path.commonpath([os.path.dirname(path) for path in absolute])
    except ValueError:  # no common directory (different drives)
        return [Path(path).as_posix() for path in absolute]
    return [Path(os.path.relpath(path, parent)).as_posix() for path in absolute]


def _merge_registration(finding: Finding, unregistered: bool, matches: set[str]) -> None:
    """Set the merged finding's registration from what its reconciling sources reported.

    Unregistered in any source wins. Sources that matched it to different agents are ambiguous,
    as two matching inventory entries are in one scan: the finding stays shadow and names the
    candidates. Without a reconciling source it is unassessed, and any match state another
    source carried is removed.
    """
    if unregistered:
        finding.shadow, finding.registry_match = True, None
    elif len(matches) == 1:
        finding.shadow, finding.registry_match = False, next(iter(matches))
    else:
        clear_match_state(finding)
        finding.registry_match = None
        finding.shadow = True if matches else None
        if matches:
            finding.metadata["registry_suggestions"] = sorted(matches)
            finding.metadata["registry_match_reason"] = "ambiguous-resource-approval"


def merge_reports(reports: list[tuple[str, dict[str, Any]]]) -> ScanResult:
    """Merge ``(name, report)`` pairs into one :class:`ScanResult`; raises ``ValueError`` on bad input."""
    if not reports:
        raise ValueError("no reports to merge")
    if len(reports) > MAX_SOURCES:
        raise ValueError("too many reports to merge")
    findings: list[Finding] = []
    sources_by_id: dict[str, list[str]] = {}
    risks_by_id: dict[str, Risk] = {}
    unregistered: set[str] = set()
    matches_by_id: dict[str, set[str]] = {}
    identity_by_id: dict[str, str] = {}
    autonomy_by_id: dict[str, list[Any]] = {}
    stats: list[ScanStats] = []
    sources: list[dict[str, Any]] = []
    fingerprints: list[str] = []
    comparable = True
    reasons: list[str] = []
    started: list[str] = []
    finished: list[str] = []
    inventory_size = 0
    inventory_present = False
    for name, raw in reports:
        report = _check(raw, name)
        scope_value = report.get("collection_scope")
        scope: dict[str, Any] = scope_value if isinstance(scope_value, dict) else {}
        complete = _complete(report) and _summary_matches_findings(report)
        fingerprint = _scope_digest(report)
        if not complete:
            comparable = False
            reasons.append(f"{name}: scan incomplete")
        if not isinstance(fingerprint, str) or scope.get("schema") != _SCOPE_SCHEMA:
            comparable = False
            reasons.append(f"{name}: collection scope not comparable")
        else:
            fingerprints.append(fingerprint)
        present = report.get("inventory_present", False)
        if type(present) is not bool:
            raise ValueError("report inventory presence must be a boolean")
        for entry in report["findings"]:
            finding = Finding.from_dict(entry)
            # A report's ids are untrusted. Findings merge only when the
            # identity their own fields describe agrees as well, so a report
            # cannot fold another source's finding into one of its own by
            # reusing its id. (The id itself may legitimately differ from
            # compute_id(): a redacted resource keeps its raw-identity digest
            # and gateway ids are keyed.)
            identity = finding.compute_id()
            if identity_by_id.setdefault(finding.id, identity) != identity:
                raise ValueError(f"{name}: a finding id is already used by a finding with another identity")
            sources_by_id.setdefault(finding.id, []).append(name)
            previous = risks_by_id.get(finding.id)
            if previous is None or (finding.risk.score, finding.risk.danger_score) > (
                previous.score,
                previous.danger_score,
            ):
                risks_by_id[finding.id] = finding.risk
            # Only a source that reconciled against an inventory assessed registration: a
            # connector or plugin can set shadow and registry_match in a scan without one. A
            # registration must name its match, so a bare shadow false is unassessed.
            if present and finding.shadow is True:
                unregistered.add(finding.id)
            elif present and finding.shadow is False and finding.registry_match:
                matches_by_id.setdefault(finding.id, set()).add(finding.registry_match)
            if "autonomy" in finding.metadata:
                autonomy_by_id.setdefault(finding.id, []).append(finding.metadata["autonomy"])
            findings.append(finding)
        stats.extend(_stats(report))
        if not complete:
            stats.append(
                ScanStats(
                    connector="engine.fleet",
                    started_at=now_iso(),
                    incomplete=True,
                    errors=[f"{name}: source report is incomplete or has inconsistent completion evidence"],
                )
            )
        if isinstance(report.get("started_at"), str):
            started.append(report["started_at"])
        if isinstance(report.get("finished_at"), str):
            finished.append(report["finished_at"])
        size = report.get("inventory_size", 0)
        if type(size) is not int or size < 0:
            raise ValueError("report inventory size must be a nonnegative integer")
        inventory_size = max(inventory_size, size)
        inventory_present = inventory_present or present
        sources.append(
            {
                "name": name,
                "version": report.get("version"),
                "complete": complete,
                "findings": len(report["findings"]),
                "fingerprint": fingerprint,
            }
        )
    merged = merge(findings)
    for finding in merged:
        names = sorted(dict.fromkeys(sources_by_id.get(finding.id, [])))
        finding.metadata["merged_from"] = names
        # Source scans can use different risk policies. Preserve the highest
        # observed assessment instead of rescoring with an unknown policy or
        # retaining whichever low-risk report appeared first.
        finding.risk = risks_by_id[finding.id]
        # merge() keeps the first observation's registry match, which may come
        # from a source that did not reconcile the finding.
        _merge_registration(finding, finding.id in unregistered, matches_by_id.get(finding.id, set()))
        # Unioned tags, capabilities and evidence can change the interval; the merged one also
        # admits at least what each source's block admits, as risk keeps the highest score.
        merge_autonomy(finding, autonomy_by_id.get(finding.id, []))
        finding.metadata["fleet_risk_aggregation"] = "maximum-source-score"
    merged.sort(key=lambda f: (-f.risk.score, f.resource, f.id))
    if comparable:
        digest = hashlib.sha256("\n".join(sorted(fingerprints)).encode()).hexdigest()
        scope_out: dict[str, Any] = {"schema": _SCOPE_SCHEMA, "comparable": True, "fingerprint": digest}
    else:
        scope_out = {"schema": _SCOPE_SCHEMA, "comparable": False, "reason": "; ".join(reasons)}
    scope_out["fleet"] = {"schema": "shadowscan.fleet-merge/v1", "sources": sources}
    result = ScanResult(
        findings=merged,
        stats=stats,
        version=__version__,
        inventory_size=inventory_size,
        inventory_present=inventory_present,
        collection_scope=scope_out,
    )
    if started:
        result.started_at = min(started)
    result.finished_at = max(finished) if finished else None
    return result
