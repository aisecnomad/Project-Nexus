"""SARIF 2.1.0 output for code-scanning integrations (GitHub Code Scanning, Azure DevOps, IDEs).

Every finding becomes a result; code findings carry physical locations
(``path:line`` from evidence), other surfaces carry logical locations
(resource ids). Rules are generated per (kind, primary signature).

Risk labels are heuristic discovery scores, not CVSS. This reporter does not
emit ``security-severity`` (GitHub treats that property as a CVSS-like score)
and does not use SARIF level ``error`` for a discovery hit. See docs/severity.md.

The log is kept valid for the SARIF 2.1.0 schema and for GitHub code scanning,
which rejects a whole upload over one malformed field: a ``region`` is only
emitted with a ``startLine`` (SARIF section 3.30), rule names match
``^[A-Za-z_][A-Za-z0-9_]*$``, timestamps are ISO 8601 UTC with a ``Z`` suffix or
omitted (section 3.9), property-bag ``tags`` are distinct strings, and a key
whose value would be ``null`` is omitted.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from shadowscan import __version__
from shadowscan.models import Finding, RiskLevel, ScanResult, Surface
from shadowscan.reporters._publication import publication_stats

# Discovery hits are not vulnerabilities. ``error`` is reserved for tool
# failures. A heuristic critical/high finding is a warning an analyst must
# confirm, not a blocking security defect.
_LEVEL = {
    RiskLevel.CRITICAL: "warning",
    RiskLevel.HIGH: "warning",
    RiskLevel.MEDIUM: "warning",
    RiskLevel.LOW: "note",
    RiskLevel.INFO: "note",
}
_LOC = re.compile(r"^(?P<path>.+?)(?::(?P<line>\d+))?$")
_RANK = {RiskLevel.INFO: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
_RULE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_]")
_SNIPPET_LIMIT = 200
_MAX_LOCATIONS = 20
_GCP_RESOURCE = re.compile(
    r"^projects/[^/]+/(?:global|locations|regions|serviceAccounts|service_accounts|zones)(?:/|$)"
)


def _compact(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if value is not None}


def _utc_timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _rule_name(rule_id: str) -> str:
    name = _RULE_NAME_CHARS.sub("_", rule_id)
    return name if re.match(r"[A-Za-z_]", name) else "_" + name


def _artifact_location(path: str, root: str) -> dict[str, str]:
    normalized = path.replace("\\", "/")
    base = root.replace("\\", "/").rstrip("/")
    if base and (normalized == base or normalized.startswith(base + "/")):
        return {"uri": quote(normalized[len(base) :].lstrip("/") or ".", safe="/"), "uriBaseId": "%SRCROOT%"}
    if PurePosixPath(normalized).is_absolute():
        return {"uri": "file://" + quote(normalized, safe="/")}
    return {"uri": quote(normalized, safe="/"), "uriBaseId": "%SRCROOT%"}


def _rule_id(f: Finding) -> str:
    primary = (f.frameworks or f.model_providers or ["generic"])[0]
    return f"shadowscan/{f.kind.value}/{primary}"


def _is_resource_location(location: str) -> bool:
    normalized = location.replace("\\", "/")
    return (
        re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", normalized) is not None
        or normalized.startswith(("arn:", "urn:", "ocid1.", "/subscriptions/"))
        or _GCP_RESOURCE.match(normalized) is not None
    )


def _physical_locations(f: Finding) -> list[dict[str, Any]]:
    locs: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    root = str(f.metadata.get("scan_root") or "")
    for e in f.evidence:
        if not e.location or _is_resource_location(e.location):
            continue
        m = _LOC.match(e.location)
        if not m:
            continue
        artifact = _artifact_location(m.group("path"), root)
        line = int(m.group("line") or 0)
        key = (artifact["uri"], line)
        if key in seen:
            continue
        seen.add(key)
        snippet = e.snippet[:_SNIPPET_LIMIT] if e.snippet else None
        physical: dict[str, Any] = {"artifactLocation": artifact}
        loc: dict[str, Any] = {"physicalLocation": physical}
        if line >= 1:
            physical["region"] = _compact({"startLine": line, "snippet": {"text": snippet} if snippet else None})
        elif snippet:
            loc["properties"] = {"snippet": snippet}
        locs.append(loc)
        if len(locs) >= _MAX_LOCATIONS:
            break
    metadata_path = f.metadata.get("path")
    if not locs and isinstance(metadata_path, str) and not _is_resource_location(metadata_path):
        locs.append({"physicalLocation": {"artifactLocation": _artifact_location(metadata_path, root)}})
    return locs


def _rule(f: Finding, rid: str) -> dict[str, Any]:
    technology = (f.frameworks or f.model_providers or ["generic"])[0]
    return {
        "id": rid,
        "name": _rule_name(rid),
        "shortDescription": {"text": f"{f.kind.value} ({technology})"},
        "fullDescription": {"text": f"ShadowScan detected a {f.kind.value} on the {f.surface.value} surface."},
        "help": {"text": ("Heuristic discovery hit, not a CVSS vulnerability and not proof of execution. Confirm ownership and runtime evidence before registering or blocking. See docs/severity.md.")},
        "defaultConfiguration": {"level": _LEVEL[f.risk.level]},
        "properties": {"tags": ["ai-agent", f.surface.value, f.kind.value], "shadowscan/heuristic-risk": f.risk.level.value, "shadowscan/score-basis": "heuristic-not-cvss"},
    }


def _result(f: Finding, rid: str) -> dict[str, Any]:
    message = f"{f.title} — risk {f.risk.level.value} ({f.risk.score}), confidence {f.confidence:.2f}"
    if f.shadow:
        message += " — SHADOW (not in inventory)"
    factors = "; ".join(x.description for x in f.risk.factors if x.weight > 0)
    res: dict[str, Any] = {
        "ruleId": rid,
        "level": _LEVEL[f.risk.level],
        "message": {"text": message + (f". Risk factors: {factors}" if factors else "")},
        "partialFingerprints": {"shadowscan/finding": f.id},
        "properties": _compact({"surface": f.surface.value, "kind": f.kind.value, "resource": f.resource, "provider": f.provider, "owner": f.owner, "frameworks": f.frameworks, "model_providers": f.model_providers, "capabilities": f.capabilities, "tags": list(dict.fromkeys(f.tags)), "shadow": f.shadow, "risk_score": f.risk.score, "confidence": f.confidence}),
    }
    locations = _physical_locations(f) if f.surface == Surface.CODE else []
    if locations:
        res["locations"] = locations
    else:
        logical = _compact({"name": f.resource, "kind": f.resource_type or None, "fullyQualifiedName": f.resource})
        res["locations"] = [{"logicalLocations": [logical]}]
    return res


def _invocation(result: ScanResult) -> dict[str, Any]:
    notifications = [
        {"level": "error" if st["errors"] or st["skipped"] else "warning", "message": {"text": f"{st['connector']}: {msg}"}}
        for st in publication_stats(result)
        for msg in dict.fromkeys(st["errors"] + st["warnings"] + ([st["skip_reason"]] if st["skip_reason"] else []))
    ]
    return _compact({"executionSuccessful": result.complete, "startTimeUtc": _utc_timestamp(result.started_at), "endTimeUtc": _utc_timestamp(result.finished_at), "toolExecutionNotifications": notifications})


def render_sarif(result: ScanResult) -> str:
    for finding in result.findings:
        finding.sanitize()
    rules: dict[str, dict[str, Any]] = {}
    worst: dict[str, RiskLevel] = {}
    results: list[dict[str, Any]] = []
    for f in result.findings:
        rid = _rule_id(f)
        if rid not in worst or _RANK[f.risk.level] > _RANK[worst[rid]]:
            worst[rid] = f.risk.level
        if rid not in rules:
            rules[rid] = _rule(f, rid)
        results.append(_result(f, rid))
    for rid, level in worst.items():
        rules[rid]["defaultConfiguration"]["level"] = _LEVEL[level]
        rules[rid]["properties"]["shadowscan/heuristic-risk"] = level.value
        rules[rid]["properties"]["shadowscan/score-basis"] = "heuristic-not-cvss"
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ShadowScan", "version": __version__, "informationUri": "https://github.com/aisecnomad/Project-Nexus", "rules": list(rules.values())}}, "results": results, "invocations": [_invocation(result)], "properties": {"summary": result.summary()}}]}
    return json.dumps(sarif, indent=2, default=str, allow_nan=False)
