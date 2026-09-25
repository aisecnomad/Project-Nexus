"""SARIF 2.1.0 output for code-scanning integrations (GitHub Code Scanning, Azure DevOps, IDEs).

Every finding becomes a result; code findings carry physical locations
(``path:line`` from evidence), other surfaces carry logical locations
(resource ids). Rules are generated per (kind, primary signature).

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

_LEVEL = {RiskLevel.CRITICAL: "error", RiskLevel.HIGH: "error", RiskLevel.MEDIUM: "warning", RiskLevel.LOW: "note", RiskLevel.INFO: "note"}
_SECURITY_SEVERITY = {RiskLevel.CRITICAL: "9.5", RiskLevel.HIGH: "7.5", RiskLevel.MEDIUM: "5.0", RiskLevel.LOW: "2.5", RiskLevel.INFO: "1.0"}
_LOC = re.compile(r"^(?P<path>.+?)(?::(?P<line>\d+))?$")
_RANK = {RiskLevel.INFO: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
_RULE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_]")
_SNIPPET_LIMIT = 200
_MAX_LOCATIONS = 20


def _compact(mapping: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None: SARIF properties are optional, never ``null``."""
    return {key: value for key, value in mapping.items() if value is not None}


def _utc_timestamp(value: object) -> str | None:
    """An ISO 8601 UTC timestamp with a ``Z`` suffix (SARIF section 3.9), or None.

    Offsets are converted to UTC and a naive value is taken as UTC (the engine
    only records aware UTC timestamps). A value that is not an ISO 8601
    date/time yields None so the caller omits the key instead of emitting an
    invalid timestamp or ``null``.
    """
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
    """A rule ``name`` GitHub code scanning accepts (``^[A-Za-z_][A-Za-z0-9_]*$``).

    Rule ids contain ``/``, ``.`` and ``-`` (``shadowscan/mcp-server/protocol.mcp``);
    every character outside the allowed set becomes ``_`` and a name that would
    start with a digit is prefixed with ``_``. The ``id`` stays the stable key.
    """
    name = _RULE_NAME_CHARS.sub("_", rule_id)
    return name if re.match(r"[A-Za-z_]", name) else "_" + name


def _artifact_location(path: str, root: str) -> dict[str, str]:
    """A SARIF artifactLocation whose ``uri`` is a valid, percent-encoded URI reference.

    Paths are made relative to the scan root only on a path-segment boundary
    ('/repo' must not strip '/repo2/...'). Characters such as ' ', '#', '?'
    and '%' are encoded so code-scanning UIs map alerts to the right file.
    """
    normalized = path.replace("\\", "/")
    base = root.replace("\\", "/").rstrip("/")
    if base and (normalized == base or normalized.startswith(base + "/")):
        return {"uri": quote(normalized[len(base):].lstrip("/") or ".", safe="/"), "uriBaseId": "%SRCROOT%"}
    if PurePosixPath(normalized).is_absolute():
        # Outside the scan root: an absolute URI must not carry a uriBaseId.
        return {"uri": "file://" + quote(normalized, safe="/")}
    return {"uri": quote(normalized, safe="/"), "uriBaseId": "%SRCROOT%"}


def _rule_id(f: Finding) -> str:
    primary = (f.frameworks or f.model_providers or ["generic"])[0]
    return f"shadowscan/{f.kind.value}/{primary}"


def _physical_locations(f: Finding) -> list[dict[str, Any]]:
    """Physical locations for ``path[:line]`` evidence, deduplicated and capped.

    A ``region`` is emitted only when the evidence carries a line number: SARIF
    2.1.0 section 3.30 requires a region to be a text region (``startLine``) or
    a binary region (``byteOffset`` or ``charOffset``), and GitHub code scanning
    rejects an upload containing a snippet-only region. Evidence with a snippet
    but no line (dependency evidence from manifests, for example) yields a
    physical location with only the artifact; its snippet is kept in the
    location's ``properties`` bag under ``snippet``, which SARIF leaves free-form.
    """
    locs: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    root = str(f.metadata.get("scan_root") or "")
    for e in f.evidence:
        if not e.location or e.location.startswith(("http", "arn:", "/subscriptions/", "projects/", "ocid1.")):
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
    if not locs and f.metadata.get("path"):
        locs.append({"physicalLocation": {"artifactLocation": _artifact_location(str(f.metadata["path"]), root)}})
    return locs


def render_sarif(result: ScanResult) -> str:
    """Render a scan result as a SARIF 2.1.0 log (validity rules are in the module docstring)."""
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
            rules[rid] = {
                "id": rid,
                "name": _rule_name(rid),
                "shortDescription": {"text": f"{f.kind.value} ({(f.frameworks or f.model_providers or ['generic'])[0]})"},
                "fullDescription": {"text": f"ShadowScan detected a {f.kind.value} on the {f.surface.value} surface."},
                "help": {"text": "Review the agent, confirm ownership, register it in the agent inventory and remediate the listed risk factors."},
                "defaultConfiguration": {"level": _LEVEL[f.risk.level]},
                "properties": {"tags": ["security", "ai-agent", f.surface.value, f.kind.value], "security-severity": _SECURITY_SEVERITY[f.risk.level]},
            }
        message = f"{f.title} — risk {f.risk.level.value} ({f.risk.score}), confidence {f.confidence:.2f}"
        if f.shadow:
            message += " — SHADOW (not in inventory)"
        factors = "; ".join(x.description for x in f.risk.factors if x.weight > 0)
        res: dict[str, Any] = {
            "ruleId": rid,
            "level": _LEVEL[f.risk.level],
            "message": {"text": message + (f". Risk factors: {factors}" if factors else "")},
            "partialFingerprints": {"shadowscan/finding": f.id},
            "properties": _compact({
                "surface": f.surface.value,
                "kind": f.kind.value,
                "resource": f.resource,
                "provider": f.provider,
                "owner": f.owner,
                "frameworks": f.frameworks,
                "model_providers": f.model_providers,
                "capabilities": f.capabilities,
                # A property bag's reserved ``tags`` key is a set of distinct strings.
                "tags": list(dict.fromkeys(f.tags)),
                "shadow": f.shadow,
                "risk_score": f.risk.score,
                "confidence": f.confidence,
            }),
        }
        locations = _physical_locations(f) if f.surface == Surface.CODE else []
        if locations:
            res["locations"] = locations
        else:
            logical = _compact({"name": f.resource, "kind": f.resource_type or None, "fullyQualifiedName": f.resource})
            res["locations"] = [{"logicalLocations": [logical]}]
        results.append(res)
    # Code-scanning UIs show a rule's severity for all of its alerts: use the
    # most severe result, independent of report ordering.
    for rid, level in worst.items():
        rules[rid]["defaultConfiguration"]["level"] = _LEVEL[level]
        rules[rid]["properties"]["security-severity"] = _SECURITY_SEVERITY[level]
    invocation = _compact({
        "executionSuccessful": result.complete,
        "startTimeUtc": _utc_timestamp(result.started_at),
        "endTimeUtc": _utc_timestamp(result.finished_at),
        "toolExecutionNotifications": [
            {"level": "error" if st.errors or st.skipped else "warning", "message": {"text": f"{st.connector}: {msg}"}}
            for st in result.stats for msg in dict.fromkeys(st.errors + st.warnings + ([st.skip_reason] if st.skip_reason else []))
        ],
    })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ShadowScan", "version": __version__, "informationUri": "https://github.com/aisecnomad/Project-Nexus", "rules": list(rules.values())}},
                "results": results,
                "invocations": [invocation],
                "properties": {"summary": result.summary()},
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)
