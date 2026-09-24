"""SARIF 2.1.0 output for code-scanning integrations (GitHub Code Scanning, Azure DevOps, IDEs).

Every finding becomes a result; code findings carry physical locations
(``path:line`` from evidence), other surfaces carry logical locations
(resource ids). Rules are generated per (kind, primary signature).
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from shadowscan import __version__
from shadowscan.models import Finding, RiskLevel, ScanResult, Surface

_LEVEL = {RiskLevel.CRITICAL: "error", RiskLevel.HIGH: "error", RiskLevel.MEDIUM: "warning", RiskLevel.LOW: "note", RiskLevel.INFO: "note"}
_SECURITY_SEVERITY = {RiskLevel.CRITICAL: "9.5", RiskLevel.HIGH: "7.5", RiskLevel.MEDIUM: "5.0", RiskLevel.LOW: "2.5", RiskLevel.INFO: "1.0"}
_LOC = re.compile(r"^(?P<path>.+?)(?::(?P<line>\d+))?$")
_RANK = {RiskLevel.INFO: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}


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
    locs: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    root = str(f.metadata.get("scan_root") or "")
    for e in f.evidence:
        if not e.location or e.location.startswith(("http", "arn:", "/subscriptions/", "projects/", "ocid1.")):
            continue
        m = _LOC.match(e.location)
        if not m:
            continue
        artifact = _artifact_location(m.group("path"), root)
        line = int(m.group("line")) if m.group("line") else None
        key = (artifact["uri"], line)
        if key in seen:
            continue
        seen.add(key)
        region = {"startLine": line} if line else {}
        loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": artifact}}
        if region:
            loc["physicalLocation"]["region"] = region
        if e.snippet:
            loc["physicalLocation"].setdefault("region", {})["snippet"] = {"text": e.snippet[:200]}
        locs.append(loc)
        if len(locs) >= 20:
            break
    if not locs and f.metadata.get("path"):
        locs.append({"physicalLocation": {"artifactLocation": _artifact_location(str(f.metadata["path"]), root)}})
    return locs


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
            rules[rid] = {
                "id": rid,
                "name": rid.replace("/", "_").replace(".", "_"),
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
            "properties": {
                "surface": f.surface.value,
                "kind": f.kind.value,
                "resource": f.resource,
                "provider": f.provider,
                "owner": f.owner,
                "frameworks": f.frameworks,
                "model_providers": f.model_providers,
                "capabilities": f.capabilities,
                "tags": f.tags,
                "shadow": f.shadow,
                "risk_score": f.risk.score,
                "confidence": f.confidence,
            },
        }
        locations = _physical_locations(f) if f.surface == Surface.CODE else []
        if locations:
            res["locations"] = locations
        else:
            res["locations"] = [{"logicalLocations": [{"name": f.resource, "kind": f.resource_type, "fullyQualifiedName": f.resource}]}]
        results.append(res)
    # Code-scanning UIs show a rule's severity for all of its alerts: use the
    # most severe result, independent of report ordering.
    for rid, level in worst.items():
        rules[rid]["defaultConfiguration"]["level"] = _LEVEL[level]
        rules[rid]["properties"]["security-severity"] = _SECURITY_SEVERITY[level]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ShadowScan", "version": __version__, "informationUri": "https://github.com/aisecnomad/Project-Nexus", "rules": list(rules.values())}},
                "results": results,
                "invocations": [{"executionSuccessful": result.complete, "startTimeUtc": result.started_at, "endTimeUtc": result.finished_at, "toolExecutionNotifications": [
                    {"level": "error" if st.errors or st.skipped else "warning", "message": {"text": f"{st.connector}: {msg}"}}
                    for st in result.stats for msg in dict.fromkeys(st.errors + st.warnings + ([st.skip_reason] if st.skip_reason else []))
                ]}],
                "properties": {"summary": result.summary()},
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)
