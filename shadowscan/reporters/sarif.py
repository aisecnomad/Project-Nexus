"""SARIF 2.1.0 output for code-scanning integrations (GitHub Code Scanning, Azure DevOps, IDEs).

Every finding becomes a result; code findings carry physical locations
(``path:line`` from evidence), other surfaces carry logical locations
(resource ids). Rules are generated per (kind, primary signature).
"""

from __future__ import annotations

import json
import re
from typing import Any

from shadowscan import __version__
from shadowscan.models import Finding, RiskLevel, ScanResult, Surface

_LEVEL = {RiskLevel.CRITICAL: "error", RiskLevel.HIGH: "error", RiskLevel.MEDIUM: "warning", RiskLevel.LOW: "note", RiskLevel.INFO: "note"}
_SECURITY_SEVERITY = {RiskLevel.CRITICAL: "9.5", RiskLevel.HIGH: "7.5", RiskLevel.MEDIUM: "5.0", RiskLevel.LOW: "2.5", RiskLevel.INFO: "1.0"}
_LOC = re.compile(r"^(?P<path>.+?)(?::(?P<line>\d+))?$")


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
        path = m.group("path")
        if root and path.startswith(root):
            path = path[len(root) :].lstrip("/")
        line = int(m.group("line")) if m.group("line") else None
        key = (path, line)
        if key in seen:
            continue
        seen.add(key)
        region = {"startLine": line} if line else {}
        loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"}}}
        if region:
            loc["physicalLocation"]["region"] = region
        if e.snippet:
            loc["physicalLocation"].setdefault("region", {})["snippet"] = {"text": e.snippet[:200]}
        locs.append(loc)
        if len(locs) >= 20:
            break
    if not locs and f.metadata.get("path"):
        locs.append({"physicalLocation": {"artifactLocation": {"uri": str(f.metadata["path"]), "uriBaseId": "%SRCROOT%"}}})
    return locs


def render_sarif(result: ScanResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in result.findings:
        rid = _rule_id(f)
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
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ShadowScan", "version": __version__, "informationUri": "https://github.com/aisecnomad/Project-Nexus", "rules": list(rules.values())}},
                "results": results,
                "invocations": [{"executionSuccessful": True, "startTimeUtc": result.started_at, "endTimeUtc": result.finished_at}],
                "properties": {"summary": result.summary()},
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)
