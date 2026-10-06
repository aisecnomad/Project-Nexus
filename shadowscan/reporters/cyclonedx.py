"""CycloneDX 1.6 AI-BOM export."""

from __future__ import annotations

import json
import uuid
from typing import Any

from shadowscan.models import Kind, ScanResult


def _bom_ref(finding: dict[str, Any]) -> str:
    identifier = finding.get("id")
    if identifier:
        return str(identifier)
    stable = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"shadowscan:finding:{stable}"))


def _component(finding: dict[str, Any]) -> dict[str, Any]:
    properties = [
        {"name": f"shadowscan:{key}", "value": str(finding[key])}
        for key in ("surface", "connector", "resource", "risk_level")
        if finding.get(key) is not None
    ]
    properties.extend(
        {"name": f"shadowscan:tag:{tag}", "value": "true"} for tag in sorted(set(finding.get("tags", [])))
    )
    properties.sort(key=lambda item: item["name"])
    return {
        "type": "machine-learning-model",
        "name": str(finding.get("title") or finding.get("resource") or "discovered AI component")[:200],
        "bom-ref": _bom_ref(finding),
        "properties": properties,
    }


def _service(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(finding.get("title") or finding.get("resource") or "discovered AI service")[:200],
        "bom-ref": _bom_ref(finding),
        "properties": [
            {"name": "shadowscan:surface", "value": str(finding.get("surface", ""))},
            {"name": "shadowscan:resource", "value": str(finding.get("resource", ""))},
        ],
    }


def render_cyclonedx(result: ScanResult) -> str:
    """Render findings as CycloneDX 1.6 machine-learning-models and services."""
    findings = sorted(
        (finding.to_dict() for finding in result.findings),
        key=lambda finding: (
            str(finding.get("connector", "")),
            str(finding.get("resource", "")),
            str(finding.get("id", "")),
        ),
    )
    components = []
    services = []
    for finding in findings:
        if finding.get("connector") == "endpoint.models" or finding.get("resource_type") == "local-model":
            components.append(_component(finding))
        elif finding.get("kind") == Kind.MCP_SERVER.value or finding.get("connector") in {
            "endpoint.ollama",
            "endpoint.mcp",
        }:
            services.append(_service(finding))
        else:
            components.append(_component(finding))

    def sort_key(item: dict[str, Any]) -> str:
        return json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    components.sort(key=sort_key)
    services.sort(key=sort_key)
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": result.started_at,
            "tools": [{"vendor": "Project Nexus", "name": "ShadowScan", "version": result.version}],
        },
        "components": components,
        "services": services,
    }
    serial_source = json.dumps(bom, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    bom["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'shadowscan:bom:{serial_source}')}"
    return json.dumps(bom, indent=2, ensure_ascii=False, allow_nan=False)
