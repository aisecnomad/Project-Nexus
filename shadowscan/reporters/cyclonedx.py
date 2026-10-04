"""CycloneDX 1.6 AI-BOM export."""

from __future__ import annotations

import json
import uuid
from typing import Any

from shadowscan.models import Kind, ScanResult


def _component(finding: dict[str, Any]) -> dict[str, Any]:
    properties = [
        {"name": f"shadowscan:{key}", "value": str(finding[key])}
        for key in ("surface", "connector", "resource", "risk_level")
        if finding.get(key) is not None
    ]
    properties.extend({"name": f"shadowscan:tag:{tag}", "value": "true"} for tag in finding.get("tags", []))
    return {
        "type": "machine-learning-model",
        "name": str(finding.get("title") or finding.get("resource") or "discovered AI component")[:200],
        "bom-ref": str(finding.get("id") or uuid.uuid4()),
        "properties": properties,
    }


def _service(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(finding.get("title") or finding.get("resource") or "discovered AI service")[:200],
        "bom-ref": str(finding.get("id") or uuid.uuid4()),
        "properties": [
            {"name": "shadowscan:surface", "value": str(finding.get("surface", ""))},
            {"name": "shadowscan:resource", "value": str(finding.get("resource", ""))},
        ],
    }


def render_cyclonedx(result: ScanResult) -> str:
    """Render findings as CycloneDX 1.6 machine-learning-models and services."""
    findings = [finding.to_dict() for finding in result.findings]
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
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": result.started_at,
            "tools": [{"vendor": "Project Nexus", "name": "ShadowScan", "version": result.version}],
        },
        "components": components,
        "services": services,
    }
    return json.dumps(bom, indent=2, ensure_ascii=False, allow_nan=False)
