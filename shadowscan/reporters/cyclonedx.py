"""CycloneDX 1.6 JSON: every finding as a component carrying ShadowScan properties.

The BOM holds what a supply-chain tool can consume: one component per finding
with its surface, kind, risk, confidence, shadow status, owner, technologies
and evidence locations. It never holds evidence snippets or credential
values. Names, resources and locations are the sanitized values of the JSON
report; secrets and tokens become ``data`` components named by the redacted
finding title.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from shadowscan import __version__
from shadowscan.models import Kind, ScanResult

SPEC_VERSION = "1.6"

# Identity-shaped findings (grants, service identities) are applications in the
# BOM sense: things that act in the estate. Their kind travels as a property.
_COMPONENT_TYPES: dict[Kind, str] = {
    Kind.AGENT: "application",
    Kind.BOT_APP: "application",
    Kind.WORKFLOW: "application",
    Kind.GATEWAY_CALLER: "application",
    Kind.MCP_SERVER: "application",
    Kind.OAUTH_GRANT: "application",
    Kind.SERVICE_IDENTITY: "application",
    Kind.IAM_GRANT: "application",
    Kind.FRAMEWORK_USAGE: "library",
    Kind.CLOUD_RESOURCE: "platform",
    Kind.AGENT_CONFIG: "file",
    Kind.INFRA: "file",
    Kind.SECRET: "data",
    Kind.TOKEN: "data",
}
_SERIAL_NAMESPACE = uuid.UUID("7a3b7c3e-9f2c-4a0a-9c4e-0f2b1d3c5a7e")
_MAX_OCCURRENCES = 100


def _prop(name: str, value: Any) -> dict[str, str] | None:
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, list):
        text = ", ".join(str(v) for v in value)
    else:
        text = str(value)
    return {"name": f"shadowscan:{name}", "value": text}


def _properties(pairs: list[tuple[str, Any]]) -> list[dict[str, str]]:
    return [p for name, value in pairs if (p := _prop(name, value)) is not None]


def _component(finding: dict[str, Any]) -> dict[str, Any]:
    kind = Kind(finding["kind"])
    risk_value = finding.get("risk")
    risk: dict[str, Any] = risk_value if isinstance(risk_value, dict) else {}
    properties = _properties(
        [
            ("kind", kind.value),
            ("surface", finding.get("surface")),
            ("connector", finding.get("connector")),
            ("resource", finding.get("resource")),
            ("resource_type", finding.get("resource_type")),
            ("provider", finding.get("provider")),
            ("account", finding.get("account")),
            ("region", finding.get("region")),
            ("owner", finding.get("owner")),
            ("confidence", finding.get("confidence")),
            ("likelihood", finding.get("likelihood")),
            ("risk_score", risk.get("score")),
            ("risk_level", risk.get("level")),
            ("shadow", finding.get("shadow")),
            ("registry_match", finding.get("registry_match")),
            ("frameworks", finding.get("frameworks")),
            ("model_providers", finding.get("model_providers")),
            ("models", finding.get("models")),
            ("capabilities", finding.get("capabilities")),
            ("permissions", finding.get("permissions")),
            ("first_seen", finding.get("first_seen")),
            ("last_seen", finding.get("last_seen")),
        ]
    )
    occurrences: list[dict[str, str]] = []
    seen: set[str] = set()
    for evidence in finding.get("evidence") or []:
        location = evidence.get("location") if isinstance(evidence, dict) else None
        if location and location not in seen and len(occurrences) < _MAX_OCCURRENCES:
            seen.add(location)
            occurrences.append({"location": str(location)})
    component: dict[str, Any] = {
        "type": _COMPONENT_TYPES.get(kind, "application"),
        "bom-ref": finding["id"],
        "name": finding.get("title") or finding["id"],
        "group": str(finding.get("surface") or ""),
        "description": f"{kind.value} observed by {finding.get('connector')}",
        "properties": properties,
    }
    tags = finding.get("tags") or []
    if tags:
        component["tags"] = [str(t) for t in tags]
    if occurrences:
        component["evidence"] = {"occurrences": occurrences}
    return component


def render_cyclonedx(result: ScanResult) -> str:
    """Render the scan as a CycloneDX 1.6 JSON BOM; the same report renders the same BOM."""
    report = result.to_dict()
    summary = report.get("summary") or {}
    scope = report.get("collection_scope")
    fingerprint = scope.get("fingerprint") if isinstance(scope, dict) else None
    serial = uuid.uuid5(
        _SERIAL_NAMESPACE, f"{report.get('started_at')}:{report.get('finished_at')}:{len(report['findings'])}"
    )
    bom: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": report.get("finished_at") or report.get("started_at"),
            "tools": {"components": [{"type": "application", "name": "shadowscan", "version": __version__}]},
            "component": {
                "type": "application",
                "name": "shadowscan-scan",
                "bom-ref": f"shadowscan-scan:{serial}",
                "properties": _properties(
                    [
                        ("complete", summary.get("complete")),
                        ("status", summary.get("status")),
                        ("total", summary.get("total")),
                        ("shadow", summary.get("shadow")),
                        ("inventory_size", report.get("inventory_size")),
                        ("finding_identity_schema", report.get("finding_identity_schema")),
                        ("collection_scope_fingerprint", fingerprint),
                        ("errors", summary.get("errors")),
                    ]
                ),
            },
        },
        "components": [_component(f) for f in report["findings"]],
    }
    return json.dumps(bom, indent=2, allow_nan=False)
