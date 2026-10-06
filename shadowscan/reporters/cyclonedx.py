"""CycloneDX 1.6 JSON output: the scan as an AI bill of materials.

Each discovered agent, MCP configuration, AI app, caller, model store or
network contact becomes an ``application`` component whose ``bom-ref`` is the
finding id. What it is built with or talks to becomes a shared entry that the
component depends on:

* agent frameworks, coding agents and protocols are ``framework`` components;
* model providers are ``services``;
* concrete model ids are ``machine-learning-model`` components;
* MCP servers listed by an MCP configuration are ``services``.

Credential findings (``secret`` and ``token``) are not components: a BOM is an
inventory, and the JSON or SARIF report is the place to triage credentials.
ShadowScan's heuristic risk, confidence and shadow status are recorded as
``shadowscan:*`` properties, never as CycloneDX vulnerabilities or ratings.

A BOM never reads as more complete than the scan: ``compositions`` declares
the inventory ``incomplete`` when any connector failed or stopped early, and
``unknown`` otherwise, because a complete scan still covers only the
configured sources. The output is deterministic for a given result.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from shadowscan import __version__
from shadowscan.models import Finding, Kind, ScanResult
from shadowscan.reporters._publication import publication_stats
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.utils.redaction import sanitize

_PROJECT_URI = "https://github.com/aisecnomad/Project-Nexus"
_EXCLUDED_KINDS = {Kind.SECRET, Kind.TOKEN}
_MAX_MCP_SERVERS = 50
_MAX_MODELS = 20
_SERIAL_NAMESPACE = uuid.UUID("6f1c3c56-2a52-5b8e-9a0e-5c7d4f1e2b10")


def _timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _properties(pairs: list[tuple[str, object]]) -> list[dict[str, str]]:
    """CycloneDX properties: string values only, empty values omitted."""
    out = []
    for name, value in pairs:
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        elif isinstance(value, bool):
            value = "true" if value else "false"
        out.append({"name": name, "value": str(value)})
    return out


def _ref(prefix: str, value: str) -> str:
    """A stable bom-ref for a shared entry, safe for any identifier text."""
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    return f"{prefix}:{digest}"


class _Bom:
    def __init__(self, index: SignatureIndex) -> None:
        self.index = index
        self.components: dict[str, dict[str, Any]] = {}
        self.services: dict[str, dict[str, Any]] = {}
        self.dependencies: dict[str, set[str]] = {}

    def signature_component(self, sid: str) -> str:
        ref = f"signature:{sid}"
        if ref not in self.components:
            sig = self.index.get(sid)
            component: dict[str, Any] = {
                "type": "framework",
                "bom-ref": ref,
                "name": sig.name if sig else sid,
            }
            if sig is not None:
                if sig.vendor:
                    component["publisher"] = sig.vendor
                if sig.description:
                    component["description"] = sig.description
                if sig.homepage:
                    component["externalReferences"] = [{"type": "website", "url": sig.homepage}]
                component["properties"] = _properties(
                    [("shadowscan:signature", sid), ("shadowscan:category", sig.category)]
                )
            else:
                component["properties"] = _properties([("shadowscan:signature", sid)])
            self.components[ref] = component
        return ref

    def provider_service(self, sid: str) -> str:
        ref = f"signature:{sid}"
        if ref not in self.services:
            sig = self.index.get(sid)
            service: dict[str, Any] = {
                "bom-ref": ref,
                "name": sig.name if sig else sid,
                "trustZone": "external",
            }
            if sig is not None and sig.vendor:
                service["provider"] = {"name": sig.vendor}
            if sig is not None and sig.homepage:
                service["externalReferences"] = [{"type": "website", "url": sig.homepage}]
            service["properties"] = _properties([("shadowscan:signature", sid)])
            self.services[ref] = service
        return ref

    def model_component(self, model: str) -> str:
        ref = _ref("model", model)
        if ref not in self.components:
            self.components[ref] = {"type": "machine-learning-model", "bom-ref": ref, "name": model}
        return ref

    def mcp_service(self, finding: Finding, server: dict[str, Any]) -> str | None:
        name = server.get("name")
        if not isinstance(name, str) or not name:
            return None
        ref = _ref("mcp", f"{finding.id}\0{name}")
        service: dict[str, Any] = {"bom-ref": ref, "name": name, "group": "mcp-server"}
        urls = [u for u in server.get("urls") or [server.get("url")] if isinstance(u, str) and u]
        endpoints = [u for u in urls if u.startswith(("https://", "http://"))]
        if endpoints:
            service["endpoints"] = endpoints[:5]
        risks = [r.get("id") for r in server.get("risks") or [] if isinstance(r, dict)]
        service["properties"] = _properties(
            [
                ("shadowscan:mcp:transport", server.get("transport")),
                (
                    "shadowscan:mcp:command",
                    server.get("command") if isinstance(server.get("command"), str) else None,
                ),
                (
                    "shadowscan:mcp:disabled",
                    server.get("disabled") if isinstance(server.get("disabled"), bool) else None,
                ),
                ("shadowscan:mcp:risks", [r for r in risks if isinstance(r, str)]),
            ]
        )
        self.services[ref] = service
        return ref

    def add(self, f: Finding) -> None:
        ref = f.id
        component: dict[str, Any] = {
            "type": "application",
            "bom-ref": ref,
            "name": f.title,
            "group": f.surface.value,
            "description": f"{f.kind.value} discovered by {f.connector}",
        }
        if f.owner:
            component["authors"] = [{"name": f.owner}]
        component["properties"] = _properties(
            [
                ("shadowscan:finding-id", f.id),
                ("shadowscan:surface", f.surface.value),
                ("shadowscan:kind", f.kind.value),
                ("shadowscan:connector", f.connector),
                ("shadowscan:resource", f.resource),
                ("shadowscan:resource-type", f.resource_type),
                ("shadowscan:provider", f.provider),
                ("shadowscan:account", f.account),
                ("shadowscan:region", f.region),
                ("shadowscan:owner", f.owner),
                ("shadowscan:shadow", f.shadow),
                ("shadowscan:registry-match", f.registry_match),
                ("shadowscan:heuristic-risk", f.risk.level.value),
                ("shadowscan:heuristic-risk-score", f.risk.score),
                ("shadowscan:confidence", f"{f.confidence:.2f}"),
                ("shadowscan:likelihood", f.likelihood.value),
                ("shadowscan:capabilities", f.capabilities),
                ("shadowscan:tags", f.tags),
                ("shadowscan:first-seen", _timestamp(f.first_seen)),
                ("shadowscan:last-seen", _timestamp(f.last_seen)),
            ]
        )
        self.components[ref] = component
        needs = self.dependencies.setdefault(ref, set())
        for sid in f.frameworks:
            needs.add(self.signature_component(sid))
        for sid in f.model_providers:
            needs.add(self.provider_service(sid))
        for model in f.models[:_MAX_MODELS]:
            if isinstance(model, str) and model:
                needs.add(self.model_component(model))
        if f.kind == Kind.MCP_SERVER:
            servers = f.metadata.get("servers")
            for server in servers[:_MAX_MCP_SERVERS] if isinstance(servers, list) else []:
                if isinstance(server, dict) and (service := self.mcp_service(f, server)):
                    needs.add(service)


def render_cyclonedx(result: ScanResult, index: SignatureIndex | None = None) -> str:
    """Render a scan result as a CycloneDX 1.6 JSON BOM."""
    for finding in result.findings:
        finding.sanitize()
    bom = _Bom(index or get_index())
    included = [f for f in result.findings if f.kind not in _EXCLUDED_KINDS]
    for f in sorted(included, key=lambda x: x.id):
        bom.add(f)
    excluded = len(result.findings) - len(included)
    stats = publication_stats(result)
    complete = result.complete
    seed = json.dumps([result.started_at, sorted(f.id for f in result.findings)])
    serial = uuid.uuid5(_SERIAL_NAMESPACE, seed)
    timestamp = _timestamp(result.finished_at) or _timestamp(result.started_at)
    metadata: dict[str, Any] = {
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "ShadowScan",
                    "version": __version__,
                    "externalReferences": [{"type": "vcs", "url": _PROJECT_URI}],
                }
            ]
        },
        "properties": _properties(
            [
                ("shadowscan:scan:status", "complete" if complete else "incomplete"),
                ("shadowscan:scan:findings", len(result.findings)),
                ("shadowscan:scan:credential-findings-excluded", excluded),
                ("shadowscan:scan:connectors", [s["connector"] for s in stats]),
                (
                    "shadowscan:scan:incomplete-connectors",
                    [
                        s["connector"]
                        for s in stats
                        if s.get("errors") or s.get("skipped") or s.get("incomplete")
                    ],
                ),
                ("shadowscan:scan:inventory-size", result.inventory_size),
            ]
        ),
    }
    if timestamp:
        metadata["timestamp"] = timestamp
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": [bom.components[k] for k in sorted(bom.components)],
        "services": [bom.services[k] for k in sorted(bom.services)],
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(needs)} for ref, needs in sorted(bom.dependencies.items())
        ],
        "compositions": [
            {
                "aggregate": "unknown" if complete else "incomplete",
                "assemblies": sorted(bom.components),
            }
        ],
    }
    if not document["services"]:
        del document["services"]
    # Findings were sanitized above; sanitize the assembled document as a whole
    # too, so a credential split across fields cannot survive publication.
    return json.dumps(sanitize(document), indent=2, allow_nan=False)
