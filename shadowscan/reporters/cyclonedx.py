"""CycloneDX 1.6 JSON output: the scan as an AI bill of materials.

Each finding becomes one entry whose ``bom-ref`` is the finding id:

* a model artifact or model store (``local-model`` findings, ``endpoint.models``,
  the models ``endpoint.ollama`` lists) is a ``machine-learning-model`` component;
* an MCP configuration or inventory (``mcp-server`` findings, ``endpoint.mcp``)
  or another ``endpoint.ollama`` finding is a ``service``;
* everything else (agents, agent configurations, AI apps, callers, network
  contacts, running processes) is an ``application`` component.

What a finding is built with or talks to becomes a shared entry that it
depends on:

* agent frameworks, coding agents and protocols are ``framework`` components;
* model providers are ``services``;
* concrete model ids are ``machine-learning-model`` components;
* MCP servers listed by an MCP configuration are ``services``;
* the MCP server a project implements (a finding with the ``mcp-server``
  capability, from ``metadata.mcp_server`` and ``metadata.mcp_tools``) is a
  ``service`` in group ``mcp-server`` that the application depends on.

Credential findings (``secret`` and ``token``) are not components: a BOM is an
inventory, and the JSON or SARIF report is the place to triage credentials.
ShadowScan's heuristic risk, confidence and shadow status are recorded as
``shadowscan:*`` properties, never as CycloneDX vulnerabilities or ratings,
and so are its edition-qualified threat and control references
(``shadowscan:threats``, ``shadowscan:controls``): evidence references, not
compliance results.

A BOM never reads as more complete than the scan: ``compositions`` declares
the inventory ``incomplete`` when any connector failed or stopped early, and
``unknown`` otherwise, because a complete scan still covers only the
configured sources. A finding whose MCP servers, models, server endpoints,
implemented-server tools or files exceed the per-entry bounds, or that lists
a malformed server entry, is named in a further ``incomplete`` composition.
The output is deterministic for a given result, and every ``bom-ref`` is unique.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from shadowscan import __version__
from shadowscan.mappings import finding_references
from shadowscan.models import DERIVED_METADATA_KEYS, Finding, Kind, ScanResult
from shadowscan.reporters._publication import publication_stats
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.utils.redaction import sanitize

_PROJECT_URI = "https://github.com/aisecnomad/Project-Nexus"
_EXCLUDED_KINDS = {Kind.SECRET, Kind.TOKEN}
_MAX_MCP_SERVERS = 50
_MAX_MODELS = 20
_MAX_ENDPOINTS = 5
_MAX_MCP_TOOLS = 20  # tools of an implemented server
_MAX_MCP_FILES = 10  # files that construct it
_SERIAL_NAMESPACE = uuid.UUID("6f1c3c56-2a52-5b8e-9a0e-5c7d4f1e2b10")
_SERVICE_CONNECTORS = {"endpoint.mcp", "endpoint.ollama"}
_MODEL_CONNECTORS = {"endpoint.models"}
# Shared entries live under this prefix; a finding id that takes it gets a digest ref instead.
_SHARED = "shadowscan:"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _finding_digest(f: Finding) -> str:
    record = f.to_dict()
    # Threat and control references follow the packaged catalogs, not the finding.
    for key in DERIVED_METADATA_KEYS:
        record["metadata"].pop(key, None)
    return _digest(json.dumps(record, sort_keys=True, default=str))


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


def _http_url(value: object) -> bool:
    """An http or https URL; the scheme is compared case-insensitively."""
    if not isinstance(value, str):
        return False
    try:
        return urlsplit(value.strip()).scheme.lower() in {"http", "https"}
    except ValueError:
        return False


def _text(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    return value if isinstance(value, str) else None


def _published(entry: dict[str, Any]) -> dict[str, Any]:
    """Sanitize one entry on its own (a whole BOM can exceed the sanitizer's node bound).

    The ``bom-ref`` is generated here or is an already sanitized finding id, and
    must stay byte-identical so dependencies and compositions still resolve.
    """
    ref = entry.get("bom-ref")
    body = sanitize({k: v for k, v in entry.items() if k != "bom-ref"})
    return {"bom-ref": ref, **body} if ref is not None else dict(body)


class _Bom:
    def __init__(self, index: SignatureIndex) -> None:
        self.index = index
        self.components: dict[str, dict[str, Any]] = {}
        self.finding_services: dict[str, dict[str, Any]] = {}
        self.services: dict[str, dict[str, Any]] = {}
        self.dependencies: dict[str, set[str]] = {}
        self.truncated: list[str] = []
        self.used: set[str] = set()

    def finding_ref(self, f: Finding) -> str:
        """The finding id when it is usable and unique, else a stable digest ref."""
        ref = f.id if isinstance(f.id, str) and f.id and not f.id.startswith(_SHARED) else ""
        if not ref or ref in self.used:
            base = f"{_SHARED}finding:{_finding_digest(f)}"
            ref, n = base, 1
            while ref in self.used:
                n += 1
                ref = f"{base}-{n}"
        self.used.add(ref)
        return ref

    def _technology(self, f: Finding, sid: str) -> dict[str, str]:
        """Name, vendor and category as the scan's own index recorded them (custom packs included)."""
        recorded = f.metadata.get("technologies")
        for tech in recorded if isinstance(recorded, list) else []:
            if isinstance(tech, dict) and tech.get("id") == sid:
                return {k: str(v) for k, v in tech.items() if isinstance(v, str) and v}
        sig = self.index.get(sid)
        if sig is None:
            return {"id": sid, "name": sid}
        return {"id": sid, "name": sig.name, "category": sig.category, "vendor": sig.vendor or ""}

    def signature_component(self, f: Finding, sid: str) -> str:
        ref = f"{_SHARED}framework:{sid}"
        if ref not in self.components:
            tech = self._technology(f, sid)
            sig = self.index.get(sid)
            component: dict[str, Any] = {"type": "framework", "bom-ref": ref, "name": tech.get("name", sid)}
            if tech.get("vendor"):
                component["publisher"] = tech["vendor"]
            if sig is not None and sig.description:
                component["description"] = sig.description
            if sig is not None and sig.homepage:
                component["externalReferences"] = [{"type": "website", "url": sig.homepage}]
            component["properties"] = _properties(
                [("shadowscan:signature", sid), ("shadowscan:category", tech.get("category"))]
            )
            self.components[ref] = component
        return ref

    def provider_service(self, f: Finding, sid: str) -> str:
        ref = f"{_SHARED}provider:{sid}"
        if ref not in self.services:
            tech = self._technology(f, sid)
            sig = self.index.get(sid)
            # No trust zone: a provider id names hosted APIs and local runtimes alike.
            service: dict[str, Any] = {"bom-ref": ref, "name": tech.get("name", sid)}
            if tech.get("vendor"):
                service["provider"] = {"name": tech["vendor"]}
            if sig is not None and sig.homepage:
                service["externalReferences"] = [{"type": "website", "url": sig.homepage}]
            service["properties"] = _properties([("shadowscan:signature", sid)])
            self.services[ref] = service
        return ref

    def model_component(self, model: str) -> str:
        ref = f"{_SHARED}model:{_digest(model)}"
        if ref not in self.components:
            self.components[ref] = {"type": "machine-learning-model", "bom-ref": ref, "name": model}
        return ref

    def mcp_service(self, owner_ref: str, position: int, server: dict[str, Any]) -> tuple[str, bool]:
        """The service ref for one listed server, and whether its endpoints were capped."""
        name = server.get("name")
        if not isinstance(name, str) or not name:
            # A configuration can key a server by an empty name; it is still a server.
            name = f"(unnamed MCP server #{position + 1})"
        # The position keeps same-named servers from two files apart.
        ref = f"{_SHARED}mcp:{_digest(json.dumps([owner_ref, position, name]))}"
        service: dict[str, Any] = {"bom-ref": ref, "name": name, "group": "mcp-server"}
        urls = server.get("urls")
        urls = urls if isinstance(urls, list) else [server.get("url")]
        endpoints = [u.strip() for u in urls if _http_url(u)]
        endpoints_omitted = max(0, len(endpoints) - _MAX_ENDPOINTS)
        if endpoints:
            service["endpoints"] = endpoints[:_MAX_ENDPOINTS]
        risks = server.get("risks")
        risk_ids = [
            r if isinstance(r, str) else r.get("id")
            for r in (risks if isinstance(risks, list) else [])
            if isinstance(r, (str, dict))
        ]
        disabled = server.get("disabled")
        service["properties"] = _properties(
            [
                ("shadowscan:mcp:transport", _text(server, "transport")),
                ("shadowscan:mcp:command", _text(server, "command")),
                ("shadowscan:mcp:file", _text(server, "location")),
                ("shadowscan:mcp:disabled", disabled if isinstance(disabled, bool) else None),
                ("shadowscan:mcp:risks", [r for r in risk_ids if isinstance(r, str)]),
                ("shadowscan:mcp:endpoints-omitted", endpoints_omitted or None),
            ]
        )
        self.services[ref] = service
        return ref, bool(endpoints_omitted)

    def implemented_mcp_service(self, owner_ref: str, f: Finding) -> tuple[str, bool]:
        """The service ref for the MCP server ``f`` implements, and whether its lists were capped.

        A project that exposes tools over MCP stays an ``application`` component
        (its frameworks and providers stay its dependencies); the server it
        provides is published as a service of its own that it depends on.
        """
        ref = f"{_SHARED}mcp-server:{_digest(json.dumps([owner_ref]))}"
        service: dict[str, Any] = {
            "bom-ref": ref,
            "name": f.title or f.resource or "implemented MCP server",
            "group": "mcp-server",
        }
        details = f.metadata.get("mcp_server")
        details = details if isinstance(details, dict) else {}
        languages = details.get("languages")
        languages = [x for x in languages if isinstance(x, str)] if isinstance(languages, list) else []
        transports = details.get("transports")
        transports = [x for x in transports if isinstance(x, str)] if isinstance(transports, list) else []
        constructions = details.get("constructions")
        files: list[str] = []
        for construction in constructions if isinstance(constructions, list) else []:
            location = construction.get("file") if isinstance(construction, dict) else None
            if isinstance(location, str) and location and location not in files:
                files.append(location)
        tools = f.metadata.get("mcp_tools")
        tools = [t for t in tools if isinstance(t, str) and t] if isinstance(tools, list) else []
        tools_omitted = max(0, len(tools) - _MAX_MCP_TOOLS)
        files_omitted = max(0, len(files) - _MAX_MCP_FILES)
        service["properties"] = _properties(
            [
                ("shadowscan:mcp:implementation", "source"),
                ("shadowscan:mcp:languages", languages),
                # One known transport names the server's; several are left to the finding.
                ("shadowscan:mcp:transport", transports[0] if len(transports) == 1 else None),
                ("shadowscan:mcp:tools", tools[:_MAX_MCP_TOOLS]),
                ("shadowscan:mcp:tools-omitted", tools_omitted or None),
                ("shadowscan:mcp:files", files[:_MAX_MCP_FILES]),
                ("shadowscan:mcp:files-omitted", files_omitted or None),
            ]
        )
        self.services[ref] = service
        return ref, bool(tools_omitted or files_omitted)

    def add(self, f: Finding) -> None:
        ref = self.finding_ref(f)
        entry: dict[str, Any] = {
            "bom-ref": ref,
            "name": f.title or f.resource or "discovered AI component",
            "group": f.surface.value,
            "description": f"{f.kind.value} discovered by {f.connector}",
        }
        is_model = (
            f.kind == Kind.LOCAL_MODEL or f.connector in _MODEL_CONNECTORS or f.resource_type == "local-model"
        )
        is_service = not is_model and (f.kind == Kind.MCP_SERVER or f.connector in _SERVICE_CONNECTORS)
        if not is_service:
            entry = {"type": "machine-learning-model" if is_model else "application", **entry}
            if f.owner:
                entry["authors"] = [{"name": f.owner}]
        servers = f.metadata.get("servers") if f.kind == Kind.MCP_SERVER else None
        servers = servers if isinstance(servers, list) else []
        models = [m for m in f.models if isinstance(m, str) and m]
        kept = servers[:_MAX_MCP_SERVERS]
        # Entries past the bound, and malformed entries within it, are not published.
        servers_omitted = len(servers) - len(kept) + sum(not isinstance(s, dict) for s in kept)
        models_omitted = max(0, len(models) - _MAX_MODELS)
        threats, controls = finding_references(f)
        entry["properties"] = _properties(
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
                ("shadowscan:threats", threats),
                ("shadowscan:controls", controls),
                ("shadowscan:first-seen", _timestamp(f.first_seen)),
                ("shadowscan:last-seen", _timestamp(f.last_seen)),
                ("shadowscan:mcp:servers-omitted", servers_omitted or None),
                ("shadowscan:models-omitted", models_omitted or None),
            ]
        )
        if is_service:
            self.finding_services[ref] = entry
        else:
            self.components[ref] = entry
        needs = self.dependencies.setdefault(ref, set())
        for sid in f.frameworks:
            needs.add(self.signature_component(f, sid))
        for sid in f.model_providers:
            needs.add(self.provider_service(f, sid))
        for model in models[:_MAX_MODELS]:
            needs.add(self.model_component(model))
        endpoints_capped = False
        for position, server in enumerate(kept):
            if isinstance(server, dict):
                service, capped = self.mcp_service(ref, position, server)
                needs.add(service)
                endpoints_capped = endpoints_capped or capped
        lists_capped = False
        if f.kind != Kind.MCP_SERVER and "mcp-server" in f.capabilities:
            service, lists_capped = self.implemented_mcp_service(ref, f)
            needs.add(service)
        if servers_omitted or models_omitted or endpoints_capped or lists_capped:
            self.truncated.append(ref)


def render_cyclonedx(result: ScanResult, index: SignatureIndex | None = None) -> str:
    """Render a scan result as a CycloneDX 1.6 JSON BOM."""
    for finding in result.findings:
        finding.sanitize()
    bom = _Bom(index or get_index())
    included = [f for f in result.findings if f.kind not in _EXCLUDED_KINDS]
    for f in sorted(included, key=lambda x: (x.id or "", _finding_digest(x))):
        bom.add(f)
    excluded = len(result.findings) - len(included)
    stats = publication_stats(result)
    complete = result.complete
    seed = json.dumps([result.started_at, sorted(sorted(bom.used), key=str)])
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
                ("shadowscan:bom:truncated-findings", len(bom.truncated) or None),
            ]
        ),
    }
    if timestamp:
        metadata["timestamp"] = timestamp
    compositions: list[dict[str, Any]] = [
        {
            "aggregate": "unknown" if complete else "incomplete",
            "assemblies": sorted(bom.components) + sorted(bom.finding_services),
        }
    ]
    if bom.truncated:
        compositions.append({"aggregate": "incomplete", "dependencies": sorted(bom.truncated)})
    services = [bom.finding_services[k] for k in sorted(bom.finding_services)] + [
        bom.services[k] for k in sorted(bom.services)
    ]
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": _published(metadata),
        "components": [_published(bom.components[k]) for k in sorted(bom.components)],
        # Findings that are services first, then the providers and servers they use.
        "services": [_published(s) for s in services],
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(needs)} for ref, needs in sorted(bom.dependencies.items())
        ],
        "compositions": compositions,
    }
    if not document["services"]:
        del document["services"]
    refs = [e["bom-ref"] for e in document["components"] + document.get("services", [])]
    # Guarded by finding_ref; fail closed if that ever breaks.
    if len(refs) != len(set(refs)):  # pragma: no cover
        raise ValueError("CycloneDX bom-refs are not unique")
    return json.dumps(document, indent=2, allow_nan=False)
