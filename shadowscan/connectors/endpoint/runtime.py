"""Offline-first endpoint and runtime inventory connectors."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from itertools import islice
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.common import finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.redaction import sanitize_text

_MAX_LABEL = 160
_MAX_TOOLS = 500
_MAX_OTEL_SPANS = 100_000
_POISONING = re.compile(
    r"<\s*IMPORTANT\s*>|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"(?:exfiltrat|send|forward)\w*\s+(?:the\s+)?(?:data|secret|credential|prompt)|https?://",
    re.IGNORECASE,
)
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff\U000e0000-\U000e007f]")
_TOOL_REF = re.compile(r"\b(?:use|call|invoke)\s+the\s+[`\"']?([A-Za-z][\w.-]{0,63})", re.IGNORECASE)
_HOST = re.compile(
    r"(?:https?://)?[a-z0-9-]{1,63}\.(?:openai\.com|anthropic\.com|googleapis\.com)\b",
    re.IGNORECASE,
)


def _text(value: object, limit: int = _MAX_LABEL) -> str:
    if not isinstance(value, str):
        return ""
    return sanitize_text(value)[:limit]


def _sensitive_attribute(key: str) -> bool:
    normalized = key.casefold()
    return (
        normalized.startswith(("gen_ai.prompt", "gen_ai.completion", "llm.input", "llm.output"))
        or normalized.endswith(".content")
        or ".content." in normalized
    )


def _attrs(value: object, warn: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Convert OTLP attribute arrays or mappings into a small scalar mapping."""
    if isinstance(value, dict):
        if len(value) > 1000 and warn is not None:
            warn("gateway.otel: attribute limit reached")
        mapping_out: dict[str, Any] = {}
        for key, item in islice(value.items(), 1000):
            if not isinstance(key, str):
                if warn is not None:
                    warn("gateway.otel: malformed attribute key")
                continue
            if not _sensitive_attribute(key):
                mapping_out[key] = item
        return mapping_out
    if isinstance(value, list):
        list_out: dict[str, Any] = {}
        if len(value) > 1000 and warn is not None:
            warn("gateway.otel: attribute limit reached")
        for item in value[:1000]:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                if warn is not None:
                    warn("gateway.otel: malformed attribute")
                continue
            if _sensitive_attribute(item["key"]):
                continue
            raw = item.get("value")
            if isinstance(raw, dict):
                raw = next(iter(raw.values()), None)
            list_out[item["key"]] = raw
        return list_out
    if value is not None and warn is not None:
        warn("gateway.otel: malformed attributes")
    return {}


def _records(
    records: Iterable[dict[str, Any]], warn: Callable[[str], None] | None = None
) -> Iterator[dict[str, Any]]:
    """Yield bounded-enough dict records from standard nested telemetry envelopes."""
    span_count = 0
    for record in records:
        yield record
        spans = record.get("resourceSpans")
        if "resourceSpans" not in record:
            continue
        if not isinstance(spans, list):
            if warn is not None:
                warn("gateway.otel: malformed resource spans")
            continue
        if len(spans) > 1000 and warn is not None:
            warn("gateway.otel: resource span limit reached")
        for resource_span in spans[:1000]:
            if not isinstance(resource_span, dict):
                if warn is not None:
                    warn("gateway.otel: malformed resource span")
                continue
            raw_resource = resource_span.get("resource")
            if not isinstance(raw_resource, dict):
                if "resource" in resource_span and warn is not None:
                    warn("gateway.otel: malformed resource attributes")
                raw_resource = {}
            resource = _attrs(raw_resource.get("attributes"), warn)
            scopes = resource_span.get("scopeSpans")
            if not isinstance(scopes, list):
                if warn is not None:
                    warn("gateway.otel: malformed scope spans")
                continue
            if len(scopes) > 1000 and warn is not None:
                warn("gateway.otel: scope span limit reached")
            for scope in scopes[:1000]:
                if not isinstance(scope, dict) or not isinstance(scope.get("spans"), list):
                    if warn is not None:
                        warn("gateway.otel: malformed span collection")
                    continue
                if len(scope["spans"]) > 1000 and warn is not None:
                    warn("gateway.otel: span limit reached")
                for span in scope["spans"][:1000]:
                    if not isinstance(span, dict):
                        if warn is not None:
                            warn("gateway.otel: malformed span")
                        continue
                    if span_count >= _MAX_OTEL_SPANS:
                        if warn is not None:
                            warn("gateway.otel: aggregate span limit reached")
                        return
                    span_count += 1
                    yield {"resource": resource, **span}


class _EndpointConnector(BaseConnector):
    surface: ClassVar[Surface] = Surface.ENDPOINT
    offline_formats: ClassVar[str] = "JSON / JSONL / YAML export"

    def collect(self) -> Iterable[dict[str, Any]]:
        raise NotImplementedError("endpoint inventory requires offline input")

    def _finding(
        self,
        resource: str,
        resource_type: str,
        title: str,
        *,
        kind: Kind = Kind.AGENT,
        provider: str | None = None,
        tags: Iterable[str] = (),
        capabilities: Iterable[str] = (),
        metadata: dict[str, Any] | None = None,
        weight: float = 0.7,
    ) -> Finding:
        finding = Finding(
            surface=self.surface,
            connector=self.name,
            kind=kind,
            title=_text(title) or resource_type,
            resource=_text(resource) or "unknown",
            resource_type=resource_type,
            provider=provider,
            confidence=weight,
            capabilities=list(dict.fromkeys(capabilities)),
            tags=list(dict.fromkeys(tags)),
            metadata=metadata or {},
        )
        finding.add_evidence(
            Evidence(
                signal=f"{resource_type}:inventory",
                description=_text(title) or resource_type,
                weight=weight,
            )
        )
        self.ctx.examined()
        return finalize(finding, self.index)


class HostConnector(_EndpointConnector):
    name = "endpoint.host"
    provider = "host"
    description = "Offline host inventory of local AI agents, MCP clients, and model runtimes."
    config_keys = {"input": "Offline host inventory JSON, JSONL, or YAML export."}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            name = _text(record.get("name") or record.get("path") or record.get("process"))
            category = _text(record.get("type") or record.get("category") or "host-runtime")
            if not name:
                self.ctx.warn("endpoint.host: record has no runtime or configuration name")
                continue
            yield self._finding(
                name,
                category,
                f"Host AI runtime or client: {name}",
                provider=_text(record.get("provider")) or None,
                tags=("host-runtime",),
                metadata={"source": _text(record.get("source"))} if record.get("source") else {},
            )


class MCPInventoryConnector(_EndpointConnector):
    name = "endpoint.mcp"
    provider = "mcp"
    description = "Analyze offline MCP server tool, resource, and prompt inventory exports."
    config_keys = {
        "input": "Offline MCP list-responses JSON / JSONL export; live probes require explicit opt-in."
    }

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        names_by_server: dict[str, set[str]] = defaultdict(set)
        server_auth: dict[str, str] = {}
        server_tls: dict[str, bool] = {}
        staged: list[tuple[str, dict[str, Any]]] = []
        count = 0
        limit_hit = False
        for record in records:
            server = _text(record.get("server") or record.get("name") or record.get("url"))
            if not server:
                self.ctx.warn("endpoint.mcp: record has no server identifier")
                continue
            auth = record.get("auth") or record.get("auth_mode")
            server_auth[server] = _text(auth).casefold() if isinstance(auth, str) else ""
            endpoint = _text(record.get("url") or server).lower()
            server_tls[server] = endpoint.startswith("https://")
            tools = record.get("tools", [])
            if not isinstance(tools, list):
                self.ctx.warn("endpoint.mcp: malformed tools list")
                continue
            if len(tools) > _MAX_TOOLS:
                self.ctx.warn("endpoint.mcp: tool limit reached")
                tools = tools[:_MAX_TOOLS]
            for tool in tools:
                if not isinstance(tool, dict):
                    self.ctx.warn("endpoint.mcp: malformed tool definition")
                    continue
                if count >= _MAX_TOOLS:
                    self.ctx.warn("endpoint.mcp: aggregate tool limit reached")
                    limit_hit = True
                    break
                count += 1
                name = _text(tool.get("name"))
                if not name:
                    self.ctx.warn("endpoint.mcp: tool has no valid name")
                    continue
                if name:
                    names_by_server[server].add(name.casefold())
                staged.append((server, tool))
            if limit_hit:
                break

        for server, tool in staged:
            name = _text(tool.get("name")) or "unnamed-tool"
            desc = _text(tool.get("description"), 4096)
            tags: list[str] = []
            if (
                _POISONING.search(desc)
                or _ZERO_WIDTH.search(desc)
                or _TOOL_REF.search(desc)
                or _HOST.search(desc)
            ):
                tags.append("tool-poisoning")
            if any(name.casefold() in tools for other, tools in names_by_server.items() if other != server):
                tags.append("tool-name-shadowing")
            auth = _text(tool.get("auth") or tool.get("auth_mode")).casefold() or server_auth.get(server, "")
            if auth in {"", "none", "unauthenticated"}:
                tags.append("unauthenticated-mcp")
            words = set(re.findall(r"[a-z]+", name.casefold()))
            capabilities = []
            if words & {"exec", "execute", "shell", "command", "terminal"}:
                capabilities.append("code-exec")
            if words & {"file", "read", "write", "directory", "filesystem"}:
                capabilities.append("data-access")
            if words & {"fetch", "http", "web", "search", "browser"}:
                capabilities.append("browsing")
            if words & {"slack", "email", "ticket", "issue", "send", "publish"}:
                capabilities.append("saas-actions")
            yield self._finding(
                f"{server}/{name}",
                "mcp-tool",
                f"MCP tool {name} on {_text(server)}",
                kind=Kind.MCP_SERVER,
                tags=tags,
                capabilities=capabilities,
                metadata={
                    "server": server,
                    "tool": name,
                    "tool_definition_sha256": hashlib.sha256(
                        json.dumps(tool, sort_keys=True, separators=(",", ":"), default=str).encode()
                    ).hexdigest(),
                    "tls": server_tls.get(
                        server, _text(tool.get("url") or server).lower().startswith("https://")
                    ),
                },
                weight=0.8 if tags else 0.65,
            )


class OtelConnector(_EndpointConnector):
    name = "gateway.otel"
    surface = Surface.GATEWAY
    provider = "opentelemetry"
    description = "Aggregate OpenTelemetry GenAI span exports without retaining prompt content."
    config_keys = {"input": "Offline OTLP JSON / JSONL span export."}
    uses_run_identity_key = True

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for record in _records(records, self.ctx.warn):
            attrs = _attrs(record.get("attributes"), self.ctx.warn)
            resource = record.get("resource")
            if isinstance(resource, dict):
                attrs = {**_attrs(resource.get("attributes"), self.ctx.warn), **attrs}
            service = _text(attrs.get("service.name") or record.get("serviceName") or "unknown-service")
            agent = _text(attrs.get("gen_ai.agent.name") or attrs.get("agent.name") or service)
            model = _text(attrs.get("gen_ai.request.model") or attrs.get("llm.request.model"))
            system = _text(attrs.get("gen_ai.system") or attrs.get("llm.provider"))
            if not (model or system or "gen_ai.operation.name" in attrs or "llm.operation.name" in attrs):
                continue
            key = (service, agent, system or "unknown")
            aggregate = groups.setdefault(key, {"models": set(), "operations": set(), "count": 0})
            if model:
                aggregate["models"].add(model)
            op = _text(attrs.get("gen_ai.operation.name") or attrs.get("llm.operation.name"))
            if op:
                aggregate["operations"].add(op)
            aggregate["count"] += 1
            self.ctx.examined()
        for (service, agent, provider), aggregate in groups.items():
            models = sorted(aggregate["models"])[:100]
            yield self._finding(
                f"service:{service}/agent:{agent}",
                "gateway-caller",
                f"Observed GenAI caller {agent} ({service})",
                kind=Kind.GATEWAY_CALLER,
                provider=provider,
                metadata={"models": models, "span_count": aggregate["count"]},
                weight=0.75,
            )


class OllamaConnector(_EndpointConnector):
    name = "endpoint.ollama"
    provider = "ollama"
    description = "Inventory local LLM server and model exports."
    config_keys = {"input": "Offline /api/version, /api/tags, /api/ps JSON export."}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            models = record.get("models")
            if not isinstance(models, list):
                if "models" in record:
                    self.ctx.warn("endpoint.ollama: malformed model inventory")
                    continue
                if any(key in record for key in ("version", "processes")):
                    models = []
                else:
                    self.ctx.warn("endpoint.ollama: malformed model inventory")
                    continue
            if len(models) > 500:
                self.ctx.warn("endpoint.ollama: model limit reached")
            endpoint = _text(record.get("endpoint") or record.get("url") or "local Ollama")
            tags = ["local-llm-runtime"]
            host = _text(record.get("host") or record.get("endpoint") or record.get("url")).lower()
            if host and not any(x in host for x in ("localhost", "127.0.0.1", "::1")):
                tags.append("exposed-llm-server")
            for model in models[:500]:
                if not isinstance(model, dict):
                    self.ctx.warn("endpoint.ollama: malformed model entry")
                    continue
                model_name = _text(model.get("name") or model.get("model"))
                if not model_name:
                    continue
                yield self._finding(
                    f"{endpoint}/model/{model_name}",
                    "local-model",
                    f"Local LLM model {model_name}",
                    provider="ollama",
                    tags=tags,
                    metadata={"size": model["size"]} if type(model.get("size")) is int else {},
                    weight=0.75,
                )
            self.ctx.examined()


class ModelArtifactConnector(_EndpointConnector):
    name = "endpoint.models"
    provider = "local-model"
    description = "Analyze bounded metadata exports for local model artifacts."
    config_keys = {
        "input": "Offline artifact metadata JSON / JSONL; only GGUF header metadata should be exported.",
    }

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            raw_path = record.get("path") or record.get("name")
            path = sanitize_text(raw_path) if isinstance(raw_path, str) else ""
            if not path:
                self.ctx.warn("endpoint.models: artifact record has no path")
                continue
            extension = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            tags = ["local-model-artifact"]
            if extension in {"pt", "bin", "pkl", "pickle"}:
                tags.append("unsafe-serialization")
            meta = record.get("metadata")
            metadata: dict[str, Any] = {"format": extension}
            if isinstance(meta, dict):
                metadata.update(
                    {
                        key: _text(meta[key])
                        for key in ("general.architecture", "general.name", "general.license")
                        if isinstance(meta.get(key), str)
                    }
                )
            elif meta is not None:
                self.ctx.warn("endpoint.models: malformed artifact metadata")
            size = record.get("size")
            if type(size) is int and 0 <= size < 2**63:
                metadata["size"] = size
            elif size is not None:
                self.ctx.warn("endpoint.models: malformed artifact size")
            digest = record.get("sha256")
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                metadata["sha256"] = digest.lower()
            elif digest is not None:
                self.ctx.warn("endpoint.models: malformed artifact digest")
            yield self._finding(
                path,
                "model-artifact",
                f"Local model artifact {path.rsplit('/', 1)[-1]}",
                tags=tags,
                metadata=metadata,
                weight=0.8,
            )


class EbpfConnector(_EndpointConnector):
    name = "endpoint.ebpf"
    provider = "runtime-telemetry"
    description = "Correlate offline eBPF runtime events with known AI hosts and local model ports."
    config_keys = {"input": "Offline Tetragon, Falco, Tracee, or Hubble JSON / JSONL export."}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            serialized = " ".join(
                _text(record.get(key), 512)
                for key in ("destination", "remote_addr", "hostname", "server.address", "url")
            )
            process = record.get("process")
            if isinstance(process, dict):
                serialized += " " + _text(process.get("binary") or process.get("name"))
            else:
                if process is not None:
                    self.ctx.warn("endpoint.ebpf: malformed process")
                serialized += " " + _text(record.get("binary") or record.get("process_name"))
            lower = serialized.lower()
            port = str(record.get("port") or record.get("destination_port") or "")
            tags = []
            if _HOST.search(serialized) or any(host in lower for host in ("openai", "anthropic", "ollama")):
                tags.append("llm-egress")
            if port in {"11434", "1234", "8080", "8000"}:
                tags.append("local-llm-traffic")
            if not tags:
                self.ctx.examined()
                continue
            pod = _text(record.get("pod") or record.get("pod_name"))
            ns = _text(record.get("namespace"))
            process_binary = (
                process.get("binary") or process.get("name") if isinstance(process, dict) else None
            )
            binary = _text(process_binary or record.get("binary") or record.get("process_name"))
            binary = binary or "runtime-process"
            yield self._finding(
                f"{ns}/{pod}/{binary}".strip("/"),
                "runtime-process",
                f"Runtime process {binary} communicated with an AI service",
                tags=tags,
                metadata={"namespace": ns, "pod": pod} if pod or ns else {},
                weight=0.75,
            )
