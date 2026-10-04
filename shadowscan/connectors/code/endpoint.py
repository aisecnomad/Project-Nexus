"""Opt-in endpoint inventory for coding agents, MCP configs, Ollama, and GGUF files."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import apply_matches, finalize, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface

_MCP_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
_AGENT_DIRS = {".claude", ".cursor", ".continue", ".windsurf", ".codex", ".gemini"}
_MAX_FILES = 20000


class EndpointConnector(BaseConnector):
    name: ClassVar[str] = "code.endpoint"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "endpoint"
    description: ClassVar[str] = (
        "Local endpoint inventory of MCP client configs, coding-agent directories, "
        "Ollama manifests, and GGUF model files. Opt-in path walk or offline export."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "path": "live: directory to walk (required for live mode)",
        "input": "offline: JSON/JSONL inventory of path, kind, name",
        "max_files": "maximum files examined (default 20000)",
    }
    offline_formats: ClassVar[str] = "JSON/JSONL endpoint inventory"

    @classmethod
    def scanned_local_paths(cls, config: dict[str, Any]) -> list[str]:
        path = config.get("path")
        return [str(path)] if path and not config.get("input") else []

    def collect(self) -> Iterable[dict[str, Any]]:
        root = self.ctx.get("path")
        if not root:
            raise ConnectorError(f"{self.name}: live mode needs path, or set input for an offline export")
        limit = int(self.ctx.get("max_files") or _MAX_FILES)
        examined = 0
        base = Path(str(root))
        if not base.is_dir():
            raise ConnectorError(f"{self.name}: path is not a directory")
        for dirpath, dirnames, filenames in os.walk(base):
            self.ctx.check_deadline()
            dirnames[:] = [name for name in dirnames if name not in {".git", "node_modules", ".venv"}]
            current = Path(dirpath)
            if current.name in _AGENT_DIRS:
                yield {"kind": "coding-agent", "name": current.name, "path": str(current)}
            for filename in filenames:
                examined += 1
                if examined > limit:
                    self.ctx.warn(f"file limit {limit} reached")
                    return
                path = current / filename
                lower = filename.lower()
                if filename in _MCP_NAMES or lower.endswith(".mcp.json"):
                    yield {"kind": "mcp-config", "name": filename, "path": str(path)}
                elif lower.endswith(".gguf"):
                    yield {"kind": "gguf", "name": filename, "path": str(path)}
                elif filename in {"Modelfile", "ollama.json"}:
                    yield {"kind": "ollama", "name": filename, "path": str(path)}

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        yield from super().load_offline(path)

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            self.ctx.examined()
            kind = str(record.get("kind") or "endpoint")
            name = str(record.get("name") or "unknown")
            location = str(record.get("path") or name)
            finding_kind = Kind.MCP_SERVER if kind == "mcp-config" else Kind.AGENT_CONFIG
            if kind == "gguf":
                finding_kind = Kind.INFRA
            finding = Finding(
                surface=self.surface,
                connector=self.name,
                kind=finding_kind,
                title=f"Endpoint {kind}: {name}",
                resource=f"endpoint:{kind}:{location}",
                resource_type=kind,
                provider=self.provider,
            )
            weight = 0.9 if kind in {"mcp-config", "gguf"} else 0.7
            finding.add_evidence(
                Evidence(
                    signal=f"endpoint:{kind}",
                    description=f"{kind} observed at {name}",
                    location=location,
                    weight=weight,
                )
            )
            if kind == "gguf":
                finding.add_model_provider("provider.llama-cpp")
                finding.add_tag("gguf")
            if kind == "ollama":
                finding.add_model_provider("provider.ollama")
            if kind == "mcp-config":
                finding.add_tag("mcp")
            apply_matches(finding, name_matches(self.index, name, kind), location=location)
            yield finalize(finding, self.index)
