"""SafeDep vet ``ai discover`` in project scope."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.discovery_benchmark import taxonomy
from tools.discovery_benchmark.adapters import (
    Command,
    Normalized,
    ToolConfig,
    ToolSpec,
    load_json,
    run_version,
)

SPEC = ToolSpec(
    id="vet",
    name="SafeDep vet (ai discover)",
    vendor="SafeDep",
    categories=frozenset({"mcp-client-config", "agent-config"}),
    notes="vet ai discover --scope project; reports project configs and MCP servers, no source analysis",
)
_PATH_KEYS = ("path", "file", "config_path", "config", "source", "location", "source_file")


class VetAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("vet") else "no 'bin' configured for vet"

    def version(self, cfg: ToolConfig) -> str:
        return run_version([cfg.binary("vet") or "vet", "version"], pattern=r"(v?\d+\.\d+\.\d+\S*)")

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        argv = (
            cfg.binary("vet") or "vet",
            "ai",
            "discover",
            "--scope",
            "project",
            "-D",
            str(repo_dir),
            "--report-json",
            str(out_dir / "vet.json"),
            "--silent",
        )
        return [Command(argv, cwd="repo", env={"VET_DISABLE_TELEMETRY": "true", "VET_TELEMETRY": "false"})]

    def normalize(self, out_dir: Path) -> Normalized:
        report = out_dir / "vet.json"
        if not report.exists() or report.read_text(encoding="utf-8", errors="replace").strip() in {
            "",
            "null",
            "[]",
        }:
            return Normalized()  # vet writes no, an empty or a null report when it finds nothing
        data = load_json(report)
        if data is None:
            return Normalized(error="vet.json malformed")
        items = data if isinstance(data, list) else [data]
        result = Normalized(raw_count=len(items))
        mapped: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            facts: set[str] = set()
            name = str(item.get("Name") or item.get("name") or "")
            app = str(item.get("App") or item.get("app") or "")
            paths: list[str] = []
            for key in ("ConfigPath", *_PATH_KEYS):
                value = item.get(key)
                if isinstance(value, str) and value:
                    paths.append(value)
            agent = item.get("Agent")
            if isinstance(agent, dict):
                for entry in agent.get("InstructionFiles") or []:
                    if isinstance(entry, str):
                        paths.append(entry)
            server = item.get("MCPServer")
            metadata = item.get("Metadata")
            for path in paths:
                facts.update(taxonomy.facts_for_config_path(path))
            if isinstance(metadata, dict) and any(str(k).startswith("skill.") for k in metadata):
                facts.add("agent-config:skills")
            if isinstance(server, dict) and server:
                if not any(f.startswith("mcp-client-config:") for f in facts):
                    facts.add("mcp-client-config:generic")
            elif isinstance(agent, dict) and not any(f.startswith("agent-config:") for f in facts):
                facts.add("agent-config:generic")
            if facts:
                mapped.append({"name": name, "app": app, "facts": sorted(facts)})
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
