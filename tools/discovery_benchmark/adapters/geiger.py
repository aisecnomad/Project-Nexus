"""Atomburst Geiger: project-level agent and MCP configuration inventory."""

from __future__ import annotations

import json
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
    id="geiger",
    name="Geiger",
    vendor="Atomburst",
    categories=frozenset({"mcp-client-config", "agent-config", "mcp"}),
    notes="geiger --path <repo> --home <empty home> --json; reads configs only",
)
_KIND_FACTS = {
    "skill": "agent-config:skills",
    "subagent": "agent-config:claude-dir",
    "hook": "agent-config:claude-dir",
    "plugin": "agent-config:claude-dir",
}


class GeigerAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("geiger") else "no 'bin' configured for geiger"

    def version(self, cfg: ToolConfig) -> str:
        binary = Path(cfg.binary("geiger") or "geiger")
        try:
            package = binary.resolve().parent.parent / "package.json"
            data = json.loads(package.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("version"), str):
                return str(data["version"])
        except (OSError, json.JSONDecodeError):
            pass
        return run_version([str(binary), "--version"], pattern=r"(\d+\.\d+\.\d+\S*)")

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        argv = (
            cfg.binary("geiger") or "geiger",
            "--path",
            str(repo_dir),
            "--home",
            cfg.setting("empty_home", "/nonexistent"),
            "--json",
            str(out_dir / "geiger.json"),
        )
        return [Command(argv, ok_exit_codes=frozenset({0, 2}))]

    def normalize(self, out_dir: Path) -> Normalized:
        if not (out_dir / "geiger.json").exists():
            return Normalized()
        data = load_json(out_dir / "geiger.json")
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            return Normalized(error="geiger.json malformed")
        result = Normalized(raw_count=len(data["findings"]))
        mapped: list[dict[str, Any]] = []
        for finding in data["findings"]:
            if not isinstance(finding, dict):
                continue
            facts: set[str] = set()
            kind = str(finding.get("kind", ""))
            files = [str(e.get("file", "")) for e in finding.get("evidence") or [] if isinstance(e, dict)]
            for path in files:
                facts.update(taxonomy.facts_for_config_path(path))
            if kind == "mcp-server":
                if not any(f.startswith("mcp-client-config:") for f in facts):
                    facts.add("mcp-client-config:generic")
            elif kind in _KIND_FACTS and not any(f.startswith("agent-config:") for f in facts):
                facts.add(_KIND_FACTS[kind])
            if facts:
                mapped.append(
                    {"kind": kind, "name": str(finding.get("name", ""))[:80], "facts": sorted(facts)}
                )
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
