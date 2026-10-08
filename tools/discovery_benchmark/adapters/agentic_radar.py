"""SplxAI Agentic Radar: per-framework static workflow scan."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.discovery_benchmark.adapters import (
    Command,
    Normalized,
    ToolConfig,
    ToolSpec,
    load_json,
    run_version,
)

SPEC = ToolSpec(
    id="agentic_radar",
    name="Agentic Radar",
    vendor="SplxAI",
    categories=frozenset({"framework", "mcp", "lowcode"}),
    notes="agentic-radar scan <framework> --export-graph-json for each supported framework; union of results",
)
FRAMEWORKS = {
    "langgraph": "framework:langgraph",
    "crewai": "framework:crewai",
    "n8n": "lowcode:n8n",
    "openai-agents": "framework:openai-agents",
    "autogen": "framework:autogen",
}


def _count_nodes(doc: Any) -> int:
    if isinstance(doc, dict):
        for key in ("nodes", "agents", "workflow", "graph"):
            value = doc.get(key)
            if isinstance(value, list) and value:
                return len(value)
            if isinstance(value, dict):
                inner = _count_nodes(value)
                if inner:
                    return inner
    if isinstance(doc, list):
        return len(doc)
    return 0


def _mentions_mcp(doc: Any) -> bool:
    text = str(doc).lower()
    return "mcp" in text


class AgenticRadarAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("agentic_radar") else "no 'bin' configured for agentic_radar"

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("agentic_radar") or "agentic-radar", "--version"], pattern=r"(\d+\.\d+\.\d+\S*)"
        )

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        binary = cfg.binary("agentic_radar") or "agentic-radar"
        return [
            Command(
                (
                    binary,
                    "scan",
                    fw,
                    "-i",
                    str(repo_dir),
                    "-o",
                    str(out_dir / f"{fw}.json"),
                    "--export-graph-json",
                ),
                ok_exit_codes=frozenset({0, 1}),
            )
            for fw in FRAMEWORKS
        ]

    def normalize(self, out_dir: Path) -> Normalized:
        result = Normalized()
        mapped: list[dict[str, Any]] = []
        for fw, fact in FRAMEWORKS.items():
            doc = load_json(out_dir / f"{fw}.json")
            if doc is None:
                continue
            nodes = _count_nodes(doc)
            if nodes:
                result.raw_count += nodes
                result.facts.add(fact)
                facts = {fact}
                if _mentions_mcp(doc):
                    result.facts.add("mcp:sdk")
                    facts.add("mcp:sdk")
                mapped.append({"framework": fw, "nodes": nodes, "facts": sorted(facts)})
        result.detail["mapped"] = mapped
        return result
