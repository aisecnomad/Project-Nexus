"""Cisco AI BOM: requires an LLM credential for every analysis, so it only runs when configured.

The benchmark run is deterministic and offline, so this adapter is skipped unless
``AIBOM_LLM_MODEL`` and the provider credential are supplied through the tool
configuration. Its normalization is best effort and untested against live output.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.discovery_benchmark import taxonomy
from tools.discovery_benchmark.adapters import (
    Command,
    Normalized,
    ToolConfig,
    ToolSpec,
    facts_from_purl,
    load_json,
    python_package_version,
)

SPEC = ToolSpec(
    id="cisco_aibom",
    name="Cisco AI BOM",
    vendor="Cisco AI Defense",
    categories=frozenset({"framework", "provider", "mcp", "a2a", "iac"}),
    notes="skipped unless an LLM model and credential are configured (the tool refuses to run without one)",
)


class CiscoAibomAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        if not cfg.binary("cisco_aibom"):
            return "no 'bin' configured for cisco_aibom"
        llm = cfg.tool("cisco_aibom").get("llm_model")
        if not isinstance(llm, str) or not llm:
            return "requires an LLM credential (tools.cisco_aibom.llm_model/llm_env); benchmark runs offline"
        return None

    def version(self, cfg: ToolConfig) -> str:
        python = str(Path(cfg.binary("cisco_aibom") or "cisco-aibom").parent / "python")
        return python_package_version(python, "cisco-aibom")

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        tool = cfg.tool("cisco_aibom")
        env = (
            {str(k): str(v) for k, v in (tool.get("llm_env") or {}).items()}
            if isinstance(tool.get("llm_env"), dict)
            else {}
        )
        argv = (
            cfg.binary("cisco_aibom") or "cisco-aibom",
            "analyze",
            str(repo_dir),
            "-o",
            "json",
            "-O",
            str(out_dir / "aibom.json"),
            "--llm-model",
            str(tool.get("llm_model", "")),
        )
        return [Command(argv, env=env)]

    def normalize(self, out_dir: Path) -> Normalized:
        data = load_json(out_dir / "aibom.json")
        if not isinstance(data, dict):
            return Normalized(error="aibom.json missing or malformed")
        result = Normalized()
        mapped: list[dict[str, Any]] = []
        components: list[Any] = []
        for key in ("components", "models", "agents", "tools", "mcp_servers", "mcp_clients", "frameworks"):
            value = data.get(key)
            if isinstance(value, list):
                components.extend((key, c) for c in value)
        for key, comp in components:
            if not isinstance(comp, dict):
                continue
            result.raw_count += 1
            facts: set[str] = set()
            facts.update(facts_from_purl(str(comp.get("purl", ""))))
            facts.update(taxonomy.facts_from_name(str(comp.get("name", ""))))
            if key.startswith("mcp"):
                facts.add("mcp:sdk")
            if facts:
                mapped.append(
                    {"section": key, "name": str(comp.get("name", ""))[:60], "facts": sorted(facts)}
                )
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
