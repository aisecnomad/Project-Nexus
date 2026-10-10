"""NuGuard AI-SBOM generation (static, no LLM enrichment)."""

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
    id="nuguard",
    name="NuGuard (sbom generate)",
    vendor="NuGuardAI",
    categories=frozenset({"framework", "provider", "mcp", "lowcode", "iac", "a2a"}),
    notes="nuguard sbom generate --no-llm --no-scan-images; summary.frameworks, deps purls and node names",
)


class NuGuardAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("nuguard") else "no 'bin' configured for nuguard"

    def version(self, cfg: ToolConfig) -> str:
        python = str(Path(cfg.binary("nuguard") or "nuguard").parent / "python")
        return python_package_version(python, "nuguard")

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        argv = (
            cfg.binary("nuguard") or "nuguard",
            "sbom",
            "generate",
            "-s",
            str(repo_dir),
            "-o",
            str(out_dir / "sbom.json"),
            "--no-llm",
            "--no-scan-images",
        )
        return [Command(argv)]

    def normalize(self, out_dir: Path) -> Normalized:
        data = load_json(out_dir / "sbom.json")
        if not isinstance(data, dict):
            return Normalized(error="sbom.json missing or malformed")
        result = Normalized()
        mapped: list[dict[str, Any]] = []
        raw_summary = data.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        for fw in summary.get("frameworks") or []:
            fw_facts = taxonomy.facts_from_name(str(fw))
            if fw_facts:
                mapped.append({"framework": str(fw), "facts": sorted(fw_facts)})
                result.facts.update(fw_facts)
        for dep in data.get("deps") or []:
            if not isinstance(dep, dict):
                continue
            result.raw_count += 1
            dep_facts = facts_from_purl(str(dep.get("purl", "")))
            if dep_facts:
                mapped.append({"dep": str(dep.get("name", "")), "facts": sorted(dep_facts)})
                result.facts.update(dep_facts)
        for node in data.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            result.raw_count += 1
            ctype = str(node.get("component_type", "")).upper()
            raw_meta = node.get("metadata")
            meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
            facts: set[str] = set()
            if ctype in {"MODEL", "LLM"}:
                facts.update(
                    f
                    for f in taxonomy.facts_from_name(str(node.get("name", "")))
                    if f.startswith("provider:")
                )
                facts.update(
                    f
                    for f in taxonomy.facts_from_name(str(meta.get("provider", "")))
                    if f.startswith("provider:")
                )
            if ctype in {"AGENT", "TOOL"}:
                facts.update(
                    f
                    for f in taxonomy.facts_from_name(str(meta.get("framework", "")))
                    if f.startswith("framework:")
                )
            if ctype in {"MCP_SERVER", "MCP", "MCP_CLIENT"} or "mcp" in str(meta.get("adapter", "")).lower():
                facts.add("mcp:sdk")
            if facts:
                mapped.append({"node": ctype, "name": str(node.get("name", ""))[:60], "facts": sorted(facts)})
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
