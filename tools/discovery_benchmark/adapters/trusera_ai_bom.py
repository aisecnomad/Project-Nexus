"""Trusera ai-bom (``ai-bom scan``)."""

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
    property_map,
    python_package_version,
)

SPEC = ToolSpec(
    id="trusera_ai_bom",
    name="Trusera ai-bom",
    vendor="Trusera",
    categories=frozenset({"framework", "provider", "mcp", "mcp-client-config", "a2a", "lowcode", "iac"}),
    notes="ai-bom scan --format json, default regex scanners (no --deep), telemetry off",
)
_IAC_BY_PROVIDER = {
    "aws bedrock": "iac:bedrock",
    "azure openai": "iac:azure-openai",
    "google vertex": "iac:vertex-ai",
    "google vertex ai": "iac:vertex-ai",
    "google dialogflow cx": "iac:dialogflow",
}


class TruseraAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("trusera_ai_bom") else "no 'bin' configured for trusera_ai_bom"

    def version(self, cfg: ToolConfig) -> str:
        python = str(Path(cfg.binary("trusera_ai_bom") or "ai-bom").parent / "python")
        return python_package_version(python, "ai-bom")

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        argv = (
            cfg.binary("trusera_ai_bom") or "ai-bom",
            "scan",
            str(repo_dir),
            "--format",
            "json",
            "-o",
            str(out_dir / "ai-bom.json"),
            "--quiet",
            "--no-telemetry",
            "--workers",
            "0",
        )
        return [Command(argv)]

    def normalize(self, out_dir: Path) -> Normalized:
        data = load_json(out_dir / "ai-bom.json")
        if not isinstance(data, dict) or not isinstance(data.get("components"), list):
            return Normalized(error="ai-bom.json missing or malformed")
        result = Normalized(raw_count=len(data["components"]))
        mapped: list[dict[str, Any]] = []
        for comp in data["components"]:
            if not isinstance(comp, dict):
                continue
            props = property_map(comp)
            name = str(comp.get("name", ""))
            source = props.get("trusera:source", "")
            provider = props.get("trusera:provider", "")
            location = props.get("trusera:source_location", "")
            facts: set[str] = set()
            purl = str(comp.get("purl", ""))
            facts.update(facts_from_purl(purl))
            if source == "mcp-config":
                facts.update(
                    f for f in taxonomy.facts_for_config_path(location) if f.startswith("mcp-client-config:")
                )
            elif source == "cloud":
                key = provider.lower().strip()
                fact = _IAC_BY_PROVIDER.get(key)
                if fact:
                    facts.add(fact)
                else:
                    facts.update(
                        f.replace("provider:", "iac:")
                        for f in taxonomy.facts_from_name(provider)
                        if f.startswith("provider:")
                    )
            elif source == "n8n":
                facts.add("lowcode:n8n")
            elif source == "model-files":
                pass
            else:
                facts.update(taxonomy.facts_from_name(name))
                if provider and provider.lower() not in {"unknown", "generic"}:
                    facts.update(f for f in taxonomy.facts_from_name(provider) if f.startswith("provider:"))
            if facts:
                mapped.append({"name": name, "source": source, "facts": sorted(facts)})
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
