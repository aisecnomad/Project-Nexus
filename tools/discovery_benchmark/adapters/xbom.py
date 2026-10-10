"""SafeDep xbom: static AI-component BOM from source code."""

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
    id="xbom",
    name="SafeDep xbom",
    vendor="SafeDep",
    categories=frozenset({"framework", "provider", "mcp", "a2a"}),
    notes="xbom generate --bom (source-code analysis); telemetry disabled by environment",
)


class XbomAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("xbom") else "no 'bin' configured for xbom"

    def version(self, cfg: ToolConfig) -> str:
        return run_version([cfg.binary("xbom") or "xbom", "version"], pattern=r"version:\s*(v?\d[\w.-]*)")

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        argv = (
            cfg.binary("xbom") or "xbom",
            "generate",
            "-D",
            str(repo_dir),
            "--bom",
            str(out_dir / "xbom.json"),
        )
        return [Command(argv, env={"XBOM_DISABLE_TELEMETRY": "true"})]

    def normalize(self, out_dir: Path) -> Normalized:
        data = load_json(out_dir / "xbom.json")
        if not isinstance(data, dict):
            return Normalized(error="xbom.json missing or malformed")
        components = data.get("components") or []
        result = Normalized(raw_count=len(components))
        mapped: list[dict[str, Any]] = []
        for comp in components:
            if not isinstance(comp, dict):
                continue
            facts: set[str] = set()
            ref = str(comp.get("bom-ref", ""))
            name = str(comp.get("name", ""))
            manufacturer = comp.get("manufacturer")
            vendor = str(manufacturer.get("name", "")) if isinstance(manufacturer, dict) else ""
            facts.update(taxonomy.facts_for("pyimport", ref))
            facts.update(taxonomy.facts_for("jsimport", ref))
            facts.update(taxonomy.facts_for("goimport", ref))
            facts.update(taxonomy.facts_for("javaimport", ref))
            facts.update(taxonomy.facts_from_name(f"{vendor} {name}"))
            if facts:
                mapped.append({"ref": ref, "name": name, "facts": sorted(facts)})
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
