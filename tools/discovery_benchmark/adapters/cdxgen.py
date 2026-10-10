"""CycloneDX cdxgen: dependency SBOM baseline mapped through the alias tables."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.discovery_benchmark.adapters import (
    Command,
    Normalized,
    ToolConfig,
    ToolSpec,
    facts_from_purl,
    load_json,
    run_version,
)

SPEC = ToolSpec(
    id="cdxgen",
    name="cdxgen (CycloneDX)",
    vendor="CycloneDX / OWASP",
    categories=frozenset({"framework", "provider", "mcp", "a2a"}),
    notes=(
        "plain dependency SBOM (--technique manifest-analysis --no-install-deps); the AI-BOM "
        "features described for cdxgen 13.x are not in the npm release used here, so this is the "
        "'SBOM + alias table' baseline"
    ),
)


class CdxgenAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("cdxgen") else "no 'bin' configured for cdxgen"

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("cdxgen") or "cdxgen", "--version"], pattern=r"Generator (\d+\.\d+\.\d+\S*)"
        )

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        argv = (
            cfg.binary("cdxgen") or "cdxgen",
            "--no-install-deps",
            "--technique",
            "manifest-analysis",
            "--no-validate",
            "-o",
            str(out_dir / "bom.json"),
            str(repo_dir),
        )
        env = {"FETCH_LICENSE": "false", "CDXGEN_NO_ANALYTICS": "1"}
        return [Command(argv, env=env)]

    def normalize(self, out_dir: Path) -> Normalized:
        data = load_json(out_dir / "bom.json")
        if not isinstance(data, dict):
            return Normalized(error="bom.json missing or malformed")
        components = data.get("components") or []
        result = Normalized(raw_count=len(components))
        mapped: list[dict[str, Any]] = []
        for comp in components:
            if not isinstance(comp, dict):
                continue
            purl = str(comp.get("purl", ""))
            facts = facts_from_purl(purl)
            if facts:
                mapped.append({"purl": purl, "facts": sorted(facts)})
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
