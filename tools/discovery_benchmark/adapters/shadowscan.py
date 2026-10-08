"""ShadowScan (NexusShadowScan) ``code.filesystem`` connector."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

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
    id="shadowscan",
    name="ShadowScan (Project Nexus)",
    vendor="aisecnomad",
    categories=frozenset(taxonomy.CATEGORIES),
    notes="code.filesystem connector, default options, JSON report; exit 3 (incomplete) is accepted",
)

_IAC_BY_SLUG = {
    "aws-bedrock-agents": "iac:bedrock",
    "aws-bedrock-agentcore": "iac:bedrock",
    "azure-ai-foundry-agents": "iac:azure-openai",
    "azure-openai": "iac:azure-openai",
    "gcp-vertex-agent-engine": "iac:vertex-ai",
    "gcp-vertex-ai": "iac:vertex-ai",
    "gcp-dialogflow": "iac:dialogflow",
}
_PROVIDER_BY_CLOUD_SLUG = {
    "aws-bedrock-agents": "provider:bedrock",
    "aws-bedrock-agentcore": "provider:bedrock",
    "azure-ai-foundry-agents": "provider:azure-openai",
    "gcp-vertex-agent-engine": "provider:vertex-ai",
}
_LOWCODE = {
    "n8n": "lowcode:n8n",
    "dify": "lowcode:dify",
    "flowise": "lowcode:flowise",
    "langflow": "lowcode:langflow",
}


def _slug_facts(signature: str) -> frozenset[str]:
    """Map a signature id such as ``framework.vercel-ai-sdk`` onto taxonomy facts."""
    family, _, slug = signature.partition(".")
    words = slug.replace("-", " ").replace("_", " ")
    if family == "framework":
        return frozenset(f for f in taxonomy.facts_from_name(words) if f.startswith("framework:"))
    if family == "provider":
        return frozenset(f for f in taxonomy.facts_from_name(words) if f.startswith("provider:"))
    if family == "protocol":
        if slug == "mcp":
            return frozenset({"mcp:sdk"})
        if slug == "a2a":
            return frozenset({"a2a:sdk"})
        return frozenset()
    if family == "platform":
        if slug in _LOWCODE:
            return frozenset({_LOWCODE[slug]})
        return frozenset(f for f in taxonomy.facts_from_name(words) if f.startswith("framework:"))
    if family == "cloud":
        fact = _PROVIDER_BY_CLOUD_SLUG.get(slug)
        return frozenset({fact}) if fact else frozenset()
    return frozenset()


class ShadowScanAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("shadowscan") else "no 'bin' configured for shadowscan"

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("shadowscan") or "shadowscan", "--version"], pattern=r"(\d+\.\d+\.\d+\S*)"
        )

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        config = {
            "options": {"parallel": 2, "connector_timeout_seconds": 1500},
            "connectors": [{"name": "code.filesystem", "path": str(repo_dir), "label": repo_dir.name}],
        }
        (out_dir / "shadowscan.yaml").write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        argv = (
            cfg.binary("shadowscan") or "shadowscan",
            "scan",
            "-c",
            str(out_dir / "shadowscan.yaml"),
            "--format",
            "json",
            "-o",
            str(out_dir / "report.json"),
        )
        return [Command(argv, ok_exit_codes=frozenset({0, 3}))]

    def normalize(self, out_dir: Path) -> Normalized:
        data = load_json(out_dir / "report.json")
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            return Normalized(error="report.json missing or malformed")
        result = Normalized(raw_count=len(data["findings"]))
        incomplete = any(isinstance(s, dict) and s.get("incomplete") for s in data.get("stats") or [])
        result.detail["incomplete"] = incomplete
        mapped: list[dict[str, Any]] = []
        for finding in data["findings"]:
            if not isinstance(finding, dict):
                continue
            kind = str(finding.get("kind", ""))
            facts: set[str] = set()
            if kind in {"secret", "token"}:
                continue
            locations = [
                str(e.get("location") or "") for e in finding.get("evidence") or [] if isinstance(e, dict)
            ]
            resource = str(finding.get("resource", ""))
            signatures = [str(s) for s in finding.get("frameworks") or []]
            providers = [str(s) for s in finding.get("model_providers") or []]
            if kind == "infra":
                for sig in signatures + providers:
                    family, _, slug = sig.partition(".")
                    if family in {"cloud", "provider"} and slug in _IAC_BY_SLUG:
                        facts.add(_IAC_BY_SLUG[slug])
                    elif family == "provider" and slug in {"aws-bedrock", "bedrock"}:
                        facts.add("iac:bedrock")
                    elif family == "provider" and slug in {"azure-openai"}:
                        facts.add("iac:azure-openai")
                    elif family == "provider" and slug in {"vertex-ai", "google-vertex", "gcp-vertex-ai"}:
                        facts.add("iac:vertex-ai")
                    elif family in {"provider", "framework", "platform", "protocol"}:
                        facts.update(_slug_facts(sig))
            elif kind == "mcp-server":
                for path in [resource, *locations]:
                    facts.update(
                        f for f in taxonomy.facts_for_config_path(path) if f.startswith("mcp-client-config:")
                    )
                for sig in signatures:
                    if not sig.startswith("protocol."):
                        facts.update(_slug_facts(sig))
            elif kind == "agent-config":
                for path in [resource, *locations]:
                    facts.update(
                        f for f in taxonomy.facts_for_config_path(path) if f.startswith("agent-config:")
                    )
                if not facts:
                    facts.add("agent-config:generic")
            elif kind == "workflow":
                for sig in signatures:
                    facts.update(_slug_facts(sig))
                for sig in providers:
                    facts.update(_slug_facts(sig))
            else:  # agent, framework-usage, ai-app, local-model, cloud-resource ...
                for sig in signatures:
                    if sig == "protocol.a2a" and resource.endswith(".json"):
                        facts.add("a2a:agent-card")
                    else:
                        facts.update(_slug_facts(sig))
                for sig in providers:
                    facts.update(_slug_facts(sig))
            if facts:
                mapped.append({"kind": kind, "resource": resource, "facts": sorted(facts)})
                result.facts.update(facts)
        result.detail["mapped"] = mapped[:400]
        return result
