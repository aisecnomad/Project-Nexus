"""DefendAI AgentDiscover: static code scan, dependency scan and MCP config export."""

from __future__ import annotations

import re
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
    id="agentdiscover",
    name="AgentDiscover",
    vendor="DefendAI",
    categories=frozenset({"framework", "provider", "mcp", "mcp-client-config"}),
    notes="agentdiscover scan (SARIF) + deps (text) + export-mcpfw-policy (YAML); no platform upload",
)


class AgentDiscoverAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("agentdiscover") else "no 'bin' configured for agentdiscover"

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("agentdiscover") or "agentdiscover", "--version"], pattern=r"v?(\d+\.\d+\.\d+\S*)"
        )

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        binary = cfg.binary("agentdiscover") or "agentdiscover"
        return [
            Command(
                (binary, "scan", str(repo_dir), "--format", "sarif", "--output", str(out_dir / "scan.sarif"))
            ),
            Command((binary, "deps", str(repo_dir))),
            Command(
                (binary, "export-mcpfw-policy", str(repo_dir), "--output", str(out_dir / "mcp-policy.yaml")),
                ok_exit_codes=frozenset({0, 1}),
            ),
        ]

    def normalize(self, out_dir: Path) -> Normalized:
        result = Normalized()
        mapped: list[dict[str, Any]] = []
        sarif = load_json(out_dir / "scan.sarif")
        if isinstance(sarif, dict):
            for run in sarif.get("runs") or []:
                for item in run.get("results") or [] if isinstance(run, dict) else []:
                    if not isinstance(item, dict):
                        continue
                    result.raw_count += 1
                    rule = str(item.get("ruleId", ""))
                    message = str((item.get("message") or {}).get("text", ""))
                    item_facts: set[str] = set(taxonomy.facts_from_name(message))
                    if item_facts:
                        mapped.append({"rule": rule, "message": message[:120], "facts": sorted(item_facts)})
                        result.facts.update(item_facts)
        elif (out_dir / "scan.sarif").exists():
            result.error = "scan.sarif malformed"
        deps_text = ""
        for candidate in sorted(out_dir.glob("*.stdout.txt")):
            text = candidate.read_text(encoding="utf-8", errors="replace")
            if "Scanning dependencies" in text:
                deps_text = text
        for line in deps_text.splitlines():
            if re.search(
                r"(No dependency files|Looked for|Dependencies are managed|Tip:|could mean|Risk|Total|Summ)",
                line,
            ):
                continue
            line_facts = taxonomy.facts_from_name(line)
            if line_facts:
                result.raw_count += 1
                mapped.append({"deps": line.strip()[:120], "facts": sorted(line_facts)})
                result.facts.update(line_facts)
        policy_path = out_dir / "mcp-policy.yaml"
        if policy_path.exists():
            try:
                policy = yaml.safe_load(policy_path.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                policy = None
            servers = policy.get("servers") if isinstance(policy, dict) else None
            if isinstance(servers, list) and servers:
                result.raw_count += len(servers)
                result.facts.add("mcp-client-config:generic")
                mapped.append(
                    {"mcp_servers": [str(s.get("server", "")) for s in servers if isinstance(s, dict)][:20]}
                )
        result.detail["mapped"] = mapped[:400]
        return result
