"""Which tools' own detection vocabularies mention each technology the oracle knows.

``python -m tools.benchmark.realworld.vocab_overlap --tool-root TOOL_ROOT --out registry/vocab-overlap.json``

The oracle's registry and ShadowScan's signature packs both describe the AI ecosystem, and the two were
written by people who share knowledge of it. A review of this benchmark measured the overlap (79% of the
registry's package names appear in ShadowScan's source, 6-33% in other tools'). If the registry favoured
ShadowScan, ShadowScan would score high on positives defined by technologies only it knows.

This script makes that visible and testable. For every registry technology and developer-configuration rule
it asks, tool by tool, whether the tool's own source or data mentions one of the technology's names (a crude
whole-token match on lower-cased text; a mention is not proof of detection, and a miss is not proof of
blindness). The scorer then adds the label variant ``shared-vocab``: a repository is positive only when at
least one of its supporting technologies is mentioned by a tool other than ShadowScan, so positives that
rest on ShadowScan-only vocabulary drop out, and reports every tool's recall on the ShadowScan-only
positives separately. Tests, documentation and fixtures of the tools are not read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
TEXT_SUFFIXES = frozenset(
    {".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".json", ".yaml", ".yml", ".toml", ".txt"}
)
SKIP_PARTS = frozenset(
    {"tests", "test", "__tests__", "testdata", "fixtures", "docs", "examples", "node_modules", "__pycache__"}
)
SKIP_NAME = re.compile(r"(_test\.go|\.poku\.js|\.test\.[jt]s|\.spec\.[jt]s|lock\.json|-lock\.yaml|\.lock)$")
MAX_FILE = 3_000_000
# Developer-configuration rules are regexes over paths; these are the file and directory names they stand for.
DEV_TOKENS: dict[str, tuple[str, ...]] = {
    "claude-code": ("claude.md", ".claude", "claude_desktop_config", "claude-code", "claude code"),
    "claude-plugin": (".claude-plugin", "plugin.json"),
    "agents-md": ("agents.md",),
    "cursor": (".cursorrules", ".cursor", "cursor rules", "cursor/rules"),
    "windsurf": (".windsurfrules", ".windsurf", "windsurf"),
    "copilot": ("copilot-instructions", ".github/copilot", "copilot"),
    "gemini-cli": ("gemini.md", ".gemini", "gemini-cli", "gemini cli"),
    "codex-cli": (".codex", "codex"),
    "cline-roo-kilo": (".clinerules", ".roorules", ".roomodes", "cline", "roo code", "kilocode"),
    "continue-dev": (".continue", "continue.dev"),
    "aider": (".aider", "aider.conf", "aider"),
    "amazonq-kiro-junie": (".amazonq", ".kiro", ".junie", "amazon q", "kiro", "junie"),
    "agent-skills": ("skill.md", ".claude/skills", "agent skill", "skills/"),
    "mcp-config": (".mcp.json", "mcp.json", "mcp_config", "mcpservers", "mcp servers"),
    "ai-review-bots": (".coderabbit", "coderabbit", ".pr_agent", "pr-agent", "greptile", "sourcery"),
    "ci-ai-agent": ("claude-code-action", "anthropics/claude", "openai/codex-action", "gemini-cli-action"),
}  # fmt: skip


def source_roots(tool_root: Path) -> dict[str, list[Path]]:
    third = tool_root / "third_party"
    site = next((tool_root / "venvs" / "aibom" / "lib").glob("python*/site-packages"), None)
    agent_bom_site = next((tool_root / "venvs" / "agentbom" / "lib").glob("python*/site-packages"), None)
    roots: dict[str, list[Path]] = {
        "shadowscan": [REPO_ROOT / "shadowscan"],
        "trusera-ai-bom": [third / "Trusera_ai-bom" / "src"],
        "agentdiscover": [third / "Defend-AI-Tech-Inc_agent-discover-scanner" / "src"],
        "agt-discovery": [
            third / "microsoft_agent-governance-toolkit" / "agent-governance-python" / "agent-discovery"
        ],
        "safedep-vet": [third / "safedep_vet" / "signatures", third / "safedep_vet" / "pkg"],
        "cdxgen-aibom": [tool_root / "cdxgen" / "node_modules" / "@cyclonedx" / "cdxgen" / "lib"],
        "agentic-radar": [third / "splx-ai_agentic-radar" / "agentic_radar"],
    }
    if site:
        roots["cisco-aibom"] = [site / "aibom"]
    if agent_bom_site:
        roots["agent-bom"] = [agent_bom_site / "agent_bom"]
    return roots


def read_vocabulary(roots: list[Path]) -> str:
    parts: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if (
                path.suffix not in TEXT_SUFFIXES
                or not path.is_file()
                or path.is_symlink()
                or SKIP_PARTS & set(path.relative_to(root).parts)
                or SKIP_NAME.search(path.name)
                or path.stat().st_size > MAX_FILE
            ):
                continue
            parts.append(path.read_text(encoding="utf-8", errors="ignore").lower())
    return "\n".join(parts)


def names_of(tech: dict[str, Any]) -> list[str]:
    """Every package, import and module name the registry lists for a technology."""
    found: set[str] = {str(tech["name"]).lower(), str(tech["id"]).lower()}
    for key, value in tech.items():
        if key in {"id", "name", "tier"}:
            continue
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str):
                found.add(item.lower().rstrip("-_./"))
    return sorted(n for n in found if len(n) >= 4 or n in {"mcp", "a2a", "dspy", "crew"})


def mentioned(name: str, vocabulary: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", vocabulary) is not None


def build(tool_root: Path, registry: dict[str, Any]) -> dict[str, Any]:
    vocabularies = {tool: read_vocabulary(roots) for tool, roots in source_roots(tool_root).items()}
    names: dict[str, list[str]] = {t["id"]: names_of(t) for t in registry["technologies"]}
    names.update({rule_id: list(tokens) for rule_id, tokens in DEV_TOKENS.items()})
    coverage = {
        tool: {tid: any(mentioned(n, text) for n in ns) for tid, ns in sorted(names.items())}
        for tool, text in sorted(vocabularies.items())
    }
    others = [t for t in coverage if t != "shadowscan"]
    ids = sorted(names)
    return {
        "method": "whole-token match of registry names in each tool's own non-test source and data",
        "tools": sorted(coverage),
        "vocabulary_bytes": {tool: len(text) for tool, text in sorted(vocabularies.items())},
        "coverage": coverage,
        "shadowscan_only": [
            t for t in ids if coverage["shadowscan"][t] and not any(coverage[o][t] for o in others)
        ],
        "shared": [t for t in ids if any(coverage[o][t] for o in others)],
        "mentioned_by_nobody": [t for t in ids if not any(c[t] for c in coverage.values())],
        "technologies": len(ids),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--registry", type=Path, default=HERE / "registry" / "ai_registry.json")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    document = build(args.tool_root, registry)
    args.out.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"{document['technologies']} technologies: {len(document['shared'])} shared, "
        f"{len(document['shadowscan_only'])} ShadowScan-only, "
        f"{len(document['mentioned_by_nobody'])} by nobody"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
