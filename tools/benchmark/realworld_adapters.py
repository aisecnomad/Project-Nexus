"""Adapters for the real-world repository benchmark (repo surface only).

The synthetic benchmark (``adapters.py``) materializes generated cases; here
every case is a pinned checkout of a real public repository, so the adapters
reuse the synthetic adapters' calibrated run-and-parse logic and only replace
where the tree comes from. Two tools the synthetic benchmark does not cover,
SplxAI Agentic Radar and SafeDep vet, get their own adapters because both
accept a repository checkout as input. A deliberately naive grep baseline
anchors the floor: any result a real tool adds must beat a page of regexes.

Detection rules, written before the scored run:

- ShadowScan, Cisco AI BOM, agent-bom, AgentDiscover: unchanged from
  ``adapters.py`` (same report rules, same "detected" definitions).
- Agentic Radar: one scan per supported framework (crewai, langgraph,
  n8n, openai-agents, autogen); detected when any scan's report contains at
  least one agent. ``agentic`` mirrors detected (the tool only reports
  agentic workflows). A framework scan that fails on a repository that does
  not use that framework is not an error; the outcome is an error only when
  every framework scan fails.
- SafeDep vet: ``vet code scan`` with the bundled AI signatures; detected
  when at least one code-analysis finding matches. ``agentic`` stays None:
  the report does not separate agent evidence from plain LLM usage.
- Grep baseline: detected when any pattern matches outside ``.git``;
  ``agentic`` when an agent-tier pattern (framework import or dependency,
  MCP or coding-agent configuration, agent IaC) matches, not just a
  provider-SDK pattern. Patterns were written from the family list in the
  synthetic benchmark's README before any tool ran on the corpus.

All subprocess tools run in fresh network and PID namespaces via
``_isolated``: nothing can call home, resolve OSV, or start a remote MCP
session, and scans stay deterministic and local.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from time import monotonic

from tools.benchmark.adapters import (
    Adapter,
    AgentBom,
    AgentDiscover,
    CiscoAIBOM,
    Outcome,
    ShadowScan,
    ToolEnv,
    _base_env,
    _empty_home,
    _isolated,
    _tail,
)
from tools.benchmark.common import Case

RADAR_FRAMEWORKS = ("crewai", "langgraph", "n8n", "openai-agents", "autogen")


class RealTreeMixin:
    """Serve the pinned checkout instead of materializing a synthetic case."""

    paths: dict[str, Path]

    def __init__(self, paths: dict[str, Path]) -> None:
        self.paths = paths

    def tree(self, case: Case, work: Path, name: str) -> Path:
        return self.paths[case.case_id]


class RWShadowScan(RealTreeMixin, ShadowScan):
    surfaces = {"repo": "code.filesystem on the pinned checkout, default options"}

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        # Default options (no use_git override): what an operator gets from
        # `shadowscan scan` on a checkout with no tuning.
        connector = {"name": "code.filesystem", "path": str(self.paths[case.case_id])}
        return self._scan(connector, work, env)


class RWCiscoAIBOM(RealTreeMixin, CiscoAIBOM):
    surfaces = {"repo": "analyze on the pinned checkout; Tier-3 LLM classifier unreachable"}


class RWAgentBom(RealTreeMixin, AgentBom):
    surfaces = {"repo": "scan <checkout> --no-scan --offline (inventory only), empty HOME"}


class RWAgentDiscover(RealTreeMixin, AgentDiscover):
    surfaces = {"repo": "scan --format sarif + audit --skip-layers 2,3,4,5, empty HOME"}


class AgenticRadar(Adapter):
    """SplxAI Agentic Radar: static scans of agentic-workflow code.

    The CLI takes one framework per invocation, so the adapter runs every
    supported framework over the checkout and counts a repository as
    detected when any report holds at least one agent. Reports are read
    from the JSON the tool embeds in its HTML report; this parse location
    may be calibrated, the detection rule above may not.
    """

    name = "agentic-radar"
    display = "Agentic Radar (SplxAI)"
    source = "splx-ai/agentic-radar"
    surfaces = {"repo": "scan <framework> --export-graph-json per framework; any graph with an agent node"}
    _NOTHING = "didn't find any agentic workflow"

    def __init__(self, paths: dict[str, Path]) -> None:
        self.paths = paths

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("radar", "agentic-radar")
        return None if exe.exists() else str(exe)

    @staticmethod
    def _graph_counts(doc: dict[str, object]) -> tuple[int, int, int]:
        """(agent nodes, tool entries, mcp nodes) from the exported graph JSON."""
        nodes = doc.get("nodes")
        types: list[str] = []
        if isinstance(nodes, list):
            types = [str(n.get("node_type", "")).lower() for n in nodes if isinstance(n, dict)]
        agents = sum(t == "agent" for t in types)
        mcp = sum("mcp" in t for t in types)
        tools = doc.get("tools")
        return agents, len(tools) if isinstance(tools, list) else 0, mcp

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.paths[case.case_id]
        exe = str(env.venv_bin("radar", "agentic-radar"))
        total_agents = total_items = 0
        errors: list[str] = []
        succeeded: list[str] = []
        started = monotonic()
        for framework in RADAR_FRAMEWORKS:
            out = work / f"radar-{framework}.json"
            code, stdout, stderr, _ = _isolated(
                [exe, "scan", framework, "-i", str(root), "-o", str(out), "--export-graph-json"],
                env=_base_env(_empty_home(work), work),
                cwd=work,
            )
            if not out.exists():
                # "Agentic Radar didn't find any agentic workflow" exits without
                # writing a report: a clean zero for this framework (calibrated).
                if self._NOTHING in stdout or self._NOTHING in stderr:
                    succeeded.append(f"{framework}=0")
                else:
                    errors.append(f"{framework}: exit {code}: {_tail(stderr or stdout, 120)}")
                continue
            try:
                doc = json.loads(out.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                errors.append(f"{framework}: unparseable graph JSON")
                continue
            agents, tools, mcp = self._graph_counts(doc)
            succeeded.append(f"{framework}={agents}")
            total_agents += agents
            total_items += agents + tools + mcp
        seconds = monotonic() - started
        if not succeeded:
            return Outcome("error", seconds=seconds, note="; ".join(errors)[:300])
        note = " ".join(succeeded) + (
            f" | failed: {','.join(e.split(':')[0] for e in errors)}" if errors else ""
        )
        return Outcome(
            "ok",
            detected=total_agents > 0,
            items=total_items,
            agentic=total_agents > 0,
            seconds=seconds,
            note=note[:200],
        )


class SafeDepVet(Adapter):
    """SafeDep vet ``code scan``: community AI signatures over first-party code."""

    name = "safedep-vet"
    display = "SafeDep vet (code scan)"
    source = "safedep/vet"
    surfaces = {"repo": "vet code scan on the checkout; any AI code-analysis finding"}

    def __init__(self, paths: dict[str, Path]) -> None:
        self.paths = paths

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.root / "bin" / "vet"
        return None if exe.exists() else str(exe)

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.paths[case.case_id]
        db = work / "vet-code.db"
        exe = str(env.root / "bin" / "vet")
        environ = {**_base_env(_empty_home(work), work), "VET_DISABLE_TELEMETRY": "true"}
        code, stdout, stderr, secs = _isolated(
            [exe, "code", "scan", "--app", str(root), "--db", str(db), "--no-tui", "--no-banner"],
            env=environ,
            cwd=work,
        )
        if code != 0 or not db.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        rows = self._signature_matches(db)
        if rows is None:
            return Outcome("error", seconds=secs, note="code scan db unreadable")
        # Calibrated on the seed-1 corpus: vet's xBOM signatures also cover
        # non-AI capabilities (for example python.database.sql, tagged
        # ["database","sql","capability"]), so only matches tagged "ai" count,
        # which is SafeDep's own documented shadow-AI filter. A match tagged
        # "agent" (for example pydantic.ai.agent) is the agent-tier signal.
        ai = [(sig, tags) for sig, tags in rows if "ai" in tags]
        return Outcome(
            "ok",
            detected=len(ai) > 0,
            items=len(ai),
            agentic=any("agent" in tags for _, tags in ai),
            seconds=secs,
            note=",".join(sorted({sig for sig, _ in ai})[:8])[:200],
        )

    @staticmethod
    def _signature_matches(db: Path) -> list[tuple[str, frozenset[str]]] | None:
        """(signature_id, tags) rows from the scan database's code_signature_matches."""
        import sqlite3

        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        except sqlite3.Error:
            return None
        try:
            rows: list[tuple[str, frozenset[str]]] = []
            for sig, tags in con.execute("SELECT signature_id, tags FROM code_signature_matches"):
                try:
                    parsed = json.loads(tags) if tags else []
                except (json.JSONDecodeError, TypeError):
                    parsed = []
                rows.append((str(sig), frozenset(str(t) for t in parsed)))
            return rows
        except sqlite3.Error:
            return None
        finally:
            con.close()


# Agent-tier patterns: frameworks, MCP and coding-agent configuration, agent
# IaC. Sources: the family list in tools/benchmark/README.md. A hit on any of
# these marks the repo agentic for the baseline.
_AGENT_PATTERNS: dict[str, str] = {
    "crewai": r"\bfrom crewai\b|\bimport crewai\b|[\"']crewai([-_]tools)?[\"']|crewai[>=<~\[]",
    "langgraph": r"\bfrom langgraph\b|[\"']@langchain/langgraph[\"']|langgraph[>=<~\[]",
    "langchain-agents": r"\bfrom langchain[._]agents\b|create_react_agent|AgentExecutor",
    "autogen": r"\bfrom autogen\b|autogen[-_]agentchat|[\"']ag2[\"']",
    "openai-agents": r"\bfrom agents import\b|openai[-_]agents[>=<~\"']|[\"']@openai/agents[\"']",
    "pydantic-ai": r"\bfrom pydantic_ai\b|pydantic[-_]ai[>=<~\[\"']",
    "smolagents": r"\bsmolagents\b",
    "google-adk": r"\bfrom google\.adk\b|google-adk[>=<~\"']",
    "semantic-kernel": r"\bMicrosoft\.SemanticKernel\b|\bsemantic_kernel\b",
    "llamaindex-agent": r"llama_index.*agent|from llama_index\.core\.agent",
    "claude-agent-sdk": r"claude[-_]agent[-_]sdk",
    "vercel-ai-tools": r"@ai-sdk/|\bgenerateText\s*\(|\bstreamText\s*\(",
    "mastra": r"@mastra/core|\bfrom [\"']@mastra\b",
    "mcp-sdk": r"@modelcontextprotocol/|\bfrom mcp\.server\b|\bFastMCP\b|mcp\[cli\]",
    "mcp-config": r"(^|/)\.mcp\.json$|(^|/)mcp\.json$|claude_desktop_config\.json$",
    "coding-agent-config": r"(^|/)CLAUDE\.md$|(^|/)AGENTS\.md$|(^|/)\.claude/agents/|(^|/)\.cursor/rules",
    "a2a-card": r"(^|/)\.well-known/agent(-card)?\.json$|\ba2a[-_]sdk\b",
    "n8n-agent-node": r"@n8n/n8n-nodes-langchain\.agent",
    "iac-agent": r"aws_bedrockagent_agent|awscc_bedrock_agent|google_vertex_ai_agent|AWS::Bedrock::Agent",
}
# LLM-tier patterns: provider SDKs and API hosts without agent evidence.
_LLM_PATTERNS: dict[str, str] = {
    "openai-sdk": r"\bfrom openai import\b|\bimport openai\b|[\"']openai[\"']\s*:|openai[>=<~]=",
    "anthropic-sdk": r"\bimport anthropic\b|\bfrom anthropic\b|@anthropic-ai/sdk|anthropic[>=<~]=",
    "google-genai": r"\bgoogle[-._]generativeai\b|\bfrom google import genai\b|google-genai[>=<~\"']",
    "api-hosts": r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com",
    "litellm": r"\blitellm\b",
    "ollama": r"\bollama\b",
    "bedrock-runtime": r"bedrock-runtime|InvokeModel",
}
_TEXT_BYTES = 1_000_000
_NAME_KEYS = ("mcp-config", "coding-agent-config", "a2a-card")


class GrepBaseline(Adapter):
    """A page of regexes over file names and text contents: the floor to beat."""

    name = "grep-baseline"
    display = "Naive grep baseline"
    source = "this repository (tools/benchmark/realworld_adapters.py)"
    surfaces = {"repo": "fixed regex set over paths and text file contents (no .git)"}

    def __init__(self, paths: dict[str, Path]) -> None:
        self.paths = paths
        self._agent = {k: re.compile(v) for k, v in _AGENT_PATTERNS.items()}
        self._llm = {k: re.compile(v) for k, v in _LLM_PATTERNS.items()}

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.paths[case.case_id]
        started = monotonic()
        hits: set[str] = set()
        for path in root.rglob("*"):
            if ".git" in path.parts or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            for key in _NAME_KEYS:
                if self._agent[key].search("/" + rel):
                    hits.add(key)
            try:
                if path.stat().st_size > _TEXT_BYTES:
                    continue
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for key, pattern in self._agent.items():
                if key not in hits and key not in _NAME_KEYS and pattern.search(text):
                    hits.add(key)
            for key, pattern in self._llm.items():
                if key not in hits and pattern.search(text):
                    hits.add(key)
        agentic = any(h in self._agent for h in hits)
        return Outcome(
            "ok",
            detected=bool(hits),
            items=len(hits),
            agentic=agentic,
            seconds=monotonic() - started,
            note=",".join(sorted(hits))[:200],
        )


def rw_adapters(paths: dict[str, Path]) -> tuple[Adapter, ...]:
    return (
        RWShadowScan(paths),
        RWCiscoAIBOM(paths),
        RWAgentBom(paths),
        RWAgentDiscover(paths),
        AgenticRadar(paths),
        SafeDepVet(paths),
        GrepBaseline(paths),
    )
