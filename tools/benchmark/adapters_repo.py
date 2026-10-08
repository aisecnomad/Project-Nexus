"""Repository-surface adapters added for the real-world corpus.

Each adapter follows the rules in ``adapters.py``: the tool runs as a
subprocess in fresh network and PID namespaces, its own report decides
"detected", and the rule is written here before the scored run. The optional
``evidence`` counts feed the secondary evidence-coverage table only.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from tools.benchmark.adapters import (
    Adapter,
    Outcome,
    ToolEnv,
    _base_env,
    _empty_home,
    _isolated,
    _tail,
)
from tools.benchmark.common import Case

RADAR_FRAMEWORKS = ("langgraph", "crewai", "n8n", "openai-agents", "autogen")
_GRAPH_ENDPOINTS = frozenset({"START", "END", "__start__", "__end__"})


class AgenticRadar(Adapter):
    """SPLX Agentic Radar maps agentic workflows for one named framework per run.

    Discovery here means the union of its five framework scans. Calibrated on
    the three-repository calibration set: a run that reports "didn't find any
    agentic workflow" exits 1 without a graph and is a clean nothing-found for
    that framework; a run that crashes (its parser raises on code it cannot
    read) is a crash for that framework. The case is ``ok`` when no framework
    crashed or at least one framework produced a graph, and an error when a
    framework crashed and no graph was produced, since the crash may hide a
    detection.
    """

    name = "agentic-radar"
    display = "Agentic Radar (SPLX)"
    source = "splx-ai/agentic-radar"
    surfaces = {"repo": "scan <framework> -i <checkout> --export-graph-json, for each of the five frameworks"}
    evidence_types = ("framework", "mcp-code")

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("radar", "agentic-radar")
        return None if exe.exists() else str(exe)

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "repo")
        exe = str(env.venv_bin("radar", "agentic-radar"))
        total = 0.0
        produced = 0
        crashes = 0
        nodes = agents = tools = mcp = 0
        notes: list[str] = []
        raw: dict[str, str] = {}
        for framework in RADAR_FRAMEWORKS:
            out = work / f"radar-{framework}.json"
            code, stdout, stderr, secs = _isolated(
                [exe, "scan", framework, "-i", str(root), "-o", str(out), "--export-graph-json"],
                env=_base_env(_empty_home(work), work),
                cwd=work,
            )
            total += secs
            if not out.exists():
                if _RADAR_NOTHING in stdout or _RADAR_NOTHING in stderr:
                    continue
                crashes += 1
                notes.append(f"{framework}: exit {code} {_tail(stderr, 60)}")
                continue
            text = out.read_text(encoding="utf-8")
            raw[out.name] = text
            try:
                graph = json.loads(text)
            except json.JSONDecodeError:
                notes.append(f"{framework}: unreadable graph")
                continue
            produced += 1
            for node in graph.get("nodes", []):
                if str(node.get("name")) in _GRAPH_ENDPOINTS:
                    continue
                nodes += 1
                if "mcp" in str(node.get("node_type", "")).lower():
                    mcp += 1
            agents += len(graph.get("agents", []))
            tools += len(graph.get("tools", []))
        if crashes and not produced:
            return Outcome(
                "error", seconds=total, note=f"{crashes} framework scans crashed: " + "; ".join(notes)
            )
        items = nodes + agents + tools
        evidence: dict[str, int] = {}
        if items:
            evidence["framework"] = items
        if mcp:
            evidence["mcp-code"] = mcp
        return Outcome(
            "ok",
            detected=items > 0,
            items=items,
            agentic=items > 0,
            seconds=total,
            note=f"graphs={produced}/5 crashes={crashes} nodes={nodes} agents={agents} "
            f"tools={tools} mcp={mcp}",
            raw=raw,
            evidence=evidence,
        )


_RADAR_NOTHING = "didn't find any agentic workflow"
_CDX_AGENTIC = ("agent", "mcp", "skill", "instruction", "prompt", "tool")


class CdxgenAIBOM(Adapter):
    """OWASP cdxgen in its AI inventory mode (``-t ai``).

    The AI inventory lists models, AI configuration files, MCP configurations
    and agent instructions it recognizes; ordinary library dependencies are not
    part of this project type, so a BOM with any component is a detection.
    """

    name = "cdxgen-aibom"
    display = "OWASP cdxgen (AI inventory)"
    source = "cdxgen/cdxgen"
    surfaces = {"repo": "cdxgen -t ai --no-install-deps --no-babel on the checkout"}
    evidence_types = ("provider", "mcp-config", "coding-agent-config", "agent-skill", "local-model")

    def _exe(self, env: ToolEnv) -> Path:
        return env.root / "cdxgen" / "node_modules" / ".bin" / "cdxgen"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = self._exe(env)
        return None if exe.exists() else str(exe)

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "repo")
        out = work / "bom.json"
        cmd = [
            str(self._exe(env)), "-t", "ai", "--no-install-deps", "--no-babel", "--spec-version", "1.6",
            "-o", str(out), str(root),
        ]  # fmt: skip
        run_env = {**_base_env(_empty_home(work), work), "FETCH_LICENSE": "false"}
        code, stdout, stderr, secs = _isolated(cmd, env=run_env, cwd=work)
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        try:
            bom = json.loads(text)
        except json.JSONDecodeError:
            return Outcome("error", seconds=secs, note="unreadable BOM", raw={"bom.json": text})
        components = [c for c in bom.get("components", []) if isinstance(c, dict)]
        evidence: dict[str, int] = {}
        kinds: set[str] = set()
        agentic = False
        for comp in components:
            props = {
                str(p.get("name")): str(p.get("value"))
                for p in comp.get("properties", [])
                if isinstance(p, dict)
            }
            kind = (
                props.get("cdx:ai:kind") or props.get("cdx:file:kind") or props.get("cdx:mcp:kind") or ""
            ).lower()
            ctype = str(comp.get("type") or "")
            purl = str(comp.get("purl") or "")
            kinds.add(kind or ctype)
            if any(word in kind for word in _CDX_AGENTIC) or purl.startswith("pkg:mcp"):
                agentic = True
            if ctype == "machine-learning-model":
                key = (
                    "local-model"
                    if re.search(r"\.(gguf|safetensors|onnx|pt|pth|ckpt)$", str(comp.get("name", "")))
                    else "provider"
                )
            elif "mcp" in kind or purl.startswith("pkg:mcp"):
                key = "mcp-config"
            elif "skill" in kind:
                key = "agent-skill"
            elif "prompt" in kind or "instruction" in kind or "agent" in kind:
                key = "coding-agent-config"
            else:
                continue  # notebooks, datasets and other inventory items map to no evidence type
            evidence[key] = evidence.get(key, 0) + 1
        return Outcome(
            "ok",
            detected=bool(components),
            items=len(components),
            agentic=agentic,
            seconds=secs,
            note=",".join(sorted(k for k in kinds if k))[:200],
            raw={"bom.json": text},
            evidence=evidence,
        )


class CiscoSkillScanner(Adapter):
    """Cisco AI Defense Skill Scanner finds and audits agent skill packages.

    It is scored as a discovery tool on skills only: a case is detected when
    ``scan-all --recursive`` reports at least one skill package, whatever the
    audit verdict. "No skills found to scan" is a clean result, not an error.
    """

    name = "cisco-skill-scanner"
    display = "Cisco Skill Scanner"
    source = "cisco-ai-defense/skill-scanner"
    surfaces = {"repo": "scan-all <checkout> --recursive --format json (static analyzers; no LLM)"}
    evidence_types = ("agent-skill",)
    _NONE = "No skills found to scan"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("skillscanner", "skill-scanner")
        return None if exe.exists() else str(exe)

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "repo")
        exe = str(env.venv_bin("skillscanner", "skill-scanner"))
        code, stdout, stderr, secs = _isolated(
            [exe, "scan-all", str(root), "--recursive", "--format", "json"],
            env=_base_env(_empty_home(work), work),
            cwd=work,
        )
        if self._NONE in stdout or self._NONE in stderr:
            return Outcome("ok", detected=False, items=0, agentic=False, seconds=secs, note="no skills")
        try:
            doc = json.loads(stdout[stdout.index("{") :]) if "{" in stdout else None
        except (json.JSONDecodeError, ValueError):
            doc = None
        if not isinstance(doc, dict):
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        skills = int((doc.get("summary") or {}).get("total_skills_scanned") or len(doc.get("results") or []))
        findings = int((doc.get("summary") or {}).get("total_findings") or 0)
        return Outcome(
            "ok",
            detected=skills > 0,
            items=skills,
            agentic=skills > 0,
            seconds=secs,
            note=f"skills={skills} findings={findings}",
            raw={"skill-scanner.json": stdout},
            evidence={"agent-skill": skills} if skills else {},
        )


# Words a reasonable engineer greps for; every one of them also occurs outside AI.
_PROVIDER_WORDS = (
    "openai", "anthropic", "gemini", "claude", "ollama", "bedrock", "mistral", "cohere",
    "huggingface", "vertex ai", "gpt-4", "chatgpt",
)  # fmt: skip
_FRAMEWORK_WORDS = (
    "langchain", "langgraph", "crewai", "autogen", "llamaindex", "llama_index",
    "semantic kernel", "copilot", "ai agent",
)  # fmt: skip
BASELINE_WORDS: dict[str, tuple[str, ...]] = {
    "provider": _PROVIDER_WORDS,
    "framework": _FRAMEWORK_WORDS,
    "mcp": ("mcp",),
}
BASELINE_FILES: dict[str, str] = {
    ".mcp.json": "mcp-config",
    "CLAUDE.md": "coding-agent-config",
    ".cursorrules": "coding-agent-config",
    "AGENTS.md": "coding-agent-config",
    "SKILL.md": "agent-skill",
    "copilot-instructions.md": "coding-agent-config",
}
_BASELINE_MAX_BYTES = 1_000_000
_BASELINE_SKIP = frozenset({".git"})


def _baseline_patterns() -> dict[str, re.Pattern[str]]:
    return {
        group: re.compile(
            r"(?<![a-z0-9])(?:" + "|".join(re.escape(w) for w in words) + r")(?![a-z0-9])", re.I
        )
        for group, words in BASELINE_WORDS.items()
    }


class KeywordBaseline(Adapter):
    """A naive control: case-insensitive word search for AI names and config filenames.

    It shows what grepping buys on real repositories and where it fails (name
    collisions such as Minecraft Bedrock, Gemini the protocol or AWS Copilot).
    """

    name = "keyword-grep"
    display = "Keyword grep (control)"
    source = "this repository"
    surfaces = {
        "repo": "word search for 22 AI product/SDK names and 6 agent config filenames over text files"
    }
    evidence_types = ("provider", "framework", "mcp-code", "mcp-config", "coding-agent-config", "agent-skill")

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "repo")
        patterns = _baseline_patterns()
        started = time.monotonic()
        counts: dict[str, int] = {}
        files_hit: dict[str, int] = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _BASELINE_SKIP]
            for filename in filenames:
                path = Path(dirpath) / filename
                if filename in BASELINE_FILES:
                    key = BASELINE_FILES[filename]
                    files_hit[key] = files_hit.get(key, 0) + 1
                try:
                    if path.is_symlink() or path.stat().st_size > _BASELINE_MAX_BYTES:
                        continue
                    data = path.read_bytes()
                except OSError:
                    continue
                if b"\0" in data[:4096]:
                    continue
                text = data.decode("utf-8", errors="replace")
                for group, pattern in patterns.items():
                    hits = len(pattern.findall(text))
                    if hits:
                        counts[group] = counts.get(group, 0) + hits
        evidence: dict[str, int] = {}
        if counts.get("provider"):
            evidence["provider"] = counts["provider"]
        if counts.get("framework"):
            evidence["framework"] = counts["framework"]
        if counts.get("mcp"):
            evidence["mcp-code"] = counts["mcp"]
        evidence.update(files_hit)
        items = sum(counts.values()) + sum(files_hit.values())
        agentic = bool(counts.get("framework") or counts.get("mcp") or files_hit)
        return Outcome(
            "ok",
            detected=items > 0,
            items=items,
            agentic=agentic,
            seconds=time.monotonic() - started,
            note=" ".join(f"{k}={v}" for k, v in sorted({**counts, **files_hit}.items()))[:200],
            evidence=evidence,
        )


REPO_ADAPTERS: tuple[Adapter, ...] = (AgenticRadar(), CdxgenAIBOM(), CiscoSkillScanner(), KeywordBaseline())


def adapter_evidence_types(adapter: Adapter) -> tuple[str, ...]:
    """Evidence types an adapter can report (empty for adapters that cannot map their output)."""
    declared: Any = getattr(adapter, "evidence_types", ())
    return tuple(str(t) for t in declared)
