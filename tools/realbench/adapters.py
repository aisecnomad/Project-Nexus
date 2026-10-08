"""Run one tool on one repository checkout and map its report to fixed verdicts.

Each run happens in fresh mount, network and PID namespaces: the checkout is
bind-mounted read-only over itself, there is no network, the tool sees only
its own processes, and ``HOME`` is an empty directory. Third-party tools are
installed outside this repository (``install_tools.sh``); ``ToolEnv`` locates
them.

Every adapter returns an :class:`Outcome`:

- ``status``: ``ok`` (a complete report), ``partial`` (a report the tool
  itself marks incomplete) or ``error`` (no usable report: crash, timeout,
  unparseable output);
- ``detected``: the report holds at least one AI-related item, as the tool
  defines it;
- ``agentic``: the report holds at least one item the tool classifies as an
  agent, agent framework, MCP server or client, workflow or agent
  configuration; ``None`` for tools that do not make that distinction;
- ``paths``: repository-relative files the report cites as evidence.

The rules are fixed before the scored run (see PROTOCOL.md §7) and applied to
the tool's own report, which is kept outside the repository.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TIMEOUT_S = 900
MAX_PATHS = 300
# Unshare a mount namespace, then make the checkout read-only for the tool.
_RO_WRAPPER = 'set -e; r="$1"; shift; mount --bind "$r" "$r"; mount -o remount,bind,ro "$r"; exec "$@"'


@dataclass
class Outcome:
    status: str
    detected: bool = False
    agentic: bool | None = None
    items: int = 0
    kinds: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    seconds: float = 0.0
    note: str = ""
    raw: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolEnv:
    root: Path  # third-party checkouts, venvs and binaries
    python: str  # interpreter with ShadowScan installed

    def venv_bin(self, venv: str, exe: str) -> Path:
        return self.root / "venvs" / venv / "bin" / exe

    def checkout(self, name: str) -> Path:
        return self.root / "third_party" / name


Run = tuple[int, str, str, float]


def isolated(cmd: list[str], *, repo: Path, env: dict[str, str], cwd: Path, timeout: int = TIMEOUT_S) -> Run:
    """Run ``cmd`` offline with ``repo`` mounted read-only; returns (code, stdout, stderr, seconds).

    ``--kill-child`` ties the namespace's first process to ``unshare``, so a
    timeout that kills ``unshare`` also ends every process the tool started.
    """
    full = [
        "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child", "--mount-proc", "--",
        "/bin/sh", "-c", _RO_WRAPPER, "sh", str(repo), *cmd,
    ]  # fmt: skip
    started = time.monotonic()
    try:
        proc = subprocess.run(
            full,
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            cwd=cwd,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s", time.monotonic() - started
    return proc.returncode, proc.stdout, proc.stderr, time.monotonic() - started


def base_env(work: Path, extra_path: str = "") -> dict[str, str]:
    """A minimal environment: empty ``HOME``, no proxies or credentials."""
    home = work / "home"
    tmp = work / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    path = "/usr/local/bin:/usr/bin:/bin"
    return {
        "HOME": str(home),
        "PATH": f"{extra_path}:{path}" if extra_path else path,
        "LANG": "C.UTF-8",
        "TMPDIR": str(tmp),
        "NO_COLOR": "1",
    }


def tail(text: str, n: int = 300) -> str:
    return text.strip().replace("\n", " | ")[-n:]


def relpath(value: Any, repo: Path) -> str | None:
    """Normalise a reported location (``path``, ``path:line``, ``file://`` URI) to a repo-relative path."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().removeprefix("file://")
    root = str(repo).rstrip("/") + "/"
    if text.startswith(root):
        text = text[len(root) :]
    elif text.startswith("/"):
        return None  # outside the checkout (host files, HOME)
    text = re.sub(r":\d+(:\d+)?(-\d+)?$", "", text).removeprefix("./")
    if not text or text.startswith("../"):
        return None
    return text


def collect_paths(values: list[Any], repo: Path) -> list[str]:
    out = sorted({p for v in values if (p := relpath(v, repo)) is not None})
    return out[:MAX_PATHS]


def json_values(doc: Any, keys: frozenset[str]) -> list[Any]:
    """Every value stored under one of ``keys`` anywhere in ``doc``."""
    found: list[Any] = []
    stack = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in keys and not isinstance(v, (dict, list)):
                    found.append(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return found


class Adapter:
    name = ""
    display = ""
    source = ""  # upstream repository
    mode = ""  # how the tool is run on a checkout
    agentic_rule = ""  # which report items count as agentic, or why there are none

    def unavailable(self, env: ToolEnv) -> str | None:
        return None

    def run(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        reason = self.unavailable(env)
        if reason:
            return Outcome("error", note=f"not installed: {reason}")
        return self.scan(repo, work, env)

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# ShadowScan (this repository)

SHADOWSCAN_AGENTIC = frozenset({"agent", "mcp-server", "agent-config", "bot-app", "workflow"})


class ShadowScan(Adapter):
    name = "shadowscan"
    display = "Project Nexus ShadowScan"
    source = "aisecnomad/Project-Nexus"
    mode = "scan with one code.filesystem connector on the checkout, defaults, use_git false"
    agentic_rule = (
        "a finding of kind " + ", ".join(sorted(SHADOWSCAN_AGENTIC)) + " (the tool's own agent kinds)"
    )

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        cfg = work / "shadowscan.json"
        cfg.write_text(
            json.dumps({"connectors": [{"name": "code.filesystem", "path": str(repo), "use_git": False}]}),
            encoding="utf-8",
        )
        out = work / "report.json"
        code, _, stderr, secs = isolated(
            [env.python, "-m", "shadowscan", "scan", "-c", str(cfg), "-f", "json", "-o", str(out)],
            repo=repo,
            env=base_env(work),
            cwd=work,
        )
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {tail(stderr)}")
        text = out.read_text(encoding="utf-8")
        report = json.loads(text)
        findings = report.get("findings", [])
        kinds = sorted({str(f.get("kind")) for f in findings})
        locations = [e.get("location") for f in findings for e in f.get("evidence") or []]
        complete = bool(report.get("summary", {}).get("complete")) and code == 0
        status = "ok" if complete else ("partial" if code in (0, 3) else "error")
        return Outcome(
            status,
            detected=bool(findings),
            agentic=bool(set(kinds) & SHADOWSCAN_AGENTIC),
            items=len(findings),
            kinds=kinds,
            paths=collect_paths(locations, repo),
            seconds=secs,
            note=f"exit {code}" + ("" if complete else f"; incomplete: {tail(stderr, 160)}"),
            raw={"report.json": text, "stderr.log": stderr[-20000:]},
        )


# ---------------------------------------------------------------------------
# Cisco AI BOM

CISCO_AGENTIC = frozenset({"agent", "agent_proxy", "mcp_server", "mcp_client", "tool", "skill"})


class CiscoAIBOM(Adapter):
    name = "cisco-aibom"
    display = "Cisco AI BOM"
    source = "cisco-ai-defense/aibom"
    mode = (
        "analyze <checkout> --output-format json; the required LLM endpoint is unreachable offline, "
        "so the LLM tier keeps its deterministic candidates (marked unreviewed)"
    )
    agentic_rule = "a component of type " + ", ".join(sorted(CISCO_AGENTIC))

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("aibom", "cisco-aibom")
        return None if exe.exists() else str(exe)

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        out = work / "aibom.json"
        cmd = [
            str(env.venv_bin("aibom", "cisco-aibom")), "analyze", str(repo),
            "--output-format", "json", "--output-file", str(out),
            "--llm-provider", "openai", "--llm-model", "gpt-4o",
            "--llm-api-base", "http://127.0.0.1:9/v1", "--llm-api-key", "unused",
            "--agentic-timeout", "5", "--agentic-max-retry-seconds", "1",
            "--agentic-max-consecutive-failures", "1",
        ]  # fmt: skip
        code, stdout, stderr, secs = isolated(cmd, repo=repo, env=base_env(work), cwd=work)
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        analysis = json.loads(text)["aibom_analysis"]
        meta = analysis.get("metadata", {})
        summary = analysis.get("summary", {})
        types = sorted(summary.get("component_types") or {})
        total = int(summary.get("total_components") or 0)
        locations = json_values(analysis.get("sources") or analysis, frozenset({"file_path", "file", "path"}))
        status = (
            "ok" if meta.get("status") == "completed" and not meta.get("sources_with_errors") else "partial"
        )
        return Outcome(
            status,
            detected=total > 0,
            agentic=bool(set(types) & CISCO_AGENTIC),
            items=total,
            kinds=types,
            paths=collect_paths(locations, repo),
            seconds=secs,
            note=f"exit {code}; status {meta.get('status')}",
            raw={"aibom.json": text, "stderr.log": stderr[-20000:]},
        )


# ---------------------------------------------------------------------------
# agent-bom

AGENTBOM_NOT_AI = frozenset({"invisible_unicode"})  # a source-hygiene check, not an AI component
AGENTBOM_AGENTIC_TYPES = frozenset({"agent_framework"})
_TOKEN_PATH = re.compile(r"<path:([^>]+)>")


class AgentBom(Adapter):
    """The report always lists a pseudo-agent for the scanned project whose
    servers are its sub-projects (surface ``other``) and, when AI is present,
    an ``ai-inventory`` entry; those wrappers are not evidence by themselves.

    AI evidence is an ``ai_inventory`` component or framework agent, a tool
    definition found by its code analysis (``ast_analysis.tools``), a project
    MCP server, or another discovered agent: a GitHub Actions workflow that
    uses AI (``gha:<workflow>``), MCP server images in Compose files, or skill
    files. Calibration notes: Terraform files always yield a ``tf:`` agent so
    that providers can be checked for CVEs, and only one carrying AI resources
    (server tools) is counted; the code analysis's prompt and guardrail
    heuristics fired on non-AI calibration repositories (a seismology library,
    a forum) and are not counted, matching the tool's own AI-BOM entity
    summary, which counts neither."""

    name = "agent-bom"
    display = "agent-bom"
    source = "msaad00/agent-bom"
    mode = (
        "scan <checkout> --no-scan --offline -f json (inventory only, no vulnerability lookups), empty HOME"
    )
    agentic_rule = (
        "a framework agent, an agent_framework component, a tool definition, an MCP server, or a discovered "
        "agent other than the project wrapper (Terraform agents only with AI resources)"
    )
    venv = "agentbom-latest"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin(self.venv, "agent-bom")
        return None if exe.exists() else str(exe)

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        out = work / "agent-bom.json"
        cmd = [str(env.venv_bin(self.venv, "agent-bom")), "scan", str(repo), "--no-scan", "--offline"]
        cmd += ["-f", "json", "-o", str(out)]
        code, stdout, stderr, secs = isolated(cmd, repo=repo, env=base_env(work), cwd=work)
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        doc = json.loads(text)
        inventory = doc.get("ai_inventory") or {}
        components = [c for c in inventory.get("components") or [] if c.get("type") not in AGENTBOM_NOT_AI]
        framework_agents = list(inventory.get("framework_agents") or [])
        tool_defs = list((inventory.get("ast_analysis") or {}).get("tools") or [])
        mcp: list[dict[str, Any]] = []
        others: list[dict[str, Any]] = []
        for agent in doc.get("agents", []):
            if (agent.get("discovery_provenance") or {}).get("source") == "project":
                mcp += [s for s in agent.get("mcp_servers", []) if s.get("surface") == "mcp-server"]
            elif agent.get("source") != "terraform" or any(
                s.get("tools") for s in agent.get("mcp_servers", [])
            ):
                others.append(agent)
        locations: list[Any] = [c.get("file") for c in components]
        locations += [a.get("file_path") for a in framework_agents]
        locations += [t.get("file") for t in tool_defs]
        locations += [
            m for s in mcp for src in s.get("discovery_sources") or [] for m in _TOKEN_PATH.findall(src)
        ]
        locations += [a.get("config_path") for a in others]
        types = {str(c.get("type")) for c in components}
        items = len(components) + len(framework_agents) + len(tool_defs) + len(mcp) + len(others)
        agentic = bool(framework_agents or tool_defs or mcp or others or types & AGENTBOM_AGENTIC_TYPES)
        kinds = sorted(
            types
            | ({"framework_agent"} if framework_agents else set())
            | ({"tool_definition"} if tool_defs else set())
            | ({"mcp"} if mcp else set())
        )
        kinds += sorted({str(a.get("source") or a.get("agent_type")) for a in others})
        return Outcome(
            # Exit 1 reports a critical finding (for example an exposed credential), not a failure.
            "ok" if code in (0, 1) else "partial",
            detected=items > 0,
            agentic=agentic,
            items=items,
            kinds=kinds,
            paths=collect_paths(locations, repo),
            seconds=secs,
            note=f"exit {code}; components={len(components)} framework_agents={len(framework_agents)} "
            f"mcp={len(mcp)} agents={[a.get('name') for a in others][:4]}"[:240],
            raw={"agent-bom.json": text, "stderr.log": stderr[-20000:]},
        )


# ---------------------------------------------------------------------------
# AgentDiscover Scanner (Defend AI)


class AgentDiscover(Adapter):
    """``scan`` holds the code findings (SARIF) and ``audit`` adds MCP
    configuration detection and the agent inventory, so both run and either
    counts. ``scan`` writes no SARIF for a tree without Python or JavaScript and
    says so; that is a clean "nothing found". Audit layers 2-5 need live hosts,
    clusters or cloud accounts and are skipped."""

    name = "agentdiscover"
    display = "AgentDiscover Scanner"
    source = "Defend-AI-Tech-Inc/agent-discover-scanner"
    mode = "scan <checkout> --format sarif, then audit <checkout> --skip-layers 2,3,4,5"
    agentic_rule = "an inventoried agent or an MCP server in the audit"
    _NO_FILES = "No Python or JavaScript files found"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("agentdiscover", "agentdiscover")
        return None if exe.exists() else str(exe)

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        exe = str(env.venv_bin("agentdiscover", "agentdiscover"))
        sarif = work / "results.sarif"
        environ = base_env(work)
        code, stdout, stderr, secs = isolated(
            [exe, "scan", str(repo), "--format", "sarif", "--output", str(sarif)],
            repo=repo,
            env=environ,
            cwd=work,
        )
        results: list[Any] = []
        raw: dict[str, str] = {}
        if sarif.exists():
            raw["results.sarif"] = sarif.read_text(encoding="utf-8")
            doc = json.loads(raw["results.sarif"])
            results = [r for run in doc.get("runs", []) for r in run.get("results", [])]
        elif not (code == 0 and self._NO_FILES in stdout):
            return Outcome("error", seconds=secs, note=f"scan exit {code}: {tail(stderr or stdout)}")
        bundle = work / "audit"
        code2, stdout2, stderr2, secs2 = isolated(
            [exe, "audit", str(repo), "--output", str(bundle), "--skip-layers", "2,3,4,5", "--duration", "1"],
            repo=repo,
            env=environ,
            cwd=work,
        )
        inventory_path = bundle / "raw" / "agent_inventory.json"
        mcp_path = bundle / "mcp-report.md"
        if code2 != 0 or not inventory_path.exists() or not mcp_path.exists():
            return Outcome(
                "error", seconds=secs + secs2, note=f"audit exit {code2}: {tail(stderr2 or stdout2)}", raw=raw
            )
        raw["agent_inventory.json"] = inventory_path.read_text(encoding="utf-8")
        raw["mcp-report.md"] = mcp_path.read_text(encoding="utf-8")
        inventory = json.loads(raw["agent_inventory.json"])
        agents = int((inventory.get("summary") or {}).get("total_agents") or 0)
        mcp = [line[3:].strip() for line in raw["mcp-report.md"].splitlines() if line.startswith("## ")]
        uris = [
            loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            for r in results
            for loc in r.get("locations") or []
        ]
        uris += json_values(inventory, frozenset({"file_path", "source_file", "file", "path"}))
        rules = sorted({str(r.get("ruleId")) for r in results})
        items = len(results) + agents + len(mcp)
        return Outcome(
            "ok",
            detected=items > 0,
            agentic=bool(mcp or agents),
            items=items,
            kinds=rules + (["agent"] if agents else []) + (["mcp"] if mcp else []),
            paths=collect_paths(uris, repo),
            seconds=secs + secs2,
            note=f"rules={','.join(rules)} agents={agents} mcp={len(mcp)}"[:240],
            raw=raw,
        )


# ---------------------------------------------------------------------------
# SafeDep vet: AI discovery (project scope) and AI-tagged code signatures

VET_AI_TAGS = frozenset({"ai", "llm", "llms", "agent", "mcp", "crewai", "langchain", "embeddings"})
VET_AGENT_TAGS = frozenset({"agent", "mcp", "crewai"})
# ai discover kinds: 1 MCP server, 2 coding agent, 4 CLI, 5 project configuration, 9 skill
VET_AGENTIC_KINDS = frozenset({1, 2, 5, 9})


class Vet(Adapter):
    """``vet ai discover --scope project`` reads agent, MCP and assistant
    configuration at the project root; ``vet code scan`` matches code against
    vet's signatures, whose tags mark AI SDKs, agent frameworks and MCP. Both
    run and either counts. Without ``--scope project`` vet also reads ``HOME``
    and runs AI CLIs it finds on ``PATH``; telemetry is disabled."""

    name = "vet"
    display = "SafeDep vet"
    source = "safedep/vet"
    mode = "ai discover --scope project -D <checkout> --report-json, then code scan --app <checkout> --db"
    agentic_rule = (
        "an ai-discover item of kind MCP server, coding agent, project configuration or skill, or a code "
        "signature tagged agent, mcp or crewai"
    )

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.root / "bin" / "vet"
        return None if exe.exists() else str(exe)

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        exe = str(env.root / "bin" / "vet")
        environ = {**base_env(work), "VET_DISABLE_TELEMETRY": "true"}
        discover = work / "vet-ai.json"
        code, stdout, stderr, secs = isolated(
            [exe, "ai", "discover", "--no-banner", "--scope", "project", "-D", str(repo),
             "--report-json", str(discover), "--silent"],
            repo=repo, env=environ, cwd=work,
        )  # fmt: skip
        if code != 0 or not discover.exists():
            return Outcome("error", seconds=secs, note=f"ai discover exit {code}: {tail(stderr or stdout)}")
        raw = {"vet-ai.json": discover.read_text(encoding="utf-8")}
        items = json.loads(raw["vet-ai.json"]) or []
        db = work / "code.db"
        code2, stdout2, stderr2, secs2 = isolated(
            [exe, "code", "scan", "--no-banner", "--db", str(db), "--app", str(repo), "--no-tui"],
            repo=repo, env=environ, cwd=work,
        )  # fmt: skip
        if code2 != 0 or not db.exists():
            return Outcome(
                "error",
                seconds=secs + secs2,
                note=f"code scan exit {code2}: {tail(stderr2 or stdout2)}",
                raw=raw,
            )
        matches = _vet_matches(db)
        raw["code-matches.json"] = json.dumps(matches)
        ai_rows = [m for m in matches if set(m["tags"]) & VET_AI_TAGS]
        locations: list[Any] = [it.get("ConfigPath") for it in items]
        locations += [f for it in items for f in ((it.get("Agent") or {}).get("InstructionFiles") or [])]
        locations += [m["file_path"] for m in ai_rows]
        agentic = any(it.get("Kind") in VET_AGENTIC_KINDS for it in items) or any(
            set(m["tags"]) & VET_AGENT_TAGS for m in ai_rows
        )
        kinds = sorted({f"discover:{it.get('Kind')}" for it in items} | {m["signature_id"] for m in ai_rows})
        return Outcome(
            "ok",
            detected=bool(items or ai_rows),
            agentic=agentic,
            items=len(items) + len(ai_rows),
            kinds=kinds[:40],
            paths=collect_paths(locations, repo),
            seconds=secs + secs2,
            note=f"discover={len(items)} ai_signatures={len(ai_rows)} of {len(matches)} matches",
            raw=raw,
        )


def _vet_matches(db: Path) -> list[dict[str, Any]]:
    import sqlite3

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "select signature_id, tags, file_path, line from code_signature_matches"
        ).fetchall()
    finally:
        con.close()
    out = []
    for signature, tags, path, line in rows:
        if isinstance(tags, bytes):
            tags = tags.decode("utf-8", "replace")
        try:
            parsed = json.loads(tags) if tags else []
        except json.JSONDecodeError:
            parsed = []
        out.append(
            {"signature_id": signature, "tags": [str(t) for t in parsed], "file_path": path, "line": line}
        )
    return out


# ---------------------------------------------------------------------------
# agentguard (ak2dev)

AGENTGUARD_AGENTIC = frozenset(
    {"mcp_server", "mcp_client_config", "skill", "agent", "subagent", "instruction_file"}
)


class AgentGuard(Adapter):
    """``scan`` walks the whole tree and inventories MCP servers, MCP client
    configuration, skills and agent instruction files. An explicit empty
    policy keeps the scanned repository's own ``.agentguard.yaml`` from
    setting the policy. Exit 1 means a high-severity finding; 2 an analyzer
    error, kept as a partial report."""

    name = "agentguard"
    display = "agentguard"
    source = "ak2dev/agentguard-v1"
    mode = "scan <checkout> --config <empty policy> -f json"
    agentic_rule = "an inventory item of kind " + ", ".join(sorted(AGENTGUARD_AGENTIC))

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("agentguard", "agentguard")
        return None if exe.exists() else str(exe)

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        policy = work / "empty-policy.yaml"
        policy.write_text("{}\n", encoding="utf-8")
        out = work / "agentguard.json"
        code, stdout, stderr, secs = isolated(
            [str(env.venv_bin("agentguard", "agentguard")), "scan", str(repo), "--config", str(policy),
             "-f", "json", "-o", str(out)],
            repo=repo, env=base_env(work), cwd=work,
        )  # fmt: skip
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        doc = json.loads(text)
        inventory = doc.get("inventory") or []
        kinds = sorted({str(i.get("kind")) for i in inventory})
        return Outcome(
            "ok" if code in (0, 1) else "partial",
            detected=bool(inventory),
            agentic=bool(set(kinds) & AGENTGUARD_AGENTIC),
            items=len(inventory),
            kinds=kinds,
            paths=collect_paths([i.get("root") for i in inventory], repo),
            seconds=secs,
            note=f"exit {code}; inventory={len(inventory)} findings={len(doc.get('findings') or [])}",
            raw={"agentguard.json": text, "stderr.log": stderr[-20000:]},
        )


# ---------------------------------------------------------------------------
# cdxgen (OWASP CycloneDX) in AI, MCP and AI-skill mode


class Cdxgen(Adapter):
    """``-t ai -t mcp -t ai-skill`` produces an AI/ML-BOM: models, inference
    services, agent definitions, MCP configuration, packages and services,
    and agent instruction files. Dependency installation is off and an empty
    command allow-list stops cdxgen from running package managers or other
    binaries inside the checkout."""

    name = "cdxgen"
    display = "cdxgen (CycloneDX AI/MCP BOM)"
    source = "CycloneDX/cdxgen"
    mode = (
        "-t ai -t mcp -t ai-skill -r --no-install-deps, FETCH_LICENSE=false, CDXGEN_ALLOWED_COMMANDS=__none__"
    )
    agentic_rule = "a component or service with cdx:agent:* or cdx:mcp:* properties"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.root / "cdxgen" / "node_modules" / ".bin" / "cdxgen"
        return None if exe.exists() else str(exe)

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        exe = env.root / "cdxgen" / "node_modules" / ".bin" / "cdxgen"
        out = work / "bom.json"
        node_bin = str(Path(os.environ.get("REALBENCH_NODE", "/opt/node22/bin/node")).parent)
        environ = {
            **base_env(work, extra_path=node_bin),
            "FETCH_LICENSE": "false",
            "CDXGEN_ALLOWED_COMMANDS": "__none__",
        }
        code, stdout, stderr, secs = isolated(
            [str(exe), "-t", "ai", "-t", "mcp", "-t", "ai-skill", "-r", "--no-install-deps",
             "--spec-version", "1.6", "-o", str(out), str(repo)],
            repo=repo, env=environ, cwd=work,
        )  # fmt: skip
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        bom = json.loads(text)
        ai_items, agentic_items, locations = [], [], []
        for item in [*(bom.get("components") or []), *(bom.get("services") or [])]:
            props = {p.get("name"): p.get("value") for p in item.get("properties") or []}
            keys = [k for k in props if isinstance(k, str)]
            if any(k.startswith(("cdx:ai:", "cdx:agent:", "cdx:mcp:")) for k in keys):
                ai_items.append(item)
                locations.append(props.get("SrcFile"))
                if any(k.startswith(("cdx:agent:", "cdx:mcp:")) for k in keys):
                    agentic_items.append(item)
        kinds = sorted({str(i.get("type") or "service") for i in ai_items})
        return Outcome(
            "ok" if code == 0 else "partial",
            detected=bool(ai_items),
            agentic=bool(agentic_items),
            items=len(ai_items),
            kinds=kinds,
            paths=collect_paths(locations, repo),
            seconds=secs,
            note=f"exit {code}; ai={len(ai_items)} agentic={len(agentic_items)}",
            raw={"bom.json": text, "stderr.log": stderr[-20000:]},
        )


# ---------------------------------------------------------------------------
# Baselines: what an organisation can do with grep and a dependency list

GREP_GENAI = (
    r"openai|anthropic|langchain|langgraph|llama_index|llamaindex|crewai|autogen|semantic_kernel"
    r"|semantic-kernel|ollama|litellm|mistralai|huggingface_hub|chatgpt|gpt-4|gpt-3\.5|claude|gemini"
    r"|bedrock|vertexai|modelcontextprotocol|mcpServers"
)
GREP_AGENT = (
    r"langgraph|crewai|autogen|AgentExecutor|create_react_agent|modelcontextprotocol|mcpServers|FastMCP"
    r"|smolagents|pydantic_ai|openai-agents|@openai/agents|claude_agent_sdk|google\.adk"
)


def _rg_files(repo: Path, pattern: str, work: Path) -> Run:
    cmd = ["rg", "-i", "-l", "--hidden", "--no-ignore", "--no-messages", "-g", "!.git/", "-e", pattern, "."]
    return isolated(cmd, repo=repo, env=base_env(work), cwd=repo)


class KeywordGrep(Adapter):
    name = "baseline-grep"
    display = "Baseline: keyword grep"
    source = "this repository (ripgrep)"
    mode = "case-insensitive ripgrep over every file except .git for provider and framework names"
    agentic_rule = "a file matches the agent-framework or MCP name list"

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        code, stdout, stderr, secs = _rg_files(repo, GREP_GENAI, work)
        if code not in (0, 1):
            return Outcome("error", seconds=secs, note=f"rg exit {code}: {tail(stderr)}")
        files = [line.removeprefix("./") for line in stdout.splitlines() if line]
        code2, stdout2, stderr2, secs2 = _rg_files(repo, GREP_AGENT, work)
        if code2 not in (0, 1):
            return Outcome("error", seconds=secs + secs2, note=f"rg exit {code2}: {tail(stderr2)}")
        agent_files = [line.removeprefix("./") for line in stdout2.splitlines() if line]
        return Outcome(
            "ok",
            detected=bool(files),
            agentic=bool(agent_files),
            items=len(files),
            kinds=["match"] if files else [],
            paths=sorted(files)[:MAX_PATHS],
            seconds=secs + secs2,
            note=f"{len(files)} files, {len(agent_files)} agent files",
        )


# Direct dependencies that mean generative-AI use; the agentic subset marks agent frameworks and MCP.
GENAI_PACKAGES = {
    "pypi": (
        r"openai|anthropic|google-genai|google-generativeai|google-cloud-aiplatform|vertexai|langchain.*"
        r"|langgraph.*|llama-index.*|llama_index.*|crewai.*|autogen.*|ag2|pyautogen|semantic-kernel"
        r"|haystack-ai|farm-haystack|dspy|dspy-ai|smolagents|pydantic-ai.*|agno|phidata|mistralai|cohere"
        r"|groq|together|replicate|ollama|litellm|instructor|guidance|diffusers|vllm|llama-cpp-python"
        r"|gpt4all|mcp|fastmcp|strands-agents.*|openai-agents|claude-agent-sdk|claude-code-sdk"
        r"|google-adk|letta|camel-ai"
    ),
    "npm": (
        r"openai|@anthropic-ai/.+|@google/genai|@google/generative-ai|@google-cloud/vertexai|langchain"
        r"|@langchain/.+|llamaindex|ai|@ai-sdk/.+|@modelcontextprotocol/.+|@mastra/.+|ollama"
        r"|@mistralai/mistralai|cohere-ai|groq-sdk|together-ai|replicate|@huggingface/inference"
        r"|@openai/agents.*|@aws-sdk/client-bedrock.*|@azure/openai|fastmcp"
    ),
    "go": (
        r"github\.com/sashabaranov/go-openai|github\.com/openai/openai-go.*|github\.com/anthropics/anthropic-sdk-go"
        r"|github\.com/tmc/langchaingo|github\.com/google/generative-ai-go|google\.golang\.org/genai"
        r"|github\.com/ollama/ollama|github\.com/mark3labs/mcp-go|github\.com/modelcontextprotocol/go-sdk"
        r"|github\.com/cloudwego/eino|github\.com/aws/aws-sdk-go-v2/service/bedrock.*"
        r"|github\.com/firebase/genkit.*"
    ),
    "maven": (
        r"dev\.langchain4j:.+|org\.springframework\.ai:.+|com\.openai:openai-java|com\.anthropic:anthropic-java"
        r"|com\.google\.genai:google-genai|io\.modelcontextprotocol\.sdk:.+|software\.amazon\.awssdk:bedrock.*"
        r"|langchain4j.*|spring-ai-.+|openai-java|anthropic-java|google-genai|mcp"
    ),
    "nuget": (
        r"Microsoft\.SemanticKernel.*|OpenAI|Azure\.AI\.OpenAI|Anthropic\.SDK|Microsoft\.Extensions\.AI.*"
        r"|ModelContextProtocol.*|AWSSDK\.BedrockRuntime|OllamaSharp|Microsoft\.Agents\..+"
    ),
    "cargo": r"async-openai|rig-core|ollama-rs|rmcp|genai",
    "gem": r"ruby-openai|anthropic|langchainrb|omniai",
    "composer": r"openai-php/client|prism-php/prism|theodo-group/llphant",
}
AGENT_PACKAGES = (
    r"langgraph.*|crewai.*|autogen.*|ag2|pyautogen|smolagents|pydantic-ai.*|openai-agents|claude-agent-sdk"
    r"|google-adk|agno|phidata|letta|camel-ai|strands-agents.*|mcp|fastmcp|@modelcontextprotocol/.+|@mastra/.+"
    r"|@openai/agents.*|@anthropic-ai/claude-agent-sdk|@aws-sdk/client-bedrock-agent.*"
    r"|github\.com/mark3labs/mcp-go|github\.com/modelcontextprotocol/go-sdk|io\.modelcontextprotocol\.sdk:.+"
    r"|ModelContextProtocol.*|rmcp|Microsoft\.Agents\..+"
)
_MANIFEST = re.compile(
    r"(^|/)(requirements[\w.-]*\.txt|pyproject\.toml|setup\.py|setup\.cfg|Pipfile|package\.json|go\.mod"
    r"|pom\.xml|build\.gradle(\.kts)?|[\w.-]+\.csproj|Directory\.Packages\.props|Gemfile|composer\.json"
    r"|Cargo\.toml)$"
)
_SKIP_DIRS = frozenset({".git", "node_modules", "vendor", "third_party", "site-packages", ".venv", "venv"})


def manifest_packages(path: Path) -> list[tuple[str, str]]:
    """``(ecosystem, name)`` direct dependencies declared in one manifest (best effort, no resolution)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:500_000]
    except OSError:
        return []
    name = path.name
    out: list[tuple[str, str]] = []
    if name == "package.json":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(doc, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                block = doc.get(section)
                if isinstance(block, dict):
                    out += [("npm", k) for k in block]
    elif name == "composer.json":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(doc, dict):
            for section in ("require", "require-dev"):
                block = doc.get(section)
                if isinstance(block, dict):
                    out += [("composer", k) for k in block]
    elif name.startswith("requirements") or name == "Pipfile":
        for line in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)", line.split("#")[0])
            if m and not line.lstrip().startswith("-"):
                out.append(("pypi", m.group(1)))
    elif name in ("pyproject.toml", "setup.py", "setup.cfg"):
        out += [
            ("pypi", m)
            for m in re.findall(
                r"""['"]\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|['"])""", text
            )
        ]
        out += [
            ("pypi", m) for m in re.findall(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*=\s*['\"{]", text, re.M)
        ]
        out += [
            ("pypi", m)
            for m in re.findall(r"^\s+([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:[<>=!~]=?.*)?$", text, re.M)
        ]
    elif name == "go.mod":
        out += [
            ("go", m) for m in re.findall(r"^\s*(?:require\s+)?([\w.-]+\.[\w.-]+/[\w./-]+)\s+v", text, re.M)
        ]
    elif name == "pom.xml":
        for group, artifact in re.findall(
            r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>", text
        ):
            out.append(("maven", f"{group.strip()}:{artifact.strip()}"))
            out.append(("maven", artifact.strip()))
    elif name.startswith("build.gradle"):
        for coord in re.findall(r"""['"]([\w.\-]+:[\w.\-]+)(?::[^'"]*)?['"]""", text):
            out.append(("maven", coord))
            out.append(("maven", coord.split(":")[1]))
    elif name.endswith(".csproj") or name == "Directory.Packages.props":
        out += [("nuget", m) for m in re.findall(r'Package(?:Reference|Version)\s+Include="([^"]+)"', text)]
    elif name == "Gemfile":
        out += [("gem", m) for m in re.findall(r"""^\s*gem\s+['"]([^'"]+)['"]""", text, re.M)]
    elif name == "Cargo.toml":
        out += [("cargo", m) for m in re.findall(r"^\s*([A-Za-z0-9_\-]+)\s*=", text, re.M)]
    return out


class ManifestDeps(Adapter):
    name = "baseline-deps"
    display = "Baseline: manifest dependencies"
    source = "this repository"
    mode = "parse dependency manifests (outside vendored dirs) for a fixed list of generative-AI packages"
    agentic_rule = "a dependency on an agent framework or MCP package"

    def scan(self, repo: Path, work: Path, env: ToolEnv) -> Outcome:
        started = time.monotonic()
        genai = {eco: re.compile(f"(?i)^(?:{p})$") for eco, p in GENAI_PACKAGES.items()}
        agent = re.compile(f"(?i)^(?:{AGENT_PACKAGES})$")
        hits: list[tuple[str, str]] = []
        agent_hits: list[str] = []
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for f in files:
                path = Path(root) / f
                rel = str(path.relative_to(repo))
                if not _MANIFEST.search(rel) or path.is_symlink():
                    continue
                for eco, pkg in manifest_packages(path):
                    if genai[eco].match(pkg):
                        hits.append((rel, pkg))
                        if agent.match(pkg):
                            agent_hits.append(pkg)
        return Outcome(
            "ok",
            detected=bool(hits),
            agentic=bool(agent_hits),
            items=len(hits),
            kinds=sorted({p for _, p in hits})[:40],
            paths=sorted({r for r, _ in hits})[:MAX_PATHS],
            seconds=time.monotonic() - started,
            note=",".join(sorted({p for _, p in hits}))[:240],
        )


ADAPTERS: tuple[Adapter, ...] = (
    ShadowScan(),
    CiscoAIBOM(),
    AgentBom(),
    AgentDiscover(),
    Vet(),
    AgentGuard(),
    Cdxgen(),
    KeywordGrep(),
    ManifestDeps(),
)
