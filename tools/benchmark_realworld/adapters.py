"""Tool adapters for the real-world benchmark.

The existing adapters in ``tools.benchmark.adapters`` are reused unchanged, so
their detection rules are the ones fixed for the synthetic benchmark. The three
adapters defined here cover tools that benchmark had not run; their rules are
fixed in ``PROTOCOL.md`` section 7 and were calibrated on constructed trees that
are not corpus members.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.benchmark.adapters import (
    Adapter,
    AgentBom,
    AgentDiscover,
    AIDetector,
    CiscoAIBOM,
    CiscoMCPScanner,
    ClawHunter,
    Outcome,
    ShadowScan,
    ShadowScanDedicated,
    SnykAgentScan,
    ToolEnv,
    _base_env,
    _empty_home,
    _isolated,
    _tail,
)
from tools.benchmark.common import Case

# The versions the real-world run used. ``tests/unit/test_benchmark_realworld.py``
# checks these against ``install_tools.sh``, so the two cannot drift apart.
TOOL_PINS: dict[str, str] = {
    "cisco-aibom": "1.10.0",
    "agent-bom": "0.108.2",
    "agentdiscover": "2.9.5",
    "snyk-agent-scan": "0.6.8",
    "cisco-ai-mcp-scanner": "4.8.6",
    "mcp-audit-scanner": "0.18.2",
    "shadow-mcp": "0.2.0",
    "safedep-vet": "v1.17.5",
}


def _in_scope(items: list[Any], scope: str) -> list[Any] | None:
    """Items for one ``Scope`` code. ``None`` (an unexpected format) when an item has no
    Scope or a Scope other than the two documented codes; such an item is never dropped."""
    if any(not isinstance(i, dict) or str(i.get("Scope")) not in ("1", "2") for i in items):
        return None
    return [i for i in items if str(i["Scope"]) == scope]


class SafeDepVet(Adapter):
    """``vet ai discover``: the project scope for a repository, the system scope for a home.

    Calibrated: an empty inventory is printed as ``null``; each item carries a
    ``Scope`` of ``"1"`` (system) or ``"2"`` (project).
    """

    name = "safedep-vet"
    display = "SafeDep vet"
    source = "safedep/vet"
    surfaces = {
        "repo": "vet ai discover -D <tree> --scope project, empty home; any project-scope item",
        "endpoint": "vet ai discover --scope system, HOME=<tree>; any system-scope item",
    }

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.root / "bin" / "vet"
        return None if exe.exists() else str(exe)

    def _inventory(
        self, home: Path, cwd: Path, work: Path, env: ToolEnv, scope: str, project: Path | None
    ) -> Any:
        report = work / f"vet-{scope}.json"
        cmd = [str(env.root / "bin" / "vet"), "ai", "discover", "--scope", scope]
        cmd += ["--report-json", str(report), "--no-banner", "-s"]
        if project is not None:
            cmd += ["-D", str(project)]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(home, work), cwd=cwd)
        if code != 0 or not report.exists():
            return None, "", f"exit {code}: {_tail(stderr or stdout)}", secs
        text = report.read_text(encoding="utf-8")
        items = json.loads(text)
        if items is None:  # an empty inventory is printed as null
            items = []
        if not isinstance(items, list):
            return None, "", "unexpected inventory format (not a list)", secs
        return items, text, "", secs

    def _outcome(self, items: list[Any], text: str, secs: float, scope: str, name: str) -> Outcome:
        own = _in_scope(items, scope)
        if own is None:
            return Outcome("error", seconds=secs, note="unexpected inventory format (no Scope)")
        return Outcome(
            "ok",
            detected=bool(own),
            items=len(own),
            agentic=bool(own),
            seconds=secs,
            note=",".join(sorted({str(i.get("App")) for i in own}))[:200],
            raw={name: text},
        )

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        tree = self.tree(case, work, "repo")
        home = _empty_home(work)
        items, text, err, secs = self._inventory(home, home, work, env, "project", tree)
        if items is None:
            return Outcome("error", seconds=secs, note=err)
        return self._outcome(items, text, secs, "2", "vet-project.json")

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        home = self.tree(case, work, "home")
        cwd = work / "cwd"
        cwd.mkdir()
        items, text, err, secs = self._inventory(home, cwd, work, env, "system", None)
        if items is None:
            return Outcome("error", seconds=secs, note=err)
        return self._outcome(items, text, secs, "1", "vet-system.json")


class MCPAuditDiscover(Adapter):
    """``mcp-audit discover --json`` from the ``mcp-audit-scanner`` package.

    Not the ``mcp-audit`` command of the ``shadow-mcp`` package, which shares the name.
    Calibrated: ``--path`` finds a project ``.mcp.json`` in a tree; a home directory
    yields its client configurations. Discovery reads files only.
    """

    name = "mcp-audit"
    display = "mcp-audit (mcp-audit-scanner)"
    source = "mcp-audit-scanner"
    surfaces = {
        "repo": "discover --json --path <tree>, empty home; any entry",
        "endpoint": "discover --json, HOME=<tree>; any client or server entry",
    }

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("mcpaudit", "mcp-audit")
        return None if exe.exists() else str(exe)

    def _discover(self, home: Path, work: Path, env: ToolEnv, extra: Path | None) -> tuple[Any, str, float]:
        cmd = [str(env.venv_bin("mcpaudit", "mcp-audit")), "discover", "--json"]
        if extra is not None:
            cmd += ["--path", str(extra)]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(home, work), cwd=work)
        if code != 0:
            return None, f"exit {code}: {_tail(stderr or stdout)}", secs
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return None, f"unreadable output: {_tail(stdout)}", secs
        if not isinstance(doc, list):
            return None, "unexpected output shape", secs
        return doc, stdout, secs

    def _outcome(self, items: Any, text: str, secs: float) -> Outcome:
        return Outcome(
            "ok",
            detected=bool(items),
            items=len(items),
            agentic=bool(items),
            seconds=secs,
            note=",".join(sorted({str(i.get("client")) for i in items if isinstance(i, dict)}))[:200],
            raw={"discover.json": text},
        )

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        tree = self.tree(case, work, "repo")
        items, text, secs = self._discover(_empty_home(work), work, env, tree)
        if items is None:
            return Outcome("error", seconds=secs, note=text)
        return self._outcome(items, text, secs)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        home = self.tree(case, work, "home")
        items, text, secs = self._discover(home, work, env, None)
        if items is None:
            return Outcome("error", seconds=secs, note=text)
        return self._outcome(items, text, secs)


class ShadowMCPDiscover(Adapter):
    """``shadow-mcp discover`` (inventory only, no grading, no processes, no ``claude`` CLI).

    Its collectors read user-scope locations only (Claude Code and Desktop, Codex,
    DXT and project ``.mcp.json`` from the working directory), so it is scored on the
    home view only. ``--connect`` is never used: it starts servers named in configs.
    """

    name = "shadow-mcp"
    display = "shadow-mcp"
    source = "shadow-mcp"
    surfaces = {"endpoint": "discover --home <tree> --no-processes --no-cli; any server in the inventory"}

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("shadowmcp", "shadow-mcp")
        return None if exe.exists() else str(exe)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        home = self.tree(case, work, "home")
        out = work / "shadow-mcp.json"
        cmd = [str(env.venv_bin("shadowmcp", "shadow-mcp")), "discover", "--home", str(home)]
        cmd += ["--no-processes", "--no-cli", "--format", "json", "--json", str(out)]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(home, work), cwd=work)
        if code != 0 or not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        try:
            servers = list(json.loads(text).get("servers") or [])
        except (json.JSONDecodeError, AttributeError):
            return Outcome("error", seconds=secs, note="unreadable inventory")
        return Outcome(
            "ok",
            detected=bool(servers),
            items=len(servers),
            agentic=bool(servers),
            seconds=secs,
            note=",".join(sorted({str(s.get("name")) for s in servers if isinstance(s, dict)}))[:200],
            raw={"shadow-mcp.json": text},
        )


class ShadowScanDedicatedV2(ShadowScanDedicated):
    """Dedicated connectors on the endpoint surface only (benchmark v2).

    On the repository surface this configuration calls the same ``code.filesystem``
    scan as the published configuration, so v2 does not run it twice. The v1
    repository rows are kept and reported as a determinism check.
    """

    surfaces = {"endpoint": ShadowScanDedicated.surfaces["endpoint"]}


# Every tool the real-world benchmark runs. Network-only tools (Open Shadow AI,
# AgentSonar, Shadow AI Detector) have no real-world input and are not listed.
ADAPTERS: tuple[Adapter, ...] = (
    ShadowScan(),
    ShadowScanDedicated(),
    CiscoAIBOM(),
    AgentBom(),
    AgentDiscover(),
    SafeDepVet(),
    MCPAuditDiscover(),
    ShadowMCPDiscover(),
    SnykAgentScan(),
    CiscoMCPScanner(),
    ClawHunter(),
    AIDetector(),
)


class ShadowScanRepoOnlyV2(ShadowScan):
    """The published configuration on the repository surface only (benchmark v2).

    On the endpoint surface this configuration scans the copied tree as a path, so
    its rows measure repository files and not the home view (protocol v2, section 5).
    Its v1 whole-tree home rows are reported as a diagnostic, not as endpoint evidence.
    """

    surfaces = {"repo": ShadowScan.surfaces["repo"]}


class CiscoAIBOMRepoOnlyV2(CiscoAIBOM):
    """Cisco AI BOM on the repository surface only (benchmark v2); see ShadowScanRepoOnlyV2."""

    surfaces = {"repo": CiscoAIBOM.surfaces["repo"]}


class AgentDiscoverRepoOnlyV2(AgentDiscover):
    """AgentDiscover on the repository surface only (benchmark v2); see ShadowScanRepoOnlyV2."""

    surfaces = {"repo": AgentDiscover.surfaces["repo"]}


# The tools for benchmark v2. Each override changes only the surfaces a tool is run on;
# every other tool is the v1 adapter unchanged.
_V2_OVERRIDES: dict[str, Adapter] = {
    "shadowscan": ShadowScanRepoOnlyV2(),
    "shadowscan-dedicated": ShadowScanDedicatedV2(),
    "cisco-aibom": CiscoAIBOMRepoOnlyV2(),
    "agentdiscover": AgentDiscoverRepoOnlyV2(),
}
ADAPTERS_V2: tuple[Adapter, ...] = tuple(_V2_OVERRIDES.get(a.name, a) for a in ADAPTERS)
