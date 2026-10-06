"""Tool adapters: run one tool on one case and decide "detected" by a fixed rule.

Every adapter runs its tool as a subprocess in a fresh network namespace
(``unshare -n``) so no tool can reach the internet, start a remote MCP session
or upload case content. Third-party tools are installed outside this
repository (see README); the paths come from ``ToolEnv``.

The detection rule for each tool is written here before the scored run: a case
is *detected* when the tool's own report contains at least one AI-related item
(as that tool defines it) for the case input. Reports are kept verbatim in the
results directory so the rule can be audited and re-applied.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from tools.benchmark.common import Case
from tools.benchmark.generate import materialize

TIMEOUT_S = 300
AGENTIC_KINDS = frozenset({"agent", "mcp-server", "agent-config", "bot-app", "workflow"})


@dataclass
class Outcome:
    """``status`` is ``ok``, ``error`` (crash, timeout, incomplete scan) or ``n/a``."""

    status: str
    detected: bool = False
    items: int = 0
    agentic: bool | None = None
    seconds: float = 0.0
    note: str = ""
    raw: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolEnv:
    root: Path  # directory holding third-party checkouts, venvs and builds
    python: str  # interpreter running this benchmark (and ShadowScan)

    def venv_bin(self, venv: str, exe: str) -> Path:
        return self.root / "venvs" / venv / "bin" / exe

    def checkout(self, name: str) -> Path:
        return self.root / "third_party" / name


Run = tuple[int, str, str, float]


def _isolated(cmd: list[str], *, env: dict[str, str], cwd: Path, stdin: str | None = None) -> Run:
    """Run ``cmd`` without network access; returns (code, stdout, stderr, seconds)."""
    full = ["unshare", "-n", "--", *cmd]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            full,
            input=stdin,
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd,
            timeout=TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {TIMEOUT_S}s", time.monotonic() - started
    return proc.returncode, proc.stdout, proc.stderr, time.monotonic() - started


def _base_env(home: Path, extra_path: str = "") -> dict[str, str]:
    path = ":".join(p for p in (extra_path, "/usr/local/bin:/usr/bin:/bin") if p)
    return {"HOME": str(home), "PATH": path, "LANG": "C.UTF-8", "TMPDIR": str(home.parent / "tmp")}


def _tail(text: str, n: int = 300) -> str:
    return text.strip().replace("\n", " | ")[-n:]


class Adapter:
    name = ""
    display = ""
    source = ""  # upstream repository
    surfaces: dict[str, str] = {}  # surface -> how the tool is run on it

    def unavailable(self, env: ToolEnv) -> str | None:
        """Return a reason when the tool is not installed."""
        return None

    def run(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        if case.surface not in self.surfaces:
            return Outcome("n/a", note="surface not supported by this tool")
        reason = self.unavailable(env)
        if reason:
            return Outcome("error", note=f"not installed: {reason}")
        (work / "tmp").mkdir(parents=True, exist_ok=True)
        return getattr(self, f"run_{case.surface}")(case, work, env)  # type: ignore[no-any-return]

    # helpers ------------------------------------------------------------

    @staticmethod
    def tree(case: Case, work: Path, name: str) -> Path:
        root = work / name
        root.mkdir()
        materialize(case, root)
        return root


# ----------------------------------------------------------------------------
# ShadowScan (this repository)


def access_log_records(case: Case) -> list[dict[str, Any]]:
    """Render flows as nginx-style JSON access-log records."""
    return [
        {
            "time": f["ts"],
            "remote_addr": f["src_ip"],
            "remote_user": f["user"],
            "request_method": f["method"],
            "request_uri": f["path"],
            "status": f["status"],
            "body_bytes_sent": f["bytes_in"],
            "http_user_agent": f["user_agent"],
            "host": f["host"],
        }
        for f in case.flows
    ]


class ShadowScan(Adapter):
    name = "shadowscan"
    display = "Project Nexus ShadowScan"
    source = "aisecnomad/Project-Nexus"
    surfaces = {
        "repo": "code.filesystem on the checkout",
        "endpoint": "code.filesystem on the home directory",
        "network": "gateway.logs on a JSON access log",
    }

    def _scan(self, connector: dict[str, Any], work: Path, env: ToolEnv) -> Outcome:
        cfg = work / "shadowscan.yaml"
        cfg.write_text(json.dumps({"connectors": [connector]}), encoding="utf-8")
        out = work / "report.json"
        code, stdout, stderr, secs = _isolated(
            [env.python, "-m", "shadowscan", "scan", "-c", str(cfg), "-f", "json", "-o", str(out)],
            env={**_base_env(work), "PYTHONPATH": str(Path(__file__).resolve().parents[2])},
            cwd=work,
        )
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr)}")
        text = out.read_text(encoding="utf-8")
        report = json.loads(text)
        summary = report.get("summary", {})
        findings = report.get("findings", [])
        kinds = {f.get("kind") for f in findings}
        raw = {"report.json": text}
        if code == 3 or not summary.get("complete", False):
            return Outcome("error", seconds=secs, note=f"incomplete scan (exit {code})", raw=raw)
        if code != 0:
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr)}", raw=raw)
        return Outcome(
            "ok",
            detected=bool(findings),
            items=len(findings),
            agentic=bool(kinds & AGENTIC_KINDS),
            seconds=secs,
            note=",".join(sorted(k for k in kinds if k)),
            raw=raw,
        )

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "repo")
        return self._scan({"name": "code.filesystem", "path": str(root), "use_git": False}, work, env)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "home")
        return self._scan({"name": "code.filesystem", "path": str(root), "use_git": False}, work, env)

    def run_network(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        log = work / "access.jsonl"
        log.write_text("".join(json.dumps(r) + "\n" for r in access_log_records(case)), encoding="utf-8")
        return self._scan({"name": "gateway.logs", "input": str(log)}, work, env)


# ----------------------------------------------------------------------------
# Cisco AI BOM


def _json_items(doc: Any, keys: tuple[str, ...]) -> list[Any]:
    """Collect list values stored under any of ``keys`` anywhere in ``doc``."""
    found: list[Any] = []
    stack = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in keys and isinstance(v, list):
                    found.extend(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return found


class CiscoAIBOM(Adapter):
    name = "cisco-aibom"
    display = "Cisco AI BOM"
    source = "cisco-ai-defense/aibom"
    surfaces = {
        "repo": "analyze <checkout>; Tier-3 LLM classifier unreachable (deterministic floor)",
        "endpoint": "analyze <home directory>; Tier-3 LLM classifier unreachable",
    }

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("aibom", "cisco-aibom")
        return None if exe.exists() else str(exe)

    def _analyze(self, root: Path, work: Path, env: ToolEnv) -> Outcome:
        out = work / "aibom.json"
        cmd = [
            str(env.venv_bin("aibom", "cisco-aibom")), "analyze", str(root),
            "--output-format", "json", "--output-file", str(out),
            # analyze requires an LLM; there is no network, so Tier 3 degrades to
            # the deterministic candidates, which the report marks `unreviewed`.
            "--llm-provider", "openai", "--llm-model", "gpt-4o",
            "--llm-api-base", "http://127.0.0.1:9/v1", "--llm-api-key", "unused",
        ]  # fmt: skip
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(work), cwd=work)
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        doc = json.loads(text)
        comps = _json_items(doc, ("components", "ai_components"))
        types = {str(c.get("type") or c.get("component_type")) for c in comps if isinstance(c, dict)}
        return Outcome(
            "ok",
            detected=bool(comps),
            items=len(comps),
            agentic=bool(types & {"agent", "agent_proxy", "mcp_server", "mcp_client", "tool", "skill"}),
            seconds=secs,
            note=",".join(sorted(types))[:200],
            raw={"aibom.json": text},
        )

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        return self._analyze(self.tree(case, work, "repo"), work, env)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        return self._analyze(self.tree(case, work, "home"), work, env)


# ----------------------------------------------------------------------------
# agent-bom


class AgentBom(Adapter):
    name = "agent-bom"
    display = "agent-bom"
    source = "msaad00/agent-bom"
    surfaces = {
        "repo": "scan <checkout> --no-scan (inventory only)",
        "endpoint": "scan with HOME=<case> (client auto-discovery) --no-scan",
    }

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("agentbom", "agent-bom")
        return None if exe.exists() else str(exe)

    def _scan(self, args: list[str], home: Path, work: Path, env: ToolEnv) -> Outcome:
        out = work / "agent-bom.json"
        cmd = [str(env.venv_bin("agentbom", "agent-bom")), "scan", *args, "--no-scan", "--offline"]
        cmd += ["-f", "json", "-o", str(out)]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(home), cwd=work)
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        doc = json.loads(text)
        agents = _json_items(doc, ("agents",))
        servers = _json_items(doc, ("mcp_servers", "servers"))
        ai = _json_items(doc, ("ai_components", "ai_inventory", "ai_findings", "skills"))
        items = len(agents) + len(servers) + len(ai)
        return Outcome(
            "ok",
            detected=items > 0,
            items=items,
            agentic=bool(agents or servers),
            seconds=secs,
            note=f"agents={len(agents)} servers={len(servers)} ai={len(ai)}",
            raw={"agent-bom.json": text},
        )

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "repo")
        empty_home = work / "emptyhome"
        empty_home.mkdir()
        return self._scan([str(root)], empty_home, work, env)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        home = self.tree(case, work, "home")
        return self._scan([], home, work, env)


# ----------------------------------------------------------------------------
# AgentDiscover Scanner (Defend AI)


class AgentDiscover(Adapter):
    name = "agentdiscover"
    display = "AgentDiscover Scanner"
    source = "Defend-AI-Tech-Inc/agent-discover-scanner"
    surfaces = {
        "repo": "scan <checkout> --format sarif (Layer 1 source analysis)",
        "endpoint": "scan <home directory> --format sarif (Layer 1 source analysis)",
    }

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("agentdiscover", "agentdiscover")
        return None if exe.exists() else str(exe)

    def _scan(self, root: Path, work: Path, env: ToolEnv) -> Outcome:
        out = work / "results.sarif"
        cmd = [str(env.venv_bin("agentdiscover", "agentdiscover")), "scan", str(root)]
        cmd += ["--format", "sarif", "--output", str(out)]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(work), cwd=work)
        if not out.exists():
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        text = out.read_text(encoding="utf-8")
        results = _json_items(json.loads(text), ("results",))
        rules = {str(r.get("ruleId")) for r in results if isinstance(r, dict)}
        return Outcome(
            "ok",
            detected=bool(results),
            items=len(results),
            seconds=secs,
            note=",".join(sorted(rules))[:200],
            raw={"results.sarif": text},
        )

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        return self._scan(self.tree(case, work, "repo"), work, env)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        return self._scan(self.tree(case, work, "home"), work, env)


# ----------------------------------------------------------------------------
# Snyk Agent Scan


class SnykAgentScan(Adapter):
    name = "snyk-agent-scan"
    display = "Snyk Agent Scan"
    source = "snyk/agent-scan"
    surfaces = {
        "repo": "inspect <checkout> --json (project-scope configs; no analysis upload)",
        "endpoint": "inspect --json with HOME=<case> (machine discovery; no analysis upload)",
    }

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("snyk", "snyk-agent-scan")
        return None if exe.exists() else str(exe)

    def _inspect(self, args: list[str], home: Path, work: Path, env: ToolEnv) -> Outcome:
        cmd = [str(env.venv_bin("snyk", "snyk-agent-scan")), "inspect", *args, "--json"]
        cmd += ["--storage-file", str(work / "agent-scan-state"), "--server-timeout", "2"]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(home), cwd=work)
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        servers = _json_items(doc, ("servers",))
        skills = _json_items(doc, ("skills",))
        items = len(servers) + len(skills)
        return Outcome(
            "ok",
            detected=items > 0,
            items=items,
            agentic=items > 0,
            seconds=secs,
            note=f"servers={len(servers)} skills={len(skills)}",
            raw={"inspect.json": stdout},
        )

    def run_repo(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        root = self.tree(case, work, "repo")
        empty_home = work / "emptyhome"
        empty_home.mkdir()
        return self._inspect([str(root)], empty_home, work, env)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        return self._inspect([], self.tree(case, work, "home"), work, env)


# ----------------------------------------------------------------------------
# Cisco MCP Scanner


class CiscoMCPScanner(Adapter):
    name = "cisco-mcp-scanner"
    display = "Cisco MCP Scanner"
    source = "cisco-ai-defense/mcp-scanner"
    surfaces = {"endpoint": "--scan-known-configs --analyzers yara with HOME=<case>"}

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("mcpscanner", "mcp-scanner")
        return None if exe.exists() else str(exe)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        home = self.tree(case, work, "home")
        cmd = [str(env.venv_bin("mcpscanner", "mcp-scanner")), "--scan-known-configs", "--analyzers", "yara"]
        cmd += ["--format", "raw", "--stdio-timeout", "2"]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(home), cwd=work)
        start = stdout.find("{") if "{" in stdout else stdout.find("[")
        try:
            doc = json.loads(stdout[start:]) if start >= 0 else None
        except json.JSONDecodeError:
            doc = None
        if doc is None:
            if code == 0 and not stdout.strip():
                return Outcome("ok", seconds=secs, note="no output", raw={"stdout.txt": stdout})
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        entries = doc if isinstance(doc, list) else _json_items(doc, ("results", "servers", "scan_results"))
        if isinstance(doc, dict) and not entries:
            entries = [v for v in doc.values() if isinstance(v, (list, dict)) and v]
        return Outcome(
            "ok",
            detected=bool(entries),
            items=len(entries),
            agentic=bool(entries),
            seconds=secs,
            raw={"stdout.json": stdout},
        )


# ----------------------------------------------------------------------------
# Open Shadow AI (catalog matcher on squid logs)


def squid_lines(case: Case) -> list[str]:
    lines = []
    for f in case.flows:
        epoch = datetime.fromisoformat(f["ts"].replace("Z", "+00:00")).timestamp()
        url = f"{f['scheme']}://{f['host']}:{f['port']}{f['path']}"
        lines.append(
            f"{epoch:.3f} {f['duration_ms']} {f['src_ip']} TCP_MISS/{f['status']} {f['bytes_in']} "
            f"{f['method']} {url} {f['user']} DIRECT/{f['dst_ip']} application/json"
        )
    return lines


class OpenShadowAI(Adapter):
    name = "open-shadow-ai"
    display = "Open Shadow AI"
    source = "alebgl77/open-shadow-ai"
    surfaces = {"network": "squid parser + built-in catalog matcher (in-process, no database)"}

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.venv_bin("openshadowai", "python")
        return None if exe.exists() else str(exe)

    def run_network(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        log = work / "access.log"
        log.write_text("\n".join(squid_lines(case)) + "\n", encoding="utf-8")
        helper = Path(__file__).with_name("helpers") / "open_shadow_ai_match.py"
        catalog = env.checkout("alebgl77_open-shadow-ai") / "catalog"
        cmd = [str(env.venv_bin("openshadowai", "python")), "-I", str(helper), str(catalog), str(log)]
        code, stdout, stderr, secs = _isolated(cmd, env=_base_env(work), cwd=work)
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        matches = [m for m in doc["events"] if m.get("match")]
        return Outcome(
            "ok",
            detected=bool(matches),
            items=len(matches),
            seconds=secs,
            note=",".join(sorted({m["match"] for m in matches}))[:200],
            raw={"matches.json": stdout},
        )


# ----------------------------------------------------------------------------
# AgentSonar (classify-only mode)

AGENTSONAR_THRESHOLD = 0.3  # the cut-off used in the project's own examples


def agentsonar_events(case: Case) -> list[dict[str, Any]]:
    """Each connection becomes the SNI (or DNS) event and the end-of-flow streaming event."""
    events: list[dict[str, Any]] = []
    for f in case.flows:
        first = "tls" if f["scheme"] == "https" else "dns"
        events.append({"proc": f["process"], "pid": f["pid"], "domain": f["host"], "source": first})
        events.append(
            {
                "proc": f["process"],
                "pid": f["pid"],
                "domain": f["host"],
                "source": "streaming",
                "extras": {
                    "duration_ms": str(f["duration_ms"]),
                    "bytes_in": str(f["bytes_in"]),
                    "bytes_out": str(f["bytes_out"]),
                    "packets_in": str(f["packets_in"]),
                    "packets_out": str(f["packets_out"]),
                    "concurrent": "1",
                    "programmatic": "true" if f["programmatic"] else "false",
                },
            }
        )
    return events


class AgentSonar(Adapter):
    name = "agentsonar"
    display = "AgentSonar (Knostic)"
    source = "knostic/AgentSonar"
    surfaces = {"network": f"classify (stdin events); detected when a pair scores > {AGENTSONAR_THRESHOLD}"}

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.root / "bin" / "agentsonar"
        return None if exe.exists() else str(exe)

    def run_network(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        stdin = "".join(json.dumps(e) + "\n" for e in agentsonar_events(case))
        code, stdout, stderr, secs = _isolated(
            [str(env.root / "bin" / "agentsonar"), "classify"], env=_base_env(work), cwd=work, stdin=stdin
        )
        if code != 0:
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr)}")
        best: dict[tuple[str, str], float] = {}
        for line in stdout.splitlines():
            row = json.loads(line)
            if row.get("is_noise"):
                continue
            score = max([float(v) for v in (row.get("scores") or {}).values()] or [0.0])
            if row.get("agent"):
                score = 1.0
            key = (row["proc"], row["domain"])
            best[key] = max(best.get(key, 0.0), score)
        flagged = {k: v for k, v in best.items() if v > AGENTSONAR_THRESHOLD}
        return Outcome(
            "ok",
            detected=bool(flagged),
            items=len(flagged),
            seconds=secs,
            note=";".join(f"{p}->{d}={s:.2f}" for (p, d), s in sorted(flagged.items()))[:200],
            raw={"classify.jsonl": stdout},
        )


# ----------------------------------------------------------------------------
# Shadow AI Detector (mizcausevic-dev)


def traffic_events(case: Case) -> list[dict[str, Any]]:
    return [
        {
            "eventId": f"{case.case_id}-{i}",
            "timestamp": f["ts"],
            "url": f"{f['scheme']}://{f['host']}:{f['port']}{f['path']}",
            "method": f["method"],
            "payloadSnippet": "",
            "user": f"{f['user']}@corp.example",
            "department": f["department"],
            "sourceHost": f["src_ip"],
            "bytesUp": f["bytes_out"],
            "bytesDown": f["bytes_in"],
        }
        for i, f in enumerate(case.flows)
    ]


class ShadowAIDetector(Adapter):
    name = "shadow-ai-detector"
    display = "Shadow AI Detector"
    source = "mizcausevic-dev/shadow-ai-detector"
    surfaces = {"network": "assessFleet() over proxy events, empty sanctioned list"}

    def unavailable(self, env: ToolEnv) -> str | None:
        built = env.checkout("mizcausevic-dev_shadow-ai-detector") / "dist" / "governance" / "risk-scorer.js"
        return None if built.exists() and shutil.which("node") else str(built)

    def run_network(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        events = work / "events.json"
        events.write_text(json.dumps(traffic_events(case)), encoding="utf-8")
        helper = Path(__file__).with_name("helpers") / "shadow_ai_detector_assess.cjs"
        dist = env.checkout("mizcausevic-dev_shadow-ai-detector") / "dist"
        node = shutil.which("node") or "node"
        code, stdout, stderr, secs = _isolated(
            [node, str(helper), str(dist), str(events)],
            env={**_base_env(work), "PATH": f"{Path(node).parent}:/usr/bin:/bin"},
            cwd=work,
        )
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        matched = [a for a in doc if a.get("matched")]
        return Outcome(
            "ok",
            detected=bool(matched),
            items=len(matched),
            seconds=secs,
            note=",".join(sorted({str(a.get("endpointId")) for a in matched}))[:200],
            raw={"assessments.json": stdout},
        )


# ----------------------------------------------------------------------------
# Endpoint scripts: Claw-Hunter and AI-Detector


class ClawHunter(Adapter):
    name = "claw-hunter"
    display = "Claw-Hunter (Backslash)"
    source = "backslash-security/claw-hunter"
    surfaces = {"endpoint": "claw-hunter.sh --json with HOME=<case>"}

    def unavailable(self, env: ToolEnv) -> str | None:
        script = env.checkout("backslash-security_claw-hunter") / "claw-hunter.sh"
        return None if script.exists() else str(script)

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        home = self.tree(case, work, "home")
        script = env.checkout("backslash-security_claw-hunter") / "claw-hunter.sh"
        code, stdout, stderr, secs = _isolated(["bash", str(script), "--json"], env=_base_env(home), cwd=work)
        start = stdout.find("{")
        try:
            doc = json.loads(stdout[start:]) if start >= 0 else None
        except json.JSONDecodeError:
            doc = None
        if not isinstance(doc, dict):
            return Outcome("error", seconds=secs, note=f"exit {code}: {_tail(stderr or stdout)}")
        installed = bool(doc.get("installed") or doc.get("openclaw_installed") or doc.get("detected"))
        return Outcome(
            "ok",
            detected=installed,
            items=int(installed),
            agentic=installed,
            seconds=secs,
            raw={"claw-hunter.json": stdout[start:]},
        )


class AIDetector(Adapter):
    """Runs as an unprivileged user so the script scans ``$HOME`` instead of /home/* and /root."""

    name = "ai-detector"
    display = "AI-Detector (shamo0)"
    source = "shamo0/AI-Detector"
    surfaces = {"endpoint": "detect-shadow-ai.sh, SHADOW_AI_REPORT=json, network module off, HOME=<case>"}
    _baseline: frozenset[str] | None = None

    def unavailable(self, env: ToolEnv) -> str | None:
        script = env.checkout("shamo0_AI-Detector") / "detect-shadow-ai.sh"
        return None if script.exists() else str(script)

    def _findings(
        self, home: Path, work: Path, env: ToolEnv
    ) -> tuple[int, list[dict[str, Any]] | None, str, float]:
        script = env.checkout("shamo0_AI-Detector") / "detect-shadow-ai.sh"
        for p in (work, *work.rglob("*")):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(work.parent, 0o755)
        cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "bash", str(script)]
        environ = {**_base_env(home), "SHADOW_AI_REPORT": "json", "SHADOW_AI_NETWORK": "false"}
        code, stdout, stderr, secs = _isolated(cmd, env=environ, cwd=work)
        start = stdout.find("{")
        try:
            doc = json.loads(stdout[start:]) if start >= 0 else None
        except json.JSONDecodeError:
            doc = None
        if not isinstance(doc, dict):
            return code, None, f"exit {code}: {_tail(stderr or stdout)}", secs
        found = doc.get("findings", [])
        return code, found if isinstance(found, list) else [], stdout[start:], secs

    @staticmethod
    def _key(item: dict[str, Any], home: Path) -> str:
        return f"{item.get('category')}|{str(item.get('detail')).replace(str(home), '~')}"

    def run_endpoint(self, case: Case, work: Path, env: ToolEnv) -> Outcome:
        if self._baseline is None:
            base_work = work.parent / f"{work.name}-baseline"
            (base_work / "home").mkdir(parents=True)
            (base_work / "tmp").mkdir()
            _, found, _, _ = self._findings(base_work / "home", base_work, env)
            self._baseline = frozenset(self._key(f, base_work / "home") for f in (found or []))
        home = self.tree(case, work, "home")
        code, found, text, secs = self._findings(home, work, env)
        if found is None:
            return Outcome("error", seconds=secs, note=text)
        # Host-level findings (installed binaries, containers) also appear with an
        # empty home, so they do not belong to the case.
        own = [f for f in found if self._key(f, home) not in self._baseline]
        cats = {str(f.get("category")) for f in own}
        return Outcome(
            "ok",
            detected=bool(own),
            items=len(own),
            seconds=secs,
            note=",".join(sorted(cats))[:200],
            raw={"report.json": text},
        )


ADAPTERS: tuple[Adapter, ...] = (
    ShadowScan(),
    CiscoAIBOM(),
    AgentBom(),
    AgentDiscover(),
    SnykAgentScan(),
    CiscoMCPScanner(),
    OpenShadowAI(),
    AgentSonar(),
    ShadowAIDetector(),
    ClawHunter(),
    AIDetector(),
)
