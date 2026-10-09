"""Tool adapters for the real-world benchmark: one tool, one snapshot, one fixed rule.

Each adapter runs its tool inside a :class:`~tools.benchmark.realworld.sandbox.Session` (no
network, unprivileged, resource-capped) and decides *detected* by a rule written here before
the scored run. A repository is **detected** when the tool's own report contains at least
one AI-related item for it, as that tool defines AI-related, *for the target of this
benchmark* (LLM, agent, MCP and coding-agent integrations):

* items a tool's own taxonomy files under classical machine learning or MLOps (datasets, training runs,
  hyper-parameters, ML frameworks) or that it says are not an independent signal are not counted by the
  headline rule. Each adapter lists what it leaves out and offers a variant (``variants``) that counts it;
* a crash, a timeout, an unreadable or schema-invalid report is ``error``, and so is a scan the tool itself
  calls incomplete when it reports nothing: never a clean result (the fail-closed rule in AGENTS.md applies
  to the benchmark too). A scan the tool calls incomplete that still reports findings is recorded as
  ``partial``; the scorer counts it as an error in the headline and as a detection in a sensitivity analysis,
  for every tool alike;
* ``agentic`` is the tool's own claim that the finding is an agent, MCP server, coding-agent
  configuration or agent framework (exploratory metric);
* ``variants`` holds alternative rules declared in advance, reported next to the headline.

Allowed calibration changes (decided on the calibration split only): how a tool is invoked
and how its report is read. Changing what counts as a detection after scored results exist
is not allowed.

All tools run offline. Anything that needs a service (an LLM, a vulnerability database, a
cloud API) is measured without it; each docstring says what that costs the tool. Published rows hold
no raw tool output: notes are fixed tokens and exception class names, names are filtered identifiers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.benchmark.realworld.sandbox import RunResult, Sandbox, Session

HERE = Path(__file__).resolve().parent
MAX_NAMES = 40
AGENTIC_SHADOWSCAN_KINDS = frozenset({"agent", "mcp-server", "agent-config", "bot-app", "workflow"})
EXCEPTION_NAME = re.compile(r"(?m)^\s*([A-Za-z_][\w.]{0,40}(?:Error|Exception))\b")
KEY_LIKE = re.compile(
    r"(?i)(sk-[a-z0-9_-]{8,}|sk_(live|test)_[a-z0-9]{8,}|gh[pousr]_[a-z0-9]{16,}|AKIA[0-9A-Z]{12,}|xox[abprs]-"
    r"|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}|[A-Za-z0-9+/]{32,}={0,2})"
)


@dataclass
class Outcome:
    status: str  # ok | error
    detected: bool = False
    agentic: bool | None = None
    items: int = 0
    names: list[str] = field(default_factory=list)
    variants: dict[str, bool] = field(default_factory=dict)
    seconds: float = 0.0
    note: str = ""
    partial: bool = False  # the tool says its scan was incomplete but its report still has AI findings

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status, "detected": self.detected, "agentic": self.agentic, "items": self.items,
            "names": self.names[:MAX_NAMES], "variants": self.variants, "seconds": round(self.seconds, 2),
            "note": self.note[:300], "partial": self.partial,
        }  # fmt: skip


@dataclass(frozen=True)
class ToolEnv:
    root: Path  # tool root created by install_tools.sh
    sandbox: Sandbox

    def venv_bin(self, venv: str, exe: str) -> str:
        return str(self.root / "venvs" / venv / "bin" / exe)


def clean_names(values: list[Any]) -> list[str]:
    """Identifier-like names only: no free text, nothing key-shaped, at most 60 characters each."""
    out: list[str] = []
    for value in values:
        text = " ".join(str(value).split())[:60]
        if text and text not in out and not KEY_LIKE.search(text) and "=" not in text:
            out.append(text)
    return out[:MAX_NAMES]


def parse_json(text: str | None) -> Any:
    if text is None:
        raise ValueError("report missing")
    return json.loads(text)


def find_lists(doc: Any, keys: tuple[str, ...]) -> list[Any]:
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


def fail(res: RunResult, note: str) -> Outcome:
    """An error row: the reason is an exit status plus exception class names, never raw output."""
    if res.timed_out:
        why = "timeout"
    elif res.code in (137, -9):
        why = "killed (memory or signal)"
    else:
        why = f"exit {res.code}"
    kinds = sorted(set(EXCEPTION_NAME.findall(f"{res.stderr}\n{res.stdout}")))[:2]
    return Outcome(
        "error", seconds=res.seconds, note=f"{note}: {why}" + (f" ({', '.join(kinds)})" if kinds else "")
    )


class Adapter:
    name = ""
    display = ""
    source = ""
    scope = ""  # what the tool does on this surface, offline

    def unavailable(self, env: ToolEnv) -> str | None:
        return None

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        raise NotImplementedError


# ----------------------------------------------------------------------------
# ShadowScan (this repository)


class ShadowScan(Adapter):
    """``code.filesystem`` on the snapshot, defaults, no inventory, as ``shadowscan scan`` ships. Detected
    when the scan reports any finding. Exit 3 or an incomplete summary means the tool could not read
    everything (for example a file over the default 1 MB ``max_file_size``): with no finding that is an
    error, with findings it is recorded as ``partial``. The configuration variants below change one
    documented option each; they are sensitivity rows, never the headline."""

    name = "shadowscan"
    display = "Project Nexus ShadowScan"
    source = "aisecnomad/Project-Nexus"
    scope = (
        "code.filesystem on the checkout (signature packs for frameworks, providers, MCP and coding agents)"
    )
    connector_options: dict[str, Any] = {}
    cli_options: tuple[str, ...] = ()

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = Path(env.venv_bin("shadowscan", "python"))
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        cfg = s.out / "shadowscan.yaml"
        connector = {
            "name": "code.filesystem",
            "path": str(s.tree),
            "use_git": False,
            **self.connector_options,
        }
        cfg.write_text(json.dumps({"connectors": [connector]}))
        res = s.run(
            [
                env.venv_bin("shadowscan", "python"),
                "-m",
                "shadowscan",
                "scan",
                "-c",
                str(cfg),
                "-f",
                "json",
                "-o",
                str(s.out / "report.json"),
                *self.cli_options,
            ]  # fmt: skip
        )
        try:
            report = parse_json(s.read(s.out / "report.json"))
            summary = report["summary"]
            findings = report["findings"]
            complete = bool(summary["complete"])
        except (ValueError, KeyError, TypeError):
            return fail(res, "no report")
        if res.code not in (0, 3):
            return fail(res, "scan failed")
        incomplete = res.code == 3 or not complete
        warnings = [
            w for st in report.get("stats", []) if isinstance(st, dict) for w in st.get("warnings", [])
        ]
        if incomplete and not findings:
            return Outcome(
                "error", seconds=res.seconds, note=f"incomplete scan, no findings ({len(warnings)} warnings)"
            )
        kinds = {f.get("kind") for f in findings}
        names = [
            str(k).split(".", 1)[-1]
            for k in [*summary.get("frameworks", {}), *summary.get("model_providers", {})]
        ]
        return Outcome(
            "ok",
            detected=bool(findings),
            agentic=bool(kinds & AGENTIC_SHADOWSCAN_KINDS),
            items=len(findings),
            names=clean_names(names),
            seconds=res.seconds,
            note=",".join(sorted(str(k) for k in kinds if k))
            + (f" | incomplete: {len(warnings)} warnings" if incomplete else ""),
            partial=incomplete,
        )


class ShadowScanBigFiles(ShadowScan):
    """Sensitivity row: ``max_file_size`` raised to 25 MB and the per-connector deadline to 540 s, the
    documented remedy when the default run exits 3 on an oversize file. Everything else as the default."""

    name = "shadowscan-bigfiles"
    display = "ShadowScan, max_file_size 25 MB"
    scope = "as shadowscan, with max_file_size 25 MB and connector deadline 540 s"
    connector_options = {"max_file_size": 25_000_000}
    cli_options = ("--connector-timeout-seconds", "540")


class ShadowScanConfidence(ShadowScan):
    """Sensitivity row: ``--min-confidence 0.3``, the value in the README's example configuration (the
    command-line default is 0)."""

    name = "shadowscan-conf03"
    display = "ShadowScan, min-confidence 0.3"
    scope = "as shadowscan, with --min-confidence 0.3"
    cli_options = ("--min-confidence", "0.3")


# ----------------------------------------------------------------------------
# Cisco AI BOM


class CiscoAIBOM(Adapter):
    """``analyze`` with an unreachable LLM endpoint (the tool insists on one), so its Tier-3
    classifier degrades and the report keeps the deterministic candidates. **Its help calls the LLM
    required for accurate results, so this row measures Cisco AI BOM without it.** Headline rule: any
    component except the classical-ML and MLOps types its own enumeration groups under "ML lifecycle"
    plus datasets and feature stores (``NOISE``), which an AI bill of materials lists by design and which
    are not an LLM or agent integration. Variant ``any_component``: any component at all. Cost of offline
    mode: no LLM review, so candidates stay ``unreviewed``, and a fixed cool-down per retry of the dead
    endpoint that makes large repositories slow."""

    name = "cisco-aibom"
    display = "Cisco AI BOM"
    source = "cisco-ai-defense/aibom"
    scope = "analyze <checkout>; LLM classifier unreachable (deterministic candidates only)"
    NOISE = frozenset({
        "dataset", "feature_store", "training_run", "hyperparameter", "model_artifact",
        "experiment_tracker", "model_registry", "data_versioning", "ml_pipeline",
    })  # fmt: skip
    AGENTIC = frozenset({"agent", "agent_proxy", "mcp_server", "mcp_client", "mcp_gateway", "tool", "skill"})

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = Path(env.venv_bin("aibom", "cisco-aibom"))
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        out = s.out / "aibom.json"
        res = s.run(
            [
                env.venv_bin("aibom", "cisco-aibom"),
                "analyze",
                str(s.tree),
                "--output-format",
                "json",
                "--output-file",
                str(out),
                "--llm-provider",
                "openai",
                "--llm-model",
                "gpt-4o",
                "--llm-api-base",
                "http://127.0.0.1:9/v1",
                "--llm-api-key",
                "unused",
                "--agentic-timeout",
                "5",
                "--agentic-max-retry-seconds",
                "0",
                "--agentic-max-consecutive-failures",
                "1",
                "--no-show-summary",
                "--no-progress",
            ]  # fmt: skip
        )
        try:
            analysis = parse_json(s.read(out))["aibom_analysis"]
            status = analysis["metadata"].get("status")
            summary = analysis["summary"]
        except (ValueError, KeyError, TypeError):
            return fail(res, "no report")
        if status not in {"completed", "completed_with_errors"}:
            return Outcome("error", seconds=res.seconds, note=f"status {str(status)[:30]}")
        partial = status == "completed_with_errors" or bool(analysis["metadata"].get("sources_with_errors"))
        types: dict[str, int] = dict(summary.get("component_types") or {})
        total = int(summary.get("total_components") or 0)
        relevant = sum(n for t, n in types.items() if t not in self.NOISE)
        if partial and not relevant:
            return Outcome("error", seconds=res.seconds, note="source errors and no AI components")
        names = [c.get("name") for c in find_lists(analysis, ("components",)) if isinstance(c, dict)]
        return Outcome(
            "ok", detected=relevant > 0, agentic=bool(set(types) & self.AGENTIC), items=total,
            names=clean_names(names or list(types)), variants={"any_component": total > 0},
            seconds=res.seconds, note=",".join(sorted(types))[:200], partial=partial,
        )  # fmt: skip


# ----------------------------------------------------------------------------
# agent-bom


class AgentBom(Adapter):
    """``scan <checkout> --ai-inventory <checkout> --no-scan --offline``: the documented "source code for AI
    SDK imports, model references, API keys, and shadow AI" scan (it is only switched on automatically
    for Python projects, so it is requested explicitly), inventory only, no CVE lookups. The report
    always lists a pseudo-agent for the scanned project whose "servers" are its package manifests and CI
    workflows; that is dependency inventory, not AI evidence. Headline rule: an ``ai_inventory`` component
    other than classical machine learning (``ml_framework``) or a hidden-character finding, an AST-detected
    tool definition, or an agent that is not the project pseudo-agent and is absent from an empty-tree
    baseline (skill files, MCP configuration, AI workflows, notebooks). Variant ``any_component`` counts
    every inventory component. Exit 1 mixes verdicts (a critical secret finding fails the run) with "scan
    did not complete", so completeness is read from the report instead: ``scan_run.outcome`` of
    ``partial`` (a coverage budget ran out, for example the AST pass stops at 500 source files) is recorded
    as ``partial``, and any other value than ``complete`` or ``partial`` is an error. Cost of offline mode: no
    vulnerability matching, which is not what this benchmark measures."""

    name = "agent-bom"
    display = "agent-bom"
    source = "msaad00/agent-bom"
    scope = "scan <checkout> --ai-inventory --no-scan --offline (inventory only)"
    NOISE = frozenset({"ml_framework", "invisible_unicode"})
    _baseline: frozenset[tuple[str, str, str]] | None = None

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = Path(env.venv_bin("agentbom", "agent-bom"))
        return None if exe.exists() else str(exe)

    @staticmethod
    def _key(agent: dict[str, Any]) -> tuple[str, str, str]:
        return (str(agent.get("name")), str(agent.get("agent_type")), str(agent.get("status")))

    @staticmethod
    def _is_project_pseudo_agent(agent: dict[str, Any]) -> bool:
        source = (agent.get("discovery_provenance") or {}).get("source")
        return (
            source == "project"
            or str(agent.get("name")).startswith("project:")
            or agent.get("name") == "ai-inventory"
        )

    def _scan(self, s: Session, env: ToolEnv) -> tuple[Any, RunResult]:
        """The parsed report (None if absent or unreadable) and the run; a failure keeps its exit status."""
        out = s.out / "agent-bom.json"
        res = s.run(
            [
                env.venv_bin("agentbom", "agent-bom"),
                "scan",
                str(s.tree),
                "--ai-inventory",
                str(s.tree),
                "--no-scan",
                "--offline",
                "-f",
                "json",
                "-o",
                str(out),
            ]  # fmt: skip
        )
        try:
            return parse_json(s.read(out)), res
        except ValueError:
            return None, res

    def baseline(self, env: ToolEnv) -> frozenset[tuple[str, str, str]]:
        if AgentBom._baseline is None:
            with env.sandbox.session(None) as s:
                doc, _ = self._scan(s, env)
            AgentBom._baseline = frozenset(
                self._key(a) for a in (doc or {}).get("agents", []) if not self._is_project_pseudo_agent(a)
            )
        return AgentBom._baseline

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        baseline = self.baseline(env)
        doc, res = self._scan(s, env)
        try:
            agents = doc["agents"]
            inventory = doc.get("ai_inventory") or {}
            outcome = doc["scan_run"]["outcome"]
        except (KeyError, TypeError):
            return fail(res, "no report")
        if res.code not in (0, 1) or outcome not in {"complete", "partial"}:
            return fail(res, f"scan failed (outcome {str(outcome)[:20]})")
        components = [c for c in inventory.get("components", []) if isinstance(c, dict)]
        relevant = [c for c in components if c.get("type") not in self.NOISE]
        tools = (inventory.get("ast_analysis") or {}).get("tools") or []
        clients: list[Any] = []
        servers: list[Any] = []
        for agent in agents:
            if (
                isinstance(agent, dict)
                and not self._is_project_pseudo_agent(agent)
                and self._key(agent) not in baseline
            ):
                clients.append(agent.get("name"))
                servers += [m.get("name") for m in agent.get("mcp_servers", []) if isinstance(m, dict)]
        items = len(relevant) + len(tools) + len(clients) + len(servers)
        anything = bool(components) or bool(tools) or bool(clients)
        return Outcome(
            "ok", detected=items > 0, agentic=bool(clients or servers or tools or any(
                c.get("type") == "agent_framework" for c in relevant)),
            items=items, variants={"any_component": anything},
            names=clean_names([*[c.get("name") for c in relevant], *clients, *servers]),
            seconds=res.seconds, note="scan_run outcome partial" if outcome == "partial" else "",
            partial=outcome == "partial",
        )  # fmt: skip


# ----------------------------------------------------------------------------
# AgentDiscover Scanner


class AgentDiscover(Adapter):
    """``scan`` (Layer-1 code findings, SARIF) and ``audit`` with Layers 2-5 skipped (they need
    live hosts, clusters or cloud accounts): MCP configuration detection and the agent
    inventory. Headline rule: a SARIF result for a framework or provider rule (DAI001-DAI007), an agent in
    the audit inventory, or an MCP entry in the audit report. DAI008 (declared model identifier) and DAI009
    (generation parameters) are, in the tool's own source, "metadata-enrichment" signals that "never" count
    as an independent agent signal, and they fire on any call that has a ``model=`` or ``temperature=``
    argument; the variant ``any_rule`` counts them. ``scan`` writes no SARIF for a tree with no Python or
    JavaScript file and says so; that is a clean result, not an error. Cost of offline mode: Layers 2-5
    (network, Kubernetes, endpoint, cloud audit) are out of scope on a repository snapshot."""

    name = "agentdiscover"
    display = "AgentDiscover Scanner"
    source = "Defend-AI-Tech-Inc/agent-discover-scanner"
    scope = "scan --format sarif + audit --skip-layers 2,3,4,5"
    NO_FILES = "No Python or JavaScript files found"
    INDEPENDENT = frozenset(f"DAI00{n}" for n in range(1, 8))

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = Path(env.venv_bin("agentdiscover", "agentdiscover"))
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        exe = env.venv_bin("agentdiscover", "agentdiscover")
        sarif = s.out / "results.sarif"
        scan = s.run([exe, "scan", str(s.tree), "--format", "sarif", "--output", str(sarif)])
        results: list[Any] = []
        text = s.read(sarif)
        if text is not None:
            try:
                doc = json.loads(text)
                if not isinstance(doc, dict) or "runs" not in doc:
                    return fail(scan, "unexpected SARIF")
                results = find_lists(doc, ("results",))
            except ValueError:
                return fail(scan, "unreadable SARIF")
        elif not (scan.code == 0 and self.NO_FILES in scan.stdout):
            return fail(scan, "scan failed")
        audit_cmd = [exe, "audit", str(s.tree), "--output", str(s.out / "audit")]
        audit = s.run([*audit_cmd, "--skip-layers", "2,3,4,5", "--duration", "1"])
        inventory = s.read(s.out / "audit" / "raw" / "agent_inventory.json")
        mcp_report = s.read(s.out / "audit" / "mcp-report.md")
        if audit.code != 0 or inventory is None or mcp_report is None:
            return fail(audit, "audit failed")
        try:
            agents = int(json.loads(inventory)["summary"].get("total_agents") or 0)
        except (ValueError, KeyError, TypeError, AttributeError):
            return fail(audit, "unreadable inventory")
        mcp = [line[3:].strip() for line in mcp_report.splitlines() if line.startswith("## ")]
        rule_ids = [str(r.get("ruleId")) for r in results if isinstance(r, dict)]
        independent = [r for r in rule_ids if r in self.INDEPENDENT]
        scan_hit = bool(independent)
        audit_hit = bool(agents or mcp)
        return Outcome(
            "ok",
            detected=scan_hit or audit_hit,
            agentic=audit_hit or scan_hit,
            items=len(independent) + agents + len(mcp),
            names=clean_names([*sorted(set(rule_ids)), *mcp]),
            variants={
                "any_rule": bool(results) or audit_hit,
                "scan_only": scan_hit,
                "audit_only": audit_hit,
            },
            seconds=scan.seconds + audit.seconds,
        )


# ----------------------------------------------------------------------------
# Trusera ai-bom


class TruseraAIBOM(Adapter):
    """``scan`` with defaults (no ``--deep``), JSON (CycloneDX) output, telemetry off. Every
    component the tool lists is AI-related by construction (frameworks, models, services,
    keys); detected when there is at least one. Agentic: a framework used for orchestration or
    an MCP service. A non-zero exit or a report that is not a CycloneDX document is an error. Cost of
    offline mode: none known (the scan is local)."""

    name = "trusera-ai-bom"
    display = "Trusera ai-bom"
    source = "Trusera/ai-bom"
    scope = "scan <checkout> -f json (default depth)"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = Path(env.venv_bin("trusera", "ai-bom"))
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        out = s.out / "ai-bom.json"
        cmd = [env.venv_bin("trusera", "ai-bom"), "scan", str(s.tree), "-f", "json", "-o", str(out)]
        res = s.run([*cmd, "-q", "--no-telemetry"])
        try:
            doc = parse_json(s.read(out))
            if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
                raise ValueError("not a CycloneDX document")
            raw = doc["components"]
            if not isinstance(raw, list):
                raise ValueError("components is not a list")
        except (ValueError, KeyError):
            return fail(res, "no report")
        if res.code != 0:
            return fail(res, "scan failed")
        comps = [c for c in raw if isinstance(c, dict)]
        agentic = False
        names: list[Any] = []
        for c in comps:
            props = {
                p.get("name"): str(p.get("value")) for p in c.get("properties", []) if isinstance(p, dict)
            }
            provider = props.get("trusera:provider", "")
            names.append(provider or c.get("name"))
            if (
                c.get("type") == "framework"
                or "mcp" in provider.lower()
                or "mcp" in str(c.get("name")).lower()
            ):
                agentic = True
        return Outcome(
            "ok",
            detected=bool(comps),
            agentic=agentic,
            items=len(comps),
            names=clean_names(names),
            seconds=res.seconds,
        )


# ----------------------------------------------------------------------------
# Microsoft Agent Governance Toolkit: agent-discovery


class AgtDiscovery(Adapter):
    """``scan --scanner config --paths <snapshot>``: the config scanner, which matches well-known
    agent configuration file names (``mcp.json``, ``agentmesh.yaml``, ``crewai.yaml``, agent
    Dockerfiles). The ``process`` scanner looks at the benchmark host, and the ``github`` scanner
    needs the network, so neither applies to a snapshot. Detected when it discovers at least one
    agent. By design it does not read source code, so it is expected to miss code-only repositories. A
    non-zero exit or an inventory that is not a list is an error."""

    name = "agt-discovery"
    display = "Microsoft AGT agent-discovery"
    source = "microsoft/agent-governance-toolkit"
    scope = "scan -s config (file-name based); process and github scanners not applicable offline"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = Path(env.venv_bin("agt", "agent-discovery"))
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        store = s.out / "inventory.json"
        cmd = [env.venv_bin("agt", "agent-discovery"), "scan", "-s", "config", "-p", str(s.tree)]
        res = s.run([*cmd, "-o", "json", "--storage", str(store)])
        try:
            agents = parse_json(s.read(store))
        except ValueError:
            return fail(res, "no inventory")
        if not isinstance(agents, list) or res.code != 0:
            return fail(res, "unexpected inventory" if res.code == 0 else "scan failed")
        names = [a.get("agent_type") for a in agents if isinstance(a, dict)]
        return Outcome(
            "ok", detected=bool(agents), agentic=bool(agents), items=len(agents), names=clean_names(names),
            seconds=res.seconds,
        )  # fmt: skip


# ----------------------------------------------------------------------------
# SafeDep vet


READ_VET_MATCHES = (
    "import json,sqlite3,sys\n"
    "con=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)\n"
    "rows=con.execute('select distinct signature_id,tags from code_signature_matches').fetchall()\n"
    "print(json.dumps([[r[0],(r[1].decode() if isinstance(r[1],bytes) else r[1]) or '[]'] for r in rows]))\n"
)


class SafeDepVet(Adapter):
    """Two commands, both local: ``ai discover --scope project -D <snapshot>`` (project-level AI
    tool configuration such as ``.mcp.json`` and ``CLAUDE.md``; its system scope reads the host and
    is not used) and ``code scan --app <snapshot>`` (embedded signatures for AI SDKs in Python,
    JavaScript/TypeScript, Go and Java). Detected when discovery lists any item, or the code scan has a
    match for a signature tagged ``ai``, ``llm``, ``agent``, ``mcp`` or ``crewai`` (the 54 CrewAI signatures
    carry ``crewai`` and ``agent`` but not ``ai``; the signature set also holds cryptography, filesystem and
    cloud-messaging signatures, which are not counted). The scan database is read by an unprivileged
    process inside the sandbox. Variants: ``discover_only`` and ``code_only``. Cost of offline mode:
    SafeDep Cloud features (malware analysis, sync) are unavailable."""

    name = "safedep-vet"
    display = "SafeDep vet"
    source = "safedep/vet"
    scope = "ai discover --scope project + code scan (xBOM signatures tagged ai/llm/agent/mcp/crewai)"
    AI_TAGS = frozenset({"ai", "llm", "agent", "mcp", "crewai"})

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.root / "bin" / "vet"
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        vet = str(env.root / "bin" / "vet")
        disc = s.run([vet, "ai", "discover", "--scope", "project", "-D", str(s.tree), "--report-json",
                      str(s.out / "discover.json"), "-s", "--no-banner"])  # fmt: skip
        try:
            items = parse_json(s.read(s.out / "discover.json")) or []
            if not isinstance(items, list):
                raise ValueError("unexpected discovery report")
        except ValueError:
            return fail(disc, "no discovery report")
        db = s.out / "code.db"
        code = s.run([vet, "code", "scan", "--app", str(s.tree), "--db", str(db), "--no-tui", "--no-banner"])
        if code.code != 0 or s.contained(db) is None:
            return fail(code, "code scan failed")
        read = s.run(["python3", "-I", "-c", READ_VET_MATCHES, str(db)], timeout=120)
        try:
            rows = json.loads(read.stdout.strip().splitlines()[-1])
            matches = [
                (str(sig_id), tags)
                for sig_id, raw in rows
                if self.AI_TAGS & set(tags := [str(t) for t in json.loads(raw)])
            ]
        except (ValueError, IndexError, TypeError):
            return Outcome("error", seconds=disc.seconds + code.seconds, note="unreadable code database")
        names = [i.get("Name") for i in items if isinstance(i, dict)] + [m[0] for m in matches]
        agentic = bool(items) or any({"agent", "mcp"} & set(m[1]) for m in matches)
        return Outcome(
            "ok", detected=bool(items or matches), agentic=agentic, items=len(items) + len(matches),
            names=clean_names(names), variants={"discover_only": bool(items), "code_only": bool(matches)},
            seconds=disc.seconds + code.seconds,
        )  # fmt: skip


# ----------------------------------------------------------------------------
# cdxgen AI-BOM


class CdxgenAIBOM(Adapter):
    """``aibom`` (cdxgen's AI-BOM entry point) with dependency installation disabled. Headline rule: the BOM
    has at least one component or service carrying a ``cdx:ai:*`` property that was derived from content
    (kinds ``model``, ``inference-service`` and any other non-file kind). cdxgen also tags every shell script
    and notebook, and every Markdown/text/JSON/YAML file whose name contains ``prompt``, ``agent``,
    ``model``, ``system`` and similar words, as a ``prompt-config-file`` or ``notebook-file``
    purely by file-name pattern (``cdx:file:kind``); the variant ``with_file_heuristics`` counts those. cdxgen
    warns that it runs ``python`` in the project directory, which is one reason for the sandbox. A non-zero
    exit or a document that is not CycloneDX is an error. Cost of offline mode: none known for AI detection
    (it reads source and configuration)."""

    name = "cdxgen-aibom"
    display = "cdxgen AI-BOM (OWASP)"
    source = "cdxgen/cdxgen"
    scope = "aibom --no-install-deps (models, inference services, prompts, MCP configuration)"
    FILE_KINDS = frozenset({"prompt-config-file", "notebook-file"})

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = env.root / "cdxgen" / "node_modules" / ".bin" / "aibom"
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        exe = str(env.root / "cdxgen" / "node_modules" / ".bin" / "aibom")
        out = s.out / "bom.json"
        res = s.run(["node", exe, "-o", str(out), "--no-install-deps", "--no-validate", str(s.tree)])
        try:
            doc = parse_json(s.read(out))
            if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
                raise ValueError("not a CycloneDX document")
        except ValueError:
            return fail(res, "no BOM")
        if res.code != 0:
            return fail(res, "aibom failed")
        content: list[dict[str, Any]] = []
        files: list[dict[str, Any]] = []
        kinds: set[str] = set()
        for item in [*(doc.get("components") or []), *(doc.get("services") or [])]:
            if not isinstance(item, dict):
                continue
            props = {
                p.get("name"): str(p.get("value")) for p in item.get("properties", []) if isinstance(p, dict)
            }
            if not any(str(k).startswith("cdx:ai:") for k in props):
                continue
            kind = props.get("cdx:ai:kind", "")
            kinds.add(kind)
            (files if kind in self.FILE_KINDS else content).append(item)
        agentic = any(("agent" in k or "mcp" in k or "tool" in k) for k in kinds)
        return Outcome(
            "ok",
            detected=bool(content),
            agentic=agentic,
            items=len(content),
            names=clean_names([i.get("name") for i in content or files]),
            variants={"with_file_heuristics": bool(content or files)},
            seconds=res.seconds,
            note=",".join(sorted(kinds))[:200],
        )


# ----------------------------------------------------------------------------
# Agentic Radar (SPLX / Zscaler)


class AgenticRadar(Adapter):
    """``scan <framework> --export-graph-json`` for each of the five supported frameworks (LangGraph,
    CrewAI, n8n, OpenAI Agents, AutoGen), because the tool has to be told which framework to expect.
    Exit 0 with a non-empty graph is a detection; exit 1 with "didn't find any agentic workflow" is
    clean for that framework; any other failure (a Python traceback, a timeout) is a crash for that
    framework. The repository is ``error`` when nothing was detected and some framework scanner
    crashed (a crash must not look like an empty scan). This is an exploratory tool for this surface:
    it analyses workflows of a known framework and does not discover unknown agents."""

    name = "agentic-radar"
    display = "Agentic Radar (SPLX)"
    source = "splx-ai/agentic-radar"
    scope = "scan <framework> for langgraph, crewai, n8n, openai-agents, autogen (static analysis)"
    FRAMEWORKS = ("langgraph", "crewai", "n8n", "openai-agents", "autogen")
    NOT_FOUND = "didn't find any agentic workflow"

    def unavailable(self, env: ToolEnv) -> str | None:
        exe = Path(env.venv_bin("radar", "agentic-radar"))
        return None if exe.exists() else str(exe)

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        exe = env.venv_bin("radar", "agentic-radar")
        found: list[str] = []
        crashed: list[str] = []
        seconds = 0.0
        for fw in self.FRAMEWORKS:
            out = s.out / f"{fw}.json"
            res = s.run(
                [exe, "scan", fw, "-i", str(s.tree), "-o", str(out), "--export-graph-json"], timeout=120
            )
            seconds += res.seconds
            if res.code == 0:
                try:
                    graph = parse_json(s.read(out))
                except ValueError:
                    crashed.append(fw)
                    continue
                if graph.get("nodes"):
                    found.append(fw)
            elif not (res.code == 1 and self.NOT_FOUND in res.stdout):
                crashed.append(fw)
        if not found and crashed:
            return Outcome("error", seconds=seconds, note=f"scanner crashed for {','.join(crashed)}")
        return Outcome(
            "ok", detected=bool(found), agentic=bool(found), items=len(found), names=clean_names(found),
            seconds=seconds, note=("crashed: " + ",".join(crashed)) if crashed else "",
        )  # fmt: skip


# ----------------------------------------------------------------------------
# Keyword baselines


class Grep(Adapter):
    """A fixed regular expression over file contents (``baseline_grep.py``). ``any`` searches every
    text file, prose included; ``code`` skips prose and lock files. Detected on any hit. This is the
    floor against which the real tools are read."""

    mode = "any"

    def run(self, s: Session, env: ToolEnv) -> Outcome:
        script = (
            s.out / "baseline_grep.py"
        )  # the sandbox does not see this repository, so the script is copied in
        script.write_text((HERE / "baseline_grep.py").read_text(encoding="utf-8"), encoding="utf-8")
        res = s.run(["python3", "-I", str(script), str(s.tree), self.mode])
        try:
            doc = json.loads(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return fail(res, "no output")
        return Outcome("ok", detected=doc["hits"] > 0, items=int(doc["hits"]), seconds=res.seconds)


class GrepAny(Grep):
    name = "grep-any"
    display = "keyword grep (all text files)"
    source = "baseline"
    scope = "case-insensitive vendor and framework names in any text file"
    mode = "any"


class GrepCode(Grep):
    name = "grep-code"
    display = "keyword grep (code and config only)"
    source = "baseline"
    scope = "same pattern, prose and lock files excluded"
    mode = "code"


ADAPTERS: tuple[Adapter, ...] = (
    ShadowScan(), CiscoAIBOM(), TruseraAIBOM(), AgentBom(), AgentDiscover(), AgtDiscovery(), SafeDepVet(),
    CdxgenAIBOM(), AgenticRadar(), GrepAny(), GrepCode(), ShadowScanBigFiles(), ShadowScanConfidence(),
)  # fmt: skip
