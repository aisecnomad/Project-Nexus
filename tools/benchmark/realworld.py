"""Real-world repository benchmark: pinned public checkouts labeled by hand.

The synthetic head-to-head (``run.py``) scores tools on generated cases. This
module runs the same adapters on real GitHub and GitLab repositories, each
pinned to a commit and labeled with evidence paths in ``realworld_corpus.json``.

    python -m tools.benchmark.realworld fetch  --corpus C --checkouts DIR
    python -m tools.benchmark.realworld run    --corpus C --checkouts DIR --tool-root ROOT --results OUT
    python -m tools.benchmark.realworld report --corpus C --results OUT --output REPORT.md

``fetch`` clones each repository at its pinned commit (shallow, no Git LFS
objects, no credentials) into its own directory and refuses a checkout whose
HEAD is not the pin. ``run`` copies a checkout per tool run and executes every
tool inside fresh network and PID namespaces; nothing from a checkout is ever
executed by the harness itself. ``report`` scores the results with the same
statistics as the synthetic benchmark and adds the evidence-coverage and
per-repository tables.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.benchmark import adapters
from tools.benchmark.adapters import Adapter, AgentBom, AgentDiscover, CiscoAIBOM, ShadowScan, ToolEnv
from tools.benchmark.adapters_repo import REPO_ADAPTERS, adapter_evidence_types
from tools.benchmark.common import DIFFICULTIES, LABELS, Case
from tools.benchmark.run import run_tool
from tools.benchmark.score import confusion, score, wilson

DEFAULT_CORPUS = Path(__file__).with_name("realworld_corpus.json")
EVIDENCE_TYPES = (
    "framework",  # agent framework or agent SDK used in code or declared as a dependency
    "provider",  # LLM provider SDK, API endpoint or model id used in code
    "mcp-code",  # MCP server or client implementation
    "mcp-config",  # MCP client configuration file naming servers
    "coding-agent-config",  # CLAUDE.md, .cursorrules, AGENTS.md, Copilot instructions and similar
    "agent-skill",  # SKILL.md skill packages
    "a2a-card",  # A2A agent cards
    "lowcode-flow",  # exported n8n, Flowise, Langflow or Dify flows with AI steps
    "iac",  # infrastructure as code provisioning AI agents or model endpoints
    "credential",  # provider credential pattern in tracked files (counted, never copied)
    "local-model",  # local model runtime files such as Modelfiles or weights
)
STRATA = (
    "app",  # an application or sample that uses agents
    "framework-source",  # the source of an agent framework, SDK or MCP server
    "config-only",  # agent evidence that is configuration, skills or exported flows, not code
    "llm-only",  # LLM SDK or API use without agent evidence
    "name-collision",  # a product or term that collides with an AI name but is not AI
    "ml-not-agent",  # classical or deep learning without an LLM integration
    "docs-only",  # AI mentioned only in prose, lists or crawler data
    "plain",  # ordinary software with no AI relation
)
HOSTS = {"github": "https://github.com/{repo}.git", "gitlab": "https://gitlab.com/{repo}.git"}
_ID = re.compile(r"rw-[a-z0-9][a-z0-9-]{1,60}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\Z")
_FAMILY = re.compile(r"[a-z0-9][a-z0-9-]{1,60}\Z")
CLONE_TIMEOUT_S = 900


class CorpusError(ValueError):
    """The real-world corpus file is malformed."""


@dataclass
class RepoCase(Case):
    """A ``Case`` backed by a pinned public repository instead of generated files."""

    source: dict[str, str] = field(default_factory=dict)  # host, repo, sha, license
    stratum: str = ""
    languages: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)  # {"type", "family", "paths"}
    checkout: str = ""  # runtime only: the verified local checkout

    @property
    def evidence_types(self) -> set[str]:
        return {str(e["type"]) for e in self.evidence}

    def to_json(self) -> dict[str, Any]:
        out = super().to_json()
        out.update(
            {
                "source": self.source,
                "stratum": self.stratum,
                "languages": self.languages,
                "evidence": self.evidence,
            }
        )
        return out

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RepoCase:
        return cls(
            case_id=data["id"],
            surface=data["surface"],
            family=data["family"],
            label=data["label"],
            difficulty=data["difficulty"],
            rationale=data["rationale"],
            source=dict(data.get("source", {})),
            stratum=str(data.get("stratum", "")),
            languages=list(data.get("languages", [])),
            evidence=list(data.get("evidence", [])),
        )


def validate_corpus(doc: dict[str, Any]) -> list[RepoCase]:
    """Check the corpus document and return its cases; raise ``CorpusError`` otherwise."""
    if (
        not isinstance(doc, dict)
        or not isinstance(doc.get("metadata"), dict)
        or not isinstance(doc.get("cases"), list)
    ):
        raise CorpusError("corpus must have 'metadata' and 'cases'")
    if doc["metadata"].get("type") != "real-world-pinned":
        raise CorpusError("metadata.type must be 'real-world-pinned'")
    cases: list[RepoCase] = []
    seen_ids: set[str] = set()
    seen_repos: set[str] = set()
    for raw in doc["cases"]:
        try:
            case = RepoCase.from_json(raw)
        except (KeyError, TypeError) as exc:
            raise CorpusError(f"case {raw.get('id') if isinstance(raw, dict) else raw!r}: {exc}") from exc
        where = f"case {case.case_id}"
        if not _ID.match(case.case_id):
            raise CorpusError(f"{where}: bad id")
        if case.case_id in seen_ids:
            raise CorpusError(f"{where}: duplicate id")
        seen_ids.add(case.case_id)
        if case.surface != "repo":
            raise CorpusError(f"{where}: surface must be 'repo'")
        if case.label not in LABELS or case.difficulty not in DIFFICULTIES:
            raise CorpusError(f"{where}: bad label or difficulty")
        if case.stratum not in STRATA:
            raise CorpusError(f"{where}: unknown stratum {case.stratum!r}")
        if not _FAMILY.match(case.family):
            raise CorpusError(f"{where}: bad family")
        if not case.rationale.strip():
            raise CorpusError(f"{where}: rationale required")
        src = case.source
        if src.get("host") not in HOSTS or not _REPO.match(str(src.get("repo", ""))):
            raise CorpusError(f"{where}: source.host must be github or gitlab with owner/name repo")
        if not _SHA.match(str(src.get("sha", ""))):
            raise CorpusError(f"{where}: source.sha must be a 40-character lowercase commit hash")
        key = f"{src['host']}:{src['repo']}"
        if key in seen_repos:
            raise CorpusError(f"{where}: repository listed twice")
        seen_repos.add(key)
        if not case.languages or not all(isinstance(lang, str) and lang for lang in case.languages):
            raise CorpusError(f"{where}: languages required")
        for ev in case.evidence:
            if not isinstance(ev, dict) or ev.get("type") not in EVIDENCE_TYPES:
                raise CorpusError(f"{where}: evidence type must be one of {EVIDENCE_TYPES}")
            paths = ev.get("paths")
            if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
                raise CorpusError(f"{where}: evidence needs at least one path")
            if any(p.startswith("/") or ".." in p.split("/") for p in paths):
                raise CorpusError(f"{where}: evidence paths must be relative to the checkout")
        types = case.evidence_types
        agentic = types - {"provider", "credential", "local-model"}
        if case.label == "agent" and not agentic:
            raise CorpusError(f"{where}: an agent case needs agent evidence")
        if case.label == "llm" and (agentic or not types):
            raise CorpusError(f"{where}: an llm case needs provider evidence and no agent evidence")
        if case.label == "none" and types - {"credential"}:
            raise CorpusError(f"{where}: a none case cannot carry AI evidence")
        cases.append(case)
    if not cases:
        raise CorpusError("corpus has no cases")
    return cases


def load_corpus(path: Path) -> tuple[dict[str, Any], list[RepoCase]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc["metadata"], validate_corpus(doc)


def corpus_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ----------------------------------------------------------------------------
# fetch


def _git(args: list[str], cwd: Path, timeout: int = CLONE_TIMEOUT_S) -> subprocess.CompletedProcess[str]:
    env = {
        **{
            k: v
            for k, v in os.environ.items()
            if k
            in ("PATH", "HOME", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "GIT_SSL_CAINFO")
        },
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C.UTF-8",
    }
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )


def head_sha(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    proc = _git(["rev-parse", "HEAD"], path, timeout=60)
    return proc.stdout.strip() if proc.returncode == 0 else None


def fetch_case(case: RepoCase, checkouts: Path) -> dict[str, Any]:
    """Materialize ``case`` at its pinned commit below ``checkouts/<id>``; return a manifest row."""
    target = checkouts / case.case_id
    sha = case.source["sha"]
    url = HOSTS[case.source["host"]].format(repo=case.source["repo"])
    if head_sha(target) != sha:
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        steps = (
            ["init", "-q"],
            ["remote", "add", "origin", url],
            ["fetch", "-q", "--depth", "1", "origin", sha],
            ["-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"],
        )
        for step in steps:
            proc = _git(step, target)
            if proc.returncode != 0:
                raise RuntimeError(f"{case.case_id}: git {step[0]} failed: {proc.stderr.strip()[-300:]}")
        if head_sha(target) != sha:
            raise RuntimeError(f"{case.case_id}: checkout is not at {sha}")
    listing = _git(["ls-files", "-z"], target, timeout=120).stdout
    files = [f for f in listing.split("\0") if f]
    size = 0
    for rel in files:
        try:
            size += os.lstat(target / rel).st_size
        except OSError:
            pass
    return {"id": case.case_id, "repo": case.source["repo"], "sha": sha, "files": len(files), "bytes": size}


def fetch(corpus: Path, checkouts: Path) -> list[dict[str, Any]]:
    _, cases = load_corpus(corpus)
    checkouts.mkdir(parents=True, exist_ok=True)
    manifest = []
    for case in cases:
        row = fetch_case(case, checkouts)
        manifest.append(row)
        print(json.dumps(row), flush=True)
    (checkouts / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest


# ----------------------------------------------------------------------------
# run


def repo_adapters() -> tuple[Adapter, ...]:
    """Adapters that take a repository checkout, in report order."""
    return (ShadowScan(), CiscoAIBOM(), AgentBom(), AgentDiscover(), *REPO_ADAPTERS)


def attach_checkouts(cases: list[RepoCase], checkouts: Path) -> None:
    for case in cases:
        target = checkouts / case.case_id
        actual = head_sha(target)
        if actual != case.source["sha"]:
            raise RuntimeError(
                f"{case.case_id}: checkout {target} is at {actual}, pinned {case.source['sha']}"
            )
        case.checkout = str(target.resolve())


def run(
    corpus: Path,
    checkouts: Path,
    tool_root: Path,
    results: Path,
    tools: set[str] | None,
    workers: int,
    timeout: int,
    only: set[str] | None = None,
) -> int:
    metadata, cases = load_corpus(corpus)
    if only:
        cases = [c for c in cases if c.case_id in only]
    attach_checkouts(cases, checkouts)
    chosen = [a for a in repo_adapters() if tools is None or a.name in tools]
    if tools and tools - {a.name for a in chosen}:
        raise SystemExit(f"unknown tools: {sorted(tools - {a.name for a in chosen})}")
    adapters.TIMEOUT_S = timeout
    results.mkdir(parents=True, exist_ok=True)
    env = ToolEnv(root=tool_root.resolve(), python=sys.executable)
    scratch = Path(tempfile.mkdtemp(prefix="realworld-work-")).resolve()
    runs = []
    try:
        for adapter in chosen:
            summary = run_tool(adapter, list(cases), env, results, workers, scratch)
            summary["evidence_types"] = list(adapter_evidence_types(adapter))
            runs.append(summary)
            print(json.dumps(summary), flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    manifest_path = results / "run-manifest.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"runs": []}
    kept = [r for r in previous.get("runs", []) if r["tool"] not in {s["tool"] for s in runs}]
    checkout_manifest = checkouts / "manifest.json"
    manifest = {
        "corpus": corpus.name,
        "corpus_sha256": corpus_sha256(corpus),
        "corpus_metadata": metadata,
        "cases_run": len(cases),
        "checkouts": json.loads(checkout_manifest.read_text()) if checkout_manifest.exists() else [],
        "timeout_seconds": timeout,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "runs": kept + runs,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


# ----------------------------------------------------------------------------
# scoring additions


def _rows(results: Path, tool: str) -> list[dict[str, Any]]:
    path = results / f"{tool}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def evidence_coverage(
    results: Path, cases: list[RepoCase], tools: list[tuple[str, tuple[str, ...]]]
) -> dict[str, Any]:
    """Per evidence type and tool: recall on cases labeled with it, and spurious reports on the rest.

    A tool is only scored on evidence types its adapter declares it can map.
    """
    by_id = {c.case_id: c for c in cases}
    out: dict[str, Any] = {}
    for tool, declared in tools:
        rows = {r["case"]: r for r in _rows(results, tool) if r["case"] in by_id}
        if not rows:
            continue
        entry: dict[str, Any] = {}
        for etype in EVIDENCE_TYPES:
            if etype not in declared:
                continue
            labeled = [cid for cid, c in by_id.items() if etype in c.evidence_types and cid in rows]
            unlabeled = [cid for cid, c in by_id.items() if etype not in c.evidence_types and cid in rows]
            hit = sum(
                1
                for cid in labeled
                if rows[cid]["status"] == "ok" and (rows[cid].get("evidence") or {}).get(etype, 0) > 0
            )
            spurious = sum(
                1
                for cid in unlabeled
                if rows[cid]["status"] == "ok" and (rows[cid].get("evidence") or {}).get(etype, 0) > 0
            )
            entry[etype] = {
                "labeled": len(labeled),
                "found": hit,
                "recall": wilson(hit, len(labeled)),
                "unlabeled": len(unlabeled),
                "reported_on_unlabeled": spurious,
            }
        out[tool] = entry
    return out


def shadowscan_lenient(results: Path) -> dict[str, Any] | None:
    """Post hoc: ShadowScan under two alternative readings of its reports.

    ``lenient`` counts an incomplete scan (exit 3) that still wrote findings as a
    detection. ``lenient_no_secret_only`` additionally ignores reports whose only
    findings are ``secret`` (provider-key-shaped strings), which an agent
    inventory may not want to count. The incompleteness reasons are tallied from
    the connector stats. None of this was pre-registered.
    """
    rows = _rows(results, "shadowscan")
    if not rows:
        return None
    raw_path = results / "raw" / "shadowscan.jsonl.gz"
    found: dict[str, bool] = {}
    non_secret: dict[str, bool] = {}
    reasons: Counter[str] = Counter()
    if raw_path.exists():
        import gzip

        with gzip.open(raw_path, "rt", encoding="utf-8") as fh:
            for line in fh:
                item = json.loads(line)
                report = json.loads(item["raw"].get("report.json", "{}"))
                findings = report.get("findings") or []
                found[item["case"]] = bool(findings)
                non_secret[item["case"]] = any(f.get("kind") != "secret" for f in findings)
                if not report.get("summary", {}).get("complete", True):
                    seen: set[str] = set()
                    for stat in report.get("stats") or []:
                        for msg in list(stat.get("errors") or []) + list(stat.get("warnings") or []):
                            seen.add(_incomplete_reason(str(msg)))
                    seen.discard("")
                    reasons.update(seen)
    lenient = []
    strict = []
    for r in rows:
        incomplete = r["status"] == "error" and "incomplete" in r.get("note", "")
        hit = found.get(r["case"], False) if incomplete else (r["status"] == "ok" and r["detected"])
        lenient.append({**r, "status": "ok", "detected": hit} if incomplete else r)
        strict.append({**r, "status": "ok", "detected": hit and non_secret.get(r["case"], False)})
    return {
        "pre_registered": confusion(rows),
        "lenient": confusion(lenient),
        "lenient_no_secret_only": confusion(strict),
        "incomplete": sum(1 for r in rows if r["status"] == "error" and "incomplete" in r.get("note", "")),
        "reasons": dict(reasons.most_common()),
    }


def _incomplete_reason(msg: str) -> str:
    """Bucket a ShadowScan connector error or warning into a short reason, or '' when it is informational."""
    if "incomplete source lexical analysis" in msg:
        return "source lexical analysis incomplete"
    if "symbolic link" in msg:
        return "symbolic link with unavailable target"
    if "exceeds max_file_size" in msg:
        return "text file over max_file_size"
    if "import-bound" in msg:
        return "import-bound analysis incomplete"
    if "structured parsing" in msg or "structured config" in msg:
        return "structured configuration parsing"
    if "MCP servers must be" in msg:
        return "malformed MCP configuration"
    if "submodule" in msg:
        return "missing submodule checkout"
    if "binary or undecodable" in msg:
        return "binary content in an analyzable path"
    if "A2A" in msg:
        return "unreadable A2A agent card"
    if "default-excluded" in msg or "over max_file_size" in msg or "invalid structured configuration" in msg:
        return ""
    return "other"


def stratum_rates(
    results: Path, cases: list[RepoCase], tools: list[str]
) -> dict[str, dict[str, tuple[int, int]]]:
    by_id = {c.case_id: c for c in cases}
    out: dict[str, dict[str, tuple[int, int]]] = {}
    for tool in tools:
        acc: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r in _rows(results, tool):
            case = by_id.get(r["case"])
            if case is None or r["status"] == "n/a":
                continue
            acc[case.stratum][0] += r["status"] == "ok" and r["detected"]
            acc[case.stratum][1] += 1
        out[tool] = {k: (v[0], v[1]) for k, v in acc.items()}
    return out


# ----------------------------------------------------------------------------
# report


def _ci(triple: Any) -> str:
    if not triple or triple[0] is None:
        return "–"
    p, lo, hi = triple
    return f"{p:.2f} ({lo:.2f}–{hi:.2f})"


def render(corpus: Path, results: Path) -> str:
    metadata, cases = load_corpus(corpus)
    by_id = {c.case_id: c for c in cases}
    all_adapters = {a.name: a for a in repo_adapters()}
    s = score(results, "shadowscan")
    tools = [name for name in all_adapters if name in s["tools"]]
    display = {name: all_adapters[name].display for name in tools}
    m = s["manifest"]
    out: list[str] = []
    w = out.append
    w("# Shadow-AI discovery on real repositories: results\n")
    w(
        f"Corpus: {len(cases)} public repositories pinned to commits "
        f"(corpus SHA-256 `{m['corpus_sha256']}`). "
        f"Python {m['python']} on {m['platform']}. Per-tool timeout {m.get('timeout_seconds', '?')} s.\n"
    )
    w(
        "**Labels were written by the author of this harness, with evidence paths, and were not "
        "independently reviewed.** The corpus is a stratified selection, not a random sample of "
        "repositories, so these rates do not estimate field precision or recall. Intervals are 95% "
        "Wilson (proportions) or bootstrap (F1). See the README for the per-tool run modes and limits.\n"
    )
    w("## Corpus composition\n")
    w("| Stratum | Label | Repositories |")
    w("|---|---|---|")
    comp = Counter((c.stratum, c.label) for c in cases)
    for stratum in STRATA:
        for label in LABELS:
            if comp[(stratum, label)]:
                w(f"| {stratum} | {label} | {comp[(stratum, label)]} |")
    langs = Counter(lang for c in cases for lang in c.languages)
    w("")
    w(
        "Languages (a repository can count more than once): "
        + ", ".join(f"{k} {v}" for k, v in langs.most_common())
        + ".\n"
    )
    w("## Repository detection\n")
    w(
        "| Tool | n | TP | FP | FN | TN | Errors | Recall | Specificity | Precision | F1 | MCC "
        "| Agent recall | Median s |"
    )
    w("|---|" + "---|" * 13)
    ranked = sorted(tools, key=lambda t: -s["tools"][t]["surfaces"]["repo"]["mcc"])
    for t in ranked:
        x = s["tools"][t]["surfaces"]["repo"]
        lo, hi = x["f1_ci"]
        tier = x.get("agent_tier", {}).get("agent_recall")
        secs = x["median_seconds"]
        w(
            f"| {display[t]} | {x['n']} | {x['tp']} | {x['fp']} | {x['fn']} | {x['tn']} | {x['errors']} "
            f"| {_ci(x['recall'])} | {_ci(x['specificity'])} | {_ci(x['precision'])} "
            f"| {x['f1']:.2f} ({lo:.2f}–{hi:.2f}) | {x['mcc']:.2f} | {_ci(tier)} "
            f"| {'–' if secs is None else f'{secs:.1f}'} |"
        )
    w("")
    w("## Detection by stratum\n")
    w("Positives: higher is better. `none` strata: lower is better.\n")
    rates = stratum_rates(results, cases, ranked)
    w("| Stratum | Label | " + " | ".join(display[t] for t in ranked) + " |")
    w("|---|---|" + "---|" * len(ranked))
    for stratum in STRATA:
        labels = sorted({c.label for c in cases if c.stratum == stratum}, key=LABELS.index)
        for label in labels:
            cells = []
            for t in ranked:
                hit, n = rates[t].get(stratum, (0, 0))
                cells.append(f"{hit}/{n}" if n else "–")
            w(f"| {stratum} | {label} | " + " | ".join(cells) + " |")
    w("")
    w("## Evidence coverage (secondary)\n")
    w(
        "For each evidence type a tool's adapter can map, the share of repositories labeled with that "
        "evidence on which the tool reported at least one item of that type, and how many repositories "
        "without that label received such a report. A tool is not scored on types it cannot express.\n"
    )
    coverage = evidence_coverage(
        results, cases, [(t, adapter_evidence_types(all_adapters[t])) for t in ranked]
    )
    w("| Evidence type | Labeled | " + " | ".join(display[t] for t in ranked) + " |")
    w("|---|---|" + "---|" * len(ranked))
    for etype in EVIDENCE_TYPES:
        labeled = sum(1 for c in cases if etype in c.evidence_types)
        cells = []
        for t in ranked:
            x = coverage.get(t, {}).get(etype)
            if not x:
                cells.append("–")
            else:
                cells.append(f"{x['found']}/{x['labeled']} (+{x['reported_on_unlabeled']} unlabeled)")
        w(f"| {etype} | {labeled} | " + " | ".join(cells) + " |")
    w("")
    if s["paired"]:
        w("## Paired comparison with ShadowScan (exact McNemar on correct/incorrect)\n")
        w("| Tool | n | ShadowScan right, other wrong | Other right, ShadowScan wrong | p |")
        w("|---|---|---|---|---|")
        for t in ranked:
            x = s["paired"].get(t, {}).get("repo")
            if x:
                w(
                    f"| {display[t]} | {x['n']} | {x['shadowscan_right_other_wrong']} "
                    f"| {x['other_right_shadowscan_wrong']} | {x['mcnemar_p']:.2g} |"
                )
        w("")
    lenient = shadowscan_lenient(results)
    if lenient and lenient["incomplete"]:
        w("## Supplementary (post hoc): ShadowScan incomplete scans\n")
        w(
            f"{lenient['incomplete']} ShadowScan scans ended incomplete (exit 3) and count as errors "
            "under the pre-registered rule, as ShadowScan's own fail-closed contract requires. The rows "
            "below re-read the stored reports: first counting an incomplete scan with findings as a "
            "detection, then also ignoring reports whose only findings are provider-key-shaped strings. "
            "Neither rule was pre-registered.\n"
        )
        w("| Rule | Recall | Specificity | F1 | MCC |")
        w("|---|---|---|---|---|")
        for rule, x in (
            ("pre-registered", lenient["pre_registered"]),
            ("incomplete with findings = detected", lenient["lenient"]),
            ("as above, ignoring reports whose only findings are secrets", lenient["lenient_no_secret_only"]),
        ):
            w(f"| {rule} | {_ci(x['recall'])} | {_ci(x['specificity'])} | {x['f1']:.2f} | {x['mcc']:.2f} |")
        w("")
        if lenient["reasons"]:
            w("Why the scans were incomplete (a scan can have several reasons):\n")
            w("| Reason | Scans |")
            w("|---|---|")
            for reason, count in lenient["reasons"].items():
                w(f"| {reason} | {count} |")
            w("")
    w("## Per-repository results\n")
    w("✓ detected, · not detected, ✗ error (crash, timeout or incomplete scan), – not applicable.\n")
    w("| Repository | Stratum | Label | " + " | ".join(display[t] for t in ranked) + " |")
    w("|---|---|---|" + "---|" * len(ranked))
    table = {t: {r["case"]: r for r in _rows(results, t)} for t in ranked}
    for case in sorted(cases, key=lambda c: (LABELS.index(c.label), c.stratum, c.case_id)):
        cells = []
        for t in ranked:
            r = table[t].get(case.case_id)
            if r is None or r["status"] == "n/a":
                cells.append("–")
            elif r["status"] == "error":
                cells.append("✗")
            else:
                cells.append("✓" if r["detected"] else "·")
        src = case.source
        host = "gitlab.com" if src["host"] == "gitlab" else "github.com"
        link = f"[{src['repo']}](https://{host}/{src['repo']}/tree/{src['sha'][:12]})"
        w(f"| {link} | {case.stratum} | {case.label} | " + " | ".join(cells) + " |")
    w("")
    w("## Errors\n")
    any_err = False
    for t in ranked:
        errs = [r for r in _rows(results, t) if r["status"] == "error"]
        if errs:
            any_err = True
            kinds = Counter(
                (
                    "timeout"
                    if "timeout" in r["note"]
                    else "incomplete"
                    if "incomplete" in r["note"]
                    else "crash"
                )
                for r in errs
            )
            summary = ", ".join(f"{k} {v}" for k, v in kinds.items())
            example = f"`{errs[0]['note'][:160]}` on `{by_id[errs[0]['case']].source['repo']}`"
            w(f"- {display[t]}: {len(errs)} errors ({summary}), e.g. {example}")
    if not any_err:
        w("- None: every tool completed every repository.")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_fetch = sub.add_parser("fetch", help="clone every pinned repository")
    p_fetch.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    p_fetch.add_argument("--checkouts", type=Path, required=True)
    p_run = sub.add_parser("run", help="run the adapters on the checkouts")
    p_run.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    p_run.add_argument("--checkouts", type=Path, required=True)
    p_run.add_argument("--tool-root", type=Path, required=True)
    p_run.add_argument("--results", type=Path, required=True)
    p_run.add_argument("--tools", default="all", help="comma-separated adapter names")
    p_run.add_argument("--workers", type=int, default=4)
    p_run.add_argument("--timeout", type=int, default=900, help="seconds per tool invocation")
    p_run.add_argument("--only", default="", help="comma-separated case ids (calibration only)")
    p_report = sub.add_parser("report", help="render the Markdown report")
    p_report.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    p_report.add_argument("--results", type=Path, required=True)
    p_report.add_argument("--output", type=Path)
    p_validate = sub.add_parser("validate", help="check the corpus file")
    p_validate.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args(argv)
    if args.command == "fetch":
        fetch(args.corpus, args.checkouts)
        return 0
    if args.command == "run":
        tools = None if args.tools == "all" else set(args.tools.split(","))
        only = set(filter(None, args.only.split(","))) or None
        return run(
            args.corpus, args.checkouts, args.tool_root, args.results, tools, args.workers, args.timeout, only
        )
    if args.command == "report":
        text = render(args.corpus, args.results)
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0
    metadata, cases = load_corpus(args.corpus)
    print(f"{len(cases)} cases, {Counter(c.label for c in cases)}, sha256 {corpus_sha256(args.corpus)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
