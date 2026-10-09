"""Run the repo-surface tool cohort over the pinned real-world corpus.

``python -m tools.benchmark.realworld_run --corpus benchmarks/realworld/corpus.json \\
    --corpus-dir DIR --tool-root DIR --results OUT``
(optional: ``--tools a,b``, ``--workers 2``, ``--timeout 900``, ``--fetch``)

The corpus manifest pins every repository to a commit. ``--fetch`` clones each
missing repository and checks out its pinned commit; a run refuses to score a
checkout that is missing, at the wrong commit, or dirty (fail closed, never
silently scan the wrong tree). After each tool the pinned commit and entire
working tree, including ignored files, are re-verified. A changed checkout
stops the run before another tool runs; evidence is never silently restored.

Rows reuse the synthetic benchmark's schema, so ``tools.benchmark.score`` and
its Wilson/bootstrap/McNemar machinery apply unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.benchmark import adapters as adapters_mod
from tools.benchmark.common import Case
from tools.benchmark.realworld_adapters import rw_adapters
from tools.benchmark.run import run_tool


@dataclass(frozen=True)
class RepoSpec:
    repo_id: str
    url: str
    sha: str
    label: str
    family: str
    difficulty: str
    rationale: str


def load_manifest(path: Path) -> tuple[dict[str, Any], list[RepoSpec]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    specs = [
        RepoSpec(
            repo_id=r["id"],
            url=r["url"],
            sha=r["sha"],
            label=r["label"],
            family=r["family"],
            difficulty=r["difficulty"],
            rationale=r["rationale"],
        )
        for r in doc["repos"]
    ]
    return doc["metadata"], specs


def _git(args: list[str], cwd: Path | None = None) -> tuple[int, str]:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=600, check=False)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def fetch(specs: list[RepoSpec], corpus_dir: Path) -> None:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for spec in specs:
        dest = corpus_dir / spec.repo_id
        if not (dest / ".git").exists():
            code, out = _git(["clone", "--depth", "1", spec.url, str(dest)])
            if code != 0:
                raise RuntimeError(f"clone failed for {spec.repo_id}: {out[-300:]}")
        code, head = _git(["rev-parse", "HEAD"], dest)
        if code == 0 and head == spec.sha:
            continue
        code, out = _git(["fetch", "--depth", "1", "origin", spec.sha], dest)
        if code != 0:
            raise RuntimeError(f"fetch of pinned commit failed for {spec.repo_id}: {out[-300:]}")
        code, out = _git(["-c", "advice.detachedHead=false", "checkout", spec.sha], dest)
        if code != 0:
            raise RuntimeError(f"checkout failed for {spec.repo_id}: {out[-300:]}")


def verify(specs: list[RepoSpec], corpus_dir: Path) -> list[str]:
    """Problems that make the corpus unscoreable; empty means clean."""
    problems = []
    for spec in specs:
        dest = corpus_dir / spec.repo_id
        if not (dest / ".git").exists():
            problems.append(f"{spec.repo_id}: missing (run with --fetch)")
            continue
        code, head = _git(["rev-parse", "HEAD"], dest)
        if code != 0 or head != spec.sha:
            problems.append(f"{spec.repo_id}: at {head[:12]}, manifest pins {spec.sha[:12]}")
        code, status = _git(["status", "--porcelain", "--untracked-files=all", "--ignored"], dest)
        if code != 0 or status:
            problems.append(f"{spec.repo_id}: working tree dirty")
    return problems


def verify_after_tool(specs: list[RepoSpec], corpus_dir: Path, name: str) -> None:
    problems = verify(specs, corpus_dir)
    if problems:
        raise RuntimeError(f"corpus integrity changed after {name}; run stopped: {'; '.join(problems)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--tools", default="all", help="comma-separated adapter names")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=900, help="seconds per tool per repository")
    parser.add_argument("--fetch", action="store_true", help="clone or update pinned checkouts first")
    args = parser.parse_args(argv)

    corpus_bytes = args.corpus.read_bytes()
    metadata, specs = load_manifest(args.corpus)
    corpus_dir = args.corpus_dir.resolve()
    if args.fetch:
        fetch(specs, corpus_dir)
    problems = verify(specs, corpus_dir)
    if problems:
        for problem in problems:
            print(f"corpus: {problem}", file=sys.stderr)
        return 2

    adapters_mod.TIMEOUT_S = args.timeout
    paths = {spec.repo_id: corpus_dir / spec.repo_id for spec in specs}
    cases = [
        Case(
            case_id=spec.repo_id,
            surface="repo",
            family=spec.family,
            label=spec.label,
            difficulty=spec.difficulty,
            rationale=spec.rationale,
        )
        for spec in specs
    ]
    available = {a.name: a for a in rw_adapters(paths)}
    wanted = list(available) if args.tools == "all" else args.tools.split(",")
    unknown = [name for name in wanted if name not in available]
    if unknown:
        parser.error(f"unknown tools: {unknown}; known: {sorted(available)}")

    args.results.mkdir(parents=True, exist_ok=True)
    env = adapters_mod.ToolEnv(root=args.tool_root.resolve(), python=sys.executable)
    scratch = Path(tempfile.mkdtemp(prefix="realworld-bench-")).resolve()
    runs: list[dict[str, Any]] = []
    try:
        for name in wanted:
            adapter = available[name]
            summary = run_tool(adapter, cases, env, args.results, args.workers, scratch)
            verify_after_tool(specs, corpus_dir, name)
            runs.append(summary)
            print(json.dumps(summary), flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    manifest_path = args.results / "run-manifest.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"runs": []}
    kept = [r for r in previous.get("runs", []) if r["tool"] not in {s["tool"] for s in runs}]
    manifest = {
        "corpus": args.corpus.name,
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "corpus_metadata": metadata,
        "cases_run": len(cases),
        "timeout_seconds": args.timeout,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "checkouts_dirtied_by_tool": previous.get("checkouts_dirtied_by_tool", {}),
        "runs": kept + runs,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
