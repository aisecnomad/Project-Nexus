"""Run the tools over a corpus manifest, one sandbox session per (tool, repository).

``python -m tools.benchmark.realworld.run --manifest manifest.jsonl --corpus CORPUS \\
    --tool-root /opt/rwb/toolroot --results OUT [--tools a,b] [--workers 4] [--limit N]``

Resumable: finished (tool, repository) pairs in ``OUT/<tool>.jsonl`` are skipped, so an
interrupted run continues. Raw tool output is never written; only the normalised outcome,
because third-party repositories can contain third-party credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from tools.benchmark.realworld import freeze
from tools.benchmark.realworld.adapters import ADAPTERS, Adapter, Outcome, ToolEnv
from tools.benchmark.realworld.sandbox import Sandbox

# Slow tools first so their idle waits overlap with everything else.
PRIORITY = {"cisco-aibom": 0, "agentic-radar": 1, "agentdiscover": 2}
REPO_ROOT = Path(__file__).resolve().parents[3]


def load_rows(path: Path, limit: int = 0) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows[:limit] if limit else rows


def git(args: list[str], cwd: Path) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    return done.stdout.strip()


def tool_versions(env: ToolEnv) -> dict[str, Any]:
    """Pinned third-party commits and versions; every probe runs in the sandbox (no network, empty HOME),
    because some of these tools send telemetry from a version command."""
    root = env.root
    versions: dict[str, Any] = {}
    for checkout in sorted((root / "third_party").glob("*")):
        versions[checkout.name] = git(["rev-parse", "HEAD"], checkout) or "unknown"
    cdxgen = root / "cdxgen" / "node_modules" / "@cyclonedx" / "cdxgen" / "package.json"
    if cdxgen.exists():
        versions["cdxgen"] = json.loads(cdxgen.read_text(encoding="utf-8")).get("version")
    vet = root / "bin" / "vet"
    if vet.exists():
        with env.sandbox.session(None) as session:
            done = session.run([str(vet), "version", "--no-banner"], timeout=60)
        versions["safedep_vet_version"] = (done.stdout + done.stderr).strip().splitlines()[-1:] or ["unknown"]
    versions["shadowscan_commit"] = git(["rev-parse", "HEAD"], REPO_ROOT)
    versions["shadowscan_source_dirty"] = bool(
        git(["status", "--porcelain", "--", "shadowscan", "pyproject.toml"], REPO_ROOT)
    )
    installed = next((root / "venvs" / "shadowscan" / "lib").glob("python*/site-packages/shadowscan"), None)
    versions["shadowscan_source_tree_sha256"] = freeze.tree_sha256(REPO_ROOT / "shadowscan")
    versions["shadowscan_installed_tree_sha256"] = freeze.tree_sha256(installed) if installed else None
    return versions


def run_job(adapter: Adapter, row: dict[str, Any], corpus: Path, env: ToolEnv) -> Outcome:
    started = time.monotonic()
    try:
        with env.sandbox.session(corpus / row["dir"]) as session:
            return adapter.run(session, env)
    except Exception as exc:  # noqa: BLE001 - a broken adapter or report is an error outcome, never a crash of the run
        return Outcome(
            "error",
            seconds=time.monotonic() - started,
            note=f"adapter exception: {type(exc).__name__}",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, default=Path("/opt/rwb/runs"))
    parser.add_argument("--tools", default="all")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--freeze", type=Path, help="refuse to run unless the frozen files are unchanged")
    args = parser.parse_args(argv)

    if args.freeze:
        problems = freeze.check(args.freeze)
        if problems:
            parser.error("the harness differs from the freeze record: " + "; ".join(problems))
    rows = load_rows(args.manifest, args.limit)
    wanted = None if args.tools == "all" else set(args.tools.split(","))
    adapters = [a for a in ADAPTERS if wanted is None or a.name in wanted]
    if wanted and wanted - {a.name for a in adapters}:
        parser.error(f"unknown tools: {sorted(wanted - {a.name for a in adapters})}")
    tool_root = args.tool_root.resolve()
    env = ToolEnv(root=tool_root, sandbox=Sandbox(args.scratch, timeout=args.timeout, expose=(tool_root,)))
    problems = env.sandbox.selftest()
    if problems:
        parser.error("the sandbox does not isolate as documented: " + "; ".join(problems))
    args.results.mkdir(parents=True, exist_ok=True)

    jobs: list[tuple[Adapter, dict[str, Any]]] = []
    for adapter in adapters:
        reason = adapter.unavailable(env)
        if reason:
            parser.error(f"{adapter.name} is not installed ({reason})")
        path = args.results / f"{adapter.name}.jsonl"
        done = (
            {json.loads(line)["id"] for line in path.read_text(encoding="utf-8").splitlines() if line}
            if path.exists()
            else set()
        )
        jobs += [(adapter, row) for row in rows if row["id"] not in done]
    jobs.sort(key=lambda job: (PRIORITY.get(job[0].name, 9), job[1]["id"]))

    lock = threading.Lock()
    counter = Counter[str]()
    started = time.time()

    def work(job: tuple[Adapter, dict[str, Any]]) -> None:
        adapter, row = job
        outcome = run_job(adapter, row, args.corpus, env)
        line = json.dumps({"id": row["id"], "tool": adapter.name, **outcome.to_json()}, sort_keys=True)
        with lock:
            with open(args.results / f"{adapter.name}.jsonl", "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            counter[f"{adapter.name}:{outcome.status}"] += 1
            total = sum(counter.values())
            if total % 25 == 0:
                errors = sum(v for k, v in counter.items() if k.endswith(":error"))
                print(f"{total}/{len(jobs)} done, {time.time() - started:.0f}s, errors={errors}", flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(work, jobs))

    manifest_bytes = args.manifest.read_bytes()
    record = {
        "manifest": args.manifest.name,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "repositories": len(rows),
        "tools": [a.name for a in adapters],
        "tool_info": {a.name: {"display": a.display, "source": a.source, "scope": a.scope} for a in adapters},
        "outcomes": dict(sorted(counter.items())),
        "wall_seconds": round(time.time() - started, 1),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "timeout_s": args.timeout,
        "workers": args.workers,
        "frozen_files_sha256": {
            name: freeze.sha256(freeze.HERE / name) for name in freeze.FROZEN if (freeze.HERE / name).exists()
        },
        "freeze_record_sha256": freeze.sha256(args.freeze) if args.freeze else None,
        "versions": tool_versions(env),
        "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    previous = args.results / "run-manifest.json"
    history = json.loads(previous.read_text(encoding="utf-8")).get("runs", []) if previous.exists() else []
    previous.write_text(json.dumps({"runs": [*history, record]}, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(record["outcomes"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
