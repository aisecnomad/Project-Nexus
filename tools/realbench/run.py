"""Run every adapter on every repository of a corpus manifest.

``python -m tools.realbench.run --manifest corpus.json --corpus DIR --tool-root DIR --results OUT``
(optional: ``--tools a,b``, ``--workers 4``, ``--repeat-fraction 0.1``)

Writes ``OUT/<tool>.jsonl`` (one normalised row per repository), raw reports
to ``OUT/raw/<tool>/<id>.json.gz`` (kept outside the repository; their SHA-256
is in the row) and ``OUT/run-manifest.json``. A seeded fraction of
repositories is run a second time per tool (``<tool>.repeat.jsonl``) to
measure run-to-run flips.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.realbench.adapters import ADAPTERS, Adapter, Outcome, ToolEnv
from tools.realbench.labels import redact

REPEAT_SEED = 7


def _run_one(adapter: Adapter, repo: Path, env: ToolEnv, scratch: Path, rid: str) -> Outcome:
    work = Path(tempfile.mkdtemp(prefix=f"{adapter.name}-{rid}-", dir=scratch))
    try:
        return adapter.run(repo, work, env)
    except Exception as exc:  # noqa: BLE001 - a broken adapter or report is an error outcome, not a crash
        return Outcome("error", note=f"adapter exception: {type(exc).__name__}: {exc}"[:300])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _row(rid: str, outcome: Outcome, raw_sha: str | None) -> dict[str, Any]:
    return {
        "id": rid,
        "status": outcome.status,
        "detected": outcome.detected,
        "agentic": outcome.agentic,
        "items": outcome.items,
        "kinds": outcome.kinds[:40],
        "paths": outcome.paths,
        "seconds": round(outcome.seconds, 2),
        "note": redact(outcome.note) if outcome.note else "",
        "raw_sha256": raw_sha,
        **({"agentic_kinds": outcome.agentic_kinds} if outcome.agentic_kinds is not None else {}),
    }


def run_tool(
    adapter: Adapter,
    repos: list[dict[str, Any]],
    corpus: Path,
    env: ToolEnv,
    results: Path,
    workers: int,
    scratch: Path,
    suffix: str = "",
) -> dict[str, Any]:
    raw_dir = results / "raw" / adapter.name
    raw_dir.mkdir(parents=True, exist_ok=True)
    rows: dict[str, dict[str, Any]] = {}
    lock = threading.Lock()
    started = time.time()

    def task(repo: dict[str, Any]) -> None:
        rid = repo["id"]
        outcome = _run_one(adapter, corpus / rid, env, scratch, rid)
        raw_sha = None
        if outcome.raw and not suffix:
            blob = json.dumps(outcome.raw, sort_keys=True).encode()
            raw_sha = hashlib.sha256(blob).hexdigest()
            with gzip.open(raw_dir / f"{rid}.json.gz", "wb") as fh:
                fh.write(blob)
        with lock:
            rows[rid] = _row(rid, outcome, raw_sha)
            print(f"{adapter.name:14} {rid} {outcome.status:7} det={outcome.detected!s:5} "
                  f"agt={outcome.agentic!s:5} {outcome.seconds:6.1f}s", flush=True)  # fmt: skip

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(task, repos))
    path = results / f"{adapter.name}{suffix}.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for repo in repos:
            fh.write(json.dumps(rows[repo["id"]], sort_keys=True) + "\n")
    statuses = [r["status"] for r in rows.values()]
    return {
        "tool": adapter.name,
        "display": adapter.display,
        "source": adapter.source,
        "mode": adapter.mode,
        "agentic_rule": adapter.agentic_rule,
        "file": path.name,
        "wall_seconds": round(time.time() - started, 1),
        "ok": statuses.count("ok"),
        "partial": statuses.count("partial"),
        "error": statuses.count("error"),
    }


def _git_head(path: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable, help="interpreter with ShadowScan installed")
    parser.add_argument("--tools", default="all")
    parser.add_argument("--ids", default="", help="comma-separated subset (calibration only)")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--repeat-fraction", type=float, default=0.0)
    args = parser.parse_args(argv)

    manifest_bytes = args.manifest.read_bytes()
    repos = json.loads(manifest_bytes)["repos"]
    if args.ids:
        wanted_ids = set(args.ids.split(","))
        repos = [r for r in repos if r["id"] in wanted_ids]
    wanted = None if args.tools == "all" else set(args.tools.split(","))
    adapters = [a for a in ADAPTERS if wanted is None or a.name in wanted]
    if wanted and wanted - {a.name for a in adapters}:
        parser.error(f"unknown tools: {sorted(wanted - {a.name for a in adapters})}")
    args.results.mkdir(parents=True, exist_ok=True)
    env = ToolEnv(root=args.tool_root.resolve(), python=args.python)
    started_at_commit = _git_head(Path(__file__).resolve().parents[2])
    scratch = Path(tempfile.mkdtemp(prefix="realbench-work-")).resolve()
    repeat = []
    if args.repeat_fraction:
        k = max(1, round(len(repos) * args.repeat_fraction))
        repeat = sorted(random.Random(REPEAT_SEED).sample(repos, k), key=lambda r: r["id"])
    runs = []
    try:
        for adapter in adapters:
            summary = run_tool(adapter, repos, args.corpus, env, args.results, args.workers, scratch)
            if repeat:
                again = run_tool(
                    adapter, repeat, args.corpus, env, args.results, args.workers, scratch, ".repeat"
                )
                summary["repeat"] = {"n": len(repeat), "file": again["file"]}
            runs.append(summary)
            print(json.dumps(summary), flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    manifest_path = args.results / "run-manifest.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"runs": []}
    kept = [r for r in previous.get("runs", []) if r["tool"] not in {s["tool"] for s in runs}]
    project = Path(__file__).resolve().parents[2]
    out = {
        "manifest": args.manifest.name,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "repositories": len(repos),
        "finished_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "shadowscan_commit": started_at_commit,
        "commit_at_finish": _git_head(project),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "tool_commits": {
            p.name: _git_head(p) for p in sorted((args.tool_root / "third_party").glob("*")) if p.is_dir()
        },
        "runs": kept + runs,
    }
    manifest_path.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
