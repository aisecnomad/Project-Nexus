"""Run tool adapters over a generated corpus and write one JSONL file per tool.

``python -m tools.benchmark.run --corpus corpus.json --tool-root DIR --results OUT``
(optional: ``--tools a,b``, ``--workers 4``)

Cases a tool does not support are recorded as ``n/a``. A crash, timeout or
incomplete scan is recorded as ``error`` and is never silently a negative.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import platform
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from tools.benchmark.adapters import ADAPTERS, Adapter, Outcome, ToolEnv
from tools.benchmark.common import Case
from tools.benchmark.generate import load_corpus


def _run_one(adapter: Adapter, case: Case, env: ToolEnv, scratch: Path) -> Outcome:
    work = Path(tempfile.mkdtemp(prefix=f"{adapter.name}-{case.case_id}-", dir=scratch))
    try:
        return adapter.run(case, work, env)
    except Exception as exc:  # noqa: BLE001 - a broken adapter or report is an error outcome, not a crash
        return Outcome("error", note=f"adapter exception: {type(exc).__name__}: {exc}"[:300])
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(work.parent / f"{work.name}-baseline", ignore_errors=True)


def run_tool(
    adapter: Adapter, cases: list[Case], env: ToolEnv, results: Path, workers: int, scratch: Path
) -> dict[str, Any]:
    out_path = results / f"{adapter.name}.jsonl"
    raw_path = results / "raw" / f"{adapter.name}.jsonl.gz"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    rows: dict[str, dict[str, Any]] = {}
    started = time.time()
    with gzip.open(raw_path, "wt", encoding="utf-8") as raw_fh:

        def task(case: Case) -> None:
            outcome = _run_one(adapter, case, env, scratch)
            row = {
                "case": case.case_id,
                "surface": case.surface,
                "family": case.family,
                "label": case.label,
                "difficulty": case.difficulty,
                "status": outcome.status,
                "detected": outcome.detected,
                "items": outcome.items,
                "agentic": outcome.agentic,
                "seconds": round(outcome.seconds, 3),
                "note": outcome.note,
                "evidence": outcome.evidence,
            }
            with lock:
                rows[case.case_id] = row
                if outcome.raw:
                    raw_fh.write(json.dumps({"case": case.case_id, "raw": outcome.raw}) + "\n")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(task, cases))
    with open(out_path, "w", encoding="utf-8") as fh:
        for case in cases:
            fh.write(json.dumps(rows[case.case_id]) + "\n")
    statuses = [r["status"] for r in rows.values()]
    return {
        "tool": adapter.name,
        "display": adapter.display,
        "source": adapter.source,
        "surfaces": adapter.surfaces,
        "wall_seconds": round(time.time() - started, 1),
        "ok": statuses.count("ok"),
        "error": statuses.count("error"),
        "n/a": statuses.count("n/a"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--tool-root", type=Path, required=True, help="third-party checkouts, venvs and bin/")
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--tools", default="all", help="comma-separated adapter names")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0, help="first N cases per surface (calibration only)")
    args = parser.parse_args(argv)

    corpus_bytes = args.corpus.read_bytes()
    metadata, cases = load_corpus(args.corpus)
    if args.limit:
        kept: list[Case] = []
        for surface in ("repo", "endpoint", "network"):
            kept += [c for c in cases if c.surface == surface][: args.limit]
        cases = kept
    wanted = None if args.tools == "all" else set(args.tools.split(","))
    adapters = [a for a in ADAPTERS if wanted is None or a.name in wanted]
    if wanted and wanted - {a.name for a in adapters}:
        parser.error(f"unknown tools: {sorted(wanted - {a.name for a in adapters})}")
    args.results.mkdir(parents=True, exist_ok=True)
    env = ToolEnv(root=args.tool_root.resolve(), python=sys.executable)
    scratch = Path(tempfile.mkdtemp(prefix="benchmark-work-")).resolve()
    runs = []
    try:
        for adapter in adapters:
            summary = run_tool(adapter, cases, env, args.results, args.workers, scratch)
            runs.append(summary)
            print(json.dumps(summary), flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    manifest_path = args.results / "run-manifest.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"runs": []}
    kept_runs = [r for r in previous.get("runs", []) if r["tool"] not in {s["tool"] for s in runs}]
    manifest = {
        "corpus": str(args.corpus.name),
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "corpus_metadata": metadata,
        "cases_run": len(cases),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runs": kept_runs + runs,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
