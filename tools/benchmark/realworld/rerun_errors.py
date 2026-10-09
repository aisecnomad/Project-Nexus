"""Re-run, alone, the (tool, repository) pairs that ended in a timeout, a kill or an adapter exception.

``python -m tools.benchmark.realworld.rerun_errors --manifest M --corpus CORPUS --tool-root TOOL_ROOT
--results results --out results-rerun --merged results-merged [--workers 2]``

The scored run uses many workers on few CPUs, so a pair can time out because the machine was loaded rather
than because the tool is slow. This is a declared deviation (PROTOCOL.md is frozen and does not describe it;
REPORT.md does): the headline stays the first run, and ``--merged`` receives a copy of the results in which
each re-run pair replaces its first row, for a sensitivity table. Only errors whose note says timeout, killed
or adapter exception are re-run, once. A pair that fails again keeps the new error row.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from tools.benchmark.realworld.adapters import ADAPTERS, ToolEnv
from tools.benchmark.realworld.run import load_rows, run_job
from tools.benchmark.realworld.sandbox import Sandbox

MARKERS = ("timeout", "killed", "adapter exception")


def candidates(results: Path) -> list[tuple[str, str]]:
    """(tool, id) pairs whose first-run row is a load-sensitive or harness error."""
    pairs: list[tuple[str, str]] = []
    for path in sorted(results.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row["status"] != "ok" and any(m in row["note"] for m in MARKERS):
                pairs.append((row["tool"], row["id"]))
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--merged", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, default=Path("/opt/rwb/runs"))
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)

    rows = {r["id"]: r for r in load_rows(args.manifest)}
    adapters = {a.name: a for a in ADAPTERS}
    tool_root = args.tool_root.resolve()
    env = ToolEnv(root=tool_root, sandbox=Sandbox(args.scratch, timeout=args.timeout, expose=(tool_root,)))
    pairs = candidates(args.results)
    args.out.mkdir(parents=True, exist_ok=True)

    def work(pair: tuple[str, str]) -> dict[str, Any]:
        tool, rid = pair
        outcome = run_job(adapters[tool], rows[rid], args.corpus, env)
        return {"id": rid, "tool": tool, **outcome.to_json()}

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        redone = list(pool.map(work, pairs))
    by_pair = {(r["tool"], r["id"]): r for r in redone}
    for tool in sorted({t for t, _ in pairs}):
        with open(args.out / f"{tool}.jsonl", "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(r, sort_keys=True) + "\n" for r in redone if r["tool"] == tool)

    shutil.rmtree(args.merged, ignore_errors=True)
    args.merged.mkdir(parents=True)
    for path in sorted(args.results.glob("*.jsonl")):
        merged = []
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            merged.append(by_pair.get((row["tool"], row["id"]), row))
        (args.merged / path.name).write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in merged), encoding="utf-8"
        )
    now_ok = sum(1 for r in redone if r["status"] == "ok")
    print(json.dumps({"rerun": len(redone), "ok_now": now_ok, "still_error": len(redone) - now_ok}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
