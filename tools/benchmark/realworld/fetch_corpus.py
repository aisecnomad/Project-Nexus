"""Re-create the corpus from the manifest: one pinned commit per repository, anonymous git reads only.

``python -m tools.benchmark.realworld.fetch_corpus --manifest manifest.jsonl --corpus CORPUS [--workers 4]``

Each repository goes into ``CORPUS/<row dir>`` and its commit and tree hash are checked against the
manifest, so a force-pushed or deleted upstream is reported rather than silently replaced. Repositories
that are gone are listed; the benchmark can be re-run on the rest. Existing directories are kept.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from tools.benchmark.realworld.fetch import FetchError, fetch_snapshot


def fetch_row(row: dict[str, Any], corpus: Path) -> tuple[str, str]:
    dest = corpus / row["dir"]
    if dest.exists():
        return row["id"], "kept"
    try:
        snapshot = fetch_snapshot(row["url"], dest, row["sha"], require_code=False)
    except FetchError as exc:
        return row["id"], f"failed: {exc.reason}"
    if snapshot.tree != row["tree"]:
        return row["id"], "tree hash differs from the manifest"
    return row["id"], "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    rows = [
        json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    args.corpus.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        outcomes = list(pool.map(lambda row: fetch_row(row, args.corpus), rows))
    problems = [(rid, why) for rid, why in outcomes if why not in {"ok", "kept"}]
    for rid, why in problems:
        print(f"{rid}: {why}", file=sys.stderr)
    print(f"{len(rows) - len(problems)} of {len(rows)} repositories present")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
