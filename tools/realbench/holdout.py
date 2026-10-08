"""Draw the post-change holdout corpus from the committed frame snapshot.

``python -m tools.realbench.holdout --frames tools/realbench/frames --workdir DIR --manifest OUT --log LOG``

Pre-registered in PROTOCOL.md §13 before the draw. The procedure is the scored
draw of ``sample.py`` (same frames, strata, quotas, eligibility rules and
two-stage selection) with three differences:

1. the seed is ``HOLDOUT_SEED``;
2. every repository, and every owner, of the scored and calibration corpora
   (and every purposive repository) is excluded, so the holdout shares no
   repository or owner with the corpus whose results guided the changes;
3. there are no purposive sets: hand-picking new hard negatives after seeing
   the first results would not be blind.

Accepted repositories get shuffled neutral identifiers ``h001``...
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.realbench.frames import load_frames
from tools.realbench.sample import (
    MAX_BYTES,
    MAX_FILES,
    QUOTAS,
    Drawer,
    frame_candidates,
    frames_digest,
    repo_key,
)

HOLDOUT_SEED = 20261009
HERE = Path(__file__).resolve().parent


def drawn_before(manifests: list[Path], purposive: Path) -> tuple[set[str], set[str]]:
    """Repository keys and owners of every earlier corpus, calibration set and purposive list."""
    keys: set[str] = set()
    owners: set[str] = set()
    urls = [
        repo["url"] for path in manifests for repo in json.loads(path.read_text(encoding="utf-8"))["repos"]
    ]
    lists = json.loads(purposive.read_text(encoding="utf-8"))
    urls += [item["url"] for stratum in ("hard-negatives", "config-positives") for item in lists[stratum]]
    for url in urls:
        parsed = repo_key(url)
        if parsed is None:
            raise ValueError(f"unparseable earlier URL {url}")
        keys.add(parsed[0])
        owners.add(parsed[1])
    return keys, owners


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frames", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True, help="checkouts go to holdout/")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True, help="gzipped JSONL of every draw attempt")
    parser.add_argument(
        "--exclude",
        type=Path,
        nargs="+",
        default=[HERE / "corpus.json", HERE / "calibration.json"],
        help="manifests whose repositories and owners are excluded",
    )
    parser.add_argument("--purposive", type=Path, default=HERE / "purposive.json")
    args = parser.parse_args(argv)

    frames = load_frames(args.frames)
    missing = set(QUOTAS) - set(frames)
    if missing:
        parser.error(f"frame snapshot lacks strata {sorted(missing)}")
    keys, owners = drawn_before(args.exclude, args.purposive)
    started = datetime.now(UTC).replace(microsecond=0).isoformat()
    args.workdir.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.log, "wt", encoding="utf-8") as log:
        drawer = Drawer(args.workdir, log)
        drawer.keys |= keys
        drawer.owners |= owners
        holdout: list[dict[str, Any]] = []
        for stratum, quota in QUOTAS.items():
            pools = frame_candidates(frames[stratum], stratum)
            got = drawer.draw("holdout", stratum, pools, quota, HOLDOUT_SEED)
            if len(got) < quota:
                print(f"warning: {stratum} filled {len(got)}/{quota}", file=sys.stderr)
            holdout += got
        drawer.place(holdout, "h", args.workdir / "holdout", HOLDOUT_SEED)
        drawer.cleanup()
    meta = {
        "created_at": started,
        "frames_sha256": frames_digest(args.frames),
        "holdout_seed": HOLDOUT_SEED,
        "quotas": QUOTAS,
        "excluded_repositories": len(keys),
        "excluded_owners": len(owners),
        "max_bytes": MAX_BYTES,
        "max_files": MAX_FILES,
        "clone": "git clone --depth 1 --no-tags --single-branch (no submodules, LFS smudge skipped)",
    }
    args.manifest.write_text(json.dumps({**meta, "repos": holdout}, indent=1) + "\n", encoding="utf-8")
    counts = Counter(e["stratum"] for e in holdout)
    print(json.dumps({"holdout": len(holdout), "by_stratum": counts}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
