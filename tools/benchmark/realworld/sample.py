"""Build the benchmark corpus: candidate pools -> stratified, seeded selection -> pinned manifest.

``python -m tools.benchmark.realworld.sample --work DIR --out tools/benchmark/realworld``

Selection is deterministic for a given set of pools: each frame's pool is
shuffled with a seed derived from the frame name, candidates are fetched in that
order, and the first ones that pass the eligibility checks fill the quota. No
tool under test, and no label, takes part in selection. Per-owner caps keep one
organisation from dominating. The first ``calibration`` repositories of a frame
become the calibration split; the rest are the scored split. Nothing from the
calibration split is scored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from tools.benchmark.realworld import frames
from tools.benchmark.realworld.fetch import FetchError, Snapshot, fetch_snapshot
from tools.benchmark.realworld.frames import Candidate, Http
from tools.benchmark.realworld.oracle import Index, load_index

HERE = Path(__file__).resolve().parent
QUOTAS: dict[str, tuple[int, int]] = {  # frame -> (scored, calibration)
    "pypi-ai": (26, 3), "pypi-other": (26, 3),
    "npm-ai": (26, 3), "npm-other": (26, 3),
    "go-ai": (12, 1), "go-random": (24, 2),
    "gitlab-ai": (20, 2), "gitlab-random": (30, 3),
    "list-mcp": (20, 2), "list-claude-code": (20, 2), "list-agents": (20, 2), "list-ordinary": (30, 3),
    "hard-negative": (24, 2), "classical-ml": (14, 2), "prose-only": (8, 1),
}  # fmt: skip
LIST_REPOS: dict[str, list[str]] = {
    "list-mcp": ["https://github.com/punkpeye/awesome-mcp-servers"],
    "list-claude-code": ["https://github.com/hesreallyhim/awesome-claude-code"],
    "list-agents": ["https://github.com/e2b-dev/awesome-ai-agents", "https://github.com/kyrolabs/awesome-langchain"],
    "list-ordinary": [
        "https://github.com/awesome-selfhosted/awesome-selfhosted",
        "https://github.com/avelino/awesome-go",
        "https://github.com/vinta/awesome-python",
        "https://github.com/rust-unofficial/awesome-rust",
    ],
}  # fmt: skip
REQUIRE_CODE = {"prose-only": False}
MAX_PER_OWNER = 2
WORKERS = 4


def slug(c: Candidate) -> str:
    digest = hashlib.sha256(c.url.lower().encode()).hexdigest()[:8]
    return f"{c.host}__{c.owner}__{c.repo}__{digest}".replace("/", "_")


def build_pools(args: argparse.Namespace, index: Index, http: Http) -> dict[str, list[Candidate]]:
    pools: dict[str, list[Candidate]] = {}
    pools["pypi-ai"], pools["pypi-other"] = frames.pypi_candidates(
        http, index, args.seed, args.pypi_names, args.since
    )
    pools["npm-ai"] = frames.npm_candidates(http, index, frames.NPM_AI_QUERIES, 2, args.since, "npm-ai")
    pools["npm-other"] = frames.npm_candidates(
        http, index, frames.NPM_OTHER_QUERIES, 2, args.since, "npm-other"
    )
    pools["go-ai"], pools["go-random"] = frames.go_candidates(
        http, args.seed, args.go_windows, args.since, args.until
    )
    pools["gitlab-ai"], pools["gitlab-random"] = frames.gitlab_candidates(
        http, args.seed, args.gitlab_starts, args.since
    )
    lists_dir = args.work / "lists"
    lists_dir.mkdir(parents=True, exist_ok=True)
    for frame, urls in LIST_REPOS.items():
        pools.setdefault(frame, [])
        for url in urls:
            cand = frames.canonical(url, frame)
            assert cand is not None
            target = lists_dir / slug(cand)
            if not target.exists():
                try:
                    fetch_snapshot(url, target, require_code=False)
                except FetchError as exc:
                    print(f"list {url}: {exc}", file=sys.stderr)
                    continue
            pools[frame] += [c for c in frames.read_list_repo(target, frame, cand.key) if c.key != cand.key]
    pools.update(frames.purposive(HERE / "purposive.json"))
    for frame, cands in pools.items():
        for c in cands:
            c.frame = frame
    return pools


def no_ai_dependency(http: Http, index: Index) -> Callable[[Candidate], bool]:
    """Frame check for ordinary npm packages: their latest release must not depend on AI tooling."""

    def check(c: Candidate) -> bool:
        return not frames.npm_has_ai_dep(http, index, str(c.meta.get("package")))

    return check


def attempt(c: Candidate, frame: str, corpus: Path) -> tuple[Candidate, Snapshot | None, str]:
    try:
        return c, fetch_snapshot(c.url, corpus / slug(c), require_code=REQUIRE_CODE.get(frame, True)), ""
    except FetchError as exc:
        return c, None, exc.reason
    except OSError as exc:
        return c, None, f"os-error:{type(exc).__name__}"


def select(
    frame: str,
    pool: list[Candidate],
    seed: int,
    corpus: Path,
    taken: set[str],
    owners: Counter[tuple[str, str]],
    rejects: list[dict[str, Any]],
    check: Callable[[Candidate], bool] | None,
) -> list[dict[str, Any]]:
    scored, calibration = QUOTAS[frame]
    target = scored + calibration
    order = sorted(pool, key=lambda c: c.key)
    random.Random(f"{seed}:{frame}").shuffle(order)
    accepted: list[dict[str, Any]] = []

    def reject(c: Candidate, reason: str) -> None:
        rejects.append({"frame": frame, "url": c.url, "reason": reason})

    cursor = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool_ex:
        while len(accepted) < target and cursor < len(order):
            chunk: list[Candidate] = []
            while len(chunk) < WORKERS and cursor < len(order):
                c = order[cursor]
                cursor += 1
                owner = (c.host, c.owner.lower())
                if c.key in taken:
                    reject(c, "duplicate")
                elif owners[owner] >= MAX_PER_OWNER:
                    reject(c, "owner-cap")
                elif check is not None and not check(c):
                    reject(c, "failed-frame-check")
                else:
                    chunk.append(c)
            for c, snap, reason in pool_ex.map(lambda cand: attempt(cand, frame, corpus), chunk):
                owner = (c.host, c.owner.lower())
                if snap is None:
                    reject(c, reason)
                    continue
                if len(accepted) >= target or c.key in taken or owners[owner] >= MAX_PER_OWNER:
                    shutil.rmtree(corpus / slug(c), ignore_errors=True)
                    reject(c, "surplus")
                    continue
                taken.add(c.key)
                owners[owner] += 1
                accepted.append(
                    {
                        "dir": slug(c),
                        "url": c.url,
                        "host": c.host,
                        "owner": c.owner,
                        "repo": c.repo,
                        "frame": frame,
                        "split": "calibration" if len(accepted) < calibration else "scored",
                        "sha": snap.sha,
                        "tree": snap.tree,
                        "files": snap.files,
                        "source_files": snap.source_files,
                        "bytes": snap.bytes,
                        "symlinks": snap.symlinks,
                        "symlinks_neutralized": snap.symlinks_neutralized,
                        "meta": c.meta,
                    }
                )
    print(f"{frame}: accepted {len(accepted)}/{target} (pool {len(pool)}, tried {cursor})", flush=True)
    return accepted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--work", type=Path, required=True, help="scratch root: HTTP cache, pools, list clones, corpus"
    )
    parser.add_argument("--out", type=Path, default=HERE)
    parser.add_argument("--seed", type=int, default=20261008)
    parser.add_argument("--since", default="2025-01-01")
    parser.add_argument("--until", default="2026-09-30")
    parser.add_argument("--pypi-names", type=int, default=9000)
    parser.add_argument("--go-windows", type=int, default=60)
    parser.add_argument("--gitlab-starts", type=int, default=200)
    parser.add_argument("--pools-only", action="store_true")
    parser.add_argument("--reuse-pools", action="store_true")
    parser.add_argument("--frames", default="all")
    args = parser.parse_args(argv)

    index = load_index(HERE / "registry" / "ai_registry.json")
    http = Http(args.work / "cache" / "http")
    pools_path = args.work / "pools.json"
    if args.reuse_pools and pools_path.exists():
        raw = json.loads(pools_path.read_text(encoding="utf-8"))
        pools = {f: [Candidate(**c) for c in cs] for f, cs in raw.items()}
    else:
        pools = build_pools(args, index, http)
        pools_path.write_text(
            json.dumps({f: [asdict(c) for c in cs] for f, cs in pools.items()}), encoding="utf-8"
        )
    print(json.dumps({f: len(cs) for f, cs in pools.items()}), flush=True)
    if args.pools_only:
        return 0

    corpus = args.work / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    wanted = list(QUOTAS) if args.frames == "all" else args.frames.split(",")
    taken: set[str] = set()
    owners: Counter[tuple[str, str]] = Counter()
    rejects: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for frame in wanted:
        check = no_ai_dependency(http, index) if frame == "npm-other" else None
        rows += select(frame, pools.get(frame, []), args.seed, corpus, taken, owners, rejects, check)

    counters = {"scored": 0, "calibration": 0}
    for row in rows:
        counters[row["split"]] += 1
        row["id"] = (
            f"rw-{counters['scored']:03d}"
            if row["split"] == "scored"
            else f"cal-{counters['calibration']:02d}"
        )
    scored = [r for r in rows if r["split"] == "scored"]
    calibration = [r for r in rows if r["split"] == "calibration"]
    for name, items in (
        ("manifest.jsonl", scored),
        ("calibration.jsonl", calibration),
        ("rejects.jsonl", rejects),
    ):
        (args.out / name).write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in items), encoding="utf-8"
        )
    accepted_counts = Counter((r["frame"], r["split"]) for r in rows)
    summary = {
        "seed": args.seed,
        "since": args.since,
        "until": args.until,
        "sampled_on": time.strftime("%Y-%m-%d", time.gmtime()),
        "quotas": QUOTAS,
        "pool_sizes": {f: len(cs) for f, cs in pools.items()},
        "accepted": {f"{f}|{s}": n for (f, s), n in sorted(accepted_counts.items())},
        "reject_reasons": dict(Counter(r["reason"] for r in rejects).most_common()),
        "max_per_owner": MAX_PER_OWNER,
    }
    (args.out / "sampling-summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"scored": len(scored), "calibration": len(calibration), "rejects": len(rejects)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
