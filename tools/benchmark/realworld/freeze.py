"""Record and verify the files that define the benchmark before the scored run starts.

``python -m tools.benchmark.realworld.freeze --write results/freeze.json`` stores the SHA-256 of every
file in ``FROZEN`` plus the ShadowScan source tree hash; ``--check results/freeze.json`` (also done by
``run.py --freeze``) fails when any of them has changed since.

This is a self-attested record. Nothing in this benchmark is committed to version control, so the record
cannot prove *when* a file was written; it proves that the files used for the scored run are the files
listed here, byte for byte, and it stops the author from editing the oracle, the adapters or the sample
between the freeze and the run without the run noticing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
FROZEN = (
    "PROTOCOL.md", "adapters.py", "baseline_grep.py", "contamination.py", "exclusions.json", "fetch.py",
    "fetch_corpus.py", "frames.py", "freeze.py", "install_tools.sh", "oracle.py", "purposive.json",
    "registry/ai_registry.json", "registry/vocab-overlap.json", "run.py", "sample.py", "sandbox.py",
    "score.py", "vocab_overlap.py", "manifest.jsonl", "calibration.jsonl", "labels.jsonl",
    "labels-calibration.jsonl", "rejects.jsonl", "sampling-summary.json",
)  # fmt: skip


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha256(root: Path, suffixes: tuple[str, ...] = (".py", ".yaml", ".yml", ".json")) -> str:
    """One hash over the relative names and contents of the package files under ``root``."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in suffixes):
        if "__pycache__" in path.parts:
            continue
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def git(*args: str) -> str:
    done = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return done.stdout.strip()


def snapshot() -> dict[str, object]:
    return {
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "self-attested; nothing is committed, so this proves identity of files, not time of writing",
        "files": {name: sha256(HERE / name) for name in FROZEN},
        "shadowscan_source_tree_sha256": tree_sha256(REPO_ROOT / "shadowscan"),
        "git_head": git("rev-parse", "HEAD"),
        "git_changes_outside_benchmark": [
            line
            for line in git("status", "--porcelain").splitlines()
            if "benchmark/realworld" not in line and "test_benchmark_realworld" not in line
        ],
    }


def check(path: Path) -> list[str]:
    recorded = json.loads(path.read_text(encoding="utf-8"))
    problems = [
        f"{name}: changed since the freeze"
        for name, digest in recorded["files"].items()
        if not (HERE / name).exists() or sha256(HERE / name) != digest
    ]
    if tree_sha256(REPO_ROOT / "shadowscan") != recorded["shadowscan_source_tree_sha256"]:
        problems.append("shadowscan source tree: changed since the freeze")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(snapshot(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"froze {len(FROZEN)} files to {args.write}")
        return 0
    problems = check(args.check)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
