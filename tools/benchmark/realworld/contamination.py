"""List corpus repositories that the ShadowScan repository itself names.

``python -m tools.benchmark.realworld.contamination [--write exclusions.json]``

ShadowScan is one of the tools scored and its authors wrote its signature packs, evaluation corpora and
documentation. A corpus repository that any of those files names (``owner/name`` or the full host path)
may have been used to build or tune ShadowScan, so it is not an unseen repository for that tool. The
scorer drops these repositories from every tool's analysis (the set must be the same for all tools) and
the report lists them. The search is deterministic and reads only files tracked or untracked-but-not-
ignored in this repository, excluding this benchmark's own directory and its test file.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
SELF_PREFIXES = ("tools/benchmark/realworld/", "tests/test_benchmark_realworld.py")
MAX_BYTES = 5_000_000


def repository_files() -> dict[str, str]:
    listing = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\n")
    texts: dict[str, str] = {}
    for name in listing:
        if not name or name.startswith(SELF_PREFIXES):
            continue
        path = REPO_ROOT / name
        try:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES:
                texts[name] = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
    return texts


def find(rows: list[dict[str, object]], texts: dict[str, str]) -> dict[str, dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    for row in rows:
        owner = str(row["owner"]).lower()
        name = str(row["url"]).rstrip("/").rsplit("/", 1)[-1].lower()
        needles = (f"{row['host']}/{owner}/{name}", f"{owner}/{name}")
        files = sorted(f for f, text in texts.items() if any(n in text for n in needles) and len(name) > 3)
        if files:
            found[str(row["id"])] = {"url": row["url"], "frame": row["frame"], "files": files[:10]}
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--write", type=Path, help="write the exclusion list to this file")
    args = parser.parse_args(argv)
    rows = [
        json.loads(line)
        for name in ("manifest.jsonl", "calibration.jsonl")
        for line in (HERE / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    found = find(rows, repository_files())
    document = {
        "reason": (
            "named in a file of the ShadowScan repository (signature pack, evaluation corpus, documentation)"
        ),
        "excluded": found,
    }
    text = json.dumps(document, indent=1, sort_keys=True) + "\n"
    if args.write:
        args.write.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
