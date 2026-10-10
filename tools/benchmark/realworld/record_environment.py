"""Record what the scored run ran on: a hash of every stored repository snapshot and each tool's packages.

``python -m tools.benchmark.realworld.record_environment --manifest manifest.jsonl --corpus CORPUS
--tool-root TOOL_ROOT --out results/environment.json``

The manifest pins each upstream commit and tree hash; this records the snapshots *as stored and audited*
(symlinks neutralised), so that a re-run can check it is looking at the same bytes. Hashing reads the corpus
only. Package lists come from ``uv pip freeze`` for each virtual environment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any


def snapshot_hash(root: Path) -> str:
    """One SHA-256 over every file (relative path, size, bytes) and symlink (relative path, target)."""
    digest = hashlib.sha256()
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = Path(current) / name
            rel = str(path.relative_to(root)).encode()
            if path.is_symlink():
                digest.update(b"L\0" + rel + b"\0" + os.readlink(path).encode() + b"\0")
            else:
                data = path.read_bytes()
                digest.update(b"F\0" + rel + b"\0" + str(len(data)).encode() + b"\0" + data + b"\0")
    return digest.hexdigest()


def pip_freeze(venv: Path) -> list[str]:
    done = subprocess.run(
        ["uv", "pip", "freeze", "--python", str(venv / "bin" / "python")],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    return sorted(line.strip() for line in done.stdout.splitlines() if line.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = [
        json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    corpus = {row["id"]: snapshot_hash(args.corpus / row["dir"]) for row in rows}
    environments: dict[str, Any] = {
        venv.name: pip_freeze(venv) for venv in sorted((args.tool_root / "venvs").iterdir()) if venv.is_dir()
    }
    node = subprocess.run(["node", "--version"], capture_output=True, text=True, check=False).stdout.strip()
    document = {
        "corpus_sha256": corpus,
        "corpus_sha256_of_hashes": hashlib.sha256(json.dumps(corpus, sort_keys=True).encode()).hexdigest(),
        "python_environments": environments,
        "node": node,
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpus": os.cpu_count(),
        },
    }
    args.out.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(corpus)} snapshots and {len(environments)} environments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
