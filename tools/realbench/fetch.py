"""Rebuild the corpus checkouts at their pinned commits.

``python -m tools.realbench.fetch --manifest tools/realbench/corpus.json --output DIR``

Each repository is fetched at its recorded commit with ``--depth 1`` (GitHub
and GitLab serve reachable commits by SHA), and its tree hash is checked
against the manifest so a rewritten history cannot pass silently. Checkouts
are untrusted data: nothing in them is executed, and Git LFS smudging is off.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _git(args: list[str], cwd: Path, timeout: int = 600) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=True
    ).stdout.strip()


def fetch(repo: dict[str, Any], dest: Path) -> str:
    """Return ``ok``, ``exists`` or an error description."""
    if dest.exists():
        try:
            if _git(["rev-parse", "HEAD^{tree}"], dest) == repo["tree"]:
                return "exists"
        except (subprocess.CalledProcessError, OSError):
            pass
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        _git(["init", "--quiet"], dest)
        _git(["fetch", "--quiet", "--depth", "1", "--no-tags", repo["url"], repo["sha"]], dest)
        _git(["-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD"], dest)
        tree = _git(["rev-parse", "HEAD^{tree}"], dest)
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        return f"fetch failed: {(exc.stderr or '').strip()[-200:]}"
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        return "fetch timed out"
    if tree != repo["tree"]:
        return f"tree mismatch: expected {repo['tree']}, got {tree}"
    return "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ids", default="", help="comma-separated subset")
    args = parser.parse_args(argv)
    repos = json.loads(args.manifest.read_text(encoding="utf-8"))["repos"]
    wanted = set(filter(None, args.ids.split(",")))
    failures = 0
    for repo in repos:
        if wanted and repo["id"] not in wanted:
            continue
        status = fetch(repo, args.output / repo["id"])
        failures += status not in ("ok", "exists")
        print(f"{repo['id']} {status} {repo['url']}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
