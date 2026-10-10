"""Reproducible checkouts: fetch each corpus repository at its pinned commit.

Only ``git`` runs here. Hooks are not installed by a fresh fetch and no
repository content is executed. Checkouts are detached at the pinned commit
so a later push to the default branch cannot change the benchmark input.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from tools.discovery_benchmark.corpus import Corpus, Repo

GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "0"}


class FetchError(RuntimeError):
    """A repository could not be fetched at its pinned commit."""


def _git(args: list[str], cwd: Path | None, timeout: int) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **GIT_ENV}
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def head_commit(checkout: Path) -> str:
    result = _git(["rev-parse", "HEAD"], checkout, 60)
    if result.returncode != 0:
        raise FetchError(f"{checkout}: not a git checkout ({result.stderr.strip()})")
    return result.stdout.strip()


def fetch_repo(repo: Repo, dest: Path, *, timeout: int = 900) -> str:
    """Fetch ``repo`` at its pinned commit into ``dest`` and return HEAD.

    The pinned commit is requested directly (depth 1). Hosts that refuse an
    unadvertised commit fall back to a shallow clone of the default branch,
    which only succeeds when that branch still points at the pinned commit.
    """
    if dest.exists():
        if head_commit(dest) == repo.commit:
            return repo.commit
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    init = _git(["init", "-q"], dest, 60)
    if init.returncode != 0:
        raise FetchError(f"{repo.id}: git init failed: {init.stderr.strip()}")
    _git(["remote", "add", "origin", repo.url], dest, 60)
    fetched = _git(["fetch", "-q", "--depth", "1", "origin", repo.commit], dest, timeout)
    if fetched.returncode == 0:
        checkout = _git(["checkout", "-q", "--detach", "FETCH_HEAD"], dest, timeout)
        if checkout.returncode != 0:
            raise FetchError(f"{repo.id}: checkout failed: {checkout.stderr.strip()}")
    else:
        shutil.rmtree(dest)
        clone = _git(
            [
                "clone",
                "-q",
                "--depth",
                "1",
                "--single-branch",
                "--branch",
                repo.default_branch,
                repo.url,
                str(dest),
            ],
            None,
            timeout,
        )
        if clone.returncode != 0:
            raise FetchError(
                f"{repo.id}: fetch by commit and clone both failed: {clone.stderr.strip()[:300]}"
            )
    actual = head_commit(dest)
    if actual != repo.commit:
        raise FetchError(f"{repo.id}: HEAD {actual} is not the pinned commit {repo.commit}")
    return actual


def fetch_all(corpus: Corpus, root: Path, *, timeout: int = 900) -> dict[str, str]:
    """Fetch every repository under ``root/<repo id>``; errors are collected, not raised."""
    outcome: dict[str, str] = {}
    for repo in corpus.repos:
        try:
            outcome[repo.id] = fetch_repo(repo, root / repo.id, timeout=timeout)
        except (FetchError, subprocess.TimeoutExpired) as exc:
            outcome[repo.id] = f"ERROR: {exc}"
    return outcome


def verify_all(corpus: Corpus, root: Path) -> dict[str, str]:
    """Report, per repository, whether an existing checkout is at the pinned commit."""
    outcome: dict[str, str] = {}
    for repo in corpus.repos:
        checkout = root / repo.id
        if not checkout.exists():
            outcome[repo.id] = "MISSING"
            continue
        try:
            actual = head_commit(checkout)
        except FetchError as exc:
            outcome[repo.id] = f"ERROR: {exc}"
            continue
        outcome[repo.id] = "OK" if actual == repo.commit else f"MISMATCH: {actual}"
    return outcome
