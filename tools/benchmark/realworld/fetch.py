"""Fetch one repository snapshot into its own directory, treating all of it as untrusted data.

Only anonymous ``git`` reads of public repositories are used (no API tokens, no
credentials). Nothing in the snapshot is ever executed: hooks are disabled, Git
LFS and submodules are not fetched, ``.git`` is removed after checkout, and every
symlink that is absolute, dangling, cyclic or physically resolves outside the snapshot
is replaced by a one-line text file so that no tool can be steered to read host files
or special devices.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 150 * 1024 * 1024
MAX_FILES = 25_000
GIT_TIMEOUT_S = 300
SOURCE_EXTS = frozenset(
    {".py", ".ipynb", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".scala",
     ".cs", ".rb", ".php", ".swift", ".dart", ".c", ".h", ".cpp", ".cc", ".lua", ".sh", ".ex", ".r", ".jl"}
)  # fmt: skip

SAFE_GIT = [
    "git",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "advice.detachedHead=false",
    "-c", "credential.helper=",
]  # fmt: skip


class FetchError(Exception):
    """A snapshot could not be fetched or is not eligible; ``reason`` is a short slug."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class Snapshot:
    sha: str
    tree: str
    files: int
    source_files: int
    bytes: int
    symlinks: int
    symlinks_neutralized: int


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "true", "LC_ALL": "C.UTF-8"}
    )
    return env


def _run(
    args: list[str], cwd: Path | None = None, timeout: int = GIT_TIMEOUT_S
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*SAFE_GIT, *args],
        cwd=cwd,
        env=_git_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def ls_remote_head(url: str) -> str | None:
    """Return the full SHA of the remote HEAD, or None when the repository is unreachable."""
    for attempt in range(2):
        try:
            proc = _run(["ls-remote", url, "HEAD"], timeout=90)
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode == 0 and proc.stdout.strip():
            sha = proc.stdout.split()[0]
            return sha if len(sha) == 40 else None
        if "429" in proc.stderr and attempt == 0:
            time.sleep(5)
            continue
        return None
    return None


def _symlink_escapes(path: Path, root_real: str) -> bool:
    """True when the link must be removed: absolute, dangling, cyclic, or physically outside ``root_real``.

    Resolution is physical (``realpath`` follows every other link on the way), never lexical: a lexical
    check accepts ``l1 -> sub/l2/../..`` when ``sub/l2 -> ..``, although the kernel resolves it two levels
    above the snapshot.
    """
    target = os.readlink(path)
    if os.path.isabs(target):
        return True
    resolved = os.path.realpath(path, strict=False)
    if not (resolved == root_real or resolved.startswith(root_real + os.sep)):
        return True
    if not os.path.lexists(resolved):
        return True  # dangling, or resolution stopped at a non-directory
    parent = os.path.realpath(path.parent)
    return parent == resolved or parent.startswith(resolved + os.sep)  # points at an ancestor: a cycle


def _neutralize_symlinks(root: Path) -> tuple[int, int]:
    """Replace every symlink that is not provably inside ``root`` with a one-line text file.

    Repeats until no link changes: removing a link can only shorten what other links resolve to, so the
    loop ends, and the survivors all resolve to a path inside the snapshot that is not an ancestor of
    the link.
    """
    root_real = os.path.realpath(root)
    total = 0
    neutralized = 0
    first = True
    changed = True
    while changed:
        changed = False
        for current, dirs, files in os.walk(root, followlinks=False):
            for name in [*dirs, *files]:
                path = Path(current) / name
                if not path.is_symlink():
                    continue
                if first:
                    total += 1
                if not _symlink_escapes(path, root_real):
                    continue
                target = os.readlink(path)
                path.unlink()
                path.write_text(
                    f"symlink outside the snapshot was removed by the benchmark: {target}\n", encoding="utf-8"
                )
                neutralized += 1
                changed = True
        first = False
    return total, neutralized


def _normalize_modes_and_count(root: Path) -> tuple[int, int, int]:
    files = source_files = size = 0
    for current, _dirs, names in os.walk(root, followlinks=False):
        os.chmod(current, 0o755)
        for name in names:
            path = Path(current) / name
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                path.unlink()
                continue
            os.chmod(path, 0o755 if st.st_mode & stat.S_IXUSR else 0o644)
            files += 1
            size += st.st_size
            source_files += path.suffix.lower() in SOURCE_EXTS
        if files > MAX_FILES or size > MAX_BYTES:
            break
    return files, source_files, size


def fetch_snapshot(url: str, dest: Path, sha: str | None = None, *, require_code: bool = True) -> Snapshot:
    """Check out ``sha`` (default: remote HEAD) of ``url`` into the new directory ``dest``."""
    if dest.exists():
        raise FetchError("destination-exists", str(dest))
    dest.mkdir(parents=True)
    try:
        want = sha or ls_remote_head(url)
        if not want:
            raise FetchError("unreachable")
        steps = [
            ["init", "-q"],
            ["remote", "add", "origin", url],
            ["fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", want],
            ["checkout", "-q", "--detach", "FETCH_HEAD"],
        ]
        for step in steps:
            for attempt in range(2):
                proc = _run(step, cwd=dest)
                if proc.returncode == 0:
                    break
                if step[0] == "fetch" and "429" in proc.stderr and attempt == 0:
                    time.sleep(5)
                    continue
                raise FetchError(f"git-{step[0]}-failed", proc.stderr.strip()[-200:])
        head = _run(["rev-parse", "HEAD"], cwd=dest).stdout.strip()
        tree = _run(["rev-parse", "HEAD^{tree}"], cwd=dest).stdout.strip()
        shutil.rmtree(dest / ".git")
        total_links, neutralized = _neutralize_symlinks(dest)
        files, source_files, size = _normalize_modes_and_count(dest)
        if files > MAX_FILES:
            raise FetchError("too-many-files", str(files))
        if size > MAX_BYTES:
            raise FetchError("too-large", str(size))
        if files < 3:
            raise FetchError("too-small", str(files))
        if require_code and source_files < 1:
            raise FetchError("no-source-files")
        return Snapshot(head, tree, files, source_files, size, total_links, neutralized)
    except subprocess.TimeoutExpired as exc:
        raise FetchError("timeout", str(exc.timeout)) from exc
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
