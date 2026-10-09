"""Bounded, non-recursive directory walking for the code scanner.

Shared by the filesystem connector's directory enumeration: a walk budget
that charges every retained or probed entry against ``max_entries`` and the
scan deadline, project-root marker detection, an iterative ``os.walk``
replacement that never follows links, and report-safe name handling for
paths that are not valid UTF-8.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from shadowscan.utils.files import open_confined_file

DEFAULT_MAX_WALK_ENTRIES = 1_000_000

# Entries inspected to decide whether a skipped directory holds any file.
_EMPTY_DIRECTORY_PROBE_ENTRIES = 256


PROJECT_ROOT_MARKERS = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "Pipfile",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "environment.yml",
}

# `setup.py` is also an ordinary module name (a package's `tracing/setup.py`,
# a web app's `controllers/setup.py`). It marks a project only when it builds
# a package; anything that cannot be read keeps the historical marker.
_SETUP_SCRIPT_MAX_BYTES = 256 * 1024
_PACKAGING_SETUP = re.compile(rb"\b(?:setuptools|distutils|skbuild)\b|(?<!def )(?<![.\w])setup\s*\(")


def _packaging_setup_script(path: Path, root: Path | None = None) -> bool:
    """Whether ``path`` packages a project; True when it cannot be read.

    A link that resolves inside ``root`` (the resolved scan root) is judged by
    its target's content, as a copy of the target would be; the target is
    opened at its real path without following a link in any component.
    """
    if root is not None and os.path.islink(path):
        try:
            target = path.resolve(strict=True)
        except (OSError, RuntimeError):
            return True
        if target != root and root not in target.parents:
            return True
        path = target
    try:
        with open_confined_file(path, label="setup.py") as (stream, _):
            head = stream.read(_SETUP_SCRIPT_MAX_BYTES)
    except (OSError, ValueError):
        return True
    return _PACKAGING_SETUP.search(head) is not None


def _marks_project(directory: Path, names: Iterable[str], root: Path | None = None) -> bool:
    """True when ``names`` in ``directory`` include a project manifest (``root``: _packaging_setup_script)."""
    return any(
        name in PROJECT_ROOT_MARKERS
        and (name != "setup.py" or _packaging_setup_script(directory / name, root))
        for name in names
    )


def _holds_file(directory: Path, budget: _WalkBudget | None = None) -> bool:
    """Whether a skipped ``directory`` holds anything that is not a directory.

    Probes at most ``_EMPTY_DIRECTORY_PROBE_ENTRIES`` entries without following
    a link (a link in place of the directory is not listed at all). A tree the
    probe cannot finish or cannot list counts as non-empty, so the omission is
    disclosed rather than assumed to be nothing.
    """
    try:
        if directory.is_symlink():
            return False
    except OSError:
        return True
    pending = [directory]
    inspected = 0
    budget = budget or _WalkBudget()
    while pending:
        budget.check()
        try:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    budget.count_entry()
                    inspected += 1
                    if inspected > _EMPTY_DIRECTORY_PROBE_ENTRIES or not entry.is_dir(follow_symlinks=False):
                        return True
                    pending.append(Path(entry.path))
        except OSError:
            return True
    return False


class _WalkLimitError(ValueError):
    """A bounded enumeration stopped; retain findings and report incomplete coverage."""


@dataclass
class _WalkBudget:
    """Bound retained directory names and all auxiliary listings within one source-tree scan."""

    maximum: int = DEFAULT_MAX_WALK_ENTRIES
    check_deadline: Callable[[], None] | None = None
    entries: int = 0

    def check(self) -> None:
        if self.check_deadline is not None:
            # Completion failures use the connector's single canonical error.
            # Only entry exhaustion is recoverable inside the directory walk.
            self.check_deadline()

    def count_entry(self) -> None:
        self.check()
        self.entries += 1
        if self.entries > self.maximum:
            raise _WalkLimitError(f"max_entries ({self.maximum}) reached during directory enumeration")


@dataclass
class _WalkCounters:
    """What one directory walk has examined so far, shared with its link checks."""

    examined: int = 0  # files and links counted toward max_files
    non_regular: int = 0  # entries named like analyzable content that are not regular files
    stop_at: float | None = None  # monotonic time after which link checks stop (deadline minus margin)
    budget: _WalkBudget = field(default_factory=_WalkBudget)
    # Files to analyze at the paths of the links just checked: (rel, real path, project, size).
    aliases: list[tuple[str, Path, str, int]] = field(default_factory=list)


def _walk_directories(
    top: Path, onerror: Callable[[OSError], None], *, budget: _WalkBudget | None = None
) -> Iterator[tuple[str, list[str], list[str]]]:
    """Walk ``top`` top-down like ``os.walk(top, followlinks=False, onerror=onerror)``, without recursion.

    ``os.walk`` recurses before Python 3.12, so a tree about a thousand directories
    deep ends in a RecursionError that discards every finding. This keeps its
    contract: a directory is yielded before its children, a link to a directory is
    listed in ``dirnames`` but never entered, the caller may prune or reorder
    ``dirnames`` in place, and a directory that cannot be listed is passed to
    ``onerror`` and skipped. Every name is charged before retention, including
    names the caller later excludes. The shared budget also checks cancellation
    and deadlines, and bounds auxiliary coverage probes.
    """
    stack = [os.fspath(top)]
    budget = budget or _WalkBudget()
    while stack:
        budget.check()
        current = stack.pop()
        dirs: list[str] = []
        files: list[str] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    budget.count_entry()
                    try:
                        is_dir = entry.is_dir()
                    except OSError:
                        is_dir = False
                    (dirs if is_dir else files).append(entry.name)
        except OSError as error:
            onerror(error)
            continue
        yield current, dirs, files
        for name in reversed(dirs):
            budget.check()
            child = os.path.join(current, name)
            if not os.path.islink(child):
                stack.append(child)


def _report_name(name: str) -> str:
    """A report-safe form of a path or path component read from disk.

    ``os.walk`` returns the bytes of a name that is not UTF-8 as lone surrogates,
    which no reporter can encode: each becomes a ``\\xNN`` escape. Valid names are
    returned unchanged; I/O keeps using the ``Path`` that holds the on-disk name.
    """
    if name.isascii():
        return name
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        try:
            raw = name.encode("utf-8", errors="surrogateescape")
        except UnicodeEncodeError:
            raw = name.encode("utf-8", errors="backslashreplace")
        return raw.decode("utf-8", errors="backslashreplace")
    return name


def _nearest_root(rel_dir: str, roots: list[str]) -> str:
    """Discard completed branches from the active root stack during the walk."""
    while len(roots) > 1 and rel_dir != roots[-1] and not rel_dir.startswith(roots[-1] + "/"):
        roots.pop()
    return roots[-1]
