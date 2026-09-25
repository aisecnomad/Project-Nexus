"""Bounded, symlink-free regular-file access for local policy, report and offline inputs."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from fnmatch import fnmatchcase
from pathlib import Path
from typing import BinaryIO

MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_POLICY_FILES = 10_000
_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")


class NotRegularFileError(ValueError):
    """A confined open reached a directory, FIFO, socket or device instead of a regular file."""


def require_no_symlinks(path: Path) -> Path:
    """Reject explicit inputs that traverse a symlink, including parent links."""
    absolute = Path(os.path.abspath(path))
    for part in (*reversed(absolute.parents), absolute):
        if part.is_symlink():
            raise ValueError("policy input must not traverse symbolic links")
    return absolute


def policy_files(root: Path, suffixes: set[str]) -> Iterator[Path]:
    """Walk a policy directory without following links or special files."""
    root = require_no_symlinks(root)
    if not root.is_dir():
        raise FileNotFoundError(f"policy directory not found: {root}")
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        count += len(dirs)
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            count += 1
            if count > MAX_POLICY_FILES:
                raise ValueError("policy directory exceeds file limit")
            path = Path(directory) / name
            if path.suffix.lower() not in suffixes or path.is_symlink():
                continue
            if stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
                yield path


def policy_glob(pattern: Path) -> Iterator[Path]:
    """Expand glob components without recursive glob's symlink traversal."""
    absolute = Path(os.path.abspath(pattern))
    components = absolute.parts[1:]
    stack = [(Path(absolute.anchor), 0)]
    seen: set[tuple[Path, int]] = set()
    examined = 0
    while stack:
        parent, position = stack.pop()
        if (parent, position) in seen:
            continue
        seen.add((parent, position))
        examined += 1
        if examined > MAX_POLICY_FILES:
            raise ValueError("inventory glob exceeds entry limit")
        if parent.is_symlink():
            continue
        if position == len(components):
            if parent.is_file():
                yield parent
            continue
        if not parent.is_dir():
            continue
        pattern_part = components[position]
        if pattern_part != "**" and not any(ch in pattern_part for ch in "*?["):
            stack.append((parent / pattern_part, position + 1))
            continue
        if pattern_part == "**":
            stack.append((parent, position + 1))
        with os.scandir(parent) as entries:
            for entry in entries:
                examined += 1
                if examined > MAX_POLICY_FILES:
                    raise ValueError("inventory glob exceeds entry limit")
                if entry.is_symlink():
                    continue
                if pattern_part == "**":
                    if entry.is_dir(follow_symlinks=False):
                        stack.append((Path(entry.path), position))
                elif fnmatchcase(entry.name, pattern_part):
                    stack.append((Path(entry.path), position + 1))


@contextmanager
def open_confined_file(path: Path, *, label: str = "input") -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open a regular file for reading without following a link in any path component.

    Every directory component of the absolute path is opened relative to its
    parent with ``O_NOFOLLOW`` and ``O_DIRECTORY``, so a component swapped for
    a symlink after an earlier check cannot redirect the open. The final
    component is opened with ``O_NONBLOCK`` so a FIFO put in its place cannot
    block before the descriptor is inspected, and the descriptor is rejected
    with :class:`NotRegularFileError` unless ``fstat`` reports a regular file.
    ``..`` components are not collapsed: callers normalise the path the way
    their surrounding checks expect, and a link anywhere in it is refused.

    The binary stream and the ``fstat`` result of its descriptor are yielded
    together. Byte limits stay with the caller because the readers built on
    this helper bound their input differently on purpose: the policy reader
    rejects a file larger than one fixed cap before reading it; the whole-file
    offline reader rejects a file larger than the smallest of its per-file cap
    and the remaining aggregate budget; the line-oriented offline reader checks
    only the per-file cap up front and charges the aggregate budget line by
    line, so records that precede the limit are still yielded. Each caller
    calls :func:`changed_since` at the point where it accounts for the bytes it
    read, so a file rewritten mid-read is reported after its size accounting.

    Raises ``ValueError`` when the platform lacks ``O_NOFOLLOW`` or ``dir_fd``
    support, because the walk cannot then be made safe. ``OSError`` propagates
    unchanged and may name the path, so diagnostics must not echo it.
    """
    if (
        not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
        or os.open not in os.supports_dir_fd
    ):
        raise ValueError("secure file access is unavailable on this platform")
    absolute = Path(path).absolute()
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fd: int | None = None
    directory = os.open(absolute.anchor, flags | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:-1]:
            child = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(absolute.name, flags | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise NotRegularFileError(f"{label} is not a regular file")
        stream = os.fdopen(fd, "rb")
        fd = None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
    with stream:
        yield stream, before


def changed_since(before: os.stat_result, fd: int) -> bool:
    """Report whether the file behind ``fd`` was resized or rewritten since ``before`` was taken."""
    after = os.fstat(fd)
    return any(getattr(before, field) != getattr(after, field) for field in _IDENTITY_FIELDS)


def read_policy_text(path: Path, max_bytes: int = MAX_POLICY_BYTES) -> str:
    """Open each path component without following links; cap allocation before decoding."""
    with open_confined_file(Path(os.path.abspath(path)), label="policy input") as (stream, before):
        if before.st_size > max_bytes:
            raise ValueError("policy input exceeds byte limit")
        data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("policy input exceeds byte limit")
        if changed_since(before, stream.fileno()):
            raise ValueError("policy input changed while reading")
        return data.decode("utf-8")
