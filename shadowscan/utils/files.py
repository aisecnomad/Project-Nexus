"""Bounded, regular-file reads for local policy and approval inputs."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from fnmatch import fnmatchcase
from pathlib import Path

MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_POLICY_FILES = 10_000


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


def read_policy_text(path: Path, max_bytes: int = MAX_POLICY_BYTES) -> str:
    """Open each path component without following links; cap allocation before decoding."""
    absolute = Path(os.path.abspath(path))
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    directory = os.open(absolute.anchor, directory_flags)
    try:
        for component in absolute.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(absolute.name, os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("policy input must be a regular file")
            if before.st_size > max_bytes:
                raise ValueError("policy input exceeds byte limit")
            data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("policy input exceeds byte limit")
            after = os.fstat(stream.fileno())
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, field) != getattr(after, field) for field in fields):
                raise ValueError("policy input changed while reading")
            return data.decode("utf-8")
    finally:
        os.close(directory)
