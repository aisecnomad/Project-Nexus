"""Bounded, symlink-free regular-file access for local policy, report and offline inputs."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from fnmatch import fnmatchcase
from pathlib import Path, PurePath
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


SKIPPED_LINK = "symbolic link"
SKIPPED_UNSUPPORTED = "unsupported file type"


def policy_files(
    root: Path, suffixes: set[str], skipped: list[tuple[str, str]] | None = None
) -> Iterator[Path]:
    """Walk a policy directory without following links or special files.

    When ``skipped`` is given, each entry passed over is appended to it as
    ``(path relative to root, reason)``: a symbolic link (``SKIPPED_LINK``)
    or a file without a supported suffix or that is not a regular file
    (``SKIPPED_UNSUPPORTED``). Only names are recorded, never contents.
    """
    root = require_no_symlinks(root)
    if not root.is_dir():
        raise FileNotFoundError(f"policy directory not found: {root}")

    def walk_error(error: OSError) -> None:
        # An unreadable subtree must not silently erase policies from a scan.
        # Keep paths from the OS error out of operator-visible diagnostics.
        raise ValueError("policy directory could not be read") from None

    notes = skipped if skipped is not None else []
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        count += len(dirs)
        if count > MAX_POLICY_FILES:
            raise ValueError("policy directory exceeds file limit")
        base = Path(directory)
        notes += [
            ((base / d).relative_to(root).as_posix(), SKIPPED_LINK) for d in dirs if (base / d).is_symlink()
        ]
        dirs[:] = sorted(d for d in dirs if not (base / d).is_symlink())
        for name in sorted(files):
            count += 1
            if count > MAX_POLICY_FILES:
                raise ValueError("policy directory exceeds file limit")
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                notes.append((relative, SKIPPED_LINK))
            elif path.suffix.lower() in suffixes and stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
                yield path
            else:
                notes.append((relative, SKIPPED_UNSUPPORTED))


def policy_glob(pattern: Path, skipped_links: list[str] | None = None) -> Iterator[Path]:
    """Expand glob components without recursive glob's symlink traversal.

    When ``skipped_links`` is given, each symbolic link the pattern would
    otherwise have entered or matched is appended to it once, by path.
    """
    links = skipped_links if skipped_links is not None else []
    noted: set[str] = set()
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
            if str(parent) not in noted:
                noted.add(str(parent))
                links.append(str(parent))
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
                    if (
                        pattern_part == "**" or fnmatchcase(entry.name, pattern_part)
                    ) and entry.path not in noted:
                        noted.add(entry.path)
                        links.append(entry.path)
                    continue
                if pattern_part == "**":
                    if entry.is_dir(follow_symlinks=False):
                        stack.append((Path(entry.path), position))
                elif fnmatchcase(entry.name, pattern_part):
                    stack.append((Path(entry.path), position + 1))


def _require_confined_open() -> None:
    if (
        not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
        or os.open not in os.supports_dir_fd
    ):
        raise ValueError("secure file access is unavailable on this platform")


def _traversal_flags() -> int:
    """Return the flags that open a directory only to look up names below it.

    ``O_PATH`` (Linux) needs search permission alone, as opening a file by its
    path does, so a traverse-only ancestor such as a mode 0711 home directory
    does not stop the walk. With ``O_NOFOLLOW`` and ``O_DIRECTORY`` a link is
    still refused (``ENOTDIR``). Without ``O_PATH`` the directory is opened
    for reading, which also needs read permission.
    """
    return getattr(os, "O_PATH", os.O_RDONLY) | os.O_NOFOLLOW | os.O_DIRECTORY


def open_confined_directory(path: PurePath) -> int:
    """Open a directory without following a link in any component of its absolute path.

    Returns a descriptor the caller must close. Files below the directory are
    then opened with :func:`open_confined_file` and ``dir_fd``, which walks
    only their components relative to it, so a directory tree is confined to
    the root opened here without reopening its ancestors for every file.
    Every component, the directory itself included, is opened only for
    traversal (:func:`_traversal_flags`): the descriptor serves to anchor
    those opens, not to list the directory, and like an open by path they
    need search, not read, permission on the directory and its ancestors.
    Without ``O_PATH`` but with ``O_NOFOLLOW_ANY`` (macOS), the kernel opens
    the whole path in one call and fails with ``ELOOP`` at the first link in
    any component, the last one included, so the ancestors still need only
    search permission; the directory itself is opened for reading. XNU
    rejects ``O_NOFOLLOW`` alongside that flag (``EINVAL``), and it adds
    nothing there. Raises ``ValueError`` like :func:`open_confined_file`;
    ``OSError`` propagates unchanged and may name the path.
    """
    _require_confined_open()
    absolute = Path(path).absolute()
    nofollow_any = getattr(os, "O_NOFOLLOW_ANY", 0)
    if nofollow_any and not hasattr(os, "O_PATH"):
        return os.open(absolute, os.O_RDONLY | nofollow_any | os.O_DIRECTORY)
    flags = _traversal_flags()
    directory = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=directory)
            os.close(directory)
            directory = child
    except BaseException:
        os.close(directory)
        raise
    return directory


@contextmanager
def open_confined_file(
    path: PurePath,
    *,
    label: str = "input",
    dir_fd: int | None = None,
) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open a regular file for reading without following a link in any path component.

    Every directory component of the absolute path is opened relative to its
    parent with ``O_NOFOLLOW`` and ``O_DIRECTORY``, so a component swapped for
    a symlink after an earlier check cannot redirect the open. Directories are
    opened only for traversal (:func:`_traversal_flags`), so like an ordinary
    open by path this needs search, not read, permission on them. The final
    component is opened with ``O_NONBLOCK`` so a FIFO put in its place cannot
    block before the descriptor is inspected, and the descriptor is rejected
    with :class:`NotRegularFileError` unless ``fstat`` reports a regular file.
    ``..`` components are not collapsed: callers normalise the path the way
    their surrounding checks expect, and a link anywhere in it is refused.

    With ``dir_fd``, ``path`` is relative to that open directory (see
    :func:`open_confined_directory`), which stays open and owned by the
    caller. Only the components below it are opened, the same way, and a
    path that is absolute, empty or contains ``..`` is refused with
    ``ValueError`` because it could leave that directory.

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
    _require_confined_open()
    traversal = _traversal_flags()
    if dir_fd is None:
        absolute = Path(path).absolute()
        components, name = absolute.parts[1:-1], absolute.name
        directory, owned = os.open(absolute.anchor, traversal), True
    else:
        parts = PurePath(path).parts
        if not parts or PurePath(path).is_absolute() or ".." in parts:
            raise ValueError(f"{label} path must stay below its directory")
        components, name = parts[:-1], parts[-1]
        directory, owned = dir_fd, False
    fd: int | None = None
    try:
        for component in components:
            child = os.open(component, traversal, dir_fd=directory)
            if owned:
                os.close(directory)
            directory, owned = child, True
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise NotRegularFileError(f"{label} is not a regular file")
        stream = os.fdopen(fd, "rb")
        fd = None
    finally:
        if fd is not None:
            os.close(fd)
        if owned:
            os.close(directory)
    with stream:
        yield stream, before


def changed_since(before: os.stat_result, fd: int) -> bool:
    """Report whether the file behind ``fd`` was resized or rewritten since ``before`` was taken."""
    after = os.fstat(fd)
    return any(getattr(before, field) != getattr(after, field) for field in _IDENTITY_FIELDS)


def read_policy_text(path: Path, max_bytes: int = MAX_POLICY_BYTES) -> str:
    """Open each path component without following links; cap allocation before decoding.

    A leading UTF-8 byte-order mark is dropped: spreadsheet "CSV UTF-8" and
    some editors' JSON exports start with one.
    """
    with open_confined_file(Path(os.path.abspath(path)), label="policy input") as (stream, before):
        if before.st_size > max_bytes:
            raise ValueError("policy input exceeds byte limit")
        data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("policy input exceeds byte limit")
        if changed_since(before, stream.fileno()):
            raise ValueError("policy input changed while reading")
        return data.decode("utf-8-sig")
