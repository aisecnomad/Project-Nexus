"""Atomic, owner-readable output files for sensitive scan artifacts."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from shadowscan.utils.files import require_no_symlinks


def prepare_private_directory(path: str | Path) -> Path:
    """Create private storage without changing permissions on an existing directory."""
    target = require_no_symlinks(Path(path).expanduser())
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError("output directory must be owned by the current user with private mode 0700")
    finally:
        os.close(fd)
    return target


def write_private_text(path: str | Path, text: str) -> None:
    """Replace an output atomically without following an existing file symlink.

    The parent directory is chosen by the trusted operator. A temporary file in
    that directory is created with mode 0600, including when replacing a more
    permissive report. Failed writes leave the previous report intact.
    """
    target = Path(path)
    if target.is_symlink():
        raise ValueError("refusing a symlink output file")
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
