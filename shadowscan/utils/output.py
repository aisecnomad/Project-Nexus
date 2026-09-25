"""Atomic, owner-readable output files for sensitive scan artifacts."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from shadowscan.utils.files import require_no_symlinks


def terminal_text(value: object) -> str:
    """Display untrusted values without executing terminal control sequences.

    Rich's Text/markup=False prevents markup interpretation but still passes
    through ANSI escape sequences. Render control and bidi-formatting characters
    visibly so repository names, evidence and diagnostics cannot alter terminal
    state or conceal/reorder a report. Call before adding intentional newlines.
    """
    out = []
    for char in str(value):
        code = ord(char)
        if code < 32 or 0x7F <= code <= 0x9F or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069 or code in (0x061C, 0x200E, 0x200F, 0x2028, 0x2029):
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    return "".join(out)


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
