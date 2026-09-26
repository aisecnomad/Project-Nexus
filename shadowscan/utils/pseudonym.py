"""Operator-held key for pseudonyms that stay stable across scans.

By default gateway caller and scope pseudonyms use a random key per scan, so
reports cannot be linked and gateway findings are not comparable between runs.
An operator who needs to track the same caller over time can supply a private
key file. The key itself never enters configuration dumps or reports: only a
short key identifier derived from it does, so reports made with different keys
are never treated as comparable.
"""

from __future__ import annotations

import hmac
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

ENV_VAR = "SHADOWSCAN_PSEUDONYMIZATION_KEY_FILE"
MIN_SECRET_BYTES = 32
MAX_KEY_FILE_BYTES = 4096


class PseudonymKeyError(ValueError):
    """The configured pseudonymization key file is unusable."""


@dataclass(frozen=True, slots=True)
class PseudonymKey:
    key: bytes = field(repr=False)
    key_id: str

    def subkey(self, purpose: str) -> bytes:
        """An independent key for one use, so pseudonym families cannot be cross-matched."""
        return hmac.digest(self.key, f"shadowscan.pseudonym.{purpose}.v1".encode(), "sha256")


def configured_key_file(configured: str | None) -> str | None:
    """The configured key file, else the environment variable, else None."""
    return configured or os.environ.get(ENV_VAR) or None


def load_pseudonymization_key(path: str | os.PathLike[str]) -> PseudonymKey:
    """Read a private key file: a regular file, not a symlink, owner-only on POSIX."""
    p = Path(path)
    try:
        info = os.lstat(p)
    except OSError as exc:
        raise PseudonymKeyError(f"pseudonymization key file is unreadable ({type(exc).__name__})") from None
    if stat.S_ISLNK(info.st_mode):
        raise PseudonymKeyError("pseudonymization key file must not be a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise PseudonymKeyError("pseudonymization key file must be a regular file")
    if os.name == "posix" and info.st_mode & 0o077:
        raise PseudonymKeyError("pseudonymization key file must be accessible only by its owner (chmod 600)")
    if info.st_size > MAX_KEY_FILE_BYTES:
        raise PseudonymKeyError(f"pseudonymization key file exceeds {MAX_KEY_FILE_BYTES} bytes")
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(MAX_KEY_FILE_BYTES + 1)
    except OSError as exc:
        raise PseudonymKeyError(f"pseudonymization key file is unreadable ({type(exc).__name__})") from None
    secret = raw.strip()
    if len(raw) > MAX_KEY_FILE_BYTES or len(secret) < MIN_SECRET_BYTES:
        raise PseudonymKeyError(f"pseudonymization key file must hold {MIN_SECRET_BYTES} to {MAX_KEY_FILE_BYTES} bytes of secret material")
    key = hmac.digest(secret, b"shadowscan.pseudonymization.v1", "sha256")
    key_id = hmac.digest(key, b"shadowscan.pseudonymization.key-id.v1", "sha256").hex()[:16]
    return PseudonymKey(key=key, key_id=key_id)
