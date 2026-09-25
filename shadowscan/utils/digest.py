"""Content digests of the scanner's own source tree.

Collection-scope fingerprints and incremental cache keys both attest which
scanner code produced a result. They share one digest so a report comparison
and a cache lookup agree on what "same scanner" means.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True).encode()


def scanner_source_digest(package: Path | None = None) -> str:
    """Return a SHA-256 over every Python source file of the scanner package.

    The digest covers file contents and package-relative paths only. It is
    stable across installations of identical code, which is what a report
    comparison needs, and it changes with any source edit, which is what the
    incremental cache needs. Read errors propagate as ``OSError`` so callers
    fail closed.
    """
    root = package if package is not None else Path(__file__).parent.parent
    entries = [
        [path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()]
        for path in sorted(root.rglob("*.py"))
        if path.is_file()
    ]
    return hashlib.sha256(_canonical(entries)).hexdigest()
