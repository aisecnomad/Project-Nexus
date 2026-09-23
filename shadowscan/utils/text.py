"""Text helpers: redaction, safe file reading, small parsers."""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_BINARY_SNIFF = 8192


def redact(value: str, keep: int = 4) -> str:
    """Redact a secret keeping a short prefix/suffix for correlation."""
    if not value:
        return value
    if len(value) <= keep * 2 + 3:
        return "*" * len(value)
    return f"{value[:keep]}…{value[-keep:]}"


def redact_in_text(text: str, patterns: list[re.Pattern[str]]) -> str:
    for rx in patterns:
        text = rx.sub(lambda m: redact(m.group(0)), text)
    return text


def is_probably_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(_BINARY_SNIFF)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    return False


def read_text(path: Path, max_bytes: int, errors: list[str] | None = None) -> str | None:
    """Read a bounded regular file without following its final symlink.

    Validate the opened descriptor, not a separate stat result: the file may
    change between directory traversal and reading. Binary inputs are ignored;
    limits and I/O failures are reported to callers that track completeness.
    """
    try:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as fh:
            info = os.fstat(fh.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("not a regular file")
            if info.st_size > max_bytes:
                raise ValueError("file exceeds max_file_size")
            raw = fh.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("file exceeds max_file_size")
        if b"\x00" in raw[:_BINARY_SNIFF]:
            return None
        return raw.decode("utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        if errors is not None:
            # Do not embed raw file contents or exception messages in reports.
            errors.append(str(exc) if isinstance(exc, ValueError) else "file could not be read")
        return None


def notebook_to_source(text: str, errors: list[str] | None = None) -> str:
    """Extract code cells from a Jupyter notebook as a python source blob."""
    try:
        nb = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        if errors is not None:
            errors.append("notebook contains invalid JSON")
        return ""
    if not isinstance(nb, dict) or not isinstance(nb.get("cells", []), list):
        if errors is not None:
            errors.append("notebook cells must be an array")
        return ""
    out: list[str] = []
    for cell in nb.get("cells", []):
        if not isinstance(cell, dict):
            if errors is not None:
                errors.append("notebook cell must be an object")
            continue
        if cell.get("cell_type") != "code":
            continue
        src = cell.get("source", "")
        if isinstance(src, list):
            if not all(isinstance(part, str) for part in src):
                if errors is not None:
                    errors.append("notebook source array must contain strings")
                continue
            src = "".join(src)
        if not isinstance(src, str):
            if errors is not None:
                errors.append("notebook source must be text or an array of strings")
            continue
        out.append(src)
    return "\n".join(out)


def excerpt_line(text: str, line: int, width: int = 160) -> str:
    """Return the given 1-indexed line trimmed to width."""
    try:
        s = text.splitlines()[line - 1]
    except IndexError:
        return ""
    s = s.strip()
    return s if len(s) <= width else s[: width - 1] + "…"


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing (ISO 8601, epoch seconds / millis)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:
            v /= 1000.0
        try:
            return datetime.fromtimestamp(v, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if s.isdigit():
        return parse_timestamp(int(s))
    s = s.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def to_iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat() if dt else None


def flatten(d: Any, prefix: str = "", out: dict[str, Any] | None = None) -> dict[str, Any]:
    """Flatten nested dicts/lists into dotted keys (for schema sniffing of logs)."""
    if out is None:
        out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{prefix}{k}"
            if isinstance(v, (dict, list)):
                flatten(v, key + ".", out)
            else:
                out[key] = v
    elif isinstance(d, list):
        for i, v in enumerate(d[:50]):
            key = f"{prefix}{i}"
            if isinstance(v, (dict, list)):
                flatten(v, key + ".", out)
            else:
                out[key] = v
    return out


def get_path(d: dict[str, Any], *paths: str, default: Any = None) -> Any:
    """Return the first present value among dotted paths."""
    for path in paths:
        cur: Any = d
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return default


def truncate(s: str | None, n: int = 200) -> str | None:
    if s is None:
        return None
    return s if len(s) <= n else s[: n - 1] + "…"


_HOST_IN_URL = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?([^/:?#]+)(?::\d+)?", re.IGNORECASE)


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    m = _HOST_IN_URL.match(url.strip())
    return m.group(1).lower() if m else None
