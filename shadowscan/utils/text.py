"""Text helpers: redaction, safe file reading and small parsers."""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from shadowscan.utils.files import NotRegularFileError, open_confined_file
from shadowscan.utils.redaction import credential_id
from shadowscan.utils.safe_json import strict_json_loads

_BINARY_SNIFF = 8192
# Epoch seconds or milliseconds, optionally fractional (nginx $msec, Kong).
_EPOCH_RX = re.compile(r"\d{1,19}(?:\.\d{1,9})?")


def redact(value: str, keep: int = 4) -> str:
    """Return a stable opaque credential identity without retaining raw fragments.

    ``keep`` remains accepted for compatibility with older call sites, but no
    prefix or suffix is kept. New code should call ``credential_id`` directly.
    """
    del keep
    if not value:
        return value
    return credential_id(value)


def read_text(
    path: PurePath,
    max_bytes: int,
    errors: list[str] | None = None,
    *,
    dir_fd: int | None = None,
) -> str | None:
    """Read a bounded regular file without following a symlink in any path component.

    With ``dir_fd``, ``path`` is relative to that open directory, normally the
    scan root, and only the components below it are opened; otherwise the
    whole absolute path is. Each directory is opened with ``O_NOFOLLOW``
    relative to its parent (:func:`open_confined_file`), so a directory swapped
    for a link between directory traversal and reading fails the read instead
    of redirecting it outside the tree. Validate the opened descriptor, not a
    separate stat result: the file may change between directory traversal and
    reading. Binary inputs are ignored; limits and I/O failures are reported to
    callers that track completeness.
    """
    try:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        with open_confined_file(path, label="file", dir_fd=dir_fd) as (fh, info):
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
            if isinstance(exc, NotRegularFileError):
                errors.append("not a regular file")
            elif isinstance(exc, ValueError):
                errors.append(str(exc))
            else:
                errors.append("file could not be read")
        return None


def notebook_to_source(text: str, errors: list[str] | None = None) -> str:
    """Extract code cells from a Jupyter notebook as a python source blob."""
    try:
        nb = strict_json_loads(text)
    except (ValueError, RecursionError):
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


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing (ISO 8601, epoch seconds / millis)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            v = float(value)
        except OverflowError:
            return None
        if not math.isfinite(v):
            return None
        if v > 1e12:
            v /= 1000.0
        try:
            return datetime.fromtimestamp(v, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if len(s) > 64:
        # No supported timestamp representation is this long; hostile claims
        # (thousands of digits) must not reach int()/float() conversion.
        return None
    if _EPOCH_RX.fullmatch(s):
        return parse_timestamp(float(s))
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


_URL_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*+://", re.IGNORECASE)


def host_of(url: str | None) -> str | None:
    """Return the lowercase host of ``url`` (RFC 3986 authority; scheme optional).

    Userinfo before the last ``@`` and the port are removed, and a bracketed
    IPv6 literal is returned without its brackets. A URL such as
    ``https://api.openai.com:443@evil.example/`` therefore names ``evil.example``,
    the host a client connects to, never the userinfo.
    """
    if not url:
        return None
    rest = url.strip()
    scheme = _URL_SCHEME.match(rest)
    if scheme:
        rest = rest[scheme.end() :]
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0].rpartition("@")[2]
    if authority.startswith("["):
        end = authority.find("]")
        host = authority[1:end] if end > 0 else ""
    else:
        host = authority.split(":", 1)[0]
    return host.lower() or None
