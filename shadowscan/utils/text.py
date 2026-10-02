"""Text helpers: redaction, safe file reading and small parsers."""

from __future__ import annotations

import codecs
import io
import math
import re
import tokenize
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from shadowscan.utils.files import NotRegularFileError, open_confined_file
from shadowscan.utils.redaction import credential_id
from shadowscan.utils.safe_json import strict_json_loads

_BINARY_SNIFF = 8192
# Reported by ``read_text`` for a NUL-bearing file that is not text in any
# encoding it decodes and not a binary artifact it may skip (``_skips_binary``).
# Callers pass only files they would analyze, so this is a coverage gap, never
# a reason to treat the scan as complete.
BINARY_CONTENT_ERROR = "binary or undecodable content in analyzable file"
# Byte-order marks, longest first (the UTF-32LE mark begins with the UTF-16LE one).
_BOM_CODECS: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
)
# Headers of compiled, packed and media artifacts. An interpreter can still run
# a script whose first line looks like a header, so this evidence alone never
# hides a name the scanner analyzes by its extension (``.sh``, ``.js``); see
# ``_skips_binary`` for where it does apply.
_BINARY_MAGIC: tuple[bytes, ...] = (
    b"\x7fELF",  # ELF
    b"\xca\xfe\xba\xbe",  # Mach-O universal
    b"\xfe\xed\xfa\xce",  # Mach-O
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"MZ",  # PE and DOS executables
    b"\x00asm",  # WebAssembly
    b"\x1f\x8b",  # gzip
    b"PK\x03\x04",  # zip, jar, wheel
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
    b"\x28\xb5\x2f\xfd",  # zstd
    b"7z\xbc\xaf\x27\x1c",  # 7z
    b"SQLite format 3\x00",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",  # JPEG
    b"GIF87a",
    b"GIF89a",
    b"%PDF-",
)
# Text codec that a PEP 263 coding cookie must not select: its decoder is not
# linear in its input (``punycode`` re-copies its output for every code point,
# about 30 s for a 1 MB file with the GIL held), so a hostile cookie would stall
# the scan. Such a file is reported as undecodable instead.
_SLOW_SOURCE_CODECS = frozenset({"punycode"})
# Epoch seconds or milliseconds, optionally fractional (nginx $msec, Kong).
_EPOCH_RX = re.compile(r"\d{1,19}(?:\.\d{1,9})?")
# A compact calendar day (yyyymmdd); checked before the epoch form claims it.
_CALENDAR_DAY_RX = re.compile(r"(?:19|20)\d{6}")


def redact(value: str, keep: int = 4) -> str:
    """Return a stable opaque credential identity without retaining raw fragments.

    ``keep`` remains accepted for compatibility with older call sites, but no
    prefix or suffix is kept. New code should call ``credential_id`` directly.
    """
    del keep
    if not value:
        return value
    return credential_id(value)


def _skips_binary(name: str, raw: bytes, analyzable_name: bool) -> bool:
    """Whether NUL-bearing ``raw`` is a recognised binary artifact to skip without a coverage gap.

    The content must start with a ``_BINARY_MAGIC`` header. Even then a name
    analyzed for its own sake stays a gap unless it has no extension at all.
    Packet-like ``.ts`` bytes cannot establish that the file is video rather
    than TypeScript: source comments can contain the same binary padding.
    Unrecognised binary content is always a gap.
    """
    if not raw.startswith(_BINARY_MAGIC):
        return False
    return not analyzable_name or "." not in name


def _python_source_text(raw: bytes) -> str | None:
    """Decode a Python source with the PEP 263 codec it declares; None when it declares none.

    A cookie naming UTF-8, an unknown codec or a codec that is not a text
    encoding leaves the caller's default decoding in place (the interpreter
    cannot run such a file either). A text codec that cannot decode the bytes,
    or that is too slow to run on untrusted input, is a coverage gap.
    """
    try:
        declared, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        codec = codecs.lookup(declared).name
    except (SyntaxError, LookupError):
        return None
    if codec == "utf-8":
        return None
    if codec in _SLOW_SOURCE_CODECS:
        raise ValueError(BINARY_CONTENT_ERROR)
    try:
        return raw.decode(declared)
    except LookupError:
        return None
    except UnicodeDecodeError:
        # Name the gap, not the position or byte the decoder rejected.
        raise ValueError(BINARY_CONTENT_ERROR) from None


def _decode_text(raw: bytes, name: str, analyzable_name: bool) -> str | None:
    """Decode file content for analysis; None for a recognised binary artifact (``_skips_binary``)."""
    for bom, codec in _BOM_CODECS:
        if raw.startswith(bom):
            decoded = raw.decode(codec, errors="replace")
            # A mark does not make the rest text: a NUL in the decoded prefix
            # is still binary content under an analyzable name.
            if "\x00" in decoded[:_BINARY_SNIFF]:
                raise ValueError(BINARY_CONTENT_ERROR)
            return decoded
    if b"\x00" in raw[:_BINARY_SNIFF]:
        if _skips_binary(name, raw, analyzable_name):
            return None
        raise ValueError(BINARY_CONTENT_ERROR)
    if name.lower().endswith(".py"):
        declared = _python_source_text(raw)
        if declared is not None:
            return declared
    return raw.decode("utf-8", errors="replace")


def read_text(
    path: PurePath,
    max_bytes: int,
    errors: list[str] | None = None,
    *,
    dir_fd: int | None = None,
    analyzable_name: bool = True,
) -> str | None:
    """Read a bounded regular file without following a symlink in any path component.

    With ``dir_fd``, ``path`` is relative to that open directory, normally the
    scan root, and only the components below it are opened; otherwise the
    whole absolute path is. Each directory is opened with ``O_NOFOLLOW``
    relative to its parent (:func:`open_confined_file`), so a directory swapped
    for a link between directory traversal and reading fails the read instead
    of redirecting it outside the tree. Validate the opened descriptor, not a
    separate stat result: the file may change between directory traversal and
    reading. Text with a byte-order mark (UTF-8, UTF-16, UTF-32) is decoded and
    the mark removed, and a Python source is decoded with the codec its PEP 263
    cookie declares. Callers pass only files they would analyze, so any other
    content with a NUL byte in its first 8 KiB is reported as
    ``BINARY_CONTENT_ERROR`` rather than ignored. The exception is a recognised
    binary artifact (``_skips_binary``) without any file extension or, with
    ``analyzable_name`` False, any recognised artifact: the caller then reads
    the file only because of the directory it is in, such as an image kept
    beside coding-agent rules. Limits and I/O failures are reported to callers
    that track completeness.
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
        return _decode_text(raw, path.name, analyzable_name)
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


def notebook_to_source(text: str, errors: list[str] | None = None, *, cells: list[str] | None = None) -> str:
    """Extract code cells from a Jupyter notebook as a python source blob.

    The cells are joined by line breaks; ``cells``, when given, receives each
    code cell's source in order, so a caller can treat them one at a time.
    """
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
    if cells is not None:
        cells.extend(out)
    return "\n".join(out)


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing.

    ISO 8601, epoch seconds / millis / micros / nanos, Go ``time.Time.String()``
    output and RFC 2822 dates. Anything else is ``None``.
    """
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
        # Seconds, then milli-, micro- and nanoseconds; each unit's range ends
        # before the next begins for dates before the year 33658.
        if v > 1e18:
            v /= 1e9
        elif v > 1e15:
            v /= 1e6
        elif v > 1e12:
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
    if _CALENDAR_DAY_RX.fullmatch(s):
        # Eight digits starting 19xx/20xx are a calendar day (yyyymmdd, as in
        # a log's ``date`` field); as epoch seconds they would all fall in
        # 1970-1973. An impossible day is no timestamp at all.
        try:
            return datetime.strptime(s, "%Y%m%d").replace(tzinfo=UTC)
        except ValueError:
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
    return _go_or_rfc2822_time(s)


# Go's time.Time.String(): "2006-01-02 15:04:05.999999999 -0700 MST", with an
# optional monotonic clock reading ("m=+0.000000001"). Every part is bounded.
_GO_TIME_RX = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))? ([+-]\d{4})"
    r"(?: [A-Za-z0-9+:-]{1,16})?(?: m=[+-]\d{1,20}(?:\.\d{1,9})?)?"
)


def _go_or_rfc2822_time(s: str) -> datetime | None:
    """Parse Go ``time.Time.String()`` output or an RFC 2822 date (mail, HTTP, syslog exporters)."""
    from email.utils import parsedate_to_datetime

    go = _GO_TIME_RX.fullmatch(s)
    if go:
        fraction = (go.group(2) or "")[:6].ljust(6, "0")
        try:
            return datetime.strptime(f"{go.group(1)}.{fraction} {go.group(3)}", "%Y-%m-%d %H:%M:%S.%f %z")
        except ValueError:
            return None
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


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
    IPv6 literal is returned without its brackets. An authority such as
    ``api.openai.com:443@evil.example`` therefore names ``evil.example``, the host
    a client connects to, never the userinfo.
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
