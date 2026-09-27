"""Offline export reading shared by every connector.

In offline mode a connector reads an export of the records its live mode would
collect (``input:`` in its configuration): one file, or a directory of JSON,
JSONL, YAML or CSV exports. This module holds that machinery:

* export discovery that never follows links (:func:`offline_files`);
* confined whole-file and line readers with per-file, aggregate and per-line
  byte limits (:func:`read_offline_bytes`, :func:`iter_bounded_lines`);
* parsing by format (:func:`load_offline_file`) and validation of records and
  collection envelopes, including uncollected pagination
  (:func:`unwrap`, :func:`offline_pagination_issue`).

Limits, malformed records, provider error pages and continuation cursors are
reported through the connector context, which marks the scan incomplete; valid
records next to a rejected one are still returned.

:class:`~shadowscan.connectors.base.BaseConnector` keeps thin methods under the
historical names (``load_offline``, ``_unwrap``, ``_read_offline_bytes``...).
Those methods are the override points: connectors specialize them and tests
replace them. The functions here therefore call back through the connector, or
its class, wherever a subclass may change the behaviour.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import stat
import zlib
from collections.abc import Callable, Iterator
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from shadowscan.utils.files import NotRegularFileError, changed_since, open_confined_file
from shadowscan.utils.safe_yaml import YAMLResourceLimitError, bounded_safe_load

if TYPE_CHECKING:
    from shadowscan.connectors.base import BaseConnector

Report = Callable[[str], None]
# Whether the file behind a descriptor changed since the given stat was taken.
ChangeCheck = Callable[[os.stat_result, int], bool]

DEFAULT_MAX_INPUT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_INPUT_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_INPUT_FILES = 10_000
# Hard ceilings the configured byte limits are clamped to.
MAX_OFFLINE_FILE_BYTES = 64 * 1024 * 1024
MAX_OFFLINE_TOTAL_BYTES = 512 * 1024 * 1024
# Fixed caps: one line, one directory walk, and the invalid records one
# export lists individually before summarising the rest.
MAX_OFFLINE_LINE_BYTES = 4 * 1024 * 1024
MAX_OFFLINE_ENTRIES = 200_000
MAX_INVALID_LINE_ERRORS = 20
OFFLINE_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".csv"})

# Envelope keys that hold a record collection.
_WRAPPERS = frozenset({
    "records", "items", "value", "data", "results", "resources", "logs", "entries",
    "plugins", "installations", "apps", "users", "members", "workflows", "scenarios",
    "aiAgents", "teamsApps", "servicePrincipals", "clients", "tokens", "agents", "bots",
    "flows", "Records", "logEvents", "hits",
})
_COLLECTIONS = frozenset({"items", "records", "value", "data", "results", "resources", "logEvents"})
_PAGINATION = frozenset({
    "has_more", "IsTruncated", "next_page", "nextPage", "next_page_token",
    "nextPageToken", "nextToken", "NextToken", "NextMarker", "@odata.nextLink",
    "nextLink", "nextCursor", "next_cursor", "response_metadata",
})
_STRING_CURSORS = (
    "next_page_token", "nextPageToken", "nextToken", "NextToken",
    "NextMarker", "@odata.nextLink", "nextLink", "nextCursor", "next_cursor",
)
_CSV_ERROR_FIELDS = frozenset({
    "id", "name", "error", "ok", "code", "message", "status", "requestid", "request_id", "traceid",
})
# Fields that let a known log event describing an upstream error stay a record.
_EVENT_FIELDS = frozenset({"attempt", "timestamp", "message", "status", "operation", "duration_ms"})


@dataclass(slots=True)
class OfflineInputBudget:
    """Aggregate byte and file budget shared by the files of one offline input."""

    max_bytes: int
    max_files: int
    bytes_read: int = 0
    files_seen: int = 0
    file_limit_warning_sent: bool = False

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.max_bytes - self.bytes_read)

    def consume(self, count: int) -> bool:
        if count < 0 or count > self.remaining_bytes:
            return False
        self.bytes_read += count
        return True


def _prefixed(report: Report, prefix: str) -> Report:
    """Report under ``prefix``, bound now rather than when a later record is read."""
    return lambda message: report(f"{prefix}: {message}")


# ------------------------------------------------------------------ discovery
def offline_files(conn: BaseConnector, path: str, suffixes: AbstractSet[str] | None = None) -> Iterator[Path]:
    """Find exports without traversing links; rejected inputs affect completeness."""
    ctx, name = conn.ctx, conn.name
    root = Path(path).expanduser().absolute()
    suffixes = conn._OFFLINE_SUFFIXES if suffixes is None else suffixes
    try:
        if any(part.is_symlink() for part in (root, *root.parents)):
            raise ValueError("symlink input is not allowed")
        mode = root.stat().st_mode
    except (OSError, ValueError):
        ctx.error(f"{name}: offline input is missing, inaccessible, or a symlink")
        return
    if stat.S_ISREG(mode):
        yield root
        return
    if not stat.S_ISDIR(mode):
        ctx.error(f"{name}: offline input must be a regular file or directory")
        return
    count = 0
    files_seen = 0
    found = False

    def failed(_: OSError) -> None:
        ctx.error(f"{name}: offline directory could not be read")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        count += 1 + len(dirs) + len(files)
        if count > conn._MAX_OFFLINE_ENTRIES:
            ctx.error(f"{name}: offline directory entry limit exceeded")
            return
        base = Path(directory)
        kept = []
        for entry in sorted(dirs):
            if (base / entry).is_symlink():
                ctx.warn(f"{name}: offline input symlinks are skipped")
            else:
                kept.append(entry)
        dirs[:] = kept
        for entry in sorted(files):
            item = base / entry
            try:
                mode = item.lstat().st_mode
            except OSError:
                failed(OSError())
                continue
            if not stat.S_ISREG(mode):
                ctx.warn(f"{name}: offline input symlinks or special files are skipped")
                continue
            if item.suffix.lower() in suffixes:
                found = True
                if files_seen >= conn.max_input_files:
                    ctx.warn(f"{name}: max_input_files ({conn.max_input_files}) reached")
                    return
                files_seen += 1
                yield item
    if not found:
        ctx.error(f"{name}: offline directory contains no supported export files")


def iter_offline_files(conn: BaseConnector, path: str, budget: OfflineInputBudget,
                       suffixes: AbstractSet[str] | None = None) -> Iterator[Path]:
    """Yield export files while the budget's file count allows, warning once when it does not."""
    for source in conn._offline_files(path, suffixes):
        if budget.files_seen >= budget.max_files:
            if not budget.file_limit_warning_sent:
                conn.ctx.warn(f"{conn.name}: max_input_files ({budget.max_files}) reached")
                budget.file_limit_warning_sent = True
            return
        budget.files_seen += 1
        yield source


# -------------------------------------------------------------------- readers
def read_offline_bytes(conn: BaseConnector, path: Path, budget: OfflineInputBudget | None = None,
                       *, changed: ChangeCheck = changed_since) -> bytes | None:
    """Read one whole offline file through the confined opener.

    The file is rejected as a whole when it exceeds the per-file cap or the
    remaining aggregate budget. Without a budget the connector-wide
    ``_offline_bytes_read`` counter plays the aggregate role and an
    oversized file is an error rather than a skipped-file warning.
    """
    try:
        with open_confined_file(path.expanduser().absolute(), label="offline input") as (stream, before):
            used = budget.bytes_read if budget is not None else getattr(conn, "_offline_bytes_read", 0)
            remaining = (budget.max_bytes - used) if budget is not None else (conn.max_input_bytes - used)
            limit = min(conn.max_input_file_bytes, remaining, conn._MAX_OFFLINE_FILE_BYTES,
                        conn._MAX_OFFLINE_TOTAL_BYTES - used)

            def oversized() -> None:
                if budget is None:
                    raise ValueError("offline input exceeds the byte limit")
                file_limited = conn.max_input_file_bytes <= remaining
                exceeded = "max_input_file_bytes" if file_limited else "max_input_bytes"
                conn.ctx.warn(f"{conn.name}: {exceeded} reached; oversized offline input was skipped")

            if before.st_size > limit:
                oversized()
                return None
            raw = stream.read(limit + 1)
            modified = changed(before, stream.fileno())
        if budget is None:
            conn._offline_bytes_read = used + len(raw)
        else:
            budget.consume(len(raw))
        if len(raw) > limit:
            oversized()
            return None
        if modified:
            raise ValueError("offline input changed while being read")
        return raw
    except (OSError, ValueError) as exc:
        # Parser and OS exception strings may contain raw data or secret paths.
        reason = str(exc) if isinstance(exc, ValueError) else "offline input could not be securely read"
        conn.ctx.error(f"{conn.name}: {reason}")
        return None


def read_offline_text(conn: BaseConnector, path: Path,
                      budget: OfflineInputBudget | None = None) -> str | None:
    """Read one whole offline file as UTF-8 text (a byte-order mark is dropped)."""
    raw = conn._read_offline_bytes(path, budget)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        conn.ctx.error(f"{conn.name}: offline input is not valid UTF-8")
        return None


def iter_bounded_lines(conn: BaseConnector, path: Path, budget: OfflineInputBudget, *,
                       compressed: bool = False, changed: ChangeCheck = changed_since) -> Iterator[str]:
    """Read UTF-8 lines with secure opens and per-file, aggregate, and line caps.

    Only the per-file cap is checked before reading. The aggregate budget
    is charged line by line, so records that precede the limit are yielded
    even when the file as a whole would not fit.
    """
    ctx, name = conn.ctx, conn.name
    try:
        with open_confined_file(path.expanduser().absolute(), label="offline input") as (raw, before):
            if before.st_size > min(conn.max_input_file_bytes, conn._MAX_OFFLINE_FILE_BYTES):
                ctx.warn(f"{name}: max_input_file_bytes ({conn.max_input_file_bytes}) reached")
                return
            stream = gzip.GzipFile(fileobj=raw, mode="rb") if compressed else raw
            file_bytes = 0
            try:
                while True:
                    remaining = min(conn.max_input_file_bytes - file_bytes, budget.remaining_bytes)
                    read_size = min(MAX_OFFLINE_LINE_BYTES + 1, remaining + 1)
                    line = stream.readline(read_size)
                    if not line:
                        break
                    if len(line) > MAX_OFFLINE_LINE_BYTES:
                        ctx.warn(f"{name}: max_input_line_bytes ({MAX_OFFLINE_LINE_BYTES}) reached")
                        return
                    if len(line) > remaining:
                        file_limited = conn.max_input_file_bytes - file_bytes <= budget.remaining_bytes
                        exceeded = "max_input_file_bytes" if file_limited else "max_input_bytes"
                        ctx.warn(f"{name}: {exceeded} reached; remaining offline input was skipped")
                        return
                    if not budget.consume(len(line)):
                        ctx.warn(f"{name}: max_input_bytes ({budget.max_bytes}) reached")
                        return
                    file_bytes += len(line)
                    try:
                        yield line.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        ctx.error(f"{name}: offline input is not valid UTF-8")
                        return
            finally:
                if compressed:
                    stream.close()
            if changed(before, raw.fileno()):
                ctx.error(f"{name}: offline input changed while being read")
    except NotRegularFileError as exc:
        ctx.warn(f"{name}: {exc}")
    except (OSError, EOFError, gzip.BadGzipFile, ValueError, zlib.error) as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        ctx.warn(f"{name}: offline input could not be read ({detail})")


# -------------------------------------------------------------------- parsing
def load_offline(conn: BaseConnector, path: str) -> Iterator[dict[str, Any]]:
    """Validate exports under shared input budgets and preserve valid records."""
    budget = conn._offline_budget()
    for source in conn._iter_offline_files(path, budget, conn._OFFLINE_SUFFIXES):
        yield from conn._load_offline_file(source, budget)


def load_offline_file(conn: BaseConnector, source: Path,
                      budget: OfflineInputBudget) -> Iterator[dict[str, Any]]:
    """Parse one export by its suffix: JSONL, CSV, YAML, or JSON with a JSONL fallback."""
    suffix = source.suffix.lower()
    report = conn._bounded_diagnostics(lambda message: conn.ctx.error(f"{conn.name}: {message}"))

    if suffix in {".jsonl", ".ndjson"}:
        saw_record = False
        for number, line in enumerate(conn._iter_bounded_lines(source, budget), 1):
            if not line.strip():
                continue
            saw_record = True
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, RecursionError, ValueError):
                report(f"invalid JSON record at line {number}")
                continue
            yield from conn._unwrap(data, _prefixed(report, f"line {number}"))
        if not saw_record:
            report("empty offline export; use [] for an empty inventory")
        return
    if suffix == ".csv":
        yield from _csv_rows(csv.DictReader(conn._iter_bounded_lines(source, budget), strict=True),
                             report, conn._is_csv_provider_error)
        return
    text = conn._read_offline_text(source, budget)
    if text is None:
        return
    if not text.strip():
        report("empty offline export; use [] for an empty inventory")
        return
    if suffix in {".yaml", ".yml"}:
        try:
            data = bounded_safe_load(text)
        except YAMLResourceLimitError:
            report("YAML safety limit exceeded")
            return
        except (yaml.YAMLError, RecursionError, ValueError):
            report("invalid YAML export")
            return
        yield from conn._unwrap(data, report)
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        yield from conn._json_lines(text, report)
    except (RecursionError, ValueError):
        report("invalid JSON export")
    else:
        yield from conn._unwrap(data, report)


def bounded_diagnostics(report: Report, limit: int) -> Report:
    """Bound diagnostics per export while continuing to inspect later records."""
    errors = 0

    def limited(message: str) -> None:
        nonlocal errors
        errors += 1
        if errors <= limit:
            report(message)
        elif errors == limit + 1:
            report("further invalid records in this export are not listed individually")

    return limited


def json_lines(cls: type[BaseConnector], text: str, report: Report) -> Iterator[dict[str, Any]]:
    """Parse a ``.json`` export that is not one document as one JSON object per line."""
    lines = text.splitlines()
    first = next((line.strip() for line in lines if line.strip()), "")
    if first in {"[", "{"}:
        # A broken pretty-printed document is not a JSONL stream. Do not
        # amplify a single parse failure into one diagnostic per line.
        report("invalid JSON export")
        return
    report = cls._bounded_diagnostics(report)
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, RecursionError, ValueError):
            report(f"invalid JSON record at line {number}")
            continue
        if not isinstance(data, dict):
            report(f"line {number}: JSONL records must be objects")
            continue
        yield from cls._unwrap(data, _prefixed(report, f"line {number}"))


def csv_records(text: str, report: Report) -> Iterator[dict[str, Any]]:
    """Parse CSV text into rows, rejecting malformed rows and provider error rows."""
    yield from _csv_rows(csv.DictReader(io.StringIO(text), strict=True), report, is_csv_provider_error)


def _csv_rows(reader: csv.DictReader[str], report: Report,
              is_provider_error: Callable[[dict[str, str]], bool]) -> Iterator[dict[str, Any]]:
    try:
        fields = reader.fieldnames
        if not fields or any(not field.strip() for field in fields) or len(set(fields)) != len(fields):
            report("CSV export needs unique, nonempty column names")
            return
        for rec in reader:
            if None in rec or any(value is None for value in rec.values()):
                report(f"CSV row at line {reader.line_num} has the wrong number of columns")
                continue
            if is_provider_error(rec):
                report(f"provider error response in CSV row at line {reader.line_num}; coverage incomplete")
                continue
            yield rec
    except csv.Error:
        report("invalid CSV export")


def is_csv_provider_error(record: dict[str, str]) -> bool:
    """Recognize metadata-only failures without treating log event rows as failures."""
    fields = {key.strip().lower(): value for key, value in record.items()}
    if not fields.keys() <= _CSV_ERROR_FIELDS:
        return False
    return bool(fields.get("error", "").strip()) or fields.get("ok", "").strip().lower() == "false"


# -------------------------------------------------------------------- records
def valid_record(data: Any) -> bool:
    """Validate structural shape without echoing data; reject YAML alias cycles."""
    if not isinstance(data, dict) or not data:
        return False
    active: set[int] = set()
    remaining = 100_000

    def check(value: Any, depth: int = 0) -> bool:
        nonlocal remaining
        remaining -= 1
        if depth > 64 or remaining < 0:
            return False
        if not isinstance(value, (dict, list)):
            return not isinstance(value, (set, bytes))
        identity = id(value)
        if identity in active:
            return False
        active.add(identity)
        try:
            if isinstance(value, dict):
                return all(isinstance(key, str) and check(item, depth + 1) for key, item in value.items())
            return all(check(item, depth + 1) for item in value)
        finally:
            active.remove(identity)

    return check(data)


def is_error_record(data: dict[str, Any]) -> bool:
    return "error" in data or bool(data.get("errors")) or data.get("ok") is False


def _is_native_error_record(data: dict[str, Any]) -> bool:
    """Whether a record carrying error fields is still a provider record (a logged event)."""
    if {"items", "records", "value", "results", "resources", "logEvents"}.intersection(data):
        return False
    payload = data.get("data")
    if isinstance(payload, list) and any(
        isinstance(item, dict) and (_COLLECTIONS | _PAGINATION).intersection(item) for item in payload
    ):
        return False
    if data.get("object") == "error" or data.get("type") == "error" or data.get("_kind") == "error":
        return False
    kind = data.get("_kind")
    if kind == "cloudtrail-event" and data.get("eventName") and data.get("eventTime"):
        return True
    if kind == "audit-event" and data.get("principal") and data.get("timestamp"):
        return True
    if kind == "integration_log" and data.get("change_type") and (
        data.get("app_id") or data.get("service_id")
    ):
        return True
    # A known log event can legitimately describe an upstream error.
    # Preserve it only when its nested payload has event attributes;
    # an error with page records remains a failed partial export.
    return (
        "id" in data and isinstance(data.get("error"), dict)
        and isinstance(payload, list) and bool(payload)
        and all(
            isinstance(item, dict) and bool(_EVENT_FIELDS.intersection(item))
            and not _COLLECTIONS.intersection(item) and not _PAGINATION.intersection(item)
            for item in payload
        )
    )


def is_native_offline_record(data: dict[str, Any]) -> bool:
    """Whether ``data`` is one provider record rather than a collection envelope."""
    # Page IDs, labels and provider-specific ``kind`` values are not
    # enough to turn a collection into one resource.  Explicit resource
    # type fields can identify a native record with nested collections.
    if _COLLECTIONS.intersection(data) and _PAGINATION.intersection(data):
        # A page can carry an ID, resource-looking type and continuation.
        # Never let those labels bypass the envelope pagination check.
        return False
    if _COLLECTIONS.intersection(data) and (
        data.get("type") in ("list", "page", "collection")
        or data.get("object") in ("list", "page", "collection")
    ):
        return False
    if is_error_record(data):
        return _is_native_error_record(data)
    listed = "items" in data or "records" in data or ("value" in data and isinstance(data["value"], list))
    if listed and not (
        {"_kind", "resource", "resourceId", "arn"}.intersection(data)
        or ("type" in data and data["type"] not in ("list", "page", "collection"))
        or data.get("object") not in (None, "list", "page", "collection")
    ):
        return False
    identity_keys = {"_id", "_kind", "name", "arn", "type", "kind", "resource", "resourceId"}
    if identity_keys.intersection(data) or data.get("object") not in (None, "list", "page"):
        return True
    return "id" in data


def record_fields_valid(
    data: Any, *, strings: tuple[str, ...] = (), mappings: tuple[str, ...] = (),
    arrays: tuple[str, ...] = (), required: tuple[str, ...] = (),
) -> bool:
    """Check fields consumed by a provider without disclosing rejected values."""
    if not isinstance(data, dict) or is_error_record(data):
        return False
    if any(not isinstance(data.get(key), str) or not data[key].strip() for key in required):
        return False
    for fields, expected in ((strings, str), (mappings, dict), (arrays, list)):
        if any(data.get(key) is not None and not isinstance(data[key], expected) for key in fields):
            return False
    return True


def offline_pagination_issue(data: dict[str, Any]) -> str | None:
    """Reject partial export envelopes without disclosing opaque cursors.

    Slack nests its continuation cursor under response_metadata; AWS also
    signals truncation separately from its marker. Empty result arrays do
    not establish that either provider has reached the end of a collection.
    Call only for collection envelopes, never arbitrary resource fields.
    """
    for flag in ("has_more", "IsTruncated"):
        if flag in data and not isinstance(data[flag], bool):
            return "offline export has invalid pagination metadata"
    metadata = data.get("response_metadata", {})
    if not isinstance(metadata, dict):
        return "offline export has invalid pagination metadata"
    for key in _STRING_CURSORS:
        cursor = data.get(key)
        if cursor is not None and not isinstance(cursor, str):
            return "offline export has invalid pagination metadata"
    cursor = metadata.get("next_cursor")
    if cursor is not None and not isinstance(cursor, str):
        return "offline export has invalid pagination metadata"
    for key in ("next_page", "nextPage"):
        page = data.get(key)
        # Providers use either an opaque link/token or a positive page
        # number. Falsey containers/booleans are malformed, not a proof
        # that collection reached its terminal page.
        if page is not None and not (
            isinstance(page, str) or (type(page) is int and page > 0)
        ):
            return "offline export has invalid pagination metadata"
    keys = ("has_more", "IsTruncated", "next_page", "nextPage", *_STRING_CURSORS)
    if any(data.get(key) for key in keys) or metadata.get("next_cursor"):
        return "offline export contains an uncollected next page"
    return None


def unwrap(cls: type[BaseConnector], data: Any, failed: Report) -> Iterator[dict[str, Any]]:
    """Accept records or a common envelope, rejecting invalid shapes explicitly.

    Identified native records keep nested fields such as data/results intact.
    An envelope containing more than one collection is ambiguous, not empty.
    ``failed`` receives each rejection; it may raise to stop at the first one.
    """
    wrappers = _WRAPPERS.union(cls._OFFLINE_COLLECTION_KINDS)
    record_kind: str | None = None
    if isinstance(data, dict):
        # Lists supplied as records are never recursively unwrapped. Direct
        # single-record exports require the same protection from field collisions.
        native = cls._is_native_offline_record(data)
        if not native and cls._is_error_record(data):
            failed("provider error response in offline export; coverage is incomplete")
            if not wrappers.intersection(data):
                return
        keys = wrappers.intersection(data) if not native else set()
        if len(keys) > 1:
            failed("ambiguous export envelope contains multiple record collections")
            return
        if keys:
            pagination_issue = cls._offline_pagination_issue(data)
            if pagination_issue:
                failed(pagination_issue)
            key = next(iter(keys))
            record_kind = cls._OFFLINE_COLLECTION_KINDS.get(key)
            collection = data[key]
            if not isinstance(collection, list):
                failed("export envelope record collection must be an array")
                return
            data = collection
        else:
            data = [data]
    if not isinstance(data, list):
        failed("offline export must contain an object or an array of objects")
        return
    for number, item in enumerate(data, 1):
        if not valid_record(item):
            failed(f"invalid export record {number}; expected a nonempty object with string keys")
            continue
        if cls._is_error_record(item) and not cls._is_native_offline_record(item):
            if wrappers.intersection(item):
                # A failed page embedded in an export can still contain
                # observed records.  Keep them, but never mark it complete.
                yield from cls._unwrap(item, failed)
            else:
                failed("provider error response in offline export; coverage is incomplete")
            continue
        yield {**item, "_kind": record_kind} if record_kind else item
