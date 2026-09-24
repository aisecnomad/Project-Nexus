"""Connector base classes.

A connector scans one *surface* (code, identity, gateway, lowcode, saas, cloud)
for one provider / data source and yields :class:`Finding` objects.

Every connector supports two execution modes:

* **live** – talk to the provider's API with credentials from the config or
  environment (``collect()`` returns raw records);
* **offline** – read an export of the same records from a file (``input:``),
  which makes connectors usable without credentials, reproducible and testable.

``analyze()`` turns raw records into findings and is shared by both modes.
"""

from __future__ import annotations

import csv
import gzip
import importlib
import json
import logging
import os
import stat
import tempfile
import zlib
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import yaml

from shadowscan.models import Finding, ScanStats, Surface, now_iso
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize
from shadowscan.utils.safe_yaml import YAMLResourceLimitError, bounded_safe_load


class ConnectorError(RuntimeError):
    """Raised when a connector cannot run at all (bad config, missing creds)."""


_DEFAULT_MAX_INPUT_BYTES = 256 * 1024 * 1024
_DEFAULT_MAX_INPUT_FILE_BYTES = 32 * 1024 * 1024
_DEFAULT_MAX_INPUT_FILES = 10_000
_MAX_OFFLINE_LINE_BYTES = 4 * 1024 * 1024


@dataclass(slots=True)
class _OfflineInputBudget:
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


def _positive_limit(value: Any, name: str) -> int:
    if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
        raise ConnectorError(f"{name} must be a positive integer")
    try:
        limit = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConnectorError(f"{name} must be a positive integer") from exc
    if limit < 1:
        raise ConnectorError(f"{name} must be a positive integer")
    return limit


class ConnectorContext:
    """Runtime context handed to a connector."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        index: SignatureIndex | None = None,
        logger: logging.Logger | None = None,
        input_path: str | None = None,
        workdir: str | None = None,
    ):
        self.config: dict[str, Any] = dict(config or {})
        self.index: SignatureIndex = index or get_index()
        self.log = logger or logging.getLogger("shadowscan")
        self.input_path = input_path or self.config.get("input")
        self.workdir = workdir
        self.stats: ScanStats | None = None
        self.dump_path: str | None = None
        self._resolved_config: dict[str, Any] = {}

    # ---------------------------------------------------------------- config
    def get(self, key: str, default: Any = None, env: str | None = None) -> Any:
        """Read a config key, falling back to an environment variable."""
        val = self.config.get(key)
        if val is None and env:
            val = os.environ.get(env)
        resolved = default if val is None else val
        self._resolved_config[key] = resolved
        return resolved

    def require(self, key: str, env: str | None = None) -> Any:
        val = self.get(key, env=env)
        if val in (None, ""):
            hint = f" (or env {env})" if env else ""
            raise ConnectorError(f"missing required config '{key}'{hint}")
        return val

    def sanitize_message(self, msg: str) -> str:
        """Remove configured credentials even when an upstream error echoes them."""
        try:
            return sanitize({"config": {**self.config, **self._resolved_config}, "message": msg})["message"]
        except SanitizationLimitError:
            if self.stats is not None:
                self.stats.incomplete = True
            return f"diagnostic omitted: sanitization safety limit exceeded {REDACTED}"

    def warn(self, msg: str, incomplete: bool = True) -> None:
        msg = self.sanitize_message(msg)
        self.log.warning(msg)
        if self.stats is not None:
            self.stats.warnings.append(msg)
            self.stats.incomplete = self.stats.incomplete or incomplete

    def error(self, msg: str) -> None:
        msg = self.sanitize_message(msg)
        self.log.error(msg)
        if self.stats is not None:
            self.stats.errors.append(msg)
            self.stats.incomplete = True

    def examined(self, n: int = 1) -> None:
        if self.stats is not None:
            self.stats.objects_examined += n


class BaseConnector(ABC):
    """Base class for all connectors."""

    name: ClassVar[str] = "base"
    surface: ClassVar[Surface] = Surface.CODE
    description: ClassVar[str] = ""
    provider: ClassVar[str | None] = None
    requires: ClassVar[list[str]] = []  # optional python packages for live mode
    config_keys: ClassVar[dict[str, str]] = {}  # documentation: key -> description
    offline_formats: ClassVar[str] = "JSON / JSONL / YAML / CSV export"
    _OFFLINE_COLLECTION_KINDS: ClassVar[dict[str, str]] = {}

    def __init__(self, ctx: ConnectorContext):
        self.ctx = ctx
        self.index = ctx.index
        self.log = ctx.log
        self.max_input_bytes = min(
            _positive_limit(ctx.get("max_input_bytes", _DEFAULT_MAX_INPUT_BYTES), "max_input_bytes"),
            self._MAX_OFFLINE_TOTAL_BYTES,
        )
        self.max_input_file_bytes = min(
            _positive_limit(ctx.get("max_input_file_bytes", _DEFAULT_MAX_INPUT_FILE_BYTES), "max_input_file_bytes"),
            self._MAX_OFFLINE_FILE_BYTES,
        )
        self.max_input_files = _positive_limit(ctx.get("max_input_files", _DEFAULT_MAX_INPUT_FILES), "max_input_files")

    # ----------------------------------------------------------------- modes
    @property
    def offline(self) -> bool:
        return bool(self.ctx.input_path)

    def check_requirements(self) -> None:
        missing = []
        for mod in self.requires:
            try:
                importlib.import_module(mod)
            except ImportError:
                missing.append(mod)
        if missing:
            raise ConnectorError(
                f"{self.name}: live mode needs python packages {missing}; install the matching extra "
                f"(e.g. pip install 'shadowscan[cloud]') or use offline input"
            )

    @abstractmethod
    def collect(self) -> Iterable[dict[str, Any]]:
        """Fetch raw records from the live source."""

    @abstractmethod
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        """Turn raw records into findings."""

    _OFFLINE_SUFFIXES = {".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".csv"}
    _MAX_OFFLINE_FILE_BYTES = 64 * 1024 * 1024
    _MAX_OFFLINE_TOTAL_BYTES = 512 * 1024 * 1024
    _MAX_OFFLINE_ENTRIES = 200_000

    def _offline_budget(self) -> _OfflineInputBudget:
        return _OfflineInputBudget(self.max_input_bytes, self.max_input_files)

    def _offline_files(self, path: str, suffixes: set[str] | None = None) -> Iterator[Path]:
        """Find exports without traversing links; rejected inputs affect completeness."""
        root = Path(path).expanduser().absolute()
        suffixes = self._OFFLINE_SUFFIXES if suffixes is None else suffixes
        try:
            if any(part.is_symlink() for part in (root, *root.parents)):
                raise ValueError("symlink input is not allowed")
            mode = root.stat().st_mode
        except (OSError, ValueError):
            self.ctx.error(f"{self.name}: offline input is missing, inaccessible, or a symlink")
            return
        if stat.S_ISREG(mode):
            yield root
            return
        if not stat.S_ISDIR(mode):
            self.ctx.error(f"{self.name}: offline input must be a regular file or directory")
            return
        count = 0
        files_seen = 0
        found = False

        def failed(_: OSError) -> None:
            self.ctx.error(f"{self.name}: offline directory could not be read")

        for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
            count += 1 + len(dirs) + len(files)
            if count > self._MAX_OFFLINE_ENTRIES:
                self.ctx.error(f"{self.name}: offline directory entry limit exceeded")
                return
            base = Path(directory)
            kept = []
            for name in sorted(dirs):
                if (base / name).is_symlink():
                    self.ctx.warn(f"{self.name}: offline input symlinks are skipped")
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(files):
                item = base / name
                try:
                    mode = item.lstat().st_mode
                except OSError:
                    failed(OSError())
                    continue
                if not stat.S_ISREG(mode):
                    self.ctx.warn(f"{self.name}: offline input symlinks or special files are skipped")
                    continue
                if item.suffix.lower() in suffixes:
                    found = True
                    if files_seen >= self.max_input_files:
                        self.ctx.warn(f"{self.name}: max_input_files ({self.max_input_files}) reached")
                        return
                    files_seen += 1
                    yield item
        if not found:
            self.ctx.error(f"{self.name}: offline directory contains no supported export files")

    def _read_offline_bytes(self, path: Path, budget: _OfflineInputBudget | None = None) -> bytes | None:
        """Open every path component without following links, then read a bounded file.

        A directory swapped to a symlink after traversal cannot redirect the open.
        NONBLOCK also prevents a replaced FIFO from hanging before descriptor checks.
        """
        parent_fd: int | None = None
        file_fd: int | None = None
        try:
            absolute = path.expanduser().absolute()
            if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
                raise ValueError("secure offline file access is unavailable on this platform")
            flags = os.O_RDONLY | os.O_NOFOLLOW
            parent_fd = os.open(absolute.anchor, flags | os.O_DIRECTORY)
            for part in absolute.parts[1:-1]:
                next_fd = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            file_fd = os.open(absolute.name, flags | os.O_NONBLOCK, dir_fd=parent_fd)
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("offline input is not a regular file")
            used = budget.bytes_read if budget is not None else getattr(self, "_offline_bytes_read", 0)
            remaining = (budget.max_bytes - used) if budget is not None else (self.max_input_bytes - used)
            limit = min(self.max_input_file_bytes, remaining, self._MAX_OFFLINE_FILE_BYTES, self._MAX_OFFLINE_TOTAL_BYTES - used)
            if before.st_size > limit:
                if budget is not None:
                    limit_name = "max_input_file_bytes" if self.max_input_file_bytes <= remaining else "max_input_bytes"
                    self.ctx.warn(f"{self.name}: {limit_name} reached; oversized offline input was skipped")
                    return None
                raise ValueError("offline input exceeds the byte limit")
            with os.fdopen(file_fd, "rb") as stream:
                file_fd = None
                raw = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
            if budget is None:
                self._offline_bytes_read = used + len(raw)
            else:
                budget.consume(len(raw))
            if len(raw) > limit:
                if budget is not None:
                    limit_name = "max_input_file_bytes" if self.max_input_file_bytes <= remaining else "max_input_bytes"
                    self.ctx.warn(f"{self.name}: {limit_name} reached; oversized offline input was skipped")
                    return None
                raise ValueError("offline input exceeds the byte limit")
            if any(getattr(before, key) != getattr(after, key) for key in ("st_size", "st_mtime_ns", "st_ctime_ns")):
                raise ValueError("offline input changed while being read")
            return raw
        except (OSError, ValueError) as exc:
            # Parser and OS exception strings may contain raw data or secret paths.
            reason = str(exc) if isinstance(exc, ValueError) else "offline input could not be securely read"
            self.ctx.error(f"{self.name}: {reason}")
            return None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if parent_fd is not None:
                os.close(parent_fd)

    def _read_offline_text(self, path: Path, budget: _OfflineInputBudget | None = None) -> str | None:
        raw = self._read_offline_bytes(path, budget)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            self.ctx.error(f"{self.name}: offline input is not valid UTF-8")
            return None

    def _iter_offline_files(
        self, path: str, budget: _OfflineInputBudget, suffixes: set[str] | None = None
    ) -> Iterator[Path]:
        for source in self._offline_files(path, suffixes):
            if budget.files_seen >= budget.max_files:
                if not budget.file_limit_warning_sent:
                    self.ctx.warn(f"{self.name}: max_input_files ({budget.max_files}) reached")
                    budget.file_limit_warning_sent = True
                return
            budget.files_seen += 1
            yield source

    def read_offline_text(self, path: str) -> str | None:
        """Read one bounded regular offline text file for specialized connectors."""
        source = Path(path).expanduser()
        if source.is_symlink():
            self.ctx.warn(f"{self.name}: offline input symlinks are skipped")
            return None
        if not source.is_file():
            raise ConnectorError(f"{self.name}: offline input must be a regular file")
        budget = self._offline_budget()
        budget.files_seen = 1
        return self._read_offline_text(source, budget)

    def _iter_bounded_lines(
        self, path: Path, budget: _OfflineInputBudget, *, compressed: bool = False
    ) -> Iterator[str]:
        """Read UTF-8 lines with secure opens and per-file, aggregate, and line caps."""
        parent_fd: int | None = None
        file_fd: int | None = None
        try:
            absolute = path.expanduser().absolute()
            if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
                raise ValueError("secure offline file access is unavailable on this platform")
            flags = os.O_RDONLY | os.O_NOFOLLOW
            parent_fd = os.open(absolute.anchor, flags | os.O_DIRECTORY)
            for part in absolute.parts[1:-1]:
                next_fd = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            file_fd = os.open(absolute.name, flags | os.O_NONBLOCK, dir_fd=parent_fd)
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                self.ctx.warn(f"{self.name}: offline input is not a regular file")
                return
            if before.st_size > min(self.max_input_file_bytes, self._MAX_OFFLINE_FILE_BYTES):
                self.ctx.warn(f"{self.name}: max_input_file_bytes ({self.max_input_file_bytes}) reached")
                return
            with os.fdopen(file_fd, "rb") as raw:
                file_fd = None
                stream = gzip.GzipFile(fileobj=raw, mode="rb") if compressed else raw
                file_bytes = 0
                try:
                    while True:
                        remaining = min(self.max_input_file_bytes - file_bytes, budget.remaining_bytes)
                        read_size = min(_MAX_OFFLINE_LINE_BYTES + 1, remaining + 1)
                        line = stream.readline(read_size)
                        if not line:
                            break
                        if len(line) > _MAX_OFFLINE_LINE_BYTES:
                            self.ctx.warn(f"{self.name}: max_input_line_bytes ({_MAX_OFFLINE_LINE_BYTES}) reached")
                            return
                        if len(line) > remaining:
                            limit_name = "max_input_file_bytes" if self.max_input_file_bytes - file_bytes <= budget.remaining_bytes else "max_input_bytes"
                            self.ctx.warn(f"{self.name}: {limit_name} reached; remaining offline input was skipped")
                            return
                        if not budget.consume(len(line)):
                            self.ctx.warn(f"{self.name}: max_input_bytes ({budget.max_bytes}) reached")
                            return
                        file_bytes += len(line)
                        try:
                            yield line.decode("utf-8-sig")
                        except UnicodeDecodeError:
                            self.ctx.error(f"{self.name}: offline input is not valid UTF-8")
                            return
                finally:
                    if compressed:
                        stream.close()
                after = os.fstat(raw.fileno())
                if any(getattr(before, key) != getattr(after, key) for key in ("st_size", "st_mtime_ns", "st_ctime_ns")):
                    self.ctx.error(f"{self.name}: offline input changed while being read")
        except (OSError, EOFError, gzip.BadGzipFile, ValueError, zlib.error) as exc:
            detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            self.ctx.warn(f"{self.name}: offline input could not be read ({detail})")
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if parent_fd is not None:
                os.close(parent_fd)

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        """Validate exports under shared input budgets and preserve valid records."""
        budget = self._offline_budget()
        for source in self._iter_offline_files(path, budget, self._OFFLINE_SUFFIXES):
            yield from self._load_offline_file(source, budget)

    def _load_offline_file(self, source: Path, budget: _OfflineInputBudget) -> Iterator[dict[str, Any]]:
        suffix = source.suffix.lower()
        def report(message: str) -> None:
            self.ctx.error(f"{self.name}: {message}")

        if suffix in {".jsonl", ".ndjson"}:
            saw_record = False
            for number, line in enumerate(self._iter_bounded_lines(source, budget), 1):
                if not line.strip():
                    continue
                saw_record = True
                try:
                    data = json.loads(line)
                except (json.JSONDecodeError, RecursionError, ValueError):
                    report(f"invalid JSON record at line {number}")
                    continue
                yield from self._unwrap(data, lambda message: report(f"line {number}: {message}"))
            if not saw_record:
                report("empty offline export; use [] for an empty inventory")
            return
        if suffix == ".csv":
            try:
                reader = csv.DictReader(self._iter_bounded_lines(source, budget), strict=True)
                fields = reader.fieldnames
                if not fields or any(not field.strip() for field in fields) or len(set(fields)) != len(fields):
                    report("CSV export needs unique, nonempty column names")
                    return
                for rec in reader:
                    if None in rec or any(value is None for value in rec.values()):
                        report(f"CSV row at line {reader.line_num} has the wrong number of columns")
                        continue
                    yield rec
            except csv.Error:
                report("invalid CSV export")
            return
        text = self._read_offline_text(source, budget)
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
            yield from self._unwrap(data, report)
            return
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            yield from self._json_lines(text, report)
        except (RecursionError, ValueError):
            report("invalid JSON export")
        else:
            yield from self._unwrap(data, report)

    _MAX_INVALID_LINE_ERRORS = 20

    @classmethod
    def _json_lines(cls, text: str, report: Callable[[str], None]) -> Iterator[dict[str, Any]]:
        lines = text.splitlines()
        first = next((line for line in lines if line.strip()), "")
        try:
            first_is_object = first.lstrip().startswith("{") and isinstance(json.loads(first), dict)
        except (json.JSONDecodeError, RecursionError, ValueError):
            first_is_object = False
        if not first_is_object:
            # A corrupted pretty-printed document is not a JSON-lines export;
            # one diagnostic is enough instead of one per line.
            report("invalid JSON export")
            return
        invalid = 0
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise TypeError("JSONL records must be objects")
            except (json.JSONDecodeError, RecursionError, ValueError, TypeError) as exc:
                invalid += 1
                if invalid <= cls._MAX_INVALID_LINE_ERRORS:
                    detail = "JSONL records must be objects" if isinstance(exc, TypeError) else "invalid JSON record"
                    report(f"line {number}: {detail}")
                elif invalid == cls._MAX_INVALID_LINE_ERRORS + 1:
                    report("further invalid records in this export are not listed individually")
                continue
            yield from cls._unwrap(data, lambda message: report(f"line {number}: {message}"))

    @staticmethod
    def _csv_records(text: str, report: Callable[[str], None]) -> Iterator[dict[str, Any]]:
        import io

        try:
            reader = csv.DictReader(io.StringIO(text), strict=True)
            fields = reader.fieldnames
            if not fields or any(not field.strip() for field in fields) or len(set(fields)) != len(fields):
                report("CSV export needs unique, nonempty column names")
                return
            for rec in reader:
                if None in rec or any(value is None for value in rec.values()):
                    report(f"CSV row at line {reader.line_num} has the wrong number of columns")
                    continue
                yield rec
        except csv.Error:
            report("invalid CSV export")

    @staticmethod
    def _valid_record(data: Any) -> bool:
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

    @staticmethod
    def _is_native_offline_record(data: dict[str, Any]) -> bool:
        identity_keys = {"id", "_id", "_kind", "name", "arn", "type", "kind", "resource", "resourceId"}
        return bool(identity_keys.intersection(data)) or data.get("object") not in (None, "list", "page")

    @staticmethod
    def _is_error_record(data: dict[str, Any]) -> bool:
        return "error" in data or bool(data.get("errors")) or data.get("ok") is False

    @staticmethod
    def _record_fields_valid(
        data: Any, *, strings: tuple[str, ...] = (), mappings: tuple[str, ...] = (),
        arrays: tuple[str, ...] = (), required: tuple[str, ...] = (),
    ) -> bool:
        """Check fields consumed by a provider without disclosing rejected values."""
        if not isinstance(data, dict) or BaseConnector._is_error_record(data):
            return False
        if any(not isinstance(data.get(key), str) or not data[key].strip() for key in required):
            return False
        for fields, expected in ((strings, str), (mappings, dict), (arrays, list)):
            if any(data.get(key) is not None and not isinstance(data[key], expected) for key in fields):
                return False
        return True

    @classmethod
    def _unwrap(cls, data: Any, on_error: Callable[[str], None] | None = None) -> Iterator[dict[str, Any]]:
        """Accept records or a common envelope, rejecting invalid shapes explicitly.

        Identified native records keep nested fields such as data/results intact.
        An envelope containing more than one collection is ambiguous, not empty.
        """
        def failed(message: str) -> None:
            if on_error is None:
                raise ConnectorError(message)
            on_error(message)

        wrappers = {
            "records", "items", "value", "data", "results", "resources", "logs", "entries",
            "plugins", "installations", "apps", "users", "members", "workflows", "scenarios",
            "aiAgents", "teamsApps", "servicePrincipals", "clients", "tokens", "agents", "bots",
            "flows", "Records", "logEvents", "hits",
        }
        wrappers.update(cls._OFFLINE_COLLECTION_KINDS)
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
                pagination_keys = (
                    "has_more", "next_page", "nextPage", "next_page_token", "nextPageToken",
                    "nextToken", "NextToken", "@odata.nextLink", "nextLink", "nextCursor",
                )
                if any(data.get(key) for key in pagination_keys):
                    failed("offline export contains an uncollected next page")
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
            if not BaseConnector._valid_record(item):
                failed(f"invalid export record {number}; expected a nonempty object with string keys")
                continue
            yield {**item, "_kind": record_kind} if record_kind else item

    # ------------------------------------------------------------------- run
    def _tee(self, records: Iterable[dict[str, Any]], path: str) -> Iterator[dict[str, Any]]:
        """Export sanitized records atomically, with owner-only permissions.

        The original records are used for analysis but are never written to disk.
        JWT inputs are excluded entirely via the ``_NoDump`` marker.
        """
        target = Path(path)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        written = 0
        rejected = False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for rec in records:
                    offset = fh.tell()
                    try:
                        encoded_chars = 0
                        for chunk in json.JSONEncoder(default=str).iterencode(sanitize(rec)):
                            encoded_chars += len(chunk)
                            if encoded_chars > self._MAX_OFFLINE_FILE_BYTES:
                                raise SanitizationLimitError("export record size limit exceeded")
                            fh.write(chunk)
                        fh.write("\n")
                    except SanitizationLimitError:
                        # iterencode may already have written part of this
                        # record. Roll it back before accepting any later one.
                        fh.seek(offset)
                        fh.truncate()
                        rejected = True
                        self.ctx.error(f"{self.name}: export record rejected: sanitization safety limit exceeded")
                        continue
                    written += 1
                    yield rec
            if written or not rejected:
                os.replace(temporary, target)
                self.ctx.dump_path = str(target)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def run(self) -> list[Finding]:
        stats = ScanStats(connector=self.name, started_at=now_iso())
        self.ctx.stats = stats
        self.ctx.dump_path = None
        self._offline_bytes_read = 0
        findings: list[Finding] = []
        try:
            if self.offline:
                records: Iterable[dict[str, Any]] = self.load_offline(str(self.ctx.input_path))
            else:
                self.check_requirements()
                records = self.collect()
            dump = self.ctx.config.get("_dump_path")
            if dump and not isinstance(self, _NoDump):
                records = self._tee(records, str(dump))
            for f in self.analyze(records):
                f.connector = self.name
                if f.provider is None:
                    f.provider = self.provider
                f.sanitize()
                findings.append(f)
        except ConnectorError as exc:
            stats.skipped = True
            stats.skip_reason = self.ctx.sanitize_message(str(exc))
            self.ctx.error(str(exc))
        except Exception as exc:  # noqa: BLE001 - connectors must never abort the whole scan
            self.ctx.error(f"{self.name}: {type(exc).__name__}: {exc}")
            self.log.debug("connector failure (%s)", type(exc).__name__)
        stats.finished_at = now_iso()
        stats.findings = len(findings)
        return findings


class _NoDump:
    """Exclude input records from exports (filesystem walks or sensitive token streams)."""
