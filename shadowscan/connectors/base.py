"""Connector base classes.

A connector scans one *surface* (code, identity, gateway, lowcode, saas, cloud,
endpoint, network, runtime) for one provider / data source and yields
:class:`Finding` objects.

Every connector supports two execution modes:

* **live** – talk to the provider's API with credentials from the config or
  environment (``collect()`` returns raw records);
* **offline** – read an export of the same records from a file (``input:``),
  which makes connectors usable without credentials, reproducible and testable.

``analyze()`` turns raw records into findings and is shared by both modes.
Reading and validating offline exports is implemented in
:mod:`shadowscan.connectors.offline`; ``BaseConnector`` keeps thin methods
under the names connectors override.

``BaseConnector`` also declares the *engine hooks*: class-level capabilities
the engine consults instead of special-casing connector names (per-root
incremental caching, the scan-wide instance-credential approval, and the
per-run identity key). Their defaults describe an ordinary connector.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import tempfile
import time
from _thread import LockType
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator
from collections.abc import Set as AbstractSet
from pathlib import Path
from threading import Event
from typing import Any, ClassVar, NoReturn

from shadowscan.connectors import offline as _offline
from shadowscan.connectors.offline import OfflineInputBudget
from shadowscan.models import Finding, ScanStats, Surface, now_iso
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.utils.files import changed_since
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize


class ConnectorError(RuntimeError):
    """Raised when a connector cannot run at all (bad config, missing creds)."""


# Historical names, still imported by connectors.
_OfflineInputBudget = OfflineInputBudget
_MAX_OFFLINE_LINE_BYTES = _offline.MAX_OFFLINE_LINE_BYTES


def _raise_connector_error(message: str) -> NoReturn:
    raise ConnectorError(message)


def _integer_option(value: Any, name: str, minimum: int, requirement: str) -> int:
    """An integer connector option: booleans, fractions, non-finite and non-numeric values are errors."""
    if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
        raise ConnectorError(f"{name} must be {requirement}")
    try:
        limit = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConnectorError(f"{name} must be {requirement}") from exc
    if limit < minimum:
        raise ConnectorError(f"{name} must be {requirement}")
    return limit


def _positive_limit(value: Any, name: str) -> int:
    return _integer_option(value, name, 1, "a positive integer")


def _non_negative_limit(value: Any, name: str) -> int:
    """Like ``_positive_limit``, for options such as look-back windows where 0 switches a feature off."""
    return _integer_option(value, name, 0, "a non-negative integer")


class _ExportReplayLimitError(ValueError):
    """A credential-free export limit diagnostic; analysis can still use the original record."""


class ConnectorContext:
    """Runtime context handed to a connector."""

    _MAX_DIAGNOSTICS = 1000

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        index: SignatureIndex | None = None,
        logger: logging.Logger | None = None,
        input_path: str | None = None,
        workdir: str | None = None,
        deadline: float | None = None,
        cancelled: Event | None = None,
        publication_lock: LockType | None = None,
        gateway_identity_key: bytes | None = None,
        gateway_identity_key_stable: bool = False,
    ) -> None:
        self.config: dict[str, Any] = dict(config or {})
        self.index: SignatureIndex = index or get_index()
        self.log = logger or logging.getLogger("shadowscan")
        self.input_path = input_path or self.config.get("input")
        self.workdir = workdir
        self.deadline = deadline
        self.cancelled = cancelled
        self.publication_lock = publication_lock
        # Private scan context, separate from user configuration and reports.
        # The key is random for each scan unless it is stable: the operator's
        # SHADOWSCAN_IDENTITY_KEY, which keeps identities equal across scans.
        self.gateway_identity_key = gateway_identity_key
        self.gateway_identity_key_stable = gateway_identity_key_stable
        self.stats: ScanStats | None = None
        self.dump_path: str | None = None
        self._resolved_config: dict[str, Any] = {}
        self._diagnostic_counts: dict[str, int] = {}

    def check_deadline(self) -> None:
        """Cooperative cancellation; cannot interrupt an in-flight SDK or plugin call."""
        if (self.cancelled is not None and self.cancelled.is_set()) or (
            self.deadline is not None and time.monotonic() >= self.deadline
        ):
            raise ConnectorError("connector completion deadline exceeded")

    def publish_replace(self, source: str | Path, target: str | Path) -> None:
        """Publish only while cancellation and replacement share the same lock.

        The supervisor sets ``cancelled`` under ``publication_lock``. A
        replacement either finishes before that decision or sees cancellation
        and leaves the prior artifact intact.
        """
        if self.publication_lock is None:
            self.check_deadline()
            os.replace(source, target)
            return
        with self.publication_lock:
            self.check_deadline()
            os.replace(source, target)

    def checked_records(self, records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        self.check_deadline()
        iterator = iter(records)
        while True:
            # A for-loop fetches the next record before entering its body.
            # Fetching may issue another SDK request, so check first as well.
            self.check_deadline()
            try:
                record = next(iterator)
            except StopIteration:
                return
            self.check_deadline()
            yield record

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
            # Use positional extraction: a short secret can also occur in a
            # wrapper key such as 'message', which the sanitizer must redact.
            values = [{**self.config, **self._resolved_config}, msg]
            result: str = sanitize(values, redact_short_secrets=True)[1]
            return result
        except SanitizationLimitError:
            if self.stats is not None:
                self.stats.incomplete = True
            return f"diagnostic omitted: sanitization safety limit exceeded {REDACTED}"

    def warn(self, msg: str, incomplete: bool = True) -> None:
        if self.stats is not None:
            self.stats.incomplete = self.stats.incomplete or incomplete
        self._diagnostic(msg, warning=True)

    def error(self, msg: str) -> None:
        if self.stats is not None:
            self.stats.incomplete = True
        self._diagnostic(msg, warning=False)

    def _diagnostic(self, msg: str, *, warning: bool) -> None:
        channel = "warnings" if warning else "errors"
        count = self._diagnostic_counts.get(channel, 0) + 1
        self._diagnostic_counts[channel] = count
        if count > self._MAX_DIAGNOSTICS + 1:
            return
        if count == self._MAX_DIAGNOSTICS + 1:
            msg = f"additional connector {channel} omitted: diagnostic limit reached"
        else:
            msg = self.sanitize_message(msg)
        # Upstream errors can echo credentials fetched inside an SDK, including
        # opaque values that neither our configuration nor regexes identify.
        # Application logs are often forwarded beyond the private scan report:
        # keep that sink independent of diagnostic text, even after redaction.
        if warning:
            self.log.warning("Connector warning recorded; inspect scan report for sanitized details")
        else:
            self.log.error("Connector error recorded; inspect scan report for sanitized details")
        if self.stats is not None:
            getattr(self.stats, channel).append(msg)

    def examined(self, n: int = 1) -> None:
        self.check_deadline()
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
    # Offline export limits that __init__ reads for every connector. The
    # `connectors` command lists them after config_keys; a connector whose
    # offline input is a code checkout rather than an export overrides with {}.
    shared_config_keys: ClassVar[dict[str, str]] = {
        "max_input_bytes": (
            "offline: maximum expanded bytes read across all input files "
            "(default 256 MiB, hard ceiling 512 MiB)"
        ),
        "max_input_file_bytes": (
            "offline: maximum expanded bytes read from one input file (default 32 MiB, hard ceiling 64 MiB)"
        ),
        "max_input_files": "offline: maximum files read from a directory input (default 10,000)",
    }
    offline_formats: ClassVar[str] = "JSON / JSONL / YAML / CSV export"
    _OFFLINE_COLLECTION_KINDS: ClassVar[dict[str, str]] = {}
    # Provider inventory records (cloud functions, apps, containers) carry
    # environment blocks that are mostly ordinary settings. Their values are
    # still withheld in exports, but they are not credentials to remove from
    # sibling fields such as ARNs. Tool/agent configuration parsers keep the
    # default: their env blocks are where secrets live.
    _ENV_VALUES_ARE_CONFIGURATION: ClassVar[bool] = False

    # ------------------------------------------------------------ engine hooks
    # Capabilities the engine consults instead of special-casing connector
    # names; the defaults describe an ordinary connector.

    # Jobs of a connector that sets this share one private key per scan run
    # (ConnectorContext.gateway_identity_key): identical sources in a report
    # get the same opaque identities, which separate runs cannot link unless
    # the operator supplies a stable SHADOWSCAN_IDENTITY_KEY.
    uses_run_identity_key: ClassVar[bool] = False

    # A built-in connector that reads vendor agent registries sets this so its
    # findings may carry ``metadata["registry_record"]`` (shadowscan.registries).
    # The engine drops that key from every other connector's findings, plugins
    # included even when they declare it: an approved record of a trusted
    # registry approves findings, so a record copied from an export or
    # repository by an unrelated parser, or emitted by third-party code, must
    # not count.
    emits_registry_records: ClassVar[bool] = False

    @classmethod
    def inherits_instance_credentials_approval(cls) -> bool:
        """Whether the engine sets ``allow_instance_credentials`` from the scan options.

        True for every cloud-surface connector, whether or not it documents
        the key: the registry holds each ``cloud.*`` name, plugins included,
        to that surface. Also true for any connector that documents the key
        in ``config_keys``. The scan-wide approval then replaces any value in
        the connector's own configuration.
        """
        return cls.surface == Surface.CLOUD or "allow_instance_credentials" in cls.config_keys

    @classmethod
    def cache_roots_separately(cls, roots: list[Any], root_ids: Any, *, labelled: bool) -> bool:
        """Whether an incremental multi-root ``paths`` scan may run and be cached per root.

        The engine then runs one job per root, so an unchanged repository is
        reused while its sibling is rescanned. Return False to collect all
        roots together. Raise ConnectorError for invalid roots: the engine
        marks the connector incomplete before construction or collection.
        """
        return False

    @classmethod
    def scanned_local_paths(cls, config: dict[str, Any]) -> list[str]:
        """Local files or directories this connector scans as the subject of the run, as configured.

        The engine compares them with the approval inventories of the scan: an inventory inside a
        scanned tree can be edited by the content under review (a pull request approving its own
        findings), so it warns. Empty for a connector that reads no local tree, including a
        filesystem connector that replays an ``input`` export.
        """
        return []

    def __init__(self, ctx: ConnectorContext) -> None:
        self.ctx = ctx
        self.index = ctx.index
        self.log = ctx.log
        self.max_input_bytes = min(
            _positive_limit(ctx.get("max_input_bytes", _offline.DEFAULT_MAX_INPUT_BYTES), "max_input_bytes"),
            self._MAX_OFFLINE_TOTAL_BYTES,
        )
        self.max_input_file_bytes = min(
            _positive_limit(
                ctx.get("max_input_file_bytes", _offline.DEFAULT_MAX_INPUT_FILE_BYTES), "max_input_file_bytes"
            ),
            self._MAX_OFFLINE_FILE_BYTES,
        )
        self.max_input_files = _positive_limit(
            ctx.get("max_input_files", _offline.DEFAULT_MAX_INPUT_FILES), "max_input_files"
        )

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
                f"(install '.[cloud]' from the reviewed Project Nexus checkout) or use offline input"
            )

    @abstractmethod
    def collect(self) -> Iterable[dict[str, Any]]:
        """Fetch raw records from the live source."""

    @abstractmethod
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        """Turn raw records into findings."""

    # --------------------------------------------------------- offline input
    # Parsing and reading live in shadowscan.connectors.offline. These thin
    # methods keep the names connectors override and tests replace; the
    # offline functions call back through them.
    _OFFLINE_SUFFIXES: ClassVar[set[str]] = set(_offline.OFFLINE_SUFFIXES)
    _MAX_OFFLINE_FILE_BYTES: ClassVar[int] = _offline.MAX_OFFLINE_FILE_BYTES
    _MAX_OFFLINE_TOTAL_BYTES: ClassVar[int] = _offline.MAX_OFFLINE_TOTAL_BYTES
    _MAX_OFFLINE_ENTRIES: ClassVar[int] = _offline.MAX_OFFLINE_ENTRIES
    _MAX_INVALID_LINE_ERRORS: ClassVar[int] = _offline.MAX_INVALID_LINE_ERRORS
    _MAX_LISTED_UNSUPPORTED: ClassVar[int] = _offline.MAX_LISTED_UNSUPPORTED

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        """Validate exports under shared input budgets and preserve valid records."""
        return _offline.load_offline(self, path)

    def _offline_budget(self) -> OfflineInputBudget:
        return OfflineInputBudget(self.max_input_bytes, self.max_input_files)

    @staticmethod
    def _empty_export_message(budget: OfflineInputBudget) -> str:
        return _offline.empty_export_message(budget)

    def _offline_files(self, path: str, suffixes: AbstractSet[str] | None = None) -> Iterator[Path]:
        return _offline.offline_files(self, path, suffixes)

    def _iter_offline_files(
        self, path: str, budget: OfflineInputBudget, suffixes: AbstractSet[str] | None = None
    ) -> Iterator[Path]:
        return _offline.iter_offline_files(self, path, budget, suffixes)

    def _read_offline_bytes(self, path: Path, budget: OfflineInputBudget | None = None) -> bytes | None:
        # Passed from here so this module's changed_since stays the one seam
        # tests patch to simulate a file rewritten during either reader.
        return _offline.read_offline_bytes(self, path, budget, changed=changed_since)

    def _read_offline_text(self, path: Path, budget: OfflineInputBudget | None = None) -> str | None:
        return _offline.read_offline_text(self, path, budget)

    def _iter_bounded_lines(
        self, path: Path, budget: OfflineInputBudget, *, compressed: bool = False
    ) -> Iterator[str]:
        return _offline.iter_bounded_lines(self, path, budget, compressed=compressed, changed=changed_since)

    def _load_offline_file(self, source: Path, budget: OfflineInputBudget) -> Iterator[dict[str, Any]]:
        return _offline.load_offline_file(self, source, budget)

    @classmethod
    def _bounded_diagnostics(cls, report: Callable[[str], None]) -> Callable[[str], None]:
        return _offline.bounded_diagnostics(report, cls._MAX_INVALID_LINE_ERRORS)

    @classmethod
    def _json_lines(cls, text: str, report: Callable[[str], None]) -> Iterator[dict[str, Any]]:
        return _offline.json_lines(cls, text, report)

    @staticmethod
    def _csv_records(text: str, report: Callable[[str], None]) -> Iterator[dict[str, Any]]:
        return _offline.csv_records(text, report)

    @staticmethod
    def _is_csv_provider_error(record: dict[str, str]) -> bool:
        return _offline.is_csv_provider_error(record)

    @staticmethod
    def _valid_record(data: Any) -> bool:
        return _offline.valid_record(data)

    @staticmethod
    def _is_native_offline_record(data: dict[str, Any]) -> bool:
        return _offline.is_native_offline_record(data)

    @staticmethod
    def _is_error_record(data: dict[str, Any]) -> bool:
        return _offline.is_error_record(data)

    @staticmethod
    def _record_fields_valid(
        data: Any,
        *,
        strings: tuple[str, ...] = (),
        mappings: tuple[str, ...] = (),
        arrays: tuple[str, ...] = (),
        required: tuple[str, ...] = (),
    ) -> bool:
        return _offline.record_fields_valid(
            data, strings=strings, mappings=mappings, arrays=arrays, required=required
        )

    @staticmethod
    def _offline_pagination_issue(data: dict[str, Any]) -> str | None:
        return _offline.offline_pagination_issue(data)

    @classmethod
    def _unwrap(cls, data: Any, on_error: Callable[[str], None] | None = None) -> Iterator[dict[str, Any]]:
        """Accept records or a common envelope; without ``on_error`` a rejection raises ConnectorError."""
        return _offline.unwrap(cls, data, on_error if on_error is not None else _raise_connector_error)

    # ------------------------------------------------------------------- run
    def _tee(self, records: Iterable[dict[str, Any]], path: str) -> Iterator[dict[str, Any]]:
        """Export sanitized records atomically, with owner-only permissions.

        The original records are used for analysis but are never written to disk.
        JWT inputs are excluded entirely via the ``_NoDump`` marker.
        Every published line and file fits the same connector's replay byte
        limits. Export byte/JSON encoding failures mark collection incomplete
        while leaving original records available for analysis. Sanitizer safety
        rejection skips the unsafe record before either export or analysis.
        Any rejected record prevents publication of the entire new export.
        """
        target = Path(path)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        written = 0
        rejected = False
        max_file_bytes = min(self.max_input_file_bytes, self.max_input_bytes)
        encoder = json.JSONEncoder(default=str, allow_nan=False)
        try:
            with os.fdopen(fd, "wb") as fh:
                for rec in records:
                    offset = fh.tell()
                    try:
                        clean = sanitize(rec, env_values_are_secrets=not self._ENV_VALUES_ARE_CONFIGURATION)
                    except SanitizationLimitError:
                        rejected = True
                        self.ctx.error(
                            f"{self.name}: export record rejected: sanitization safety limit exceeded"
                        )
                        continue
                    try:
                        record_bytes = 0
                        for chunk in encoder.iterencode(clean):
                            self.ctx.check_deadline()
                            encoded = chunk.encode("utf-8")
                            record_bytes += len(encoded)
                            # The newline is part of the importer's line and
                            # file byte budgets, including at an exact boundary.
                            if record_bytes + 1 > _MAX_OFFLINE_LINE_BYTES:
                                raise _ExportReplayLimitError(
                                    "encoded record exceeds the replay line byte limit"
                                )
                            if offset + record_bytes + 1 > max_file_bytes:
                                raise _ExportReplayLimitError(
                                    "encoded export exceeds the replay file byte limit"
                                )
                            fh.write(encoded)
                        fh.write(b"\n")
                    except _ExportReplayLimitError as exc:
                        # Remove the partial line before considering later
                        # records. Export limits do not erase valid analysis.
                        fh.seek(offset)
                        fh.truncate()
                        rejected = True
                        self.ctx.error(f"{self.name}: export record omitted: {exc}")
                    except (TypeError, ValueError):
                        # JSON encoding exceptions can echo data (for example
                        # an unsupported mapping key). Keep only a fixed reason.
                        fh.seek(offset)
                        fh.truncate()
                        rejected = True
                        self.ctx.error(f"{self.name}: export record omitted: record is not strict JSON")
                    else:
                        written += 1
                    yield rec
                if not written and not rejected:
                    # A zero-byte file is not an explicitly empty inventory.
                    empty = b'{"records": []}\n'
                    if len(empty) > max_file_bytes:
                        rejected = True
                        self.ctx.error(f"{self.name}: empty export exceeds the replay file byte limit")
                    else:
                        fh.write(empty)
            if not rejected:
                self.ctx.publish_replace(temporary, target)
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
            self.ctx.check_deadline()
            if self.offline:
                records: Iterable[dict[str, Any]] = self.load_offline(str(self.ctx.input_path))
            else:
                self.check_requirements()
                records = self.collect()
            records = self.ctx.checked_records(records)
            dump = self.ctx.config.get("_dump_path")
            if dump and not isinstance(self, _NoDump):
                records = self._tee(records, str(dump))
            for f in self.analyze(records):
                self.ctx.check_deadline()
                f.connector = self.name
                if f.provider is None:
                    f.provider = self.provider
                try:
                    f.sanitize()
                except SanitizationLimitError:
                    # One oversized finding must not discard the others (for
                    # example a credential finding emitted after an aggregate
                    # that exceeds the sanitizer's output budget).
                    self.ctx.error(f"{self.name}: finding omitted: sanitization safety limit exceeded")
                    continue
                findings.append(f)
            self.ctx.check_deadline()
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
