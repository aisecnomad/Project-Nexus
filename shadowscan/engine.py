"""Scan orchestration: run connectors, merge, correlate, reconcile with the inventory, score."""

from __future__ import annotations

import base64
import fnmatch
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Lock
from typing import Any

from shadowscan import __version__
from shadowscan.autonomy import apply_autonomy
from shadowscan.comparison import IDENTITY_KEY_ENV, build_collection_scope
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig, validate_min_confidence
from shadowscan.connectors import ConnectorContext, builtin_connector_names, get_connector_class
from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.correlation import correlate, correlate_lifecycle, correlate_runtime
from shadowscan.errors import SetupError
from shadowscan.incremental import IncrementalCache
from shadowscan.merge import merge
from shadowscan.models import Finding, ScanResult, ScanStats, now_iso
from shadowscan.registry import Inventory, InventoryEntry
from shadowscan.risk import RiskPolicy, assess, provider_ids
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.signatures.loader import signature_source_digest
from shadowscan.triage import Triage, TriageConfigError
from shadowscan.utils.credential_identity import reset_credential_identity_key, set_credential_identity_key
from shadowscan.utils.http import (
    reset_allow_private_origin,
    reset_request_deadline,
    set_allow_private_origin,
    set_request_deadline,
)
from shadowscan.utils.output import prepare_private_directory, write_private_text
from shadowscan.utils.redaction import SanitizationLimitError, sanitize

log = logging.getLogger("shadowscan.engine")

ProgressFn = Callable[[str, str], None]  # (connector id, message)
_Job = tuple[int, ConnectorSpec]  # (1-based configuration ordinal, connector)
_JobResult = tuple[ConnectorSpec, list[Finding], ScanStats]
# A job's connector class, or the exception its lookup raised.
_Resolved = type[BaseConnector] | Exception

_TIMEOUT_MESSAGE = "connector_timeout completion deadline exceeded; results discarded"
_TIMEOUT_WARNING = (
    "Cancellation is cooperative: an in-flight SDK, plugin call, or filesystem "
    "replacement may continue. A cache or record artifact whose replacement "
    "started before cancellation may appear after this incomplete report; do not "
    "use timed-out artifacts as accepted results. Use an external process timeout "
    "when a hard execution limit is required."
)

# The operator's stable identity key comes from IDENTITY_KEY_ENV only, never
# from a configuration field.
_MIN_IDENTITY_KEY_BYTES = 32
_HEX_KEY = re.compile(r"(?:[0-9A-Fa-f]{2})+")


def _stable_identity_key() -> bytes | None:
    """Decode ``SHADOWSCAN_IDENTITY_KEY``, or None when it is not set.

    Gateway pseudonyms and finding IDs use a random key per scan unless the
    operator supplies at least 32 secret bytes, encoded as ``hex:<value>`` or
    ``base64:<value>``; prefix names are case-insensitive. Bare encodings are
    accepted only when exactly one canonical encoding is valid; ambiguous
    values require a prefix. The key must never reach a log, report, cache,
    record export or diagnostic, and a set but unusable value stops the scan
    rather than silently falling back to unlinkable per-scan identities.
    """
    value = os.environ.get(IDENTITY_KEY_ENV)
    if value is None:
        return None
    text = value.strip()
    encoding: str | None = None
    if text[:4].casefold() == "hex:":
        encoding, text = "hex", text[4:]
    elif text[:7].casefold() == "base64:":
        encoding, text = "base64", text[7:]

    try:
        hex_encoded = bool(_HEX_KEY.fullmatch(text))
        base64_key: bytes | None = None
        if encoding != "hex":
            try:
                base64_key = base64.b64decode(text, validate=True)
                if base64.b64encode(base64_key).decode("ascii") != text:
                    base64_key = None
            except ValueError:  # binascii.Error, or text that is not ASCII
                pass
        if encoding is None and hex_encoded and base64_key is not None:
            raise SetupError(
                f"{IDENTITY_KEY_ENV} has an ambiguous encoding; "
                "ambiguous bare values are no longer accepted. Use an explicit "
                "hex:<value> or base64:<value> prefix"
            )
        if encoding == "hex" or (encoding is None and hex_encoded):
            key = bytes.fromhex(text)
        elif base64_key is not None:
            key = base64_key
        else:
            key = b""
    except ValueError:  # binascii.Error, or text that is not ASCII
        key = b""
    if len(key) < _MIN_IDENTITY_KEY_BYTES:
        # SetupError text is printed verbatim: name the variable, never its value.
        raise SetupError(
            f"{IDENTITY_KEY_ENV} must decode to at least {_MIN_IDENTITY_KEY_BYTES} bytes using "
            "hex:<value> or base64:<value>"
        )
    return key


@dataclass
class _JobState:
    started_at: str | None = None
    deadline: float | None = None
    completed_at: float | None = None
    cancelled: Event = field(default_factory=Event)
    publication_lock: Lock = field(default_factory=Lock)
    isolated_process: bool = False
    kill_process: Callable[[], None] | None = None

    @property
    def supervision_deadline(self) -> float | None:
        if self.deadline is None:
            return None
        # The process runner enforces the original deadline, including IPC.
        # Retain a last-resort parent guard while allowing bounded TERM/KILL
        # cleanup to finish before treating its supervision thread as abandoned.
        return self.deadline + (2.0 if self.isolated_process else 0.0)


def _hooks(resolved: _Resolved) -> type[BaseConnector]:
    """The class whose declared engine hooks apply to a job.

    A failed lookup, or a stand-in class outside the connector hierarchy, gets
    BaseConnector's defaults; ``_ConnectorRunner._collect`` still reports a
    failed lookup as an incomplete connector.
    """
    if isinstance(resolved, type) and issubclass(resolved, BaseConnector):
        return resolved
    return BaseConnector


def _retain_sanitizable(candidates: list[Finding]) -> tuple[list[Finding], int]:
    """Keep findings the sanitizer can bound; count the ones it must omit."""
    retained = []
    omitted = 0
    for finding in candidates:
        try:
            finding.sanitize()
        except SanitizationLimitError:
            omitted += 1
            continue
        retained.append(finding)
    return retained, omitted


class _ExportLedger:
    """Record-export manifest entries reported by connector workers of one run."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._entries: list[dict[str, Any]] = []

    def record(self, state: _JobState, entry: dict[str, Any]) -> None:
        with self._lock:
            if not state.cancelled.is_set():
                self._entries.append(entry)

    def entries(self, jobs: list[_Job], timed_out: set[int]) -> list[dict[str, Any]]:
        """Replace anything a timed-out connector reported with an explicit failure entry."""
        with self._lock:
            entries = [entry for entry in self._entries if entry["config_ordinal"] not in timed_out]
            for number, spec in jobs:
                if number in timed_out:
                    entries.append(
                        {
                            "config_ordinal": number,
                            "part": f"{number:04d}",
                            "connector": spec.name,
                            "label": spec.label,
                            "filename": None,
                            "complete": False,
                            "exported": False,
                        }
                    )
            return entries


class _ConnectorRunner:
    """Run one configured connector on a worker thread and shape its result.

    Everything here executes under the connector deadline. Cache reuse,
    per-repository splitting, sanitization of findings and diagnostics, and
    export bookkeeping all count towards the measured connector runtime.
    """

    def __init__(
        self, engine: Engine, cache: IncrementalCache, dump_directory: Path | None, exports: _ExportLedger
    ) -> None:
        self._engine = engine
        self._config = engine.config
        self._index = engine.index
        self._cache = cache
        self._dump_directory = dump_directory
        self._exports = exports
        # Identical sources in one report share an opaque identity, while
        # separate Engine.run calls cannot link redacted caller/scope IDs
        # unless the operator supplied a stable key.
        self._identity_key_stable = engine._identity_key is not None
        self._run_identity_key = engine._identity_key or secrets.token_bytes(32)

    def run(self, number: int, spec: ConnectorSpec, state: _JobState) -> _JobResult:
        state.started_at = now_iso()
        timeout = self._config.connector_timeout_seconds
        state.deadline = time.monotonic() + timeout
        try:
            if state.isolated_process:
                from shadowscan.plugin_process import run_plugin_process

                return run_plugin_process(self, number, spec, state)
            return self._run_job(number, spec, state)
        except KeyboardInterrupt:
            raise
        except BaseException as exc:  # noqa: BLE001 - e.g. sys.exit() while importing a plugin
            # The supervisor re-raises a worker's exception in the main
            # thread, so a SystemExit here would end the scan without a report.
            message = f"{spec.name}: connector worker failed ({type(exc).__name__})"
            log.warning("connector failed; diagnostic recorded in incomplete scan stats")
            stats = ScanStats(
                connector=spec.id,
                started_at=state.started_at or now_iso(),
                finished_at=now_iso(),
                incomplete=True,
                skipped=True,
                skip_reason=message,
                errors=[message],
            )
            return spec, [], stats
        finally:
            # Include sanitization, cache writes and callbacks in the
            # measured runtime, even if completion precedes the next poll.
            state.completed_at = time.monotonic()

    def _resolve(self, name: str, state: _JobState) -> _Resolved:
        """Look up a job's connector class once; ``_collect`` reports a failure.

        The lookup imports an approved plugin, so as in collection it runs
        under the scan's private-origin policy and not at all for a job that
        is already out of time: ``_collect`` reports the deadline first.
        """
        if state.cancelled.is_set() or (state.deadline is not None and time.monotonic() >= state.deadline):
            return ConnectorError("connector completion deadline exceeded")
        origin_token = set_allow_private_origin(self._config.allow_private_origin)
        try:
            if self._config.plugins:
                return get_connector_class(name, allowed_plugins=self._config.plugins)
            return get_connector_class(name)
        except Exception as exc:  # noqa: BLE001 - reported as an incomplete connector by _collect
            return exc
        except BaseException as exc:  # noqa: BLE001 - plugin code calling sys.exit() is a connector failure
            return _hook_failure(name, "connector lookup", exc)
        finally:
            reset_allow_private_origin(origin_token)

    def _run_job(self, number: int, spec: ConnectorSpec, state: _JobState) -> _JobResult:
        resolved = self._resolve(spec.name, state)
        roots = spec.config.get("paths")
        root_ids = spec.config.get("root_ids")
        if isinstance(roots, list):
            split, resolved = self._split_roots(spec, resolved, roots, root_ids)
            if split:
                return self._run_split(number, spec, resolved, state, roots, root_ids)
        return self._run_one(spec, resolved, f"{number:04d}", state)

    def _split_roots(
        self, spec: ConnectorSpec, resolved: _Resolved, roots: list[Any], root_ids: Any
    ) -> tuple[bool, _Resolved]:
        """Decide whether a multi-root scan can be cached per repository.

        Also returns the job's connector class, or the failure ``_run_one``
        reports as an incomplete connector when the class's hook fails.
        """
        if not (self._config.incremental and not spec.config.get("input") and len(roots) > 1):
            return False, resolved
        if isinstance(resolved, Exception):
            return False, resolved  # _run_one reports the lookup failure as incomplete
        try:
            labelled = bool(spec.label or spec.config.get("label"))
            if not _hooks(resolved).cache_roots_separately(roots, root_ids, labelled=labelled):
                return False, resolved
        except ConnectorError as exc:
            # A failed hook must stop collection even if construction would
            # succeed. Built-in validation text is sanitized by _run_one;
            # arbitrary plugin hook messages may contain credentials.
            failure = (
                exc
                if spec.name in builtin_connector_names()
                else _hook_failure(spec.name, "cache_roots_separately()", exc)
            )
            return False, failure
        except BaseException as exc:  # noqa: BLE001 - a failing plugin hook is a connector failure
            return False, _hook_failure(spec.name, "cache_roots_separately()", exc)
        try:
            return self._cache.supports_connector(spec, resolved), resolved
        except Exception:  # noqa: BLE001 - _run_one reports import failures as incomplete
            return False, resolved

    def _run_split(
        self,
        number: int,
        spec: ConnectorSpec,
        resolved: _Resolved,
        state: _JobState,
        roots: list[Any],
        root_ids: Any,
    ) -> _JobResult:
        # Repositories are independent cache units: modifying repo B must not
        # force expensive analysis of unchanged repo A in the same connector.
        combined: list[Finding] = []
        parts: list[ScanStats] = []
        for root_number, root in enumerate(roots, 1):
            child_config = {k: v for k, v in spec.config.items() if k not in {"paths", "root_ids"}}
            child_config["path"] = root
            # A cache split retains both the `paths` identity and its
            # optional stable root ID from the original configuration.
            child_config["_shared_label_roots"] = True
            if root_ids is not None:
                child_config["_root_id"] = root_ids[root_number - 1]
            child = ConnectorSpec(name=spec.name, config=child_config, label=spec.label)
            dump_key = f"{number:04d}-{root_number:04d}"
            _, child_findings, child_stats = self._run_one(child, resolved, dump_key, state)
            combined.extend(child_findings)
            parts.append(child_stats)
        cached_count = sum(s.cached for s in parts)
        stats = ScanStats(
            connector=spec.id,
            started_at=min(s.started_at for s in parts),
            finished_at=now_iso(),
            findings=len(combined),
            objects_examined=sum(s.objects_examined for s in parts),
            errors=[e for s in parts for e in s.errors],
            warnings=[w for s in parts for w in s.warnings],
            incomplete=any(s.incomplete or s.skipped or s.errors for s in parts),
            skipped=all(s.skipped for s in parts),
            cached=cached_count == len(parts),
        )
        if cached_count:
            stats.warnings.append(
                f"incremental: reused {cached_count}/{len(parts)} unchanged repository roots"
            )
        return spec, combined, stats

    def _connector_config(
        self, spec: ConnectorSpec, inherits_approval: bool, dump_key: str
    ) -> dict[str, Any]:
        cfg = dict(spec.config)
        if "allow_instance_credentials" in cfg or inherits_approval:
            # Scan-wide approval cannot be bypassed by a connector-level key.
            cfg["allow_instance_credentials"] = self._config.allow_instance_credentials
        if spec.label:
            cfg.setdefault("label", spec.label)
        if self._dump_directory:
            label = re.sub(r"[^A-Za-z0-9_-]", "_", spec.id)[:80] or "connector"
            cfg["_dump_path"] = os.path.join(self._dump_directory, f"{dump_key}-{label}.jsonl")
        return cfg

    def _run_one(
        self, spec: ConnectorSpec, resolved: _Resolved, dump_key: str, state: _JobState
    ) -> _JobResult:
        self._engine._report_progress(spec.id, "starting")
        hooks = _hooks(resolved)
        try:
            inherits_approval = hooks.inherits_instance_credentials_approval()
        except BaseException as exc:  # noqa: BLE001 - a failing plugin hook is a connector failure
            # _collect raises the failure before the connector is constructed.
            resolved = _hook_failure(spec.name, "inherits_instance_credentials_approval()", exc)
            hooks, inherits_approval = _hooks(resolved), True
        cfg = self._connector_config(spec, inherits_approval, dump_key)
        identity_key = self._run_identity_key if hooks.uses_run_identity_key else None
        ctx = ConnectorContext(
            config=cfg,
            index=self._index,
            workdir=self._config.workdir,
            deadline=state.deadline,
            cancelled=state.cancelled,
            publication_lock=state.publication_lock,
            gateway_identity_key=identity_key,
            gateway_identity_key_stable=identity_key is not None and self._identity_key_stable,
        )
        fs: list[Finding] = []
        started_at = now_iso()
        origin_token = set_allow_private_origin(self._config.allow_private_origin)
        limits_token = set_request_deadline(state.deadline, state.cancelled)
        credential_token = set_credential_identity_key(self._run_identity_key)
        try:
            st, reused = self._collect(spec, resolved, ctx, started_at, fs)
            if reused:
                return spec, fs, st
        except KeyboardInterrupt:
            raise
        except BaseException as exc:  # noqa: BLE001 - isolate construction and collection failures,
            # including a plugin's sys.exit(), which must not end the scan as a clean pass.
            message = ctx.sanitize_message(_failure_message(spec, exc))
            st = ctx.stats or ScanStats(connector=spec.id, started_at=started_at)
            st.connector = spec.id
            st.finished_at = now_iso()
            st.incomplete = True
            st.skipped = not fs
            st.skip_reason = message if st.skipped else None
            st.errors.append(message)
            log.warning("connector failed; diagnostic recorded in incomplete scan stats")
        finally:
            reset_credential_identity_key(credential_token)
            reset_request_deadline(limits_token)
            reset_allow_private_origin(origin_token)
        st.findings = len(fs)
        _sanitize_diagnostics(st)
        if self._dump_directory and not state.cancelled.is_set():
            exported = ctx.dump_path == cfg.get("_dump_path") and ctx.dump_path is not None and not st.skipped
            self._exports.record(
                state,
                {
                    "config_ordinal": int(dump_key.split("-")[0]),
                    "part": dump_key,
                    "connector": spec.name,
                    "label": spec.label,
                    "filename": Path(ctx.dump_path).name if exported and ctx.dump_path else None,
                    "complete": not (st.incomplete or st.skipped or st.errors),
                    "exported": exported,
                },
            )
        if not state.cancelled.is_set():
            self._engine._report_progress(spec.id, f"{len(fs)} findings")
        return spec, fs, st

    def _collect(
        self,
        spec: ConnectorSpec,
        resolved: _Resolved,
        ctx: ConnectorContext,
        started_at: str,
        fs: list[Finding],
    ) -> tuple[ScanStats, bool]:
        """Reuse a cached result or collect afresh, appending findings to ``fs``.

        ``fs`` is filled in place so a failure part-way through still reports
        what was already retained. The flag says an unchanged cached result
        was returned, which skips the post-collection bookkeeping.
        """
        cache = self._cache
        ctx.check_deadline()
        if isinstance(resolved, Exception):
            raise resolved
        cls = resolved
        # Constructor validation still runs before a cached result is used.
        connector = cls(ctx)
        snapshot = (
            cache.snapshot(spec, check_deadline=ctx.check_deadline, deadline=ctx.deadline)
            if cache.supports_connector(spec, cls)
            else None
        )
        cached = cache.load(spec, snapshot, check_deadline=ctx.check_deadline) if snapshot else None
        if cached is not None:
            cached_findings, st = cached
            fs.extend(cached_findings)
            if cache.snapshot(spec, check_deadline=ctx.check_deadline, deadline=ctx.deadline) == snapshot:
                ctx.check_deadline()
                self._engine._report_progress(spec.id, f"{len(fs)} findings (unchanged input; cached)")
                return st, True
            fs.clear()
        collected = connector.run()
        ctx.check_deadline()
        st = ctx.stats or ScanStats(
            connector=spec.id,
            started_at=started_at,
            finished_at=now_iso(),
            incomplete=True,
            errors=["connector did not report completion status"],
        )
        st.connector = spec.id
        st.incomplete = st.incomplete or bool(st.errors) or st.skipped
        for finding in collected:
            try:
                finding.sanitize()
            except SanitizationLimitError:
                st.incomplete = True
                st.errors.append("finding omitted: sanitization safety limit exceeded")
                continue
            fs.append(finding)
        if snapshot and not st.incomplete:
            # Do not attach a result to a digest computed before an input
            # changed during collection. Preserve the findings, mark the
            # scan incomplete and require a fresh scan for security gates.
            if cache.snapshot(spec, check_deadline=ctx.check_deadline, deadline=ctx.deadline) == snapshot:
                ctx.check_deadline()
                cache.save(
                    snapshot, fs, st, check_deadline=ctx.check_deadline, publish_replace=ctx.publish_replace
                )
            else:
                st.incomplete = True
                st.errors.append("static input changed during the scan; rerun required")
        return st, False


def _hook_failure(name: str, call: str, exc: BaseException) -> ConnectorError:
    """The error ``_collect`` reports when plugin code fails outside collection.

    Covers looking up a connector class and calling its engine hooks. A
    KeyboardInterrupt still ends the scan. Only the exception type is kept,
    as for a plugin that fails at import: a ``SystemExit`` argument or other
    exception text from plugin code may carry a credential.
    """
    if isinstance(exc, KeyboardInterrupt):
        raise exc
    return ConnectorError(f"{name}: {call} raised {type(exc).__name__}")


def _failure_message(spec: ConnectorSpec, exc: BaseException) -> str:
    """Describe a connector failure once, without a repr-quoted KeyError or a doubled connector prefix."""
    if isinstance(exc, KeyError) and len(exc.args) == 1 and isinstance(exc.args[0], str):
        return f"{spec.name}: {exc.args[0]}"
    if type(exc) is ConnectorError:
        # The message a connector writes for itself, as BaseConnector.run reports it.
        text = str(exc)
        return text if text.startswith(f"{spec.name}:") else f"{spec.name}: {text}"
    detail = str(exc)
    return f"{spec.name}: {type(exc).__name__}" + (f": {detail}" if detail else "")


def _sanitize_diagnostics(st: ScanStats) -> None:
    try:
        # Preserve credential context across diagnostics until every field has
        # been checked. Redacting errors first would erase a known opaque value
        # before an identical copy in warnings or the skip reason is examined.
        st.errors, st.warnings, (st.skip_reason,) = sanitize((st.errors, st.warnings, (st.skip_reason,)))
    except SanitizationLimitError:
        st.incomplete = True
        st.errors = ["connector diagnostics omitted: sanitization safety limit exceeded"]
        st.warnings = []
        st.skip_reason = None


_MAX_INVENTORY_WARNINGS = 20
# Finding resources of very different shapes. Probe matches are advisory
# evidence of broad scope, not proof that a pattern matches every resource.
_RESOURCE_PROBES = (
    "a",
    "Z9",
    "SHADOWSCAN",
    "1234567890",
    "github:acme/agent",
    "arn:aws:iam::123456789012:role/agent",
    "a/b[c]",
    "]",
    "[",
    "-",
    " ",
    "/",
    "~",
    "\x7f",
    r"\resource",
    "line\n\tbreak",
    "\u00e9",
    "\U0001f600",
    "x" * 512,
    "0" * 1024,
)


def _resource_pattern_breadth(pattern: str) -> str | None:
    """Distinguish proven universal globs from suspiciously broad probe matches."""
    # Only a nonempty run of stars proves universal matching, including the
    # empty string. Question marks impose a minimum length; surrounding spaces
    # are literal glob data and must not be removed during classification.
    if pattern and all(character == "*" for character in pattern):
        return "universal"
    matches = sum(fnmatch.fnmatchcase(probe, pattern) for probe in _RESOURCE_PROBES)
    return "near-universal" if matches >= len(_RESOURCE_PROBES) - 1 else None


def _scanned_roots(specs: list[ConnectorSpec]) -> list[tuple[str, Path]]:
    """Local source trees scanned in this run, as configured and as resolved."""
    roots = []
    for spec in specs:
        try:
            # Built-in connectors only: this lookup never imports a plugin outside a job's deadline.
            declared = _hooks(get_connector_class(spec.name)).scanned_local_paths(spec.config)
        except Exception:  # noqa: BLE001 - an unknown or unapproved connector declares no tree
            continue
        roots += [(path, Path(os.path.realpath(path))) for path in declared]
    return roots


def _inventory_warnings(
    paths: list[str], inventory: Inventory | None, specs: list[ConnectorSpec]
) -> list[str]:
    """Approvals that scanned content could change, or whose resource scope is broad.

    Also lists cards whose autonomy level was not read because they lack schema_version 2.
    Advisory, not incomplete: ``shadowscan code . --inventory agent-card.yaml``
    is legitimate locally, but in CI a pull request can edit an inventory kept
    in the scanned tree and approve its own findings.
    """
    if inventory is None:
        return []
    warnings: list[str] = []
    candidates = [(path, Path(os.path.realpath(path))) for path in paths]
    # A directory or glob outside a scanned tree can still load files from inside it.
    candidates += [(source, Path(os.path.realpath(source))) for source in inventory.sources]
    for shown_root, root in _scanned_roots(specs):
        reported: list[Path] = []
        for shown, location in candidates:
            if location.is_relative_to(root) and not any(location.is_relative_to(done) for done in reported):
                reported.append(location)
                warnings.append(
                    f"inventory {shown} is inside scanned path {shown_root}; "
                    "scanned content could alter approvals"
                )
    for entry in inventory.entries:
        broad = next(
            (
                (pattern, breadth)
                for pattern in entry.resources
                if (breadth := _resource_pattern_breadth(pattern))
            ),
            None,
        )
        if broad is not None:
            pattern, breadth = broad
            shown = "*" if breadth == "universal" else pattern[:60]
            source = f" in {entry.source}" if entry.source else ""
            scoped = (
                entry.surfaces or entry.providers or entry.accounts or entry.regions or entry.discriminators
            )
            effect = (
                "approves every finding"
                if breadth == "universal"
                else "appears near-universal across sampled resource shapes; review approval scope"
            )
            warnings.append(
                f"inventory entry {entry.agent_id}{source} has resource pattern {shown!r},"
                f" which {effect}"
                f"{' its scope constraints allow' if scoped and breadth == 'universal' else ''}"
            )
    warnings += [
        f"inventory {link}: symbolic link skipped (links are not followed)"
        for link in inventory.skipped_links
    ]
    warnings += inventory.autonomy_warnings()
    warnings = list(dict.fromkeys(warnings))
    if len(warnings) > _MAX_INVENTORY_WARNINGS:
        omitted = len(warnings) - _MAX_INVENTORY_WARNINGS
        warnings = [*warnings[:_MAX_INVENTORY_WARNINGS], f"{omitted} further inventory warnings omitted"]
    return warnings


class _Supervisor:
    """Drive submitted connector futures to completion under their deadlines.

    A connector that overruns ``connector_timeout_seconds`` is cancelled
    cooperatively and reported as incomplete; its late result is discarded.
    Queued siblings survive while any worker slot can still run them.
    """

    def __init__(
        self,
        engine: Engine,
        futures: dict[Future[_JobResult], _Job],
        states: dict[int, _JobState],
        workers: int,
        started_at: str,
    ) -> None:
        self._engine = engine
        self._futures = futures
        self._states = states
        self._workers = workers
        self._started_at = started_at
        self.completed: dict[int, _JobResult] = {}
        self.timed_out: set[int] = set()

    def run(self) -> None:
        pending = set(self._futures)
        while pending:
            done, _ = wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
            expired = []
            for future in done:
                number, _ = self._futures[future]
                state = self._states[number]
                if (
                    state.completed_at is not None
                    and state.supervision_deadline is not None
                    and state.completed_at >= state.supervision_deadline
                ):
                    expired.append(future)
                else:
                    self.completed[number] = future.result()
                    pending.remove(future)
            for future in pending - done:
                state = self._states[self._futures[future][0]]
                deadline = state.supervision_deadline
                if deadline is not None and time.monotonic() >= deadline:
                    expired.append(future)
            for future in expired:
                self._expire(future)
                pending.remove(future)
            if pending and self.timed_out and self._capacity_exhausted():
                self._abandon_queue(pending)

    def _expire(self, future: Future[_JobResult]) -> None:
        number, spec = self._futures[future]
        state = self._states[number]
        # A worker may already be blocked inside an OS replacement
        # while holding this lock. Waiting here would turn the
        # cooperative connector deadline into an unbounded wait.
        # If acquired, cancel before another publication can begin;
        # otherwise mark cancellation immediately. The in-flight
        # replacement may finish after we return, so its artifact
        # must never be treated as an accepted scan export.
        if state.publication_lock.acquire(blocking=False):
            try:
                state.cancelled.set()
            finally:
                state.publication_lock.release()
        else:
            state.cancelled.set()
        self.timed_out.add(number)
        if state.kill_process is not None:
            state.kill_process()
        if future.running():
            self._engine.abandoned_workers.append(spec.id)
            self._engine._abandoned_futures.append(future)
        self.completed[number] = (
            spec,
            [],
            ScanStats(
                connector=spec.id,
                started_at=state.started_at or self._started_at,
                finished_at=now_iso(),
                incomplete=True,
                skipped=True,
                skip_reason=_TIMEOUT_MESSAGE,
                errors=[_TIMEOUT_MESSAGE],
                warnings=[_TIMEOUT_WARNING],
            ),
        )

    def _capacity_exhausted(self) -> bool:
        # A timed-out worker can still be running inside an SDK or
        # plugin call. Preserve queued siblings while *any* worker
        # can eventually run them. Only abandon the queue when all
        # worker slots are still occupied by timed-out calls; waiting
        # for those calls would defeat the completion deadline, and
        # replacing them would exceed the configured parallelism.
        running = [future for future in self._futures if future.running()]
        return len(running) >= self._workers and all(
            self._futures[future][0] in self.timed_out for future in running
        )

    def _abandon_queue(self, pending: set[Future[_JobResult]]) -> None:
        for future in tuple(pending):
            if future.cancel():
                number, spec = self._futures[future]
                with self._states[number].publication_lock:
                    self._states[number].cancelled.set()
                self.timed_out.add(number)
                self.completed[number] = (
                    spec,
                    [],
                    ScanStats(
                        connector=spec.id,
                        started_at=self._started_at,
                        finished_at=now_iso(),
                        incomplete=True,
                        skipped=True,
                        skip_reason="no worker capacity remains after connector timeouts",
                        errors=["connector not started: all worker slots remain occupied by timed-out calls"],
                    ),
                )
                pending.remove(future)


class Engine:
    def __init__(
        self, config: ScanConfig, index: SignatureIndex | None = None, progress: ProgressFn | None = None
    ) -> None:
        self.config = config
        config.validate_security_options()
        config.validate_connector_specs()
        # Process configuration, never ScanConfig, so it cannot reach caches or reports.
        self._identity_key = _stable_identity_key()
        self._index_supplied = index is not None
        self._signature_digest: str | None = None
        self.index = index if index is not None else self._load_index()
        self._validate_risk_policy()
        self.progress = progress or (lambda cid, msg: None)
        # Connector ids whose worker threads outlived ``connector_timeout_seconds`` in
        # the last run. Their threads may still be blocked inside an SDK call;
        # a process that must exit promptly has to use ``os._exit``.
        self.abandoned_workers: list[str] = []
        self._abandoned_futures: list[Future[Any]] = []
        # Validate eagerly so setup errors fail at construction. A run still
        # reloads the inventory: approval can change after construction and a
        # stale first-run snapshot must never authorize a finding.
        self.inventory: Inventory | None = Inventory.load(config.inventory) if config.inventory else None

    def _report_progress(self, connector: str, message: str) -> None:
        """A failed output observer must not change collection or scan completeness."""
        try:
            self.progress(connector, message)
        except Exception:  # noqa: BLE001 - third-party callback must not abort a worker
            log.warning("progress callback failed; scan continues")

    # ------------------------------------------------------------ preparation
    def _pack_digest(self) -> str | None:
        try:
            return signature_source_digest(
                self.config.signature_dirs or None, allow_override=self.config.allow_signature_override
            )
        except (OSError, ValueError):
            # The load that follows reports the underlying problem.
            return None

    def _load_index(self) -> SignatureIndex:
        # Digest before loading: a pack edited in between is then reloaded
        # by the next run rather than masked by a digest taken afterwards.
        digest = self._pack_digest()
        index = get_index(
            extra_dirs=self.config.signature_dirs or None,
            reload=True,
            allow_override=self.config.allow_signature_override,
        )
        self._signature_digest = digest
        return index

    def _refresh_index(self) -> None:
        """A reusable Engine must notice signature pack edits between runs.

        Parsing the packs dominates start-up, so the loaded index is kept
        while the pack sources' content digest is unchanged.
        """
        if self._index_supplied:
            return
        if self._signature_digest is None or self._pack_digest() != self._signature_digest:
            self.index = self._load_index()

    def _validate_risk_policy(self) -> None:
        """Reject a risk_weights provider id that no loaded provider signature has."""
        try:
            RiskPolicy.from_options(
                self.config.risk_weights, self.config.risk_basis, known_providers=provider_ids(self.index)
            )
        except ValueError as exc:
            raise ConfigValidationError(f"options.{exc}") from None

    def _refresh_inventory(self) -> None:
        # Registry approval can change independently of source inputs or an Engine
        # instance's lifetime. It is never persisted in connector cache entries.
        paths = list(self.config.inventory)
        self.inventory = Inventory.load(paths) if paths else None

    def _prepare_run(self) -> None:
        if any(not future.done() for future in self._abandoned_futures):
            raise RuntimeError(
                "a previous timed-out connector is still running; use a fresh process for the next scan"
            )
        self._abandoned_futures.clear()
        self.abandoned_workers.clear()
        self.config.min_confidence = validate_min_confidence(self.config.min_confidence)
        # ScanConfig is intentionally mutable for embedding callers and CLI
        # overrides. Revalidate every security-relevant field, including
        # nested risk weights, before any connector is constructed.
        self.config.validate_security_options()
        # Embedding callers can mutate ConnectorSpec instances between runs;
        # re-establish the built-in schema and boolean boundary before any
        # connector sees the configuration.
        self.config.validate_connector_specs()
        self._refresh_index()
        self._validate_risk_policy()
        self._refresh_inventory()

    # -------------------------------------------------------------- selection
    def _invalid_selectors(self, only: list[str] | None) -> list[str]:
        if not only:
            return []
        selectable = {
            value for spec in self.config.connectors if spec.enabled for value in (spec.id, spec.name)
        }
        return [selector for selector in only if selector not in selectable]

    def _select_jobs(self, only: list[str] | None) -> list[_Job]:
        return [
            (number, spec)
            for number, spec in enumerate(self.config.connectors, 1)
            if spec.enabled and (not only or spec.id in only or spec.name in only)
        ]

    def _not_run(self, jobs: list[_Job]) -> list[dict[str, str]]:
        """Configured connectors that were deliberately not run, for the report's reader.

        Disabling a connector or narrowing with ``--only`` is operator intent
        and never makes a scan incomplete, but the report would otherwise show
        no trace that a configured source was left out.
        """
        selected = {number for number, _ in jobs}
        return [
            {"connector": spec.id, "reason": "disabled" if not spec.enabled else "not selected by --only"}
            for number, spec in enumerate(self.config.connectors, 1)
            if number not in selected
        ]

    @staticmethod
    def _reject_selection(result: ScanResult, invalid: list[str]) -> ScanResult:
        result.collection_scope = {
            "schema": "shadowscan.collection-scope/v1",
            "comparable": False,
            "reason": "requested connectors are unknown or disabled",
        }
        result.stats = [
            ScanStats(
                connector="engine.selection",
                started_at=result.started_at,
                finished_at=now_iso(),
                skipped=True,
                incomplete=True,
                skip_reason="invalid connector selection",
                errors=[
                    sanitize(f"unknown or disabled connector selector: {selector}") for selector in invalid
                ],
            )
        ]
        result.finished_at = now_iso()
        return result

    def _inventory_stats(self, specs: list[ConnectorSpec], started_at: str) -> list[ScanStats]:
        """Record inventory placement and wildcard approvals as warnings in every report format."""
        warnings = _inventory_warnings(self.config.inventory, self.inventory, specs)
        if not warnings:
            return []
        # Logs can travel beyond the private report: keep paths out of them.
        log.warning("inventory approval warning recorded in scan stats (engine.inventory)")
        stats = ScanStats(
            connector="engine.inventory", started_at=started_at, finished_at=now_iso(), warnings=warnings
        )
        _sanitize_diagnostics(stats)
        return [stats]

    @staticmethod
    def _selection_stats(specs: list[ConnectorSpec]) -> list[ScanStats]:
        if specs:
            return []
        log.warning("no connectors selected")
        return [
            ScanStats(
                connector="engine",
                started_at=now_iso(),
                finished_at=now_iso(),
                skipped=True,
                skip_reason="no connectors selected",
                incomplete=True,
                errors=["no connectors selected"],
            )
        ]

    # ------------------------------------------------------------- collection
    def _collect(
        self,
        jobs: list[_Job],
        cache: IncrementalCache,
        dump_directory: Path | None,
        exports: _ExportLedger,
        started_at: str,
    ) -> tuple[dict[int, _JobResult], set[int]]:
        """Run every selected connector under deadline supervision."""
        states = {
            number: _JobState(
                isolated_process=self.config.plugin_execution == "process"
                and spec.name not in builtin_connector_names()
            )
            for number, spec in jobs
        }
        runner = _ConnectorRunner(self, cache, dump_directory, exports)
        workers = max(1, min(self.config.parallel, len(jobs) or 1))
        # Supervise the single-worker path too. A ThreadPoolExecutor context
        # manager would wait forever for a stuck connector on exit.
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="shadowscan")
        futures = {
            pool.submit(runner.run, number, spec, states[number]): (number, spec) for number, spec in jobs
        }
        supervisor = _Supervisor(self, futures, states, workers, started_at)
        try:
            supervisor.run()
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
            # Supervision can end abnormally (KeyboardInterrupt). A plugin
            # worker must not outlive it until its deadline; a job whose worker
            # is not started yet sees the cancellation and stops it at once.
            for state in states.values():
                if state.isolated_process:
                    state.cancelled.set()
                    if state.kill_process is not None:
                        state.kill_process()
        return supervisor.completed, supervisor.timed_out

    # --------------------------------------------------------- postprocessing
    def _reconcile_and_score(self, findings: list[Finding]) -> None:
        risk_policy = RiskPolicy.from_options(self.config.risk_weights, self.config.risk_basis)
        for f in findings:
            entry: InventoryEntry | None = None
            if self.inventory is not None:
                entry = self.inventory.match(f)
                f.registry_match = entry.agent_id if entry else None
                f.shadow = entry is None
                if entry and not f.owner:
                    f.owner = entry.owner
            # Before scoring: a declared level below the observed floor adds a weighted tag.
            apply_autonomy(f, entry)
            f.risk = assess(f, self.index, inventory_present=self.inventory is not None, policy=risk_policy)

    def _postprocess(self, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
        """Merge, correlate, reconcile and score; report what had to be omitted."""
        # Individually bounded findings can exceed the output budget when
        # merged. Reject only that aggregate before correlation touches it.
        findings, omitted = _retain_sanitizable(merge(findings))
        correlate(findings)
        errors = []
        try:
            correlate_runtime(findings)
        except SanitizationLimitError:
            errors.append("runtime correlation incomplete: sanitization safety limit exceeded")
        correlate_lifecycle(findings)
        self._reconcile_and_score(findings)
        findings, omitted_after_scoring = _retain_sanitizable(findings)
        omitted += omitted_after_scoring
        if omitted:
            errors.append(
                f"{omitted} finding(s) omitted after aggregation: sanitization safety limit exceeded"
            )
        return findings, errors

    @staticmethod
    def _write_manifest(
        dump_directory: Path, exports: list[dict[str, Any]], started_at: str, stats: list[ScanStats]
    ) -> None:
        manifest = {
            "schema": "shadowscan.record-exports/v1",
            "started_at": started_at,
            "complete": bool(stats) and not any(st.incomplete or st.skipped or st.errors for st in stats),
            "exports": sorted(exports, key=lambda entry: entry["part"]),
        }
        try:
            text = json.dumps(sanitize(manifest), indent=2) + "\n"
            write_private_text(Path(dump_directory) / "manifest.json", text)
        except (OSError, ValueError) as exc:
            stats.append(
                ScanStats(
                    connector="engine.exports",
                    started_at=started_at,
                    finished_at=now_iso(),
                    incomplete=True,
                    errors=[f"record export manifest could not be saved: {sanitize(str(exc))}"],
                )
            )

    # ------------------------------------------------------------------ run
    def _triage(self, findings: list[Finding], started_at: str) -> ScanStats:
        """Opt-in advisory LLM triage; its failures are warnings, never discovery gaps."""
        entry = ScanStats(connector="engine.llm-triage", started_at=started_at)
        try:
            triage = Triage(
                self.config.llm_triage, self.index, allow_private_origin=self.config.allow_private_origin
            )
            entry.warnings.extend(triage.run(findings))
        except TriageConfigError as exc:
            entry.warnings.append(str(exc))
        except Exception as exc:  # noqa: BLE001 - advisory: a triage failure never costs the scan its report
            # Only the type name is kept: the text of an exception can echo a reply or a key.
            entry.warnings.append(f"llm triage failed ({type(exc).__name__})")
        entry.finished_at = now_iso()
        return entry

    def run(self, only: list[str] | None = None) -> ScanResult:
        self._prepare_run()
        result = ScanResult(
            version=__version__,
            inventory_size=len(self.inventory) if self.inventory else 0,
            inventory_present=self.inventory is not None,
        )
        invalid = self._invalid_selectors(only)
        if invalid:
            return self._reject_selection(result, invalid)
        jobs = self._select_jobs(only)
        specs = [spec for _, spec in jobs]
        self.config.validate_connector_isolation(specs)
        result.collection_scope = build_collection_scope(
            self.config, self.index, specs, identity_key=self._identity_key
        )
        result.collection_scope["credential_identity_schema"] = "shadowscan.credential-identity/v1"
        result.collection_scope["credential_identity_scope"] = "keyed" if self._identity_key else "run"
        not_run = self._not_run(jobs)
        if not_run:
            # Outside the fingerprint and comparability: operator intent only.
            result.collection_scope["not_run"] = not_run
        stats = self._selection_stats(specs) + self._inventory_stats(specs, result.started_at)
        cache = IncrementalCache(self.config, self.index, identity_key=self._identity_key)
        dump_records = self.config.dump_records
        dump_directory = prepare_private_directory(dump_records) if dump_records else None
        exports = _ExportLedger()
        completed, timed_out = self._collect(jobs, cache, dump_directory, exports, result.started_at)
        # Merge uses first-observed owner and metadata as precedence.
        # Preserve configured order regardless of request completion.
        findings: list[Finding] = []
        for number, _ in jobs:
            _, fs, st = completed[number]
            findings.extend(fs)
            stats.append(st)
        export_entries = exports.entries(jobs, timed_out) if dump_directory else []
        findings, postprocess_errors = self._postprocess(findings)
        if postprocess_errors:
            stats.append(
                ScanStats(
                    connector="engine.postprocess",
                    started_at=result.started_at,
                    finished_at=now_iso(),
                    incomplete=True,
                    errors=postprocess_errors,
                )
            )
        if self.config.min_confidence > 0:
            findings = [f for f in findings if f.confidence >= self.config.min_confidence]
            _prune_related(findings)
            _prune_runtime_links(findings)
            _prune_lifecycle_links(findings)
        findings.sort(key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title))
        if self.config.llm_triage.enabled:
            stats.append(self._triage(findings, result.started_at))
        if dump_directory:
            self._write_manifest(dump_directory, export_entries, result.started_at, stats)
        result.findings = findings
        result.stats = sorted(stats, key=lambda s: s.connector)
        result.finished_at = now_iso()
        return result


def _prune_lifecycle_links(findings: list[Finding]) -> None:
    """Drop ``metadata['lifecycle']['related']`` identifiers of findings absent from ``findings``."""
    retained = {f.id for f in findings}
    for f in findings:
        lifecycle = f.metadata.get("lifecycle")
        if not isinstance(lifecycle, dict):
            continue
        related = lifecycle.get("related")
        if isinstance(related, list):
            lifecycle["related"] = [link for link in related if link in retained]


def _prune_related(findings: list[Finding]) -> None:
    """Drop ``metadata['related']`` links to findings absent from ``findings``.

    Correlation runs before the confidence threshold. A report must not link
    to a finding it omits; removing those identifiers from every list keeps
    the remaining pairs symmetric, as :func:`correlate` created them.
    """
    retained = {f.id for f in findings}
    for f in findings:
        links = f.metadata.get("related")
        if not isinstance(links, list):
            continue
        kept = [link for link in links if link in retained]
        if len(kept) == len(links):
            continue
        if kept:
            f.metadata["related"] = kept
        else:
            del f.metadata["related"]


def _prune_runtime_links(findings: list[Finding]) -> None:
    """Drop ``runtime_activity`` references to gateway findings absent from ``findings``.

    Gateway identities are scan-local, so an omitted gateway finding's ID names
    nothing outside this report. The observation itself stays: its events,
    window and scope are what the exported log recorded, whatever the gateway
    finding's own confidence.
    """
    retained = {f.id for f in findings}
    for f in findings:
        activity = f.metadata.get("runtime_activity")
        sources = activity.get("sources") if isinstance(activity, dict) else None
        for source in sources if isinstance(sources, list) else []:
            if isinstance(source, dict) and source.get("gateway_finding_id") not in retained:
                source["gateway_finding_id"] = None
        for ev in f.evidence:
            ids = ev.attributes.get("gateway_finding_ids")
            if isinstance(ids, list):
                ev.attributes["gateway_finding_ids"] = [i for i in ids if i in retained]
