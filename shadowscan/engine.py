"""Scan orchestration: run connectors, merge, correlate, reconcile with the inventory, score."""

from __future__ import annotations

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
from shadowscan.comparison import build_collection_scope
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig, validate_min_confidence
from shadowscan.connectors import ConnectorContext, builtin_connector_names, get_connector_class
from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import merge_duplicate_metadata
from shadowscan.correlation import correlate_runtime
from shadowscan.incremental import IncrementalCache
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, now_iso
from shadowscan.registry import Inventory
from shadowscan.risk import RiskPolicy, assess, provider_ids
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.signatures.loader import signature_source_digest
from shadowscan.utils.http import reset_allow_private_origin, set_allow_private_origin
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
        # separate Engine.run calls cannot link redacted caller/scope IDs.
        self._run_identity_key = secrets.token_bytes(32)

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
        finally:
            reset_allow_private_origin(origin_token)

    def _run_job(self, number: int, spec: ConnectorSpec, state: _JobState) -> _JobResult:
        resolved = self._resolve(spec.name, state)
        roots = spec.config.get("paths")
        root_ids = spec.config.get("root_ids")
        if not isinstance(roots, list) or not self._split_roots(spec, resolved, roots, root_ids):
            return self._run_one(spec, resolved, f"{number:04d}", state)
        return self._run_split(number, spec, resolved, state, roots, root_ids)

    def _split_roots(self, spec: ConnectorSpec, resolved: _Resolved, roots: list[Any], root_ids: Any) -> bool:
        """Decide whether a multi-root scan can be cached per repository."""
        if not (self._config.incremental and not spec.config.get("input") and len(roots) > 1):
            return False
        if isinstance(resolved, Exception):
            return False  # _run_one reports the lookup failure as incomplete
        try:
            labelled = bool(spec.label or spec.config.get("label"))
            if not _hooks(resolved).cache_roots_separately(roots, root_ids, labelled=labelled):
                return False
        except ConnectorError:
            # Run once so constructor validation reports an incomplete
            # scan, rather than partially scanning the valid children.
            return False
        try:
            return self._cache.supports_connector(spec, resolved)
        except Exception:  # noqa: BLE001 - _run_one reports import failures as incomplete
            return False

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
        self, spec: ConnectorSpec, hooks: type[BaseConnector], dump_key: str
    ) -> dict[str, Any]:
        cfg = dict(spec.config)
        if "allow_instance_credentials" in cfg or hooks.inherits_instance_credentials_approval():
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
        cfg = self._connector_config(spec, hooks, dump_key)
        identity_key = self._run_identity_key if hooks.uses_run_identity_key else None
        ctx = ConnectorContext(
            config=cfg,
            index=self._index,
            workdir=self._config.workdir,
            deadline=state.deadline,
            cancelled=state.cancelled,
            publication_lock=state.publication_lock,
            gateway_identity_key=identity_key,
        )
        fs: list[Finding] = []
        started_at = now_iso()
        origin_token = set_allow_private_origin(self._config.allow_private_origin)
        try:
            st, reused = self._collect(spec, resolved, ctx, started_at, fs)
            if reused:
                return spec, fs, st
        except KeyboardInterrupt:
            raise
        except BaseException as exc:  # noqa: BLE001 - isolate construction and collection failures,
            # including a plugin's sys.exit(), which must not end the scan as a clean pass.
            message = ctx.sanitize_message(f"{spec.name}: {type(exc).__name__}: {exc}")
            st = ctx.stats or ScanStats(connector=spec.id, started_at=started_at)
            st.connector = spec.id
            st.finished_at = now_iso()
            st.incomplete = True
            st.skipped = not fs
            st.skip_reason = message if st.skipped else None
            st.errors.append(message)
            log.warning("connector failed; diagnostic recorded in incomplete scan stats")
        finally:
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


def _sanitize_diagnostics(st: ScanStats) -> None:
    try:
        st.errors = sanitize(st.errors)
        st.warnings = sanitize(st.warnings)
    except SanitizationLimitError:
        st.incomplete = True
        st.errors = ["connector diagnostics omitted: sanitization safety limit exceeded"]
        st.warnings = []


_MAX_INVENTORY_WARNINGS = 20


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
    """Approvals that scanned content could change, or that approve every finding.

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
        if any(not pattern.strip("*") for pattern in entry.resources):
            source = f" in {entry.source}" if entry.source else ""
            scoped = entry.surfaces or entry.providers or entry.accounts or entry.regions
            warnings.append(
                f"inventory entry {entry.agent_id}{source} has resource pattern '*', which approves every"
                f" finding{' its scope constraints allow' if scoped else ''}"
            )
    warnings += [
        f"inventory {link}: symbolic link skipped (links are not followed)"
        for link in inventory.skipped_links
    ]
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
            if self.inventory is not None:
                entry = self.inventory.match(f)
                f.registry_match = entry.agent_id if entry else None
                f.shadow = entry is None
                if entry and not f.owner:
                    f.owner = entry.owner
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
    def run(self, only: list[str] | None = None) -> ScanResult:
        self._prepare_run()
        result = ScanResult(version=__version__, inventory_size=len(self.inventory) if self.inventory else 0)
        invalid = self._invalid_selectors(only)
        if invalid:
            return self._reject_selection(result, invalid)
        jobs = self._select_jobs(only)
        specs = [spec for _, spec in jobs]
        self.config.validate_connector_isolation(specs)
        result.collection_scope = build_collection_scope(self.config, self.index, specs)
        stats = self._selection_stats(specs) + self._inventory_stats(specs, result.started_at)
        cache = IncrementalCache(self.config, self.index)
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
        findings.sort(key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title))
        if dump_directory:
            self._write_manifest(dump_directory, export_entries, result.started_at, stats)
        result.findings = findings
        result.stats = sorted(stats, key=lambda s: s.connector)
        result.finished_at = now_iso()
        return result


# ------------------------------------------------------------------ merging

# Classification precedence when two observations of one finding disagree.
_KIND_PRIORITY = {Kind.AGENT: 3, Kind.SERVICE_IDENTITY: 2, Kind.OAUTH_GRANT: 1}


def _merge_classification(cur: Finding, f: Finding) -> None:
    """Select the classification and its resource subtype as one pair.

    A lexical subtype tie-break keeps repeated/grouped merges associative
    without attaching the first record's subtype to another record's kind.
    """
    classifications = [(finding.kind, finding.resource_type) for finding in (cur, f)]
    classification = max(
        classifications,
        key=lambda value: (_KIND_PRIORITY.get(value[0], 0), value[0].value, value[1]),
    )
    for key, current_values in (
        ("observed_kinds", {kind.value for kind, _ in classifications}),
        ("observed_resource_types", {resource_type for _, resource_type in classifications}),
    ):
        for finding in (cur, f):
            previous = finding.metadata.get(key)
            if isinstance(previous, list):
                current_values.update(value for value in previous if isinstance(value, str))
        if len(current_values) > 1:
            cur.metadata[key] = sorted(current_values)
    cur.kind, cur.resource_type = classification


def _merge_observations(cur: Finding, f: Finding) -> None:
    """Union evidence, technologies, capabilities, tags, permissions and models."""
    seen = {(e.signal, e.location, e.description) for e in cur.evidence}
    for e in f.evidence:
        evidence_key = (e.signal, e.location, e.description)
        if evidence_key not in seen:
            seen.add(evidence_key)
            cur.evidence.append(e)
    for fw in f.frameworks:
        cur.add_framework(fw)
    for p in f.model_providers:
        cur.add_model_provider(p)
    for c in f.capabilities:
        cur.add_capability(c)
    for t in f.tags:
        cur.add_tag(t)
    for p in f.permissions:
        if p not in cur.permissions:
            cur.permissions.append(p)
    for m in f.models:
        if m not in cur.models:
            cur.models.append(m)
    cur.owner = cur.owner or f.owner


def merge(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same id (same object seen by the same connector twice).

    The first observation takes precedence for owner and metadata; lists such
    as evidence and frameworks are unioned. Metadata keys that combine across
    observations follow :func:`shadowscan.connectors.common.merge_duplicate_metadata`.
    """
    by_id: dict[str, Finding] = {}
    for f in findings:
        cur = by_id.get(f.id)
        if cur is None:
            by_id[f.id] = f
            continue
        _merge_classification(cur, f)
        _merge_observations(cur, f)
        merge_duplicate_metadata(cur, f)
        # Widen the window only now: metadata merging may record each
        # observation's own window (per-source runtime snapshots).
        cur.first_seen = min((x for x in (cur.first_seen, f.first_seen) if x), default=None)
        cur.last_seen = max((x for x in (cur.last_seen, f.last_seen) if x), default=None)
        cur.recompute_confidence()
    return list(by_id.values())


# -------------------------------------------------------------- correlation

_NAME_KEYS = (
    "agent_name",
    "name",
    "display_name",
    "app_slug",
    "okta_name",
    "developer_name",
    "schema_name",
    "app_id",
    "client_id",
    "msa_app_id",
    "bot_id",
    "principal",
    "caller",
    "repository",
    "project",
    "function_name",
    "agent_id",
)


def _norm(s: Any) -> str | None:
    if s is None:
        return None
    t = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return t if len(t) >= 5 else None


def correlate(findings: list[Finding]) -> None:
    """Link findings across surfaces that describe the same agent / identity / resource.

    Keys: resource ids (ARNs, app/client ids), normalised names and repository labels found in
    metadata. Linked ids are stored in ``metadata['related']`` on both sides.
    """
    keys: dict[str, set[str]] = {}
    for f in findings:
        cand: set[str] = set()
        res = _norm(f.resource)
        if res:
            cand.add(f"res:{res}")
        for k in _NAME_KEYS:
            v = f.metadata.get(k)
            if isinstance(v, str):
                n = _norm(v)
                if n:
                    cand.add(f"name:{n}")
        if f.kind in {Kind.AGENT, Kind.BOT_APP, Kind.SERVICE_IDENTITY, Kind.OAUTH_GRANT, Kind.MCP_SERVER}:
            tail = f.title.split(":", 1)[-1].strip() if ":" in f.title else None
            n = _norm(tail)
            if n and len(n) >= 8:
                cand.add(f"name:{n}")
        # cloud resources referenced from other findings' metadata / evidence locations
        for e in f.evidence:
            if e.location and e.location.startswith(("arn:", "projects/", "/subscriptions/", "ocid1.")):
                n = _norm(e.location)
                if n:
                    cand.add(f"res:{n}")
        for k in cand:
            keys.setdefault(k, set()).add(f.id)
    related: dict[str, set[str]] = {}
    for ids in keys.values():
        if 1 < len(ids) <= 25:
            for i in ids:
                related.setdefault(i, set()).update(ids - {i})
    if not related:
        return
    by_id = {f.id: f for f in findings}
    for fid, others in related.items():
        linked_finding = by_id.get(fid)
        if linked_finding:
            # Only link across different connectors / surfaces (within one
            # connector, duplicates are merged already).
            links = sorted(
                o
                for o in others
                if by_id.get(o)
                and (
                    by_id[o].connector != linked_finding.connector
                    or by_id[o].surface != linked_finding.surface
                )
            )
            if links:
                linked_finding.metadata["related"] = links
