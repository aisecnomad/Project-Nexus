"""Scan orchestration: run connectors, merge, correlate, reconcile with the inventory, score."""

from __future__ import annotations

import hashlib
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
from shadowscan.config import ConnectorSpec, ScanConfig, validate_min_confidence
from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.code.filesystem import validate_distinct_paths, validate_root_ids
from shadowscan.correlation import correlate_runtime
from shadowscan.incremental import IncrementalCache
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface, now_iso
from shadowscan.registry import Inventory
from shadowscan.risk import assess
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.signatures.loader import signature_source_digest
from shadowscan.utils.http import reset_allow_private_origin, set_allow_private_origin
from shadowscan.utils.output import prepare_private_directory, write_private_text
from shadowscan.utils.redaction import SanitizationLimitError, sanitize

log = logging.getLogger("shadowscan.engine")

ProgressFn = Callable[[str, str], None]  # (connector id, message)
_Job = tuple[int, ConnectorSpec]  # (1-based configuration ordinal, connector)
_JobResult = tuple[ConnectorSpec, list[Finding], ScanStats]

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


def _security_options(config: ScanConfig) -> tuple[Any, ...]:
    """Snapshot the options ``ScanConfig.validate_security_options`` normalises."""
    plugins = config.plugins
    return (
        tuple(plugins) if isinstance(plugins, list) else plugins,
        config.allow_signature_override, config.allow_private_origin, config.allow_instance_credentials,
        config.allow_credential_mixing, config.connector_timeout_seconds, config.incremental,
        config.fail_on, config.parallel,
    )


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
                    entries.append({
                        "config_ordinal": number, "part": f"{number:04d}", "connector": spec.name,
                        "label": spec.label, "filename": None, "complete": False, "exported": False,
                    })
            return entries


class _ConnectorRunner:
    """Run one configured connector on a worker thread and shape its result.

    Everything here executes under the connector deadline. Cache reuse,
    per-repository splitting, sanitization of findings and diagnostics, and
    export bookkeeping all count towards the measured connector runtime.
    """

    def __init__(self, engine: Engine, cache: IncrementalCache, dump_directory: Path | None, exports: _ExportLedger):
        self._engine = engine
        self._config = engine.config
        self._index = engine.index
        self._cache = cache
        self._dump_directory = dump_directory
        self._exports = exports
        # Identical gateway sources in one report share an opaque identity,
        # while separate Engine.run calls cannot link redacted caller/scope IDs.
        self._gateway_identity_key = secrets.token_bytes(32)

    def run(self, number: int, spec: ConnectorSpec, state: _JobState) -> _JobResult:
        state.started_at = now_iso()
        timeout = self._config.connector_timeout_seconds
        state.deadline = time.monotonic() + timeout
        try:
            return self._run_job(number, spec, state)
        finally:
            # Include sanitization, cache writes and callbacks in the
            # measured runtime, even if completion precedes the next poll.
            state.completed_at = time.monotonic()

    def _lookup(self, name: str) -> type[BaseConnector]:
        if self._config.plugins:
            return get_connector_class(name, allowed_plugins=self._config.plugins)
        return get_connector_class(name)

    def _run_job(self, number: int, spec: ConnectorSpec, state: _JobState) -> _JobResult:
        roots = spec.config.get("paths")
        root_ids = spec.config.get("root_ids")
        if not isinstance(roots, list) or not self._split_roots(spec, roots, root_ids):
            return self._run_one(spec, f"{number:04d}", state)
        return self._run_split(number, spec, state, roots, root_ids)

    def _split_roots(self, spec: ConnectorSpec, roots: list[Any], root_ids: Any) -> bool:
        """Decide whether a multi-root filesystem scan can be cached per repository."""
        if not (self._config.incremental and spec.name == "code.filesystem"
                and not spec.config.get("input") and len(roots) > 1):
            return False
        try:
            if spec.label or spec.config.get("label"):
                validate_distinct_paths(roots)
            if root_ids is not None:
                validate_root_ids(roots, root_ids)
        except ConnectorError:
            # Run once so constructor validation reports an incomplete
            # scan, rather than partially scanning the valid children.
            return False
        try:
            return self._cache.supports_connector(spec, self._lookup(spec.name))
        except Exception:  # noqa: BLE001 - _run_one reports lookup/import failures as incomplete
            return False

    def _run_split(self, number: int, spec: ConnectorSpec, state: _JobState, roots: list[Any], root_ids: Any) -> _JobResult:
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
            _, child_findings, child_stats = self._run_one(child, f"{number:04d}-{root_number:04d}", state)
            combined.extend(child_findings)
            parts.append(child_stats)
        cached_count = sum(s.cached for s in parts)
        stats = ScanStats(
            connector=spec.id, started_at=min(s.started_at for s in parts),
            finished_at=now_iso(), findings=len(combined),
            objects_examined=sum(s.objects_examined for s in parts),
            errors=[e for s in parts for e in s.errors],
            warnings=[w for s in parts for w in s.warnings],
            incomplete=any(s.incomplete or s.skipped or s.errors for s in parts),
            skipped=all(s.skipped for s in parts), cached=cached_count == len(parts),
        )
        if cached_count:
            stats.warnings.append(f"incremental: reused {cached_count}/{len(parts)} unchanged repository roots")
        return spec, combined, stats

    def _connector_config(self, spec: ConnectorSpec, dump_key: str) -> dict[str, Any]:
        cfg = dict(spec.config)
        if spec.name.startswith("cloud."):
            # Scan-wide approval cannot be bypassed by a connector-level key.
            cfg["allow_instance_credentials"] = self._config.allow_instance_credentials
        if spec.label:
            cfg.setdefault("label", spec.label)
        if self._dump_directory:
            label = re.sub(r"[^A-Za-z0-9_-]", "_", spec.id)[:80] or "connector"
            cfg["_dump_path"] = os.path.join(self._dump_directory, f"{dump_key}-{label}.jsonl")
        return cfg

    def _run_one(self, spec: ConnectorSpec, dump_key: str, state: _JobState) -> _JobResult:
        self._engine._report_progress(spec.id, "starting")
        cfg = self._connector_config(spec, dump_key)
        ctx = ConnectorContext(config=cfg, index=self._index, workdir=self._config.workdir,
                               deadline=state.deadline, cancelled=state.cancelled,
                               publication_lock=state.publication_lock,
                               gateway_identity_key=self._gateway_identity_key if spec.name == "gateway.logs" else None)
        fs: list[Finding] = []
        started_at = now_iso()
        origin_token = set_allow_private_origin(self._config.allow_private_origin)
        try:
            st, reused = self._collect(spec, ctx, started_at, fs)
            if reused:
                return spec, fs, st
        except Exception as exc:  # noqa: BLE001 - isolate construction as well as collection failures
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
            self._exports.record(state, {
                "config_ordinal": int(dump_key.split("-")[0]), "part": dump_key,
                "connector": spec.name, "label": spec.label,
                "filename": Path(ctx.dump_path).name if exported and ctx.dump_path else None,
                "complete": not (st.incomplete or st.skipped or st.errors),
                "exported": exported,
            })
        if not state.cancelled.is_set():
            self._engine._report_progress(spec.id, f"{len(fs)} findings")
        return spec, fs, st

    def _collect(self, spec: ConnectorSpec, ctx: ConnectorContext, started_at: str,
                 fs: list[Finding]) -> tuple[ScanStats, bool]:
        """Reuse a cached result or collect afresh, appending findings to ``fs``.

        ``fs`` is filled in place so a failure part-way through still reports
        what was already retained. The flag says an unchanged cached result
        was returned, which skips the post-collection bookkeeping.
        """
        cache = self._cache
        ctx.check_deadline()
        cls = self._lookup(spec.name)
        # Constructor validation still runs before a cached result is used.
        connector = cls(ctx)
        snapshot = cache.snapshot(spec) if cache.supports_connector(spec, cls) else None
        cached = cache.load(spec, snapshot) if snapshot else None
        if cached is not None:
            cached_findings, st = cached
            fs.extend(cached_findings)
            if cache.snapshot(spec) == snapshot:
                ctx.check_deadline()
                self._engine._report_progress(spec.id, f"{len(fs)} findings (unchanged input; cached)")
                return st, True
            fs.clear()
        collected = connector.run()
        ctx.check_deadline()
        st = ctx.stats or ScanStats(
            connector=spec.id, started_at=started_at, finished_at=now_iso(),
            incomplete=True, errors=["connector did not report completion status"],
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
            if cache.snapshot(spec) == snapshot:
                ctx.check_deadline()
                cache.save(snapshot, fs, st, check_deadline=ctx.check_deadline,
                           publish_replace=ctx.publish_replace)
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


class _Supervisor:
    """Drive submitted connector futures to completion under their deadlines.

    A connector that overruns ``connector_timeout_seconds`` is cancelled
    cooperatively and reported as incomplete; its late result is discarded.
    Queued siblings survive while any worker slot can still run them.
    """

    def __init__(self, engine: Engine, futures: dict[Future[_JobResult], _Job],
                 states: dict[int, _JobState], workers: int, started_at: str):
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
                if state.completed_at is not None and state.deadline is not None and state.completed_at >= state.deadline:
                    expired.append(future)
                else:
                    self.completed[number] = future.result()
                    pending.remove(future)
            for future in pending - done:
                deadline = self._states[self._futures[future][0]].deadline
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
        if future.running():
            self._engine.abandoned_workers.append(spec.id)
            self._engine._abandoned_futures.append(future)
        self.completed[number] = (spec, [], ScanStats(
            connector=spec.id, started_at=state.started_at or self._started_at,
            finished_at=now_iso(), incomplete=True, skipped=True,
            skip_reason=_TIMEOUT_MESSAGE, errors=[_TIMEOUT_MESSAGE], warnings=[_TIMEOUT_WARNING],
        ))

    def _capacity_exhausted(self) -> bool:
        # A timed-out worker can still be running inside an SDK or
        # plugin call. Preserve queued siblings while *any* worker
        # can eventually run them. Only abandon the queue when all
        # worker slots are still occupied by timed-out calls; waiting
        # for those calls would defeat the completion deadline, and
        # replacing them would exceed the configured parallelism.
        running = [future for future in self._futures if future.running()]
        return len(running) >= self._workers and all(self._futures[future][0] in self.timed_out for future in running)

    def _abandon_queue(self, pending: set[Future[_JobResult]]) -> None:
        for future in tuple(pending):
            if future.cancel():
                number, spec = self._futures[future]
                with self._states[number].publication_lock:
                    self._states[number].cancelled.set()
                self.timed_out.add(number)
                self.completed[number] = (spec, [], ScanStats(
                    connector=spec.id, started_at=self._started_at, finished_at=now_iso(),
                    incomplete=True, skipped=True,
                    skip_reason="no worker capacity remains after connector timeouts",
                    errors=["connector not started: all worker slots remain occupied by timed-out calls"],
                ))
                pending.remove(future)


class Engine:
    def __init__(self, config: ScanConfig, index: SignatureIndex | None = None, progress: ProgressFn | None = None):
        self.config = config
        config.validate_security_options()
        self._validated_options = _security_options(config)
        self._index_supplied = index is not None
        self._signature_digest: str | None = None
        self.index = index if index is not None else self._load_index()
        self.progress = progress or (lambda cid, msg: None)
        # Connector ids whose worker threads outlived ``connector_timeout_seconds`` in
        # the last run. Their threads may still be blocked inside an SDK call;
        # a process that must exit promptly has to use ``os._exit``.
        self.abandoned_workers: list[str] = []
        self._abandoned_futures: list[Future[Any]] = []
        # An invalid inventory fails at construction. The first run reuses
        # this load; later runs of a reused Engine load it again.
        self.inventory: Inventory | None = Inventory.load(config.inventory) if config.inventory else None
        self._inventory_paths: list[str] | None = list(config.inventory)

    def _report_progress(self, connector: str, message: str) -> None:
        """A failed output observer must not change collection or scan completeness."""
        try:
            self.progress(connector, message)
        except Exception:  # noqa: BLE001 - third-party callback must not abort a worker
            log.warning("progress callback failed; scan continues")

    # ------------------------------------------------------------ preparation
    def _pack_digest(self) -> str | None:
        try:
            return signature_source_digest(self.config.signature_dirs or None,
                                           allow_override=self.config.allow_signature_override)
        except (OSError, ValueError):
            # The load that follows reports the underlying problem.
            return None

    def _load_index(self) -> SignatureIndex:
        # Digest before loading: a pack edited in between is then reloaded
        # by the next run rather than masked by a digest taken afterwards.
        digest = self._pack_digest()
        index = get_index(extra_dirs=self.config.signature_dirs or None, reload=True,
                          allow_override=self.config.allow_signature_override)
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

    def _refresh_inventory(self) -> None:
        # Registry approval can change independently of source inputs or an Engine
        # instance's lifetime. It is never persisted in connector cache entries.
        paths = list(self.config.inventory)
        if self._inventory_paths is None or paths != self._inventory_paths:
            self.inventory = Inventory.load(paths) if paths else None
        self._inventory_paths = None

    def _prepare_run(self) -> None:
        if any(not future.done() for future in self._abandoned_futures):
            raise RuntimeError("a previous timed-out connector is still running; use a fresh process for the next scan")
        self._abandoned_futures.clear()
        self.abandoned_workers.clear()
        self.config.min_confidence = validate_min_confidence(self.config.min_confidence)
        if _security_options(self.config) != self._validated_options:
            self.config.validate_security_options()
            self._validated_options = _security_options(self.config)
        self._refresh_index()
        self._refresh_inventory()

    # -------------------------------------------------------------- selection
    def _invalid_selectors(self, only: list[str] | None) -> list[str]:
        if not only:
            return []
        selectable = {value for spec in self.config.connectors if spec.enabled for value in (spec.id, spec.name)}
        return [selector for selector in only if selector not in selectable]

    def _select_jobs(self, only: list[str] | None) -> list[_Job]:
        return [(number, spec) for number, spec in enumerate(self.config.connectors, 1)
                if spec.enabled and (not only or spec.id in only or spec.name in only)]

    @staticmethod
    def _reject_selection(result: ScanResult, invalid: list[str]) -> ScanResult:
        result.collection_scope = {
            "schema": "shadowscan.collection-scope/v1", "comparable": False,
            "reason": "requested connectors are unknown or disabled",
        }
        result.stats = [ScanStats(
            connector="engine.selection", started_at=result.started_at, finished_at=now_iso(),
            skipped=True, incomplete=True, skip_reason="invalid connector selection",
            errors=[sanitize(f"unknown or disabled connector selector: {selector}") for selector in invalid],
        )]
        result.finished_at = now_iso()
        return result

    @staticmethod
    def _selection_stats(specs: list[ConnectorSpec]) -> list[ScanStats]:
        if specs:
            return []
        log.warning("no connectors selected")
        return [ScanStats(
            connector="engine", started_at=now_iso(), finished_at=now_iso(),
            skipped=True, skip_reason="no connectors selected", incomplete=True,
            errors=["no connectors selected"],
        )]

    # ------------------------------------------------------------- collection
    def _collect(self, jobs: list[_Job], cache: IncrementalCache, dump_directory: Path | None,
                 exports: _ExportLedger, started_at: str) -> tuple[dict[int, _JobResult], set[int]]:
        """Run every selected connector under deadline supervision."""
        states = {number: _JobState() for number, _ in jobs}
        runner = _ConnectorRunner(self, cache, dump_directory, exports)
        workers = max(1, min(self.config.parallel, len(jobs) or 1))
        # Supervise the single-worker path too. A ThreadPoolExecutor context
        # manager would wait forever for a stuck connector on exit.
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="shadowscan")
        futures = {pool.submit(runner.run, number, spec, states[number]): (number, spec) for number, spec in jobs}
        supervisor = _Supervisor(self, futures, states, workers, started_at)
        try:
            supervisor.run()
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return supervisor.completed, supervisor.timed_out

    # --------------------------------------------------------- postprocessing
    def _reconcile_and_score(self, findings: list[Finding]) -> None:
        for f in findings:
            if self.inventory is not None:
                entry = self.inventory.match(f)
                f.registry_match = entry.agent_id if entry else None
                f.shadow = entry is None
                if entry and not f.owner:
                    f.owner = entry.owner
            f.risk = assess(f, self.index, inventory_present=self.inventory is not None)

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
            errors.append(f"{omitted} finding(s) omitted after aggregation: sanitization safety limit exceeded")
        return findings, errors

    @staticmethod
    def _write_manifest(dump_directory: Path, exports: list[dict[str, Any]], started_at: str,
                        stats: list[ScanStats]) -> None:
        manifest = {
            "schema": "shadowscan.record-exports/v1", "started_at": started_at,
            "complete": bool(stats) and not any(st.incomplete or st.skipped or st.errors for st in stats),
            "exports": sorted(exports, key=lambda entry: entry["part"]),
        }
        try:
            write_private_text(Path(dump_directory) / "manifest.json", json.dumps(sanitize(manifest), indent=2) + "\n")
        except (OSError, ValueError) as exc:
            stats.append(ScanStats(
                connector="engine.exports", started_at=started_at, finished_at=now_iso(), incomplete=True,
                errors=[f"record export manifest could not be saved: {sanitize(str(exc))}"],
            ))

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
        stats = self._selection_stats(specs)
        cache = IncrementalCache(self.config, self.index)
        dump_directory = prepare_private_directory(self.config.dump_records) if self.config.dump_records else None
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
            stats.append(ScanStats(
                connector="engine.postprocess", started_at=result.started_at, finished_at=now_iso(),
                incomplete=True, errors=postprocess_errors,
            ))
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

_GATEWAY_TOTALS = (
    "events", "records", "aggregate_records", "tool_known", "tool_requests",
    "tool_call_responses", "tokens_in", "tokens_out", "cost", "errors",
)
_GATEWAY_DISTRIBUTIONS = ("models", "providers", "hosts", "user_agents", "source_ips", "end_users", "teams", "operations", "schemas")


def _gateway_source_snapshot(finding: Finding) -> dict[str, Any]:
    metadata = finding.metadata
    observations = metadata.get("runtime_observations", [])
    digest = hashlib.sha256(json.dumps(observations, sort_keys=True, default=str).encode()).hexdigest()
    return {
        "source": metadata.get("runtime_source", {}),
        "window": {"first_seen": finding.first_seen, "last_seen": finding.last_seen},
        "observation_sha256": digest,
        "metrics": {key: metadata[key] for key in (*_GATEWAY_TOTALS, *_GATEWAY_DISTRIBUTIONS) if key in metadata},
    }


def _gateway_sources(finding: Finding) -> list[dict[str, Any]]:
    existing = finding.metadata.get("runtime_sources")
    return existing if isinstance(existing, list) else [_gateway_source_snapshot(finding)]


def _unique_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate nested observations while retaining their first provenance."""
    def key_for(value: Any) -> Any:
        if isinstance(value, dict):
            return ("dict", frozenset((key, key_for(item)) for key, item in value.items()))
        if isinstance(value, (list, tuple)):
            return (type(value).__name__, tuple(key_for(item) for item in value))
        if isinstance(value, (set, frozenset)):
            return ("set", frozenset(key_for(item) for item in value))
        # JSON numbers remain equivalent when exporters vary number syntax,
        # but booleans must not collide with Python's equal numeric values.
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return ("number", value)
        return (type(value).__name__, value)

    unique: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        key = key_for(record)
        if key not in seen:
            seen.add(key)
            unique.append(record)
    return unique


def _merge_gateway_sources(cur: Finding, sources: list[dict[str, Any]]) -> None:
    unique = _unique_records(sources)
    cur.metadata["runtime_sources"] = unique
    for key in _GATEWAY_TOTALS:
        values = [source.get("metrics", {}).get(key) for source in unique]
        numbers = [value for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)]
        if numbers:
            total = sum(numbers)
            cur.metadata[key] = round(total, 4) if key == "cost" else total
    for key in _GATEWAY_DISTRIBUTIONS:
        counts: dict[str, int | float] = {}
        for source in unique:
            distribution = source.get("metrics", {}).get(key)
            if isinstance(distribution, dict):
                for name, value in distribution.items():
                    if isinstance(name, str) and isinstance(value, (int, float)) and not isinstance(value, bool):
                        counts[name] = counts.get(name, 0) + value
        if counts:
            cur.metadata[key] = dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
    events = cur.metadata.get("events")
    if isinstance(events, int):
        cur.title = re.sub(r": \d+ requests\b", f": {events} requests", cur.title, count=1)
        identity_signal = "gateway:" + str(cur.metadata.get("caller_kind", ""))
        identity_evidence = [ev for ev in cur.evidence if ev.signal == identity_signal]
        if identity_evidence:
            primary = identity_evidence[0]
            primary.description = re.sub(r"^\d+ LLM request\(s\)", f"{events} LLM request(s)", primary.description)
            cur.evidence = [ev for ev in cur.evidence if ev.signal != identity_signal or ev is primary]
    if len(unique) > 1:
        cur.metadata["runtime_merge_note"] = "Counts sum records across inputs; overlapping exports can represent the same requests."


def merge(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same id (same object seen by the same connector twice).

    Gateway IDs include export source identity. Repeated scans of the same
    configured source are idempotent here; observations from distinct exports
    remain separate even if caller and scope match. No cross-source request
    deduplication is inferred from matching timestamps or caller names.
    """
    by_id: dict[str, Finding] = {}
    for f in findings:
        cur = by_id.get(f.id)
        if cur is None:
            by_id[f.id] = f
            continue
        # Select the classification and its resource subtype as one pair. A
        # lexical subtype tie-break keeps repeated/grouped merges associative
        # without attaching the first record's subtype to another record's kind.
        priority = {Kind.AGENT: 3, Kind.SERVICE_IDENTITY: 2, Kind.OAUTH_GRANT: 1}
        classifications = [(finding.kind, finding.resource_type) for finding in (cur, f)]
        classification = max(classifications, key=lambda value: (priority.get(value[0], 0), value[0].value, value[1]))
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
        gateway_sources = _gateway_sources(cur) + _gateway_sources(f) if cur.surface == f.surface == Surface.GATEWAY else []
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
        cur.first_seen = min(x for x in (cur.first_seen, f.first_seen) if x) if (cur.first_seen or f.first_seen) else None
        cur.last_seen = max(x for x in (cur.last_seen, f.last_seen) if x) if (cur.last_seen or f.last_seen) else None
        for k, v in f.metadata.items():
            if k == "variable_names" and isinstance(v, list):
                existing = cur.metadata.get(k, [])
                if isinstance(existing, list):
                    cur.metadata[k] = sorted(set(existing) | set(v))
            elif k == "runtime_observations" and isinstance(v, list):
                # A merged gateway caller may have been exported from several
                # inputs. Keep each source alongside its observation so the
                # correlation report does not attribute every event to input A.
                old = cur.metadata.get(k, [])
                observations = []
                for finding, group in ((cur, old), (f, v)):
                    if not isinstance(group, list):
                        continue
                    for observation in group:
                        if isinstance(observation, dict):
                            entry = dict(observation)
                            entry.setdefault("source", finding.metadata.get("runtime_source", {}))
                            observations.append(entry)
                cur.metadata[k] = _unique_records(observations)
            else:
                cur.metadata.setdefault(k, v)
        if gateway_sources:
            _merge_gateway_sources(cur, gateway_sources)
        cur.recompute_confidence()
    return list(by_id.values())


# -------------------------------------------------------------- correlation

_NAME_KEYS = ("agent_name", "name", "display_name", "app_slug", "okta_name", "developer_name", "schema_name", "app_id", "client_id", "msa_app_id", "bot_id", "principal", "caller", "repository", "project", "function_name", "agent_id")


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
    for k, ids in keys.items():
        if 1 < len(ids) <= 25:
            for i in ids:
                related.setdefault(i, set()).update(ids - {i})
    if not related:
        return
    by_id = {f.id: f for f in findings}
    for fid, others in related.items():
        linked_finding = by_id.get(fid)
        if linked_finding:
            # only link across different connectors / surfaces (within one connector duplicates are merged already)
            links = sorted(o for o in others if by_id.get(o) and (by_id[o].connector != linked_finding.connector or by_id[o].surface != linked_finding.surface))
            if links:
                linked_finding.metadata["related"] = links
