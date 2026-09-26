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
from shadowscan.utils.http import (
    CooperativeStop,
    reset_allow_private_origin,
    reset_cooperative_stop,
    set_allow_private_origin,
    set_cooperative_stop,
)
from shadowscan.utils.output import prepare_private_directory, write_private_text
from shadowscan.utils.pseudonym import PseudonymKey, configured_key_file, load_pseudonymization_key
from shadowscan.utils.redaction import SanitizationLimitError, sanitize

log = logging.getLogger("shadowscan.engine")

ProgressFn = Callable[[str, str], None]  # (connector id, message)
_JobResult = tuple[ConnectorSpec, list[Finding], ScanStats]
_JobFutures = dict[Future[_JobResult], tuple[int, ConnectorSpec]]  # future -> (config ordinal, spec)

@dataclass
class _JobState:
    started_at: str | None = None
    deadline: float | None = None
    completed_at: float | None = None
    cancelled: Event = field(default_factory=Event)
    publication_lock: Lock = field(default_factory=Lock)


@dataclass
class _ScanRun:
    """State one ``Engine.run`` shares between its supervisor and connector workers."""

    jobs: list[tuple[int, ConnectorSpec]]  # (config ordinal, spec), in configured order
    started_at: str
    cache: IncrementalCache
    dump_directory: Path | None
    states: dict[int, _JobState]
    gateway_identity_key: bytes
    workers: int
    exports: list[dict[str, Any]] = field(default_factory=list)
    export_lock: Lock = field(default_factory=Lock)
    timed_out: set[int] = field(default_factory=set)

    def record_export(self, state: _JobState, entry: dict[str, Any]) -> None:
        with self.export_lock:
            if not state.cancelled.is_set():
                self.exports.append(entry)


def _cooperative_stop_for(ctx: ConnectorContext) -> Callable[[], None]:
    """Translate the connector deadline into a signal RuntimeError handlers cannot absorb."""

    def check() -> None:
        try:
            ctx.check_deadline()
        except ConnectorError as exc:
            raise CooperativeStop(str(exc)) from None

    return check


def _pending_expired(state: _JobState, now: float) -> bool:
    """Whether a still-pending worker has exhausted its completion deadline.

    A worker that finished inside its deadline may not appear in the poll's
    ``done`` set yet; its completion timestamp, not the wall clock, decides.
    """
    if state.deadline is None or now < state.deadline:
        return False
    return state.completed_at is None or state.completed_at >= state.deadline


def _capacity_exhausted(scan: _ScanRun, futures: _JobFutures) -> bool:
    """Whether every worker slot is occupied by a call that already timed out."""
    running = [future for future in futures if future.running()]
    return (
        len(running) >= scan.workers
        and all(futures[future][0] in scan.timed_out for future in running)
    )


def _retain_sanitizable(candidates: list[Finding]) -> tuple[list[Finding], int]:
    """Sanitize findings in place; drop and count those over the safety limit."""
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


def _merge_part_warnings(parts: list[ScanStats]) -> list[str]:
    """Concatenate per-root warnings in order, stating a cache note once per connector."""
    merged: list[str] = []
    notes: set[str] = set()
    for warning in (w for part in parts for w in part.warnings):
        if warning.startswith("incremental: "):
            if warning in notes:
                continue
            notes.add(warning)
        merged.append(warning)
    return merged


def _seal_diagnostics(st: ScanStats, findings: int) -> None:
    """Record the finding count and sanitize connector diagnostics within the safety limit."""
    st.findings = findings
    try:
        st.errors = sanitize(st.errors)
        st.warnings = sanitize(st.warnings)
    except SanitizationLimitError:
        st.incomplete = True
        st.errors = ["connector diagnostics omitted: sanitization safety limit exceeded"]
        st.warnings = []


def _export_entry(spec: ConnectorSpec, dump_key: str, cfg: dict[str, Any], ctx: ConnectorContext,
                  st: ScanStats) -> dict[str, Any]:
    """The record-export manifest entry for one connector (or repository root) run."""
    exported = ctx.dump_path == cfg.get("_dump_path") and ctx.dump_path is not None and not st.skipped
    return {
        "config_ordinal": int(dump_key.split("-")[0]), "part": dump_key,
        "connector": spec.name, "label": spec.label,
        "filename": Path(ctx.dump_path).name if exported and ctx.dump_path else None,
        "complete": not (st.incomplete or st.skipped or st.errors),
        "exported": exported,
    }


class Engine:
    def __init__(self, config: ScanConfig, index: SignatureIndex | None = None, progress: ProgressFn | None = None):
        self.config = config
        config.validate_security_options()
        self._index_supplied = index is not None
        self.index = index if index is not None else get_index(
            extra_dirs=config.signature_dirs or None, reload=True, allow_override=config.allow_signature_override,
        )
        self.progress = progress or (lambda cid, msg: None)
        self.inventory: Inventory | None = None
        # Connector ids whose worker threads outlived ``connector_timeout_seconds`` in
        # the last run. Their threads may still be blocked inside an SDK call;
        # a process that must exit promptly has to use ``os._exit``.
        self.abandoned_workers: list[str] = []
        self._abandoned_futures: list[Future[Any]] = []
        # Fail construction on an invalid inventory. Each run reloads it, since
        # approvals may be edited between runs of one Engine.
        if config.inventory:
            self.inventory = Inventory.load(config.inventory)
        # An operator key makes gateway pseudonyms stable across scans; without
        # one every run draws a fresh random key. Never store the key in config.
        key_file = configured_key_file(config.pseudonymization_key_file)
        self._pseudonym_key: PseudonymKey | None = load_pseudonymization_key(key_file) if key_file else None

    def _report_progress(self, connector: str, message: str) -> None:
        """A failed output observer must not change collection or scan completeness."""
        try:
            self.progress(connector, message)
        except Exception:  # noqa: BLE001 - third-party callback must not abort a worker
            log.warning("progress callback failed; scan continues")

    # ------------------------------------------------------------------ run
    def run(self, only: list[str] | None = None) -> ScanResult:
        self._prepare_run()
        result = ScanResult(version=__version__, inventory_size=len(self.inventory) if self.inventory else 0)
        if only and self._reject_invalid_selection(only, result):
            return result
        jobs = [(number, spec) for number, spec in enumerate(self.config.connectors, 1)
                if spec.enabled and (not only or spec.id in only or spec.name in only)]
        specs = [spec for _, spec in jobs]
        self.config.validate_connector_isolation(specs)
        result.collection_scope = build_collection_scope(
            self.config, self.index, specs,
            pseudonymization_key_id=self._pseudonym_key.key_id if self._pseudonym_key else None,
        )
        stats: list[ScanStats] = []
        if not specs:
            log.warning("no connectors selected")
            stats.append(ScanStats(
                connector="engine", started_at=now_iso(), finished_at=now_iso(),
                skipped=True, skip_reason="no connectors selected", incomplete=True,
                errors=["no connectors selected"],
            ))
        scan = self._new_scan(jobs, result.started_at)
        completed = self._supervise(scan)
        findings = self._collect_results(scan, completed, stats)
        findings = self._postprocess(findings, stats, result.started_at)
        self._write_export_manifest(scan, stats)
        result.findings = findings
        result.stats = sorted(stats, key=lambda s: s.connector)
        result.finished_at = now_iso()
        return result

    def _prepare_run(self) -> None:
        """Refuse unsafe reuse, then revalidate options and reload per-run inputs."""
        if any(not future.done() for future in self._abandoned_futures):
            raise RuntimeError("a previous timed-out connector is still running; use a fresh process for the next scan")
        self._abandoned_futures.clear()
        self.abandoned_workers.clear()
        self.config.min_confidence = validate_min_confidence(self.config.min_confidence)
        self.config.validate_security_options()
        # A reusable Engine must notice signature pack edits between runs.
        if not self._index_supplied:
            self.index = get_index(extra_dirs=self.config.signature_dirs or None, reload=True,
                                   allow_override=self.config.allow_signature_override)
        # Registry approval can change independently of source inputs or an Engine
        # instance's lifetime. It is never persisted in connector cache entries.
        self.inventory = Inventory.load(self.config.inventory) if self.config.inventory else None

    def _reject_invalid_selection(self, only: list[str], result: ScanResult) -> bool:
        """Mark ``result`` incomplete and not comparable if a selector names no enabled connector."""
        selectable = {value for spec in self.config.connectors if spec.enabled for value in (spec.id, spec.name)}
        invalid = [selector for selector in only if selector not in selectable]
        if not invalid:
            return False
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
        return True

    def _new_scan(self, jobs: list[tuple[int, ConnectorSpec]], started_at: str) -> _ScanRun:
        return _ScanRun(
            jobs=jobs, started_at=started_at,
            cache=IncrementalCache(self.config, self.index),
            dump_directory=prepare_private_directory(self.config.dump_records) if self.config.dump_records else None,
            states={number: _JobState() for number, _ in jobs},
            # Identical gateway sources in one report share an opaque identity,
            # while separate Engine.run calls cannot link redacted caller/scope IDs.
            gateway_identity_key=(
                self._pseudonym_key.subkey("gateway") if self._pseudonym_key else secrets.token_bytes(32)
            ),
            workers=max(1, min(self.config.parallel, len(jobs) or 1)),
        )

    # ------------------------------------------------------------ supervision
    def _supervise(self, scan: _ScanRun) -> dict[int, _JobResult]:
        """Run every job under its completion deadline; return results by config ordinal."""
        # Supervise the single-worker path too. A ThreadPoolExecutor context
        # manager would wait forever for a stuck connector on exit.
        pool = ThreadPoolExecutor(max_workers=scan.workers, thread_name_prefix="shadowscan")
        futures = {pool.submit(self._run_job, scan, number, spec): (number, spec) for number, spec in scan.jobs}
        pending = set(futures)
        completed: dict[int, _JobResult] = {}
        try:
            while pending:
                done, _ = wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                expired = []
                for future in done:
                    number, _ = futures[future]
                    state = scan.states[number]
                    if state.completed_at is not None and state.deadline is not None and state.completed_at >= state.deadline:
                        expired.append(future)
                    else:
                        completed[number] = future.result()
                        pending.remove(future)
                now = time.monotonic()
                for future in pending - done:
                    if _pending_expired(scan.states[futures[future][0]], now):
                        expired.append(future)
                for future in expired:
                    number, spec = futures[future]
                    completed[number] = self._expire_job(scan, number, spec, future)
                    pending.remove(future)
                # A timed-out worker can still be running inside an SDK or
                # plugin call. Preserve queued siblings while *any* worker
                # can eventually run them. Only abandon the queue when all
                # worker slots are still occupied by timed-out calls; waiting
                # for those calls would defeat the completion deadline, and
                # replacing them would exceed the configured parallelism.
                if pending and scan.timed_out and _capacity_exhausted(scan, futures):
                    self._cancel_queued(scan, futures, pending, completed)
        except BaseException:
            # A worker failed outside its own isolation (or the supervisor was
            # interrupted). Cancel every sibling so none publishes a cache entry
            # or export after run() has failed, and record running ones as
            # abandoned for the next run's refusal check.
            for future in tuple(pending):
                number, spec = futures[future]
                self._expire_job(scan, number, spec, future)
            raise
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return completed

    def _expire_job(self, scan: _ScanRun, number: int, spec: ConnectorSpec, future: Future[_JobResult]) -> _JobResult:
        """Cancel a job past its completion deadline and replace its results with an incomplete stat."""
        state = scan.states[number]
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
        scan.timed_out.add(number)
        if future.running():
            self.abandoned_workers.append(spec.id)
            self._abandoned_futures.append(future)
        message = "connector_timeout completion deadline exceeded; results discarded"
        return (spec, [], ScanStats(
            connector=spec.id, started_at=state.started_at or scan.started_at,
            finished_at=now_iso(), incomplete=True, skipped=True,
            skip_reason=message, errors=[message],
            warnings=["Cancellation is cooperative: an in-flight SDK, plugin call, or filesystem "
                      "replacement may continue. A cache or record artifact whose replacement "
                      "started before cancellation may appear after this incomplete report; do not "
                      "use timed-out artifacts as accepted results. Use an external process timeout "
                      "when a hard execution limit is required."],
        ))

    def _cancel_queued(self, scan: _ScanRun, futures: _JobFutures, pending: set[Future[_JobResult]],
                       completed: dict[int, _JobResult]) -> None:
        """Report queued jobs as not started once no worker slot can run them."""
        for future in tuple(pending):
            if future.cancel():
                number, spec = futures[future]
                # A cancelled future never runs, so no worker shares this job's
                # state or publication lock; mark it cancelled like a timeout.
                scan.states[number].cancelled.set()
                scan.timed_out.add(number)
                completed[number] = (spec, [], ScanStats(
                    connector=spec.id, started_at=scan.started_at, finished_at=now_iso(),
                    incomplete=True, skipped=True,
                    skip_reason="no worker capacity remains after connector timeouts",
                    errors=["connector not started: all worker slots remain occupied by timed-out calls"],
                ))
                pending.remove(future)

    # ---------------------------------------------------------------- workers
    def _connector_class(self, name: str) -> type[BaseConnector]:
        if self.config.plugins:
            return get_connector_class(name, allowed_plugins=self.config.plugins)
        return get_connector_class(name)

    def _run_job(self, scan: _ScanRun, number: int, spec: ConnectorSpec) -> _JobResult:
        state = scan.states[number]
        state.started_at = now_iso()
        timeout = self.config.connector_timeout_seconds
        state.deadline = time.monotonic() + timeout
        try:
            return self._run_job_parts(scan, number, spec)
        finally:
            # Include sanitization, cache writes and callbacks in the
            # measured runtime, even if completion precedes the next poll.
            state.completed_at = time.monotonic()

    def _splits_roots(self, scan: _ScanRun, spec: ConnectorSpec) -> bool:
        """Whether a multi-root filesystem connector runs as independent per-root cache units."""
        roots = spec.config.get("paths")
        root_ids = spec.config.get("root_ids")
        split_roots = (
            self.config.incremental and spec.name == "code.filesystem"
            and not spec.config.get("input") and isinstance(roots, list) and len(roots) > 1
        )
        if split_roots:
            try:
                if spec.label or spec.config.get("label"):
                    validate_distinct_paths(roots)
                if root_ids is not None:
                    validate_root_ids(roots, root_ids)
            except ConnectorError:
                # Run once so constructor validation reports an incomplete
                # scan, rather than partially scanning the valid children.
                split_roots = False
        if split_roots:
            try:
                split_roots = scan.cache.supports_connector(spec, self._connector_class(spec.name))
            except Exception:  # noqa: BLE001 - _run_connector reports lookup/import failures as incomplete
                split_roots = False
        return split_roots

    def _run_job_parts(self, scan: _ScanRun, number: int, spec: ConnectorSpec) -> _JobResult:
        state = scan.states[number]
        roots = spec.config.get("paths")
        if not self._splits_roots(scan, spec) or not isinstance(roots, list):
            return self._run_connector(scan, spec, f"{number:04d}", state)
        root_ids = spec.config.get("root_ids")
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
            _, child_findings, child_stats = self._run_connector(scan, ConnectorSpec(
                name=spec.name, config=child_config, label=spec.label,
            ), f"{number:04d}-{root_number:04d}", state)
            combined.extend(child_findings)
            parts.append(child_stats)
        cached_count = sum(s.cached for s in parts)
        stats = ScanStats(
            connector=spec.id, started_at=min(s.started_at for s in parts),
            finished_at=now_iso(), findings=len(combined),
            objects_examined=sum(s.objects_examined for s in parts),
            errors=[e for s in parts for e in s.errors],
            warnings=_merge_part_warnings(parts),
            incomplete=any(s.incomplete or s.skipped or s.errors for s in parts),
            skipped=all(s.skipped for s in parts), cached=cached_count == len(parts),
        )
        if cached_count:
            stats.warnings.append(f"incremental: reused {cached_count}/{len(parts)} unchanged repository roots")
        return spec, combined, stats

    def _connector_config(self, scan: _ScanRun, spec: ConnectorSpec, dump_key: str) -> dict[str, Any]:
        cfg = dict(spec.config)
        if spec.name.startswith("cloud."):
            # Scan-wide approval cannot be bypassed by a connector-level key.
            cfg["allow_instance_credentials"] = self.config.allow_instance_credentials
        if spec.label:
            cfg.setdefault("label", spec.label)
        if scan.dump_directory:
            label = re.sub(r"[^A-Za-z0-9_-]", "_", spec.id)[:80] or "connector"
            cfg["_dump_path"] = os.path.join(scan.dump_directory, f"{dump_key}-{label}.jsonl")
        return cfg

    def _run_connector(self, scan: _ScanRun, spec: ConnectorSpec, dump_key: str, state: _JobState) -> _JobResult:
        self._report_progress(spec.id, "starting")
        cfg = self._connector_config(scan, spec, dump_key)
        ctx = ConnectorContext(config=cfg, index=self.index, workdir=self.config.workdir,
                               deadline=state.deadline, cancelled=state.cancelled,
                               publication_lock=state.publication_lock,
                               gateway_identity_key=scan.gateway_identity_key if spec.name == "gateway.logs" else None)
        cache = scan.cache
        fs: list[Finding] = []
        started_at = now_iso()
        cache_note: str | None = None
        origin_token = set_allow_private_origin(self.config.allow_private_origin)
        stop_token = set_cooperative_stop(_cooperative_stop_for(ctx))
        try:
            ctx.check_deadline()
            cls = self._connector_class(spec.name)
            # Constructor validation still runs before a cached result is used.
            connector = cls(ctx)
            eligible = cache.supports_connector(spec, cls)
            if eligible and cache.disabled_reason:
                cache_note = f"incremental: {cache.disabled_reason}; ran a full scan"
            snapshot = cache.snapshot(spec) if eligible else None
            cached = cache.load(spec, snapshot) if snapshot else None
            if cached is not None:
                fs, st = cached
                if cache.snapshot(spec) == snapshot:
                    ctx.check_deadline()
                    self._report_progress(spec.id, f"{len(fs)} findings (unchanged input; cached)")
                    return spec, fs, st
            fs = []
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
            reset_cooperative_stop(stop_token)
            reset_allow_private_origin(origin_token)
        if cache_note:
            st.warnings.append(cache_note)
        _seal_diagnostics(st, len(fs))
        if scan.dump_directory and not state.cancelled.is_set():
            scan.record_export(state, _export_entry(spec, dump_key, cfg, ctx, st))
        if not state.cancelled.is_set():
            self._report_progress(spec.id, f"{len(fs)} findings")
        return spec, fs, st

    # --------------------------------------------------------- aggregation
    def _collect_results(self, scan: _ScanRun, completed: dict[int, _JobResult],
                         stats: list[ScanStats]) -> list[Finding]:
        """Gather per-connector results in configured order and settle record exports."""
        findings: list[Finding] = []
        # Merge uses first-observed owner and metadata as precedence.
        # Preserve configured order regardless of request completion.
        for number, _ in scan.jobs:
            _, fs, st = completed[number]
            findings.extend(fs)
            stats.append(st)
        if scan.dump_directory:
            # Timed-out workers may still be inside ``record_export``.
            with scan.export_lock:
                scan.exports = [entry for entry in scan.exports if entry["config_ordinal"] not in scan.timed_out]
                for number, spec in scan.jobs:
                    if number in scan.timed_out:
                        scan.exports.append({
                            "config_ordinal": number, "part": f"{number:04d}", "connector": spec.name,
                            "label": spec.label, "filename": None, "complete": False, "exported": False,
                        })
        return findings

    def _postprocess(self, findings: list[Finding], stats: list[ScanStats], started_at: str) -> list[Finding]:
        """Merge, correlate, reconcile with the inventory, score, then filter and rank findings."""
        # Individually bounded findings can exceed the output budget when
        # merged. Reject only that aggregate before correlation touches it.
        findings, omitted = _retain_sanitizable(merge(findings))
        correlate(findings)
        postprocess_errors: list[str] = []
        try:
            correlate_runtime(findings)
        except SanitizationLimitError:
            postprocess_errors.append("runtime correlation incomplete: sanitization safety limit exceeded")
        self._reconcile_and_score(findings)
        findings, late_omitted = _retain_sanitizable(findings)
        omitted += late_omitted
        if omitted:
            postprocess_errors.append(f"{omitted} finding(s) omitted after aggregation: sanitization safety limit exceeded")
        if postprocess_errors:
            stats.append(ScanStats(
                connector="engine.postprocess", started_at=started_at, finished_at=now_iso(),
                incomplete=True, errors=postprocess_errors,
            ))
        if self.config.min_confidence > 0:
            findings = [f for f in findings if f.confidence >= self.config.min_confidence]
        findings.sort(key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title))
        return findings

    def _reconcile_and_score(self, findings: list[Finding]) -> None:
        for f in findings:
            if self.inventory is not None:
                entry = self.inventory.match(f)
                f.registry_match = entry.agent_id if entry else None
                f.shadow = entry is None
                if entry and not f.owner:
                    f.owner = entry.owner
            f.risk = assess(f, self.index, inventory_present=self.inventory is not None)

    def _write_export_manifest(self, scan: _ScanRun, stats: list[ScanStats]) -> None:
        if not scan.dump_directory:
            return
        manifest = {
            "schema": "shadowscan.record-exports/v1", "started_at": scan.started_at,
            "complete": bool(stats) and not any(st.incomplete or st.skipped or st.errors for st in stats),
            "exports": sorted(scan.exports, key=lambda entry: entry["part"]),
        }
        try:
            write_private_text(Path(scan.dump_directory) / "manifest.json", json.dumps(sanitize(manifest), indent=2) + "\n")
        except (OSError, ValueError) as exc:
            stats.append(ScanStats(
                connector="engine.exports", started_at=scan.started_at, finished_at=now_iso(), incomplete=True,
                errors=[f"record export manifest could not be saved: {sanitize(str(exc))}"],
            ))

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
