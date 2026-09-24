"""Scan orchestration: run connectors, merge, correlate, reconcile with the inventory, score."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.comparison import build_collection_scope
from shadowscan.config import ConnectorSpec, ScanConfig, validate_min_confidence
from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.code.filesystem import validate_distinct_paths, validate_root_ids
from shadowscan.correlation import correlate_runtime
from shadowscan.incremental import IncrementalCache
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface, now_iso
from shadowscan.registry import Inventory
from shadowscan.risk import assess
from shadowscan.signatures import SignatureIndex, get_index
from shadowscan.utils.http import reset_allow_private_origin, set_allow_private_origin
from shadowscan.utils.output import prepare_private_directory, write_private_text
from shadowscan.utils.redaction import SanitizationLimitError, sanitize

log = logging.getLogger("shadowscan.engine")

ProgressFn = Callable[[str, str], None]  # (connector id, message)


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
        if config.inventory:
            self.inventory = Inventory.load(config.inventory)

    # ------------------------------------------------------------------ run
    def run(self, only: list[str] | None = None) -> ScanResult:
        self.config.min_confidence = validate_min_confidence(self.config.min_confidence)
        self.config.validate_security_options()
        # A reusable Engine must notice signature pack edits between runs.
        if not self._index_supplied:
            self.index = get_index(extra_dirs=self.config.signature_dirs or None, reload=True,
                                   allow_override=self.config.allow_signature_override)
        # Registry approval can change independently of source inputs or an Engine
        # instance's lifetime. It is never persisted in connector cache entries.
        self.inventory = Inventory.load(self.config.inventory) if self.config.inventory else None
        result = ScanResult(version=__version__, inventory_size=len(self.inventory) if self.inventory else 0)
        if only:
            selectable = {value for spec in self.config.connectors if spec.enabled for value in (spec.id, spec.name)}
            invalid = [selector for selector in only if selector not in selectable]
            if invalid:
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
        jobs = [(number, spec) for number, spec in enumerate(self.config.connectors, 1)
                if spec.enabled and (not only or spec.id in only or spec.name in only)]
        specs = [spec for _, spec in jobs]
        result.collection_scope = build_collection_scope(self.config, self.index, specs)
        if not specs:
            log.warning("no connectors selected")
        findings: list[Finding] = []
        stats: list[ScanStats] = []
        if not specs:
            stats.append(ScanStats(
                connector="engine", started_at=now_iso(), finished_at=now_iso(),
                skipped=True, skip_reason="no connectors selected", incomplete=True,
                errors=["no connectors selected"],
            ))
        cache = IncrementalCache(self.config, self.index)
        dump_directory = prepare_private_directory(self.config.dump_records) if self.config.dump_records else None
        exports: list[dict[str, Any]] = []

        def _lookup(name: str):
            if self.config.plugins:
                return get_connector_class(name, allowed_plugins=self.config.plugins)
            return get_connector_class(name)

        def _run_one(spec: ConnectorSpec, dump_key: str) -> tuple[ConnectorSpec, list[Finding], ScanStats]:
            self.progress(spec.id, "starting")
            cfg = dict(spec.config)
            if spec.label:
                cfg.setdefault("label", spec.label)
            if dump_directory:
                label = re.sub(r"[^A-Za-z0-9_-]", "_", spec.id)[:80] or "connector"
                cfg["_dump_path"] = os.path.join(dump_directory, f"{dump_key}-{label}.jsonl")
            ctx = ConnectorContext(config=cfg, index=self.index, workdir=self.config.workdir)
            fs: list[Finding] = []
            started_at = now_iso()
            origin_token = set_allow_private_origin(self.config.allow_private_origin)
            try:
                cls = _lookup(spec.name)
                # Constructor validation still runs before a cached result is used.
                connector = cls(ctx)
                snapshot = cache.snapshot(spec) if cache.supports_connector(spec, cls) else None
                cached = cache.load(spec, snapshot) if snapshot else None
                if cached is not None:
                    fs, st = cached
                    if cache.snapshot(spec) == snapshot:
                        self.progress(spec.id, f"{len(fs)} findings (unchanged input; cached)")
                        return spec, fs, st
                fs = []
                collected = connector.run()
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
                        st.cache_key = snapshot.fingerprint
                        cache.save(snapshot, fs, st)
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
                log.warning("connector failed: %s", message)
            finally:
                reset_allow_private_origin(origin_token)
            st.findings = len(fs)
            try:
                st.errors = sanitize(st.errors)
                st.warnings = sanitize(st.warnings)
            except SanitizationLimitError:
                st.incomplete = True
                st.errors = ["connector diagnostics omitted: sanitization safety limit exceeded"]
                st.warnings = []
            if dump_directory:
                exported = ctx.dump_path == cfg.get("_dump_path") and ctx.dump_path is not None and not st.skipped
                exports.append({
                    "config_ordinal": int(dump_key.split("-")[0]), "part": dump_key,
                    "connector": spec.name, "label": spec.label,
                    "filename": Path(ctx.dump_path).name if exported and ctx.dump_path else None,
                    "complete": not (st.incomplete or st.skipped or st.errors),
                    "exported": exported,
                })
            self.progress(spec.id, f"{len(fs)} findings")
            return spec, fs, st

        def _run(number: int, spec: ConnectorSpec) -> tuple[ConnectorSpec, list[Finding], ScanStats]:
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
                    split_roots = cache.supports_connector(spec, _lookup(spec.name))
                except Exception:  # noqa: BLE001 - _run_one reports lookup/import failures as incomplete
                    split_roots = False
            if not split_roots or not isinstance(roots, list):
                return _run_one(spec, f"{number:04d}")
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
                _, child_findings, child_stats = _run_one(ConnectorSpec(
                    name=spec.name, config=child_config, label=spec.label,
                ), f"{number:04d}-{root_number:04d}")
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
            if all(s.cache_key for s in parts):
                stats.cache_key = hashlib.sha256("|".join(s.cache_key or "" for s in parts).encode()).hexdigest()
            return spec, combined, stats

        workers = max(1, min(self.config.parallel, len(specs) or 1))
        if workers == 1:
            for number, spec in jobs:
                _, fs, st = _run(number, spec)
                findings.extend(fs)
                if st:
                    stats.append(st)
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="shadowscan") as pool:
                futures = {pool.submit(_run, number, spec): spec for number, spec in jobs}
                for fut in as_completed(futures):
                    _, fs, st = fut.result()
                    findings.extend(fs)
                    if st:
                        stats.append(st)

        omitted = 0

        def safe_findings(candidates: list[Finding]) -> list[Finding]:
            nonlocal omitted
            retained = []
            for finding in candidates:
                try:
                    finding.sanitize()
                except SanitizationLimitError:
                    omitted += 1
                    continue
                retained.append(finding)
            return retained

        # Individually bounded findings can exceed the output budget when
        # merged. Reject only that aggregate before correlation touches it.
        findings = safe_findings(merge(findings))
        correlate(findings)
        postprocess_errors = []
        try:
            correlate_runtime(findings)
        except SanitizationLimitError:
            postprocess_errors.append("runtime correlation incomplete: sanitization safety limit exceeded")
        for f in findings:
            if self.inventory is not None:
                entry = self.inventory.match(f)
                f.registry_match = entry.agent_id if entry else None
                f.shadow = entry is None
                if entry and not f.owner:
                    f.owner = entry.owner
            f.risk = assess(f, self.index, inventory_present=self.inventory is not None)
        findings = safe_findings(findings)
        if omitted:
            postprocess_errors.append(f"{omitted} finding(s) omitted after aggregation: sanitization safety limit exceeded")
        if postprocess_errors:
            stats.append(ScanStats(
                connector="engine.postprocess", started_at=result.started_at, finished_at=now_iso(),
                incomplete=True, errors=postprocess_errors,
            ))
        if self.config.min_confidence > 0:
            findings = [f for f in findings if f.confidence >= self.config.min_confidence]
        findings.sort(key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title))
        if dump_directory:
            manifest = {
                "schema": "shadowscan.record-exports/v1", "started_at": result.started_at,
                "complete": bool(stats) and not any(st.incomplete or st.skipped or st.errors for st in stats),
                "exports": sorted(exports, key=lambda entry: entry["part"]),
            }
            try:
                write_private_text(Path(dump_directory) / "manifest.json", json.dumps(sanitize(manifest), indent=2) + "\n")
            except (OSError, ValueError) as exc:
                stats.append(ScanStats(
                    connector="engine.exports", started_at=result.started_at, finished_at=now_iso(), incomplete=True,
                    errors=[f"record export manifest could not be saved: {sanitize(str(exc))}"],
                ))
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


def _merge_gateway_sources(cur: Finding, sources: list[dict[str, Any]]) -> None:
    unique: list[dict[str, Any]] = []
    for source in sources:
        if isinstance(source, dict) and source not in unique:
            unique.append(source)
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
            if (e.signal, e.location, e.description) not in seen:
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
                            if entry not in observations:
                                observations.append(entry)
                cur.metadata[k] = observations
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
