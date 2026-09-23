"""Scan orchestration: run connectors, merge, correlate, reconcile with the inventory, score."""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from shadowscan import __version__
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, now_iso
from shadowscan.registry import Inventory
from shadowscan.risk import assess
from shadowscan.signatures import SignatureIndex, get_index

log = logging.getLogger("shadowscan.engine")

ProgressFn = Callable[[str, str], None]  # (connector id, message)


class Engine:
    def __init__(self, config: ScanConfig, index: SignatureIndex | None = None, progress: ProgressFn | None = None):
        self.config = config
        self.index = index or get_index(extra_dirs=config.signature_dirs or None)
        self.progress = progress or (lambda cid, msg: None)
        self.inventory: Inventory | None = None
        if config.inventory:
            self.inventory = Inventory.load(config.inventory)

    # ------------------------------------------------------------------ run
    def run(self, only: list[str] | None = None) -> ScanResult:
        result = ScanResult(version=__version__, inventory_size=len(self.inventory) if self.inventory else 0)
        specs = [s for s in self.config.enabled_connectors() if not only or s.id in only or s.name in only]
        if not specs:
            log.warning("no connectors selected")
        findings: list[Finding] = []
        stats: list[ScanStats] = []
        if self.config.dump_records:
            os.makedirs(self.config.dump_records, exist_ok=True)

        def _run(spec: ConnectorSpec) -> tuple[ConnectorSpec, list[Finding], ScanStats | None]:
            self.progress(spec.id, "starting")
            cfg = dict(spec.config)
            if self.config.dump_records:
                cfg["_dump_path"] = os.path.join(self.config.dump_records, f"{spec.id.replace('.', '_').replace('/', '_')}.jsonl")
            ctx = ConnectorContext(config=cfg, index=self.index, workdir=self.config.workdir)
            try:
                cls = get_connector_class(spec.name)
            except KeyError as exc:
                st = ScanStats(connector=spec.id, started_at=now_iso(), finished_at=now_iso(), skipped=True, skip_reason=str(exc), errors=[str(exc)])
                return spec, [], st
            connector = cls(ctx)
            fs = connector.run()
            st = ctx.stats
            if st:
                st.connector = spec.id
            self.progress(spec.id, f"{len(fs)} findings")
            return spec, fs, st

        workers = max(1, min(self.config.parallel, len(specs) or 1))
        if workers == 1:
            for spec in specs:
                _, fs, st = _run(spec)
                findings.extend(fs)
                if st:
                    stats.append(st)
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="shadowscan") as pool:
                futures = {pool.submit(_run, spec): spec for spec in specs}
                for fut in as_completed(futures):
                    _, fs, st = fut.result()
                    findings.extend(fs)
                    if st:
                        stats.append(st)

        findings = merge(findings)
        correlate(findings)
        for f in findings:
            if self.inventory is not None:
                entry = self.inventory.match(f)
                f.registry_match = entry.agent_id if entry else None
                f.shadow = entry is None
                if entry and not f.owner:
                    f.owner = entry.owner
            f.risk = assess(f, self.index, inventory_present=self.inventory is not None)
        if self.config.min_confidence > 0:
            findings = [f for f in findings if f.confidence >= self.config.min_confidence]
        findings.sort(key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title))
        result.findings = findings
        result.stats = sorted(stats, key=lambda s: s.connector)
        result.finished_at = now_iso()
        return result


# ------------------------------------------------------------------ merging


def merge(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same id (same object seen by the same connector twice)."""
    by_id: dict[str, Finding] = {}
    for f in findings:
        cur = by_id.get(f.id)
        if cur is None:
            by_id[f.id] = f
            continue
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
            cur.metadata.setdefault(k, v)
        if f.kind == Kind.AGENT and cur.kind == Kind.FRAMEWORK_USAGE:
            cur.kind = Kind.AGENT
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
        f = by_id.get(fid)
        if f:
            # only link across different connectors / surfaces (within one connector duplicates are merged already)
            links = sorted(o for o in others if by_id.get(o) and (by_id[o].connector != f.connector or by_id[o].surface != f.surface))
            if links:
                f.metadata["related"] = links
