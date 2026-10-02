"""Merge findings with the same id observed by the same connector twice."""

from __future__ import annotations

from shadowscan.connectors.common import merge_duplicate_metadata
from shadowscan.models import Finding, Kind

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
        cur.first_seen = min((x for x in (cur.first_seen, f.first_seen) if x), default=None)
        cur.last_seen = max((x for x in (cur.last_seen, f.last_seen) if x), default=None)
        cur.recompute_confidence()
    return list(by_id.values())
