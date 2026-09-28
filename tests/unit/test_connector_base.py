"""BaseConnector and ConnectorContext: sanitizer limits and diagnostic caps."""

from __future__ import annotations

import json

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.models import Finding, Kind, ScanStats, Surface

KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"


def _finding(title: str, **kwargs) -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="test.records",
        kind=Kind.AGENT,
        title=title,
        resource=f"repo:{title}",
        resource_type="repository",
        **kwargs,
    )


class _Oversized(BaseConnector):
    """Yields an ordinary finding, one whose aggregate exceeds the sanitizer budget, then a credential finding."""

    name = "test.records"

    def collect(self):
        yield {"id": 1}

    def analyze(self, records):
        yield _finding("first")
        huge = _finding("aggregate")
        # Individually bounded pieces whose expanded serialization exceeds the budget.
        huge.metadata["agent_definitions"] = [{"tools": ["tool"] * 1000}] * 200
        yield huge
        secret = _finding("credential")
        secret.metadata["excerpt"] = f"OPENAI_API_KEY={KEY}"
        yield secret


class _Probe(BaseConnector):
    name = "test.offline"

    def collect(self):
        return []

    def analyze(self, records):
        return []


def test_one_oversized_finding_is_omitted_without_discarding_the_others(index):
    ctx = ConnectorContext(config={}, index=index)
    findings = _Oversized(ctx).run()
    assert [f.title for f in findings] == ["first", "credential"]
    assert ctx.stats is not None and ctx.stats.incomplete
    assert any("finding omitted: sanitization safety limit exceeded" in e for e in ctx.stats.errors)
    assert KEY not in json.dumps([f.to_dict() for f in findings])


def test_context_diagnostic_limits_preserve_failure_status(monkeypatch, index, caplog):
    monkeypatch.setattr(ConnectorContext, "_MAX_DIAGNOSTICS", 2)
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=_Probe.name, started_at="now")
    for _ in range(10):
        ctx.warn("optional", incomplete=False)
    assert not ctx.stats.incomplete
    # A suppressed diagnostic must still mark missing required coverage.
    ctx.warn("required", incomplete=True)
    for _ in range(10):
        ctx.error("invalid record")
    assert ctx.stats.incomplete
    assert len(ctx.stats.errors) == len(ctx.stats.warnings) == 3
    assert len(caplog.records) == 6
    assert "diagnostic limit" in ctx.stats.errors[-1]
