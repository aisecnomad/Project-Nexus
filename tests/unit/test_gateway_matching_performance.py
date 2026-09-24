"""Repeated exported headers reuse bounded, successful framework summaries."""

from __future__ import annotations

from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import Event, GatewayLogConnector
from shadowscan.models import ScanStats
from shadowscan.signatures.matcher import MatchTimeoutError


def record():
    return {"service": "worker", "model": "gpt-4o", "user_agent": "langchain/0.3",
            "timestamp": "2026-09-23T12:00:00Z"}


def test_parallel_repeated_gateway_records_preserve_counts_with_fewer_matches(index, monkeypatch):
    original = index.match_user_agent
    calls = Counter()
    lock = Lock()

    def count(ua):
        with lock:
            calls[ua] += 1
        return original(ua)

    monkeypatch.setattr(index, "match_user_agent", count)

    def scan(_):
        ctx = ConnectorContext(config={"format": "generic"}, index=index)
        ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
        findings = list(GatewayLogConnector(ctx).analyze(record() for _ in range(100)))
        assert not ctx.stats.errors and not ctx.stats.incomplete
        assert len(findings) == 1
        assert findings[0].metadata["events"] == 100
        assert findings[0].metadata["runtime_observations"][0]["frameworks"] == ["framework.langchain"]
        return findings

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(scan, range(6)))
    assert len(results) == 6
    # One full-header lookup for all events plus one report-evidence lookup per
    # connector, instead of one full-header lookup per event.
    assert calls == {"langchain/0.3": 12}


def test_timeout_does_not_cache_partial_framework_results(index, monkeypatch):
    original = index.match_user_agent
    attempts = 0

    def interrupted(ua):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            def partial():
                yield from original(ua)
                raise MatchTimeoutError("signature matching timed out (custom.pattern); input scan is incomplete")
            return partial()
        return original(ua)

    monkeypatch.setattr(index, "match_user_agent", interrupted)
    ctx = ConnectorContext(config={"format": "generic"}, index=index)
    ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
    findings = list(GatewayLogConnector(ctx).analyze([record(), record()]))
    assert attempts == 3  # failed event, successful event, report evidence
    assert findings[0].metadata["events"] == 1
    assert ctx.stats.incomplete
    assert any("custom.pattern" in message for message in ctx.stats.warnings)


def test_framework_cache_is_bounded_and_values_do_not_alias_events(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_CACHED_USER_AGENTS", 2)
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_CACHED_USER_AGENT_CHARS", 32)
    connector = GatewayLogConnector(ConnectorContext(config={}, index=index))
    cache = OrderedDict()
    original = index.match_user_agent
    calls = Counter()

    def count(ua):
        calls[ua] += 1
        return original(ua)

    monkeypatch.setattr(index, "match_user_agent", count)

    def enrich(ua):
        event = Event("principal:worker", "principal", "worker", user_agent=ua)
        connector._runtime_context(event, record(), cache)
        return event

    first = enrich("langchain/0.3")
    first.runtime_frameworks.clear()
    assert enrich("langchain/0.3").runtime_frameworks == ["framework.langchain"]
    enrich("nothing/1")
    enrich("nothing/1")  # successful empty results are also reusable
    enrich("other/1")
    assert len(cache) == 2 and "langchain/0.3" not in cache
    enrich("langchain/0.3")
    for _ in range(2):
        enrich("x" * 33)
    assert len(cache) == 2
    assert calls == {"langchain/0.3": 2, "nothing/1": 1, "other/1": 1, "x" * 33: 2}


def test_framework_cache_is_discarded_between_analyses(index, monkeypatch):
    original = index.match_user_agent
    calls = 0

    def count(ua):
        nonlocal calls
        calls += 1
        return original(ua)

    monkeypatch.setattr(index, "match_user_agent", count)
    connector = GatewayLogConnector(ConnectorContext(config={"format": "generic"}, index=index))
    for _ in range(2):
        assert list(connector.analyze([record(), record()]))
    assert calls == 4
