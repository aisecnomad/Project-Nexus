"""Gateway exports keep bounded detail without inventing overflow callers."""

from __future__ import annotations

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway import logs
from shadowscan.connectors.gateway.logs import GatewayLogConnector
from shadowscan.models import ScanStats


def _scan(index, records, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
    findings = list(GatewayLogConnector(ctx).analyze(records))
    return findings, ctx


def test_caller_limit_omits_only_new_scoped_identities(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_DISTINCT_CALLERS", 2)

    def event(service, tenant="a"):
        return {"service": service, "tenant_id": tenant, "model": "gpt-4o"}

    findings, ctx = _scan(index, [
        event("one"), event("two"), event("three"), event("one", "b"),
        event("one"), event("four"),
    ], format="generic")
    assert {finding.resource for finding in findings} == {"principal:one", "principal:two"}
    assert {finding.resource: finding.metadata["events"] for finding in findings} == {
        "principal:one": 2, "principal:two": 1,
    }
    assert all(finding.metadata["correlation_scope"] == {"tenant": "a"} for finding in findings)
    assert ctx.stats.objects_examined == 6
    assert ctx.stats.incomplete
    assert len(ctx.stats.warnings) == 1
    assert "omitted 3 records representing 3 requests" in ctx.stats.warnings[0]


def test_usage_intervals_obey_per_caller_and_global_caps(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_USAGE_INTERVALS", 2)
    monkeypatch.setattr(logs, "_MAX_TOTAL_USAGE_INTERVALS", 3)

    def bucket(key, count, hour):
        return {"api_key_id": key, "model": "gpt-4o", "n_requests": count,
                "start_time": f"2026-09-22T{hour:02d}:00:00Z",
                "end_time": f"2026-09-22T{hour + 1:02d}:00:00Z"}

    findings, ctx = _scan(index, [
        bucket("one", 7, 10), bucket("one", 8, 11), bucket("one", 9, 12),
        bucket("two", 3, 10), bucket("two", 4, 11),
    ], format="openai-usage")
    by_requests = {finding.metadata["events"]: finding.metadata for finding in findings}
    assert set(by_requests) == {24, 7}
    assert (by_requests[24]["events"], by_requests[24]["aggregate_records"]) == (24, 3)
    assert (by_requests[7]["events"], by_requests[7]["aggregate_records"]) == (7, 2)
    assert [len(by_requests[count]["usage_intervals"]) for count in (24, 7)] == [2, 1]
    assert (by_requests[24]["usage_intervals_dropped"],
            by_requests[24]["usage_interval_requests_dropped"]) == (1, 9)
    assert (by_requests[7]["usage_intervals_dropped"],
            by_requests[7]["usage_interval_requests_dropped"]) == (1, 4)
    assert ctx.stats.incomplete
    assert len(ctx.stats.warnings) == 1
    assert "omitted 2 interval details while retaining request totals" in ctx.stats.warnings[0]


def test_shared_detail_budget_omits_distributions_and_counts_omitted_observations(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_TOTAL_DETAIL_KEYS", 3)

    def event(service, model="gpt-4o"):
        return {"service": service, "model": model, "environment": "production",
                "input_tokens": 4, "cost": 0.25}

    findings, ctx = _scan(index, [
        event("one"), event("two"), event("one"), event("two", "gpt-5"),
    ], format="generic")
    by_caller = {finding.resource: finding.metadata for finding in findings}
    assert set(by_caller) == {"principal:one", "principal:two"}
    first = by_caller["principal:one"]
    second = by_caller["principal:two"]
    assert first["events"] == second["events"] == 2
    assert (first["tokens_in"], first["cost"]) == (8, 0.5)
    assert (second["tokens_in"], second["cost"]) == (8, 0.5)
    assert first["models"] == {"gpt-4o": 2}
    assert second["models"] == {"gpt-4o": 1}
    assert len(first["runtime_observations"]) == 1
    assert first["runtime_observations"][0]["events"] == 2
    assert second["runtime_observations"] == []
    assert second["runtime_observations_dropped"] == 2
    assert second["distribution_events_dropped"] == {"models": 1}
    assert second["classification_incomplete"] is True
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1
    assert "omitted 1 distribution dimension-request counts" in ctx.stats.warnings[0]
    assert "omitted 2 observation records representing 2 requests" in ctx.stats.warnings[0]


def test_per_caller_observation_cap_marks_detail_incomplete(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_DISTINCT_KEYS", 1)
    findings, ctx = _scan(index, [
        {"service": "one", "model": "gpt-4o", "environment": "production"},
        {"service": "one", "model": "gpt-4o", "environment": "staging"},
    ], format="generic")
    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert len(findings[0].metadata["runtime_observations"]) == 1
    assert findings[0].metadata["runtime_observations_dropped"] == 1
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1
    assert "omitted 1 observation records representing 1 requests" in ctx.stats.warnings[0]


def test_per_caller_distribution_cap_reports_missing_counts_without_inventing_a_model(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_DISTINCT_KEYS", 1)
    findings, ctx = _scan(index, [
        {"service": "one", "model": "gpt-4o"},
        {"service": "one", "model": "gpt-5"},
    ], format="generic")
    assert len(findings) == 1
    metadata = findings[0].metadata
    assert metadata["events"] == 2
    assert metadata["models"] == {"gpt-4o": 1}
    assert metadata["distribution_events_dropped"] == {"models": 1}
    assert "<other>" not in findings[0].models
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1
    assert "distribution limit" in ctx.stats.warnings[0]


def test_global_detail_budget_does_not_promote_a_partial_owner(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_TOTAL_DETAIL_KEYS", 3)
    findings, ctx = _scan(index, [
        {"service": "one", "model": "gpt-4o", "user": "alice"},
        {"service": "one", "model": "gpt-4o", "user": "bob"},
    ], format="generic")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.owner is None
    assert finding.metadata["events"] == 2
    assert finding.metadata["models"] == {"gpt-4o": 2}
    assert finding.metadata["end_users"] == {"alice": 1}
    assert finding.metadata["distribution_events_dropped"] == {"end_users": 1}
    assert finding.metadata["classification_incomplete"] is True
    assert ctx.stats.incomplete
