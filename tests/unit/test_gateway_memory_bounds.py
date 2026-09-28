"""Gateway exports keep bounded detail without inventing overflow callers."""

from __future__ import annotations

import json

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway import logs
from shadowscan.connectors.gateway.logs import Event, GatewayLogConnector
from shadowscan.models import ScanStats, now_iso


def _scan(index, records, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
    findings = list(GatewayLogConnector(ctx).analyze(records))
    return findings, ctx


def test_caller_limit_omits_only_new_scoped_identities(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_DISTINCT_CALLERS", 2)

    def event(service, tenant="a"):
        return {"service": service, "tenant_id": tenant, "model": "gpt-4o"}

    findings, ctx = _scan(
        index,
        [
            event("one"),
            event("two"),
            event("three"),
            event("one", "b"),
            event("one"),
            event("four"),
        ],
        format="generic",
    )
    assert {finding.resource for finding in findings} == {"principal:one", "principal:two"}
    assert {finding.resource: finding.metadata["events"] for finding in findings} == {
        "principal:one": 2,
        "principal:two": 1,
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
        return {
            "api_key_id": key,
            "model": "gpt-4o",
            "n_requests": count,
            "start_time": f"2026-09-22T{hour:02d}:00:00Z",
            "end_time": f"2026-09-22T{hour + 1:02d}:00:00Z",
        }

    findings, ctx = _scan(
        index,
        [
            bucket("one", 7, 10),
            bucket("one", 8, 11),
            bucket("one", 9, 12),
            bucket("two", 3, 10),
            bucket("two", 4, 11),
        ],
        format="openai-usage",
    )
    by_requests = {finding.metadata["events"]: finding.metadata for finding in findings}
    assert set(by_requests) == {24, 7}
    assert (by_requests[24]["events"], by_requests[24]["aggregate_records"]) == (24, 3)
    assert (by_requests[7]["events"], by_requests[7]["aggregate_records"]) == (7, 2)
    assert [len(by_requests[count]["usage_intervals"]) for count in (24, 7)] == [2, 1]
    assert (
        by_requests[24]["usage_intervals_dropped"],
        by_requests[24]["usage_interval_requests_dropped"],
    ) == (1, 9)
    assert (by_requests[7]["usage_intervals_dropped"], by_requests[7]["usage_interval_requests_dropped"]) == (
        1,
        4,
    )
    assert ctx.stats.incomplete
    assert len(ctx.stats.warnings) == 1
    assert "omitted 2 interval details while retaining request totals" in ctx.stats.warnings[0]


def test_shared_detail_budget_omits_distributions_and_counts_omitted_observations(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_TOTAL_DETAIL_KEYS", 3)

    def event(service, model="gpt-4o"):
        return {
            "service": service,
            "model": model,
            "environment": "production",
            "input_tokens": 4,
            "cost": 0.25,
        }

    findings, ctx = _scan(
        index,
        [
            event("one"),
            event("two"),
            event("one"),
            event("two", "gpt-5"),
        ],
        format="generic",
    )
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
    findings, ctx = _scan(
        index,
        [
            {"service": "one", "model": "gpt-4o", "environment": "production"},
            {"service": "one", "model": "gpt-4o", "environment": "staging"},
        ],
        format="generic",
    )
    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert len(findings[0].metadata["runtime_observations"]) == 1
    assert findings[0].metadata["runtime_observations_dropped"] == 1
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1
    assert "omitted 1 observation records representing 1 requests" in ctx.stats.warnings[0]


def test_per_caller_distribution_cap_reports_missing_counts_without_inventing_a_model(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_DISTINCT_KEYS", 1)
    findings, ctx = _scan(
        index,
        [
            {"service": "one", "model": "gpt-4o"},
            {"service": "one", "model": "gpt-5"},
        ],
        format="generic",
    )
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
    findings, ctx = _scan(
        index,
        [
            {"service": "one", "model": "gpt-4o", "user": "alice"},
            {"service": "one", "model": "gpt-4o", "user": "bob"},
        ],
        format="generic",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.owner is None
    assert finding.metadata["events"] == 2
    assert finding.metadata["models"] == {"gpt-4o": 2}
    assert finding.metadata["end_users"] == {"alice": 1}
    assert finding.metadata["distribution_events_dropped"] == {"end_users": 1}
    assert finding.metadata["classification_incomplete"] is True
    assert ctx.stats.incomplete


def context(index, **config):
    ctx = ConnectorContext(index=index, config=config)
    ctx.stats = ScanStats(connector="test", started_at="now")
    return ctx


def test_gateway_overflow_is_atomic_and_keeps_later_callers(index):
    ctx = context(index, format="litellm")
    records = [
        {"api_key": "a", "model": "gpt-4o", "spend": 1e308},
        {"api_key": "a", "model": "gpt-4o", "spend": 1e308},
        {"api_key": "b", "model": "gpt-4o", "spend": 1},
    ]
    findings = list(GatewayLogConnector(ctx).analyze(records))
    assert len(findings) == 2
    assert sum(f.metadata["events"] for f in findings) == 2
    assert sorted(f.metadata["cost"] for f in findings) == [1, 1e308]
    json.dumps([f.metadata for f in findings], allow_nan=False)
    assert ctx.stats.incomplete


def test_gateway_usage_interval_details_are_bounded_and_totals_preserved(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_DISTINCT_KEYS", 2)
    callers = {}
    event = Event("principal:worker", "principal", "worker", aggregated=True, request_count=10)
    for _ in range(5):
        GatewayLogConnector._accumulate(callers, event)
    caller = next(iter(callers.values()))
    finding = GatewayLogConnector(context(index))._finding(caller)
    assert finding.metadata["events"] == 50
    assert len(finding.metadata["usage_intervals"]) == 2
    assert finding.metadata["usage_intervals_dropped"] == 3


def test_gateway_distribution_limit_reports_lost_classification_and_owner(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_DISTINCT_KEYS", 2)
    ctx = context(index, format="litellm")
    values = [("unknown-a", "a"), ("unknown-b", "b")] + [("gpt-4o", "real-owner")] * 5
    # Previously retained labels must keep accumulating after the limit.
    values.append(("unknown-a", "a"))
    records = [{"api_key": "one", "model": model, "user": user} for model, user in values]
    (finding,) = list(GatewayLogConnector(ctx).analyze(records))
    assert finding.metadata["events"] == 8
    assert finding.metadata["distribution_events_dropped"] == {"models": 5, "end_users": 5}
    assert finding.metadata["models"] == {"unknown-a": 2, "unknown-b": 1}
    assert finding.metadata["end_users"] == {"a": 2, "b": 1}
    assert finding.metadata["classification_incomplete"] is True
    assert finding.metadata["distribution_limit"] == 2
    assert finding.owner is None
    assert "<other>" not in finding.models and "<other>" not in finding.title
    assert ctx.stats.incomplete
    assert any("distribution limit" in warning for warning in ctx.stats.warnings)


def test_gateway_all_distribution_limits_count_omitted_requests_without_labels(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.gateway.logs._MAX_DISTINCT_KEYS", 2)
    callers = {}
    for n in range(5):
        event = Event(
            "principal:worker",
            "principal",
            "worker",
            request_count=10,
            model=f"model-{n}",
            provider=f"provider-{n}",
            host=f"host-{n}.example",
            user_agent=f"agent-{n}",
            ip=f"10.0.0.{n}",
            user=f"user-{n}",
            team=f"team-{n}",
            path=f"/operation-{n}",
        )
        GatewayLogConnector._accumulate(callers, event)
    caller = next(iter(callers.values()))
    finding = GatewayLogConnector(context(index))._finding(caller)
    dimensions = (
        "models",
        "providers",
        "hosts",
        "user_agents",
        "source_ips",
        "end_users",
        "teams",
        "operations",
    )
    assert finding.metadata["distribution_events_dropped"] == dict.fromkeys(dimensions, 30)
    assert finding.metadata["events"] == 50
    assert all(
        len(getattr(caller, attr)) == 2
        for attr in (
            "models",
            "providers",
            "hosts",
            "user_agents",
            "ips",
            "users",
            "teams",
            "paths",
        )
    )
    for dimension in dimensions:
        assert (
            sum(finding.metadata[dimension].values())
            + finding.metadata["distribution_events_dropped"][dimension]
            == 50
        )
    assert finding.owner is None
    assert finding.metadata["classification_incomplete"] is True


def _scan_export(index, records, **config):
    ctx = ConnectorContext(config={"input": "export.jsonl", **config}, index=index)
    ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
    findings = list(GatewayLogConnector(ctx).analyze(records))
    return findings, ctx


def _litellm(i=0, **extra):
    return {
        "request_id": str(i),
        "call_type": "acompletion",
        "api_key": "opaque-key-one",
        "api_key_alias": "svc-agent",
        "model": "gpt-4o",
        "custom_llm_provider": "openai",
        "spend": 0.01,
        "startTime": "2026-01-05T09:00:00Z",
        **extra,
    }


def test_retained_labels_and_samples_are_bounded(index):
    findings, _ = _scan_export(
        index, [_litellm(model="m" * 5000, custom_llm_provider="p" * 5000)], format="litellm"
    )
    assert len(findings[0].title) < 1000
    assert all(len(model) <= logs._MAX_LABEL_CHARS for model in findings[0].metadata["models"])
    assert all(len(provider) <= logs._MAX_LABEL_CHARS for provider in findings[0].metadata["providers"])
    record = {
        "virtual_key": "vk-1",
        "trace_id": "t" * 5000,
        "model": "gpt-4o",
        "created_at": "2026-01-05T09:00:00Z",
    }
    findings, _ = _scan_export(index, [record], format="portkey")
    assert len(findings[0].metadata["samples"]["trace_id"]) == logs._MAX_SAMPLE_CHARS


def test_first_distribution_label_survives_an_exhausted_detail_budget(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_TOTAL_DETAIL_KEYS", 3)
    findings, ctx = _scan_export(
        index,
        [
            {"service": "one", "model": "gpt-4o", "user": "alice", "environment": "production"},
            {"service": "two", "model": "gpt-5", "user": "bob"},
            {"service": "two", "model": "gpt-4o", "user": "bob"},
        ],
        format="generic",
    )
    by_caller = {finding.resource: finding for finding in findings}
    second = by_caller["principal:two"]
    assert second.metadata["models"] == {"gpt-5": 1}
    assert second.metadata["end_users"] == {"bob": 2}
    assert second.models == ["gpt-5"] and second.metadata["distribution_events_dropped"] == {"models": 1}
    assert ctx.stats.incomplete


def _ctx(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at=now_iso())
    return ctx


def test_gateway_observation_buckets_are_bounded(index, tmp_path):
    export = tmp_path / "gateway.jsonl"
    with export.open("w") as stream:
        for i in range(logs._MAX_DISTINCT_KEYS + 10):
            stream.write(
                json.dumps(
                    {"api_key": "key-one", "model": "gpt-4o", "spend": 0.01, "environment": f"env-{i}"}
                )
                + "\n"
            )
    findings = GatewayLogConnector(_ctx(index, input=str(export), format="litellm")).run()
    assert len(findings) == 1
    assert len(findings[0].metadata["runtime_observations"]) == logs._MAX_DISTINCT_KEYS
    assert findings[0].metadata["runtime_observations_dropped"] == 10
