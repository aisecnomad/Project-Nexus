"""Regression coverage for gateway ingestion and cross-export attribution."""
from __future__ import annotations

import gzip
import hashlib
import json
from copy import deepcopy

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import GatewayLogConnector, _has_tool_calls
from shadowscan.correlation import correlate_runtime
from shadowscan.engine import Engine, merge
from shadowscan.models import Finding, Kind, Surface


def usage_result(count=10_000, **extra):
    return {"object": "organization.usage.completions.result", "num_model_requests": count,
            "input_tokens": 80_000, "output_tokens": 20_000, "api_key_id": "key-usage-id",
            "project_id": "project-a", "user_id": None, "model": "gpt-4o", **extra}


def usage_page(*results):
    return {"object": "page", "has_more": False, "next_page": None, "data": [
        {"object": "bucket", "start_time": 1735689600, "end_time": 1735776000,
         "results": list(results)}]}


def test_native_openai_usage_preserves_requests_interval_scope_and_tokens(tmp_path, index):
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(usage_page(usage_result())))
    result = Engine(ScanConfig(connectors=[ConnectorSpec(name="gateway.logs", config={"input": str(path)})]), index=index).run()
    assert result.complete
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.metadata["events"] == 10_000 and finding.metadata["records"] == 1
    assert finding.metadata["models"] == {"gpt-4o": 10_000}
    assert finding.metadata["tokens_in"] == 80_000 and finding.metadata["tokens_out"] == 20_000
    assert finding.metadata["correlation_scope"] == {"project": "project-a"}
    assert finding.first_seen == "2025-01-01T00:00:00+00:00"
    assert finding.last_seen == "2025-01-02T00:00:00+00:00"
    assert finding.metadata["usage_intervals"] == [
        {"start": finding.first_seen, "end": finding.last_seen, "requests": 10_000, "model": "gpt-4o"}]
    assert "always-on" not in finding.tags  # a daily aggregate is not 10,000 events at midnight
    assert finding.metadata["runtime_observations"][0]["timestamped_events"] == 0


@pytest.mark.parametrize("results", [[], [usage_result(0)]])
def test_empty_native_usage_is_valid_without_fabricated_requests(tmp_path, run_connector, results):
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(usage_page(*results)))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not findings and not ctx.stats.incomplete


@pytest.mark.parametrize("bad", [True, -1, None, "lots", 1.5])
def test_bad_aggregate_counts_mark_incomplete_but_keep_valid_results(tmp_path, run_connector, bad):
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(usage_page(usage_result(bad), usage_result(7))))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].metadata["events"] == 7


@pytest.mark.parametrize("change", [{"results": {}}, {"results": [1]}, {"start_time": None}, {"end_time": 1735689600}])
def test_malformed_native_usage_bucket_cannot_report_complete(tmp_path, run_connector, change):
    page = usage_page(usage_result())
    page["data"][0].update(change)
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(page))
    _, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete


def static():
    return Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE,
                   title="Static LangChain", resource="github:acme/agent", resource_type="project",
                   frameworks=["framework.langchain"])


def event(environment="production"):
    return {"service": "agent", "model": "gpt-4o", "provider": "openai", "user_agent": "langchain/0.3",
            "environment": environment, "timestamp": "2026-01-01T00:00:00Z", "tenant_id": "tenant-a"}


def source(index, path, environment="production", *, gateway_identity_key=None, **config):
    ctx = ConnectorContext(config={"input": str(path), "correlation_bindings": [
        {"code_resource": "github:acme/agent", "caller": "principal:agent", "scope": {"tenant": "tenant-a"}}
    ], **config}, index=index, gateway_identity_key=gateway_identity_key)
    return list(GatewayLogConnector(ctx).analyze([event(environment)]))[0]


def test_same_caller_in_two_unlabelled_exports_preserves_production_and_provenance(tmp_path, index):
    staging = source(index, tmp_path / "staging.jsonl", "staging")
    production = source(index, tmp_path / "production.jsonl")
    assert staging.id != production.id and staging.resource == production.resource
    activities = []
    for ordered in ([staging, production], [production, staging]):
        code = static()
        findings = merge([code, *deepcopy(ordered)])
        assert len(findings) == 3
        correlate_runtime(findings)
        activity = code.metadata["runtime_activity"]
        assert activity["production_observed"] and activity["production_events"] == 1
        assert activity["events"] == 2 and len(activity["sources"]) == 2
        assert all(match["scope"] == {"tenant": "tenant-a"} for match in activity["sources"])
        activities.append(activity)
    assert activities[0] == activities[1]


def test_identical_source_configuration_deduplicates_but_not_overlapping_distinct_exports(tmp_path, index):
    shared_key = b"one-private-key-per-scan-test-only"
    first = source(index, tmp_path / "one.jsonl", gateway_identity_key=shared_key)
    duplicate = source(index, tmp_path / "." / "one.jsonl", gateway_identity_key=shared_key)
    second = source(index, tmp_path / "two.jsonl", gateway_identity_key=shared_key)
    code = static()
    findings = merge([first, duplicate, second, code])
    assert len(findings) == 3
    correlate_runtime(findings)
    assert code.metadata["runtime_activity"]["events"] == 2
    assert "not deduplicated" in code.metadata["runtime_activity"]["event_counting"]


def test_engine_shares_gateway_identity_within_run_and_rotates_between_runs(tmp_path, index):
    path = tmp_path / "key.jsonl"
    path.write_text(json.dumps({"api_key": "t1", "tenant_id": "other", "model": "gpt-4o"}) + "\n")
    spec = ConnectorSpec(name="gateway.logs", config={"input": str(path), "format": "generic", "label": "t1"})
    engine = Engine(ScanConfig(connectors=[spec, spec], parallel=2), index=index)
    first = engine.run()
    second = engine.run()
    assert first.complete and second.complete
    assert len(first.findings) == len(second.findings) == 1
    assert first.findings[0].metadata["events"] == second.findings[0].metadata["events"] == 1
    assert first.findings[0].id != second.findings[0].id
    assert first.findings[0].resource != second.findings[0].resource
    assert first.findings[0].metadata["runtime_source"]["id"] != second.findings[0].metadata["runtime_source"]["id"]
    guessable_source = json.dumps([str(path.resolve()), "t1", "generic", 1, True, 5_000_000, []], sort_keys=True)
    assert first.findings[0].metadata["runtime_source"]["id"] != hashlib.sha256(guessable_source.encode()).hexdigest()


def test_same_source_different_bindings_do_not_drop_workload_provenance(tmp_path, index):
    shared_key = b"one-private-key-per-scan-test-only"
    first = source(index, tmp_path / "one.jsonl", gateway_identity_key=shared_key)
    other = source(index, tmp_path / "one.jsonl", gateway_identity_key=shared_key, correlation_bindings=[
        {"code_resource": "github:acme/other", "caller": "principal:agent", "scope": {"tenant": "tenant-a"}}])
    assert first.id != other.id
    assert len(merge([first, other])) == 2


@pytest.mark.parametrize("response", [
    {"choices": [{"message": {"tool_calls": None, "function_call": None}}]},
    {"tool_calls": [], "function_call": {}, "functionCall": None},
    {"content": 'Documentation mentions "tool_calls" and "function_call"'},
    {"choices": [{"message": {"content": "normal reply"}, "finish_reason": "stop"}]},
])
def test_empty_tool_fields_and_text_mentions_do_not_indicate_tool_invocation(response):
    assert _has_tool_calls(response) is False
    assert _has_tool_calls(json.dumps(response)) is False


@pytest.mark.parametrize("response", [
    {"choices": [{"message": {"tool_calls": [{"id": "call-1", "function": {"name": "lookup"}}]}}]},
    {"content": [{"type": "tool_use", "name": "lookup", "input": {}}]},
    {"function_call": {"name": "lookup"}},
    {"candidates": [{"content": {"parts": [{"functionCall": {"name": "lookup"}}]}}]},
])
def test_actual_structured_tool_invocations_are_detected(response):
    assert _has_tool_calls(response) is True


@pytest.mark.parametrize("suffix", [".log", ".txt", ".gz"])
def test_malformed_json_in_text_is_incomplete_and_preserves_good_events(tmp_path, run_connector, suffix):
    path = tmp_path / ("gateway" + suffix)
    content = '{"service": invalid}\n' + json.dumps(event()) + '\n'
    if suffix == ".gz":
        with gzip.open(path, "wt") as fh:
            fh.write(content)
    else:
        path.write_text(content)
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].metadata["events"] == 1


def test_valid_non_llm_access_traffic_is_filtered_without_incompleteness(tmp_path, run_connector):
    path = tmp_path / "access.log"
    path.write_text('10.0.0.1 - - [10/Sep/2025:10:00:00 +0000] "GET /health HTTP/1.1" 200 12 "-" "curl/8" host=internal.example.com\n')
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not findings and not ctx.stats.incomplete


def test_nonempty_unrecognized_json_export_is_incomplete(tmp_path, run_connector):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps({"unexpected_wrapper": [{"model": "gpt-4o"}]}))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not findings and ctx.stats.incomplete


def test_malformed_embedded_cloudwatch_json_cannot_disappear(tmp_path, run_connector):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps({"logEvents": [{"message": '{"broken":'}, {"message": json.dumps(event())}]}))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1 and ctx.stats.incomplete


def test_gateway_text_inputs_obey_symlink_and_decompression_limits(tmp_path, run_connector, monkeypatch):
    real = tmp_path / "outside.log"
    real.write_text(json.dumps(event()) + "\n")
    link = tmp_path / "linked.log"
    link.symlink_to(real)
    findings, ctx = run_connector("gateway.logs", input=str(link))
    assert not findings and ctx.stats.incomplete
    compressed = tmp_path / "oversized.gz"
    with gzip.open(compressed, "wt") as stream:
        stream.write(json.dumps(event()) * 100)
    monkeypatch.setattr(GatewayLogConnector, "_MAX_OFFLINE_FILE_BYTES", 1024)
    findings, ctx = run_connector("gateway.logs", input=str(compressed))
    assert not findings and ctx.stats.incomplete


def test_invalid_result_type_never_degrades_aggregate_count_to_one(tmp_path, run_connector):
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(usage_page(usage_result(object="unexpected.result"))))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not findings and ctx.stats.incomplete


@pytest.mark.parametrize("bad", [
    {"category": "RequestResponse", "resourceId": "/subscriptions/sub-1/accounts/a", "properties": "[]"},
    {"category": "RequestResponse", "resourceId": "/subscriptions/sub-1/accounts/a", "properties": "{broken"},
    {"request_properties": ["not-an-object"], "helicone": True},
    {"service": "agent", "model": "gpt-4o", "user_agent": ["not-a-header"]},
    {"spend": 1, "api_key": "opaque-key", "status": ["not-a-status"]},
])
def test_malformed_nested_records_preserve_valid_neighbors(tmp_path, run_connector, bad):
    path = tmp_path / "gateway.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in [event(), bad, event()]))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].metadata["events"] == 2
    assert ctx.stats.objects_examined == 3


def test_numeric_http_status_is_normalized_before_aggregation(tmp_path, run_connector):
    path = tmp_path / "gateway.jsonl"
    path.write_text(json.dumps({"spend": 1, "api_key": "opaque-key", "status": 429}))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].metadata["errors"] == 1


def test_deep_invalid_json_text_line_preserves_neighbor(tmp_path, run_connector):
    path = tmp_path / "gateway.log"
    path.write_text('{"nested":' + '[' * 2000 + '0' + ']' * 2000 + '}\n' + json.dumps(event()))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].metadata["events"] == 1
