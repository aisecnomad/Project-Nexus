"""Regression coverage for gateway ingestion and cross-export attribution."""

from __future__ import annotations

import gzip
import hashlib
import json
from copy import deepcopy

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import GatewayLogConnector, _has_tool_calls, normalise
from shadowscan.correlation import correlate_runtime
from shadowscan.engine import Engine
from shadowscan.merge import merge
from shadowscan.models import Finding, Kind, ScanStats, Surface
from shadowscan.signatures.matcher import MatchTimeoutError


def usage_result(count=10_000, **extra):
    return {
        "object": "organization.usage.completions.result",
        "num_model_requests": count,
        "input_tokens": 80_000,
        "output_tokens": 20_000,
        "api_key_id": "key-usage-id",
        "project_id": "project-a",
        "user_id": None,
        "model": "gpt-4o",
        **extra,
    }


def usage_page(*results):
    return {
        "object": "page",
        "has_more": False,
        "next_page": None,
        "data": [
            {"object": "bucket", "start_time": 1735689600, "end_time": 1735776000, "results": list(results)}
        ],
    }


def test_native_openai_usage_preserves_requests_interval_scope_and_tokens(tmp_path, index):
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(usage_page(usage_result())))
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec(name="gateway.logs", config={"input": str(path)})]), index=index
    ).run()
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
        {"start": finding.first_seen, "end": finding.last_seen, "requests": 10_000, "model": "gpt-4o"}
    ]
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


@pytest.mark.parametrize(
    "change", [{"results": {}}, {"results": [1]}, {"start_time": None}, {"end_time": 1735689600}]
)
def test_malformed_native_usage_bucket_cannot_report_complete(tmp_path, run_connector, change):
    page = usage_page(usage_result())
    page["data"][0].update(change)
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(page))
    _, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete


def static():
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.FRAMEWORK_USAGE,
        title="Static LangChain",
        resource="github:acme/agent",
        resource_type="project",
        frameworks=["framework.langchain"],
    )


def event(environment="production"):
    return {
        "service": "agent",
        "model": "gpt-4o",
        "provider": "openai",
        "user_agent": "langchain/0.3",
        "environment": environment,
        "timestamp": "2026-01-01T00:00:00Z",
        "tenant_id": "tenant-a",
    }


def source(index, path, environment="production", *, gateway_identity_key=None, **config):
    ctx = ConnectorContext(
        config={
            "input": str(path),
            "correlation_bindings": [
                {
                    "code_resource": "github:acme/agent",
                    "caller": "principal:agent",
                    "scope": {"tenant": "tenant-a"},
                }
            ],
            **config,
        },
        index=index,
        gateway_identity_key=gateway_identity_key,
    )
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
    assert (
        first.findings[0].metadata["runtime_source"]["id"]
        != second.findings[0].metadata["runtime_source"]["id"]
    )
    guessable_source = json.dumps(
        [str(path.resolve()), "t1", "generic", 1, True, 5_000_000, []], sort_keys=True
    )
    assert (
        first.findings[0].metadata["runtime_source"]["id"]
        != hashlib.sha256(guessable_source.encode()).hexdigest()
    )


def test_same_source_different_bindings_do_not_drop_workload_provenance(tmp_path, index):
    shared_key = b"one-private-key-per-scan-test-only"
    first = source(index, tmp_path / "one.jsonl", gateway_identity_key=shared_key)
    other = source(
        index,
        tmp_path / "one.jsonl",
        gateway_identity_key=shared_key,
        correlation_bindings=[
            {
                "code_resource": "github:acme/other",
                "caller": "principal:agent",
                "scope": {"tenant": "tenant-a"},
            }
        ],
    )
    assert first.id != other.id
    assert len(merge([first, other])) == 2


@pytest.mark.parametrize(
    "response",
    [
        {"choices": [{"message": {"tool_calls": None, "function_call": None}}]},
        {"tool_calls": [], "function_call": {}, "functionCall": None},
        {"content": 'Documentation mentions "tool_calls" and "function_call"'},
        {"choices": [{"message": {"content": "normal reply"}, "finish_reason": "stop"}]},
    ],
)
def test_empty_tool_fields_and_text_mentions_do_not_indicate_tool_invocation(response):
    assert _has_tool_calls(response) is False
    assert _has_tool_calls(json.dumps(response)) is False


@pytest.mark.parametrize(
    "response",
    [
        {"choices": [{"message": {"tool_calls": [{"id": "call-1", "function": {"name": "lookup"}}]}}]},
        {"content": [{"type": "tool_use", "name": "lookup", "input": {}}]},
        {"function_call": {"name": "lookup"}},
        {"candidates": [{"content": {"parts": [{"functionCall": {"name": "lookup"}}]}}]},
    ],
)
def test_actual_structured_tool_invocations_are_detected(response):
    assert _has_tool_calls(response) is True


@pytest.mark.parametrize("suffix", [".log", ".txt", ".gz"])
def test_malformed_json_in_text_is_incomplete_and_preserves_good_events(tmp_path, run_connector, suffix):
    path = tmp_path / ("gateway" + suffix)
    content = '{"service": invalid}\n' + json.dumps(event()) + "\n"
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
    path.write_text(
        '10.0.0.1 - - [10/Sep/2025:10:00:00 +0000] "GET /health HTTP/1.1" 200 12 "-" "curl/8" host=internal.example.com\n'
    )
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


@pytest.mark.parametrize(
    "bad",
    [
        {"category": "RequestResponse", "resourceId": "/subscriptions/sub-1/accounts/a", "properties": "[]"},
        {
            "category": "RequestResponse",
            "resourceId": "/subscriptions/sub-1/accounts/a",
            "properties": "{broken",
        },
        {"request_properties": ["not-an-object"], "helicone": True},
        {"service": "agent", "model": "gpt-4o", "user_agent": ["not-a-header"]},
        {"spend": 1, "api_key": "opaque-key", "status": ["not-a-status"]},
    ],
)
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
    path.write_text('{"nested":' + "[" * 2000 + "0" + "]" * 2000 + "}\n" + json.dumps(event()))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].metadata["events"] == 1


def context(index, **config):
    ctx = ConnectorContext(index=index, config=config)
    ctx.stats = ScanStats(connector="test", started_at="now")
    return ctx


def test_gateway_final_matching_timeout_preserves_other_callers(index, monkeypatch):
    original = index.match_model

    def match(model):
        if model == "bad-model":
            raise MatchTimeoutError("signature matching timed out (custom.pattern)")
        return original(model)

    monkeypatch.setattr(index, "match_model", match)
    ctx = context(index, format="generic")
    findings = list(
        GatewayLogConnector(ctx).analyze(
            [
                {"service": "a", "model": "bad-model"},
                {"service": "b", "model": "gpt-4o"},
            ]
        )
    )
    assert len(findings) == 1 and findings[0].metadata["caller"] == "b"
    assert ctx.stats.incomplete
    assert any("custom.pattern" in warning for warning in ctx.stats.warnings)


# Gateway evidence that could otherwise overstate production use.
def _code() -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.FRAMEWORK_USAGE,
        title="LangChain dependency",
        resource="github:acme/agent",
        resource_type="project",
        frameworks=["framework.langchain"],
    )


def _scan(index, records, *, caller="principal:worker", scope=None):
    connector = GatewayLogConnector(
        ConnectorContext(
            config={
                "input": "gateway.jsonl",
                "correlation_bindings": [
                    {"code_resource": "github:acme/agent", "caller": caller, "scope": scope or {}}
                ],
            },
            index=index,
        )
    )
    findings = list(connector.analyze(records))
    code = _code()
    correlate_runtime([code, *findings])
    return findings, code.metadata["runtime_activity"]


@pytest.mark.parametrize(
    "response",
    [
        {"choices": [{"message": {"tool_calls": []}, "finish_reason": "stop"}]},
        {"choices": [{"message": {"tool_calls": []}, "finish_reason": "tool_calls"}]},
        {"choices": [{"message": {"content": 'the text "tool_calls" is in the prompt'}}]},
        {"content": [{"type": "text", "text": '"tool_use"'}]},
    ],
)
def test_empty_tool_calls_or_mentions_do_not_mean_agentic_execution(index, response):
    record = {
        "service": "worker",
        "model": "gpt-4o",
        "request": {"tools": [], "tool_choice": "none"},
        "response": response,
    }
    ev = normalise(record, "generic")
    assert ev.tools is False
    assert ev.tool_calls is False
    findings, _ = _scan(index, [record])
    assert len(findings) == 1
    assert findings[0].metadata["tool_requests"] == 0
    assert findings[0].metadata["tool_call_responses"] == 0
    assert "tool-use" not in findings[0].capabilities
    assert findings[0].title.startswith("LLM caller")


def test_nested_nonempty_response_tool_call_is_detected():
    record = {
        "service": "worker",
        "model": "gpt-4o",
        "response": {
            "choices": [
                {
                    "message": {
                        "tool_calls": [{"type": "function", "function": {"name": "search"}}],
                    }
                }
            ]
        },
    }
    assert normalise(record, "generic").tool_calls is True


@pytest.mark.parametrize("choice", ["none", "auto", {"type": "none"}])
def test_top_level_tool_choice_without_definitions_is_not_tool_use(index, choice):
    record = {"service": "worker", "model": "gpt-4o", "tool_choice": choice}
    assert normalise(record, "generic").tools is False
    findings, _ = _scan(index, [record])
    assert "tool-use" not in findings[0].capabilities


def test_tool_choice_none_disables_present_definitions():
    record = {
        "service": "worker",
        "model": "gpt-4o",
        "request": {
            "tools": [{"type": "function", "function": {"name": "search"}}],
            "tool_choice": "none",
        },
    }
    assert normalise(record, "generic").tools is False


def test_spoofed_user_agent_or_ip_cannot_bind_static_code(index):
    for caller, record in [
        ("access:langchain/0.3", {"user_agent": "langchain/0.3"}),
        ("access:10.1.1.7", {"remote_addr": "10.1.1.7", "user_agent": None}),
    ]:
        record.update(
            {
                "host": "api.openai.com",
                "request_uri": "/v1/chat/completions",
                "timestamp": "2026-09-22T10:00:00Z",
            }
        )
        findings, activity = _scan(index, [record], caller=caller)
        assert findings
        assert activity["status"] == "unknown"
        assert activity["reason"] == "no-trusted-workload-binding"
        assert findings[0].metadata["runtime_observations"][0]["code_resources"] == []


def test_user_agent_alone_and_favicon_are_not_llm_transactions(index):
    records = [
        {"user_agent": "langchain/0.3", "request_uri": "/favicon.ico", "remote_addr": "10.1.1.7"},
        {
            "user_agent": "langchain/0.3",
            "host": "api.openai.com",
            "request_uri": "/favicon.ico",
            "remote_addr": "10.1.1.7",
        },
        {
            "user_agent": "langchain/0.3",
            "host": "api.openai.com",
            "model": "gpt-4o",
            "request_uri": "/favicon.ico",
            "remote_addr": "10.1.1.7",
        },
    ]
    findings, _ = _scan(index, records)
    assert not findings


def test_structured_provider_usage_without_model_is_still_llm_evidence(index):
    findings, _ = _scan(
        index,
        [
            {
                "service": "worker",
                "provider": "openai",
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "timestamp": "2026-09-22T10:00:00Z",
            }
        ],
    )
    assert len(findings) == 1
    assert findings[0].metadata["tokens_in"] == 100
    assert findings[0].metadata["events"] == 1


@pytest.mark.parametrize(
    "record,caller",
    [
        (
            {"gateway_id": "shared-gateway", "model": "gpt-4o", "user_agent": "langchain/0.3"},
            "cloudflare:shared-gateway",
        ),
        (
            {"project_id": "shared-project", "model": "gpt-4o", "input_tokens": 4, "api_key_id": None},
            "openai:shared-project",
        ),
        (
            {"workspace_id": "shared-workspace", "model": "claude-sonnet-4", "uncached_input_tokens": 4},
            "anthropic:shared-workspace",
        ),
        ({"service": "unknown", "model": "gpt-4o", "user_agent": "langchain/0.3"}, "principal:unknown"),
    ],
)
def test_shared_fallback_or_placeholder_does_not_prove_a_workload(index, record, caller):
    record.update(timestamp="2026-09-22T10:00:00Z")
    findings, activity = _scan(index, [record], caller=caller)
    # A bare ``assert []`` once failed on a single CI run and could not be
    # reproduced; keep the inputs and outcome in the message so a recurrence
    # identifies the case without a rerun.
    assert findings, f"no findings for {record!r} bound to {caller!r}; activity={activity!r}"
    assert activity["status"] == "unknown", f"{record!r} bound to {caller!r}: {activity!r}"


def test_generic_service_binding_declares_its_limit_and_production_label(index):
    findings, activity = _scan(
        index,
        [
            {
                "service": "worker",
                "model": "gpt-4o",
                "user_agent": "langchain/0.3",
                "environment": "production",
                "timestamp": "2026-09-22T10:00:00Z",
            }
        ],
    )
    assert activity["status"] == "observed"
    assert activity["production_observed"] is True
    assert activity["production_label_verified"] is False
    assert activity["sources"][0]["identity_assurance"] == "operator-asserted"
    assert activity["sources"][0]["environment_assurance"] == "event-label-unverified"
    assert findings[0].metadata["runtime_observations"][0]["identity_assurance"] == "operator-asserted"


def test_usage_bucket_count_is_not_one_request_or_transaction_timestamps(index):
    records = [
        {
            "api_key_id": "key-one",
            "model": "gpt-4o",
            "input_tokens": 40,
            "n_requests": 7,
            "start_time": "2026-09-22T10:00:00Z",
        },
        {
            "api_key_id": "key-one",
            "model": "gpt-4o",
            "input_tokens": 80,
            "num_model_requests": 11,
            "start_time": "2026-09-22T11:00:00Z",
        },
    ]
    findings, activity = _scan(index, records)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.metadata["events"] == 18
    assert finding.metadata["records"] == 2
    assert finding.metadata["aggregate_records"] == 2
    assert finding.metadata["models"]["gpt-4o"] == 18
    assert finding.metadata["runtime_observations"][0]["timestamped_events"] == 0
    assert activity["status"] == "unknown"


def test_many_usage_buckets_do_not_establish_always_on_automation(index):
    records = [
        {
            "api_key_id": "key-one",
            "model": "gpt-4o",
            "input_tokens": 1,
            "n_requests": 20,
            "start_time": f"2026-09-{22 + day:02d}T{hour:02d}:00:00Z",
        }
        for day in range(3)
        for hour in range(24)
    ]
    findings, _ = _scan(index, records)
    assert findings[0].metadata["events"] == 1440
    assert "always-on" not in findings[0].tags


def test_cloudwatch_plaintext_and_cloud_logging_envelopes_preserve_provenance(index, tmp_path):
    cloudwatch = tmp_path / "watch.json"
    cloudwatch.write_text(
        json.dumps(
            {
                "logEvents": [
                    {
                        "timestamp": 1789732800000,
                        "message": '10.1.1.7 - - [18/Sep/2026:12:00:00 +0000] "POST /v1/chat/completions HTTP/1.1" 200 512 "-" "langchain/0.3" host=api.openai.com',
                    }
                ]
            }
        )
    )
    connector = GatewayLogConnector(ConnectorContext(config={"input": str(cloudwatch)}, index=index))
    watch_records = list(connector.load_offline(str(cloudwatch)))
    assert len(watch_records) == 1
    assert watch_records[0]["request_uri"] == "/v1/chat/completions"
    assert len(list(connector.analyze(watch_records))) == 1

    cloud_logging = tmp_path / "gcp.jsonl"
    cloud_logging.write_text(
        json.dumps(
            {
                "timestamp": "2026-09-22T10:00:00Z",
                "resource": {"labels": {"project_id": "project-one"}},
                "jsonPayload": {"service": "worker", "model": "gpt-4o", "user_agent": "langchain/0.3"},
            }
        )
        + "\n"
    )
    connector = GatewayLogConnector(ConnectorContext(config={"input": str(cloud_logging)}, index=index))
    records = list(connector.load_offline(str(cloud_logging)))
    findings, activity = _scan(index, records, scope={"project": "project-one"})
    assert len(findings) == 1
    assert findings[0].first_seen == "2026-09-22T10:00:00+00:00"
    assert activity["status"] == "observed"
    assert activity["sources"][0]["scope"] == {"project": "project-one"}


@pytest.mark.parametrize("suffix", [".json", ".jsonl"])
def test_top_level_cloudwatch_envelope_keeps_scope_and_timestamp(index, tmp_path, suffix):
    export = tmp_path / f"cloudwatch{suffix}"
    envelope = {
        "timestamp": "2026-09-22T10:00:00Z",
        "resource": {"labels": {"project_id": "project-one"}},
        "logEvents": [
            {"message": json.dumps({"service": "worker", "model": "gpt-4o", "user_agent": "langchain/0.3"})}
        ],
    }
    export.write_text(json.dumps(envelope) + ("\n" if suffix == ".jsonl" else ""))
    connector = GatewayLogConnector(ConnectorContext(config={"input": str(export)}, index=index))
    records = list(connector.load_offline(str(export)))
    assert len(records) == 1
    assert records[0]["resource"] == envelope["resource"]
    assert records[0]["timestamp"] == envelope["timestamp"]
    findings, activity = _scan(index, records, scope={"project": "project-one"})
    assert len(findings) == 1
    assert activity["status"] == "observed"
    assert activity["sources"][0]["scope"] == {"project": "project-one"}


def test_top_level_openai_results_keep_usage_interval_and_pagination_error(index, tmp_path):
    export = tmp_path / "usage.json"
    export.write_text(
        json.dumps(
            {
                "start_time": "2026-09-22T10:00:00Z",
                "end_time": "2026-09-22T11:00:00Z",
                "nextToken": "another-page",
                "results": [
                    {"api_key_id": "key-one", "model": "gpt-4o", "n_requests": 7, "input_tokens": 40}
                ],
            }
        )
    )
    context = ConnectorContext(config={"input": str(export), "format": "openai-usage"}, index=index)
    connector = GatewayLogConnector(context)
    findings = connector.run()
    assert context.stats is not None and context.stats.incomplete
    assert any("uncollected next page" in error for error in context.stats.errors)
    assert len(findings) == 1
    assert findings[0].metadata["events"] == 7
    assert findings[0].metadata["usage_intervals"][0]["start"] == "2026-09-22T10:00:00+00:00"
    assert findings[0].metadata["usage_intervals"][0]["end"] == "2026-09-22T11:00:00+00:00"
    assert findings[0].metadata["usage_intervals"][0]["requests"] == 7


def test_correlation_uses_source_of_each_merged_observation(index):
    findings, _ = _scan(
        index,
        [
            {
                "service": "worker",
                "model": "gpt-4o",
                "user_agent": "langchain/0.3",
                "timestamp": "2026-09-22T10:00:00Z",
            }
        ],
    )
    gateway = findings[0]
    observation = gateway.metadata["runtime_observations"][0]
    gateway.metadata["runtime_source"] = {"input": "first.jsonl"}
    observation["source"] = {"input": "second.jsonl"}
    code = _code()
    correlate_runtime([code, gateway])
    assert code.metadata["runtime_activity"]["sources"][0]["source"]["input"] == "second.jsonl"
