"""Regressions for gateway evidence that can otherwise overstate production use."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway.logs import GatewayLogConnector, normalise
from shadowscan.correlation import correlate_runtime
from shadowscan.models import Finding, Kind, Surface


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
    connector = GatewayLogConnector(ConnectorContext(config={
        "input": "gateway.jsonl",
        "correlation_bindings": [{"code_resource": "github:acme/agent", "caller": caller, "scope": scope or {}}],
    }, index=index))
    findings = list(connector.analyze(records))
    code = _code()
    correlate_runtime([code, *findings])
    return findings, code.metadata["runtime_activity"]


@pytest.mark.parametrize("response", [
    {"choices": [{"message": {"tool_calls": []}, "finish_reason": "stop"}]},
    {"choices": [{"message": {"tool_calls": []}, "finish_reason": "tool_calls"}]},
    {"choices": [{"message": {"content": 'the text "tool_calls" is in the prompt'}}]},
    {"content": [{"type": "text", "text": '"tool_use"'}]},
])
def test_empty_tool_calls_or_mentions_do_not_mean_agentic_execution(index, response):
    record = {"service": "worker", "model": "gpt-4o", "request": {"tools": [], "tool_choice": "none"}, "response": response}
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
    record = {"service": "worker", "model": "gpt-4o", "response": {"choices": [{"message": {
        "tool_calls": [{"type": "function", "function": {"name": "search"}}],
    }}]}}
    assert normalise(record, "generic").tool_calls is True


@pytest.mark.parametrize("choice", ["none", "auto", {"type": "none"}])
def test_top_level_tool_choice_without_definitions_is_not_tool_use(index, choice):
    record = {"service": "worker", "model": "gpt-4o", "tool_choice": choice}
    assert normalise(record, "generic").tools is False
    findings, _ = _scan(index, [record])
    assert "tool-use" not in findings[0].capabilities


def test_tool_choice_none_disables_present_definitions():
    record = {"service": "worker", "model": "gpt-4o", "request": {
        "tools": [{"type": "function", "function": {"name": "search"}}],
        "tool_choice": "none",
    }}
    assert normalise(record, "generic").tools is False


def test_spoofed_user_agent_or_ip_cannot_bind_static_code(index):
    for caller, record in [
        ("access:langchain/0.3", {"user_agent": "langchain/0.3"}),
        ("access:10.1.1.7", {"remote_addr": "10.1.1.7", "user_agent": None}),
    ]:
        record.update({"host": "api.openai.com", "request_uri": "/v1/chat/completions", "timestamp": "2026-09-22T10:00:00Z"})
        findings, activity = _scan(index, [record], caller=caller)
        assert findings
        assert activity["status"] == "unknown"
        assert activity["reason"] == "no-trusted-workload-binding"
        assert findings[0].metadata["runtime_observations"][0]["code_resources"] == []


def test_user_agent_alone_and_favicon_are_not_llm_transactions(index):
    records = [
        {"user_agent": "langchain/0.3", "request_uri": "/favicon.ico", "remote_addr": "10.1.1.7"},
        {"user_agent": "langchain/0.3", "host": "api.openai.com", "request_uri": "/favicon.ico", "remote_addr": "10.1.1.7"},
        {"user_agent": "langchain/0.3", "host": "api.openai.com", "model": "gpt-4o", "request_uri": "/favicon.ico", "remote_addr": "10.1.1.7"},
    ]
    findings, _ = _scan(index, records)
    assert not findings


def test_structured_provider_usage_without_model_is_still_llm_evidence(index):
    findings, _ = _scan(index, [{
        "service": "worker", "provider": "openai", "prompt_tokens": 100,
        "completion_tokens": 20, "timestamp": "2026-09-22T10:00:00Z",
    }])
    assert len(findings) == 1
    assert findings[0].metadata["tokens_in"] == 100
    assert findings[0].metadata["events"] == 1


@pytest.mark.parametrize("record,caller", [
    ({"gateway_id": "shared-gateway", "model": "gpt-4o", "user_agent": "langchain/0.3"}, "cloudflare:shared-gateway"),
    ({"project_id": "shared-project", "model": "gpt-4o", "input_tokens": 4, "api_key_id": None}, "openai:shared-project"),
    ({"workspace_id": "shared-workspace", "model": "claude-sonnet-4", "uncached_input_tokens": 4}, "anthropic:shared-workspace"),
    ({"service": "unknown", "model": "gpt-4o", "user_agent": "langchain/0.3"}, "principal:unknown"),
])
def test_shared_fallback_or_placeholder_does_not_prove_a_workload(index, record, caller):
    record.update(timestamp="2026-09-22T10:00:00Z")
    findings, activity = _scan(index, [record], caller=caller)
    assert findings
    assert activity["status"] == "unknown"


def test_generic_service_binding_declares_its_limit_and_production_label(index):
    findings, activity = _scan(index, [{
        "service": "worker", "model": "gpt-4o", "user_agent": "langchain/0.3",
        "environment": "production", "timestamp": "2026-09-22T10:00:00Z",
    }])
    assert activity["status"] == "observed"
    assert activity["production_observed"] is True
    assert activity["production_label_verified"] is False
    assert activity["sources"][0]["identity_assurance"] == "operator-asserted"
    assert activity["sources"][0]["environment_assurance"] == "event-label-unverified"
    assert findings[0].metadata["runtime_observations"][0]["identity_assurance"] == "operator-asserted"


def test_usage_bucket_count_is_not_one_request_or_transaction_timestamps(index):
    records = [
        {"api_key_id": "key-one", "model": "gpt-4o", "input_tokens": 40, "n_requests": 7, "start_time": "2026-09-22T10:00:00Z"},
        {"api_key_id": "key-one", "model": "gpt-4o", "input_tokens": 80, "num_model_requests": 11, "start_time": "2026-09-22T11:00:00Z"},
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
    records = [{
        "api_key_id": "key-one", "model": "gpt-4o", "input_tokens": 1,
        "n_requests": 20, "start_time": f"2026-09-{22 + day:02d}T{hour:02d}:00:00Z",
    } for day in range(3) for hour in range(24)]
    findings, _ = _scan(index, records)
    assert findings[0].metadata["events"] == 1440
    assert "always-on" not in findings[0].tags


def test_cloudwatch_plaintext_and_cloud_logging_envelopes_preserve_provenance(index, tmp_path):
    cloudwatch = tmp_path / "watch.json"
    cloudwatch.write_text(json.dumps({"logEvents": [{
        "timestamp": 1789732800000,
        "message": '10.1.1.7 - - [18/Sep/2026:12:00:00 +0000] "POST /v1/chat/completions HTTP/1.1" 200 512 "-" "langchain/0.3" host=api.openai.com',
    }]}))
    connector = GatewayLogConnector(ConnectorContext(config={"input": str(cloudwatch)}, index=index))
    watch_records = list(connector.load_offline(str(cloudwatch)))
    assert len(watch_records) == 1
    assert watch_records[0]["request_uri"] == "/v1/chat/completions"
    assert len(list(connector.analyze(watch_records))) == 1

    cloud_logging = tmp_path / "gcp.jsonl"
    cloud_logging.write_text(json.dumps({
        "timestamp": "2026-09-22T10:00:00Z",
        "resource": {"labels": {"project_id": "project-one"}},
        "jsonPayload": {"service": "worker", "model": "gpt-4o", "user_agent": "langchain/0.3"},
    }) + "\n")
    connector = GatewayLogConnector(ConnectorContext(config={"input": str(cloud_logging)}, index=index))
    records = list(connector.load_offline(str(cloud_logging)))
    findings, activity = _scan(index, records, scope={"project": "project-one"})
    assert len(findings) == 1
    assert findings[0].first_seen == "2026-09-22T10:00:00+00:00"
    assert activity["status"] == "observed"
    assert activity["sources"][0]["scope"] == {"project": "project-one"}


def test_correlation_uses_source_of_each_merged_observation(index):
    findings, _ = _scan(index, [{"service": "worker", "model": "gpt-4o", "user_agent": "langchain/0.3", "timestamp": "2026-09-22T10:00:00Z"}])
    gateway = findings[0]
    observation = gateway.metadata["runtime_observations"][0]
    gateway.metadata["runtime_source"] = {"input": "first.jsonl"}
    observation["source"] = {"input": "second.jsonl"}
    code = _code()
    correlate_runtime([code, gateway])
    assert code.metadata["runtime_activity"]["sources"][0]["source"]["input"] == "second.jsonl"
