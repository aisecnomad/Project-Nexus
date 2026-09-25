"""Regressions for the gateway connector review fixes (synthetic records only)."""

from __future__ import annotations

import base64
import json

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway import logs
from shadowscan.connectors.gateway.logs import (
    GatewayLogConnector,
    _has_tool_calls,
    _has_tools,
    detect_schema,
    normalise,
)
from shadowscan.models import ScanStats


def _scan(index, records, **config):
    ctx = ConnectorContext(config={"input": "export.jsonl", **config}, index=index)
    ctx.stats = ScanStats(connector="gateway.logs", started_at="now")
    findings = list(GatewayLogConnector(ctx).analyze(records))
    return findings, ctx


def _litellm(i=0, **extra):
    return {"request_id": str(i), "call_type": "acompletion", "api_key": "opaque-key-one", "api_key_alias": "svc-agent",
            "model": "gpt-4o", "custom_llm_provider": "openai", "spend": 0.01, "startTime": "2026-01-05T09:00:00Z", **extra}


TOOL_CALL_RESPONSE = {"choices": [{"finish_reason": "tool_calls", "message": {
    "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "search", "arguments": "{}"}}]}}]}


# finding 1 -----------------------------------------------------------------
def test_response_tool_calls_count_when_inspected_requests_carried_no_tools(index):
    assert _has_tools("{}") is None and _has_tools({}) is None
    records = [_litellm(i, proxy_server_request="{}", response=TOOL_CALL_RESPONSE) for i in range(2)]
    findings, _ = _scan(index, records, format="litellm")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.metadata["tool_requests"] == 0 and finding.metadata["tool_call_responses"] == 2
    assert "tool-use" in finding.capabilities
    assert any(ev.signal == "gateway:tool-calls" for ev in finding.evidence)
    assert finding.title.startswith("Agentic caller")


# finding 4 -----------------------------------------------------------------
def test_bedrock_converse_tool_use_response_is_detected():
    output = {"output": {"message": {"role": "assistant", "content": [
        {"toolUse": {"toolUseId": "t-1", "name": "run_plan", "input": {"plan": "x"}}}]}},
        "stopReason": "tool_use", "usage": {"inputTokens": 1, "outputTokens": 1}}
    assert _has_tool_calls(output) is True
    assert _has_tool_calls({"stopReason": "tool_use"}) is True
    assert _has_tool_calls({"stopReason": "end_turn", "output": {"message": {"content": [{"text": "hi"}]}}}) is False
    record = {"schemaType": "ModelInvocationLog", "timestamp": "2026-01-05T09:00:00Z", "region": "us-east-1",
              "modelId": "anthropic.claude-3-5-sonnet", "identity": {"arn": "arn:aws:iam::000000000000:role/agent"},
              "operation": "Converse", "input": {"inputBodyJson": {"messages": []}, "inputTokenCount": 1},
              "output": {"outputBodyJson": output, "outputTokenCount": 1}}
    assert normalise(record, "bedrock").tool_calls is True


# finding 5 -----------------------------------------------------------------
def test_activity_buckets_use_utc_regardless_of_export_offset(index):
    # 60 identical instants: Saturday 00:00 UTC written as Friday noon in UTC-12.
    records = [_litellm(i, startTime="2026-01-09T12:00:00-12:00") for i in range(60)]
    findings, _ = _scan(index, records, format="litellm")
    activity = findings[0].metadata["activity"]
    assert {key: activity[key] for key in ("active_hours", "night_share", "weekend_share")} == {
        "active_hours": 1, "night_share": 1.0, "weekend_share": 1.0,
    }
    assert activity["always_on"] and activity["always_on_corroborated"]
    assert "always-on" in findings[0].tags


# finding 3 -----------------------------------------------------------------
def test_known_llm_host_keeps_unlisted_operation_paths(tmp_path, run_connector):
    line = '10.0.0.9 - - [05/Jan/2026:09:00:00 +0000] "{method} {path} HTTP/1.1" 200 12 "-" "openai-python/1.51" host={host}'
    path = tmp_path / "egress.log"
    path.write_text("\n".join([
        line.format(method="POST", path="/v1/moderations", host="api.openai.com"),
        line.format(method="GET", path="/favicon.ico", host="api.openai.com"),
        line.format(method="POST", path="/v1/moderations", host="intranet.example.internal"),
    ]) + "\n")
    findings, _ = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1
    assert findings[0].metadata["events"] == 1
    assert findings[0].metadata["hosts"] == {"api.openai.com": 1}


# finding 2 -----------------------------------------------------------------
def test_vertex_detection_does_not_depend_on_serialized_prefix():
    delegation = [{"firstPartyPrincipal": {"principalEmail": f"hop-{i}@example-project.iam.gserviceaccount.com"}} for i in range(4)]
    payload = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "status": {},
               "authenticationInfo": {"principalEmail": "agent@example-project.iam.gserviceaccount.com",
                                      "serviceAccountDelegationInfo": delegation},
               "requestMetadata": {"callerIp": "203.0.113.5", "callerSuppliedUserAgent": "google-cloud-aiplatform/1.71.0"},
               "serviceName": "aiplatform.googleapis.com",
               "methodName": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
               "resourceName": "projects/example-project/locations/us-central1/publishers/google/models/gemini-1.5-pro"}
    assert json.dumps(payload).find("aiplatform") > 500  # the old prefix heuristic cannot see it
    record = {"protoPayload": payload, "resource": {"labels": {"project_id": "example-project"}}, "timestamp": "2026-01-05T09:00:00Z"}
    assert detect_schema(record) == "vertex"
    assert normalise(record, "vertex").caller == "gcp:agent@example-project.iam.gserviceaccount.com"
    assert detect_schema({"protoPayload": {"methodName": "google.cloud.aiplatform.v1.PredictionService.Predict"}}) == "vertex"


# finding 8 -----------------------------------------------------------------
def test_access_log_mentioning_a_gateway_vendor_stays_an_access_log():
    for agent in ("portkey-python-sdk/1.4.0", "helicone-python/0.3"):
        record = {"remote_addr": "10.0.0.5", "request_uri": "/v1/chat/completions", "http_user_agent": agent,
                  "host": "api.openai.com", "status": "200", "time": "2026-01-05T09:00:00Z"}
        assert detect_schema(record) == "access-log"
        event = normalise(record, "access-log")
        assert event.caller_kind == "user-agent" and event.ip == "10.0.0.5" and event.user_agent == agent
    assert detect_schema({"trace_id": "t", "virtual_key": "vk", "model": "gpt-4o"}) == "portkey"
    assert detect_schema({"x-portkey-trace-id": "t", "model": "gpt-4o"}) == "portkey"


# finding 9 -----------------------------------------------------------------
def test_token_in_user_field_is_not_partially_disclosed_by_label_truncation(index):
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    claims = base64.urlsafe_b64encode(json.dumps({"iss": "https://login.example.test/", "sub": "user-1", "scope": "a " * 40}).encode()).rstrip(b"=").decode()
    token = f"{header}.{claims}.{'s' * 86}"
    record = {"user": token, "model": "gpt-4o", "timestamp": "2026-01-05T09:00:00Z"}
    event = normalise(record, "generic")
    assert event.caller.startswith("user:caller:hmac-sha256:") and event.caller_redacted
    assert event.caller_label.startswith("caller:hmac-sha256:")
    assert not token.startswith(event.caller_label) and "eyJ" not in event.caller_label
    findings, _ = _scan(index, [record])
    report = json.dumps([finding.to_dict() for finding in findings])
    assert findings and "eyJ" not in report and token[:40] not in report


# finding 10 ----------------------------------------------------------------
def test_generic_identity_object_prefers_arn_and_never_uses_a_repr():
    record = {"identity": {"arn": "arn:aws:iam::000000000000:role/agent", "type": "AssumedRole"}, "model": "gpt-4o"}
    event = normalise(record, "generic")
    assert event.caller == "principal:arn:aws:iam::000000000000:role/agent"
    assert event.caller_label == "arn:aws:iam::000000000000:role/agent"
    assert normalise({"identity": {"type": "AssumedRole"}, "model": "gpt-4o"}, "generic") is None
    assert normalise({"api_key": {"id": "k"}, "service": "worker", "model": "gpt-4o"}, "generic").caller == "principal:worker"


# finding 11 ----------------------------------------------------------------
def test_litellm_alias_without_key_is_not_treated_as_a_credential(index):
    record = {"spend": 0.01, "api_key_alias": "research-agent", "model": "gpt-4o", "request_id": "1",
              "user": "research-agent-owner@example.test", "startTime": "2026-01-05T09:00:00Z"}
    event = normalise(record, "litellm")
    assert event.caller_kind == "service" and event.caller_label == "research-agent"
    assert "hmac-sha256" not in event.caller and not event.caller_redacted
    findings, _ = _scan(index, [record], format="litellm")
    assert findings[0].metadata["caller"] == "research-agent"
    assert findings[0].metadata["end_users"] == {"research-agent-owner@example.test": 1}
    assert findings[0].metadata["runtime_observations"][0]["identity_assurance"] == "unverified"


# finding 13 ----------------------------------------------------------------
def test_prose_message_keeps_the_structured_event(tmp_path, run_connector):
    record = {"message": "chat completion finished", "level": "info", "user_id": "u-42", "model_name": "gpt-4o",
              "usage": {"prompt_tokens": 10, "completion_tokens": 5}, "timestamp": "2026-01-05T09:00:00Z"}
    path = tmp_path / "app.jsonl"
    path.write_text(json.dumps(record) + "\n")
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1 and findings[0].resource == "user:u-42"
    assert findings[0].models == ["gpt-4o"]
    assert not ctx.stats.incomplete and not ctx.stats.warnings


# finding 12 ----------------------------------------------------------------
def test_retained_labels_and_samples_are_bounded(index):
    findings, _ = _scan(index, [_litellm(model="m" * 5000, custom_llm_provider="p" * 5000)], format="litellm")
    assert len(findings[0].title) < 1000
    assert all(len(model) <= logs._MAX_LABEL_CHARS for model in findings[0].metadata["models"])
    assert all(len(provider) <= logs._MAX_LABEL_CHARS for provider in findings[0].metadata["providers"])
    record = {"virtual_key": "vk-1", "trace_id": "t" * 5000, "model": "gpt-4o", "created_at": "2026-01-05T09:00:00Z"}
    findings, _ = _scan(index, [record], format="portkey")
    assert len(findings[0].metadata["samples"]["trace_id"]) == logs._MAX_SAMPLE_CHARS


# finding 6 -----------------------------------------------------------------
def test_first_distribution_label_survives_an_exhausted_detail_budget(index, monkeypatch):
    monkeypatch.setattr(logs, "_MAX_TOTAL_DETAIL_KEYS", 3)
    findings, ctx = _scan(index, [
        {"service": "one", "model": "gpt-4o", "user": "alice", "environment": "production"},
        {"service": "two", "model": "gpt-5", "user": "bob"},
        {"service": "two", "model": "gpt-4o", "user": "bob"},
    ], format="generic")
    by_caller = {finding.resource: finding for finding in findings}
    second = by_caller["principal:two"]
    assert second.metadata["models"] == {"gpt-5": 1}
    assert second.metadata["end_users"] == {"bob": 2}
    assert second.models == ["gpt-5"] and second.metadata["distribution_events_dropped"] == {"models": 1}
    assert ctx.stats.incomplete


# finding 7 (safe optimisation) -----------------------------------------------
class _Spy:
    def __init__(self, index):
        self._index = index
        self.names: list[str] = []

    def match_name(self, name):
        self.names.append(name)
        return self._index.match_name(name)

    def __getattr__(self, attr):
        return getattr(self._index, attr)


def test_opaque_caller_labels_skip_display_name_matching(index):
    spy = _Spy(index)
    findings, _ = _scan(spy, [_litellm(api_key_alias=None), _litellm(1, api_key="opaque-key-two")], format="litellm")
    labels = {finding.metadata["caller"] for finding in findings}
    assert any(label.startswith("credential:hmac-sha256:") for label in labels) and "svc-agent" in labels
    assert "svc-agent" in spy.names
    assert not any(name.startswith("credential:hmac-sha256:") for name in spy.names)
