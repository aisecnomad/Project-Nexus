from __future__ import annotations

import base64
import json
import time

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.gateway import logs as logs_module
from shadowscan.connectors.gateway.logs import (
    GatewayLogConnector,
    _f,
    _has_tool_calls,
    _has_tools,
    _i,
    detect_schema,
    normalise,
    parse_text_line,
)
from shadowscan.models import Kind, ScanStats, now_iso


def test_schema_detection():
    assert (
        detect_schema({"schemaType": "ModelInvocationLog", "modelId": "x", "identity": {}, "input": {}})
        == "bedrock"
    )
    assert detect_schema({"spend": 0.1, "api_key": "h", "model": "gpt-4o"}) == "litellm"
    assert (
        detect_schema({"category": "RequestResponse", "resourceId": "/x", "properties": {}}) == "azure-openai"
    )
    assert detect_schema({"protoPayload": {"serviceName": "aiplatform.googleapis.com"}}) == "vertex"
    assert (
        detect_schema(
            {"remote_addr": "1.2.3.4", "request_uri": "/v1/chat/completions", "http_user_agent": "x"}
        )
        == "access-log"
    )
    assert detect_schema({"gateway_id": "g", "provider": "openai", "model": "gpt-4o"}) == "cloudflare"
    assert detect_schema({"model": "gpt-4o", "user": "alice", "prompt_tokens": 1}) == "generic"


def test_normalise_litellm_tool_use():
    rec = {
        "api_key": "abc",
        "api_key_alias": "bot",
        "model": "gpt-4o",
        "spend": 0.2,
        "startTime": "2025-01-01T00:00:00Z",
        "proxy_server_request": {"body": {"tools": [{"type": "function"}]}},
        "response": {"choices": [{"finish_reason": "tool_calls"}]},
        "metadata": {"user_agent": "langchain/0.3"},
    }
    ev = normalise(rec, "litellm")
    assert (
        ev.caller_kind == "api-key"
        and ev.tools is True
        and ev.tool_calls is True
        and ev.user_agent == "langchain/0.3"
    )


def test_parse_access_log_line():
    rec = parse_text_line(
        '10.0.0.1 - - [10/Sep/2025:10:00:00 +0000] "POST /v1/chat/completions HTTP/1.1" 200 512 "-" "OpenAI/Python 1.5" host=api.openai.com'
    )
    assert (
        rec["request_uri"] == "/v1/chat/completions"
        and rec["http_user_agent"] == "OpenAI/Python 1.5"
        and rec["host"] == "api.openai.com"
    )


def test_litellm_fixture_callers(run_connector, fixtures):
    findings, ctx = run_connector("gateway.logs", input=str(fixtures / "gateway" / "litellm_spend.jsonl"))
    assert not ctx.stats.errors and len(findings) == 2
    agent = next(f for f in findings if f.metadata["caller"] == "research-agent-prod")
    assert agent.kind == Kind.GATEWAY_CALLER
    assert "framework.langchain" in agent.frameworks and "provider.openai" in agent.model_providers
    assert "tool-use" in agent.capabilities and agent.metadata["tool_requests"] == 200
    assert agent.metadata["events"] == 200
    human = next(f for f in findings if f.metadata["caller"] == "alice-notebook")
    assert human.owner == "alice@acme.com" and "tool-use" not in human.capabilities


def test_bedrock_and_azure_fixtures(run_connector, fixtures):
    findings, _ = run_connector("gateway.logs", input=str(fixtures / "gateway" / "bedrock_invocations.jsonl"))
    role = next(f for f in findings if "ops-agent-role" in f.resource)
    assert "provider.aws-bedrock" in role.model_providers and "tool-use" in role.capabilities
    assert role.models == ["anthropic.claude-3-5-sonnet-20241022-v2:0"]
    findings, _ = run_connector("gateway.logs", input=str(fixtures / "gateway" / "azure_openai_diag.json"))
    assert len(findings) == 1 and "framework.microsoft-agent-framework" in findings[0].frameworks
    assert findings[0].metadata["caller_kind"] == "principal"


def test_access_log_filters_non_llm_hosts(run_connector, fixtures):
    findings, _ = run_connector("gateway.logs", input=str(fixtures / "gateway" / "egress_proxy.log"))
    crew = next(f for f in findings if "crewai" in f.resource)
    assert "framework.crewai" in crew.frameworks and "provider.openai" in crew.model_providers


def context(index, **config):
    ctx = ConnectorContext(index=index, config=config)
    ctx.stats = ScanStats(connector="test", started_at="now")
    return ctx


def test_gateway_json_lines_recover_after_corrupt_first_row(index, tmp_path):
    source = tmp_path / "gateway.json"
    source.write_text("{broken\n" + json.dumps({"api_key": "a", "model": "gpt-4o", "spend": 1}) + "\n")
    ctx = context(index, input=str(source), format="litellm")
    findings = GatewayLogConnector(ctx).run()
    assert len(findings) == 1 and findings[0].metadata["events"] == 1
    assert ctx.stats.incomplete


def _scan(index, records, **config):
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


TOOL_CALL_RESPONSE = {
    "choices": [
        {
            "finish_reason": "tool_calls",
            "message": {
                "tool_calls": [
                    {"id": "call-1", "type": "function", "function": {"name": "search", "arguments": "{}"}}
                ]
            },
        }
    ]
}


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


def test_bedrock_converse_tool_use_response_is_detected():
    output = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"toolUse": {"toolUseId": "t-1", "name": "run_plan", "input": {"plan": "x"}}}],
            }
        },
        "stopReason": "tool_use",
        "usage": {"inputTokens": 1, "outputTokens": 1},
    }
    assert _has_tool_calls(output) is True
    assert _has_tool_calls({"stopReason": "tool_use"}) is True
    assert (
        _has_tool_calls({"stopReason": "end_turn", "output": {"message": {"content": [{"text": "hi"}]}}})
        is False
    )
    record = {
        "schemaType": "ModelInvocationLog",
        "timestamp": "2026-01-05T09:00:00Z",
        "region": "us-east-1",
        "modelId": "anthropic.claude-3-5-sonnet",
        "identity": {"arn": "arn:aws:iam::000000000000:role/agent"},
        "operation": "Converse",
        "input": {"inputBodyJson": {"messages": []}, "inputTokenCount": 1},
        "output": {"outputBodyJson": output, "outputTokenCount": 1},
    }
    assert normalise(record, "bedrock").tool_calls is True


def test_activity_buckets_use_utc_regardless_of_export_offset(index):
    # 60 identical instants: Saturday 00:00 UTC written as Friday noon in UTC-12.
    records = [_litellm(i, startTime="2026-01-09T12:00:00-12:00") for i in range(60)]
    findings, _ = _scan(index, records, format="litellm")
    activity = findings[0].metadata["activity"]
    assert {key: activity[key] for key in ("active_hours", "night_share", "weekend_share")} == {
        "active_hours": 1,
        "night_share": 1.0,
        "weekend_share": 1.0,
    }
    assert activity["always_on"] and activity["always_on_corroborated"]
    assert "always-on" in findings[0].tags


@pytest.mark.parametrize("timestamp", ["9999-12-31T23:59:59-01:00", "0001-01-01T00:00:00+01:00"])
def test_unrepresentable_utc_timestamp_does_not_poison_valid_caller_records(index, timestamp):
    records = [_litellm(0), _litellm(1, startTime=timestamp), _litellm(2)]

    findings, ctx = _scan(index, records, format="litellm")

    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert findings[0].first_seen == findings[0].last_seen == "2026-01-05T09:00:00+00:00"
    assert ctx.stats.incomplete
    assert any("invalid record 2" in warning for warning in ctx.stats.warnings)
    assert all("caller analysis failed" not in warning for warning in ctx.stats.warnings)


def test_unrepresentable_utc_interval_end_does_not_poison_valid_usage_record(index):
    valid = {
        "api_key_id": "key-one",
        "model": "gpt-4o",
        "num_model_requests": 2,
        "start_time": "2026-01-05T09:00:00Z",
        "end_time": "2026-01-05T10:00:00Z",
    }
    malformed = {**valid, "end_time": "9999-12-31T23:59:59-01:00", "num_model_requests": 100}

    findings, ctx = _scan(index, [malformed, valid], format="openai-usage")

    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert findings[0].last_seen == "2026-01-05T10:00:00+00:00"
    assert ctx.stats.incomplete
    assert any("invalid record 1" in warning for warning in ctx.stats.warnings)
    assert all("caller analysis failed" not in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("per_second", [1, 1000, 1_000_000, 1_000_000_000], ids=["s", "ms", "us", "ns"])
@pytest.mark.parametrize("as_text", [False, True], ids=["number", "text"])
def test_generic_epoch_timestamps_keep_activity_window_in_every_unit(
    tmp_path, run_connector, per_second, as_text
):
    # 48 requests from one caller, one per hour, as a generic export would
    # write them in epoch seconds, milliseconds, microseconds or nanoseconds.
    start = 1767225600  # 2026-01-01T00:00:00Z
    rows = []
    for hour in range(48):
        stamp = (start + hour * 3600) * per_second
        rows.append({"service": "svc-ops", "model": "gpt-4o", "timestamp": str(stamp) if as_text else stamp})
    export = tmp_path / "gateway.jsonl"
    export.write_text("".join(json.dumps(row) + "\n" for row in rows))
    findings, ctx = run_connector("gateway.logs", input=str(export))
    assert not ctx.stats.incomplete and not ctx.stats.errors and not ctx.stats.warnings
    assert len(findings) == 1 and findings[0].metadata["events"] == 48
    assert findings[0].first_seen == "2026-01-01T00:00:00+00:00"
    assert findings[0].last_seen == "2026-01-02T23:00:00+00:00"
    observation = findings[0].metadata["runtime_observations"][0]
    assert observation["timestamped_events"] == 48


def test_known_llm_host_keeps_unlisted_operation_paths(tmp_path, run_connector):
    line = '10.0.0.9 - - [05/Jan/2026:09:00:00 +0000] "{method} {path} HTTP/1.1" 200 12 "-" "openai-python/1.51" host={host}'
    path = tmp_path / "egress.log"
    path.write_text(
        "\n".join(
            [
                line.format(method="POST", path="/v1/moderations", host="api.openai.com"),
                line.format(method="GET", path="/favicon.ico", host="api.openai.com"),
                line.format(method="POST", path="/v1/moderations", host="intranet.example.internal"),
            ]
        )
        + "\n"
    )
    findings, _ = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1
    assert findings[0].metadata["events"] == 1
    assert findings[0].metadata["hosts"] == {"api.openai.com": 1}


def test_cloudflare_workers_ai_inference_is_llm_traffic_but_other_cloudflare_api_calls_are_not(
    tmp_path, run_connector
):
    # api.cloudflare.com is a general REST API: only its Workers AI paths are inference.
    line = (
        '10.0.0.5 - - [10/Oct/2025:13:55:{sec:02d} +0000] "{method} {path} HTTP/1.1" 200 2326 "-" "{ua}"'
        " host=api.cloudflare.com"
    )
    account = "/client/v4/accounts/0123456789abcdef"
    requests = [
        ("POST", f"{account}/ai/run/@cf/meta/llama-3.1-8b-instruct", "python-requests/2.31"),
        ("POST", f"{account}/ai/run/@cf/baai/bge-base-en-v1.5", "python-requests/2.31"),
        ("POST", f"{account}/ai/v1/chat/completions", "httpx/0.27"),
        ("GET", "/client/v4/zones", "terraform/1.9"),
        ("GET", f"{account}/workers/scripts", "terraform/1.9"),
        ("GET", f"{account}/ai/models/search", "terraform/1.9"),
    ]
    path = tmp_path / "access.log"
    path.write_text(
        "".join(
            line.format(sec=sec, method=method, path=target, ua=ua) + "\n"
            for sec, (method, target, ua) in enumerate(requests)
        )
    )
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not ctx.stats.incomplete
    callers = {finding.metadata["caller"]: finding.metadata["events"] for finding in findings}
    assert callers == {"python-requests/2.31": 2, "httpx/0.27": 1}


def test_vertex_detection_does_not_depend_on_serialized_prefix():
    delegation = [
        {"firstPartyPrincipal": {"principalEmail": f"hop-{i}@example-project.iam.gserviceaccount.com"}}
        for i in range(4)
    ]
    payload = {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "status": {},
        "authenticationInfo": {
            "principalEmail": "agent@example-project.iam.gserviceaccount.com",
            "serviceAccountDelegationInfo": delegation,
        },
        "requestMetadata": {
            "callerIp": "203.0.113.5",
            "callerSuppliedUserAgent": "google-cloud-aiplatform/1.71.0",
        },
        "serviceName": "aiplatform.googleapis.com",
        "methodName": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
        "resourceName": "projects/example-project/locations/us-central1/publishers/google/models/gemini-1.5-pro",
    }
    assert json.dumps(payload).find("aiplatform") > 500  # the old prefix heuristic cannot see it
    record = {
        "protoPayload": payload,
        "resource": {"labels": {"project_id": "example-project"}},
        "timestamp": "2026-01-05T09:00:00Z",
    }
    assert detect_schema(record) == "vertex"
    assert normalise(record, "vertex").caller == "gcp:agent@example-project.iam.gserviceaccount.com"
    assert (
        detect_schema(
            {"protoPayload": {"methodName": "google.cloud.aiplatform.v1.PredictionService.Predict"}}
        )
        == "vertex"
    )


def test_access_log_mentioning_a_gateway_vendor_stays_an_access_log():
    for agent in ("portkey-python-sdk/1.4.0", "helicone-python/0.3"):
        record = {
            "remote_addr": "10.0.0.5",
            "request_uri": "/v1/chat/completions",
            "http_user_agent": agent,
            "host": "api.openai.com",
            "status": "200",
            "time": "2026-01-05T09:00:00Z",
        }
        assert detect_schema(record) == "access-log"
        event = normalise(record, "access-log")
        assert event.caller_kind == "user-agent" and event.ip == "10.0.0.5" and event.user_agent == agent
    assert detect_schema({"trace_id": "t", "virtual_key": "vk", "model": "gpt-4o"}) == "portkey"
    assert detect_schema({"x-portkey-trace-id": "t", "model": "gpt-4o"}) == "portkey"


def test_token_in_user_field_is_not_partially_disclosed_by_label_truncation(index):
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    claims = (
        base64.urlsafe_b64encode(
            json.dumps({"iss": "https://login.example.test/", "sub": "user-1", "scope": "a " * 40}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    token = f"{header}.{claims}.{'s' * 86}"
    record = {"user": token, "model": "gpt-4o", "timestamp": "2026-01-05T09:00:00Z"}
    event = normalise(record, "generic")
    assert event.caller.startswith("user:caller:hmac-sha256:") and event.caller_redacted
    assert event.caller_label.startswith("caller:hmac-sha256:")
    assert not token.startswith(event.caller_label) and "eyJ" not in event.caller_label
    findings, _ = _scan(index, [record])
    report = json.dumps([finding.to_dict() for finding in findings])
    assert findings and "eyJ" not in report and token[:40] not in report


def test_generic_identity_object_prefers_arn_and_never_uses_a_repr():
    record = {
        "identity": {"arn": "arn:aws:iam::000000000000:role/agent", "type": "AssumedRole"},
        "model": "gpt-4o",
    }
    event = normalise(record, "generic")
    assert event.caller == "principal:arn:aws:iam::000000000000:role/agent"
    assert event.caller_label == "arn:aws:iam::000000000000:role/agent"
    assert normalise({"identity": {"type": "AssumedRole"}, "model": "gpt-4o"}, "generic") is None
    assert (
        normalise({"api_key": {"id": "k"}, "service": "worker", "model": "gpt-4o"}, "generic").caller
        == "principal:worker"
    )


def test_litellm_alias_without_key_is_not_treated_as_a_credential(index):
    record = {
        "spend": 0.01,
        "api_key_alias": "research-agent",
        "model": "gpt-4o",
        "request_id": "1",
        "user": "research-agent-owner@example.test",
        "startTime": "2026-01-05T09:00:00Z",
    }
    event = normalise(record, "litellm")
    assert event.caller_kind == "service" and event.caller_label == "research-agent"
    assert "hmac-sha256" not in event.caller and not event.caller_redacted
    findings, _ = _scan(index, [record], format="litellm")
    assert findings[0].metadata["caller"] == "research-agent"
    assert findings[0].metadata["end_users"] == {"research-agent-owner@example.test": 1}
    assert findings[0].metadata["runtime_observations"][0]["identity_assurance"] == "unverified"


def test_prose_message_keeps_the_structured_event(tmp_path, run_connector):
    record = {
        "message": "chat completion finished",
        "level": "info",
        "user_id": "u-42",
        "model_name": "gpt-4o",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        "timestamp": "2026-01-05T09:00:00Z",
    }
    path = tmp_path / "app.jsonl"
    path.write_text(json.dumps(record) + "\n")
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1 and findings[0].resource == "user:u-42"
    assert findings[0].models == ["gpt-4o"]
    assert not ctx.stats.incomplete and not ctx.stats.warnings


def _ctx(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at=now_iso())
    return ctx


def test_gateway_numeric_helpers_only_yield_finite_numbers():
    assert _f("nan") == 0.0 and _f(1e999) == 0.0 and _f("inf") == 0.0 and _f("1.5") == 1.5
    assert _i("inf") == 0 and _i(10**400) == 0 and _i("12") == 12


def test_text_line_parsers_are_linear_on_hostile_input():
    started = time.monotonic()
    hostile = "Bearer " + "e" * 200_000 + " status=200"
    assert parse_text_line(hostile) == {"status": "200"}
    unterminated = '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET ' + "/a" * 100_000
    assert parse_text_line(unterminated) is None
    assert time.monotonic() - started < 2
    normal = 'ts=2026-01-01T00:00:00Z method=POST path="/v1/chat/completions" status=200 ua="langchain/0.3"'
    assert parse_text_line(normal) == {
        "ts": "2026-01-01T00:00:00Z",
        "method": "POST",
        "path": "/v1/chat/completions",
        "status": "200",
        "ua": "langchain/0.3",
    }
    combined = '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /v1/chat/completions HTTP/1.1" 200 5 "-" "langchain/0.3"'
    parsed = parse_text_line(combined)
    assert (
        parsed
        and parsed["request_uri"] == "/v1/chat/completions"
        and parsed["http_user_agent"] == "langchain/0.3"
    )
    without_protocol = '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /v1/models" 200 5'
    assert parse_text_line(without_protocol)["request_uri"] == "/v1/models"


def test_query_string_cannot_hide_inference_as_a_static_asset(tmp_path, run_connector):
    # "?_=.js" used to make three chat calls look like a static asset: 0 findings, complete.
    line = (
        '10.9.9.9 - rogue-agent [10/Oct/2025:03:00:0{n} +0000] "{request} HTTP/1.1" 200 512 "-" "crewai/0.5"'
    )
    requests = [
        "POST /v1/chat/completions?_=.js",
        "POST /v1/chat/completions?_=.js#x.css",
        "POST /v1/messages?_=/healthz",
        "GET /assets/app.js?v=3",
        "GET /healthz",
        "GET /favicon.ico/../v1/chat/completions",
    ]
    path = tmp_path / "access.log"
    path.write_text("\n".join(line.format(n=n, request=r) for n, r in enumerate(requests)) + "\n")
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1 and findings[0].metadata["events"] == 4
    assert not ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "gateway.logs: requests for static assets or health probes not counted as LLM traffic: 2"
    ]


def test_path_parameters_and_format_suffixes_cannot_hide_inference(tmp_path, run_connector):
    # Servlet containers drop ";name=value" path parameters before routing and
    # suffix-matching routers serve "/chat/completions.css" as the endpoint, so
    # neither may turn an inference call into a static asset.
    line = (
        '10.9.9.9 - rogue-agent [10/Oct/2025:03:00:0{n} +0000] "{request} HTTP/1.1" 200 512 "-" "crewai/0.5"'
        " host=api.cohere.com"
    )
    requests = [
        "POST /v1/chat/completions;x.js",
        "POST /v1/chat/completions.css",
        "POST /v1/chat;jsessionid=1.js",
        "GET /static/app.js;jsessionid=abc",
        "GET /healthz;probe=1",
    ]
    path = tmp_path / "access.log"
    path.write_text("\n".join(line.format(n=n, request=r) for n, r in enumerate(requests)) + "\n")
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1 and findings[0].metadata["events"] == 3
    assert not ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "gateway.logs: requests for static assets or health probes not counted as LLM traffic: 2"
    ]


def test_logfmt_tokens_inside_a_value_or_quoted_text_are_not_fields(tmp_path, run_connector):
    # A client-controlled query string or request line logged as one token
    # must not set the model, key or host of the record.
    victim = "ts=2025-10-10T13:55:36Z api_key=KEY-REAL-0001 model=gpt-4o-mini path=/v1/chat/completions"
    hostile = [
        "ts=2025-10-10T13:55:37Z api_key=KEY-REAL-0001 GET /v1/chat/completions?model=forged-model status=200",
        'ts=2025-10-10T13:55:38Z api_key=KEY-REAL-0001 "POST /v1/chat/completions?model=forged-model" status=200',
    ]
    for line in hostile:
        assert "model" not in parse_text_line(line)
    path = tmp_path / "gateway.log"
    path.write_text("\n".join([victim, *hostile]) + "\n")
    findings, _ = run_connector("gateway.logs", input=str(path))
    assert [f.models for f in findings] == [["gpt-4o-mini"]]


def test_logfmt_escaped_quotes_cannot_inject_fields(tmp_path, run_connector):
    victim = "level=info ts=2025-10-10T13:55:36Z api_key=KEY-REAL-0001 model=gpt-4o-mini user=alice path=/v1/chat/completions"
    injected = (
        "level=info ts=2025-10-10T13:55:38Z api_key=KEY-ATTACKER-9999 model=gpt-4o-mini user=mallory "
        r'ua="x\" api_key=KEY-REAL-0001 user=alice model=forged-model \"y \\" path=/v1/chat/completions'
    )
    assert parse_text_line(injected)["ua"] == 'x" api_key=KEY-REAL-0001 user=alice model=forged-model "y \\'
    assert parse_text_line(injected)["api_key"] == "KEY-ATTACKER-9999"
    path = tmp_path / "gateway.log"
    path.write_text(f"{victim}\n{injected}\n")
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert sorted(f.metadata["events"] for f in findings) == [1, 1]
    assert all(f.models == ["gpt-4o-mini"] for f in findings)
    assert not ctx.stats.incomplete


def test_logfmt_lines_with_repeated_keys_or_open_quotes_are_malformed(tmp_path, run_connector):
    good = "ts=2025-10-10T13:55:36Z api_key=KEY-REAL-0001 model=gpt-4o-mini path=/v1/chat/completions"
    repeated = "ts=2025-10-10T13:55:37Z api_key=KEY-ATTACKER-9999 model=gpt-4o api_key=KEY-REAL-0001"
    unterminated = 'ts=2025-10-10T13:55:38Z api_key=KEY-REAL-0001 model=gpt-4o ua="x api_key=KEY-OTHER-0002'
    for line in (repeated, unterminated):
        with pytest.raises(ValueError):
            parse_text_line(line)
    path = tmp_path / "gateway.log"
    path.write_text("\n".join([good, repeated, unterminated]) + "\n")
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1 and findings[0].metadata["events"] == 1
    assert findings[0].models == ["gpt-4o-mini"]
    assert ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "gateway.logs: invalid JSON/text record at line 2",
        "gateway.logs: invalid JSON/text record at line 3",
    ]


def test_unparseable_event_times_are_counted_not_silently_dropped(tmp_path, run_connector):
    records = [
        {"api_key": "KEY-REAL-0001", "model": "gpt-4o", "timestamp": "Mon, 01 Jan 2024 00:00:00 GMT"},
        {
            "api_key": "KEY-REAL-0001",
            "model": "gpt-4o",
            "timestamp": "2024-01-01 00:00:05.5 +0000 UTC m=+1.5",
        },
        {"api_key": "KEY-REAL-0001", "model": "gpt-4o", "timestamp": "first tuesday of the month"},
    ]
    path = tmp_path / "gateway.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert len(findings) == 1 and findings[0].metadata["events"] == 3
    assert (findings[0].first_seen, findings[0].last_seen) == (
        "2024-01-01T00:00:00+00:00",
        "2024-01-01T00:00:05+00:00",
    )
    assert ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "gateway.logs: records with an unparseable timestamp field: 1; their requests are counted "
        "without activity timing"
    ]


def test_logfmt_quoted_values_are_parsed_in_linear_time():
    started = time.monotonic()
    with pytest.raises(ValueError):
        parse_text_line('a=1 ua="' + 'x\\"' * 40_000)  # unterminated after 120 KB of escapes
    assert parse_text_line('a=1 ua="' + "\\\\" * 60_000 + '"')["ua"] == "\\" * 60_000
    assert len(parse_text_line(" ".join(f"k{i}=v" for i in range(20_000)))) == 20_000
    assert time.monotonic() - started < 2


def test_gateway_json_fallback_reports_a_corrupt_document_once(index, tmp_path):
    pretty = json.dumps([{"api_key": "k", "model": "gpt-4o", "spend": 1} for _ in range(50)], indent=2)
    export = tmp_path / "export.json"
    export.write_text(pretty[:-5])
    ctx = _ctx(index, input=str(export))
    GatewayLogConnector(ctx).run()
    assert ctx.stats.errors.count("gateway.logs: invalid JSON export") == 1 and len(ctx.stats.errors) == 1
    lines = [json.dumps({"api_key": "k", "model": "gpt-4o", "spend": 1})] + ["{broken"] * 30
    export.write_text("\n".join(lines))
    ctx = _ctx(index, input=str(export))
    GatewayLogConnector(ctx).run()
    assert 1 <= len(ctx.stats.errors) <= logs_module._MAX_INVALID_LINE_ERRORS + 1
