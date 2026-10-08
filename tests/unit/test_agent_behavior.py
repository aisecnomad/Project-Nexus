"""Behavioural agent indicators (shadowscan.connectors.agent_behavior) and their gateway use."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shadowscan.connectors.agent_behavior import (
    agent_operations,
    is_browser_user_agent,
    is_generation,
    is_mcp_request,
    loop_cadence,
)


@pytest.mark.parametrize(
    ("path", "host", "label"),
    [
        ("/agents/AB12CD/agentAliases/TSTALIASID/sessions/s-1/text", "bedrock-agent-runtime.us-east-1.amazonaws.com", "Amazon Bedrock InvokeAgent"),
        ("/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-east-1/invocations", "bedrock-agentcore.us-east-1.amazonaws.com", "Amazon Bedrock AgentCore runtime"),
        ("/v1/threads/thread_abc/runs", "api.openai.com", "Assistants API run"),
        ("/v1/threads/runs", "api.openai.com", "Assistants API run"),
        ("/v1/threads/thread_abc/runs/run_1/submit_tool_outputs", "api.openai.com", "Assistants API run"),
        ("/openai/threads/thread_abc/runs/run_1/submit_tool_outputs?api-version=2024-05-01", "sample.openai.azure.com", "Assistants API run"),
        ("/v1/projects/p/locations/us-central1/reasoningEngines/123:streamQuery", "us-central1-aiplatform.googleapis.com", "Vertex AI Agent Engine"),
        ("/v3/projects/p/locations/global/agents/a/sessions/s:detectIntent", "dialogflow.googleapis.com", "Dialogflow CX agent session"),
    ],
)  # fmt: skip
def test_agent_operations(path, host, label):
    ops = agent_operations({path: 3}, method="POST", host=host)
    assert [(op.label, op.requests) for op in ops] == [(label, 3)]
    for method in (None, "GET", "DELETE", "PATCH", "PUT"):
        assert not agent_operations({path: 3}, method=method, host=host)
    for other_host in (None, "example.org", "api.anthropic.com", host + ".example.org"):
        assert not agent_operations({path: 3}, method="POST", host=other_host)


def test_agent_operations_ignore_plain_model_calls_and_sum_paths():
    ops = agent_operations(
        {
            "/v1/chat/completions": 10,
            "/model/anthropic.claude-3-5-sonnet/converse": 4,
            "/agents/A/agentAliases/B/sessions/1/text": 2,
            "/agents/A/agentAliases/B/sessions/2/text": 1,
        },
        method="POST",
        host="bedrock-agent-runtime.us-east-1.amazonaws.com",
    )
    assert [(op.label, op.signature, op.requests) for op in ops] == [
        ("Amazon Bedrock InvokeAgent", "cloud.aws-bedrock-agents", 3)
    ]


@pytest.mark.parametrize(
    ("path", "mcp_host", "expected"),
    [
        ("/mcp", False, True),
        ("/v1/mcp/", False, True),
        ("/mcp?session=1", False, True),
        ("/sse", True, True),
        ("/messages/", True, True),
        ("/sse", False, False),
        ("/mcp-docs", False, False),
        (None, True, False),
    ],
)
def test_is_mcp_request(path, mcp_host, expected):
    assert is_mcp_request(path, mcp_host) is expected


@pytest.mark.parametrize(
    ("path", "model", "method", "expected"),
    [
        ("/v1/chat/completions", "gpt-4o", "POST", True),
        ("/v1/chat/completions", "gpt-4o", None, False),
        ("/v1/chat/completions", "gpt-4o", "GET", False),
        ("/v1/embeddings", None, "POST", False),
        (None, "text-embedding-3-small", None, False),
        ("/v1/models", None, "GET", False),
        ("/v1/messages/count_tokens", None, "POST", False),
        (None, None, None, False),
        (None, "gpt-4o", None, True),
        ("/v1/assistants", "gpt-4o", "POST", False),
        ("/v1/threads/thread_abc/runs/run_1", "gpt-4o", "GET", False),
        ("/arbitrary", "gpt-4o", "POST", False),
    ],
)
def test_is_generation(path, model, method, expected):
    assert is_generation(path, model, method) is expected


@pytest.mark.parametrize(
    ("ua", "expected"),
    [
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/605.1.15", True),
        ("Mozilla/5.0 (compatible; Googlebot/2.1)", False),
        ("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/129.0", False),
        ("Mozilla/5.0 Chrome/120", False),
        ("OpenAI/Python 1.51.0", False),
        (None, False),
    ],
)
def test_is_browser_user_agent(ua, expected):
    assert is_browser_user_agent(ua) is expected


def test_loop_cadence_counts_runs_in_any_order():
    times = [0, 5, 10, 300, 1000, 1010, 1020, 1030, 1031, 5000, float("nan")]
    cadence = loop_cadence(reversed(times))
    assert (cadence.loops, cadence.longest, cadence.calls_in_loops, cadence.calls) == (2, 5, 8, 10)
    assert cadence.share == pytest.approx(0.8)


def test_simultaneous_calls_are_not_a_loop():
    assert loop_cadence([0, 0, 0, 3600, 3600, 3600]).loops == 0
    assert loop_cadence([0, 0, 5, 10]).calls == 3


def test_loop_cadence_without_loops():
    assert loop_cadence([0, 60, 120]).loops == 0
    assert loop_cadence([0, 1]).longest == 0
    assert loop_cadence([]).share == 0.0
    assert loop_cadence([0, 1, 2], min_calls=4).loops == 0


# ----------------------------------------------------------------- gateway


START = datetime(2025, 9, 1, 9, 0, tzinfo=UTC)


def _line(at: datetime, path: str, host: str, ua: str, ip: str = "10.0.0.5") -> str:
    stamp = at.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "POST {path} HTTP/1.1" 200 900 "-" "{ua}" host={host}\n'


def _scan(run_connector, tmp_path, lines: list[str]):
    path = tmp_path / "access.log"
    path.write_text("".join(lines))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not ctx.stats.incomplete
    return {f.metadata["caller"]: f for f in findings}


def test_gateway_agent_loop_cadence_from_access_logs(run_connector, tmp_path):
    sdk, browser, spaced, embed = (
        "OpenAI/Python 1.51.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/605.1.15",
        "anthropic-python/0.40.0",
        "OpenAI/JS 4.70.0",
    )
    lines = []
    for i in range(5):
        lines.append(_line(START + timedelta(seconds=6 * i), "/v1/chat/completions", "api.openai.com", sdk))
        lines.append(
            _line(START + timedelta(seconds=4 * i), "/v1/chat/completions", "api.openai.com", browser)
        )
        lines.append(_line(START + timedelta(minutes=7 * i), "/v1/messages", "api.anthropic.com", spaced))
        lines.append(_line(START + timedelta(seconds=2 * i), "/v1/embeddings", "api.openai.com", embed))
    callers = _scan(run_connector, tmp_path, lines)

    agent = callers[sdk]
    assert agent.title.startswith("LLM caller") and "agent-loop" in agent.tags
    assert not agent.metadata.get("agent_indicators")
    assert agent.metadata["agent_behaviour"]["loop_cadence"]["longest"] == 5
    assert any(e.signal == "gateway:agent-loop" for e in agent.evidence)
    for ua in (browser, spaced, embed):
        assert callers[ua].title.startswith("LLM caller"), ua
        assert "agent-loop" not in callers[ua].tags
    # A person in a browser can send calls this fast; the cadence is reported, not counted.
    assert callers[browser].metadata["agent_behaviour"]["loop_cadence"]["browser_requests"] == 5
    assert "agent_behaviour" not in callers[spaced].metadata
    assert "agent_behaviour" not in callers[embed].metadata


def test_gateway_hosted_agent_runtime_and_mcp_endpoints(run_connector, tmp_path):
    boto = "Boto3/1.35.10 md/Botocore#1.35.10 ua/2.0 os/linux lang/python#3.12.6"
    node = "node-fetch/3.3.2"
    plain = "python-httpx/0.27.2"
    lines = [
        _line(
            START + timedelta(minutes=10 * i),
            f"/agents/AGENT{i}/agentAliases/TSTALIASID/sessions/s{i}/text",
            "bedrock-agent-runtime.us-east-1.amazonaws.com",
            boto,
        )
        for i in range(2)
    ]
    lines += [
        _line(START + timedelta(minutes=9), "/mcp", "mcp.sentry.dev", node),
        _line(START + timedelta(minutes=19), "/sse", "mcp.linear.app", node),
        _line(START + timedelta(minutes=1), "/v1/chat/completions", "api.openai.com", plain),
        _line(START + timedelta(minutes=29), "/v1/chat/completions", "api.openai.com", plain),
    ]
    callers = _scan(run_connector, tmp_path, lines)

    bedrock = callers[boto]
    assert bedrock.title.startswith("Agentic caller")
    assert "agent-runtime-api" in bedrock.tags and "cloud.aws-bedrock-agents" in bedrock.frameworks
    assert bedrock.metadata["agent_behaviour"]["agent_operations"] == {"Amazon Bedrock InvokeAgent": 2}

    mcp = callers[node]
    assert mcp.title.startswith("Agentic caller") and "mcp-client" in mcp.tags
    assert "protocol.mcp" in mcp.frameworks and "tool-use" in mcp.capabilities
    assert mcp.metadata["agent_behaviour"]["mcp_requests"] == 2

    assert callers[plain].title.startswith("LLM caller")
    assert not {"mcp-client", "agent-runtime-api", "agent-loop"} & set(callers[plain].tags)


def test_names_and_consumer_sites_are_not_agent_indicators(run_connector, tmp_path):
    """Regression: a user called Jules and browsing chatgpt.com made callers agentic."""
    lines = [
        '{"time": "2025-09-01T09:00:00Z", "remote_user": "jules", "request_method": "POST", '
        '"request_uri": "/api/chat", "status": 200, "http_user_agent": "ollama-python/0.4.4", '
        '"host": "127.0.0.1:11434"}\n',
        '{"time": "2025-09-01T09:30:00Z", "remote_user": "kofi", "request_method": "POST", '
        '"request_uri": "/backend-api/conversation", "status": 200, '
        '"http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/129.0", "host": "chatgpt.com"}\n',
        '{"time": "2025-09-01T09:40:00Z", "remote_user": "dev", "request_method": "POST", '
        '"request_uri": "/aiserver.v1.ChatService/StreamChat", "status": 200, '
        '"http_user_agent": "connect-es/1.4.0", "host": "api2.cursor.sh"}\n',
    ]
    path = tmp_path / "access.jsonl"
    path.write_text("".join(lines))
    findings, ctx = run_connector("gateway.logs", input=str(path), llm_hosts_only=False)
    assert not ctx.stats.incomplete
    by = {f.metadata["caller"]: f for f in findings}
    assert by["jules"].title.startswith("LLM caller") and by["kofi"].title.startswith("LLM caller")
    assert by["dev"].title.startswith("Agentic caller")


def test_host_service_prefers_weight_then_category(index):
    from shadowscan.connectors.agent_behavior import host_service

    assert host_service(index.match_domain("chatgpt.com")).signature.id == "identity-app.openai-chatgpt"
    assert host_service(index.match_domain("api.openai.com")).signature.id == "provider.openai"
    assert host_service(index.match_domain("example.org")) is None


def test_gateway_sse_on_a_non_mcp_host_is_not_an_mcp_client(run_connector, tmp_path):
    ua = "python-httpx/0.27.2"
    lines = [
        _line(START, "/sse", "api.openai.com", ua),
        _line(START + timedelta(minutes=5), "/v1/chat/completions", "api.openai.com", ua),
    ]
    callers = _scan(run_connector, tmp_path, lines)
    assert "mcp-client" not in callers[ua].tags


@pytest.mark.parametrize(
    "path",
    [
        "/v1/assistants",
        "/v1/assistants/asst_1",
        "/v1/threads/thread_1",
        "/v1/threads/thread_1/messages",
        "/v1/threads/thread_1/runs/run_1",
        "/v1/threads/thread_1/runs/run_1/cancel",
        "/v1/threads/thread_1/runs/run_1/steps",
    ],
)
def test_management_paths_never_identify_invocation_or_model_cadence(path):
    for method in (None, "GET", "POST", "DELETE"):
        assert not agent_operations({path: 10}, method=method, host="api.openai.com")
        assert not is_generation(path, "gpt-4o", method)


def test_gateway_hosted_operation_fixture(run_connector):
    path = Path(__file__).resolve().parents[1] / "fixtures/gateway/hosted_operations.jsonl"
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not ctx.stats.incomplete
    by = {finding.metadata["caller"]: finding for finding in findings}
    positives = {"openai-run", "tool-submission", "bedrock-run", "azure-run", "native-vertex"}
    assert positives <= by.keys()
    for name, finding in by.items():
        assert ("agent-runtime-api" in finding.tags) is (name in positives), name
        assert finding.title.startswith("Agentic caller" if name in positives else "LLM caller"), name
        assert "tool-use" not in finding.capabilities, name
        assert "agent-loop" not in finding.tags, name
        if name in positives:
            evidence = next(e for e in finding.evidence if e.signal == "gateway:agent-runtime-api")
            assert "does not establish successful execution or tool use" in evidence.description
    # Three distinct calls must keep their own path/host/method provenance.
    assert by["mixed-provenance"].metadata["events"] == 3
    assert by["inventory-job"].metadata["events"] == 5


def test_native_vertex_requires_schema_service_and_precise_rpc():
    operation = "google.cloud.aiplatform.v1.ReasoningEngineExecutionService.QueryReasoningEngine"
    assert agent_operations({operation: 1}, host="aiplatform.googleapis.com", schema="vertex")
    assert not agent_operations({operation: 1}, host="aiplatform.googleapis.com", schema="generic")
    assert not agent_operations({operation: 1}, host="dialogflow.googleapis.com", schema="vertex")
    assert not agent_operations(
        {operation: 1}, method="GET", host="aiplatform.googleapis.com", schema="vertex"
    )
    assert not agent_operations({operation + "Other": 1}, host="aiplatform.googleapis.com", schema="vertex")


@pytest.mark.parametrize(
    "schema,extra",
    [
        ("generic", {"user": "reader", "method": "get"}),
        ("access-log", {"remote_user": "reader", "request": "GET /v1/assistants HTTP/1.1"}),
        ("access-log", {"remote_user": "reader", "request_method": "GET"}),
        ("kong", {"request": {"method": "GET"}}),
        ("vertex", {"httpRequest": {"requestMethod": "GET"}}),
    ],
)
def test_normalization_preserves_http_method(schema, extra):
    from shadowscan.connectors.gateway.logs import normalise

    assert normalise(extra, schema).method == "GET"


def test_malformed_http_method_marks_export_incomplete(run_connector, tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text(json.dumps({"user": "reader", "method": {"POST": True}, "model": "gpt-4o"}))
    _, ctx = run_connector("gateway.logs", input=str(path))
    assert ctx.stats.incomplete
