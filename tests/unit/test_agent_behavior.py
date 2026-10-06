"""Behavioural agent indicators (shadowscan.connectors.agent_behavior) and their gateway use."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shadowscan.connectors.agent_behavior import (
    agent_operations,
    is_browser_user_agent,
    is_generation,
    is_mcp_request,
    loop_cadence,
)


@pytest.mark.parametrize(
    ("path", "label"),
    [
        ("/agents/AB12CD/agentAliases/TSTALIASID/sessions/s-1/text", "Amazon Bedrock InvokeAgent"),
        ("/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-east-1/invocations", "Amazon Bedrock AgentCore runtime"),
        ("/v1/threads/thread_abc/runs", "Assistants API run"),
        ("/openai/threads/thread_abc/runs/run_1/submit_tool_outputs?api-version=2024-05-01", "Assistants API run"),
        ("/v1/assistants", "Assistants API"),
        ("/v1/projects/p/locations/us-central1/reasoningEngines/123:streamQuery", "Vertex AI Agent Engine"),
        ("/v3/projects/p/locations/global/agents/a/sessions/s:detectIntent", "Dialogflow CX agent session"),
    ],
)  # fmt: skip
def test_agent_operations(path, label):
    ops = agent_operations({path: 3})
    assert [(op.label, op.requests) for op in ops] == [(label, 3)]


def test_agent_operations_ignore_plain_model_calls_and_sum_paths():
    ops = agent_operations(
        {
            "/v1/chat/completions": 10,
            "/model/anthropic.claude-3-5-sonnet/converse": 4,
            "/agents/A/agentAliases/B/sessions/1/text": 2,
            "/agents/A/agentAliases/B/sessions/2/text": 1,
        }
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
    ("path", "model", "expected"),
    [
        ("/v1/chat/completions", "gpt-4o", True),
        ("/v1/embeddings", None, False),
        (None, "text-embedding-3-small", False),
        ("/v1/models", None, False),
        ("/v1/messages/count_tokens", None, False),
        (None, None, True),
    ],
)
def test_is_generation(path, model, expected):
    assert is_generation(path, model) is expected


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
    assert agent.title.startswith("Agentic caller") and "agent-loop" in agent.tags
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


def test_gateway_sse_on_a_non_mcp_host_is_not_an_mcp_client(run_connector, tmp_path):
    ua = "python-httpx/0.27.2"
    lines = [
        _line(START, "/sse", "api.openai.com", ua),
        _line(START + timedelta(minutes=5), "/v1/chat/completions", "api.openai.com", ua),
    ]
    callers = _scan(run_connector, tmp_path, lines)
    assert "mcp-client" not in callers[ua].tags
