from __future__ import annotations

from shadowscan.connectors.gateway.logs import detect_schema, normalise, parse_text_line
from shadowscan.models import Kind


def test_schema_detection():
    assert detect_schema({"schemaType": "ModelInvocationLog", "modelId": "x", "identity": {}, "input": {}}) == "bedrock"
    assert detect_schema({"spend": 0.1, "api_key": "h", "model": "gpt-4o"}) == "litellm"
    assert detect_schema({"category": "RequestResponse", "resourceId": "/x", "properties": {}}) == "azure-openai"
    assert detect_schema({"protoPayload": {"serviceName": "aiplatform.googleapis.com"}}) == "vertex"
    assert detect_schema({"remote_addr": "1.2.3.4", "request_uri": "/v1/chat/completions", "http_user_agent": "x"}) == "access-log"
    assert detect_schema({"gateway_id": "g", "provider": "openai", "model": "gpt-4o"}) == "cloudflare"
    assert detect_schema({"model": "gpt-4o", "user": "alice", "prompt_tokens": 1}) == "generic"


def test_normalise_litellm_tool_use():
    rec = {"api_key": "abc", "api_key_alias": "bot", "model": "gpt-4o", "spend": 0.2, "startTime": "2025-01-01T00:00:00Z", "proxy_server_request": {"body": {"tools": [{"type": "function"}]}}, "response": {"choices": [{"finish_reason": "tool_calls"}]}, "metadata": {"user_agent": "langchain/0.3"}}
    ev = normalise(rec, "litellm")
    assert ev.caller_kind == "api-key" and ev.tools is True and ev.tool_calls is True and ev.user_agent == "langchain/0.3"


def test_parse_access_log_line():
    rec = parse_text_line('10.0.0.1 - - [10/Sep/2025:10:00:00 +0000] "POST /v1/chat/completions HTTP/1.1" 200 512 "-" "OpenAI/Python 1.5" host=api.openai.com')
    assert rec["request_uri"] == "/v1/chat/completions" and rec["http_user_agent"] == "OpenAI/Python 1.5" and rec["host"] == "api.openai.com"


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
