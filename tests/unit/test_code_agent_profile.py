"""Code findings say what they describe for policy (``agent_type``) and whether it is agentic.

The benchmark showed agents reported under non-agent kinds (an MCP server as
"LLM usage", a Bedrock agent as plain infrastructure) and coding-assistant
instruction files counted as agents. Each finding now carries an explicit,
machine-readable summary, and generic credentials outside AI projects are
not reported as LLM provider credentials.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.models import Kind

MCP_SERVER = """\
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("bookings")


@mcp.tool()
def create_booking(name: str) -> str:
    return name


@mcp.tool()
def list_bookings() -> list[str]:
    return []
"""

MCP_CLIENT = """\
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({"math": {"command": "python", "args": ["math_server.py"], "transport": "stdio"}})
"""

CI_AGENT = """\
on: issue_comment
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
"""

BEDROCK_AGENT = """\
resource "aws_bedrockagent_agent" "support" {
  agent_name              = "support"
  foundation_model        = "anthropic.claude-3-haiku-20240307-v1:0"
  agent_resource_role_arn = aws_iam_role.agent.arn
}
"""

GENERIC_CREDENTIAL = 'DB_PASSWORD = "pR7xL2qN9vB4mK8sT3wZ"\n'


def _scan(tmp_path: Path, run_connector, files: dict[str, str]) -> tuple[list, object]:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False)


def _profiles(findings: list) -> set[tuple[str, str, bool]]:
    return {(f.kind.value, f.metadata["agent_type"], f.metadata["agentic"]) for f in findings}


def test_source_registering_mcp_tools_is_an_mcp_server(tmp_path: Path, run_connector) -> None:
    findings, ctx = _scan(tmp_path, run_connector, {"requirements.txt": "mcp\n", "server.py": MCP_SERVER})
    assert not ctx.stats.errors
    (server,) = [f for f in findings if f.resource_type == "project"]
    assert server.kind == Kind.MCP_SERVER
    assert (server.metadata["agent_type"], server.metadata["agentic"]) == ("mcp-server", True)
    assert server.metadata["mcp_tools"] == ["create_booking", "list_bookings"]
    assert server.title == (
        "MCP server in repository root: Model Context Protocol (MCP) (2 tools: create_booking, list_bookings)"
    )


def test_mcp_client_code_is_an_agent_host(tmp_path: Path, run_connector) -> None:
    findings, _ = _scan(
        tmp_path, run_connector, {"requirements.txt": "langchain-mcp-adapters\n", "client.py": MCP_CLIENT}
    )
    (project,) = [f for f in findings if f.resource_type == "project"]
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert (project.metadata["agent_type"], project.metadata["agentic"]) == ("mcp-client", True)


def test_mcp_client_code_in_tests_alone_is_not_an_agent_host(tmp_path: Path, run_connector) -> None:
    findings, _ = _scan(
        tmp_path,
        run_connector,
        {"requirements.txt": "langchain-mcp-adapters\n", "tests/test_client.py": MCP_CLIENT},
    )
    assert all(f.metadata["agentic"] is False for f in findings)


def test_plain_llm_call_is_an_integration_not_an_agent(tmp_path: Path, run_connector) -> None:
    source = 'from openai import OpenAI\n\nOpenAI().chat.completions.create(model="gpt-4o", messages=[])\n'
    findings, _ = _scan(tmp_path, run_connector, {"requirements.txt": "openai\n", "app.py": source})
    assert ("framework-usage", "llm-integration", False) in _profiles(findings)


def test_framework_agent_is_agentic(tmp_path: Path, run_connector) -> None:
    source = 'from crewai import Agent\n\nagent = Agent(role="writer", goal="draft", backstory="b")\n'
    findings, _ = _scan(tmp_path, run_connector, {"requirements.txt": "crewai\n", "crew.py": source})
    assert ("agent", "framework-agent", True) in _profiles(findings)


def test_hand_written_tool_loop_is_not_a_framework_agent(tmp_path: Path, run_connector) -> None:
    source = """\
import json
from openai import OpenAI

client = OpenAI()
tools = [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}]
messages = [{"role": "user", "content": "find the order"}]
while True:
    response = client.chat.completions.create(model="gpt-4o", messages=messages, tools=tools)
    message = response.choices[0].message
    if not message.tool_calls:
        break
    for call in message.tool_calls:
        result = lookup(**json.loads(call.function.arguments))
        messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
"""
    findings, _ = _scan(tmp_path, run_connector, {"agent.py": source})
    assert ("agent", "tool-loop", True) in _profiles(findings)


def test_coding_assistant_instructions_are_not_agentic(tmp_path: Path, run_connector) -> None:
    findings, _ = _scan(
        tmp_path,
        run_connector,
        {"CLAUDE.md": "Run the tests before committing.\n", ".cursorrules": "Prefer small functions.\n"},
    )
    assert findings
    assert {(kind, agentic) for kind, _, agentic in _profiles(findings)} == {("agent-config", False)}
    assert {f.metadata["agent_type"] for f in findings} == {"coding-assistant-config"}


def test_coding_agent_run_by_ci_is_agentic(tmp_path: Path, run_connector) -> None:
    findings, _ = _scan(
        tmp_path,
        run_connector,
        {".github/workflows/claude.yml": CI_AGENT, "CLAUDE.md": "Run the tests before committing.\n"},
    )
    assert ("agent-config", "ci-agent", True) in _profiles(findings)


def test_mcp_client_configuration_is_agentic(tmp_path: Path, run_connector) -> None:
    config = {
        "mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}
    }
    findings, _ = _scan(tmp_path, run_connector, {".mcp.json": json.dumps(config)})
    assert ("mcp-server", "mcp-client-config", True) in _profiles(findings)


def test_agent_infrastructure_is_agentic(tmp_path: Path, run_connector) -> None:
    findings, _ = _scan(tmp_path, run_connector, {"main.tf": BEDROCK_AGENT})
    assert ("infra", "agent-infrastructure", True) in _profiles(findings)


def test_generic_credential_outside_ai_projects_is_not_reported(tmp_path: Path, run_connector) -> None:
    findings, ctx = _scan(tmp_path, run_connector, {"settings.py": GENERIC_CREDENTIAL})
    assert findings == []
    assert not ctx.stats.incomplete
    # Never silent: a note names the file, never the value.
    (note,) = ctx.stats.warnings
    assert "settings.py" in note and "pR7xL2qN9vB4mK8sT3wZ" not in note


def test_generic_credentials_can_be_reported_everywhere(tmp_path: Path, run_connector) -> None:
    (tmp_path / "settings.py").write_text(GENERIC_CREDENTIAL)
    findings, _ = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, report_generic_credentials=True
    )
    assert [f.title for f in findings] == ["Hard-coded credential in settings.py"]


def test_generic_credential_in_another_projects_ai_use_is_not_reported(tmp_path: Path, run_connector) -> None:
    source = 'from crewai import Agent\n\nagent = Agent(role="writer", goal="draft", backstory="b")\n'
    findings, _ = _scan(
        tmp_path,
        run_connector,
        {
            "agent/requirements.txt": "crewai\n",
            "agent/crew.py": source,
            "billing/package.json": '{"name": "billing"}\n',
            "billing/settings.py": GENERIC_CREDENTIAL,
        },
    )
    assert findings
    assert not [f for f in findings if f.kind == Kind.SECRET]


def test_generic_credential_in_an_ai_project_is_reported_as_what_it_is(tmp_path: Path, run_connector) -> None:
    source = 'from crewai import Agent\n\nagent = Agent(role="writer", goal="draft", backstory="b")\n'
    findings, _ = _scan(
        tmp_path,
        run_connector,
        {"requirements.txt": "crewai\n", "crew.py": source, "settings.py": GENERIC_CREDENTIAL},
    )
    (secret,) = [f for f in findings if f.kind == Kind.SECRET]
    assert secret.title == "Hard-coded credential in settings.py"
    assert (secret.metadata["agent_type"], secret.metadata["agentic"]) == ("credential", False)


@pytest.mark.parametrize("project", ["", "service/"])
def test_provider_key_is_reported_wherever_it_is(tmp_path: Path, run_connector, project: str) -> None:
    key = "sk-ant-api03-" + "Zx9Kq2Lm7Np4Rt8Vw3Ys6Bc1Df5Gh0Jk" * 2 + "-AbCdEfGhAA"
    findings, _ = _scan(tmp_path, run_connector, {f"{project}config.py": f'ANTHROPIC_API_KEY = "{key}"\n'})
    secrets = [f for f in findings if f.kind == Kind.SECRET]
    assert [f.title for f in secrets] == [f"LLM provider credential in {project}config.py"]


def test_cyclonedx_carries_the_agent_profile(tmp_path: Path, run_connector) -> None:
    from shadowscan.models import ScanResult
    from shadowscan.reporters.cyclonedx import render_cyclonedx

    findings, _ = _scan(tmp_path, run_connector, {"requirements.txt": "mcp\n", "server.py": MCP_SERVER})
    bom = json.loads(render_cyclonedx(ScanResult(findings=findings)))
    properties = [
        {p["name"]: p["value"] for p in item.get("properties", [])}
        for item in bom.get("services", []) + bom.get("components", [])
    ]
    assert any(
        p.get("shadowscan:agent-type") == "mcp-server" and p.get("shadowscan:agentic") == "true"
        for p in properties
    )
