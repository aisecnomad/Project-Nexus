"""Regressions from the public-repository field review: precision and recall.

Each case mirrors code seen in popular public repositories: aiohttp clients
(discord.py) reported as MCP, UI components and call-center functions named
like agent SDK classes, duplicate manifest findings (crewAI-examples),
keyword-driven capabilities (the reference MCP servers) and provider tool
loops written with streaming, raw-response or helper calls.
"""

from __future__ import annotations

import glob

import pytest
import yaml

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.mcp_tools import mcp_tool_capabilities, mcp_tool_names
from shadowscan.models import Kind
from shadowscan.signatures.loader import signature_from_dict


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def _write(root, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _projects(findings):
    return [f for f in findings if f.resource_type == "project"]


# ------------------------------------------------------ ambiguous names
AIOHTTP = "import aiohttp\n\nasync def fetch(url):\n    async with aiohttp.ClientSession() as session:\n        async with session.get(url) as r:\n            return await r.text()\n"


@pytest.mark.parametrize("files", [
    {"client.py": AIOHTTP},
    {"client.py": AIOHTTP, "requirements.txt": "aiohttp==3.12.15\n"},
    {"client.py": "from aiohttp import ClientSession\n\nasync def go():\n    async with ClientSession() as s:\n        return s\n"},
    {"src/AgentCard.jsx": "export function AgentCard({ agent }) {\n  return <div>{agent.name}</div>;\n}\n",
     "package.json": '{"dependencies": {"react": "^18.3.1"}}'},
    {"routing.py": "def invoke_agent(agent_id, call):\n    return (agent_id, call)\n\ninvoke_agent('amy', 'call-1')\n"},
    {"skills.py": "class AgentSkill:\n    pass\n\ndef train(x):\n    return AgentSkill()\n"},
])
def test_common_identifiers_alone_are_not_ai_evidence(tmp_path, index, files):
    findings, _ = _run(index, _write(tmp_path, files))
    assert _projects(findings) == []


@pytest.mark.parametrize(("files", "signature"), [
    ({"client.py": "from mcp import ClientSession\nfrom mcp.client.stdio import stdio_client\n\n"
                   "async def main(params):\n    async with stdio_client(params) as (r, w):\n"
                   "        async with ClientSession(r, w) as session:\n            await session.initialize()\n"},
     "protocol.mcp"),
    ({"agent.py": "import boto3\n\nclient = boto3.client('bedrock-agent-runtime')\n"
                  "reply = client.invoke_agent(agentId='A', agentAliasId='B', sessionId='s', inputText='hi')\n"},
     "cloud.aws-bedrock-agents"),
    ({"card.py": "from a2a.types import AgentCard, AgentSkill\n\ncard = AgentCard(name='x', skills=[AgentSkill(id='s', name='s')])\n"},
     "protocol.a2a"),
])
def test_corroborated_identifiers_still_count(tmp_path, index, files, signature):
    findings, _ = _run(index, _write(tmp_path, files))
    assert any(signature in f.frameworks for f in _projects(findings))


def test_uncorroborated_lexical_evidence_is_capped_in_every_category(tmp_path, index):
    findings, _ = _run(index, _write(tmp_path, {"App.java": "class App { void run() { var c = new MCPClient(); } }\n"}))
    project = next(f for f in _projects(findings))
    assert "protocol.mcp" in project.frameworks and project.confidence <= 0.6
    _write(tmp_path, {"pom.xml": "<project><dependencies><dependency><groupId>io.modelcontextprotocol.sdk</groupId>"
                                 "<artifactId>mcp</artifactId><version>0.10.0</version></dependency></dependencies></project>"})
    findings, _ = _run(index, tmp_path)
    assert next(f for f in _projects(findings)).confidence > 0.6


def test_supporting_tools_alone_are_not_titled_as_an_llm_sdk(tmp_path, index):
    files = {"search.py": "from serpapi import GoogleSearch\n\ndef top(q, key):\n    return GoogleSearch({'q': q, 'api_key': key}).get_dict()\n",
             "requirements.txt": "google-search-results==2.4.2\n"}
    project = next(f for f in _projects(_run(index, _write(tmp_path, files))[0]))
    assert project.title.startswith("AI tooling in repository root: Web search")


def test_every_ambiguous_signal_can_be_corroborated():
    for path in glob.glob("shadowscan/signatures/data/**/*.yaml", recursive=True):
        with open(path, encoding="utf-8") as handle:
            documents = (yaml.safe_load(handle) or {}).get("signatures", [])
        for data in documents:
            signature = signature_from_dict(data, path)
            if any(signal.ambiguous for signal in signature.signals):
                assert any(signal.type in {"import", "dependency"} or signal.type == "code" and not signal.ambiguous
                           for signal in signature.signals), signature.id


@pytest.mark.parametrize("signal", [
    {"type": "code", "patterns": ["\\bX\\s*\\("], "ambiguous": "yes"},
    {"type": "domain", "values": ["example.com"], "ambiguous": True},
])
def test_ambiguous_is_a_boolean_on_code_signals_only(signal):
    with pytest.raises(ValueError):
        signature_from_dict({"id": "custom.sample", "name": "S", "category": "framework", "signals": [signal]})


# ------------------------------------------------ MCP paths on shared hosts
@pytest.mark.parametrize(("text", "expected"), [
    ('url = "https://api.githubcopilot.com/mcp/"', {"protocol.mcp"}),
    ("https://api.githubcopilot.com:443/mcp", {"protocol.mcp"}),
    ("x https://api.githubcopilot.com/chat/completions", {"coding-agent.github-copilot"}),
    ("https://mcp.notion.com/sse", {"protocol.mcp"}),
])
def test_mcp_endpoints_on_shared_hosts_are_decided_by_path(index, text, expected):
    assert {m.signature_id for m in index.match_domains_in_text(text)} == expected


def test_hosts_named_for_mcp_keep_every_match(index):
    assert "protocol.mcp" in {m.signature_id for m in index.match_domains_in_text("https://mcp.zapier.com/api/mcp/a")}


# ------------------------------------------------------ manifest folding
CREW = {
    "crews/research/pyproject.toml": '[project]\nname = "research"\ndependencies = ["crewai>=0.100"]\n',
    "crews/research/src/research/crew.py": "from crewai import Agent, Crew\n\nanalyst = Agent(role='a', goal='g', backstory='b')\ncrew = Crew(agents=[analyst], tasks=[])\n",
    "crews/research/src/research/config/agents.yaml": "analyst:\n  role: Analyst\n  goal: Analyse\n  backstory: Careful\n",
}


def test_manifest_inside_a_reported_project_is_folded_into_it(tmp_path, index):
    findings, _ = _run(index, _write(tmp_path, CREW))
    agents = [f for f in findings if f.kind == Kind.AGENT]
    assert len(agents) == 1 and agents[0].resource_type == "project"
    manifests = agents[0].metadata["manifests"]
    assert [m["path"] for m in manifests] == ["crews/research/src/research/config/agents.yaml"]
    assert manifests[0]["agents"][0]["name"] == "analyst"


def test_manifest_without_a_project_finding_stays_separate(tmp_path, index):
    findings, _ = _run(index, _write(tmp_path, {"config/agents.yaml": CREW["crews/research/src/research/config/agents.yaml"]}))
    assert [f.resource_type for f in findings] == ["agent-manifest"]


def test_manifest_makes_its_project_an_agent(tmp_path, index):
    files = {"pyproject.toml": '[project]\nname = "svc"\ndependencies = ["langgraph>=0.3", "openai>=1"]\n',
             "app.py": "from openai import OpenAI\nclient = OpenAI()\n",
             "langgraph.json": '{"graphs": {"agent": "./app.py:graph"}, "dependencies": ["."]}'}
    findings, _ = _run(index, _write(tmp_path, files))
    assert [(f.resource_type, f.kind) for f in findings] == [("project", Kind.AGENT)]
    assert findings[0].title.startswith("Agent in repository root")


# ------------------------------------------------------------ capabilities
def test_test_only_evidence_implies_no_capability(tmp_path, index):
    files = {"app.py": "from openai import OpenAI\nclient = OpenAI()\nprint(client.chat.completions.create(model='m', messages=[]))\n",
             "tests/run_test.py": "import subprocess\nfrom openai import OpenAI\n\ndef run(cmd):\n    OpenAI()\n    return subprocess.run(cmd, shell=True)\n"}
    project = next(f for f in _projects(_run(index, _write(tmp_path, files))[0]))
    assert "code-exec" not in project.capabilities
    assert any(e.location and e.location.startswith("tests/") for e in project.evidence)


def test_mcp_server_capabilities_come_from_registered_tools(tmp_path, index):
    files = {
        "fs/package.json": '{"dependencies": {"@modelcontextprotocol/sdk": "^1.17.0"}}',
        "fs/index.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
                       'const server = new McpServer({ name: "fs", version: "1" });\n'
                       'server.registerTool(\n  "write_file",\n  { description: "Write" },\n  async () => ({ content: [] }),\n);\n',
        "thinking/package.json": '{"dependencies": {"@modelcontextprotocol/sdk": "^1.17.0"}}',
        "thinking/index.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
                             'const server = new McpServer({ name: "t", version: "1" });\n'
                             'const schema = { thought: "string", nextThoughtNeeded: true };\n'
                             'server.registerTool("sequentialthinking", { description: "Think" }, async () => ({ content: [] }));\n',
    }
    found = {f.metadata["path"]: f for f in _projects(_run(index, _write(tmp_path, files))[0])}
    assert "data-access" in found["fs"].capabilities and found["fs"].metadata["mcp_tools"] == ["write_file"]
    assert "autonomous" not in found["thinking"].capabilities
    assert found["fs"].risk.score >= found["thinking"].risk.score


@pytest.mark.parametrize(("name", "expected"), [
    ("write_file", {"data-access"}), ("git_commit", {"data-access"}), ("fetch", {"browsing"}),
    ("create_entities", {"memory"}), ("run_command", {"code-exec"}), ("runPythonCode", {"code-exec"}),
    ("send_slack_message", {"saas-actions"}), ("sequentialthinking", set()), ("get_current_time", set()),
])
def test_tool_name_vocabulary(name, expected):
    assert mcp_tool_capabilities(name) == expected


def test_tool_names_are_read_from_common_registration_forms():
    python = (
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n@mcp.tool()\nasync def read_file(path: str):\n    ...\n\n"
        "@mcp.tool(name='run_query')\ndef q():\n    ...\n\nclass Tools(str, Enum):\n    STATUS = 'git_status'\n\n"
        "TOOLS = [Tool(name=Tools.STATUS, description='d'), Tool(name='fetch', description='d')]\n"
    )
    assert set(mcp_tool_names(python)) == {"read_file", "run_query", "git_status", "fetch"}
    assert mcp_tool_names("server.tool('echo', {}, fn)\nconst t = { name: 'add', description: 'Add' }\n") == ["echo", "add"]


# ------------------------------------------------------------- loop forms
LOOP = """import subprocess

import anthropic

client = anthropic.Anthropic()
tools = [{"name": "bash", "description": "Run", "input_schema": {"type": "object", "properties": {}}}]
messages = [{"role": "user", "content": "clean up"}]
{helper}
while True:
{request}
    messages.append({"role": "assistant", "content": resp.content})
    if resp.stop_reason != "tool_use":
        break
    results = []
    for block in resp.content:
        if block.type == "tool_use":
            out = subprocess.run(block.input["cmd"], shell=True, capture_output=True, text=True).stdout
            results.append({"type": "tool_result", "tool_use_id": block.id, "content": out})
{feedback}"""
FEEDBACK = '    messages.append({"role": "user", "content": results})\n'
REQUESTS = {
    "raw": ("", "    raw = client.beta.messages.with_raw_response.create(model='m', max_tokens=9, tools=tools, messages=messages)\n    resp = raw.parse()"),
    "stream": ("", "    with client.messages.stream(model='m', max_tokens=9, tools=tools, messages=messages) as stream:\n        resp = stream.get_final_message()"),
    "helper": ("\ndef call_model(history):\n    return client.messages.create(model='m', max_tokens=9, tools=tools, messages=history)\n\n",
               "    resp = call_model(messages)"),
}


def _loop_kind(index, tmp_path, form: str, feedback: str = FEEDBACK, **replace: str) -> Kind:
    helper, request = REQUESTS[form]
    source = LOOP.replace("{helper}", helper).replace("{request}", request).replace("{feedback}", feedback)
    for old, new in replace.items():
        source = source.replace(old, new)
    project = next(f for f in _projects(_run(index, _write(tmp_path, {"agent.py": source}))[0]))
    return project.kind


@pytest.mark.parametrize("form", sorted(REQUESTS))
def test_request_forms_with_tool_feedback_are_agents(index, tmp_path, form):
    assert _loop_kind(index, tmp_path, form) == Kind.AGENT


@pytest.mark.parametrize("form", sorted(REQUESTS))
def test_request_forms_without_tool_feedback_are_not_agents(index, tmp_path, form):
    assert _loop_kind(index, tmp_path, form, feedback="    print(results)\n") == Kind.FRAMEWORK_USAGE


def test_unused_stream_and_unparsed_raw_response_prove_nothing(index, tmp_path):
    assert _loop_kind(index, tmp_path, "stream", **{"resp = stream.get_final_message()": "resp = stream"}) == Kind.FRAMEWORK_USAGE
    assert _loop_kind(index, tmp_path, "raw", **{"resp = raw.parse()": "resp = raw"}) == Kind.FRAMEWORK_USAGE


def test_helper_must_pass_the_history_through(index, tmp_path):
    kind = _loop_kind(index, tmp_path, "helper", **{"messages=history)": "messages=[])"})
    assert kind == Kind.FRAMEWORK_USAGE
