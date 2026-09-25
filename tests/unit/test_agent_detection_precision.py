"""Regressions for differentiating model-directed tool dispatch from ordinary code."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.models import Kind

RESPONSES_LOOP = '''from openai import OpenAI
client = OpenAI()
TOOLS = {"lookup": lookup}
response = client.responses.create(model="gpt-4o", tools=TOOLS, input="query")
for item in response.output:
    if item.type == "function_call":
        result = TOOLS[item.name](item.arguments)
        response = client.responses.create(input=[{"type": "function_call_output", "call_id": item.call_id, "output": result}])
'''

RESPONSES_DIRECT = '''from openai import OpenAI
client = OpenAI()
response = client.responses.create(model="gpt-4o", tools=TOOLS, input="query")
calls = [item for item in response.output if item.type == "function_call"]
for item in calls:
    answer = lookup(item.arguments)
    conversation.append({"type": "function_call_output", "call_id": item.call_id, "output": answer})
'''


@pytest.mark.parametrize("source", [
    "def worker():\n    while True:\n        poll_queue()\n",
    "def worker():\n    while not done:\n        poll_queue()\n",
    "@tool\ndef serialize(obj):\n    return str(obj)\n",
    "@helpers.tool\ndef serialize(obj):\n    return str(obj)\n",
    "from langchain_core.tools import tool\n@tool\ndef lookup(query):\n    return query\n",
])
def test_generic_loops_and_decorators_are_not_agents(tmp_path: Path, run_connector, source: str):
    (tmp_path / "worker.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]
    if "langchain_core" not in source:
        assert not [finding for finding in findings if "framework.langchain" in finding.frameworks]


def test_responses_tool_dispatch_promotes_without_langchain(tmp_path: Path, run_connector):
    (tmp_path / "worker.py").write_text(RESPONSES_LOOP)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    agent = next(finding for finding in findings if finding.resource_type == "project")
    assert agent.kind == Kind.AGENT
    assert agent.metadata["agent_classification"] == "openai-responses-tool-dispatch"
    assert "provider.openai" in agent.model_providers
    assert "framework.langchain" not in agent.frameworks
    assert {
        "code:heuristic.function-call-branch",
        "code:heuristic.named-tool-lookup",
        "code:provider.openai",
    } <= {evidence.signal for evidence in agent.evidence}


def test_responses_direct_handler_result_promotes(tmp_path: Path, run_connector):
    (tmp_path / "worker.py").write_text(RESPONSES_DIRECT)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    agent = next(finding for finding in findings if finding.resource_type == "project")
    assert agent.kind == Kind.AGENT
    assert agent.metadata["agent_classification"] == "openai-responses-tool-dispatch"
    assert "code:heuristic.function-call-result" in {e.signal for e in agent.evidence}


@pytest.mark.parametrize("source", [
    RESPONSES_LOOP.replace('if item.type == "function_call":', 'if item.type == "message":'),
    RESPONSES_LOOP.replace('TOOLS[item.name]', 'TOOLS["lookup"]'),
    RESPONSES_LOOP.replace('TOOLS[item.name]', 'TOOLS[other.name]'),
    RESPONSES_LOOP.replace('TOOLS[item.name](item.arguments)', 'TOOLS[item.name]'),
    RESPONSES_LOOP.replace('client.responses.create', 'client.custom.create'),
    RESPONSES_DIRECT.replace('tools=TOOLS, ', ''),
    RESPONSES_DIRECT.replace('answer = lookup(item.arguments)', 'print(item.arguments)'),
    RESPONSES_DIRECT.replace('lookup(item.arguments)', 'lookup(other.arguments)'),
])
def test_partial_or_unrelated_responses_evidence_is_not_agent(tmp_path: Path, run_connector, source: str):
    (tmp_path / "worker.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]


def test_responses_evidence_must_share_a_source_file(tmp_path: Path, run_connector):
    (tmp_path / "request.py").write_text('from openai import OpenAI\nclient.responses.create(model="gpt-4o", tools=TOOLS)\n')
    (tmp_path / "parser.py").write_text('if item.type == "function_call":\n    result = TOOLS[item.name](item.arguments)\n')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]


@pytest.mark.parametrize("source", [
    RESPONSES_LOOP.replace('if item.type == "function_call":', 'if item.type == "message": # if item.type == "function_call":'),
    RESPONSES_LOOP.replace('result = TOOLS[item.name](item.arguments)', 'result = TOOLS["lookup"](item.arguments) # TOOLS[item.name]'),
    RESPONSES_DIRECT.replace('answer = lookup(item.arguments)', 'answer = "lookup(item.arguments)"'),
])
def test_comments_do_not_complete_dispatch_evidence(tmp_path: Path, run_connector, source: str):
    (tmp_path / "worker.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]


def test_typescript_responses_dispatch(tmp_path: Path, run_connector):
    (tmp_path / "worker.ts").write_text('''import OpenAI from "openai";
const client = new OpenAI();
const response = await client.responses.create({model: "gpt-4o", tools: TOOLS, input: "query"});
for (const item of response.output) {
  if (item.type === "function_call") {
    const result = TOOLS[item.name](item.arguments);
  }
}
''')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(finding.kind == Kind.AGENT and "provider.openai" in finding.model_providers for finding in findings)


def test_medium_gate_respects_agent_dispatch_and_ignores_plain_polling(tmp_path: Path):
    path = tmp_path / "worker.py"
    path.write_text("while True:\n    poll_queue()\n")
    argv = ["code", str(tmp_path), "--format", "json", "--fail-on", "medium"]
    clean = CliRunner().invoke(main, argv)
    assert clean.exit_code == 0, clean.output
    assert not json.loads(clean.stdout)["findings"]

    path.write_text(RESPONSES_LOOP)
    detected = CliRunner().invoke(main, argv)
    assert detected.exit_code == 2, detected.output
    assert any(finding["kind"] == "agent" for finding in json.loads(detected.stdout)["findings"])
