"""A Responses call is an agent signal only with reachable, linked tool feedback."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import responses_loops
from shadowscan.models import Kind

DIRECT = '''import json
from openai import OpenAI as Client
client = Client()

def run(question):
    messages = [{"role": "user", "content": question}]
    for turn in range(5):
        response = client.responses.create(model="gpt-4o", input=messages, tools=definitions)
        messages.extend(response.output)
        for item in response.output:
            if item.type != "function_call":
                continue
            handler = FUNCTIONS[item.name]
            result = handler(**json.loads(item.arguments))
            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
        if response.output_text:
            return response.output_text
'''

FILTERED = '''import json
from openai import OpenAI
client = OpenAI()
tools = [{"type": "function", "name": "lookup", "parameters": {"type": "object"}}]
def lookup(args):
    return json.dumps({"answer": args})

def run(question):
    messages = [{"role": "user", "content": question}]
    for turn in range(5):
        response = client.responses.create(model="gpt-4o", input=messages, tools=tools)
        calls = [item for item in response.output if item.type == "function_call"]
        if not calls:
            return response.output_text
        for call in calls:
            result = lookup(call.arguments)
            output = {"type": "function_call_output", "call_id": call.call_id, "output": result}
            messages.extend([call, output])
'''


def scan(tmp_path, run_connector, source=DIRECT):
    (tmp_path / "app.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    return findings, ctx


@pytest.mark.parametrize("source", [
    DIRECT,
    FILTERED,
    DIRECT.replace("from openai import OpenAI as Client", "import openai as sdk")
    .replace("client = Client()", "client = sdk.OpenAI()"),
    DIRECT.replace("from openai import OpenAI as Client", "from openai import AsyncOpenAI as Client")
    .replace("def run(question):", "async def run(question):")
    .replace("response = client.responses.create", "response = await client.responses.create"),
    DIRECT.replace("for turn in range(5):", "while True:"),
])
def test_connected_responses_tool_loop_is_one_agent(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    assert "protocol.openai-function-calling" in agents[0].frameworks
    assert {"tool-use", "autonomous"} <= set(agents[0].capabilities)
    assert sum("Responses function dispatch" in evidence.description for evidence in agents[0].evidence) == 1


def test_forwarding_current_call_before_output_establishes_context(tmp_path, run_connector):
    source = DIRECT.replace("        messages.extend(response.output)\n", "")
    source = source.replace("            messages.append({", "            messages.append(item)\n            messages.append({")
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert len([finding for finding in findings if finding.kind == Kind.AGENT]) == 1


@pytest.mark.parametrize("source", [
    DIRECT.replace("for turn in range(5):", "if True:"),
    DIRECT.replace("for turn in range(5):", "for turn in range(1):"),
    DIRECT.replace("for turn in range(5):", "for turn in range(0):"),
    DIRECT.replace('item.type != "function_call"', 'item.type != "message"'),
    DIRECT.replace("handler = FUNCTIONS[item.name]", "handler = FUNCTIONS['fixed']"),
    DIRECT.replace("handler(**json.loads(item.arguments))", "handler('fixed')"),
    DIRECT.replace("        messages.extend(response.output)\n", ""),
    FILTERED.replace("messages.extend([call, output])", "messages.extend([output])"),
    DIRECT.replace("        for item in response.output:", "        response = cached_response\n        for item in response.output:"),
    DIRECT.replace('"call_id": item.call_id', '"call_id": "fixed"'),
    DIRECT.replace("messages.append({", "audit.append({"),
    DIRECT.replace("        if response.output_text:\n", "        messages = []\n        if response.output_text:\n"),
    DIRECT.replace("        if response.output_text:\n", "        messages.clear()\n        if response.output_text:\n"),
    DIRECT.replace("        if response.output_text:\n", "        messages.pop()\n        if response.output_text:\n"),
    DIRECT.replace("        if response.output_text:\n", "        messages[:] = []\n        if response.output_text:\n"),
    DIRECT.replace('        response = client.responses.create', '        if True:\n            return\n        response = client.responses.create'),
    DIRECT.replace("        if response.output_text:\n", "        if True:\n            return\n        if response.output_text:\n"),
    DIRECT.replace('        if response.output_text:\n',
                   '        if condition:\n            return\n        if response.output_text:\n')
    .replace('            handler = FUNCTIONS[item.name]', '            if condition:\n                handler = FUNCTIONS[item.name]'),
    DIRECT.replace("            result = handler(**json.loads(item.arguments))\n"
                   '            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})',
                   '            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})\n'
                   "            result = handler(**json.loads(item.arguments))"),
    DIRECT.replace("            result = handler(**json.loads(item.arguments))\n"
                   '            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})',
                   '            if condition:\n                result = handler(**json.loads(item.arguments))\n'
                   '            if not condition:\n                messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})'),
    FILTERED.replace('item.type == "function_call"', 'item.type == "message"'),
    FILTERED.replace("lookup(call.arguments)", "lookup('fixed')"),
    FILTERED.replace("        for call in calls:", "        calls = cached_calls\n        for call in calls:"),
])
def test_disconnected_responses_evidence_stays_supporting(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert findings and not any(finding.kind == Kind.AGENT for finding in findings)


def test_local_provider_module_cannot_establish_responses_loop(tmp_path, run_connector):
    (tmp_path / "openai.py").write_text("raise RuntimeError('must not execute')\n")
    findings, ctx = scan(tmp_path, run_connector)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


def test_chat_and_responses_loops_share_one_project_finding(tmp_path, run_connector):
    chat = '''from openai import OpenAI
import json
client = OpenAI()
messages = []
while True:
    response = client.chat.completions.create(
        model="example", messages=messages,
        tools=[{"type": "function", "function": {"name": "lookup"}}],
    )
    message = response.choices[0].message
    for call in message.tool_calls:
        result = lookup(**json.loads(call.function.arguments))
        messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
'''
    findings, ctx = scan(tmp_path, run_connector, chat + "\n" + FILTERED)
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    descriptions = {evidence.description for evidence in agents[0].evidence}
    assert any("conversation feedback" in description for description in descriptions)
    assert any("Responses function dispatch" in description for description in descriptions)


def test_budget_exhaustion_marks_scan_incomplete(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(responses_loops, "MAX_FLOW_STEPS", 3)
    findings, ctx = scan(tmp_path, run_connector)
    assert ctx.stats.incomplete
    assert any("MatchTimeoutError" in message for message in ctx.stats.errors)
    assert not any(finding.kind == Kind.AGENT for finding in findings)
