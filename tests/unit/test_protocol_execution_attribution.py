"""Model-selected dispatch proves tool authority; neighboring cleanup does not."""

from __future__ import annotations

import ast

import pytest

from shadowscan.connectors.code.provider_loops import provider_tool_loop_lines
from shadowscan.connectors.code.responses_loops import responses_dispatch_lines, responses_tool_loop_lines
from shadowscan.models import Kind
from shadowscan.risk import assess

RESPONSES = """from openai import OpenAI
import subprocess
client = OpenAI()
def lookup(arguments):
    return arguments
messages = []
while True:
    response = client.responses.create(model="example", input=messages,
        tools=[{"type": "function", "name": "lookup", "parameters": {"type": "object"}}])
    messages.extend(response.output)
    for item in response.output:
        if item.type != "function_call":
            continue
        result = lookup(item.arguments)
        messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
"""

CHAT = """from openai import OpenAI
import subprocess
client = OpenAI()
def lookup(arguments):
    return arguments
messages = []
while True:
    response = client.chat.completions.create(model="example", messages=messages,
        tools=[{"type": "function", "function": {"name": "lookup"}}])
    message = response.choices[0].message
    messages.append(message)
    for call in message.tool_calls:
        result = lookup(call.function.arguments)
        messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
"""

ANTHROPIC = """import anthropic
import subprocess
client = anthropic.Anthropic()
def lookup(arguments):
    return arguments
messages = []
while True:
    response = client.messages.create(model="example", max_tokens=1024, messages=messages,
        tools=[{"name": "lookup", "input_schema": {"type": "object"}}])
    messages.append({"role": "assistant", "content": response.content})
    for block in response.content:
        if block.type == "tool_use":
            result = lookup(block.input)
            messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": block.id, "content": result}]})
"""

SINGLE = """from openai import OpenAI
import subprocess
client = OpenAI()
def shell(arguments):
    return subprocess.check_output(arguments, shell=True).decode()
messages = []
response = client.responses.create(model="example", input=messages,
    tools=[{"type": "function", "name": "shell", "parameters": {"type": "object"}}])
for item in response.output:
    if item.type == "function_call":
        result = shell(item.arguments)
        messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
"""


def _project(tmp_path, run_connector, source):
    (tmp_path / "app.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(finding for finding in findings if finding.resource_type == "project")


@pytest.mark.parametrize("source", [RESPONSES, CHAT, ANTHROPIC])
def test_inline_turn_cleanup_has_no_registered_execution_authority(tmp_path, run_connector, source):
    before = _project(tmp_path, run_connector, source)
    with_cleanup = source.replace(
        "    response =", '    subprocess.run("cleanup", shell=True)\n    response ='
    )
    after = _project(tmp_path, run_connector, with_cleanup)
    assert before.kind == after.kind == Kind.AGENT
    assert set(after.capabilities) == set(before.capabilities) == {"tool-use", "autonomous"}
    assert after.confidence == before.confidence
    assert assess(after).score == assess(before).score
    assert "code-exec" in after.metadata["contextual_capabilities"]


def test_standalone_responses_local_dispatch_retains_execution_body(tmp_path, run_connector):
    finding = _project(tmp_path, run_connector, SINGLE)
    assert finding.kind == Kind.AGENT
    assert set(finding.capabilities) == {"tool-use", "code-exec"}


@pytest.mark.parametrize("source", [RESPONSES, CHAT, ANTHROPIC])
def test_iterative_selected_local_handler_retains_execution_body(tmp_path, run_connector, source):
    source = source.replace("    return arguments", "    return subprocess.run(arguments, shell=True)")
    finding = _project(tmp_path, run_connector, source)
    assert finding.kind == Kind.AGENT
    assert {"tool-use", "autonomous", "code-exec"} <= set(finding.capabilities)


@pytest.mark.parametrize(
    ("source", "recognizer"),
    [
        (RESPONSES, responses_tool_loop_lines),
        (CHAT, provider_tool_loop_lines),
        (ANTHROPIC, provider_tool_loop_lines),
        (SINGLE, responses_dispatch_lines),
    ],
)
def test_protocol_seed_is_selected_call_instead_of_enclosing_loop(source, recognizer):
    source = source.replace("    response =", '    subprocess.run("cleanup", shell=True)\n    response =')
    tree = ast.parse(source)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    requests = {id(call) for call in calls if ast.unparse(call.func).endswith(".create")}
    dispatch_calls: set[int] = set()
    assert recognizer(tree, requests, dispatch_calls=dispatch_calls)
    assert {ast.unparse(call.func) for call in calls if id(call) in dispatch_calls} == (
        {"shell"} if source == SINGLE else {"lookup"}
    )
