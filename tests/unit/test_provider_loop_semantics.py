"""Provider-loop classification needs connected source evidence, not keywords."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import provider_loops
from shadowscan.models import Kind

LOOP = '''from openai import OpenAI
import json
client = OpenAI()
messages = [{"role": "user", "content": "Resolve pending tickets"}]
while True:
    response = client.chat.completions.create(
        model="example-model", messages=messages,
        tools=[{"type": "function", "function": {"name": "resolve_ticket"}}],
    )
    message = response.choices[0].message
    if not message.tool_calls:
        break
    messages.append(message)
    for call in message.tool_calls:
        result = resolve_ticket(**json.loads(call.function.arguments))
        messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
'''


ANTHROPIC_LOOP = '''import anthropic
import subprocess
client = anthropic.Anthropic()
tools = [{"name": "bash", "description": "Run a shell command", "input_schema": {"type": "object"}}]
messages = [{"role": "user", "content": "Clean up disk space"}]
while True:
    response = client.messages.create(model="example-model", max_tokens=1024, tools=tools, messages=messages)
    if response.stop_reason != "tool_use":
        break
    messages.append({"role": "assistant", "content": response.content})
    for block in response.content:
        if block.type == "tool_use":
            output = subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout
            messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": block.id, "content": output}]})
'''

COLLECTED_RESULTS = '''    results = []
    for block in response.content:
        if block.type == "tool_use":
            output = bash(**block.input)
            results.append({"type": "tool_result", "tool_use_id": block.id, "content": output})
    messages.append({"role": "user", "content": results})
'''


def scan(tmp_path, run_connector, source=LOOP):
    (tmp_path / "app.py").write_text(source)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)


@pytest.mark.parametrize("source", [
    LOOP,
    LOOP.replace("from openai import OpenAI", "from openai import OpenAI as Client").replace("client = OpenAI()", "client = Client()"),
    LOOP.replace("from openai import OpenAI", "import openai as sdk").replace("client = OpenAI()", "client = sdk.OpenAI()"),
    LOOP.replace("while True:", "for turn in range(5):"),
    LOOP.replace("    message = response.choices[0].message", "    selected = response\n    message = selected.choices[0].message"),
    LOOP.replace("        result = resolve_ticket(**json.loads(call.function.arguments))", "        arguments = json.loads(call.function.arguments)\n        result = resolve_ticket(**arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "functions[call.function.name](**json.loads(call.function.arguments))"),
    LOOP.replace("        result = resolve_ticket(**json.loads(call.function.arguments))", "        handler = functions[call.function.name]\n        result = handler(**json.loads(call.function.arguments))"),
    LOOP.replace("        messages.append({", "        payload = json.dumps(result)\n        messages.append({").replace('"content": json.dumps(result)', '"content": payload'),
    LOOP.replace("OpenAI", "AzureOpenAI"),
    LOOP.replace("client = OpenAI()", "client = OpenAI()\ndef run():\n" + "\n".join("    " + line for line in LOOP.splitlines()[3:])).split("\nmessages =", 1)[0] + "\n",
])
def test_connected_provider_tool_loop_is_an_agent(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    assert "protocol.openai-function-calling" in agents[0].frameworks
    assert {"tool-use", "autonomous"} <= set(agents[0].capabilities)
    assert any("conversation feedback" in evidence.description for evidence in agents[0].evidence)


@pytest.mark.parametrize("source", [
    LOOP.replace("from openai import OpenAI", "from local_client import OpenAI"),
    LOOP.replace("client = OpenAI()", "client = OpenAI()\nclient = local_client"),
    LOOP.replace("while True:", "while False:"),
    LOOP.replace("while True:", "for turn in []:"),
    LOOP.replace("    message = response.choices[0].message", "    message = canned_response.choices[0].message"),
    LOOP.replace("    message = response.choices[0].message", "    response = canned_response\n    message = response.choices[0].message"),
    LOOP.replace("for call in message.tool_calls:", "for call in saved_calls:"),
    LOOP.replace("        result = resolve_ticket(**json.loads(call.function.arguments))", "        call = saved_call\n        result = resolve_ticket(**json.loads(call.function.arguments))"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "resolve_ticket(ticket='fixed')"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "print(call.function.arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "json.loads(call.function.arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "logger.info(call.function.arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "bool(call.function.arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "json.JSONDecoder().decode(call.function.arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "any(call.function.arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "transform(call.function.arguments)"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "functions['fixed'](**json.loads(call.function.arguments))"),
    LOOP.replace("resolve_ticket(**json.loads(call.function.arguments))", "functions[unrelated.name](**json.loads(call.function.arguments))"),
    LOOP.replace("        result = resolve_ticket(**json.loads(call.function.arguments))", "        handler = functions[call.function.name]\n        handler = unrelated_handler\n        result = handler(**json.loads(call.function.arguments))"),
    LOOP.replace('"name": "resolve_ticket"', '"name": "different_tool"'),
    LOOP.replace('"content": json.dumps(result)', '"content": "static result"'),
    LOOP.replace('"tool_call_id": call.id', '"tool_call_id": "unrelated"'),
    LOOP.replace('"role": "tool"', '"role": "user"'),
    LOOP.replace("        messages.append({", "        unrelated.append({"),
    LOOP.replace("    message = response.choices[0].message", "    messages = []\n    message = response.choices[0].message"),
    LOOP.replace("while True:\n", "while True:\n    messages = []\n"),
    LOOP.replace("    message = response.choices[0].message", "    messages.clear()\n    message = response.choices[0].message"),
    LOOP.replace('tools=[{"type": "function", "function": {"name": "resolve_ticket"}}]', "tools=[]"),
    LOOP.replace('tools=[{"type": "function", "function": {"name": "resolve_ticket"}}]', "tools=None"),
    LOOP.replace("        messages.append({", "        result = 'not dispatched'\n        messages.append({"),
    LOOP.replace("        result = resolve_ticket(**json.loads(call.function.arguments))", "        result = lambda: resolve_ticket(**json.loads(call.function.arguments))"),
    LOOP.replace("        result = resolve_ticket(**json.loads(call.function.arguments))", "        def unused():\n            result = resolve_ticket(**json.loads(call.function.arguments))"),
    LOOP.replace("    message = response.choices[0].message", "    break\n    message = response.choices[0].message"),
    LOOP.replace("        result = resolve_ticket(**json.loads(call.function.arguments))", "        continue\n        result = resolve_ticket(**json.loads(call.function.arguments))"),
    'from openai import OpenAI\nexample = ' + repr(LOOP) + '\n',
    "from openai import OpenAI\n" + "\n".join("# " + line for line in LOOP.splitlines()),
])
def test_disconnected_or_inert_tool_code_is_not_an_agent(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


@pytest.mark.parametrize("source", [
    ANTHROPIC_LOOP,
    ANTHROPIC_LOOP.replace("import anthropic\n", "from anthropic import Anthropic\n").replace("anthropic.Anthropic()", "Anthropic()"),
    ANTHROPIC_LOOP.replace("import subprocess\n", "import subprocess as sp\n").replace("subprocess.run(", "sp.run("),
    ANTHROPIC_LOOP.replace("import subprocess\n", "from subprocess import check_output\n")
    .replace('subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout', 'check_output(block.input["command"], shell=True)'),
    ANTHROPIC_LOOP.replace('subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout', "bash(**block.input)"),
    ANTHROPIC_LOOP.replace('subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout', "handlers[block.name](**block.input)"),
    ANTHROPIC_LOOP.split("    for block in response.content:")[0] + COLLECTED_RESULTS,
    ANTHROPIC_LOOP.split("    for block in response.content:")[0]
    + '    if response.stop_reason == "tool_use":\n' + "".join("    " + line + "\n" for line in COLLECTED_RESULTS.splitlines()),
])
def test_connected_anthropic_tool_loop_is_an_agent(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    assert "provider.anthropic" in agents[0].model_providers
    assert {"tool-use", "autonomous"} <= set(agents[0].capabilities)
    assert any("conversation feedback" in evidence.description for evidence in agents[0].evidence)


@pytest.mark.parametrize("source", [
    ANTHROPIC_LOOP.replace('            messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": block.id, "content": output}]})\n', "            print(output)\n"),
    ANTHROPIC_LOOP.replace('"content": output}', '"content": "done"}'),
    ANTHROPIC_LOOP.replace('"tool_use_id": block.id', '"tool_use_id": "unrelated"'),
    ANTHROPIC_LOOP.replace('subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout', "log(block.input)"),
    ANTHROPIC_LOOP.replace('subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout', 'subprocess.run("ls", shell=True).stdout'),
    ANTHROPIC_LOOP.replace("import subprocess\n", "subprocess = fake_shell()\n"),
    ANTHROPIC_LOOP.replace('subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout', "bash(**block.input)")
    .replace("tools=tools", "tools=load_tools()"),
    ANTHROPIC_LOOP.replace('subprocess.run(block.input["command"], shell=True, capture_output=True, text=True).stdout', "bash(**block.input)")
    .replace("while True:\n", "tools = other_tools\nwhile True:\n"),
    ANTHROPIC_LOOP.split("    for block in response.content:")[0] + COLLECTED_RESULTS.replace("    messages.append(", "    other.append("),
    ANTHROPIC_LOOP.split("    for block in response.content:")[0] + COLLECTED_RESULTS.replace("    messages.append(", "    results = []\n    messages.append("),
    ANTHROPIC_LOOP.replace("    for block in response.content:", "    for block in saved_blocks:"),
    ANTHROPIC_LOOP.replace("while True:", "while False:"),
])
def test_disconnected_or_inert_anthropic_tool_code_is_not_an_agent(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


def test_local_provider_module_cannot_establish_a_tool_loop(tmp_path, run_connector):
    (tmp_path / "openai.py").write_text("raise RuntimeError('local source must never execute')\n")
    findings, ctx = scan(tmp_path, run_connector)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)
    assert not any(evidence.signal == "import:provider.openai" for finding in findings for evidence in finding.evidence)


def test_loop_budget_exhaustion_is_explicit(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(provider_loops, "MAX_FLOW_STEPS", 3)
    findings, ctx = scan(tmp_path, run_connector)
    assert ctx.stats.incomplete
    assert any("MatchTimeoutError" in error for error in ctx.stats.errors)
    assert not any(finding.kind == Kind.AGENT for finding in findings)


@pytest.mark.parametrize("local_path", ["agents.py", "agents/__init__.py", "src/agents/__init__.py"])
@pytest.mark.parametrize("source", [
    'from agents import Agent\nworker = Agent(name="queue worker")\n',
    'from agents import Agent as Worker\nworker = Worker(name="queue worker")\n',
    'import agents\nworker = agents.Agent(name="queue worker")\n',
])
def test_local_agents_sources_do_not_claim_the_external_sdk(tmp_path, run_connector, local_path, source):
    local = tmp_path / local_path
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text("class Agent:\n    def __init__(self, name):\n        self.name = name\n")
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)
    assert not any("framework.openai-agents-sdk" in finding.frameworks for finding in findings)
