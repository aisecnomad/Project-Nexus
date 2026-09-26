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

SINGLE_DISPATCH = '''from openai import OpenAI
client = OpenAI()
response = client.responses.create(model="example", input="question", tools=tools)
for item in response.output:
    if item.type == "function_call":
        result = handlers[item.name](item.arguments)
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
    DIRECT.replace("        messages.extend(response.output)", "        if condition:\n            break\n        messages.extend(response.output)")
    .replace("            handler = FUNCTIONS[item.name]", "            if condition:\n                continue\n            handler = FUNCTIONS[item.name]"),
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
    DIRECT.replace("            handler = FUNCTIONS[item.name]", "            item = cached_call\n            handler = FUNCTIONS[item.name]"),
    FILTERED.replace("            result = lookup(call.arguments)", "            call = cached_call\n            result = lookup(call.arguments)"),
    FILTERED.replace("messages.extend([call, output])", "messages.extend([output, call])"),
    DIRECT.replace("        messages.extend(response.output)", "        break\n        messages.extend(response.output)"),
    DIRECT.replace("        messages.extend(response.output)", "        continue\n        messages.extend(response.output)"),
    DIRECT.replace("        messages.extend(response.output)", "        if condition:\n            break\n        messages.extend(response.output)")
    .replace("            handler = FUNCTIONS[item.name]", "            if not condition:\n                continue\n            handler = FUNCTIONS[item.name]"),
    DIRECT.replace("            handler = FUNCTIONS[item.name]", "            item.arguments = cached_arguments\n            handler = FUNCTIONS[item.name]"),
    FILTERED.replace("            result = lookup(call.arguments)", "            lookup = unrelated_function\n            result = lookup(call.arguments)"),
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
    FILTERED.replace('if item.type == "function_call"]', 'if item.type == "function_call" if False]'),
    FILTERED.replace('if item.type == "function_call"]', 'if item.type == "function_call" if item.type == "message"]'),
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


@pytest.mark.parametrize("source", [
    # A local API sharing provider method names supplies no model provenance.
    '''class Responses:
    def create(self):
        return []
responses = Responses()
events = responses.create()
for item in events:
    if item.type == "function_call":
        handlers[item.name](item.arguments)
''',
    # A genuine text request cannot lend provenance to a separate dispatcher.
    '''from openai import OpenAI
client = OpenAI()
def summarize(text):
    return client.responses.create(model="example", input=text)
def dispatch(events):
    for item in events:
        if item.type == "function_call":
            handlers[item.name](item.arguments)
''',
    # Matching dispatch text in an empty loop is never executable evidence.
    '''from openai import OpenAI
client = OpenAI()
response = client.responses.create(model="example", input="hello")
for item in []:
    if item.type == "function_call":
        handlers[item.name](item.arguments)
''',
])
def test_lexical_responses_fragments_cannot_override_semantics(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert findings  # Supporting observations remain available to analysts.
    assert all(finding.kind == Kind.FRAMEWORK_USAGE for finding in findings)
    assert all(finding.metadata["agent_indicators"] == 0 for finding in findings)


@pytest.mark.parametrize("include_tests", [False, True])
def test_responses_dispatch_respects_test_only_policy(tmp_path, run_connector, include_tests):
    # The single action is connected and also matches the obsolete lexical
    # fallback; only the explicit include_tests setting may make it decisive.
    (tmp_path / "test_agent.py").write_text(SINGLE_DISPATCH)
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False,
        include_tests=include_tests,
    )
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert len(findings) == 1
    assert (findings[0].kind == Kind.AGENT) is include_tests
    assert ("test-code-only" in findings[0].tags) is not include_tests


@pytest.mark.parametrize("source", [
    SINGLE_DISPATCH.replace("for item in response.output:", "for item in cached.output:"),
    SINGLE_DISPATCH.replace("for item in response.output:", "response = cached\nfor item in response.output:"),
    SINGLE_DISPATCH.replace("for item in response.output:", "for item in []:"),
    SINGLE_DISPATCH.replace('if item.type == "function_call":', 'if item.type == "message":'),
    SINGLE_DISPATCH.replace('if item.type == "function_call":', 'if False:\n        if item.type == "function_call":\n            pass'),
    SINGLE_DISPATCH.replace("        result = handlers", "        item = cached\n        result = handlers"),
    SINGLE_DISPATCH.replace("        result = handlers", "        continue\n        result = handlers"),
    SINGLE_DISPATCH.replace("        result = handlers", "        item.arguments = stale\n        result = handlers"),
    SINGLE_DISPATCH.replace("item.arguments)", "other.arguments)"),
    SINGLE_DISPATCH.replace("item.name]", "other.name]"),
    SINGLE_DISPATCH.replace("tools=tools", "tools=[]"),
    SINGLE_DISPATCH.replace("response = client.responses.create", "return\nresponse = client.responses.create"),
    SINGLE_DISPATCH.replace("from openai import OpenAI", "from local_client import OpenAI"),
    SINGLE_DISPATCH.replace("client = OpenAI()", "client = OpenAI()\nclient = local_client"),
])
def test_single_dispatch_requires_reachable_import_bound_response(tmp_path, run_connector, source):
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


def test_single_dispatch_is_not_reported_as_repeating_autonomy(tmp_path, run_connector):
    findings, ctx = scan(tmp_path, run_connector, SINGLE_DISPATCH)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.AGENT
    assert "autonomous" not in findings[0].capabilities
    assert any("selected-action dispatch" in evidence.description for evidence in findings[0].evidence)


def test_single_dispatch_cannot_join_incompatible_paths(tmp_path, run_connector):
    source = SINGLE_DISPATCH.replace("response = client.responses.create", "if disabled:\n    return\nresponse = client.responses.create")
    source = source.replace("        result = handlers", "        if disabled:\n            result = handlers")
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


@pytest.mark.parametrize("dispatch", [
    "        handlers[item.name](item.arguments)",           # result not kept
    "        handlers.get(item.name)(item.arguments)",       # registry lookup, result not kept
])
def test_single_dispatch_without_a_kept_result_is_an_agent(tmp_path, run_connector, dispatch):
    source = SINGLE_DISPATCH.replace("        result = handlers[item.name](item.arguments)", dispatch)
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert [finding.kind for finding in findings] == [Kind.AGENT]


def test_returned_single_dispatch_is_an_agent(tmp_path, run_connector):
    source = '''from openai import OpenAI
client = OpenAI()
def answer(question):
    response = client.responses.create(model="example", input=question, tools=tools)
    for item in response.output:
        if item.type == "function_call":
            return handlers[item.name](item.arguments)
'''
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert [finding.kind for finding in findings] == [Kind.AGENT]


def test_unlinked_bare_local_handler_is_still_not_an_agent(tmp_path, run_connector):
    source = SINGLE_DISPATCH.replace("        result = handlers[item.name](item.arguments)",
                                     "        log(item.arguments)")
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


def test_many_plain_requests_in_a_long_module_stay_within_budget(tmp_path, run_connector):
    # Notebook exports can hold thousands of statements and many requests;
    # reachability is only analyzed for requests followed by a selection.
    cell = 'response_{n} = client.responses.create(model="m", input="q{n}", tools=tools)\nprint(response_{n}.output_text)\n'
    source = ("from openai import OpenAI\nclient = OpenAI()\ntools = [{'type': 'function', 'name': 'x'}]\n"
              + "".join(f"setting_{n} = {n}\n" for n in range(3_000))
              + "".join(cell.format(n=n) for n in range(60)))
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert findings and not any(finding.kind == Kind.AGENT for finding in findings)


def test_dispatch_after_a_return_is_unreachable(tmp_path, run_connector):
    source = SINGLE_DISPATCH.replace("        result = handlers[item.name](item.arguments)",
                                     "        return None\n        handlers[item.name](item.arguments)")
    source = source.replace("response = client", "def run(tools):\n    response = client").replace(
        "\nfor item", "\n    for item").replace("\n    if item", "\n        if item").replace(
        "\n        return None\n        handlers", "\n            return None\n            handlers")
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)
