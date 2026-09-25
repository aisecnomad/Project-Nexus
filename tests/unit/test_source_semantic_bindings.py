"""Agent construction requires a library binding, not a suggestive spelling."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import source_semantics
from shadowscan.models import Kind


def _scan(tmp_path, run_connector, source, suffix=".py"):
    (tmp_path / f"app{suffix}").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return findings


@pytest.mark.parametrize("source", [
    "while True:\n    item = queue.get()\n    print(item)\n",
    'import subprocess\ncommand = ["make", "all"]\nsubprocess.run(command, check=True)\n',
    'supervisor = "systemd"\n',
    "max_iterations = 1000\nmax_steps = 500\n",
    'def create_agent(name):\n    return {"name": name}\n',
    "checkpointer = None\n",
    "def scrape_page(url):\n    return None\n",
    "tools = [hammer, saw]\n",
])
def test_generic_programming_has_no_ai_finding(tmp_path, run_connector, source):
    assert _scan(tmp_path, run_connector, source) == []


def test_repeated_worker_idioms_cannot_become_confirmed_agents(tmp_path, run_connector):
    for number in range(12):
        (tmp_path / f"worker_{number}.py").write_text(
            "import subprocess\nwhile True:\n    command = queue.get()\n    subprocess.run(command, check=True)\n"
        )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete
    assert findings == []


def test_supporting_heuristics_require_ai_evidence_and_repetition_is_grouped(tmp_path, run_connector):
    (tmp_path / "requirements.txt").write_text("langchain\n")
    source = "while True:\n    item = queue.get()\n    print(item)\n"
    baseline = _scan(tmp_path, run_connector, source)
    project = next(f for f in baseline if f.resource_type == "project")
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert "autonomous" in project.capabilities
    for number in range(12):
        (tmp_path / f"worker_{number}.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    repeated = next(f for f in findings if f.resource_type == "project")
    assert not ctx.stats.incomplete
    assert repeated.kind == Kind.FRAMEWORK_USAGE
    assert repeated.confidence == project.confidence


@pytest.mark.parametrize(("source", "signature"), [
    ('from langgraph.prebuilt import create_react_agent as build\napp = build(model, tools)\napp.invoke({})\n', "framework.langgraph"),
    ('import langgraph.graph as graph\napp = graph.StateGraph(dict)\n', "framework.langgraph"),
    ('import langgraph.graph\napp = langgraph.graph.StateGraph(dict)\n', "framework.langgraph"),
    ('from langchain.agents import create_agent as construct\napp = construct(model, tools)\n', "framework.langchain"),
    ('from crewai import Crew as Team\napp = Team(agents=[], tasks=[])\n', "framework.crewai"),
    ('from agents import Agent as Worker\napp = Worker(instructions="Help", name="worker")\n', "framework.openai-agents-sdk"),
    ('import agents as sdk\napp = sdk.Agent(instructions="Help", name="worker")\n', "framework.openai-agents-sdk"),
    ('from pydantic_ai import Agent as Worker\napp = Worker(model)\n', "framework.pydantic-ai"),
    ('from pydantic_ai import Agent\napp = Agent[Dependencies, Result](model)\n', "framework.pydantic-ai"),
    ('from pydantic_ai import Agent as Worker\napp = Worker[Dependencies, Result](model)\n', "framework.pydantic-ai"),
    ('import pydantic_ai as ai\napp = ai.Agent[Dependencies, Result](model)\n', "framework.pydantic-ai"),
    ('from strands import Agent as Worker\napp = Worker(model=model)\n', "framework.aws-strands"),
    ('from langgraph.graph import StateGraph\nmessage = f"{StateGraph(dict)}"\n', "framework.langgraph"),
])
def test_python_import_aliases_bind_real_construction(tmp_path, run_connector, source, signature):
    findings = _scan(tmp_path, run_connector, source)
    agents = [f for f in findings if f.kind == Kind.AGENT]
    assert len(agents) == 1
    assert signature in agents[0].frameworks
    assert agents[0].confidence >= 0.85


@pytest.mark.parametrize(("module", "application", "source"), [
    ("agents.py", "app.py", 'from agents import Agent\napp = Agent(name="worker", instructions="Help")\n'),
    ("agents.py", "app.py", 'import agents as sdk\napp = sdk.Agent(name="worker", instructions="Help")\n'),
    ("agents/__init__.py", "app.py", 'from agents import Agent\napp = Agent(name="worker", instructions="Help")\n'),
    ("pkg/agents.py", "pkg/app.py", 'from agents import Agent\napp = Agent(name="worker", instructions="Help")\n'),
    ("src/agents.py", "src/app.py", 'from agents import Agent\napp = Agent(name="worker", instructions="Help")\n'),
    ("src/agents.py", "app.py", 'from agents import Agent\napp = Agent(name="worker", instructions="Help")\n'),
])
def test_checkout_local_agents_module_does_not_claim_openai_sdk(
    tmp_path, run_connector, module, application, source,
):
    local = tmp_path / module
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text("class Agent:\n    def __init__(self, **kwargs):\n        pass\n")
    app = tmp_path / application
    app.parent.mkdir(parents=True, exist_ok=True)
    app.write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any("framework.openai-agents-sdk" in f.frameworks for f in findings)


def test_local_module_does_not_hide_unrelated_sdk_on_same_import_line(tmp_path, run_connector):
    (tmp_path / "agents.py").write_text("class Agent: pass\n")
    findings = _scan(tmp_path, run_connector,
                     "import agents, langgraph.graph\n"
                     "a = agents.Agent(name='worker', instructions='Help')\n"
                     "g = langgraph.graph.StateGraph(dict)\n")
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)
    assert not any("framework.openai-agents-sdk" in f.frameworks for f in findings)


def test_unrelated_nested_module_does_not_hide_real_sdk(tmp_path, run_connector):
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / "agents.py").write_text("class Agent: pass\n")
    findings = _scan(tmp_path, run_connector,
                     'from agents import Agent\napp = Agent(name="worker", instructions="Help")\n')
    assert any(f.kind == Kind.AGENT and "framework.openai-agents-sdk" in f.frameworks for f in findings)


def test_local_module_overrides_sdk_dependency_for_construction(tmp_path, run_connector):
    (tmp_path / "agents.py").write_text("class Agent: pass\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "example"\ndependencies = ["openai-agents"]\n')
    findings = _scan(tmp_path, run_connector,
                     'from agents import Agent\napp = Agent(name="worker", instructions="Help")\n')
    assert any(f.kind == Kind.FRAMEWORK_USAGE and "framework.openai-agents-sdk" in f.frameworks
               for f in findings)
    assert not any(f.kind == Kind.AGENT for f in findings)


def test_invalid_python_does_not_restore_local_sdk_import(tmp_path, run_connector):
    (tmp_path / "agents.py").write_text("class Agent: pass\n")
    (tmp_path / "app.py").write_text('from agents import Agent\napp = Agent(name="worker")\ninvalid = (\n')
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not any("framework.openai-agents-sdk" in f.frameworks for f in findings)


@pytest.mark.parametrize("body", [
    "create_agent = custom_builder\ncreate_agent(model, tools)\n",
    "def create_agent(model, tools):\n    return None\ncreate_agent(model, tools)\n",
    "def build(create_agent):\n    return create_agent(model, tools)\n",
    "def build():\n    create_agent(model, tools)\n    create_agent = custom_builder\n",
    "f = lambda create_agent: create_agent(model, tools)\n",
    "[create_agent(model, tools) for create_agent in builders]\n",
    "{create_agent(model, tools) for create_agent in builders}\n",
    "{create_agent(model, tools): 1 for create_agent in builders}\n",
    "result = (create_agent(model, tools) for create_agent in builders)\n",
    "for create_agent in builders:\n    create_agent(model, tools)\n",
    "try:\n    process()\nexcept Exception as create_agent:\n    create_agent(model, tools)\n",
    "match value:\n    case {'builder': create_agent}:\n        create_agent(model, tools)\n",
    "if False:\n    create_agent(model, tools)\n",
    "if condition:\n    create_agent = custom_builder\ncreate_agent(model, tools)\n",
    "from local_factories import *\ncreate_agent(model, tools)\n",
    "def build():\n    create_agent(model, tools)\n    try:\n        process()\n    except Exception as create_agent:\n        pass\n",
    "def build():\n    create_agent(model, tools)\n    match value:\n        case {'builder': create_agent}:\n            pass\n",
])
def test_python_shadowed_or_unreachable_construction_is_not_attributed(tmp_path, run_connector, body):
    findings = _scan(tmp_path, run_connector, "from langchain.agents import create_agent\n" + body)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_python_namespace_reassignment_is_not_sdk_construction(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector,
                     "import langgraph.graph as graph\ngraph.StateGraph = local_factory\ngraph.StateGraph(dict)\n")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_shadowed_generic_constructor_does_not_recover_sdk_binding(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector,
                     "from pydantic_ai import Agent as Worker\nWorker = local_factory\napp = Worker[Dependencies, Result](model)\n")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_python_class_import_is_not_in_a_methods_lexical_scope(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector,
                     "class Local:\n    from langgraph.graph import StateGraph\n    def build(self):\n        return StateGraph(dict)\n")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_python_comprehension_target_does_not_shadow_the_enclosing_function(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector,
                     "from langgraph.graph import StateGraph\ndef build():\n    values = [StateGraph for StateGraph in factories]\n    return StateGraph(dict)\n")
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


@pytest.mark.parametrize("source", [
    "from langgraph.graph import StateGraph\n",
    "from langgraph.checkpoint.memory import MemorySaver\ncache = MemorySaver()\n",
    "from smolagents import InferenceClientModel\nmodel = InferenceClientModel()\n",
])
def test_import_and_framework_utilities_are_not_agents(tmp_path, run_connector, source):
    findings = _scan(tmp_path, run_connector, source)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


@pytest.mark.parametrize("source", [
    'import { StateGraph as Graph } from "@langchain/langgraph";\nconst app = new Graph();\n',
    'import * as lg from "@langchain/langgraph";\nconst app = new lg.StateGraph();\n',
    'const lg = require("@langchain/langgraph");\nconst app = new lg.StateGraph();\n',
    'const { StateGraph: Graph } = require("@langchain/langgraph");\nconst app = new Graph();\n',
    'import { createReactAgent as build } from "@langchain/langgraph/prebuilt";\nconst app = build({});\n',
])
@pytest.mark.parametrize("suffix", [".js", ".ts"])
def test_javascript_aliases_and_namespaces_bind_construction(tmp_path, run_connector, source, suffix):
    findings = _scan(tmp_path, run_connector, source, suffix)
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


@pytest.mark.parametrize("body", [
    "function build(Graph) { return new Graph(); }\n",
    "const build = (Graph) => new Graph();\n",
    "const build = Graph => new Graph();\n",
    "Graph = custom; new Graph();\n",
    "function Graph() {}\nnew Graph();\n",
    "try { process(); } catch (Graph) { new Graph(); }\n",
    "class Local { build(Graph) { return new Graph(); } }\n",
])
def test_javascript_shadowed_bindings_remain_supporting(tmp_path, run_connector, body):
    findings = _scan(tmp_path, run_connector,
                     'import { StateGraph as Graph } from "@langchain/langgraph";\n' + body, ".js")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_javascript_prose_options_do_not_create_an_agent(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector,
                     'import { generateText } from "ai";\ngenerateText({prompt: "tools: { fake }"});\n', ".ts")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_javascript_bound_tool_call_remains_detectable(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector,
                     'import { generateText as answer, tool } from "ai";\nanswer({tools: {foo: tool({})}, maxSteps: 3});\n', ".ts")
    assert any(f.kind == Kind.AGENT and "framework.vercel-ai-sdk" in f.frameworks for f in findings)


_OPENAI_RESPONSES_TOOL_DISPATCH = '''
import json
from openai import OpenAI as Client

client = Client()

def answer(question):
    messages = [{"role": "user", "content": question}]
    for turn in range(5):
        response = client.responses.create(model="gpt-4o", input=messages, tools=definitions)
        messages.extend(response.output)
        for item in response.output:
            if item.type != "function_call":
                continue
            handler = FUNCTIONS[item.name]
            result = handler(**json.loads(item.arguments))
            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": json.dumps(result)})
        if response.output_text:
            return response.output_text
'''

_OPENAI_RESPONSES_FILTERED_DISPATCH = '''import json
from openai import OpenAI

client = OpenAI()
tools = [{"type": "function", "name": "lookup_inventory", "description": "Look up a SKU",
          "parameters": {"type": "object", "properties": {"sku": {"type": "string"}}, "required": ["sku"]}}]

def lookup_inventory(arguments):
    sku = json.loads(arguments)["sku"]
    return json.dumps({"sku": sku, "quantity": 10})

def run(request):
    conversation = [{"role": "user", "content": request}]
    for _ in range(8):
        response = client.responses.create(model="gpt-4.1", input=conversation, tools=tools)
        tool_calls = [item for item in response.output if item.type == "function_call"]
        if not tool_calls:
            return response.output_text
        for call in tool_calls:
            result = lookup_inventory(call.arguments)
            conversation.extend([call, {"type": "function_call_output", "call_id": call.call_id,
                                        "output": result}])
'''


def test_python_custom_openai_responses_tool_loop_is_agent(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector, _OPENAI_RESPONSES_TOOL_DISPATCH)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == Kind.AGENT
    assert "provider.openai" in finding.model_providers
    assert {"tool-use", "autonomous"} <= set(finding.capabilities)
    assert finding.metadata["agent_indicators"] == 1
    assert any("iterative Responses tool dispatch and feedback" in e.description for e in finding.evidence)


def test_python_filtered_responses_tool_calls_with_extend_is_agent(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector, _OPENAI_RESPONSES_FILTERED_DISPATCH)
    assert len(findings) == 1
    assert findings[0].kind == Kind.AGENT
    assert "provider.openai" in findings[0].model_providers
    assert findings[0].metadata["agent_indicators"] == 1


@pytest.mark.parametrize("source", [
    _OPENAI_RESPONSES_FILTERED_DISPATCH.replace("for _ in range(8):", "if True:"),
    _OPENAI_RESPONSES_FILTERED_DISPATCH.replace("for _ in range(8):", "for _ in range(1):"),
    _OPENAI_RESPONSES_FILTERED_DISPATCH.replace('if item.type == "function_call"', 'if item.type == "message"'),
    _OPENAI_RESPONSES_FILTERED_DISPATCH.replace("lookup_inventory(call.arguments)", "lookup_inventory('fixed')"),
    _OPENAI_RESPONSES_FILTERED_DISPATCH.replace("conversation.extend([call,", "audit.extend([call,"),
    _OPENAI_RESPONSES_FILTERED_DISPATCH.replace('"call_id": call.call_id', '"call_id": "fixed"'),
])
def test_filtered_responses_pattern_requires_repetition_selection_dispatch_and_feedback(
    tmp_path, run_connector, source,
):
    findings = _scan(tmp_path, run_connector, source)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_responses_ast_work_limit_marks_scan_incomplete(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(source_semantics, "MAX_TOOL_LOOP_AST_WORK", 4)
    (tmp_path / "app.py").write_text(_OPENAI_RESPONSES_FILTERED_DISPATCH)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert ctx.stats.incomplete
    assert any("MatchTimeoutError" in error for error in ctx.stats.errors)
    assert not any(f.kind == Kind.AGENT for f in findings)


@pytest.mark.parametrize("source", [
    '''from openai import OpenAI
client = OpenAI()
messages = []
for turn in range(5):
    response = client.responses.create(model="gpt-4o", input=messages, tools=definitions)
    for item in response.output:
        if item.type == "function_call":
            pass
        if item.type == "message":
            handler = FUNCTIONS[item.name]
            result = handler(item.arguments)
            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
''',
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("        if response.output_text:\n", "        messages = []\n        if response.output_text:\n"),
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("        if response.output_text:\n", "        messages.clear()\n        if response.output_text:\n"),
    '''from openai import OpenAI
client = OpenAI()
messages = []
for turn in range(5):
    response = client.responses.create(model="gpt-4o", input=messages, tools=definitions)
    for item in response.output:
        if item.type == "function_call":
            result = audit(item.name, item.arguments)
            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
''',
    '''import json
from openai import OpenAI
client = OpenAI()
messages = []
for turn in range(5):
    response = client.responses.create(model="gpt-4o", input=messages, tools=definitions)
    for item in response.output:
        if item.type == "function_call":
            result = json.dumps({"name": item.name, "arguments": item.arguments})
            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
''',
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("    for turn in range(5):\n", "    for turn in range(0):\n"),
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("    for turn in range(5):\n", "    for turn in []:\n"),
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("        response = client.responses.create", "        break\n        response = client.responses.create"),
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("        if response.output_text:\n", "        break\n        if response.output_text:\n"),
])
def test_responses_disconnected_or_unreachable_tool_flow_remains_supporting(tmp_path, run_connector, source):
    findings = _scan(tmp_path, run_connector, source)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_async_custom_openai_responses_while_loop_is_agent(tmp_path, run_connector):
    source = '''import openai as ai
client = ai.AsyncOpenAI()
async def answer(question):
    messages = [{"role": "user", "content": question}]
    while True:
        response = await client.responses.create(input=messages, tools=definitions, model="gpt-4o")
        for item in response.output:
            if item.type == "function_call":
                handler = FUNCTIONS.get(item.name)
                result = handler(item.arguments)
                tool_message = {"type": "function_call_output", "call_id": item.call_id, "output": result}
                messages.append(tool_message)
        if response.output_text:
            return response.output_text
'''
    findings = _scan(tmp_path, run_connector, source)
    assert any(f.kind == Kind.AGENT and "provider.openai" in f.model_providers for f in findings)


@pytest.mark.parametrize("module_path", ["openai.py", "openai/__init__.py"])
def test_local_openai_module_cannot_prove_an_sdk_tool_loop(tmp_path, run_connector, module_path):
    local_module = tmp_path / module_path
    local_module.parent.mkdir(parents=True, exist_ok=True)
    local_module.write_text("class OpenAI:\n    pass\n")
    findings = _scan(tmp_path, run_connector, _OPENAI_RESPONSES_TOOL_DISPATCH)
    assert not any(f.kind == Kind.AGENT for f in findings)
    assert not any("iterative Responses tool dispatch and feedback" in e.description
                   for f in findings for e in f.evidence)


@pytest.mark.parametrize("source", [
    # One-shot function calling is an application pattern, not proof of an
    # autonomous loop, even when it sends the result in a second request.
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("    for turn in range(5):\n", "    if True:\n"),
    # A model call in a loop alone cannot establish model-directed execution.
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("handler = FUNCTIONS[item.name]", "handler = FUNCTIONS['fixed']"),
    # An unrelated function named responses.create is not the bound SDK call.
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("client = Client()", "client = local_client"),
    # Sending a function result to a separate list does not feed the model.
    _OPENAI_RESPONSES_TOOL_DISPATCH.replace("messages.append({", "audit.append({"),
    # Disabled dispatch is not evidence of an executable tool loop.
    '''from openai import OpenAI
client = OpenAI()
messages = []
for turn in range(5):
    response = client.responses.create(input=messages, tools=definitions, model="gpt-4o")
    for item in response.output:
        if item.type == "function_call":
            if False:
                handler = FUNCTIONS[item.name]
                result = handler(item.arguments)
                messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
''',
    # Quoted source fragments and comments carry no executable evidence.
    '''from openai import OpenAI
client = OpenAI()
note = """for step in range(5):
    response = client.responses.create(input=messages, tools=definitions)
    for item in response.output:
        result = FUNCTIONS[item.name](item.arguments)
        messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})"""
''',
])
def test_openai_tool_loop_requires_repeated_bound_model_dispatch_and_feedback(tmp_path, run_connector, source):
    findings = _scan(tmp_path, run_connector, source)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


def test_typescript_generic_imported_constructor(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector,
                     'import { Agent as Worker } from "@openai/agents";\nconst app = new Worker<Context>({ name: "worker" });\n', ".ts")
    assert any(f.kind == Kind.AGENT and "framework.openai-agents-sdk" in f.frameworks for f in findings)


@pytest.mark.parametrize(("limit", "value"), [("MAX_AST_NODES", 5), ("MAX_BOUND_CALLS", 1)])
def test_source_binding_budget_exhaustion_marks_scan_incomplete(tmp_path, run_connector, monkeypatch, limit, value):
    monkeypatch.setattr(source_semantics, limit, value)
    (tmp_path / "app.py").write_text(
        "from langgraph.graph import StateGraph\nfirst = StateGraph(dict)\nsecond = StateGraph(dict)\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any("MatchTimeoutError" in error for error in ctx.stats.errors)
    assert not any(f.kind == Kind.AGENT for f in findings)
