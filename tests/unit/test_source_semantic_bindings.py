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
    source = "max_iterations = 20\nwhile True:\n    item = queue.get()\n    print(item)\n"
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
    assert any("source binding" in error and "limit exceeded" in error for error in ctx.stats.errors)
    assert not any(f.kind == Kind.AGENT for f in findings)
