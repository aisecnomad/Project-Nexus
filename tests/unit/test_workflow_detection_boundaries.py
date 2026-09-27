"""Framework availability is not proof of an agent or enabled tool execution."""

from __future__ import annotations

import pytest

from shadowscan.models import Kind
from shadowscan.risk import assess


def _scan(tmp_path, run_connector, source, suffix=".py"):
    (tmp_path / f"app{suffix}").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(f for f in findings if f.resource_type == "project")


def test_deterministic_langgraph_is_usage_without_tool_capability(tmp_path, run_connector):
    finding = _scan(tmp_path, run_connector, '''from typing import TypedDict
from langgraph.graph import StateGraph, START, END

class State(TypedDict):
    count: int

def increment(state: State):
    return {"count": state["count"] + 1}

graph = StateGraph(State)
graph.add_node("increment", increment)
graph.add_edge(START, "increment")
graph.add_edge("increment", END)
result = graph.compile().invoke({"count": 0})
''')
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in finding.capabilities
    assert "tool-use" in finding.metadata["potential_capabilities"]


@pytest.mark.parametrize("source", [
    "from crewai.flow.flow import Flow\nworkflow = Flow()\n",
    "from crewai.flow.flow import Flow, start\nclass Counter(Flow):\n    @start()\n    def increment(self):\n        return 1 + 1\nCounter().kickoff()\n",
    'import { StateGraph } from "@langchain/langgraph";\nconst workflow = new StateGraph();\n',
])
def test_generic_flow_construction_does_not_establish_agent(tmp_path, run_connector, source):
    finding = _scan(tmp_path, run_connector, source, ".ts" if source.startswith("import {") else ".py")
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert not {"tool-use", "multi-agent"} & set(finding.capabilities)


@pytest.mark.parametrize(("source", "potential"), [
    ("from langgraph.graph import StateGraph\n", {"tool-use"}),
    ("from pydantic_ai import Agent\n", {"tool-use"}),
    ("from crewai import Crew\n", {"tool-use", "multi-agent"}),
])
def test_bare_framework_imports_keep_unscored_potential_capabilities(tmp_path, run_connector, source, potential):
    finding = _scan(tmp_path, run_connector, source)
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert not finding.capabilities
    assert potential <= set(finding.metadata["potential_capabilities"])
    assert not any(factor.id.startswith("capability:") for factor in assess(finding).factors)


def test_dependency_only_has_no_execution_capability(tmp_path, run_connector):
    (tmp_path / "requirements.txt").write_text("crewai\npydantic-ai\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete
    finding = next(f for f in findings if f.resource_type == "project")
    assert finding.kind == Kind.FRAMEWORK_USAGE and not finding.capabilities
    assert {"tool-use", "multi-agent"} <= set(finding.metadata["potential_capabilities"])


@pytest.mark.parametrize("construct", [False, True])
def test_search_tool_capability_requires_source_call_not_dependency(tmp_path, run_connector, construct):
    (tmp_path / "requirements.txt").write_text("tavily-python\n")
    source = "from tavily import TavilyClient\n"
    if construct:
        source += "client = TavilyClient()\n"
    finding = _scan(tmp_path, run_connector, source)
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert ("browsing" in finding.capabilities) is construct
    assert ("browsing" in finding.metadata.get("potential_capabilities", [])) is not construct
    assert any(factor.id == "capability:browsing" for factor in assess(finding).factors) is construct


@pytest.mark.parametrize("options", [
    "tools: {}",
    "tools: {}, toolChoice: 'none'",
    "tools: { lookup: tool({ description: 'lookup', inputSchema: schema }) }",
    "tools: { lookup: tool({ execute: async () => 1 }) }, toolChoice: 'none'",
    "tools: { lookup: tool({ execute: async () => 1 }) }, toolChoice: choice",
    "tools: { lookup: tool({ execute: async () => 1 }) }, activeTools: []",
    "tools: { lookup: tool({ execute: async () => 1 }) }, experimental_activeTools: []",
    "tools: { lookup: tool({ execute: async () => 1 }) }, activeTools: ['other']",
    "tools: { lookup: tool({ execute: async () => 1 }) }, activeTools: selected",
    "tools: { lookup: tool({ execute: undefined }) }",
    "tools: { lookup: tool({ execute: function () { return undefined; }() }) }",
    "tools: { lookup: tool({ execute: function () { return 1; } && undefined }) }",
    "tools: { lookup: tool({ execute: function () { return 1; }.value }) }",
    "tools: { lookup: tool({ execute: (() => 1)() }) }",
    "tools: { lookup: tool({ execute: async () => {}() }) }",
    "tools: { lookup: tool({ description: 'execute: async () => 1' }) }",
    "tools: { lookup: tool({ execute: async () => 1 }) }, ...dynamicOptions",
    "tools: { lookup: tool({ execute: async () => 1 }) }, toolChoice: 'required', toolChoice: 'none'",
    "tools: { lookup: tool({ execute: async () => 1, execute: undefined }) }",
    "tools: { lookup: customTool({ execute: async () => 1 }) }",
    "tools: { lookup: tool({ execute: async () => 1 }), ...extraTools }",
    "tools: { ...getTools(), lookup: tool({ execute: async () => 1 }) }",
    "tools: { ...mcp.tools }",
    "tools: { lookup: tool({ execute: async () => 1 }) }, activeTools: ['lookup'], experimental_activeTools: []",
])
@pytest.mark.parametrize("method", ["generateText", "streamText"])
def test_schema_empty_disabled_or_ambiguous_tools_do_not_create_agent(tmp_path, run_connector, options, method):
    finding = _scan(tmp_path, run_connector,
                    f"import {{ {method}, tool }} from 'ai';\nconst result = await {method}({{model, {options}}});\n", ".ts")
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in finding.capabilities


@pytest.mark.parametrize("options", [
    "tools: { lookup: tool({ execute: async () => 1 }) }",
    "tools: { lookup: tool({ execute: async()=> 'ok' }) }",
    "tools: { lookup: tool({ execute: async ({ city }) => lookup(city) }) }, toolChoice: 'auto'",
    "tools: { lookup: tool({ execute: function (args) { return lookup(args); } }) }, toolChoice: 'required'",
    "tools: { lookup: { execute: async () => 1 } }",
    "tools: { lookup: tool({ async execute(args) { return lookup(args); } }) }",
    "tools: { lookup: tool({ execute: async () => 1 }) }, activeTools: ['lookup']",
    "tools: { lookup: tool({ execute: async () => 1 }) }, prompt: 'toolChoice: none, tools: {}'",
    "tools: { ...mcp.tools, lookup: tool({ execute: async ({ service }) => lookup(service) }) }",
])
@pytest.mark.parametrize("method", ["generateText", "streamText"])
def test_bound_enabled_tool_execution_keeps_agent_and_capability(tmp_path, run_connector, options, method):
    finding = _scan(tmp_path, run_connector,
                    f"import {{ {method}, tool }} from 'ai';\nconst result = await {method}({{model, {options}}});\n", ".ts")
    assert finding.kind == Kind.AGENT and "tool-use" in finding.capabilities


@pytest.mark.parametrize("source", [
    "import { generateText as answer, tool as fn } from 'ai';\nanswer({tools: { lookup: fn({execute: async () => 1}) }});\n",
    "import * as sdk from 'ai';\nsdk.generateText({tools: { lookup: sdk.tool({execute: async () => 1}) }});\n",
])
def test_tool_factory_aliases_are_resolved(tmp_path, run_connector, source):
    finding = _scan(tmp_path, run_connector, source, ".ts")
    assert finding.kind == Kind.AGENT and "tool-use" in finding.capabilities


def test_shadowed_tool_helper_cannot_establish_dispatch(tmp_path, run_connector):
    finding = _scan(tmp_path, run_connector, """import { generateText, tool } from 'ai';
tool = unrelated;
generateText({tools: { lookup: tool({execute: async () => 1}) }});
""", ".ts")
    assert finding.kind == Kind.FRAMEWORK_USAGE


def test_explicit_agent_construction_preserves_capability(tmp_path, run_connector):
    finding = _scan(tmp_path, run_connector, "from crewai import Agent, Crew\na = Agent(role='helper', tools=[lookup])\ncrew = Crew(agents=[a], tasks=[task])\n")
    assert finding.kind == Kind.AGENT
    assert {"tool-use", "multi-agent"} <= set(finding.capabilities)
