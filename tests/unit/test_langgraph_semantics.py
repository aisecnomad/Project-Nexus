"""A general LangGraph workflow is not evidence of a model-directed agent."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.connectors.code import langgraph_semantics
from shadowscan.connectors.code.source_semantics import _python_bindings
from shadowscan.models import Kind
from shadowscan.signatures.matcher import MatchTimeoutError

SOURCE = '''from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from app.tools import lookup

tools = [lookup]
model = ChatOpenAI().bind_tools(tools)

def call_model(state):
    response = model.invoke(state["messages"])
    return {"messages": [response]}

graph = StateGraph(dict)
graph.add_node("model", call_model)
graph.add_node("tools", ToolNode(tools))
graph.add_edge(START, "model")
graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})
graph.add_edge("tools", "model")
app = graph.compile()
'''


def recognize(source: str) -> set[int]:
    calls, _, tree = _python_bindings(source)
    return langgraph_semantics.langgraph_agent_lines(
        tree, [(call.node, call.binding.module, call.binding.symbol) for call in calls if call.node is not None],
    )


@pytest.mark.parametrize("source", [
    SOURCE,
    SOURCE.replace("StateGraph, START, END", "StateGraph as Builder, START, END").replace("graph = StateGraph", "graph = Builder"),
    SOURCE.replace("from langchain_openai import ChatOpenAI", "import langchain_openai as sdk").replace("ChatOpenAI()", "sdk.ChatOpenAI()"),
    SOURCE.replace('graph.add_edge(START, "model")', 'graph.set_entry_point("model")'),
    SOURCE.replace('graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})',
                   'graph.add_conditional_edges("model", tools_condition)'),
    SOURCE.replace("def call_model", "async def call_model").replace("model.invoke", "await model.ainvoke"),
    SOURCE.replace('response = model.invoke(state["messages"])',
                   'messages = [system_message, *state["messages"]]\n    response = model.invoke(messages)'),
    SOURCE.replace("graph.add_node(\"tools\", ToolNode(tools))", 'tool_node = ToolNode(tools)\ngraph.add_node("tools", tool_node)'),
    SOURCE.replace("app = graph.compile()", "graph = graph.compile()"),
    SOURCE.replace("from app.tools import lookup", "def lookup(query):\n    return query"),
    SOURCE.replace(".bind_tools(tools)", '.bind_tools(tools, tool_choice="auto")'),
    SOURCE.replace(".bind_tools(tools)", '.bind_tools(tools, tool_choice="required")'),
    SOURCE.replace(".bind_tools(tools)", '.bind_tools(tools, tool_choice=None)'),
])
def test_connected_model_tool_graph(source):
    assert recognize(source)


ROUTER = '''def choose(state):
    messages = state["messages"]
    last = messages[-1]
    if not last.tool_calls:
        return "stop"
    else:
        return "continue"

'''


def test_callback_routes_selected_tool_calls():
    source = SOURCE.replace("graph = StateGraph", ROUTER + "graph = StateGraph")
    source = source.replace('tools_condition, {"tools": "tools", END: END}', 'choose, {"continue": "tools", "stop": END}')
    assert recognize(source)


@pytest.mark.parametrize(("old", "new"), [
    ("from langgraph.graph import StateGraph, START, END", "from local_graph import StateGraph, START, END"),
    ("from langgraph.prebuilt import ToolNode, tools_condition", "from local_graph import ToolNode, tools_condition"),
    ("from langchain_openai import ChatOpenAI", "from local_model import ChatOpenAI"),
    ("tools = [lookup]", "tools = []"),
    ("tools = [lookup]", "tools = [None]"),
    ("tools = [lookup]", "tools = [*[]]"),
    ("tools = [lookup]", "tools = [*unknown_tools]"),
    ("tools = [lookup]", "tools = load_tools()"),
    ("tools = [lookup]", "tools = [object()]"),
    ("tools = [lookup]", "tools = [unknown_tool]"),
    ("tools = [lookup]", "tools = [lookup()]"),
    ("ChatOpenAI()", "ChatOpenAI"),
    (".bind_tools(tools)", '.bind_tools(tools, tool_choice="none")'),
    (".bind_tools(tools)", '.bind_tools(tools, **{"tool_choice": "none"})'),
    (".bind_tools(tools)", '.bind_tools(tools, tool_choice=setting)'),
    (".bind_tools(tools)", '.bind_tools(tools, tool_choice="unrecognized")'),
    (".bind_tools(tools)", ""),
    ('model.invoke(state["messages"])', "model.invoke(fixed_messages)"),
    ('model.invoke(state["messages"])', 'model.invoke(state["messages"], tool_choice="none")'),
    ('model.invoke(state["messages"])', 'model.invoke(state["messages"], tools=[])'),
    ('model.invoke(state["messages"])', 'model.invoke(state["messages"], **{"tools": []})'),
    ('model.invoke(state["messages"])', 'model.invoke(state["messages"], tool_choice=setting)'),
    ('return {"messages": [response]}', 'return {"messages": [fixed_response]}'),
    ('return {"messages": [response]}', 'return {"other": [response]}'),
    ('graph.add_node("model", call_model)', 'graph.add_node("model", deterministic_step)'),
    ('graph.add_node("tools", ToolNode(tools))', 'graph.add_node("tools", deterministic_step)'),
    ('graph.add_node("tools", ToolNode(tools))', 'graph.add_node("tools", ToolNode([other_tool]))'),
    ('ToolNode(tools)', 'ToolNode(tools, messages_key="other")'),
    ('ToolNode(tools)', 'ToolNode(tools, **{"messages_key": "other"})'),
    ('app = graph.compile()', 'app = graph.compile(**options)'),
    ('graph.add_edge("tools", "model")', 'graph.add_edge("tools", "model", **options)'),
    ('graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})',
     'graph.add_conditional_edges("model", tools_condition, path_map={"tools": END, END: "tools"})'),
    ('graph.add_edge(START, "model")', 'graph.add_edge(START, "unrelated")'),
    ('graph.add_edge("tools", "model")', 'graph.add_edge("tools", END)'),
    ('graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})',
     'graph.add_edge("model", "tools")'),
    ('{"tools": "tools", END: END}', '{"tools": END, END: "tools"}'),
    ('graph.add_conditional_edges("model",', 'graph.add_conditional_edges("unrelated",'),
    ("app = graph.compile()", ""),
    ("graph = StateGraph(dict)", "StateGraph = other_builder\ngraph = StateGraph(dict)"),
    ("graph = StateGraph(dict)", "model = other_model\ngraph = StateGraph(dict)"),
    ("graph = StateGraph(dict)", "tools_condition = fixed_route\ngraph = StateGraph(dict)"),
    ("graph = StateGraph(dict)", "ToolNode = fixed_node\ngraph = StateGraph(dict)"),
    ("graph = StateGraph(dict)", "tools.clear()\ngraph = StateGraph(dict)"),
    ("app = graph.compile()", "app = graph.compile()\nmodel = other_model"),
    ('graph.add_node("model", call_model)', 'call_model = fixed_node\ngraph.add_node("model", call_model)'),
    ('response = model.invoke(state["messages"])', 'model = local_model\n    response = model.invoke(state["messages"])'),
    ('response = model.invoke(state["messages"])', 'response = model.invoke(state["messages"])\n    model = local_model'),
    ('response = model.invoke(state["messages"])', 'state = saved_state\n    response = model.invoke(state["messages"])'),
    ('response = model.invoke(state["messages"])', 'return {}\n    response = model.invoke(state["messages"])'),
])
def test_disconnected_disabled_shadowed_or_unbound_graphs(old, new):
    assert not recognize(SOURCE.replace(old, new))


def test_general_deterministic_graph_has_no_agent_proof():
    assert not recognize('''from langgraph.graph import StateGraph, START, END
def increment(state):
    return {"count": state["count"] + 1}
graph = StateGraph(dict)
graph.add_node("increment", increment)
graph.add_edge(START, "increment")
graph.add_edge("increment", END)
app = graph.compile()
''')


def test_separate_graphs_do_not_supply_each_others_missing_evidence():
    source = SOURCE.replace('graph.add_node("tools", ToolNode(tools))',
                            'other = StateGraph(dict)\nother.add_node("tools", ToolNode(tools))\nother.compile()')
    assert not recognize(source)


def test_same_named_graph_in_another_scope_does_not_supply_evidence():
    source = SOURCE.replace('graph.add_node("tools", ToolNode(tools))',
                            'def unrelated():\n    graph = StateGraph(dict)\n    graph.add_node("tools", ToolNode(tools))\n    return graph.compile()')
    assert not recognize(source)


@pytest.mark.parametrize("replacement", [
    'if True:',
    'if not saved_message.tool_calls:',
    'last = saved_message\n    if not last.tool_calls:',
])
def test_route_must_depend_on_current_model_response(replacement):
    source = SOURCE.replace("graph = StateGraph", ROUTER.replace("if not last.tool_calls:", replacement) + "graph = StateGraph")
    source = source.replace('tools_condition, {"tools": "tools", END: END}', 'choose, {"continue": "tools", "stop": END}')
    assert not recognize(source)


@pytest.mark.parametrize(("filename", "case_id", "path"), [
    ("public_corpus.json", "langgraph-example-agent", "libs/cli/examples/graphs/agent.py"),
    ("realistic_corpus.json", "fastapi-langgraph-support-service", "app/agent.py"),
])
def test_existing_complete_corpus_graphs_keep_agent_proof(filename, case_id, path):
    corpus = json.loads((Path(__file__).resolve().parents[2] / "tools" / "evaluation" / filename).read_text())
    case = next(case for case in corpus["cases"] if case["id"] == case_id)
    assert recognize(case["files"][path])


def test_missing_import_bound_calls_cannot_prove_a_graph():
    _, _, tree = _python_bindings(SOURCE)
    assert not langgraph_semantics.langgraph_agent_lines(tree, [])


def test_analysis_budget_is_explicit(monkeypatch):
    monkeypatch.setattr(langgraph_semantics, "MAX_FLOW_STEPS", 5)
    with pytest.raises(MatchTimeoutError, match="LangGraph analysis budget"):
        recognize(SOURCE)


@pytest.mark.parametrize("limit", ["MAX_SEQUENCE_ITEMS", "MAX_SEQUENCE_ALLOCATIONS"])
def test_starred_sequence_growth_has_preallocation_limits(monkeypatch, limit):
    monkeypatch.setattr(langgraph_semantics, limit, 8)
    source = SOURCE.replace("model = ChatOpenAI()", "tools = [*tools, *tools]\n" * 18 + "model = ChatOpenAI()")
    with pytest.raises(MatchTimeoutError, match="LangGraph sequence allocation budget"):
        recognize(source)


def test_sequence_budget_exhaustion_marks_filesystem_scan_incomplete(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(langgraph_semantics, "MAX_SEQUENCE_ALLOCATIONS", 8)
    source = SOURCE.replace("model = ChatOpenAI()", "tools = [*tools, *tools]\n" * 18 + "model = ChatOpenAI()")
    (tmp_path / "graph.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert ctx.stats.incomplete
    assert any("MatchTimeoutError" in error for error in ctx.stats.errors)
    assert not any(finding.kind == Kind.AGENT for finding in findings)


@pytest.mark.parametrize("source, expected", [(SOURCE, True), ("from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n", False)])
def test_filesystem_scan_uses_connected_graph_proof(tmp_path, run_connector, source, expected):
    (tmp_path / "graph.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(finding.kind == Kind.AGENT for finding in findings) is expected


def test_local_langgraph_module_does_not_bypass_import_exclusions(tmp_path, run_connector):
    (tmp_path / "graph.py").write_text(SOURCE)
    (tmp_path / "langgraph.py").write_text("raise RuntimeError('scanned source must not execute')\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)
