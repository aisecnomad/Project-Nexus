"""Opt-in source inventory identities never inherit project-wide approval."""

from __future__ import annotations

import ast
import shutil
import time

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext, ConnectorError
from shadowscan.connectors.code import source_identity, tool_attribution
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.connectors.code.source_identity import named_construction_spans
from shadowscan.connectors.code.tool_attribution import ToolRegions
from shadowscan.engine import Engine
from shadowscan.models import Kind
from shadowscan.registry import Inventory, InventoryEntry


def _scan(run_connector, path, **config):
    return run_connector("code.filesystem", path=str(path), label="repo", use_git=False, **config)


def _agents(findings):
    return {
        f.metadata["source_identity"]["binding"]: f for f in findings if f.resource_type == "source-agent"
    }


def test_named_agents_do_not_share_project_or_sibling_approval(run_connector, fixtures, tmp_path):
    shutil.copy(fixtures / "code_source_identity" / "app.py", tmp_path / "app.py")
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.errors and not ctx.stats.incomplete
    agents = _agents(findings)
    assert set(agents) == {"approved", "added", "build.scoped"}
    assert all(f.kind == Kind.AGENT for f in agents.values())
    assert agents["approved"].resource == "repo/app.py#agent:approved"
    assert "tool-use" in agents["approved"].capabilities
    assert "code-exec" in agents["approved"].capabilities
    assert "tool-use" not in agents["added"].capabilities
    assert "tool-use" not in agents["build.scoped"].capabilities
    assert "code-exec" not in agents["added"].capabilities
    assert "code-exec" not in agents["build.scoped"].capabilities
    approved = Inventory(
        entries=[InventoryEntry(agent_id="approved", resources=[agents["approved"].resource])]
    )
    assert approved.match(agents["approved"]) is not None
    assert approved.match(agents["added"]) is None
    project_approval = Inventory(entries=[InventoryEntry(agent_id="project", resources=["repo"])])
    assert all(project_approval.match(f) is None for f in agents.values())
    project = next(f for f in findings if f.resource_type == "project")
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert "code-exec" not in project.capabilities
    assert project.metadata["source_identity"]["unresolved_constructions"] == 0


def test_source_binding_identity_survives_line_movement(run_connector, tmp_path):
    path = tmp_path / "app.py"
    source = "from agents import Agent\nworker = Agent(name='Worker', tools=[])\n"
    path.write_text(source)
    before, _ = _scan(run_connector, tmp_path, agent_granularity="source")
    path.write_text("# unrelated note\n\n" + source)
    after, _ = _scan(run_connector, tmp_path, agent_granularity="source")
    old, new = _agents(before)["worker"], _agents(after)["worker"]
    assert old.id == new.id and old.resource == new.resource
    assert old.evidence[0].location != new.evidence[0].location


def test_project_granularity_remains_default(run_connector, fixtures, tmp_path):
    shutil.copy(fixtures / "code_source_identity" / "app.py", tmp_path / "app.py")
    findings, _ = _scan(run_connector, tmp_path)
    explicit, _ = _scan(run_connector, tmp_path, agent_granularity="project")
    assert [f.to_dict() for f in findings] == [f.to_dict() for f in explicit]
    assert not _agents(findings)
    assert next(f for f in findings if f.resource_type == "project").kind == Kind.AGENT


@pytest.mark.parametrize(
    "body",
    [
        "Agent(name='Unbound', tools=[])\n",
        "worker = Agent(name='One', tools=[])\nworker = Agent(name='Two', tools=[])\n",
        "if flag:\n    worker = Agent(name='Conditional', tools=[])\n",
        "self.worker = Agent(name='Attribute', tools=[])\n",
        "def build():\n    global worker\n    worker = Agent(name='Global', tools=[])\n",
        "def build():\n    worker = Agent(name='First', tools=[])\ndef build():\n    worker = Agent(name='Second', tools=[])\n",
        "worker = Agent(name='Rebound', tools=[])\nimport unrelated as worker\n",
        "worker = Agent(name='Rebound', tools=[])\nfrom unrelated import other as worker\n",
        "worker = Agent(name='Ambiguous', tools=[])\nfrom unrelated import *\n",
        "worker = Agent(name='Captured', tools=[])\ntry:\n    operation()\nexcept Exception as worker:\n    pass\n",
        "worker = Agent(name='Captured', tools=[])\nmatch value:\n    case worker:\n        pass\n",
    ],
)
def test_unsupported_identities_stay_explicit_project_evidence(run_connector, tmp_path, body):
    (tmp_path / "app.py").write_text("from agents import Agent\n" + body)
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not _agents(findings) and not ctx.stats.incomplete
    project = next(f for f in findings if f.resource_type == "project")
    assert project.kind == Kind.AGENT
    assert project.metadata["source_identity"]["unresolved_constructions"] >= 1
    assert project.metadata["source_identity"]["runtime_instances"] == "not-enumerated"


def test_source_identities_do_not_promote_test_constructions(run_connector, tmp_path):
    (tmp_path / "test_app.py").write_text("from agents import Agent\nworker = Agent(name='Test', tools=[])\n")
    findings, _ = _scan(run_connector, tmp_path, agent_granularity="source")
    assert _agents(findings)["worker"].kind == Kind.FRAMEWORK_USAGE
    findings, _ = _scan(run_connector, tmp_path, agent_granularity="source", include_tests=True)
    assert _agents(findings)["worker"].kind == Kind.AGENT


@pytest.mark.parametrize("invalid", [None, True, 1, "", "file", [], {}])
def test_granularity_is_validated(index, invalid):
    with pytest.raises(ConnectorError, match="agent_granularity must be project or source"):
        FilesystemConnector(ConnectorContext(config={"agent_granularity": invalid}, index=index))


@pytest.mark.parametrize("cls", [GitHubConnector, GitLabConnector])
def test_remote_checkout_forwards_granularity(index, cls):
    connector = cls(ConnectorContext(config={"agent_granularity": "source"}, index=index))
    assert connector._filesystem_options()["agent_granularity"] == "source"


def test_named_identity_pass_has_budget_and_conservative_parse_boundary():
    assert named_construction_spans("invalid(") == {}
    assert named_construction_spans("agent = Agent()", max_ast_nodes=1) == {}
    assert named_construction_spans("agent = Agent()", max_ast_nodes=100) == {(8, 15): "agent"}
    assert named_construction_spans("é = 1; agent = Agent()") == {(15, 22): "agent"}
    assert named_construction_spans("a" * 257 + " = Agent()") == {}


def test_many_non_ascii_calls_on_one_line_keep_exact_offsets():
    source = "é = 'é'; " + "; ".join(f"worker{number} = Agent()" for number in range(100))
    names = named_construction_spans(source)
    assert len(names) == 100
    assert all(source[start:end] == "Agent()" for start, end in names)


@pytest.mark.parametrize("separator", ["\v", "\f", "\x85", "\u2028", "\u2029"])
@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_literal_separators_do_not_shift_named_constructor_spans(separator, newline):
    source = newline.join([f'note = "x{separator}y"', "worker = Agent()", ""])
    names = named_construction_spans(source)
    assert names == {(source.index("Agent()"), source.index("Agent()") + len("Agent()")): "worker"}


@pytest.mark.parametrize("separator", ["\v", "\f", "\x85", "\u2028", "\u2029"])
@pytest.mark.parametrize("granularity", ["project", "source"])
def test_literal_separators_do_not_erase_registered_tool_execution(
    run_connector, tmp_path, separator, granularity
):
    source = (
        "from agents import Agent, function_tool\nimport subprocess\n"
        f'note = "x{separator}y"\n'
        "@function_tool\ndef execute(command: str):\n"
        "    return subprocess.run(command, shell=True)\n"
        'worker = Agent(name="Worker", tools=[execute])\n'
    )
    (tmp_path / "app.py").write_text(source)
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity=granularity)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    assert {"tool-use", "code-exec"} <= set(agents[0].capabilities)
    constructor = next(
        item for item in agents[0].evidence if item.signal == "code:framework.openai-agents-sdk"
    )
    execution = next(item for item in agents[0].evidence if item.signal == "code:heuristic.code-execution")
    assert constructor.location == "app.py:7"
    assert constructor.snippet == 'worker = Agent(name="Worker", tools=[execute])'
    assert execution.location == "app.py:6"
    assert execution.snippet == "return subprocess.run(command, shell=True)"


@pytest.mark.parametrize("options", ["", ", tools=[]", ", tools=()", ", tools={}"])
def test_missing_and_literal_empty_tools_do_not_rescan_the_ast(monkeypatch, options):
    def unexpected(*args, **kwargs):
        pytest.fail("empty registrations must not trigger another full AST/tool pass")

    monkeypatch.setattr(source_identity, "python_tool_regions", unexpected)
    text = f"worker = Agent(name='Worker'{options})\n"
    names = named_construction_spans(text)
    regions = {}
    assert named_construction_spans(text, verified_spans=set(names), tool_regions=regions) == names
    assert len(names) == 1
    assert regions == dict.fromkeys(names, ToolRegions())


def test_nonempty_and_opaque_tools_still_use_the_registration_pass(monkeypatch):
    examined = []
    passes = []

    def inspect(text, tree, constructors, registrations, dispatch_calls, *, each, **_):
        passes.append(len(constructors))
        for call, _ in constructors:
            examined.append(call)
            each[id(call)] = ToolRegions()
        return ToolRegions()

    monkeypatch.setattr(source_identity, "python_tool_regions", inspect)
    text = "first = Agent(tools=[helper])\nsecond = Agent(tools=dynamic_tools)\n"
    names = named_construction_spans(text)
    regions = {}
    named_construction_spans(text, verified_spans=set(names), tool_regions=regions)
    assert len(examined) == 2
    assert passes == [2]  # both constructions share one whole-file pass
    assert regions == dict.fromkeys(names, ToolRegions())


def test_many_empty_tool_constructions_keep_bounded_linear_identity_work(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("large no-tool inventory must not repeat the full AST/tool pass")

    monkeypatch.setattr(source_identity, "python_tool_regions", unexpected)
    text = "from agents import Agent\n" + "".join(f"name{number} = {number}\n" for number in range(9000))
    text += "".join(f"worker{number} = Agent(name='Worker', tools=[])\n" for number in range(500))
    assert sum(1 for _ in ast.walk(ast.parse(text))) < source_identity.DEFAULT_MAX_AST_NODES
    names = named_construction_spans(text)
    assert len(names) == 500
    regions = {}
    started = time.monotonic()
    assert named_construction_spans(text, verified_spans=set(names), tool_regions=regions) == names
    assert time.monotonic() - started < 3
    assert regions == dict.fromkeys(names, ToolRegions())


@pytest.mark.parametrize("tools", ["[helper]", "(helper,)"])
def test_identical_literal_tool_names_in_one_scope_share_the_registration_pass(monkeypatch, tools):
    calls = []

    def inspect(text, tree, constructors, registrations, dispatch_calls, *, each, **_):
        for call, _ in constructors:
            calls.append(call)
            each[id(call)] = ToolRegions(bodies=((1, 2),))
        return ToolRegions(bodies=((1, 2),))

    monkeypatch.setattr(source_identity, "python_tool_regions", inspect)
    text = f"first = Agent(tools={tools})\nsecond = Agent(tools={tools})\n"
    names = named_construction_spans(text)
    regions = {}
    named_construction_spans(text, verified_spans=set(names), tool_regions=regions)
    assert len(calls) == 1
    assert regions == dict.fromkeys(names, ToolRegions(bodies=((1, 2),)))


def test_same_tool_name_in_different_scopes_never_shares_capabilities(run_connector, tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom agents import Agent, function_tool\n"
        "def safe():\n    @function_tool\n    def helper(command: str):\n        return command\n"
        "    first = Agent(tools=[helper])\n    second = Agent(tools=[helper])\n"
        "def unsafe():\n    @function_tool\n    def helper(command: str):\n"
        "        return subprocess.run(command, shell=True)\n"
        "    first = Agent(tools=[helper])\n    second = Agent(tools=[helper])\n"
    )
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = _agents(findings)
    assert set(agents) == {"safe.first", "safe.second", "unsafe.first", "unsafe.second"}
    assert "code-exec" not in agents["safe.first"].capabilities
    assert "code-exec" not in agents["safe.second"].capabilities
    assert "code-exec" in agents["unsafe.first"].capabilities
    assert "code-exec" in agents["unsafe.second"].capabilities


def test_same_literal_tools_in_separate_scopes_each_runs_registration(monkeypatch):
    calls = []

    def inspect(text, tree, constructors, registrations, dispatch_calls, *, each, **_):
        for call, _ in constructors:
            calls.append(call.lineno)
            each[id(call)] = ToolRegions(bodies=((call.lineno, call.lineno + 1),))
        return ToolRegions()

    monkeypatch.setattr(source_identity, "python_tool_regions", inspect)
    text = (
        "def first_scope():\n    first = Agent(tools=[helper])\n    second = Agent(tools=[helper])\n"
        "def second_scope():\n    first = Agent(tools=[helper])\n    second = Agent(tools=[helper])\n"
    )
    names = named_construction_spans(text)
    regions = {}
    named_construction_spans(text, verified_spans=set(names), tool_regions=regions)
    assert len(calls) == 2
    grouped = {name: regions[span] for span, name in names.items()}
    assert grouped["first_scope.first"] == grouped["first_scope.second"]
    assert grouped["second_scope.first"] == grouped["second_scope.second"]
    assert grouped["first_scope.first"] != grouped["second_scope.first"]


def test_unpacked_keyword_registration_cannot_reuse_a_proven_literal_result(monkeypatch):
    original = source_identity.python_tool_regions
    calls = []

    def inspect(*args, **kwargs):
        calls.extend(call for call, _ in args[2])
        return original(*args, **kwargs)

    monkeypatch.setattr(source_identity, "python_tool_regions", inspect)
    text = (
        "import subprocess\ndef helper(command):\n    return subprocess.run(command)\n"
        "first = Agent(tools=[helper])\nsecond = Agent(tools=[helper], **options)\n"
    )
    names = named_construction_spans(text)
    regions = {}
    named_construction_spans(text, verified_spans=set(names), tool_regions=regions)
    grouped = {name: regions[span] for span, name in names.items()}
    assert len(calls) == 2
    assert grouped["first"].bodies
    assert grouped["second"] == ToolRegions()


def test_engine_marks_added_source_agent_shadow_with_exact_inventory(index, fixtures, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copy(fixtures / "code_source_identity" / "app.py", root / "app.py")
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "agents:\n  - id: approved\n    resources: ['repo/app.py#agent:approved']\n"
        "  - id: project\n    resources: ['repo']\n"
    )
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    "code.filesystem",
                    config={"path": str(root), "label": "repo", "agent_granularity": "source"},
                )
            ],
            inventory=[str(inventory)],
        ),
        index,
    ).run()
    assert result.complete
    agents = _agents(result.findings)
    assert agents["approved"].shadow is False and agents["approved"].registry_match == "approved"
    assert agents["added"].shadow is True and agents["added"].registry_match is None


def test_notebooks_keep_project_identity(run_connector, tmp_path):
    import json

    (tmp_path / "app.ipynb").write_text(
        json.dumps(
            {
                "nbformat": 4,
                "nbformat_minor": 5,
                "metadata": {},
                "cells": [
                    {
                        "cell_type": "code",
                        "metadata": {},
                        "execution_count": None,
                        "outputs": [],
                        "source": "from agents import Agent\nworker = Agent(name='Notebook', tools=[])\n",
                    }
                ],
            }
        )
    )
    findings, _ = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not _agents(findings)
    assert (
        next(f for f in findings if f.resource_type == "project").metadata["source_identity"][
            "unresolved_constructions"
        ]
        == 1
    )


@pytest.mark.parametrize("tools", ["TOOLS", "[search.run]", "make_tools()", "[search, lookup]"])
def test_agent_registry_module_stays_complete_in_source_mode(run_connector, tmp_path, tools):
    # A registry of ~100 named agents sharing one tool shape used to repeat a
    # whole-file tool pass per construction and exceed the per-file deadline.
    source = (
        "import subprocess\nfrom agents import Agent, function_tool\n"
        "@function_tool\ndef search(query: str):\n    return subprocess.run(query, shell=True)\n"
        "@function_tool\ndef lookup(key: str):\n    return key\n"
        "def make_tools():\n    return [search]\nTOOLS = [search]\n"
    )
    source += "".join(f"setting_{number} = {number}\n" for number in range(850))
    source += "".join(f"agent_{number} = Agent(name='A{number}', tools={tools})\n" for number in range(100))
    (tmp_path / "registry.py").write_text(source)
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.incomplete and not ctx.stats.errors, ctx.stats.errors
    assert len(_agents(findings)) == 100


_SHARED_TOOL = (
    "import subprocess\nfrom agents import Agent, function_tool\n"
    "@function_tool\ndef lookup(command: str):\n    return subprocess.run(command, shell=True)\n"
    "approved = Agent(name='Approved', tools=[lookup])\n"
)


@pytest.mark.parametrize(
    "other",
    [
        "if True:\n    other = Agent(name='Other', tools=[lookup])\n",
        "Agent(name='Anon', tools=[lookup])\n",
        "other = Agent(name='One', tools=[lookup])\nother = Agent(name='Two', tools=[])\n",
        "TOOLS = [lookup]\nfor _ in range(2):\n    Agent(name='Loop', tools=TOOLS)\n",
        "options = {}\nAgent(name='Opaque', tools=[lookup], **options)\n",
    ],
)
def test_shared_tool_execution_stays_on_the_project_with_unresolved_constructions(index, tmp_path, other):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(_SHARED_TOOL + other)
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text("agents:\n  - id: approved\n    resources: ['repo/app.py#agent:approved']\n")
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    "code.filesystem",
                    config={"path": str(root), "label": "repo", "agent_granularity": "source"},
                )
            ],
            inventory=[str(inventory)],
        ),
        index,
    ).run()
    assert result.complete
    approved = _agents(result.findings)["approved"]
    assert approved.shadow is False and "code-exec" in approved.capabilities
    project = next(f for f in result.findings if f.resource_type == "project")
    assert project.metadata["source_identity"]["unresolved_constructions"] >= 1
    # The unresolved construction registers the same shell tool: its shadow
    # finding must not lose that capability to the approved named agent.
    assert project.shadow is True and {"code-exec", "tool-use"} <= set(project.capabilities)


def test_shared_tool_execution_stays_on_the_project_with_a_dispatch_loop(run_connector, tmp_path):
    (tmp_path / "app.py").write_text(
        _SHARED_TOOL + "import json\nfrom openai import OpenAI\nclient = OpenAI()\n"
        "TOOLS = [{'type': 'function', 'function': {'name': 'lookup', 'parameters': {'type': 'object'}}}]\n"
        "def ask(question):\n    messages = [{'role': 'user', 'content': question}]\n"
        "    for _ in range(6):\n"
        "        response = client.chat.completions.create(model='m', messages=messages, tools=TOOLS)\n"
        "        message = response.choices[0].message\n        messages.append(message)\n"
        "        if not message.tool_calls:\n            return message.content\n"
        "        for call in message.tool_calls:\n"
        "            result = lookup(**json.loads(call.function.arguments))\n"
        "            messages.append({'role': 'tool', 'tool_call_id': call.id, 'content': json.dumps(result)})\n"
    )
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert "code-exec" in _agents(findings)["approved"].capabilities
    project = next(f for f in findings if f.resource_type == "project")
    assert project.kind == Kind.AGENT and "code-exec" in project.capabilities


def test_tool_shared_only_by_named_constructions_moves_to_them(run_connector, tmp_path):
    (tmp_path / "app.py").write_text(
        _SHARED_TOOL + "other = Agent(name='Other', tools=[lookup])\nidle = Agent(name='Idle', tools=[])\n"
    )
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = _agents(findings)
    assert "code-exec" in agents["approved"].capabilities and "code-exec" in agents["other"].capabilities
    assert "code-exec" not in agents["idle"].capabilities
    project = next(f for f in findings if f.resource_type == "project")
    assert project.metadata["source_identity"]["unresolved_constructions"] == 0
    assert "code-exec" not in project.capabilities


def test_shared_tool_execution_stays_on_the_project_with_a_method_registration(run_connector, tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom pydantic_ai import Agent\n"
        "def lookup(command: str):\n    return subprocess.run(command, shell=True)\n"
        "approved = Agent(model='openai:gpt-4o', tools=[lookup])\n"
        "helper = Agent(model='openai:gpt-4o')\nhelper.tool_plain(lookup)\n"
    )
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = _agents(findings)
    assert "code-exec" in agents["approved"].capabilities
    # Later method registration remains project context, so the project keeps
    # the execution capability the helper agent registers.
    project = next(f for f in findings if f.resource_type == "project")
    assert "code-exec" in project.capabilities


def test_shared_tool_registry_reads_each_tool_body_once(monkeypatch):
    # Each construction resolved alone walked every body of a shared TOOLS
    # list again: 100 agents over 40 branching tools exceeded the deadline.
    source = "import subprocess\nfrom agents import Agent, function_tool\n"
    for number in range(40):
        source += f"@function_tool\ndef tool_{number}(command: str):\n"
        source += "".join(
            f"    if command == 'c{branch}':\n        return subprocess.run(['echo', '{branch}'])\n"
            for branch in range(10)
        )
    source += "TOOLS = [" + ", ".join(f"tool_{number}" for number in range(40)) + "]\n"
    source += "".join(f"agent_{number} = Agent(name='A{number}', tools=TOOLS)\n" for number in range(100))
    steps = []
    monkeypatch.setattr(tool_attribution, "pattern_timeout", lambda: steps.append(1))
    names = named_construction_spans(source)
    regions = {}
    named_construction_spans(source, verified_spans=set(names), tool_regions=regions)
    assert len(regions) == 100
    assert all(len(region.bodies) == 40 * 10 for region in regions.values())
    assert len(steps) < sum(1 for _ in ast.walk(ast.parse(source)))


_LOOKUP = (
    "import os\nimport subprocess\nfrom agents import Agent, function_tool\n"
    "@function_tool\ndef lookup(command: str):\n    return subprocess.run(command, shell=True)\n"
)


@pytest.mark.parametrize(
    "other",
    [
        # Constructions whose tools the keyword pass cannot enumerate.
        "def get_tools():\n    return [lookup]\nAgent(name='Anon', tools=get_tools())\n",
        "Agent(name='Anon', tools=[lookup] + [])\n",
        "EXTRA = [lookup]\nAgent(name='Anon', tools=[*EXTRA])\n",
        "class Box:\n    tools = [lookup]\nAgent(name='Anon', tools=Box.tools)\n",
        "def get_tools():\n    return [lookup]\nother = Agent(name='Other', tools=get_tools())\n",
        "other = Agent(name='Other', tools=[lookup] if os.environ.get('X') else [])\n",
        "other = Agent(name='Other', tools=[tool for tool in [lookup]])\n",
        "other = Agent('Other', None, [lookup])\n",
        # Code that obtains the tool, or calls it, outside any construction.
        "from langchain_openai import ChatOpenAI\nmodel = ChatOpenAI(model='gpt-4o').bind_tools([lookup])\n",
        "class Runner:\n    def run(self, command):\n        return lookup(command)\n",
        "def make():\n    return [lambda command: lookup(command)]\nother = Agent(name='Other', tools=make())\n",
        "def dispatch(name, argument):\n    return globals()[name](argument)\n",
    ],
)
def test_tool_other_code_can_obtain_keeps_its_execution_on_the_project(index, tmp_path, other):
    # Only literal tools lists and decorator, method or dispatch registrations
    # kept a tool on the project: a computed collection, a positional list or
    # code outside any construction could reach the tool an approved named
    # agent lists, and the shadow project finding lost its execution capability.
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(_LOOKUP + "approved = Agent(name='Approved', tools=[lookup])\n" + other)
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text("agents:\n  - id: approved\n    resources: ['repo/app.py#agent:approved']\n")
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    "code.filesystem",
                    config={"path": str(root), "label": "repo", "agent_granularity": "source"},
                )
            ],
            inventory=[str(inventory)],
        ),
        index,
    ).run()
    assert result.complete
    approved = _agents(result.findings)["approved"]
    assert approved.shadow is False and "code-exec" in approved.capabilities
    project = next(f for f in result.findings if f.resource_type == "project")
    assert project.shadow is True and {"code-exec", "tool-use"} <= set(project.capabilities)


def test_a_locally_decorated_tool_stays_on_the_project(run_connector, tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom agents import Agent, function_tool\nREGISTRY = []\n"
        "def register(function):\n    REGISTRY.append(function)\n    return function\n"
        "@register\n@function_tool\ndef lookup(command: str):\n    return subprocess.run(command, shell=True)\n"
        "approved = Agent(name='Approved', tools=[lookup])\nother = Agent(name='Other', tools=REGISTRY)\n"
    )
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert "code-exec" in _agents(findings)["approved"].capabilities
    project = next(f for f in findings if f.resource_type == "project")
    assert "code-exec" in project.capabilities


@pytest.mark.parametrize(
    "source",
    [
        # pydantic_ai takes the model positionally and tools only by keyword.
        "import subprocess\nfrom pydantic_ai import Agent\n"
        "def lookup(command: str):\n    return subprocess.run(command, shell=True)\n"
        "approved = Agent('openai:gpt-4o', tools=[lookup])\n"
        "summarizer = Agent('openai:gpt-4o', system_prompt='Summarize')\n",
        # A direct call outside the agents does not register the tool anywhere.
        _LOOKUP + "approved = Agent(name='Approved', tools=[lookup])\n"
        "def main():\n    lookup('ls')\nif __name__ == '__main__':\n    main()\n",
    ],
)
def test_tools_only_named_constructions_reach_leave_the_project(run_connector, tmp_path, source):
    # A positional model string made the whole file opaque, so the project
    # finding of a fully inventoried pydantic_ai module gained code-exec.
    (tmp_path / "app.py").write_text(source)
    findings, ctx = _scan(run_connector, tmp_path, agent_granularity="source")
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert "code-exec" in _agents(findings)["approved"].capabilities
    project = next(f for f in findings if f.resource_type == "project")
    assert project.metadata["source_identity"]["unresolved_constructions"] == 0
    assert "code-exec" not in project.capabilities
