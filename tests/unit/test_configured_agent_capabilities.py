"""Agent construction and configured workload capabilities are separate claims."""

from __future__ import annotations

import pytest

from shadowscan.models import Kind
from shadowscan.risk import assess


def _scan(tmp_path, run_connector, source, suffix=".py"):
    (tmp_path / f"app{suffix}").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(finding for finding in findings if finding.resource_type == "project")


@pytest.mark.parametrize("value", ["[]", "()", "{}", "None", "False", "[{}]", "{'x': None}", "unknown"])
@pytest.mark.parametrize(
    "source",
    [
        'from agents import Agent\nagent = Agent(name="summarizer", instructions="Summarize", tools=VALUE, handoffs=VALUE)\n',
        'from crewai import Agent\nagent = Agent(role="summarizer", tools=VALUE, allow_delegation=False)\n',
        'from pydantic_ai import Agent\nagent = Agent("openai:gpt-4o", tools=VALUE)\n',
        "from langgraph.prebuilt import create_react_agent\nagent = create_react_agent(model, tools=VALUE, checkpointer=None, store=False)\n",
        "from langchain.agents import create_agent\nagent = create_agent(model, tools=VALUE)\n",
    ],
)
def test_empty_or_disabled_python_options_are_unscored(tmp_path, run_connector, source, value):
    finding = _scan(tmp_path, run_connector, source.replace("VALUE", value))
    assert finding.kind == Kind.AGENT
    assert not {"tool-use", "multi-agent", "memory"} & set(finding.capabilities)
    assert "tool-use" in finding.metadata["potential_capabilities"]
    assert not any(factor.id.startswith("capability:") for factor in assess(finding).factors)


@pytest.mark.parametrize("value", ["[]", "{}", "null", "undefined", "false", "[{}]", "{x: null}", "unknown"])
def test_empty_or_disabled_javascript_options_are_unscored(tmp_path, run_connector, value):
    finding = _scan(
        tmp_path,
        run_connector,
        "import { Agent } from '@openai/agents';\n"
        f"const agent = new Agent({{name: 'summarizer', tools: {value}, handoffs: {value}}});\n",
        ".ts",
    )
    assert finding.kind == Kind.AGENT
    assert not {"tool-use", "multi-agent"} & set(finding.capabilities)
    assert "tool-use" in finding.metadata["potential_capabilities"]
    assert not any(factor.id.startswith("capability:") for factor in assess(finding).factors)


@pytest.mark.parametrize(
    ("source", "capabilities", "suffix"),
    [
        (
            'from agents import Agent\na = Agent(name="router", tools=[lookup], handoffs=[billing])\n',
            {"tool-use", "multi-agent"},
            ".py",
        ),
        (
            'from crewai import Agent\na = Agent(role="researcher", tools=[lookup], allow_delegation=True)\n',
            {"tool-use", "multi-agent"},
            ".py",
        ),
        (
            'from crewai import Agent, Crew\na = Agent(role="helper", tools=[lookup])\nc = Crew(agents=[a])\n',
            {"tool-use", "multi-agent"},
            ".py",
        ),
        (
            'from pydantic_ai import Agent\na = Agent("openai:gpt-4o", tools=[lookup])\n',
            {"tool-use"},
            ".py",
        ),
        (
            "from langgraph.prebuilt import create_react_agent\nfrom langgraph.checkpoint.memory import MemorySaver\na = create_react_agent(model, tools=[], checkpointer=MemorySaver())\n",
            {"memory"},
            ".py",
        ),
        (
            "from langchain.agents import create_agent\na = create_agent(model, [lookup])\n",
            {"tool-use"},
            ".py",
        ),
        (
            "import { Agent } from '@openai/agents';\nconst a = new Agent({name: 'router', tools: [lookup], handoffs: [billing]});\n",
            {"tool-use", "multi-agent"},
            ".ts",
        ),
    ],
)
def test_explicit_positive_options_keep_capabilities(tmp_path, run_connector, source, capabilities, suffix):
    finding = _scan(tmp_path, run_connector, source, suffix)
    assert finding.kind == Kind.AGENT
    assert set(finding.capabilities) == capabilities


@pytest.mark.parametrize("reverse", [False, True])
def test_one_disabled_agent_cannot_erase_another_agents_capabilities(tmp_path, run_connector, reverse):
    calls = [
        'a = Agent(name="router", tools=[lookup], handoffs=[billing])',
        'b = Agent(name="summarizer", tools=None, handoffs=[])',
    ]
    if reverse:
        calls.reverse()
    finding = _scan(tmp_path, run_connector, "from agents import Agent\n" + "\n".join(calls))
    assert set(finding.capabilities) == {"tool-use", "multi-agent"}


@pytest.mark.parametrize(
    ("source", "suffix"),
    [
        (
            'from agents import Agent, Runner\na = Agent(name="helper", tools=[])\nRunner.run_sync(a, "hi", handoffs=[billing], tools=[lookup])\n',
            ".py",
        ),
        (
            "import { Agent, Runner } from '@openai/agents';\nconst a = new Agent({name: 'helper', tools: []});\nRunner.run(a, {handoffs: [billing], tools: [lookup]});\n",
            ".ts",
        ),
    ],
)
def test_runner_options_do_not_describe_agent_construction(tmp_path, run_connector, source, suffix):
    finding = _scan(tmp_path, run_connector, source, suffix)
    assert finding.kind == Kind.AGENT
    assert not {"tool-use", "multi-agent"} & set(finding.capabilities)


def test_unscored_options_do_not_remove_another_files_observed_tool(tmp_path, run_connector):
    (tmp_path / "active.py").write_text(
        'from agents import Agent\na = Agent(name="active", tools=[lookup])\n'
    )
    finding = _scan(
        tmp_path,
        run_connector,
        'from agents import Agent\nb = Agent(name="inactive", tools=[], handoffs=[])\n',
    )
    assert set(finding.capabilities) == {"tool-use"}


def test_delegation_false_does_not_disable_explicit_tools(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        'from crewai import Agent\na = Agent(role="helper", tools=[lookup], allow_delegation=False)\n',
    )
    assert set(finding.capabilities) == {"tool-use"}


@pytest.mark.parametrize(
    "options",
    [
        "tools: [], handoffs: [billing], ...options",
        "tools: [], handoffs: [billing], handoffs: []",
        "tools: [], handoffs: unknown",
        "tools: [], handoffs: [...unknown]",
    ],
)
def test_ambiguous_javascript_handoffs_remain_potential(tmp_path, run_connector, options):
    finding = _scan(
        tmp_path,
        run_connector,
        "import { Agent } from '@openai/agents';\n" + f"new Agent({{{options}}});\n",
        ".ts",
    )
    assert finding.kind == Kind.AGENT and "multi-agent" not in finding.capabilities


def test_independent_tool_construction_keeps_its_specific_capability(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from langchain.agents import create_agent\nfrom langchain.tools import ShellTool\n"
        "shell = ShellTool()\na = create_agent(model, tools=[])\n",
    )
    assert "code-exec" in finding.capabilities
    assert "tool-use" not in finding.capabilities


def test_uncorroborated_lexical_framework_capabilities_remain_potential(tmp_path, run_connector):
    finding = _scan(
        tmp_path, run_connector, "class App { void init() { ChatClient.create(model); } }", ".java"
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in finding.capabilities


@pytest.mark.parametrize("method", ["tool", "tool_plain"])
@pytest.mark.parametrize("options", ["", "()", "(retries=2)"])
def test_pydantic_registered_decorators_keep_tool_capability(tmp_path, run_connector, method, options):
    finding = _scan(
        tmp_path,
        run_connector,
        'from pydantic_ai import Agent\nagent = Agent("openai:gpt-4o", tools=[])\n'
        f"@agent.{method}{options}\nasync def lookup(ticket: str) -> str:\n    return ticket\n",
    )
    assert finding.kind == Kind.AGENT and set(finding.capabilities) == {"tool-use"}
    assert any("Pydantic agent tool registration" in evidence.description for evidence in finding.evidence)


def test_pydantic_direct_function_registration_keeps_tool_capability(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        'from pydantic_ai import Agent as Worker\nagent = Worker("openai:gpt-4o", tools=[])\n'
        "def lookup(ticket: str) -> str:\n    return ticket\nagent.tool_plain(lookup)\n",
    )
    assert set(finding.capabilities) == {"tool-use"}


@pytest.mark.parametrize(
    "registration",
    [
        "@foreign.tool_plain\ndef lookup(ticket):\n    return ticket\n",
        "@foreign.tool_plain()\ndef lookup(ticket):\n    return ticket\n",
        "agent = foreign\n@agent.tool_plain\ndef lookup(ticket):\n    return ticket\n",
        "agent.tool_plain = foreign\n@agent.tool_plain()\ndef lookup(ticket):\n    return ticket\n",
        "@Agent.tool_plain\ndef lookup(ticket):\n    return ticket\n",
        "def configure(agent):\n    @agent.tool_plain\n    def lookup(ticket):\n        return ticket\n",
        "decorator = agent.tool_plain()\n",
        "decorator = agent.tool_plain(retries=2)\n",
    ],
)
def test_foreign_shadowed_or_unused_pydantic_decorators_do_not_grant_tools(
    tmp_path, run_connector, registration
):
    finding = _scan(
        tmp_path,
        run_connector,
        'from pydantic_ai import Agent\nagent = Agent("openai:gpt-4o", tools=[])\n' + registration,
    )
    assert finding.kind == Kind.AGENT
    assert "tool-use" not in finding.capabilities
