"""Agent construction and configured workload capabilities are separate claims."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import provider_tools
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


def test_unregistered_tool_construction_keeps_only_contextual_capability(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from langchain.agents import create_agent\nfrom langchain.tools import ShellTool\n"
        "shell = ShellTool()\na = create_agent(model, tools=[])\n",
    )
    assert "code-exec" not in finding.capabilities
    assert "code-exec" in finding.metadata["contextual_capabilities"]
    assert "tool-use" not in finding.capabilities


def test_uncorroborated_lexical_framework_capabilities_remain_potential(tmp_path, run_connector):
    # The project is established by an unrelated SDK; the lexical Spring AI
    # idiom without its dependency is evidence only, so neither the framework
    # nor its tool-use capability is claimed.
    (tmp_path / "requirements.txt").write_text("openai>=1.0\n")
    finding = _scan(
        tmp_path, run_connector, "class App { void init() { ChatClient.create(model); } }", ".java"
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "framework.spring-ai" not in finding.frameworks
    assert finding.metadata["potential_frameworks"] == ["framework.spring-ai"]
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


@pytest.mark.parametrize(
    ("module", "constructor", "method"),
    [("openai", "OpenAI", "chat.completions.create"), ("anthropic", "Anthropic", "messages.create")],
)
@pytest.mark.parametrize("value", ["[]", "()", "{}", "None", "False", "[{}]", "unknown", "load_tools()"])
def test_provider_empty_or_unknown_tools_are_unscored(
    tmp_path, run_connector, module, constructor, method, value
):
    finding = _scan(
        tmp_path,
        run_connector,
        f"from {module} import {constructor}\nclient = {constructor}()\n"
        f'client.{method}(model="example", tools={value})\n',
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert f"provider.{module}" in finding.model_providers
    assert "tool-use" not in finding.capabilities
    assert not any(factor.id == "capability:tool-use" for factor in assess(finding).factors)


@pytest.mark.parametrize(
    "options",
    [
        "tools=[], tool_choice='auto'",
        "tools=[{'function_declarations': []}]",
        "tools=[{'function_declarations': unknown}]",
        "tools=[{'name': 'lookup'}], tool_choice='none'",
        "tools=[{'name': 'lookup'}], tool_choice={'type': 'none'}",
        "tools=[{'name': 'lookup'}], tool_choice=unknown",
        "tools=[{'name': 'lookup'}], tool_choice={'type': unknown, 'name': 'lookup'}",
        "functions=[{'name': 'lookup'}], function_call='none'",
        "tools=[{'name': 'lookup'}], **options",
        "toolConfig={}",
        "toolConfig={'tools': []}",
        "toolConfig={'tools': [{'name': 'lookup'}], 'toolChoice': {'type': 'none'}}",
        "tools=[{'name': 'lookup'}], toolConfig=unknown",
    ],
)
def test_disabled_or_ambiguous_provider_selection_is_unscored(tmp_path, run_connector, options):
    finding = _scan(
        tmp_path,
        run_connector,
        "from openai import OpenAI\nclient = OpenAI()\n"
        f'client.chat.completions.create(model="example", {options})\n',
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" not in finding.capabilities


@pytest.mark.parametrize(
    "options",
    [
        "tools=[{'type': 'function', 'function': {'name': 'lookup'}}]",
        "tools=[{'name': 'lookup', 'input_schema': {'type': 'object'}}], tool_choice={'type': 'auto'}",
        "tools=[{'name': 'lookup'}], tool_choice='required'",
        "tools=[{'name': 'lookup'}], tool_choice={'type': 'function', 'function': {'name': 'lookup'}}",
        "functions=[{'name': 'lookup'}], function_call={'name': 'lookup'}",
        "function_declarations=[{'name': 'lookup'}]",
        "tools=[{'function_declarations': [{'name': 'lookup'}]}]",
        "toolConfig={'tools': [{'toolSpec': {'name': 'lookup'}}]}",
    ],
)
def test_nonempty_enabled_provider_tools_keep_capability(tmp_path, run_connector, options):
    finding = _scan(
        tmp_path,
        run_connector,
        "from openai import OpenAI\nclient = OpenAI()\n"
        f'client.chat.completions.create(model="example", {options})\n',
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" in finding.capabilities


@pytest.mark.parametrize(
    "options",
    [
        "tools: []",
        "tools: null",
        "tools: undefined",
        "tools: false",
        "tools: [{}]",
        "tools: [{functionDeclarations: []}]",
        "tools: [{functionDeclarations: unknown}]",
        "tools: unknown",
        "tools: loadTools()",
        "tools: [{name: 'lookup'}], tool_choice: 'none'",
        "tools: [{name: 'lookup'}], tool_choice: {type: 'none'}",
        "tools: [{name: 'lookup'}], tool_choice: unknown",
        "tools: [{name: 'lookup'}], tool_choice: {type: unknown, name: 'lookup'}",
        "functions: [{name: 'lookup'}], function_call: 'none'",
        "tools: [{name: 'lookup'}], ...options",
        "tools: [{name: 'lookup'}], tools: []",
        "toolConfig: {}",
        "toolConfig: {tools: []}",
        "toolConfig: {tools: [{toolSpec: {name: 'lookup'}}], toolChoice: {type: 'none'}}",
        "tools: [{name: 'lookup'}], toolConfig: unknown",
    ],
)
def test_empty_disabled_or_ambiguous_javascript_provider_tools_are_unscored(tmp_path, run_connector, options):
    finding = _scan(
        tmp_path,
        run_connector,
        f"import OpenAI from 'openai';\nOpenAI.chat.completions.create({{model: 'example', {options}}});\n",
        ".ts",
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" not in finding.capabilities


@pytest.mark.parametrize(
    "options",
    [
        "tools: [{type: 'function', function: {name: 'lookup'}}]",
        "tools: [{name: 'lookup'}], tool_choice: 'required'",
        "tools: [{name: 'lookup'}], tool_choice: {type: 'auto'}",
        "tools: [{name: 'lookup'}], tool_choice: {type: 'function', function: {name: 'lookup'}}",
        "functions: [{name: 'lookup'}], function_call: {name: 'lookup'}",
        "function_declarations: [{name: 'lookup'}]",
        "tools: [{functionDeclarations: [{name: 'lookup'}]}]",
        "toolConfig: {tools: [{toolSpec: {name: 'lookup'}}]}",
    ],
)
def test_nonempty_enabled_javascript_provider_tools_keep_capability(tmp_path, run_connector, options):
    finding = _scan(
        tmp_path,
        run_connector,
        f"import OpenAI from 'openai';\nOpenAI.chat.completions.create({{model: 'example', {options}}});\n",
        ".ts",
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" in finding.capabilities


@pytest.mark.parametrize(
    ("module", "constructor", "method"),
    [("openai", "OpenAI", "chat.completions.create"), ("anthropic", "Anthropic", "messages.create")],
)
@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("declaration", ["tools =", "tools: list[dict] ="])
def test_provider_single_same_scope_literal_schema_preserves_tools(
    tmp_path, run_connector, module, constructor, method, local, declaration
):
    schema = (
        "[{'type': 'function', 'function': {'name': 'lookup'}}]"
        if module == "openai"
        else "[{'name': 'lookup', 'input_schema': {'type': 'object'}}]"
    )
    body = f"{declaration} {schema}\nclient.{method}(model='example', tools=tools)\n"
    if local:
        body = "def run():\n" + "".join(f"    {line}\n" for line in body.splitlines())
    finding = _scan(
        tmp_path, run_connector, f"from {module} import {constructor}\nclient = {constructor}()\n" + body
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" in finding.capabilities


@pytest.mark.parametrize(
    "body",
    [
        "tools = []\nCALL\n",
        "tools = unknown\nCALL\n",
        "tools = load_tools()\nCALL\n",
        "tools = SCHEMA\ntools = []\nCALL\n",
        "tools = SCHEMA\ntools.clear()\nCALL\n",
        "tools = SCHEMA\ntools[0] = {}\nCALL\n",
        "tools = SCHEMA\ndel tools[0]\nCALL\n",
        "tools = SCHEMA\nalias = tools\nalias.clear()\nCALL\n",
        "tools = SCHEMA\nmutate(tools)\nCALL\n",
        "CALL\ntools = SCHEMA\n",
        "tools = SCHEMA\ndef run(tools):\n    CALL\n",
        "tools = SCHEMA\ndef run():\n    CALL\n",
        "tools = SCHEMA\ndef mutate():\n    tools.clear()\nmutate()\nCALL\n",
        "if condition:\n    tools = SCHEMA\nCALL\n",
        "tools = SCHEMA\nfrom foreign import tools\nCALL\n",
        "tools = SCHEMA\nfrom foreign import *\nfrom openai import OpenAI\nclient = OpenAI()\nCALL\n",
    ],
)
def test_provider_unsafe_schema_variable_stays_unscored(tmp_path, run_connector, body):
    source = "from openai import OpenAI\nclient = OpenAI()\n" + body.replace(
        "SCHEMA", "[{'type': 'function', 'function': {'name': 'lookup'}}]"
    ).replace("CALL", "client.chat.completions.create(model='example', tools=tools)")
    finding = _scan(tmp_path, run_connector, source)
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" not in finding.capabilities


@pytest.mark.parametrize(
    "declaration",
    ["const tools = [];", "const tools = unknown;", "const tools = loadTools();"],
)
def test_dynamic_javascript_schema_declarations_remain_supporting(tmp_path, run_connector, declaration):
    finding = _scan(
        tmp_path,
        run_connector,
        "import OpenAI from 'openai';\n"
        f"{declaration}\nOpenAI.chat.completions.create({{model: 'example', tools: tools}});\n",
        ".ts",
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" not in finding.capabilities


@pytest.mark.parametrize("config", [False, True])
def test_repeated_large_empty_schema_stays_within_analysis_budget(
    tmp_path, run_connector, monkeypatch, config
):
    # The whole input fits the AST budget. Reusing one large declaration must
    # not spend its structural budget again for each of the 128 requests.
    schema = "[" + ",".join("{}" for _ in range(9_000)) + "]"
    if config:
        fields = ",".join(f"'unused{number}': None" for number in range(4_000))
        schema = "{" + fields + ", 'tools': " + schema + "}"
    option = "toolConfig" if config else "tools"
    source = (
        "from openai import OpenAI\nclient = OpenAI()\ncatalog = "
        + schema
        + "\n"
        + f"client.chat.completions.create(model='example', {option}=catalog)\n" * 128
    )
    remaining = 300
    timeout = provider_tools.pattern_timeout

    def bounded_analysis():
        nonlocal remaining
        remaining -= 1
        assert remaining >= 0, "shared schema analysis exceeded the per-input structural budget"
        return timeout()

    monkeypatch.setattr(provider_tools, "pattern_timeout", bounded_analysis)
    finding = _scan(tmp_path, run_connector, source)
    assert finding.kind == Kind.FRAMEWORK_USAGE and "tool-use" not in finding.capabilities
