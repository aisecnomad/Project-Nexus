"""Lexical bindings and evaluated expressions govern local tool attribution."""

from __future__ import annotations

import pytest

SHELL = "import subprocess\ndef dangerous(cmd):\n    return subprocess.run(cmd, shell=True)\n"


def _scan(tmp_path, run_connector, source):
    (tmp_path / "agent.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(finding for finding in findings if finding.resource_type == "project")


def test_global_write_in_another_function_invalidates_an_outer_tool_helper(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\n"
        + SHELL
        + "def disable():\n    global dangerous\n    dangerous = lambda cmd: cmd\n"
        "disable()\ndef tool(cmd):\n    return dangerous(cmd)\n"
        'agent = Agent(name="safe", tools=[tool])\n',
    )
    assert finding.capabilities == ["tool-use"]
    assert "code-exec" in finding.metadata["contextual_capabilities"]


def test_nonlocal_write_invalidates_an_enclosing_tool_helper(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\nimport subprocess\ndef build():\n"
        "    def dangerous(cmd):\n        return subprocess.run(cmd, shell=True)\n"
        "    def disable():\n        nonlocal dangerous\n        dangerous = lambda cmd: cmd\n"
        "    disable()\n    def tool(cmd):\n        return dangerous(cmd)\n"
        '    return Agent(name="safe", tools=[tool])\n',
    )
    assert finding.capabilities == ["tool-use"]
    assert "code-exec" in finding.metadata["contextual_capabilities"]


def test_read_only_global_declaration_preserves_a_registered_helper(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\n"
        + SHELL
        + "def tool(cmd):\n    global dangerous\n    return dangerous(cmd)\n"
        'agent = Agent(name="operator", tools=[tool])\n',
    )
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)


def test_dead_local_assignment_still_shadows_an_outer_helper(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\n"
        + SHELL
        + "def tool(cmd):\n    if False:\n        dangerous = lambda value: value\n"
        "    return dangerous(cmd)\n"
        'agent = Agent(name="opaque", tools=[tool])\n',
    )
    assert finding.capabilities == ["tool-use"]
    assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    "nested",
    [
        "def unused(arg=subprocess.run(cmd, shell=True)):\n        pass",
        "def unused(*, arg=subprocess.run(cmd, shell=True)):\n        pass",
        "unused = lambda arg=subprocess.run(cmd, shell=True): arg",
        "@dangerous(cmd)\n    def unused():\n        pass",
    ],
)
def test_evaluated_nested_defaults_and_decorators_remain_execution(tmp_path, run_connector, nested):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\n"
        + SHELL
        + "def tool(cmd):\n    "
        + nested
        + '\n    return cmd\nagent = Agent(name="operator", tools=[tool])\n',
    )
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)


def test_nested_default_resolves_enclosing_binding_before_parameter_shadow(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\n"
        + SHELL
        + "def tool(cmd):\n    def unused(dangerous=dangerous(cmd)):\n        pass\n"
        '    return cmd\nagent = Agent(name="operator", tools=[tool])\n',
    )
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)


def test_bare_nested_decorator_executes_its_local_body(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\nimport subprocess\ndef tool(cmd):\n"
        "    def decorate(fn):\n        subprocess.run(cmd, shell=True)\n        return fn\n"
        "    @decorate\n    def unused():\n        pass\n"
        '    return cmd\nagent = Agent(name="operator", tools=[tool])\n',
    )
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)


@pytest.mark.parametrize("shell", [False, True])
@pytest.mark.parametrize(
    "constructor",
    [
        'from agents import Agent\nagent = Agent(name="operator", tools=TOOLS)\n',
        "from langchain.agents import create_agent\nagent = create_agent(model, TOOLS)\n",
        "from langchain.agents import initialize_agent\nagent = initialize_agent(TOOLS, model)\n",
        "from langgraph.prebuilt import create_react_agent\nagent = create_react_agent(model, TOOLS)\n",
    ],
)
def test_named_literal_registration_configures_tool_use_and_local_body(
    tmp_path, run_connector, shell, constructor
):
    definition = SHELL if shell else "def dangerous(cmd):\n    return cmd\n"
    finding = _scan(tmp_path, run_connector, definition + "TOOLS = [dangerous]\n" + constructor)
    assert "tool-use" in finding.capabilities
    assert ("code-exec" in finding.capabilities) is shell


@pytest.mark.parametrize(
    "extra",
    ["ALIAS = TOOLS\n", "TOOLS.append(dangerous)\n", "TOOLS[0] = foreign\n", "TOOLS = []\n"],
)
def test_aliased_mutated_or_rebound_literal_tools_remain_opaque(tmp_path, run_connector, extra):
    finding = _scan(
        tmp_path,
        run_connector,
        "from agents import Agent\n"
        + SHELL
        + "TOOLS = [dangerous]\n"
        + extra
        + 'agent = Agent(name="opaque", tools=TOOLS)\n',
    )
    assert not {"tool-use", "code-exec"} & set(finding.capabilities)
    assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    "arguments",
    ["model, tools=[dangerous], **options", "model, tools=[dangerous], tools=[]", "*models, [dangerous]"],
)
def test_ambiguous_constructor_arguments_do_not_connect_a_local_tool_body(tmp_path, run_connector, arguments):
    finding = _scan(
        tmp_path,
        run_connector,
        "from langchain.agents import create_agent\n" + SHELL + f"agent = create_agent({arguments})\n",
    )
    assert not {"tool-use", "code-exec"} & set(finding.capabilities)
    assert "code-exec" in finding.metadata["contextual_capabilities"]
