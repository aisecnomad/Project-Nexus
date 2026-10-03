"""Unregistered source helpers are context, not an agent's execution authority."""

from __future__ import annotations

import pytest

from shadowscan.models import Kind
from shadowscan.risk import assess

BASE = 'from agents import Agent\nagent = Agent(name="writer", tools=[])\n'
SHELL = (
    "import subprocess\n"
    "def run_shell_command(cmd: str) -> str:\n"
    "    return subprocess.check_output(cmd, shell=True).decode()\n"
)


def _project(run_connector, tmp_path):
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(finding for finding in findings if finding.resource_type == "project")


@pytest.mark.parametrize("decorated", [False, True])
@pytest.mark.parametrize("separate_file", [False, True])
def test_unused_shell_tool_cannot_add_agent_authority_or_confidence(
    tmp_path, run_connector, decorated, separate_file
):
    (tmp_path / "agent.py").write_text(BASE)
    before = _project(run_connector, tmp_path)
    helper = SHELL
    if decorated:
        helper = "from agents import function_tool\n" + SHELL.replace(
            "def run_shell_command", "@function_tool\ndef run_shell_command"
        )
    (tmp_path / ("operations.py" if separate_file else "agent.py")).write_text(
        helper if separate_file else BASE + helper
    )
    after = _project(run_connector, tmp_path)
    assert after.kind == before.kind == Kind.AGENT
    assert after.capabilities == before.capabilities == []
    assert after.confidence == before.confidence
    assert assess(after).score == assess(before).score
    assert "code-exec" in after.metadata["potential_capabilities"]
    assert "code-exec" in after.metadata["contextual_capabilities"]
    contextual = [
        evidence
        for evidence in after.evidence
        if evidence.attributes.get("capability_basis") == "contextual-unlinked-source"
    ]
    assert contextual and all(evidence.weight == 0 for evidence in contextual)


@pytest.mark.parametrize("collection", ["[run_shell_command]", "TOOLS"])
def test_registered_local_shell_body_remains_execution_capability(tmp_path, run_connector, collection):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, function_tool\n"
        + SHELL.replace("def run_shell_command", "@function_tool\ndef run_shell_command")
        + "TOOLS = [run_shell_command]\n"
        f'agent = Agent(name="operator", tools={collection})\n'
    )
    finding = _project(run_connector, tmp_path)
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)
    assert any(factor.id == "capability:code-exec" for factor in assess(finding).factors)


def test_registered_tool_direct_local_helper_keeps_execution(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent\n"
        + SHELL
        + "def tool(cmd: str):\n    return run_shell_command(cmd)\n"
        + 'agent = Agent(name="operator", tools=[tool])\n'
    )
    finding = _project(run_connector, tmp_path)
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)


def test_registered_pydantic_decorator_connects_its_execution_body(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text(
        'from pydantic_ai import Agent\nagent = Agent("openai:gpt-4o", tools=[])\n'
        + SHELL.replace("def run_shell_command", "@agent.tool_plain\ndef run_shell_command")
    )
    assert {"tool-use", "code-exec"} <= set(_project(run_connector, tmp_path).capabilities)


@pytest.mark.parametrize("opaque", [False, True])
def test_registered_safe_or_imported_tool_does_not_authorize_an_unrelated_sink(
    tmp_path, run_connector, opaque
):
    tool = "from external_tools import lookup\n" if opaque else "def lookup(query: str):\n    return query\n"
    (tmp_path / "agent.py").write_text(
        "from agents import Agent\n" + tool + SHELL + 'agent = Agent(name="operator", tools=[lookup])\n'
    )
    finding = _project(run_connector, tmp_path)
    assert finding.capabilities == ["tool-use"]
    assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    "extra",
    [
        "def unused_nested(cmd):\n        return subprocess.run(cmd, shell=True)\n    return cmd",
        "if False:\n        return subprocess.run(cmd, shell=True)\n    return cmd",
        "while False:\n        return subprocess.run(cmd, shell=True)\n    return cmd",
        "return unknown_factory(lambda: subprocess.run(cmd, shell=True))",
    ],
)
def test_unused_nested_or_constant_dead_sink_remains_context(tmp_path, run_connector, extra):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent\nimport subprocess\ndef lookup(cmd):\n    "
        + extra
        + '\nagent = Agent(name="operator", tools=[lookup])\n'
    )
    finding = _project(run_connector, tmp_path)
    assert finding.capabilities == ["tool-use"]
    assert "code-exec" in finding.metadata["contextual_capabilities"]


def test_rebound_tool_body_is_opaque(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent\n"
        + SHELL
        + "run_shell_command = foreign_tool\n"
        + 'agent = Agent(name="operator", tools=[run_shell_command])\n'
    )
    assert _project(run_connector, tmp_path).capabilities == ["tool-use"]


def test_constant_dead_tool_definition_cannot_connect_a_sink(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent\nimport subprocess\nif False:\n"
        "    def shell(cmd):\n        return subprocess.run(cmd, shell=True)\n"
        'agent = Agent(name="operator", tools=[shell])\n'
    )
    finding = _project(run_connector, tmp_path)
    assert finding.capabilities == ["tool-use"]
    assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    "shadow",
    [
        "def safe(dangerous):\n    return dangerous()\n",
        "def safe():\n    dangerous = lambda: 'safe'\n    return dangerous()\n",
    ],
)
def test_registered_tool_local_binding_cannot_connect_an_outer_shell_helper(tmp_path, run_connector, shadow):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, function_tool\nimport subprocess\n"
        "def dangerous():\n    return subprocess.run(command, shell=True)\n"
        + "@function_tool\n"
        + shadow
        + 'agent = Agent(name="operator", tools=[safe])\n'
    )
    finding = _project(run_connector, tmp_path)
    assert finding.capabilities == ["tool-use"]
    assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize("tools", ["[]", "[shell]"])
def test_concrete_sdk_shell_tool_requires_registration(tmp_path, run_connector, tools):
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import create_agent\nfrom langchain.tools import ShellTool\n"
        f"shell = ShellTool()\nagent = create_agent(model, tools={tools})\n"
    )
    finding = _project(run_connector, tmp_path)
    if tools == "[]":
        assert not {"tool-use", "code-exec"} & set(finding.capabilities)
        assert "code-exec" in finding.metadata["contextual_capabilities"]
    else:
        assert {"tool-use", "code-exec"} <= set(finding.capabilities)


@pytest.mark.parametrize("registered", [False, True])
def test_openai_builtin_execution_tool_requires_registration(tmp_path, run_connector, registered):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, CodeInterpreterTool\ninterpreter = CodeInterpreterTool()\n"
        f'agent = Agent(name="writer", tools={"[interpreter]" if registered else "[]"})\n'
    )
    finding = _project(run_connector, tmp_path)
    assert ("code-exec" in finding.capabilities) is registered
    if not registered:
        assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    ("module", "tool"), [("langchain.tools", "ShellTool"), ("agents", "CodeInterpreterTool")]
)
def test_unused_sdk_execution_tool_factory_cannot_authorize_an_empty_agent(
    tmp_path, run_connector, module, tool
):
    (tmp_path / "agent.py").write_text(
        f"from agents import Agent\nfrom {module} import {tool}\n"
        f"def unused():\n    return {tool}()\n"
        'agent = Agent(name="writer", tools=[])\n'
    )
    finding = _project(run_connector, tmp_path)
    assert not {"tool-use", "code-exec"} & set(finding.capabilities)
    assert "code-exec" in finding.metadata["contextual_capabilities"]
    assert all(
        evidence.weight == 0
        for evidence in finding.evidence
        if evidence.attributes.get("capability_basis") == "contextual-unlinked-source"
    )


def test_mcp_unrelated_maintenance_sink_remains_contextual(tmp_path, run_connector):
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('safe')\n"
        "@mcp.tool()\ndef add(a: int, b: int) -> int:\n    return a + b\n"
        "def maintenance(cmd):\n    return subprocess.run(cmd, shell=True)\n"
    )
    finding = _project(run_connector, tmp_path)
    assert "code-exec" not in finding.capabilities
    assert "code-exec" in finding.metadata["contextual_capabilities"]


def test_registered_tool_direct_nested_helper_keeps_execution(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text(
        "from agents import Agent\nimport subprocess\ndef tool(cmd):\n"
        "    def helper(command):\n        return subprocess.run(command, shell=True)\n"
        "    return helper(cmd)\n"
        'agent = Agent(name="operator", tools=[tool])\n'
    )
    assert {"tool-use", "code-exec"} <= set(_project(run_connector, tmp_path).capabilities)
