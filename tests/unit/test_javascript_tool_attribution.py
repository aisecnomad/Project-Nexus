"""Execution belongs to registered JavaScript tools, not adjacent source code."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import javascript_tool_attribution
from shadowscan.connectors.code.javascript_reachability import JavascriptReachabilityLimit
from shadowscan.connectors.code.javascript_tool_attribution import javascript_tool_regions
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import _javascript_bindings
from shadowscan.models import Kind
from shadowscan.risk import assess

AGENT_IMPORT = "import { Agent, tool, ComputerTool } from '@openai/agents';\n"
MCP_IMPORT = "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
AGENT = "const agent = new Agent({name:'writer', tools:[]});\n"
SERVER = "const server = new McpServer({name:'notes', version:'1'});\n"
SINK = "sandbox.run_code(cmd)"


def _regions(source: str):
    ignored, _ = noncode_ranges(source, "javascript")
    calls, _ = _javascript_bindings(source, ignored)
    agents = [(call.start, call.end) for call in calls if call.binding.symbol == "Agent"]
    servers = [(call.start, call.end) for call in calls if call.binding.symbol == "McpServer"]
    return javascript_tool_regions(source, ignored, agents, servers)


def _connected(source: str, expression: str = SINK) -> bool:
    offset = source.index(expression)
    return any(start <= offset < end for start, end in _regions(source).bodies)


def _project(tmp_path, run_connector, source):
    (tmp_path / "app.ts").write_text(source)
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False
    )
    assert not context.stats.incomplete, context.stats.errors
    return next(finding for finding in findings if finding.resource_type == "project")


@pytest.mark.parametrize(
    "unused",
    [
        "const unused = new CodeInterpreterTool();\n",
        "const unused = new ComputerTool();\n",
        "function run_shell_command(cmd) { return sandbox.run_code(cmd); }\n",
        "const unused = tool({name:'unused', execute:({cmd})=>sandbox.run_code(cmd)});\n",
    ],
)
def test_unused_execution_objects_and_helpers_cannot_raise_agent_authority(tmp_path, run_connector, unused):
    before = _project(tmp_path, run_connector, AGENT_IMPORT + AGENT)
    after = _project(tmp_path, run_connector, AGENT_IMPORT + unused + AGENT)
    assert after.kind == before.kind == Kind.AGENT
    assert after.capabilities == before.capabilities == []
    assert after.confidence == before.confidence
    assert assess(after).score == assess(before).score
    assert "code-exec" in after.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    "definitions, collection, expression",
    [
        ("", "[new CodeInterpreterTool()]", "CodeInterpreterTool"),
        ("const execution = new CodeInterpreterTool();\n", "[execution]", "CodeInterpreterTool"),
        (
            "const execution = new CodeInterpreterTool();\nconst TOOLS = [execution];\n",
            "TOOLS",
            "CodeInterpreterTool",
        ),
        ("", "[new ComputerTool()]", "ComputerTool()"),
        ("", "[tool({name:'shell', execute:({cmd})=>sandbox.run_code(cmd)})]", SINK),
        (
            "const execution = tool({name:'shell', execute:({cmd})=>sandbox.run_code(cmd)});\n",
            "[execution]",
            SINK,
        ),
        ("function execution(cmd) { return sandbox.run_code(cmd); }\n", "[execution]", SINK),
        ("const execution = ({cmd})=>sandbox.run_code(cmd);\n", "[execution]", SINK),
        ("", "{shell:tool({execute:({cmd})=>sandbox.run_code(cmd)})}", SINK),
    ],
)
def test_literal_registered_entries_preserve_execution_regions(definitions, collection, expression):
    source = AGENT_IMPORT + definitions + f"const agent = new Agent({{name:'a', tools:{collection}}});\n"
    assert _connected(source, expression)


@pytest.mark.parametrize(
    "collection",
    [
        "[new CodeInterpreterTool()]",
        "[new ComputerTool()]",
        "[tool({execute:({cmd})=>sandbox.run_code(cmd)})]",
    ],
)
def test_registered_builtin_and_callback_sink_remain_observed(tmp_path, run_connector, collection):
    finding = _project(
        tmp_path,
        run_connector,
        AGENT_IMPORT + f"const agent = new Agent({{name:'a', tools:{collection}}});\n",
    )
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)


def test_bound_builtin_alias_is_connected(tmp_path, run_connector):
    source = "import { Agent, ComputerTool as Desktop } from '@openai/agents';\n" + (
        "const desktop = new Desktop();\nconst agent = new Agent({name:'a', tools:[desktop]});\n"
    )
    assert _connected(source, "Desktop()")
    finding = _project(tmp_path, run_connector, source)
    assert {"tool-use", "code-exec"} <= set(finding.capabilities)


@pytest.mark.parametrize(
    "execute",
    [
        "execute: async ({cmd}) => { return sandbox.run_code(cmd); }",
        "execute: async function({cmd}) { return sandbox.run_code(cmd); }",
        "execute({cmd}) { return sandbox.run_code(cmd); }",
    ],
)
def test_supported_inline_callback_shapes_connect_only_invocations(execute):
    source = AGENT_IMPORT + f"const agent = new Agent({{tools:[tool({{{execute}}})]}});\n"
    assert _connected(source)


def test_direct_local_helper_called_from_registered_callback_is_connected():
    source = AGENT_IMPORT + (
        "function run_shell_command(cmd) { return sandbox.run_code(cmd); }\n"
        "const execution = tool({execute:({cmd})=>run_shell_command(cmd)});\n"
        "const agent = new Agent({tools:[execution]});\n"
    )
    assert _connected(source)


@pytest.mark.parametrize(
    "body",
    [
        "function unused(cmd) { return sandbox.run_code(cmd); } return cmd;",
        "const unused = (cmd) => sandbox.run_code(cmd); return cmd;",
        "const unused = (cmd) => { return sandbox.run_code(cmd); }; return cmd;",
        "return { execute(cmd) { return sandbox.run_code(cmd); } };",
        "if (false) { return sandbox.run_code(cmd); } return cmd;",
        "while (false) { sandbox.run_code(cmd); } return cmd;",
        "return factory(() => sandbox.run_code(cmd));",
    ],
)
def test_unused_nested_or_dead_execution_stays_unlinked(body):
    source = (
        AGENT_IMPORT
        + f"const execution = tool({{execute:({{cmd}})=>{{{body}}}}});\n"
        + ("const agent = new Agent({tools:[execution]});\n")
    )
    assert not _connected(source)


@pytest.mark.parametrize(
    "collection, extra",
    [
        ("dynamicTools", ""),
        ("[...execution]", ""),
        ("{...execution}", ""),
        ("[alias]", "const alias = execution;\n"),
        ("[execution]", "execution = externalTool;\n"),
        ("[execution]", "execution.execute = externalCallback;\n"),
        ("[execution]", "delete execution.execute;\n"),
        ("[execution]", "function unrelated(execution) { return execution; }\n"),
        ("TOOLS", "const TOOLS=[execution];\nTOOLS.pop();\n"),
    ],
)
def test_dynamic_aliased_rebound_or_mutated_registrations_are_opaque(collection, extra):
    source = (
        AGENT_IMPORT
        + "const execution = tool({execute:({cmd})=>sandbox.run_code(cmd)});\n"
        + (extra + f"const agent = new Agent({{tools:{collection}}});\n")
    )
    assert not _connected(source)


@pytest.mark.parametrize("method", ["registerTool", "tool"])
@pytest.mark.parametrize(
    "callback",
    [
        "async ({cmd}) => sandbox.run_code(cmd)",
        "async ({cmd}) => { return sandbox.run_code(cmd); }",
        "function({cmd}) { return sandbox.run_code(cmd); }",
    ],
)
def test_proven_mcp_receiver_connects_registered_callback(method, callback):
    source = MCP_IMPORT + SERVER + f"server.{method}('lookup', {{description:'Look up'}}, {callback});\n"
    assert _connected(source)


@pytest.mark.parametrize("method", ["registerTool", "tool"])
def test_mcp_registered_neutral_tool_name_preserves_actual_execution(tmp_path, run_connector, method):
    source = (
        MCP_IMPORT + SERVER + f"server.{method}('lookup', {{}}, async ({{cmd}})=>sandbox.run_code(cmd));\n"
    )
    finding = _project(tmp_path, run_connector, source)
    assert "code-exec" in finding.capabilities


def test_unused_sink_next_to_mcp_registration_stays_contextual(tmp_path, run_connector):
    source = (
        MCP_IMPORT
        + SERVER
        + "server.registerTool('lookup', {}, async ()=>({content:[]}));\n"
        + ("function run_shell_command(cmd) { return sandbox.run_code(cmd); }\n")
    )
    assert not _connected(source)
    finding = _project(tmp_path, run_connector, source)
    assert "code-exec" not in finding.capabilities
    assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    "prefix, registration",
    [
        ("const server = foreign;\n", "server.registerTool('lookup', {}, ({cmd})=>sandbox.run_code(cmd));"),
        (
            SERVER + "server.registerTool = foreign;\n",
            "server.registerTool('lookup', {}, ({cmd})=>sandbox.run_code(cmd));",
        ),
        (SERVER, "server.registerTool(name, {}, ({cmd})=>sandbox.run_code(cmd));"),
        (SERVER, "server.registerTool('lookup', ...options, ({cmd})=>sandbox.run_code(cmd));"),
        (SERVER, "if (false) { server.registerTool('lookup', {}, ({cmd})=>sandbox.run_code(cmd)); }"),
    ],
)
def test_unproven_or_dead_mcp_registration_cannot_connect_a_sink(prefix, registration):
    assert not _connected(MCP_IMPORT + prefix + registration)


def test_mcp_named_callback_can_resolve_a_stable_local_definition():
    source = (
        MCP_IMPORT
        + "function lookup({cmd}) { return sandbox.run_code(cmd); }\n"
        + SERVER
        + ("server.registerTool('lookup', {}, lookup);\n")
    )
    assert _connected(source)


def test_agent_tool_factory_arguments_do_not_register_deferred_lambda():
    source = AGENT_IMPORT + "const agent = new Agent({tools:[factory(()=>sandbox.run_code(cmd))]});\n"
    assert not _connected(source)


def test_deleted_tool_map_entry_cannot_preserve_execution_authority(tmp_path, run_connector):
    source = AGENT_IMPORT + (
        "const TOOLS = {shell:({cmd})=>sandbox.run_code(cmd)};\n"
        "delete TOOLS.shell;\n"
        "const agent = new Agent({name:'a', tools:TOOLS});\n"
    )
    assert not _connected(source)
    finding = _project(tmp_path, run_connector, source)
    assert "code-exec" not in finding.capabilities
    assert "code-exec" in finding.metadata["contextual_capabilities"]


@pytest.mark.parametrize(
    "mutation",
    [
        "Object.assign(TOOLS, {shell:()=>1});",
        "Object.defineProperty(TOOLS, 'shell', {value:()=>1});",
        "Reflect.deleteProperty(TOOLS, 'shell');",
        "const ALIAS = TOOLS; ALIAS.shell = ()=>1;",
        "mutateExternally(TOOLS);",
    ],
)
def test_tool_collection_escape_and_object_mutations_are_opaque(tmp_path, run_connector, mutation):
    source = AGENT_IMPORT + (
        "const TOOLS = {shell:({cmd})=>sandbox.run_code(cmd)};\n"
        + mutation
        + "\nconst agent = new Agent({name:'a', tools:TOOLS});\n"
    )
    assert not _connected(source)
    assert "code-exec" not in _project(tmp_path, run_connector, source).capabilities


@pytest.mark.parametrize(
    "mutation",
    [
        "Object.assign(execution, {execute:()=>1});",
        "Reflect.deleteProperty(execution, 'execute');",
        "const ALIAS=execution; ALIAS.execute=()=>1;",
        "mutateExternally(execution);",
    ],
)
def test_tool_descriptor_object_mutation_or_alias_is_opaque(mutation):
    source = AGENT_IMPORT + (
        "const execution = tool({execute:({cmd})=>sandbox.run_code(cmd)});\n"
        + mutation
        + "\nconst agent = new Agent({tools:[execution]});\n"
    )
    assert not _connected(source)


@pytest.mark.parametrize("limit", ["MAX_TOOL_NESTING", "MAX_SELECTED_DEFINITIONS"])
def test_registered_helper_graph_limits_fail_closed(monkeypatch, limit):
    monkeypatch.setattr(javascript_tool_attribution, limit, 1)
    source = AGENT_IMPORT + (
        "function leaf(cmd) { return sandbox.run_code(cmd); }\n"
        "function registered(cmd) { return leaf(cmd); }\n"
        "const agent = new Agent({tools:[registered]});\n"
    )
    with pytest.raises(JavascriptReachabilityLimit, match="JavaScript tool .* limit exceeded"):
        _regions(source)
