"""MCP tool discovery: capabilities come from registered server tools, found in one pass."""

from __future__ import annotations

import time

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.mcp_tools import MAX_TOOLS_PER_FILE, MCPToolLimitError, mcp_tool_names
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.risk import assess

SHELL_SERVER = """import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool(description="Run a shell command on the host")
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
"""


def _scan(index, root, files: dict[str, str], **config):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_mcp_description_decorator_preserves_execution_capability(tmp_path, index):
    findings, _ = _scan(index, tmp_path, {"server.py": SHELL_SERVER})
    server = next(f for f in findings if "protocol.mcp" in f.frameworks)
    assert "code-exec" in server.capabilities
    assert server.metadata["mcp_tools"] == ["run"]
    # The project implements the server: the capability and where it is built.
    assert "mcp-server" in server.capabilities
    construction = server.metadata["mcp_server"]["constructions"][0]
    assert (construction["file"], construction["line"], construction["bound"]) == ("server.py", 5, True)
    assert server.title.startswith("MCP server in repository root")


@pytest.mark.parametrize(
    "source",
    [
        'from mcp.server import Server\n\nserver = Server("x")\n',
        'from mcp.server.lowlevel import Server as Low\n\nserver = Low("x")\n',
    ],
)
def test_low_level_server_class_is_bound_to_its_import(tmp_path, index, source):
    findings, ctx = _scan(index, tmp_path, {"server.py": source})
    assert not ctx.stats.incomplete
    server = next(f for f in findings if "protocol.mcp" in f.frameworks)
    assert "mcp-server" in server.capabilities
    [construction] = server.metadata["mcp_server"]["constructions"]
    assert construction["bound"] is True and construction["construct"].endswith(":Server(")


@pytest.mark.parametrize(
    "source",
    [
        'from http.server import HTTPServer as Server\n\nhttpd = Server(("", 8000), None)\n',
        "from aiohttp import web\n\nserver = web.Server(handler)\n",
    ],
)
def test_other_server_classes_are_not_mcp_servers(tmp_path, index, source):
    findings, ctx = _scan(index, tmp_path, {"server.py": source})
    assert not ctx.stats.incomplete
    assert not [f for f in findings if "protocol.mcp" in f.frameworks or "mcp-server" in f.capabilities]


def test_mcp_tools_registered_only_in_tests_imply_no_capabilities(tmp_path, index):
    findings, _ = _scan(
        index,
        tmp_path,
        {
            "server.py": 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("notes")\n\n\n@mcp.tool()\ndef list_notes() -> list[str]:\n    return []\n',
            "tests/test_server.py": 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("t")\n\n\n@mcp.tool()\ndef run_command(cmd: str) -> str:\n    return cmd\n',
        },
    )
    server = next(f for f in findings if "protocol.mcp" in f.frameworks)
    assert server.metadata["mcp_tools"] == ["list_notes"]
    assert "code-exec" not in server.capabilities


def test_mcp_enum_tool_names_are_found_in_one_pass():
    # One pass over 20,000 enum classes takes well under a second; searching the
    # whole text once per enum class took about 10 s for 5,000 and grows with the
    # square. This thread's CPU time ignores scheduling delays on a busy runner.
    enums = "".join(f'class Unused{n}(str, Enum):\n    VALUE = "value_{n}"\n\n' for n in range(20_000))
    text = (
        enums + 'class Tools(str, Enum):\n    READ = "read_file"\n\nTool(name=Tools.READ, description="x")\n'
    )
    started = time.thread_time()
    assert mcp_tool_names(text, max_ast_nodes=500_000) == ["read_file"]
    assert time.thread_time() - started < 10


@pytest.mark.parametrize(
    "documentation",
    [
        '# @mcp.tool(name="execute_shell")\n',
        'EXAMPLE = \'Tool(name="execute_shell", description="test")\'\n',
        "DOCS = '''@mcp.tool(name=\"execute_shell\")'''\n",
    ],
)
def test_documentary_mcp_registrations_cannot_manufacture_capabilities(tmp_path, index, documentation):
    safe = (
        'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("safe")\n'
        "@mcp.tool()\ndef add(a:int,b:int)->int:\n    return a+b\n"
    )
    baseline, _ = _scan(index, tmp_path, {"server.py": safe})
    findings, ctx = _scan(index, tmp_path, {"server.py": safe + documentation})
    before, after = baseline[0], findings[0]
    assert after.metadata["mcp_tools"] == ["add"]
    assert after.capabilities == before.capabilities
    assert assess(after, index).score == assess(before, index).score
    assert not ctx.stats.incomplete


@pytest.mark.parametrize(
    "documentation",
    [
        '// server.registerTool("execute_shell", {}, handler);\n',
        "const example = 'server.registerTool(\"execute_shell\", {}, handler)';\n",
        'const example = `server.registerTool("execute_shell", {}, handler)`;\n',
        '/* server.registerTool("execute_shell", {}, handler); */\n',
        'const example = /server.registerTool("execute_shell", {}, handler)/;\n',
    ],
)
def test_javascript_documentation_is_not_tool_registration(tmp_path, index, documentation):
    source = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const server = new McpServer({name:"safe", version:"1"});\n'
        'server.registerTool("add", {description:"Add"}, async () => ({content:[]}));\n'
    )
    findings, ctx = _scan(index, tmp_path, {"server.ts": source + documentation})
    assert findings[0].metadata["mcp_tools"] == ["add"]
    assert "code-exec" not in findings[0].capabilities
    assert not ctx.stats.incomplete


def test_harmless_named_tool_cannot_remove_shell_capability(tmp_path, index):
    original, _ = _scan(index, tmp_path, {"server.py": SHELL_SERVER})
    findings, ctx = _scan(
        index,
        tmp_path,
        {"server.py": SHELL_SERVER + "\n@mcp.tool()\ndef add(a:int,b:int)->int:\n    return a+b\n"},
    )
    assert findings[0].metadata["mcp_tools"] == ["add", "run"]
    assert "code-exec" in findings[0].capabilities
    assert assess(findings[0], index).score >= assess(original[0], index).score
    assert not ctx.stats.incomplete


def _arithmetic_tools(count: int, start: int = 0) -> str:
    return "".join(
        f"@mcp.tool()\ndef calc_{number}(a:int)->int:\n    return a+{number}\n"
        for number in range(start, start + count)
    )


def test_per_file_tool_limit_marks_coverage_incomplete(tmp_path, index):
    source = (
        'from mcp.server.fastmcp import FastMCP\nimport subprocess\nmcp=FastMCP("ops")\n'
        + _arithmetic_tools(MAX_TOOLS_PER_FILE)
        + "@mcp.tool()\ndef run_command(command:str)->str:\n"
        "    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout\n"
    )
    findings, ctx = _scan(index, tmp_path, {"server.py": source})
    assert ctx.stats.incomplete
    assert any("MCP tool-name limit exceeded" in error for error in ctx.stats.errors)
    assert "code-exec" in findings[0].capabilities


def test_exact_file_tool_limit_is_complete_and_duplicates_consume_no_budget(tmp_path, index):
    source = (
        'from mcp.server.fastmcp import FastMCP\nmcp=FastMCP("ops")\n'
        + _arithmetic_tools(MAX_TOOLS_PER_FILE)
        + '@mcp.tool(name="calc_0")\ndef duplicate()->int:\n    return 0\n'
    )
    _, ctx = _scan(index, tmp_path, {"server.py": source})
    assert not ctx.stats.incomplete


def test_per_project_tool_limit_marks_coverage_incomplete(tmp_path, index):
    files = {
        f"server_{part}.py": 'from mcp.server.fastmcp import FastMCP\nmcp=FastMCP("ops")\n'
        + _arithmetic_tools(70, part * 70)
        for part in range(3)
    }
    findings, ctx = _scan(index, tmp_path, files)
    assert findings and ctx.stats.incomplete
    assert sum("project MCP tool-name limit exceeded" in error for error in ctx.stats.errors) == 1


def test_tool_syntax_tree_limit_is_explicit():
    with pytest.raises(MCPToolLimitError, match="syntax-tree node limit"):
        mcp_tool_names("@mcp.tool()\ndef add():\n    return 1\n", "python", max_ast_nodes=3)


def test_enum_references_do_not_register_unused_members():
    source = (
        'class Tools(str, Enum):\n    ADD = "add"\n    SHELL = "execute_shell"\n'
        'Tool(name=Tools.ADD, description="Arithmetic")\n'
    )
    assert mcp_tool_names(source) == ["add"]


@pytest.mark.parametrize(
    "foreign",
    [
        '@foreign.tool(name="execute_shell")\ndef ordinary():\n    return 1\n',
        'from ordinary import Tool\nt = Tool(name="execute_shell", description="Example")\n',
        'mcp = foreign\n@mcp.tool(name="execute_shell")\ndef ordinary():\n    return 1\n',
        'from ordinary import *\n@mcp.tool(name="execute_shell")\ndef ordinary():\n    return 1\n',
    ],
)
def test_foreign_or_rebound_receivers_cannot_acquire_mcp_registration(tmp_path, index, foreign):
    source = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("safe")\n' + foreign
    findings, ctx = _scan(index, tmp_path, {"server.py": source})
    assert findings and not ctx.stats.incomplete
    assert "code-exec" not in findings[0].capabilities
    assert "mcp_tools" not in findings[0].metadata


def test_aliased_constructor_and_description_options_establish_registration(tmp_path, index):
    source = (
        'from fastmcp import FastMCP as Server\nserver = Server("safe")\n'
        '@server.tool(description="Read a file", name="read_file")\n'
        'async def read(path:str)->str:\n    return "content"\n'
    )
    findings, ctx = _scan(index, tmp_path, {"server.py": source})
    assert not ctx.stats.incomplete
    assert findings[0].metadata["mcp_tools"] == ["read_file"]
    assert "data-access" in findings[0].capabilities


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        (
            "server.py",
            '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("notes")
# Tool(name="run_command", description="example")
example = """
@mcp.tool(name="fetch")
def fetch_example():
    pass
@mcp.tool()
def send_email():
    pass
"""
@mcp.tool(name="read_file")
def read(path):
    return path
''',
        ),
        (
            "server.ts",
            """import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "notes", version: "1" });
// server.registerTool("run_command", {}, async () => ({}));
/* server.tool("fetch", {}, async () => ({})); */
const example = `server.tool("send_email", {}, handler)`;
const schemaExample = "{ name: 'execute_shell', description: 'example' }";
server.registerTool("read_file", {}, async () => ({}));
""",
        ),
    ],
)
def test_mcp_examples_do_not_register_tools_or_capabilities(tmp_path, index, filename, source):
    findings, ctx = _scan(index, tmp_path, {filename: source})
    assert not ctx.stats.errors
    server = next(f for f in findings if "protocol.mcp" in f.frameworks)
    assert server.metadata["mcp_tools"] == ["read_file"]
    assert "data-access" in server.capabilities
    assert not {"code-exec", "browsing", "saas-actions"} & set(server.capabilities)


def test_mcp_enum_extraction_ignores_inert_references_classes_and_members():
    source = '''from enum import Enum
class Unused(str, Enum):
    RUN = "run_command"
# Tool(name=Unused.RUN, description="example")
example = """
class Example(str, Enum):
    FETCH = "fetch"
Tool(name=Example.FETCH, description="example")
"""
class Tools(str, Enum):
    """
    SEND = "send_email"
    """
    READ = "read_file"

Tool(name=Tools.READ, description="Read a file")
'''
    ignored, ambiguous = noncode_ranges(source, "python")
    assert not ambiguous
    assert mcp_tool_names(source, ignore_spans=ignored) == ["read_file"]


def test_mcp_enum_members_only_register_when_referenced():
    source = """class Tools(str, Enum):
    READ = "read_file"
    RUN = "run_command"
    FETCH = "fetch"

Tool(name=Tools.READ, description="Read a file")
Tool(name=Tools.FETCH, description="Fetch a URL")
"""
    ignored, ambiguous = noncode_ranges(source, "python")
    assert not ambiguous
    assert mcp_tool_names(source, ignore_spans=ignored) == ["read_file", "fetch"]
