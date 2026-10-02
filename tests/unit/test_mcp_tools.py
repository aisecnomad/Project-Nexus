"""MCP tool discovery: capabilities come from registered server tools, found in one pass."""

from __future__ import annotations

import time

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.mcp_tools import mcp_tool_names
from shadowscan.connectors.code.source_ranges import noncode_ranges

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


def test_mcp_server_without_recognised_tools_keeps_code_execution(tmp_path, index):
    findings, _ = _scan(index, tmp_path, {"server.py": SHELL_SERVER})
    server = next(f for f in findings if "protocol.mcp" in f.frameworks)
    assert "code-exec" in server.capabilities
    assert "mcp_tools" not in server.metadata


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
    assert mcp_tool_names(text) == ["read_file"]
    assert time.thread_time() - started < 10


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
