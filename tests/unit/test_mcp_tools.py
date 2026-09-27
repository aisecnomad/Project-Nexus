"""MCP tool discovery: capabilities come from registered server tools, found in one pass."""

from __future__ import annotations

import time

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.mcp_tools import mcp_tool_names

SHELL_SERVER = '''import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool(description="Run a shell command on the host")
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
'''


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
    findings, _ = _scan(index, tmp_path, {
        "server.py": 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("notes")\n\n\n@mcp.tool()\ndef list_notes() -> list[str]:\n    return []\n',
        "tests/test_server.py": 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("t")\n\n\n@mcp.tool()\ndef run_command(cmd: str) -> str:\n    return cmd\n',
    })
    server = next(f for f in findings if "protocol.mcp" in f.frameworks)
    assert server.metadata["mcp_tools"] == ["list_notes"]
    assert "code-exec" not in server.capabilities


def test_mcp_enum_tool_names_are_found_in_one_pass():
    enums = "".join(f"class Unused{n}(str, Enum):\n    VALUE = \"value_{n}\"\n\n" for n in range(5_000))
    text = enums + 'class Tools(str, Enum):\n    READ = "read_file"\n\nTool(name=Tools.READ, description="x")\n'
    started = time.perf_counter()
    assert mcp_tool_names(text) == ["read_file"]
    assert time.perf_counter() - started < 1
