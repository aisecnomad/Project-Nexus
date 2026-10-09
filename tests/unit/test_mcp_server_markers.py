"""MCP servers recognised from an SDK's server construct, whatever names their tools have.

On the original benchmark corpus, nine labelled MCP servers were reported as
plain LLM usage: tools registered from a table (`server.registerTool(tool.name,
...)`), the TypeScript SDK's low-level `Server` with a `tools/call` handler, Rust
`rmcp` servers, `FastMCP(...)` built with `Tool.from_function`, and a Go SDK the
signatures did not know. A file that imports an MCP SDK and constructs its
server now marks the project as an MCP server.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.models import Kind

SERVERS = {
    "typescript-table": (
        "server.ts",
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        "const server = new McpServer({ name: 'x', version: '1' });\n"
        "for (const tool of TOOLS) {\n  server.registerTool(tool.name, { description: tool.d }, tool.run);\n}\n",
    ),
    "typescript-low-level": (
        "server.ts",
        'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n'
        'import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";\n'
        "const mcp = new Server({ name: 'x', version: '1' }, { capabilities: { tools: {} } });\n"
        "mcp.setRequestHandler(CallToolRequestSchema, async (request) => run(request));\n",
    ),
    "python-tool-objects": (
        "server.py",
        "from mcp.server.fastmcp import FastMCP\nfrom mcp.server.fastmcp.tools import Tool\n\n"
        "def build():\n    return FastMCP('x', tools=[Tool.from_function(scan)])\n",
    ),
    "python-low-level": (
        "server.py",
        "from mcp.server import Server\n\nserver = Server('x')\n\n\n@server.call_tool()\n"
        "async def call(name, arguments):\n    return []\n",
    ),
    "go-sdk": (
        "main.go",
        'package main\n\nimport "github.com/modelcontextprotocol/go-sdk/mcp"\n\n'
        'func main() {\n\tserver := mcp.NewServer(&mcp.Implementation{Name: "x"}, nil)\n\t_ = server\n}\n',
    ),
    "go-mark3labs": (
        "main.go",
        'package main\n\nimport "github.com/mark3labs/mcp-go/server"\n\n'
        'func main() {\n\ts := server.NewMCPServer("x", "1.0.0")\n\t_ = s\n}\n',
    ),
    "go-thinkinaixyz": (
        "main.go",
        'package main\n\nimport "github.com/ThinkInAIXYZ/go-mcp/server"\n\n'
        "func main() {\n\ts, _ := server.NewServer(transport)\n\t_ = s\n}\n",
    ),
    "rust-rmcp": (
        "main.rs",
        "use rmcp::{ServerHandler, model::ServerInfo};\n\nstruct Srv;\n\n"
        "impl ServerHandler for Srv {\n    fn get_info(&self) -> ServerInfo { ServerInfo::default() }\n}\n",
    ),
}


def _scan(run_connector, root: Path, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return run_connector("code.filesystem", path=str(root), use_git=False)


@pytest.mark.parametrize("case", sorted(SERVERS))
def test_sdk_server_construct_is_an_mcp_server(tmp_path: Path, run_connector, case: str) -> None:
    name, source = SERVERS[case]
    findings, ctx = _scan(run_connector, tmp_path, {name: source})
    assert not ctx.stats.incomplete, ctx.stats.errors
    (project,) = [f for f in findings if f.resource_type == "project"]
    assert project.kind == Kind.MCP_SERVER
    assert (project.metadata["agent_type"], project.metadata["agentic"]) == ("mcp-server", True)
    assert any(e.signal == "mcp-server:implementation" for e in project.evidence)


@pytest.mark.parametrize(
    "source",
    [
        # A client of an MCP server is not a server.
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
        "const client = new Client({ name: 'x', version: '1' });\nawait client.callTool({ name: 'a' });\n",
        # Constructs named in comments and strings construct nothing.
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
        "// const server = new McpServer({ name: 'x' });\n"
        "const help = 'server.setRequestHandler(CallToolRequestSchema, h)';\n",
    ],
    ids=["client", "comment-and-string"],
)
def test_mcp_sdk_use_without_a_server_construct_is_not_a_server(
    tmp_path: Path, run_connector, source
) -> None:
    findings, _ = _scan(run_connector, tmp_path, {"client.ts": source})
    assert not any(f.kind == Kind.MCP_SERVER for f in findings)


def test_server_constructed_only_in_tests_does_not_make_the_project_a_server(
    tmp_path: Path, run_connector
) -> None:
    # The project's own code is an LLM client; the test suite stands up a fake MCP server.
    name, source = SERVERS["typescript-table"]
    app = 'import OpenAI from "openai";\nawait new OpenAI().chat.completions.create({ model: "gpt-4o", messages: [] });\n'
    findings, _ = _scan(run_connector, tmp_path, {f"tests/{name}": source, "src/app.ts": app})
    assert any("provider.openai" in f.model_providers for f in findings)
    assert not any(f.kind == Kind.MCP_SERVER for f in findings)
