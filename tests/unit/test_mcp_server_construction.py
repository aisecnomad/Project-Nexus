"""MCP server construction: the ``mcp-server`` capability, its corroboration and its metadata.

A project that builds a server with an MCP SDK exposes tools to other agents.
Python and JavaScript constructions are import-bound (so the low-level ``Server``
class is told apart from HTTP servers, also next to an MCP client, and a local
class named like an SDK server is not one); Go, Java, .NET and Rust idioms are
language-gated lexical patterns that need the SDK somewhere in the project
before the capability attaches. Test-only constructions imply nothing, like
other test evidence, and a client configuration is not a server implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.models import Kind

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "mcp" / "servers"
NEAR_MISSES = FIXTURES / "near_misses"

FASTMCP = 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("demo")\n'


def _scan(run_connector, root: Path, **config):
    return run_connector("code.filesystem", path=str(root), use_git=False, **config)


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _project(findings):
    return next(f for f in findings if f.resource_type == "project")


@pytest.mark.parametrize(
    ("language", "constructs", "transports"),
    [
        ("python", ["mcp.server.fastmcp:FastMCP(", "mcp.server.lowlevel:Server("], ["stdio"]),
        (
            "javascript",
            [
                "@modelcontextprotocol/sdk/server/mcp.js:McpServer(",
                "@modelcontextprotocol/sdk/server/index.js:Server(",
            ],
            ["stdio"],
        ),
        ("go", ["server.NewMCPServer(", "mcp.NewServer("], []),
        ("java", ["McpServer.sync(", "McpServer.async("], []),
        ("dotnet", [".AddMcpServer("], []),
        ("rust", ["impl ServerHandler for"], []),
    ],
)
def test_server_constructions_in_six_languages_carry_the_capability(
    run_connector, language, constructs, transports
):
    findings, ctx = _scan(run_connector, FIXTURES / language)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    [finding] = findings
    # An MCP server exposes tools; it does not choose actions, so it is not an agent.
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "protocol.mcp" in finding.frameworks
    assert {"tool-use", "mcp-server"} <= set(finding.capabilities)
    assert finding.title.startswith("MCP server in repository root: Model Context Protocol")
    server = finding.metadata["mcp_server"]
    assert server["languages"] == [language]
    assert server["transports"] == transports
    assert sorted(c["construct"] for c in server["constructions"]) == sorted(constructs)
    assert all(c["language"] == language for c in server["constructions"])
    bound = {c["bound"] for c in server["constructions"]}
    assert bound == ({True} if language in {"python", "javascript"} else {False})
    assert all(isinstance(c["line"], int) and c["line"] > 0 and c["file"] for c in server["constructions"])
    assert "constructions_limited" not in server


def test_bound_construction_replaces_the_lexical_match_of_its_line(run_connector):
    findings, _ = _scan(run_connector, FIXTURES / "python")
    [finding] = findings
    on_construction_line = [
        e for e in finding.evidence if e.signal == "code:protocol.mcp" and e.location == "server.py:5"
    ]
    assert [e.description for e in on_construction_line] == [
        "code pattern matched import-bound MCP server construction: mcp.server.fastmcp:FastMCP("
    ]
    assert all(e.weight == 0.9 for e in on_construction_line)
    # Registrations and transports keep their own evidence but are not constructions.
    constructs = [c["construct"] for c in finding.metadata["mcp_server"]["constructions"]]
    assert not any("tool" in c or "stdio" in c or ".run(" in c for c in constructs)


def test_registrations_and_transports_are_server_evidence_but_not_constructions(run_connector, tmp_path):
    source = (
        "from mcp.server.fastmcp import FastMCP\nfrom mcp.server.sse import SseServerTransport\n"
        'mcp = FastMCP("demo")\nsse = SseServerTransport("/messages/")\n'
        "@mcp.tool()\ndef add(a: int, b: int) -> int:\n    return a + b\n"
        'mcp.run(transport="sse")\n'
    )
    findings, ctx = _scan(run_connector, _write(tmp_path, {"server.py": source}))
    assert not ctx.stats.incomplete
    server = _project(findings).metadata["mcp_server"]
    assert [c["construct"] for c in server["constructions"]] == ["mcp.server.fastmcp:FastMCP("]
    assert server["transports"] == ["http"]
    # The transport call is observed by the binder and the lexical pass alike: one evidence item.
    transports = [e for e in _project(findings).evidence if e.location == "server.py:4"]
    assert len(transports) == 1 and transports[0].signal == "code:protocol.mcp"


@pytest.mark.parametrize(
    ("source", "construct"),
    [
        ('import mcp.server\n\nserver = mcp.server.Server("demo")\n', "mcp.server:Server("),
        ('from mcp.server import Server\n\nserver = Server("demo")\n', "mcp.server:Server("),
        (
            'from mcp.server.lowlevel import Server as Low\n\nserver = Low("demo")\n',
            "mcp.server.lowlevel:Server(",
        ),
        ('from fastmcp import FastMCP as Server\n\nserver = Server("demo")\n', "fastmcp:FastMCP("),
    ],
)
def test_python_low_level_and_aliased_constructions_are_import_bound(
    run_connector, tmp_path, source, construct
):
    findings, ctx = _scan(run_connector, _write(tmp_path, {"server.py": source}))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert "mcp-server" in finding.capabilities
    assert [c["construct"] for c in finding.metadata["mcp_server"]["constructions"]] == [construct]
    assert finding.metadata["mcp_server"]["constructions"][0]["bound"] is True


@pytest.mark.parametrize(
    ("source", "construct"),
    [
        (
            'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n'
            'const server = new Server({ name: "demo", version: "1" }, { capabilities: {} });\n',
            "@modelcontextprotocol/sdk/server/index.js:Server(",
        ),
        (
            'import { FastMCP } from "fastmcp";\nconst server = new FastMCP({ name: "demo", version: "1.0.0" });\n',
            "fastmcp:FastMCP(",
        ),
        (
            'import { MCPServer } from "mcp-framework";\nconst server = new MCPServer({ name: "demo" });\n',
            "mcp-framework:MCPServer(",
        ),
        (
            'import * as sdk from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            'const server = new sdk.McpServer({ name: "demo", version: "1" });\n',
            "@modelcontextprotocol/sdk/server/mcp.js:McpServer(",
        ),
    ],
)
def test_javascript_sdk_constructions_are_import_bound(run_connector, tmp_path, source, construct):
    findings, ctx = _scan(run_connector, _write(tmp_path, {"server.ts": source}))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert "mcp-server" in finding.capabilities
    assert [c["construct"] for c in finding.metadata["mcp_server"]["constructions"]] == [construct]


@pytest.mark.parametrize("fixture", ["http_python", "http_javascript"])
def test_http_server_classes_are_not_mcp_servers(run_connector, fixture):
    findings, ctx = _scan(run_connector, NEAR_MISSES / fixture)
    assert not ctx.stats.incomplete
    assert findings == []


MCP_CLIENT_PY = "from mcp import ClientSession\nfrom mcp.client.stdio import stdio_client\n"
MCP_CLIENT_TS = 'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'


@pytest.mark.parametrize(
    "files",
    [
        {"client.py": MCP_CLIENT_PY, "web.py": "from aiohttp import web\n\nserver = web.Server(handler)\n"},
        {
            "client.py": MCP_CLIENT_PY,
            "serve.py": 'from socketserver import TCPServer as Server\n\nhttpd = Server(("", 8000), Handler)\n',
        },
        {
            "client.ts": MCP_CLIENT_TS,
            "io.ts": 'import { Server } from "socket.io";\n\nconst io = new Server(httpServer);\n',
        },
    ],
    ids=["aiohttp", "socketserver", "socket.io"],
)
def test_an_mcp_client_next_to_an_http_or_socket_server_class_is_not_a_server(run_connector, tmp_path, files):
    # The client import is library evidence for protocol.mcp, so the ambiguous
    # ``Server(`` pattern is kept as evidence; it must not establish a server.
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert finding.title.startswith("LLM usage in")
    assert "mcp_server" not in finding.metadata
    assert "mcp-server" not in finding.capabilities and "tool-use" in finding.capabilities
    ambiguous = [e for e in finding.evidence if e.description.endswith("Low-level MCP server class: Server(")]
    assert ambiguous and all(e.weight == 0.6 for e in ambiguous)


def test_an_ambiguous_server_class_does_not_suppress_heuristics_of_an_mcp_client(run_connector, tmp_path):
    agent = (
        MCP_CLIENT_PY + "\nconversation_history = []\nwhile True:\n"
        "    result = await session.call_tool('x', {})\n    conversation_history.append(result)\n"
    )
    files = {"agent.py": agent, "web.py": "from aiohttp import web\n\nserver = web.Server(handler)\n"}
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert "memory" in finding.capabilities and "mcp-server" not in finding.capabilities
    assert "mcp_server" not in finding.metadata and finding.title.startswith("LLM usage in")


@pytest.mark.parametrize(
    "files",
    [
        {"src/a.ts": MCP_CLIENT_TS + "class McpServer {}\n\nconst s = new McpServer();\n"},
        {"a.py": MCP_CLIENT_PY + "\n\nclass FastMCP:\n    pass\n\n\nmcp = FastMCP('x')\n"},
    ],
    ids=["javascript", "python"],
)
def test_a_local_class_named_like_an_sdk_server_is_not_a_server(run_connector, tmp_path, files):
    # The binder reads the file and binds nothing; without the SDK's server
    # import in the file, the lexical construction stays evidence only.
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert finding.title.startswith("LLM usage in")
    assert "mcp_server" not in finding.metadata
    assert "mcp-server" not in finding.capabilities
    assert "mcp-server" in finding.metadata["potential_capabilities"]


def test_a_server_import_in_the_file_corroborates_an_unbound_lexical_construction(run_connector, tmp_path):
    files = {"server.py": "from mcp.server.fastmcp import *\n\nmcp = FastMCP('demo')\n"}
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert "mcp-server" in finding.capabilities and finding.title.startswith("MCP server in")
    [construction] = finding.metadata["mcp_server"]["constructions"]
    assert construction["construct"] == "FastMCP(" and construction["bound"] is False


def test_other_languages_idioms_in_a_python_file_match_nothing(run_connector, index, tmp_path):
    # Java and Rust server idioms are gated to their language: in a .py file they
    # are not MCP evidence, lexically or through the connector (the file is not
    # Python either, so the binder leaves it to the lexical pass).
    text = (
        "import io.modelcontextprotocol.server.McpServer;\n"
        "McpSyncServer server = McpServer.sync(transport).build();\n"
        "use rmcp::ServerHandler;\n"
        "impl ServerHandler for Counter {}\n"
    )
    assert not [m for m in index.match_code(text, "python") if m.signature_id == "protocol.mcp"]
    assert not [m for m in index.match_imports(text, "python") if m.signature_id == "protocol.mcp"]
    findings, ctx = _scan(run_connector, _write(tmp_path, {"notes.py": text}))
    assert findings == [] and not ctx.stats.incomplete


@pytest.mark.parametrize("fixture", ["uncorroborated_rust", "uncorroborated_go"])
def test_server_idiom_without_the_sdk_withholds_the_capability(run_connector, fixture):
    findings, ctx = _scan(run_connector, NEAR_MISSES / fixture)
    assert not ctx.stats.incomplete
    # A server idiom with no SDK import or dependency anywhere in the project is
    # an uncorroborated lexical match: it establishes nothing, so the project
    # yields no finding and the withheld evidence is disclosed in a scan note.
    assert findings == []
    notes = [w for w in ctx.stats.warnings if "evidence not reported" in w]
    assert len(notes) == 1 and ("main.go" in notes[0] or "main.rs" in notes[0])


def test_sdk_dependency_corroborates_a_lexical_construction(run_connector, tmp_path):
    files = {
        "Cargo.toml": '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nrmcp = "0.3"\n',
        "src/main.rs": (NEAR_MISSES / "uncorroborated_rust" / "main.rs").read_text(),
    }
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert "mcp-server" in finding.capabilities
    assert finding.metadata["mcp_server"]["languages"] == ["rust"]


def test_test_only_constructions_imply_no_server_unless_tests_are_included(run_connector, tmp_path):
    files = {"tests/test_server.py": FASTMCP, "client.py": "from mcp.client.stdio import stdio_client\n"}
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert "mcp-server" not in finding.capabilities
    assert "mcp-server" in finding.metadata["potential_capabilities"]
    assert "mcp_server" not in finding.metadata and finding.title.startswith("LLM usage in")

    findings, _ = _scan(run_connector, tmp_path, include_tests=True)
    finding = _project(findings)
    assert "mcp-server" in finding.capabilities
    assert [c["file"] for c in finding.metadata["mcp_server"]["constructions"]] == ["tests/test_server.py"]


def test_implemented_server_without_recognised_tools_suppresses_vendor_neutral_heuristics(
    run_connector, tmp_path
):
    # No tool names are read from Go, so the server's capabilities come from its
    # protocol evidence; a memory idiom describes its tools, not an agent, while
    # an execution sink still counts.
    source = (
        (NEAR_MISSES / "uncorroborated_go" / "main.go")
        .read_text()
        .replace(
            "package main\n",
            'package main\n\nimport (\n\t"os/exec"\n\n\t"github.com/mark3labs/mcp-go/server"\n)\n\n'
            "var conversation_history = []string{}\n\nfunc run_shell_command(cmd string) ([]byte, error) {\n"
            '\treturn exec.Command("sh", "-c", cmd).Output()\n}\n',
        )
    )
    findings, ctx = _scan(run_connector, _write(tmp_path, {"main.go": source}))
    assert not ctx.stats.incomplete
    finding = _project(findings)
    assert {"tool-use", "mcp-server", "code-exec"} <= set(finding.capabilities)
    assert "memory" not in finding.capabilities
    assert "memory" in finding.metadata["potential_capabilities"]
    assert finding.kind == Kind.FRAMEWORK_USAGE


def test_construction_list_is_bounded_and_the_bound_is_disclosed(run_connector, tmp_path):
    files = {f"servers/server_{n:02d}.py": FASTMCP for n in range(60)}
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete  # every file was read; only the listing is capped
    server = _project(findings).metadata["mcp_server"]
    assert len(server["constructions"]) == 50 and server["constructions_limited"] is True
    assert server["constructions"][0]["file"] == "servers/server_00.py"


def test_client_configuration_is_not_a_server_implementation(run_connector, tmp_path):
    files = {
        ".mcp.json": '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}',
        "client.py": "from mcp import ClientSession\nfrom mcp.client.stdio import stdio_client\n",
    }
    findings, ctx = _scan(run_connector, _write(tmp_path, files))
    assert not ctx.stats.incomplete
    config = next(f for f in findings if f.kind == Kind.MCP_SERVER)
    assert "mcp-server" not in config.capabilities and "tool-use" in config.capabilities
    client = _project(findings)
    assert "mcp-server" not in client.capabilities
    assert "mcp-server" not in client.metadata.get("potential_capabilities", [])
