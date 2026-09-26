"""MCP server capabilities come from the server's own name and arguments."""

from __future__ import annotations

import json

import pytest

from shadowscan.models import Kind


def mcp_capabilities(tmp_path, run_connector, server):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    [finding] = [f for f in findings if f.kind == Kind.MCP_SERVER]
    return set(finding.capabilities) - {"tool-use"}


@pytest.mark.parametrize(("server", "expected"), [
    ({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/code"]}, {"saas-actions"}),
    ({"command": "bash", "args": ["-c", "run-server"]}, {"code-exec"}),
    ({"command": "uvx", "args": ["mcp-server-shell"]}, {"code-exec"}),
    ({"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"]}, {"saas-actions"}),
    ({"command": "docker", "args": ["run", "-i", "--rm", "mcp/docker"]}, {"code-exec"}),
    ({"command": "C:\\Tools\\kubectl-mcp.exe"}, {"code-exec"}),
    # A locally built server is launched by path; that path names the server.
    ({"command": "node", "args": ["/opt/mcp/shell-server/dist/index.js", "--root", "/srv/data"]}, {"code-exec"}),
    ({"command": "python", "args": ["/home/me/mcp/terminal_server.py"]}, {"code-exec"}),
    ({"command": "uv", "args": ["--directory", "/Users/me/mcp-server-shell", "run", "server.py"]}, {"code-exec"}),
    # Vendor compounds of a capability word.
    ({"command": "uvx", "args": ["awslabs.eks-mcp-server@latest", "--allow-write"]}, {"saas-actions"}),
    ({"command": "npx", "args": ["@browsermcp/mcp@latest"]}, {"saas-actions"}),
    ({"command": "npx", "args": ["@browserbasehq/mcp-server-browserbase"]}, {"saas-actions"}),
    ({"command": "npx", "args": ["mcp-code-executor"]}, {"code-exec"}),
])
def test_capabilities_follow_the_server_not_the_launcher(tmp_path, run_connector, server, expected):
    assert mcp_capabilities(tmp_path, run_connector, server) == expected


@pytest.mark.parametrize("server", [
    {"command": "npx", "args": ["-y", "@acme/mcp-executive-summary"]},
    {"command": "uvx", "args": ["mcp-server-fetch", "--notes", "/srv/data/mysql-backups"]},
    {"command": "node", "args": ["./dist/laws-index.js"]},
    {"command": "docker", "args": ["run", "-i", "--rm", "mcp/fetch"]},
])
def test_substrings_paths_and_launchers_do_not_add_capabilities(tmp_path, run_connector, server):
    assert mcp_capabilities(tmp_path, run_connector, server) == set()
