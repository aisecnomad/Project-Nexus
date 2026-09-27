"""Characterization of MCP configuration parsing: diagnostics, projected fields and their order."""

from __future__ import annotations

import json

from shadowscan.connectors.code.filesystem import _parse_mcp_servers


def _parse(document: object, rel: str = ".mcp.json") -> tuple[list[dict[str, object]], list[str]]:
    errors: list[str] = []
    return _parse_mcp_servers(rel, json.dumps(document), errors), errors


def test_malformed_entry_fields_are_reported_in_field_order() -> None:
    servers, errors = _parse({"mcpServers": {"broken": {
        "env": ["A"], "headers": "x", "remotes": ["https://example.invalid"], "url": 7,
        "command": ["npx"], "packages": [{"registryType": "npm", "identifier": "pkg"}],
        "args": [1], "type": 3, "disabled": "no",
    }}})
    assert errors == [
        "MCP env must be an object",
        "MCP headers must be an object",
        "MCP url must be a string",
        "MCP command must be a string",
        "MCP args must be an array of strings",
        "MCP transport must be a string",
        "MCP enabled/disabled flags must be booleans",
    ]
    assert servers == [{
        "name": "broken", "transport": "unknown", "command": None, "args": [], "url": None,
        "env_names": [], "headers": [], "auto_approve": None, "secrets_inline": False, "disabled": True,
    }]


def test_projected_server_keeps_its_field_order_and_flags_inline_secrets() -> None:
    token = "ghp_" + "a1B2c3D4e5F6" * 3
    servers, errors = _parse({"mcpServers": {"github": {
        "command": "docker", "args": ["run", "--token", token], "env": {"GITHUB_TOKEN": token},
        "autoApprove": ["list_issues"], "enabled": True,
    }}})
    assert errors == []
    [server] = servers
    assert list(server) == [
        "name", "transport", "command", "args", "url", "env_names", "headers", "auto_approve",
        "secrets_inline", "secret_locations", "disabled",
    ]
    assert server["transport"] == "stdio" and server["env_names"] == ["GITHUB_TOKEN"]
    assert server["secrets_inline"] is True and server["secret_locations"] == ["env", "args"]
    assert token not in json.dumps(server)
    assert server["disabled"] is False


def test_entry_without_command_url_or_package_is_dropped_unless_disabled() -> None:
    servers, errors = _parse(
        {"mcpServers": {"empty": {}, "off": {"disabled": True}, "not-on": {"enabled": False}}},
    )
    assert servers == []
    assert errors == ["MCP server entry has no command, URL, or valid package"]


def test_remote_and_package_entries_define_a_server() -> None:
    servers, errors = _parse({"servers": [
        {"name": "remote", "remotes": [{"type": "sse", "url": "https://mcp.example.invalid/sse"}]},
        {"name": "packaged", "packages": [{"registryType": "npm", "identifier": " @scope/pkg "}]},
        {"name": "bad-remote", "remotes": ["https://example.invalid"]},
        "not-an-object",
    ]})
    assert [server["name"] for server in servers] == ["remote", "packaged"]
    assert servers[0]["url"] == "https://mcp.example.invalid/sse" and servers[0]["transport"] == "http"
    assert servers[1]["transport"] == "unknown"
    assert errors == [
        "MCP server entries must be objects",
        "MCP remote entry must be an object",
        "MCP server entry has no command, URL, or valid package",
    ]


def test_registry_manifest_is_its_own_server_entry() -> None:
    manifest = {"name": "io.example/tool", "packages": [{"registryType": "pypi", "identifier": "tool"}]}
    servers, errors = _parse(manifest, "server.json")
    assert errors == [] and [server["name"] for server in servers] == ["io.example/tool"]


def test_document_shape_errors_stop_parsing() -> None:
    assert _parse_mcp_servers(".mcp.json", "{nope", errors := []) == []
    assert errors == ["invalid MCP configuration syntax"]
    assert _parse([1, 2]) == ([], ["MCP configuration must be an object"])
    assert _parse({"mcp": [], "mcpServers": 5}) == (
        [], ["MCP mcp field must be an object", "MCP servers must be an object or array"],
    )
    assert _parse({"mcp": {"servers": {"s": {"command": "uvx", "args": None, "env": None}}}}) == ([{
        "name": "s", "transport": "stdio", "command": "uvx", "args": [], "url": None,
        "env_names": [], "headers": [], "auto_approve": None, "secrets_inline": False, "disabled": False,
    }], [])
