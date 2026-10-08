"""Characterization of MCP configuration parsing: diagnostics, projected fields and their order."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.connectors.code.mcp_config import _parse_mcp_servers
from shadowscan.models import Kind


def _parse(document: object, rel: str = ".mcp.json") -> tuple[list[dict[str, object]], list[str]]:
    errors: list[str] = []
    return _parse_mcp_servers(rel, json.dumps(document), errors), errors


def test_malformed_entry_fields_are_reported_in_field_order() -> None:
    servers, errors = _parse(
        {
            "mcpServers": {
                "broken": {
                    "env": ["A"],
                    "headers": "x",
                    "remotes": ["https://example.invalid"],
                    "url": 7,
                    "command": ["npx"],
                    "packages": [{"registryType": "npm", "identifier": "pkg"}],
                    "args": [1],
                    "type": 3,
                    "disabled": "no",
                }
            }
        }
    )
    assert errors == [
        "MCP env must be an object",
        "MCP headers must be an object",
        "MCP url must be a string",
        "MCP remote entry must be an object",
        "MCP command must be a string",
        "MCP args must be an array of strings",
        "MCP transport must be a string",
        "MCP enabled/disabled flags must be booleans",
    ]
    assert servers == [
        {
            "name": "broken",
            "transport": "unknown",
            "command": None,
            "args": [],
            "url": None,
            "urls": [],
            "env_names": [],
            "headers": [],
            "auto_approve": None,
            "secrets_inline": False,
            "disabled": True,
        }
    ]


def test_projected_server_keeps_its_field_order_and_flags_inline_secrets() -> None:
    token = "ghp_" + "a1B2c3D4e5F6" * 3
    servers, errors = _parse(
        {
            "mcpServers": {
                "github": {
                    "command": "docker",
                    "args": ["run", "--token", token],
                    "env": {"GITHUB_TOKEN": token},
                    "autoApprove": ["list_issues"],
                    "enabled": True,
                }
            }
        }
    )
    assert errors == []
    [server] = servers
    assert list(server) == [
        "name",
        "transport",
        "command",
        "args",
        "url",
        "urls",
        "env_names",
        "headers",
        "auto_approve",
        "secrets_inline",
        "secret_locations",
        "disabled",
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
    servers, errors = _parse(
        {
            "servers": [
                {"name": "remote", "remotes": [{"type": "sse", "url": "https://mcp.example.invalid/sse"}]},
                {"name": "packaged", "packages": [{"registryType": "npm", "identifier": " @scope/pkg "}]},
                {"name": "bad-remote", "remotes": ["https://example.invalid"]},
                "not-an-object",
            ]
        }
    )
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
        [],
        ["MCP mcp field must be an object", "MCP servers must be an object or array"],
    )
    assert _parse({"mcp": {"servers": {"s": {"command": "uvx", "args": None, "env": None}}}}) == (
        [
            {
                "name": "s",
                "transport": "stdio",
                "command": "uvx",
                "args": [],
                "url": None,
                "urls": [],
                "env_names": [],
                "headers": [],
                "auto_approve": None,
                "secrets_inline": False,
                "disabled": False,
            }
        ],
        [],
    )


def test_generic_server_urls_are_not_mcp_configs(tmp_path: Path, run_connector):
    (tmp_path / "settings.json").write_text(
        json.dumps({"servers": {"prod": {"url": "https://api.example.test"}}})
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if f.kind == Kind.MCP_SERVER or "protocol.mcp" in f.frameworks]


def test_explicit_mcp_servers_remain_detected(tmp_path: Path, run_connector):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"servers": {"prod": {"url": "https://api.example.test/mcp"}}})
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    assert [f.metadata["servers"][0]["name"] for f in findings if f.kind == Kind.MCP_SERVER] == ["prod"]


def test_gemini_http_url_is_an_mcp_endpoint(tmp_path: Path, run_connector) -> None:
    (tmp_path / "gemini-extension.json").write_text(
        json.dumps(
            {
                "name": "tracker",
                "version": "1.0.0",
                "mcpServers": {
                    "tracker": {
                        "httpUrl": "https://mcp.example.test/mcp/",
                        "headers": {"Authorization": "Bearer $TRACKER_TOKEN"},
                    }
                },
            }
        )
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    server = mcp[0].metadata["servers"][0]
    assert server["url"] == "https://mcp.example.test/mcp/"
    assert server["transport"] == "http"
    # A shell-style variable reference is not an inline credential.
    assert server["secrets_inline"] is False


def test_conflicting_mcp_url_aliases_are_ambiguous() -> None:
    errors: list[str] = []
    text = json.dumps(
        {"mcpServers": {"x": {"httpUrl": "https://a.example.test/mcp", "url": "https://a.example.test/sse"}}}
    )
    assert _parse_mcp_servers("gemini-extension.json", text, errors) == []
    assert errors == ["MCP server entry contains ambiguous field aliases"]


def test_literal_bearer_token_is_still_inline() -> None:
    errors: list[str] = []
    text = json.dumps(
        {
            "mcpServers": {
                "x": {
                    "httpUrl": "https://a.example.test/mcp",
                    "headers": {"Authorization": "Bearer Zq7xV2mK9pL4wR8tY3nB6cD1"},
                }
            }
        }
    )
    servers = _parse_mcp_servers("gemini-extension.json", text, errors)
    assert not errors
    assert servers[0]["secrets_inline"] is True


WORKFLOW = """name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: example/agent-action@v1
        with:
          prompt: Summarize the new issue.
          settings: |-
            {
              "mcpServers": {
                "tracker": {
                  "command": "docker",
                  "args": ["run", "-i", "--rm", "example/tracker-server"],
                  "env": {"TRACKER_TOKEN": "${{ secrets.TRACKER_TOKEN }}"}
                }
              }
            }
"""


def test_workflow_with_embedded_mcp_settings_reports_the_server(tmp_path: Path, run_connector) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(WORKFLOW)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    server = mcp[0].metadata["servers"][0]
    assert (server["name"], server["command"]) == ("tracker", "docker")
    assert server["env_names"] == ["TRACKER_TOKEN"]
    assert server["secrets_inline"] is False


def test_workflow_prose_mentioning_mcp_servers_is_not_a_config() -> None:
    errors: list[str] = []
    text = 'on: push\njobs:\n  a:\n    steps:\n      - with:\n          prompt: Explain how "mcpServers" works.\n'
    assert _parse_mcp_servers(".github/workflows/docs.yml", text, errors) == []
    assert not errors


def test_unparseable_embedded_mcp_settings_fail_closed() -> None:
    errors: list[str] = []
    text = (
        "on: push\njobs:\n  a:\n    steps:\n      - with:\n          settings: |\n"
        '            {"mcpServers": {"x": ${{ vars.SERVER }} }}\n'
    )
    assert _parse_mcp_servers(".github/workflows/agent.yml", text, errors) == []
    assert errors == ["embedded MCP servers depend on a workflow expression"]


def test_embedded_settings_that_are_not_json_even_after_rendering_fail_closed() -> None:
    errors: list[str] = []
    text = (
        "on: push\njobs:\n  a:\n    steps:\n      - with:\n          settings: |\n"
        '            {"mcpServers": {"x": {"command": "docker"}}, ${{ vars.MORE }}\n'
    )
    assert _parse_mcp_servers(".github/workflows/agent.yml", text, errors) == []
    assert errors == ["invalid embedded MCP configuration syntax"]


SETTINGS_WITH_EXPRESSIONS = """\
on: issues
jobs:
  fix:
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          settings: |-
            {
              // ${{ not an expression in a comment }}
              "debug": ${{ fromJSON(vars.GEMINI_DEBUG || false) }},
              "model": {"maxSessionTurns": ${{ vars.TURNS }}},
              "mcpServers": {
                "github": {
                  "command": "docker",
                  "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"],
                  "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}
                }
              }
            }
"""


def test_expressions_outside_the_servers_do_not_hide_embedded_servers() -> None:
    errors: list[str] = []
    servers = _parse_mcp_servers(".github/workflows/fix.yml", SETTINGS_WITH_EXPRESSIONS, errors)
    assert not errors
    assert [(s["name"], s["command"], s["env_names"]) for s in servers] == [
        ("github", "docker", ["GITHUB_PERSONAL_ACCESS_TOKEN"])
    ]
    assert servers[0]["secrets_inline"] is False


@pytest.mark.parametrize("trigger", ["on: issues", '"on": issues'])
def test_workflow_kept_outside_the_workflows_directory_is_read_as_a_workflow(
    tmp_path: Path, run_connector, trigger: str
) -> None:
    examples = tmp_path / "examples" / "workflows"
    examples.mkdir(parents=True)
    (examples / "fix.yml").write_text(SETTINGS_WITH_EXPRESSIONS.replace("on: issues", trigger))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not ctx.stats.incomplete
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert [s["name"] for s in mcp[0].metadata["servers"]] == ["github"]


def test_boolean_keys_outside_a_workflow_stay_invalid_mcp_yaml() -> None:
    errors: list[str] = []
    text = "on: true\nmcpServers:\n  s:\n    command: docker\n"
    assert _parse_mcp_servers("config/mcp.yaml", text, errors) == []
    assert errors == ["invalid MCP configuration syntax"]


@pytest.mark.parametrize("reference", ["./.mcp.json", ["./.mcp.json", "./extra-mcp.json"]])
@pytest.mark.parametrize("rel", [".claude-plugin/plugin.json", "tools/.codex-plugin/plugin.json"])
def test_plugin_manifest_may_name_its_mcp_configuration_files(rel: str, reference: object) -> None:
    servers, errors = _parse({"name": "plugin", "mcpServers": reference}, rel)
    assert (servers, errors) == ([], [])


def test_plugin_manifest_with_inline_servers_still_reports_them() -> None:
    servers, errors = _parse(
        {"name": "p", "mcpServers": {"s": {"command": "npx"}}}, ".claude-plugin/plugin.json"
    )
    assert not errors
    assert [s["name"] for s in servers] == ["s"]


def test_a_path_is_not_a_server_table_outside_a_plugin_manifest() -> None:
    servers, errors = _parse({"mcpServers": "./.mcp.json"}, ".cursor/mcp.json")
    assert servers == []
    assert errors == ["MCP servers must be an object or array"]


def test_plugin_manifest_reference_keeps_the_scan_complete(tmp_path: Path, run_connector) -> None:
    plugin = tmp_path / "plugin"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "p", "mcpServers": "./.mcp.json"}')
    (plugin / ".mcp.json").write_text('{"mcpServers": {"tracker": {"command": "npx", "args": ["tracker"]}}}')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    servers = [s["name"] for f in findings if f.kind == Kind.MCP_SERVER for s in f.metadata["servers"]]
    assert servers == ["tracker"]


def test_repeated_embedded_server_names_are_kept_apart() -> None:
    errors: list[str] = []
    text = (
        "on: push\njobs:\n  a:\n    steps:\n      - with:\n"
        '          settings: \'{"mcpServers": {"s": {"command": "docker"}}}\'\n'
        "  b:\n    steps:\n      - with:\n"
        '          mcp_config: \'{"mcpServers": {"s": {"command": "npx"}}}\'\n'
    )
    servers = _parse_mcp_servers(".github/workflows/agent.yml", text, errors)
    assert not errors
    assert [(s["name"], s["command"]) for s in servers] == [("s", "docker"), ("s#2", "npx")]


def test_credential_file_path_argument_is_not_an_inline_secret() -> None:
    errors: list[str] = []
    text = json.dumps(
        {
            "mcpServers": {
                "s": {
                    "command": "docker",
                    "args": ["run", "-e", "GOOGLE_APPLICATION_CREDENTIALS=/app/service-account.json", "img"],
                }
            }
        }
    )
    server = _parse_mcp_servers(".mcp.json", text, errors)[0]
    assert not errors
    assert server["secrets_inline"] is False
    # The argument itself stays redacted in published metadata.
    assert "/app/service-account.json" not in json.dumps(server)


@pytest.mark.parametrize(
    "argument",
    [
        "API_KEY=Zq7xV2mK9pL4wR8tY3nB6cD1aB",
        "GOOGLE_APPLICATION_CREDENTIALS=Zq7xV2mK9pL4wR8tY3nB6cD1aB",
    ],
)
def test_literal_credential_argument_is_still_inline(argument: str) -> None:
    errors: list[str] = []
    text = json.dumps({"mcpServers": {"s": {"command": "docker", "args": ["run", "-e", argument]}}})
    server = _parse_mcp_servers(".mcp.json", text, errors)[0]
    assert not errors
    assert server["secrets_inline"] is True
    assert server["secret_locations"] == ["args"]


@pytest.mark.parametrize(
    ("argument", "env"),
    [
        ("${KEY_FILE_CREDENTIALS}:/app/key.json", {"KEY_FILE_CREDENTIALS": "${KEY_FILE_CREDENTIALS}"}),
        ("${{ secrets.TRACKER_TOKEN }}", {"TRACKER_TOKEN": "${{ secrets.TRACKER_TOKEN }}"}),
    ],
)
def test_repeated_variable_reference_is_not_an_inline_secret(argument: str, env: dict[str, str]) -> None:
    errors: list[str] = []
    text = json.dumps(
        {"mcpServers": {"s": {"command": "docker", "args": ["run", "-v", argument], "env": env}}}
    )
    server = _parse_mcp_servers(".mcp.json", text, errors)[0]
    assert not errors
    assert server["secrets_inline"] is False


def test_repeated_literal_env_value_is_still_inline() -> None:
    errors: list[str] = []
    value = "Zq7xV2mK9pL4wR8tY3nB6cD1aB"
    text = json.dumps(
        {
            "mcpServers": {
                "s": {"command": "docker", "args": ["--auth", value], "env": {"TRACKER_TOKEN": value}}
            }
        }
    )
    server = _parse_mcp_servers(".mcp.json", text, errors)[0]
    assert not errors
    assert server["secrets_inline"] is True
    assert value not in json.dumps(server)
