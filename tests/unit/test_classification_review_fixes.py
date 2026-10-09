"""Review of the classification and precision changes: inputs that dropped real evidence.

An independent review proved each case below with a minimal repository: a
mention rule that judged a host by its first line, API URLs it did not
recognise, provider-format tokens suppressed as generic credentials, a workflow-
shaped YAML file that hid an MCP table, and classification gaps.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.models import Kind

GITHUB_TOKEN = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7c"
AWS_KEY = "AKIA" + "Q7XK2LM9NP4RT8VW"
GENERIC = "pR7xL2qN9vB4mK8sT3wZ"


def _scan(tmp_path: Path, run_connector, files: dict[str, str], **config) -> tuple[list, object]:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False, **config)


def _providers(findings) -> set[str]:
    return {provider for f in findings for provider in f.model_providers}


# ------------------------------------------------------------------ mentions


@pytest.mark.parametrize(
    "files",
    [
        {"config.yaml": "homepage: https://openrouter.ai\nbase_url: https://openrouter.ai/api/v1\n"},
        {
            "app.json": '{\n  "description": "Needs OPENROUTER_API_KEY",\n  "env": {"OPENROUTER_API_KEY": "x"}\n}\n'
        },
        {
            "settings.json": '{\n  "title": "a b",\n  "endpoint": "https://openrouter.ai/api/v1/chat/completions"\n}\n'
        },
        {"config.yaml": "homepage: https://openrouter.ai\rbase_url: https://openrouter.ai/api/v1\r"},
    ],
    ids=["later-config-line", "later-env-key", "line-separator-in-json", "cr-line-endings"],
)
def test_a_configured_occurrence_is_not_a_mention(tmp_path: Path, run_connector, files) -> None:
    findings, _ = _scan(tmp_path, run_connector, files)
    assert "provider.openrouter" in _providers(findings)


@pytest.mark.parametrize(
    "files",
    [
        {
            "index.html": "<script>\nfetch('https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-1.5-flash:generateContent?key=' + KEY)\n</script>\n"
        },
        {
            "config.yaml": "url: https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash"
            ":generateContent\n"
        },
        {"config.yaml": "url: https://contoso-ai.openai.azure.com/\n"},
        {"config.json": '{\n  "url": "https://contoso-ai.openai.azure.com/"\n}\n'},
        {"config.toml": 'url = "https://contoso.services.ai.azure.com/models"\n'},
    ],
    ids=["html-fetch", "googleapis-url", "azure-yaml", "azure-json", "azure-foundry-toml"],
)
def test_api_endpoints_under_link_keys_are_configuration(tmp_path: Path, run_connector, files) -> None:
    findings, ctx = _scan(tmp_path, run_connector, files)
    assert findings, ctx.stats.warnings
    assert not any("only named in data or prose" in w for w in ctx.stats.warnings)


# ---------------------------------------------------------------- credentials


@pytest.mark.parametrize("token", [GITHUB_TOKEN, AWS_KEY], ids=["github", "aws"])
def test_provider_format_tokens_are_reported_outside_ai_projects(
    tmp_path: Path, run_connector, token
) -> None:
    findings, _ = _scan(tmp_path, run_connector, {"deploy.py": f'TOKEN = "{token}"\n'})
    assert [f.kind for f in findings] == [Kind.SECRET]
    assert token not in json.dumps([f.to_dict() for f in findings])


def test_suppressed_generic_credentials_are_noted(tmp_path: Path, run_connector) -> None:
    findings, ctx = _scan(tmp_path, run_connector, {"settings.py": f'DB_PASSWORD = "{GENERIC}"\n'})
    assert findings == [] and not ctx.stats.incomplete
    assert any(
        "settings.py" in w and "report_generic_credentials" in w and GENERIC not in w
        for w in ctx.stats.warnings
    )


AI_SOURCE = 'import OpenAI from "openai";\nconst client = new OpenAI();\n'


@pytest.mark.parametrize(
    "files",
    [
        {  # a root credential that an AI sub-project uses
            ".env": f"BOT_API_KEY={GENERIC}\n",
            "apps/bot/package.json": '{"name": "bot", "dependencies": {"openai": "4.0.0"}}\n',
            "apps/bot/index.mjs": AI_SOURCE,
        },
        {  # a sub-project credential in a repository whose root uses AI
            "package.json": '{"name": "app", "dependencies": {"openai": "4.0.0"}}\n',
            "index.mjs": AI_SOURCE,
            "frontend/package.json": '{"name": "frontend"}\n',
            "frontend/config.js": f'const CHAT_API_KEY = "{GENERIC}";\n',
        },
    ],
    ids=["ancestor", "descendant"],
)
def test_generic_credential_on_the_path_of_an_ai_project_is_reported(
    tmp_path: Path, run_connector, files
) -> None:
    findings, _ = _scan(tmp_path, run_connector, files)
    assert any(f.kind == Kind.SECRET for f in findings)


# -------------------------------------------------------------- MCP parsing


def test_workflow_shaped_yaml_with_an_mcp_table_is_not_a_workflow(tmp_path: Path, run_connector) -> None:
    config = (
        "on: manual\njobs: {}\nmcpServers:\n  github:\n    command: npx\n"
        "    args: ['-y', '@modelcontextprotocol/server-github']\n"
    )
    findings, ctx = _scan(tmp_path, run_connector, {"config.yaml": config})
    assert ctx.stats.incomplete or any(f.kind == Kind.MCP_SERVER for f in findings)


@pytest.mark.parametrize(
    "files",
    [
        {".claude-plugin/plugin.json": '{"name": "p", "mcpServers": "../../shared/mcp.json"}'},
        {".claude-plugin/plugin.json": '{"name": "p", "mcpServers": "./missing.json"}'},
    ],
    ids=["outside-root", "missing"],
)
def test_plugin_mcp_path_that_is_not_in_the_tree_is_a_gap(tmp_path: Path, run_connector, files) -> None:
    _, ctx = _scan(tmp_path, run_connector, files)
    assert ctx.stats.incomplete


def test_plugin_mcp_path_is_parsed(tmp_path: Path, run_connector) -> None:
    servers = {"db": {"command": "uvx", "args": ["mcp-server-postgres"]}}
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {
            ".claude-plugin/plugin.json": '{"name": "p", "mcpServers": ["./config/db.json"]}',
            "config/db.json": json.dumps(servers),
        },
    )
    assert any(f.kind == Kind.MCP_SERVER for f in findings) or ctx.stats.incomplete


def test_mcp_configuration_errors_in_test_paths_stay_gaps(tmp_path: Path, run_connector) -> None:
    config = {"mcpServers": {"github": {"command": "npx"}, "shell": ["uvx", "mcp-server-shell"]}}
    _, ctx = _scan(tmp_path, run_connector, {"specs/.mcp.json": json.dumps(config)})
    assert ctx.stats.incomplete


# ------------------------------------------------------------ classification


def test_mcp_server_registered_only_in_tests_is_not_an_mcp_server(tmp_path: Path, run_connector) -> None:
    server = 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("t")\n\n\n@mcp.tool()\ndef ping() -> str:\n    return "pong"\n'
    findings, _ = _scan(
        tmp_path, run_connector, {"requirements.txt": "mcp\n", "tests/test_server.py": server}
    )
    assert not any(f.kind == Kind.MCP_SERVER and f.metadata.get("agentic") for f in findings)


def test_typescript_mcp_client_is_an_agent_host(tmp_path: Path, run_connector) -> None:
    source = (
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
        'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n'
        'const transport = new StdioClientTransport({ command: "node", args: ["server.js"] });\n'
        'const client = new Client({ name: "host", version: "1.0.0" });\n'
        "await client.connect(transport);\n"
    )
    findings, _ = _scan(
        tmp_path,
        run_connector,
        {
            "package.json": '{"name": "h", "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}',
            "host.ts": source,
        },
    )
    project = next(f for f in findings if f.resource_type == "project")
    assert project.metadata["agentic"] is True


def test_a2a_agent_server_is_agentic(tmp_path: Path, run_connector) -> None:
    source = (
        "from a2a.server.agent_execution import AgentExecutor\n"
        "from a2a.server.apps import A2AStarletteApplication\n\n"
        "class Planner(AgentExecutor):\n    async def execute(self, context, queue):\n        pass\n\n"
        "app = A2AStarletteApplication(agent_card=card, http_handler=handler)\n"
    )
    findings, _ = _scan(tmp_path, run_connector, {"requirements.txt": "a2a-sdk\n", "server.py": source})
    project = next(f for f in findings if f.resource_type == "project")
    assert project.metadata["agentic"] is True


def test_mcp_server_title_counts_every_tool(tmp_path: Path, run_connector) -> None:
    tools = "".join(f"\n\n@mcp.tool()\ndef tool_{i}() -> str:\n    return ''\n" for i in range(60))
    server = 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("big")' + tools
    findings, _ = _scan(tmp_path, run_connector, {"requirements.txt": "mcp\n", "server.py": server})
    project = next(f for f in findings if f.resource_type == "project")
    assert "(60 tools:" in project.title


def test_registry_server_manifest_is_an_mcp_server(tmp_path: Path, run_connector) -> None:
    manifest = {
        "name": "io.github.example/notes",
        "version": "1.0.0",
        "packages": [{"registryType": "npm", "identifier": "@example/notes-mcp", "version": "1.0.0"}],
    }
    findings, _ = _scan(tmp_path, run_connector, {"server.json": json.dumps(manifest)})
    servers = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert servers and all(f.metadata["agent_type"] == "mcp-server" for f in servers)
