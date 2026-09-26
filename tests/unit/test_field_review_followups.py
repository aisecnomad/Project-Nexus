"""Regressions from the review of the field-review series (#77).

Each case failed on the merged series: parser limits reported as complete,
quadratic or unbounded work on hostile input, and AI apps, Bedrock agents or
MCP capabilities that stopped being reported.
"""

from __future__ import annotations

import json
import time

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.mcp_tools import mcp_tool_names
from shadowscan.connectors.code.semantic_config import structured_code_matches
from shadowscan.connectors.saas.github_apps import GitHubAppsConnector
from shadowscan.signatures import matcher
from shadowscan.utils.jsonc import load_json_lenient

LIMITS = "structured configuration exceeds parser limits"


def _scan(index, root, files: dict[str, str], **config):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


# ------------------------------------------------------------ parser limits
# Python 3.12+ parses a few thousand JSON levels; this depth exceeds the C
# recursion limit on every supported version.
DEEP_JSON = '{"nodes": [], "pinData": ' + "[" * 200_000 + "]" * 200_000 + "}"
XML_BOMB = (
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
    + "".join(f'<!ENTITY {chr(98 + i)} "' + f"&{chr(97 + i)};" * 10 + '">' for i in range(8))
    + "]><GenAiPlanner>&i;</GenAiPlanner>"
)


@pytest.mark.parametrize(("rel", "text"), [
    ("flows/workflow.json", DEEP_JSON),
    ("flows/workflow.yaml", "a: " + "[" * 3000 + "]" * 3000),
    ("flows/workflow.toml", "x = " + "[" * 5000 + "]" * 5000),
    ("force-app/agent.genAiPlanner-meta.xml", XML_BOMB),
], ids=["json-depth", "yaml-depth", "toml-depth", "xml-expansion"])
def test_parser_limits_are_not_syntax_errors(index, rel, text):
    errors: list[str] = []
    limits: list[str] = []
    assert structured_code_matches(index, rel, text, errors, limits) == []
    assert limits == [LIMITS] and errors == []
    # A caller that does not separate them still fails closed.
    fallback: list[str] = []
    structured_code_matches(index, rel, text, fallback)
    assert fallback == [LIMITS]


def test_parser_limits_keep_an_ordinary_config_scan_incomplete(tmp_path, index):
    _, ctx = _scan(index, tmp_path, {"flows/workflow.json": DEEP_JSON})
    assert ctx.stats.incomplete
    assert any("flows/workflow.json" in error and LIMITS in error for error in ctx.stats.errors)


def test_syntax_errors_in_ordinary_configs_still_only_warn(tmp_path, index):
    _, ctx = _scan(index, tmp_path, {"flows/workflow.json": '{"nodes": '})
    assert not ctx.stats.incomplete and not ctx.stats.errors


# --------------------------------------------------------------------- JSONC
def test_lenient_json_is_linear_on_unterminated_strings():
    # Every quote inside an unterminated string used to restart the string
    # token, so escaped quotes made stripping quadratic in the line length.
    text = '{"a": 1, "b": "' + '\\"' * 50_000 + "\n}"
    started = time.perf_counter()
    with pytest.raises(ValueError):
        load_json_lenient(text)
    assert time.perf_counter() - started < 2


# ----------------------------------------------------------- statement cache
def test_statement_cache_keeps_only_short_statements_within_a_text_budget(index, monkeypatch):
    index._statement_imports.clear()
    index._statement_chars = 0
    long_statement = "from " + "pkg." * 200 + "m import x"
    assert len(long_statement) > matcher._STATEMENT_CACHE_MAX_LENGTH
    expected = [m.signature_id for m in index.match_imports(long_statement, "python")]
    assert [m.signature_id for m in index.match_import_statement(long_statement, "python")] == expected
    assert (long_statement, "python") not in index._statement_imports

    monkeypatch.setattr(matcher, "_STATEMENT_CACHE_MAX_CHARS", 100)
    for number in range(40):
        index.match_import_statement(f"import module_{number}", "python")
        assert index._statement_chars <= 100
        assert index._statement_chars == sum(len(statement) for statement, _ in index._statement_imports)


# ---------------------------------------------------------------- GitHub Apps
def _installations(index, tmp_path, slugs):
    path = tmp_path / "installations.json"
    path.write_text(json.dumps({"installations": [
        {"id": number, "app_id": number, "app_slug": slug, "repository_selection": "all",
         "permissions": {"contents": "write", "pull_requests": "write"}, "events": ["push"],
         "html_url": f"https://github.com/apps/{slug}", "target_type": "Organization"}
        for number, slug in enumerate(slugs, 1)
    ]}))
    ctx = ConnectorContext(config={"input": str(path)}, index=index)
    return {f.metadata["app_slug"]: f for f in GitHubAppsConnector(ctx).run()}


@pytest.mark.parametrize("slug", ["amazon-q-developer", "ellipsis-dev", "mentatbot", "factory-droid"])
def test_ai_coding_agents_are_recognised_by_their_app_slug(index, tmp_path, slug):
    found = _installations(index, tmp_path, [slug, "renovate"])
    assert set(found) == {slug}
    assert found[slug].frameworks and "unrecognized-app" not in found[slug].tags


# --------------------------------------------------------------------- Bedrock
@pytest.mark.parametrize("client", [
    'boto3.client("bedrock-agent-runtime", region_name="us-east-1")',
    'boto3.client(service_name="bedrock-agent-runtime", region_name="us-east-1")',
    'boto3.client(region_name="us-east-1", service_name="bedrock-agent-runtime")',
])
def test_bedrock_agent_clients_corroborate_invoke_agent(tmp_path, index, client):
    findings, _ = _scan(index, tmp_path, {"agent.py": (
        "import boto3\n\n"
        f"client = {client}\n"
        'response = client.invoke_agent(agentId="A1", agentAliasId="B1", sessionId="s", inputText="hi")\n'
    )})
    assert any("cloud.aws-bedrock-agents" in f.frameworks for f in findings)


@pytest.mark.parametrize("text", [
    'boto3.client(service_name="bedrock-agentcore", region_name="us-east-1")',
    "session.client(region_name=region, service_name='bedrock-agentcore-control')",
])
def test_agentcore_clients_match_by_keyword(index, text):
    assert any(m.signature_id == "cloud.aws-bedrock-agents" for m in index.match_code(text, "python"))


# ------------------------------------------------------------------------- MCP
SHELL_SERVER = '''import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool(description="Run a shell command on the host")
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
'''


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
