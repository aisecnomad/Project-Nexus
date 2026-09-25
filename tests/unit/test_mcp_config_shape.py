"""Only structurally MCP documents are MCP configurations; only real config files configure coding agents."""

from __future__ import annotations

from shadowscan.connectors.code.filesystem import FilesystemConnector, _parse_mcp_servers
from shadowscan.models import Kind

OPENAPI = '''openapi: 3.0.0
info: {title: Billing API, version: "1.0"}
servers:
  - url: https://billing.example.com/v1
paths:
  /invoices/mcp:
    get: {summary: "Monthly cost projection", responses: {"200": {description: ok}}}
'''


def test_openapi_document_with_servers_and_an_mcp_path_is_not_an_mcp_configuration(tmp_path, run_connector):
    (tmp_path / "openapi.yaml").write_text(OPENAPI)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert findings == []
    assert ctx.stats.errors == []


def test_vscode_mcp_file_with_bare_servers_mapping_is_a_configuration(tmp_path, run_connector):
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(
        '{"servers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]}}}'
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    assert [s["name"] for s in mcp[0].metadata["servers"]] == ["fs"]


def test_nested_mcp_servers_block_in_a_settings_file_is_recognized():
    assert FilesystemConnector._looks_like_mcp_config(
        "settings.json", "settings.json", '{"editor": 1, "mcp": {"servers": {"x": {"command": "npx"}}}}'
    )
    assert FilesystemConnector._looks_like_mcp_config(
        "config.yaml", "config.yaml", "mcp:\n  # tool servers\n  servers:\n    fs:\n      command: npx\n"
    )
    assert not FilesystemConnector._looks_like_mcp_config("openapi.yaml", "openapi.yaml", OPENAPI)
    assert not FilesystemConnector._looks_like_mcp_config(
        "compose.json", "compose.json", '{"servers": [{"url": "https://x"}], "notes": "mcp"}'
    )


def test_parser_accepts_bare_servers_only_when_the_file_is_dedicated_to_mcp():
    document = '{"servers": {"fs": {"command": "npx", "args": ["x"]}}}'
    assert [s["name"] for s in _parse_mcp_servers("mcp.json", document, allow_bare_servers=True)] == ["fs"]
    assert _parse_mcp_servers("service.json", document, allow_bare_servers=False) == []


def test_vendor_hostnames_inside_data_files_do_not_configure_coding_agents(tmp_path, run_connector):
    (tmp_path / "egress-allowlist.yaml").write_text(
        "allowed_hosts:\n  - cursor.sh\n  - api2.cursor.sh\n  - codeium.com\n  - windsurf.com\n"
        "env:\n  - GOOSE_MODEL\n  - CLAUDE_CODE_USE_BEDROCK\n"
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert [f for f in findings if f.kind == Kind.AGENT_CONFIG] == []


def test_real_coding_agent_configuration_files_still_produce_agent_config(tmp_path, run_connector):
    (tmp_path / ".cursor" / "rules").mkdir(parents=True)
    (tmp_path / ".cursor" / "rules" / "style.mdc").write_text("Always use tabs.\n")
    (tmp_path / "CLAUDE.md").write_text("# Project\nRun the tests before committing.\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    titles = {f.title for f in findings if f.kind == Kind.AGENT_CONFIG}
    assert any("Claude Code" in t for t in titles)
    assert any("Cursor" in t for t in titles)
