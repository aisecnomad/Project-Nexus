"""All TOML layouts accepted by the MCP parser must be discoverable."""

from __future__ import annotations

import pytest

from shadowscan.models import Kind


@pytest.mark.parametrize("content", [
    '[mcp_servers]\nactive = {command = "npx"}\n',
    'mcp_servers.active = {command = "npx"}\n',
    '[mcp_servers.active]\ncommand = "npx"\n',
])
def test_valid_toml_mcp_layouts_emit_active_server(tmp_path, run_connector, content):
    (tmp_path / "config.toml").write_text(content)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [finding for finding in findings if finding.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    assert mcp[0].metadata["server_count"] == 1
    assert [server["name"] for server in mcp[0].metadata["servers"]] == ["active"]


@pytest.mark.parametrize("content", [
    '[mcp_servers]\n',
    '[mcp_servers]\narchived = {command = "npx", disabled = true}\n',
    'mcp_servers.archived = {command = "npx", enabled = false}\n',
])
def test_empty_and_disabled_toml_layouts_do_not_emit_mcp(tmp_path, run_connector, content):
    (tmp_path / "config.toml").write_text(content)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind in {Kind.AGENT, Kind.MCP_SERVER}]
