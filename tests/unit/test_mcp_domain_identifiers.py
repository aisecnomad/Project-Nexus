"""The ``mcp.<vendor>.<tld>`` host form matches hosts, not dotted identifiers that start with ``mcp``."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.signatures import get_index


def _mcp_hosts(text: str) -> set[str]:
    return {m.value for m in get_index().match_domains_in_text(text) if m.signature_id == "protocol.mcp"}


@pytest.mark.parametrize(
    "host",
    [
        "mcp.zapier.com",  # listed explicitly
        "mcp.acme.com",
        "mcp.acme.dev",
        "mcp.acme.ai",
        "mcp.acme.io",
        "mcp.some-vendor.app",
        # Country-code and other generic top-level domains.
        "mcp.example.de",
        "mcp.ionos.fr",
        "mcp.vendor.us",
        "mcp.vendor.to",
        "mcp.vendor.jp",
        "mcp.vendor.page",
        "mcp.vendor.live",
        "mcp.vendor.info",
    ],
)
def test_mcp_vendor_hosts_match(host: str):
    assert _mcp_hosts(f'url = "https://{host}/mcp"') == {host}


@pytest.mark.parametrize(
    "identifier",
    [
        "mcp.translator.translatekey",
        "mcp.versionlist.loading",
        "mcp.currentversion.id",
        "mcp.options.theme",
        "mcp.server.stdio",
        # Two-letter country codes that are also file extensions or property names, and "host".
        "mcp.server.py",
        "mcp.notes.md",
        "mcp.client.rs",
        "mcp.config.in",
        "mcp.client.id",
        "mcp.config.host",
    ],
)
def test_dotted_identifiers_are_not_hosts(identifier: str):
    assert _mcp_hosts(f"MCP.translator.get({identifier!r}); {identifier}") == set()


def test_a_java_project_with_mcp_translation_keys_is_not_an_mcp_finding(tmp_path):
    (tmp_path / "Frame.java").write_text(
        "class Frame {\n"
        '    void init() { label.setText(translator.translateKey("mcp.translator.translatekey"));\n'
        '        bar.setText(translator.translateKey("mcp.versionlist.loading"));\n'
        '        id.setText(translator.translateKey("mcp.currentversion.id")); }\n'
        "}\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)
    assert not [finding for finding in report["findings"] if "protocol.mcp" in finding["frameworks"]]
