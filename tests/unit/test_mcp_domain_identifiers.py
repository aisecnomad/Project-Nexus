"""The ``mcp.<vendor>.<tld>`` host form matches hosts, not dotted identifiers that start with ``mcp``."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.signatures import get_index


def _mcp_hosts(text: str, *, source: bool = False) -> set[str]:
    return {
        m.value
        for m in get_index().match_domains_in_text(text, source=source)
        if m.signature_id == "protocol.mcp"
    }


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
        "mcp.vendor.biz",
    ],
)
@pytest.mark.parametrize("source", [False, True])
def test_mcp_vendor_hosts_match(host: str, source: bool):
    assert _mcp_hosts(f'url = "https://{host}/mcp"', source=source) == {host}


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
        # Words that name properties or methods.
        "mcp.logger.info",
        "mcp.session.page",
        "mcp.server.live",
    ],
)
def test_dotted_identifiers_are_not_hosts(identifier: str):
    assert _mcp_hosts(f"MCP.translator.get({identifier!r}); {identifier}") == set()


@pytest.mark.parametrize(
    "code",
    [
        'MCP.LOGGER.info("x")',
        'mcp.logger.de("starting")',
        "if mcp.client.is_connected():",
        "settings = mcp.config.to_dict()",
        "mcp.session.no = 2",
        "if mcp.session.no == 2:",
        "first = mcp.cache.de[0]",
    ],
)
def test_a_name_that_goes_on_as_code_is_not_a_host(code: str):
    # A call, an index, the rest of a name the host tokenizer stops at, or an assignment follows each.
    assert _mcp_hosts(code) == set()


@pytest.mark.parametrize(
    "code",
    ["y = mcp.result.no", "return mcp.cache.de;", "send(mcp.server.ws, 1)", "@mcp.server.de\ndef f(): pass"],
)
def test_a_property_read_in_source_is_not_a_host(code: str):
    # In program source a host is in a string or a URL; elsewhere in configuration it may stand alone.
    assert _mcp_hosts(code, source=True) == set()


@pytest.mark.parametrize(
    "code",
    [
        'host = "mcp.vendor.de"',
        "const url = `wss://mcp.vendor.de${path}`;",
        "// see https://mcp.vendor.de for the server",
        'client.connect("user@mcp.vendor.de")',
        "MCP_URL = os.environ.get('MCP_URL', 'mcp.vendor.de')",
        "url = base + mcp.vendor.de/mcp",
    ],
)
def test_a_host_in_a_string_or_url_in_source_matches(code: str):
    assert _mcp_hosts(code, source=True) == {"mcp.vendor.de"}


def test_a_bare_host_in_configuration_still_matches():
    assert _mcp_hosts("server: mcp.vendor.de\n") == {"mcp.vendor.de"}


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


def test_objects_named_mcp_in_code_are_not_an_mcp_finding(tmp_path):
    # A Minecraft Coder Pack logger and Python and JavaScript objects called mcp.
    (tmp_path / "Mod.java").write_text(
        'package x;\nclass Mod {\n  void init() { MCP.LOGGER.info("loading"); }\n}\n', encoding="utf-8"
    )
    (tmp_path / "mod.py").write_text(
        "def start(mcp):\n"
        '    mcp.logger.info("starting")\n'
        "    if mcp.client.is_connected():\n"
        "        mcp.session.page = 2\n"
        "        mcp.config.to = mcp.config.to_dict()\n"
        "        return mcp.result.no\n",
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text(
        "export function warm(mcp) {\n  const hit = mcp.cache.de;\n  return mcp.server.live || hit;\n}\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)
    assert result.exit_code == 0, result.output
    assert not [finding for finding in report["findings"] if "protocol.mcp" in finding["frameworks"]]
