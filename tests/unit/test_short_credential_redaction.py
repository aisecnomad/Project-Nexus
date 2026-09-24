"""A configured secret must not leak through diagnostic text at any length."""

import json

import click
import pytest

from shadowscan.cli import _load_report
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import _parse_mcp_servers, _safe_source_text
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.http import HttpClient
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize


@pytest.mark.parametrize("secret", ["a", "x", "abc", "secret1", "a\n"])
def test_short_configured_credential_withholds_a_diagnostic(secret):
    report = sanitize(({"token": secret}, f"InvalidHeader: {secret!r}"))
    assert report[1] == REDACTED
    assert report[0]["token"] == REDACTED


def test_short_secret_in_named_record_does_not_leak_from_another_field():
    report = sanitize({"name": "access_token", "value": "abc", "error": "Rejected abc by provider"})
    assert report["value"] == REDACTED
    assert report["error"] == REDACTED


def test_invalid_header_name_diagnostic_never_quotes_the_supplied_name():
    with pytest.raises(ValueError) as exc:
        HttpClient("https://example.com", headers={"bad-secret\n": "value"})
    assert "bad-secret" not in str(exc.value)


def test_one_character_secret_cannot_corrupt_trusted_diagnostic_or_finding_schema():
    context = ConnectorContext(config={"token": "a"})
    assert context.sanitize_message("InvalidHeader: a") == f"Inv{REDACTED}lidHe{REDACTED}der: {REDACTED}"
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title="Sample agent", resource="repo", resource_type="repository",
        metadata={"api_key": "a"}, evidence=[Evidence("status", "an agent")],
    )
    assert finding.metadata and "a" not in json.dumps(finding.to_dict()["metadata"])
    assert finding.evidence and finding.evidence[0].signal == REDACTED
    assert "metadata" in finding.to_dict() and "evidence" in finding.to_dict()
    second = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title="Sample agent 2", resource="repo2", resource_type="repository",
        metadata={"api_key": "a"},
    )
    assert finding.id != second.id and finding.id.startswith("ss-") and second.id.startswith("ss-")


def test_short_secret_in_identity_fails_closed_instead_of_colliding():
    with pytest.raises(SanitizationLimitError, match="identity"):
        Finding(
            surface=Surface.CODE, connector="gateway.logs", kind=Kind.AGENT,
            title="Agent", resource="repo", resource_type="repository",
            metadata={"api_key": "a"},
        )


def test_one_character_secret_cannot_corrupt_source_and_mcp_parser_schema():
    source = json.dumps({"mcpServers": {"agent": {
        "command": "python", "env": {"API_KEY": "a"}, "args": ["a"],
    }}})
    assert _safe_source_text("config.json", source) == REDACTED
    entries = _parse_mcp_servers("config.json", source)
    assert len(entries) == 1
    assert {"name", "transport", "command", "args", "url", "secrets_inline", "disabled"} <= entries[0].keys()
    assert entries[0]["args"] == [REDACTED]


def test_unreadable_report_diagnostic_never_echoes_sensitive_filename(tmp_path):
    source = tmp_path / "opaque-private-credential.json"
    source.write_text("{malformed")
    with pytest.raises(click.ClickException) as error:
        _load_report(str(source))
    assert source.name not in str(error.value)
    assert "could not read a ShadowScan JSON report" in str(error.value)


def test_unknown_opaque_sdk_diagnostic_is_not_sent_to_logging_sinks(caplog, monkeypatch):
    unknown = "opaque-synthetic-sdk-credential"
    ctx = ConnectorContext(config={})
    ctx.warn(f"remote SDK returned {unknown}")
    assert unknown not in caplog.text

    def fail_lookup(*args, **kwargs):
        raise ValueError(f"SDK initialization failed: {unknown}")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", fail_lookup)
    Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem")]), SignatureIndex([])).run()
    assert unknown not in caplog.text
