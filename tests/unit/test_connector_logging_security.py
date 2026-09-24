"""Application logs must never depend on upstream diagnostic payloads."""

from __future__ import annotations

import logging

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.models import ScanStats
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize


@pytest.mark.parametrize("warning", [False, True])
@pytest.mark.parametrize("secret", [
    "opaque-sdk-value-without-a-known-prefix",
    "small",
    "sdk-value\nFORGED ERROR: scan succeeded\r",
])
def test_opaque_upstream_values_never_enter_log_records(index, caplog, warning, secret):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="test", started_at="now")
    message = f"remote service rejected supplied value {secret}"
    # This is the real gap: some SDK-owned credentials are unknowable to the
    # general-purpose sanitizer. Logging must be safe even in that case.
    assert secret in ctx.sanitize_message(message)
    (ctx.warn if warning else ctx.error)(message)
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == (logging.WARNING if warning else logging.ERROR)
    assert secret not in repr(record.__dict__)
    assert message not in record.getMessage()
    assert record.args == () and record.exc_info is None and record.stack_info is None
    assert "scan report" in record.getMessage()
    assert ctx.stats.incomplete


@pytest.mark.parametrize("from_environment", [False, True])
def test_private_report_details_still_redact_configured_and_escaped_credentials(index, caplog, monkeypatch,
                                                                             from_environment):
    secret = "opaque-synthetic-secret-with-control\n"
    ctx = ConnectorContext(config={} if from_environment else {"token": secret}, index=index)
    ctx.stats = ScanStats(connector="test", started_at="now")
    if from_environment:
        monkeypatch.setenv("SHADOWSCAN_TEST_LOG_SECRET", secret)
        assert ctx.get("token", env="SHADOWSCAN_TEST_LOG_SECRET") == secret
    ctx.warn(f"upstream rejected {secret!r}")
    ctx.error(f"upstream rejected {secret}")
    for message in ctx.stats.warnings + ctx.stats.errors:
        assert "opaque-synthetic-secret" not in message
        assert "upstream rejected" in message and REDACTED in message
    assert "opaque-synthetic-secret" not in caplog.text
    assert len(caplog.records) == 2
    assert all(record.args == () and record.exc_info is None for record in caplog.records)


def test_plaintext_is_not_logged_when_report_sanitizer_changes(index, caplog, monkeypatch):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="test", started_at="now")
    monkeypatch.setattr(ctx, "sanitize_message", lambda message: message)
    ctx.error("unrecognized confidential upstream diagnostic")
    assert "confidential" not in repr(caplog.records[0].__dict__)
    assert ctx.stats.errors == ["unrecognized confidential upstream diagnostic"]


def test_diagnostic_limit_retains_static_logging_and_completeness(index, caplog, monkeypatch):
    monkeypatch.setattr(ConnectorContext, "_MAX_DIAGNOSTICS", 2)
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="test", started_at="now")
    for _ in range(8):
        ctx.warn("ordinary advisory", incomplete=False)
    assert not ctx.stats.incomplete
    ctx.warn("opaque-required-failure", incomplete=True)
    assert ctx.stats.incomplete
    assert len(ctx.stats.warnings) == len(caplog.records) == 3
    assert "diagnostic limit" in ctx.stats.warnings[-1]
    assert all("ordinary advisory" not in record.getMessage() for record in caplog.records)


def test_sanitization_limit_does_not_fall_back_to_logging_raw_payload(index, caplog, monkeypatch):
    def fail_sanitization(value, **kwargs):
        raise SanitizationLimitError("budget exceeded")

    monkeypatch.setattr("shadowscan.connectors.base.sanitize", fail_sanitization)
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="test", started_at="now")
    ctx.warn("private source diagnostic", incomplete=False)
    assert ctx.stats.incomplete
    assert REDACTED in ctx.stats.warnings[0]
    assert "sanitization safety limit" in ctx.stats.warnings[0]
    assert "private source" not in repr(caplog.records[0].__dict__)


def test_context_without_statistics_also_uses_static_log_events(index, caplog):
    ctx = ConnectorContext(index=index)
    ctx.error("private opaque diagnostic")
    assert len(caplog.records) == 1
    assert "private opaque" not in repr(caplog.records[0].__dict__)


@pytest.mark.parametrize("key", ["api_token", "foundry_token", "github_token", "token", "access_token", "client_secret", "password", "api_key"])
@pytest.mark.parametrize("secret", ["a", "R", "message", "opaque-private-secret-value\n"])
def test_every_connector_credential_name_and_length_is_redacted_from_diagnostics(index, key, secret):
    ctx = ConnectorContext(config={key: secret}, index=index)
    assert ctx.sanitize_message(secret) == REDACTED
    assert ctx.sanitize_message(repr(secret)) in {f"'{REDACTED}'", f'"{REDACTED}"'}


def test_short_secret_cannot_expand_an_existing_redaction_marker(index):
    ctx = ConnectorContext(config={"token": "opaque-private-secret-value", "password": "R"}, index=index)
    assert ctx.sanitize_message("opaque-private-secret-value R") == f"{REDACTED} {REDACTED}"


def test_literal_marker_inside_a_configured_secret_does_not_prevent_redaction(index):
    secret = "private-prefix[REDACTED]private-suffix"
    ctx = ConnectorContext(config={"token": secret, "password": "R"}, index=index)
    assert ctx.sanitize_message(secret) == REDACTED


@pytest.mark.parametrize("secret", ["h", "hooks", "slack", "services"])
def test_short_configured_secret_cannot_hide_webhook_structure_from_redaction(index, secret):
    webhook_secret = "x" * 24
    url = "https://hooks.slack.com/services/T00000000/B00000000/" + webhook_secret
    ctx = ConnectorContext(config={"token": secret}, index=index)
    message = ctx.sanitize_message("upstream rejected " + url)
    assert webhook_secret not in message
    assert REDACTED in message


def test_short_configured_secret_cannot_hide_an_unrelated_provider_credential(index):
    unrelated_secret = "sk-proj-" + "x" * 40
    ctx = ConnectorContext(config={"token": "sk"}, index=index)
    assert ctx.sanitize_message("upstream rejected " + unrelated_secret) == "upstream rejected " + REDACTED


def test_structural_redaction_preserves_whole_configured_secret_removal(index):
    secret = "opaquePrefix sk-proj-" + "x" * 40 + " opaqueSuffix"
    ctx = ConnectorContext(config={"token": secret}, index=index)
    assert ctx.sanitize_message("upstream rejected " + secret) == "upstream rejected " + REDACTED


def test_short_secret_expansion_is_bounded_before_replacement_allocation(monkeypatch):
    from shadowscan.utils import redaction

    monkeypatch.setattr(redaction, "_MAX_SANITIZATION_CHARS", 64)
    calls = []
    real_sanitizer = redaction.sanitize_text

    def observe_text(value):
        calls.append(value)
        return real_sanitizer(value)

    monkeypatch.setattr(redaction, "sanitize_text", observe_text)
    with pytest.raises(SanitizationLimitError, match="credential replacement size limit"):
        sanitize([{"password": "a"}, "a" * 50], redact_short_secrets=True)
    assert all(len(value) <= 64 for value in calls)


def test_specific_token_names_do_not_redact_usage_metrics():
    metrics = {"token_count": 12, "input_tokens": 3, "output_tokens": 9, "token_name": "agent"}
    assert sanitize(metrics) == metrics
    assert sanitize({"api_token": "opaque", "foundry_token": "opaque"}) == {
        "api_token": REDACTED, "foundry_token": REDACTED,
    }


@pytest.mark.parametrize("primary", [None, ""])
def test_github_fallback_environment_credential_is_registered_for_diagnostics(index, monkeypatch, primary):
    secret = "opaque-github-cli-environment-secret"
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", secret)
    ctx = ConnectorContext(config={} if primary is None else {"token": primary}, index=index)
    connector = GitHubConnector(ctx)
    assert connector.token == secret
    assert ctx.sanitize_message(f"upstream rejected {secret}") == f"upstream rejected {REDACTED}"
