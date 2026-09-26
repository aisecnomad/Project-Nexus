"""Redaction recognizes generic secret names and stays linear on minified bundles."""

from __future__ import annotations

import time

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text


@pytest.mark.parametrize("line", [
    "JWT_SECRET=0123456789abcdef0123456789abcdef",
    "SESSION_SECRET: abc123def456",
    "VAULT_TOKEN=hvs.CAESIJ3l0m4Q9x8Z1w2Y5v7A6b8C",
    "NPM_TOKEN=npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    "CI_JOB_TOKEN=glcbt-64_Ab12Cd34",
    "SECRET_KEY_BASE=deadbeefdeadbeef",
    "X-Amz-Security-Token=IQoJb3JpZ2luX2Vj",
    "passphrase: hunter2",
    "auth = 'opaqueValue123'",
    "MYSQL_PWD=Sup3rS3cretValue9",
    "DB_PASS=Sup3rS3cretValue9",
    "dbPass = 'Sup3rS3cretValue9'",
    "APP_SECRET=Zx81kLmNop",
])
def test_generic_secret_names_are_redacted(line):
    value = line.split("=", 1)[-1].split(": ", 1)[-1].strip("'")
    cleaned = sanitize_text(line)
    assert value not in cleaned
    assert REDACTED in cleaned


@pytest.mark.parametrize("line", [
    "max_tokens=2048", "token_count = 12", "tokenizer = 'gpt2'", "secrets_manager = 'aws'", "token_type: Bearer",
    "auth: none", 'eos_token: "</s>"', 'pad_token: "<pad>"', "pwd = os.getcwd()", "bypass = True", "auth: config",
    "auth: instance_principal",
])
def test_descriptive_continuations_stay_readable(line):
    assert sanitize_text(line) == line


def test_structured_records_keep_ordinary_keys_and_redact_generic_secret_keys():
    record = {"auth": {"type": "basic", "password": "hunter2!"}, "max_tokens": 5, "npm_token": "npm_abcdef", "token_count": 3}
    clean = sanitize(record)
    assert clean["max_tokens"] == 5 and clean["token_count"] == 3
    assert clean["npm_token"] == REDACTED
    assert "hunter2!" not in str(clean)


def test_minified_bundle_with_many_candidates_is_sanitized_in_linear_time():
    line = ("var a=1;" + 'x={token:"abc123",secret:"def456",id:7};' * 300).ljust(300_000, ";")
    started = time.perf_counter()
    cleaned = sanitize_text(line)
    assert time.perf_counter() - started < 5.0
    assert "abc123" not in cleaned and "def456" not in cleaned
    assert "id:7" in cleaned


def test_concatenated_python_secret_on_a_long_line_is_fully_redacted():
    line = "x = 1; " * 2000 + 'api_key = "part1" + "part2secretvalue"; y = 2'
    assert len(line) > 8192
    cleaned = sanitize_text(line)
    assert "part2secretvalue" not in cleaned and "part1" not in cleaned
    assert cleaned.endswith("y = 2")


def test_markers_under_generic_names_never_erase_a_whole_config_file():
    from shadowscan.connectors.code.filesystem import _safe_source_text

    source = (
        "llm:\n  provider: anthropic\n  endpoint: https://api.anthropic.com/v1/messages\n"
        "server:\n  auth: none\n  port: 8080\ntokenizer:\n  eos_token: \"</s>\"\n"
    )
    assert _safe_source_text("svc/settings.yaml", source) == source


def test_generic_names_keep_integer_counts_and_enum_options():
    clean = sanitize({"auth": "config", "evidence_counts": {"provider.openai|secret": 1}, "tokens_used": 5})
    assert clean == {"auth": "config", "evidence_counts": {"provider.openai|secret": 1}, "tokens_used": 5}


def test_generic_argv_flags_withhold_credential_values_only():
    assert sanitize(["--db-pass", "Sup3rS3cretValue9", "--mode", "fast"]) == ["--db-pass", REDACTED, "--mode", "fast"]
    assert sanitize(["--auth", "none"]) == ["--auth", "none"]


def test_oci_auth_mode_stays_comparable_and_readable_in_diagnostics(index):
    from shadowscan.connectors import ConnectorContext
    from shadowscan.models import ScanStats

    ctx = ConnectorContext(config={"auth": "config", "input": "x"}, index=index)
    ctx.stats = ScanStats(connector="cloud.oci", started_at="now")
    ctx.warn("cloud.oci: could not find config file at ~/.oci/config")
    assert "[REDACTED]" not in ctx.stats.warnings[0]
