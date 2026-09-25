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
    "CI_JOB_TOKEN=glcbt-abcdef",
    "SECRET_KEY_BASE=deadbeefdeadbeef",
    "X-Amz-Security-Token=IQoJb3JpZ2luX2Vj",
    "passphrase: hunter2",
    "auth = 'basic dXNlcjpwYXNz'",
])
def test_generic_secret_names_are_redacted(line):
    value = line.split("=", 1)[-1].split(": ", 1)[-1].strip("'")
    cleaned = sanitize_text(line)
    assert value not in cleaned
    assert REDACTED in cleaned


@pytest.mark.parametrize("line", ["max_tokens=2048", "token_count = 12", "tokenizer = 'gpt2'", "secrets_manager = 'aws'", "token_type: Bearer"])
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
