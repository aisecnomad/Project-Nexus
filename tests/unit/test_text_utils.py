"""shadowscan.utils.text: untrusted timestamps and compatibility aliases."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from shadowscan.utils import text
from shadowscan.utils.redaction import credential_id, sanitize
from shadowscan.utils.text import parse_timestamp, redact


@pytest.mark.parametrize(
    "value",
    [True, False, float("inf"), float("nan"), 10**400, "9" * 5000],
    ids=["true", "false", "infinity", "nan", "huge-number", "huge-string"],
)
def test_untrusted_invalid_timestamps_do_not_raise_or_become_valid_dates(value):
    assert parse_timestamp(value) is None


def test_fractional_epoch_strings_support_gateway_timestamps():
    assert parse_timestamp("1704067200.125") == datetime(2024, 1, 1, microsecond=125000, tzinfo=UTC)
    assert parse_timestamp("1704067200125") == datetime(2024, 1, 1, microsecond=125000, tzinfo=UTC)


def test_redact_shim_remains_a_compatibility_alias():
    token = "sk-proj-exampletokenvalue"
    assert redact(token, keep=8) == credential_id(token)


def test_sanitize_record_alias_is_replaced_by_sanitize():
    token = "sk-proj-exampletokenvalue"
    assert not hasattr(text, "sanitize_record")
    assert sanitize({"token": token})["token"] != token


@pytest.mark.parametrize(
    "url,host",
    [
        # Userinfo is not the host: everything up to the last "@" is dropped.
        ("https://user:pw@api.openai.com/v1", "api.openai.com"),
        ("https://api.openai.com:443@evil.example/v1", "evil.example"),
        ("https://a@b@Evil.Example:8443/x", "evil.example"),
        # Bracketed IPv6 literals keep their colons; the port is removed.
        ("http://[::1]:8080/", "::1"),
        ("https://[2001:DB8::7]/v1/chat", "2001:db8::7"),
        ("http://[::1", None),
        # Scheme optional; the authority ends at the first "/", "?" or "#".
        ("API.OpenAI.com/v1/chat/completions", "api.openai.com"),
        ("api.anthropic.com:443", "api.anthropic.com"),
        ("https://api.mistral.ai?x=@evil.example", "api.mistral.ai"),
        ("https://api.mistral.ai#@evil.example", "api.mistral.ai"),
        (":8080", None),
        ("https://:8080/v1", None),
        ("/v1/chat/completions", None),
        ("", None),
        (None, None),
    ],
)
def test_host_of_follows_the_rfc3986_authority(url, host):
    assert text.host_of(url) == host
