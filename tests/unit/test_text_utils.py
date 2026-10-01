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


@pytest.mark.parametrize(
    "value",
    [1704067200.125, 1704067200125, 1704067200125000, 1704067200125000000],
    ids=["seconds", "milliseconds", "microseconds", "nanoseconds"],
)
@pytest.mark.parametrize("as_text", [False, True], ids=["number", "text"])
def test_epoch_unit_is_inferred_from_magnitude(value, as_text):
    # Exporters such as OpenTelemetry and Envoy write microseconds or
    # nanoseconds; those must not silently lose first/last-seen times.
    raw = str(value) if as_text else value
    assert parse_timestamp(raw) == datetime(2024, 1, 1, microsecond=125000, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [10**19, 10**21, 9 * 10**17, -1704067200125000],
    ids=["twenty-digits", "twenty-two-digits", "beyond-year-9999", "negative"],
)
def test_epoch_values_outside_every_unit_remain_invalid(value):
    assert parse_timestamp(value) is None


def test_redact_shim_remains_a_compatibility_alias():
    token = "sk-proj-exampletokenvalue"
    assert redact(token, keep=8) == credential_id(token)


def test_sanitize_record_alias_is_replaced_by_sanitize():
    token = "sk-proj-exampletokenvalue"
    assert not hasattr(text, "sanitize_record")
    assert sanitize({"token": token})["token"] != token
