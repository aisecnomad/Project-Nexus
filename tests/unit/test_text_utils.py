"""shadowscan.utils.text: untrusted timestamps and compatibility aliases."""

from __future__ import annotations

import codecs
import time
from datetime import UTC, datetime

import pytest

from shadowscan.utils import text
from shadowscan.utils.redaction import credential_id, sanitize
from shadowscan.utils.text import BINARY_CONTENT_ERROR, line_counter, parse_timestamp, read_text, redact


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
    [
        1704067200125000,  # microseconds
        "1704067200125000",
        1704067200125000000,  # nanoseconds
        "1704067200125000000",
        "2024-01-01 00:00:00.125 +0000 UTC",  # Go time.Time.String()
        "2024-01-01 00:00:00.125000999 +0000 UTC m=+0.004321001",
        "2024-01-01 01:00:00.125 +0100 CET",
        "Mon, 01 Jan 2024 00:00:00 GMT",  # RFC 2822
        "Sun, 31 Dec 2023 19:00:00 -0500",
    ],
)
def test_sub_millisecond_epochs_go_and_rfc2822_times_parse(value):
    # These used to become None, so events silently lost their time.
    expected = datetime(2024, 1, 1, tzinfo=UTC)
    parsed = parse_timestamp(value)
    assert parsed is not None and parsed.replace(microsecond=0) == expected
    if "GMT" not in str(value) and "-0500" not in str(value):
        assert parsed.microsecond == 125000


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
    ["Mon, 31 Feb 2024 00:00:00 GMT", "2024-01-01 00:00:00 UTC m=+1", "yesterday", "Jan 2024", "1 2 3"],
)
def test_malformed_go_and_rfc2822_times_stay_unparsed(value):
    assert parse_timestamp(value) is None


@pytest.mark.parametrize(
    "value",
    [10**21, 9 * 10**17, -1704067200125000],
    ids=["twenty-two-digits", "beyond-year-9999", "negative"],
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


# ---------------------------------------------------------------- read_text
@pytest.mark.parametrize(
    ("bom", "codec"),
    [
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
    ],
    ids=["utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be"],
)
def test_read_text_decodes_bom_marked_text_and_strips_the_mark(tmp_path, bom, codec):
    (tmp_path / "requirements.txt").write_bytes(bom + "langchain==0.2.0\r\nopenai==1.30.0\r\n".encode(codec))
    errors: list[str] = []
    assert read_text(tmp_path / "requirements.txt", 1000, errors) == "langchain==0.2.0\r\nopenai==1.30.0\r\n"
    assert errors == []


def test_read_text_utf32le_bom_is_not_mistaken_for_utf16le(tmp_path):
    # The UTF-32LE mark starts with the UTF-16LE mark.
    (tmp_path / "a.txt").write_bytes(codecs.BOM_UTF32_LE + "x".encode("utf-32-le"))
    assert read_text(tmp_path / "a.txt", 100) == "x"


@pytest.mark.parametrize("name", ["app.py", "CLAUDE.md", "settings.json", "Dockerfile", "run"])
def test_read_text_reports_nul_content_of_an_analyzable_file(tmp_path, name):
    (tmp_path / name).write_bytes(b"// note \x00 hidden\nconst OpenAI = require('openai');\n")
    errors: list[str] = []
    assert read_text(tmp_path / name, 1000, errors) is None
    assert errors == [BINARY_CONTENT_ERROR]


@pytest.mark.parametrize("name", ["app.js", "agent.mjs", "planDock.ts", "view.tsx"])
def test_read_text_reads_javascript_with_a_few_nul_characters(tmp_path, name):
    # A NUL character in a string literal (`join('\x00')`) keeps the source valid UTF-8.
    content = b"// note \x00 kept\nconst OpenAI = require('openai');\n"
    (tmp_path / name).write_bytes(content)
    errors: list[str] = []
    assert read_text(tmp_path / name, 1000, errors) == content.decode()
    assert errors == []
    (tmp_path / name).write_bytes(content + b"\x00" * 8)
    assert read_text(tmp_path / name, 1000, errors) is None
    assert errors == [BINARY_CONTENT_ERROR]


def test_read_text_binary_error_names_neither_file_nor_content(tmp_path):
    (tmp_path / "secret-name.js").write_bytes(b"token-in-content" + b"\x00" * 8)
    errors: list[str] = []
    read_text(tmp_path / "secret-name.js", 1000, errors)
    assert errors == ["binary or undecodable content in analyzable file"]


@pytest.mark.parametrize(
    "header",
    [
        b"\x7fELF\x02\x01\x01",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\x00asm\x01\x00\x00\x00",
        b"\x1f\x8b\x08",
        b"PK\x03\x04",
        b"BZh9",
        b"\xfd7zXZ\x00",
        b"\x28\xb5\x2f\xfd",
        b"7z\xbc\xaf\x27\x1c",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff\xe0",
        b"GIF89a",
        b"%PDF-1.7",
    ],
)
def test_read_text_skips_extensionless_compiled_artifacts_quietly(tmp_path, header):
    (tmp_path / "tool").write_bytes(header + b"\x00" * 64)
    errors: list[str] = []
    assert read_text(tmp_path / "tool", 1000, errors) is None
    assert errors == []


def test_read_text_extension_or_unknown_header_defeats_the_quiet_skip(tmp_path):
    # An interpreter can run a script whose first line resembles a header, and
    # an unknown header proves nothing: both stay coverage gaps.
    (tmp_path / "tool.sh").write_bytes(b"\x7fELF" + b"\x00" * 64)
    (tmp_path / "blob").write_bytes(b"\x01\x02\x00\x03" * 16)
    for name in ("tool.sh", "blob"):
        errors: list[str] = []
        assert read_text(tmp_path / name, 1000, errors) is None
        assert errors == [BINARY_CONTENT_ERROR], name


def test_read_text_nul_after_the_sniff_window_is_still_text(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"a" * 9000 + b"\x00tail")
    errors: list[str] = []
    assert (read_text(tmp_path / "a.txt", 20000, errors) or "").endswith("\x00tail")
    assert errors == []


def test_read_text_decodes_python_source_with_its_declared_codec(tmp_path):
    (tmp_path / "a.py").write_bytes(b"# -*- coding: latin-1 -*-\nname = '\xe9'\nimport openai\n")
    (tmp_path / "b.py").write_bytes(
        b"#!/usr/bin/env python\n# vim: set fileencoding=shift_jis :\nx = '\x83\x41'\n"
    )
    (tmp_path / "c.py").write_bytes(codecs.BOM_UTF8 + b"# coding: utf-8\nimport openai\n")
    errors: list[str] = []
    assert (
        read_text(tmp_path / "a.py", 1000, errors)
        == "# -*- coding: latin-1 -*-\nname = '\xe9'\nimport openai\n"
    )
    assert read_text(tmp_path / "b.py", 1000, errors).endswith("x = '" + chr(0x30A2) + "'\n")
    assert read_text(tmp_path / "c.py", 1000, errors) == "# coding: utf-8\nimport openai\n"
    assert errors == []


def test_read_text_declared_codec_applies_to_python_sources_only(tmp_path):
    (tmp_path / "notes.md").write_bytes(b"# coding: latin-1\n\xe9\n")
    errors: list[str] = []
    assert read_text(tmp_path / "notes.md", 1000, errors) is None
    assert errors == [BINARY_CONTENT_ERROR]


def test_read_text_python_source_its_codec_cannot_decode_is_a_gap(tmp_path):
    (tmp_path / "a.py").write_bytes(b"# coding: ascii\nname = '\xe9'\nimport openai\n")
    errors: list[str] = []
    assert read_text(tmp_path / "a.py", 1000, errors) is None
    assert errors == [BINARY_CONTENT_ERROR]


@pytest.mark.parametrize("cookie", ["utf_16_le", "utf-16-be", "cp037", "cp500", "utf-7", "utf_32_le"])
def test_read_text_codec_that_does_not_read_ascii_as_ascii_is_a_gap(tmp_path, cookie):
    # The file is ASCII, as a cookie on its first line requires; decoded with
    # such a codec it became other characters (CJK text for UTF-16), and its
    # 'import openai' and key were silently not analyzed.
    source = f'# coding: {cookie}\nOPENAI_API_KEY = "sk-proj-AbCd1234"\nimport openai\n'.encode()
    (tmp_path / "a.py").write_bytes(source + b" " * (len(source) % 4))
    errors: list[str] = []
    assert read_text(tmp_path / "a.py", 1000, errors) is None
    assert errors == [BINARY_CONTENT_ERROR]


@pytest.mark.parametrize("cookie", ["nonsense", "rot13", "hex", "utf8", "UTF-8"])
def test_read_text_unusable_or_utf8_cookie_keeps_default_decoding(tmp_path, cookie):
    (tmp_path / "a.py").write_bytes(f"# coding: {cookie}\nimport openai\n".encode())
    errors: list[str] = []
    assert read_text(tmp_path / "a.py", 1000, errors) == f"# coding: {cookie}\nimport openai\n"
    assert errors == []


def test_read_text_does_not_decode_hostile_slow_codec(tmp_path):
    # punycode decoding re-copies its output per code point: ~1.3 s for 200 KB,
    # ~30 s for 1 MB, with the GIL held where no deadline can interrupt it.
    (tmp_path / "a.py").write_bytes(b"# coding: punycode\n" + b"a" * 400_000)
    errors: list[str] = []
    started = time.monotonic()
    assert read_text(tmp_path / "a.py", 1_000_000, errors) is None
    assert time.monotonic() - started < 2.0
    assert errors == [BINARY_CONTENT_ERROR]


def test_compact_calendar_days_are_dates_not_epoch_seconds():
    # A gateway log's ``date: 20240101`` field was read as epoch seconds (1970).
    assert parse_timestamp("20240101") == datetime(2024, 1, 1, tzinfo=UTC)
    assert parse_timestamp("20240101") != parse_timestamp(20240101.0)
    assert parse_timestamp("20241399") is None  # an impossible day is no timestamp
    assert parse_timestamp("1704067200") == datetime(2024, 1, 1, tzinfo=UTC)
    assert parse_timestamp("12345678") == datetime.fromtimestamp(12345678, tz=UTC)


class _CountingText(str):
    """A string that records how many characters ``count`` scans."""

    scanned = 0

    def count(self, sub, start=None, end=None):
        first = 0 if start is None else start
        _CountingText.scanned += (len(self) if end is None else end) - first
        return super().count(sub, start, end)


def test_line_counter_scans_each_character_once_for_ordered_offsets():
    # Counting from the start for every regex match was quadratic: a file with
    # thousands of imports exhausted the match deadline and the scan went incomplete.
    _CountingText.scanned = 0
    text = _CountingText("import a from 'x';\n" * 2000)
    line_at = line_counter(text)
    assert [line_at(19 * i) for i in range(2000)] == list(range(1, 2001))
    assert _CountingText.scanned <= len(text)


def test_line_counter_recounts_an_earlier_offset():
    line_at = line_counter("a\nb\nc\n")
    assert [line_at(4), line_at(0), line_at(2), line_at(2), line_at(6)] == [3, 1, 2, 2, 4]
