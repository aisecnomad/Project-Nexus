"""shadowscan.utils.text: untrusted timestamps and compatibility aliases."""

from __future__ import annotations

import codecs
import time
from datetime import UTC, datetime

import pytest

from shadowscan.utils import text
from shadowscan.utils.redaction import credential_id, sanitize
from shadowscan.utils.text import BINARY_CONTENT_ERROR, parse_timestamp, read_text, redact


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


@pytest.mark.parametrize("name", ["app.js", "CLAUDE.md", "settings.json", "Dockerfile", "run"])
def test_read_text_reports_nul_content_of_an_analyzable_file(tmp_path, name):
    (tmp_path / name).write_bytes(b"// note \x00 hidden\nconst OpenAI = require('openai');\n")
    errors: list[str] = []
    assert read_text(tmp_path / name, 1000, errors) is None
    assert errors == [BINARY_CONTENT_ERROR]


def test_read_text_binary_error_names_neither_file_nor_content(tmp_path):
    (tmp_path / "secret-name.js").write_bytes(b"token-in-content\x00")
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
    assert read_text(tmp_path / "notes.md", 1000) == "# coding: latin-1\n" + chr(0xFFFD) + "\n"


def test_read_text_python_source_its_codec_cannot_decode_is_a_gap(tmp_path):
    (tmp_path / "a.py").write_bytes(b"# coding: ascii\nname = '\xe9'\nimport openai\n")
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
