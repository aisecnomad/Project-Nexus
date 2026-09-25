"""Hardening follow-up from the 2026-09-25 external grade: platform preflight and shim aliases."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.utils.platform import (
    MISSING_NOFOLLOW_MESSAGE,
    UNSUPPORTED_WINDOWS_MESSAGE,
    UnsupportedPlatformError,
    require_supported_platform,
)
from shadowscan.utils.redaction import credential_id
from shadowscan.utils.text import redact, sanitize_record


def test_require_supported_platform_accepts_the_validated_host():
    require_supported_platform()  # CI runs on Linux, the only validated target


def test_require_supported_platform_rejects_windows(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "win32")
    with pytest.raises(UnsupportedPlatformError, match="Windows is unsupported"):
        require_supported_platform()


def test_require_supported_platform_rejects_missing_nofollow(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "linux")
    monkeypatch.delattr("shadowscan.utils.platform.os.O_NOFOLLOW", raising=False)
    with pytest.raises(UnsupportedPlatformError, match="O_NOFOLLOW"):
        require_supported_platform()


@pytest.mark.parametrize("argv", [["--help"], ["-h"], ["--version"]])
def test_cli_help_and_version_still_work_on_unsupported_platforms(monkeypatch, argv):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "win32")
    result = CliRunner().invoke(main, argv)
    assert result.exit_code == 0, result.output
    assert "shadowscan" in result.output.lower()


def test_cli_commands_fail_closed_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "win32")
    result = CliRunner().invoke(main, ["code", str(tmp_path)])
    assert result.exit_code == 1
    assert UNSUPPORTED_WINDOWS_MESSAGE in result.output


def test_cli_commands_fail_closed_without_nofollow(monkeypatch, tmp_path):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "linux")
    monkeypatch.delattr("shadowscan.utils.platform.os.O_NOFOLLOW", raising=False)
    result = CliRunner().invoke(main, ["code", str(tmp_path)])
    assert result.exit_code == 1
    assert MISSING_NOFOLLOW_MESSAGE in result.output


def test_text_shims_remain_compatibility_aliases():
    token = "sk-proj-exampletokenvalue"
    assert redact(token, keep=8) == credential_id(token)
    assert sanitize_record({"token": token})["token"] != token
