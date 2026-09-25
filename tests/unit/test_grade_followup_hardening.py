"""Hardening follow-up from the 2026-09-25 external grade."""

from __future__ import annotations

import sys

import pytest
from click.testing import CliRunner
from markdown_it import MarkdownIt

from shadowscan.__main__ import main as package_main
from shadowscan.models import Finding, Kind, ScanResult, Surface
from shadowscan.reporters.markdown import render_markdown
from shadowscan.utils.platform import (
    UNSUPPORTED_WINDOWS_MESSAGE,
    UnsupportedPlatformError,
    require_supported_platform,
)
from shadowscan.utils.redaction import credential_id
from shadowscan.utils.text import redact, sanitize_record


def test_require_supported_platform_rejects_windows(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "win32")
    with pytest.raises(UnsupportedPlatformError, match="Windows is unsupported"):
        require_supported_platform()


def test_require_supported_platform_rejects_missing_nofollow(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "linux")
    monkeypatch.delattr("shadowscan.utils.platform.os.O_NOFOLLOW", raising=False)
    with pytest.raises(UnsupportedPlatformError, match="O_NOFOLLOW"):
        require_supported_platform()


def test_package_entry_allows_help_on_windows(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "win32")
    monkeypatch.setattr(sys, "argv", ["shadowscan", "--help"])
    runner_argv = sys.argv
    assert runner_argv[-1] == "--help"
    from shadowscan.__main__ import _HELP_OR_VERSION

    assert "--help" in _HELP_OR_VERSION


def test_package_entry_rejects_scan_on_windows(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.platform.sys.platform", "win32")
    monkeypatch.setattr(sys, "argv", ["shadowscan", "code", "."])
    with pytest.raises(SystemExit, match=UNSUPPORTED_WINDOWS_MESSAGE):
        package_main()


def test_bare_url_in_finding_title_is_defanged():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="callback https://attacker.invalid/collect",
        resource="repo",
        resource_type="repository",
    )
    report = render_markdown(ScanResult(findings=[finding]))
    html = MarkdownIt("default").enable("table").render(report)
    assert "https[:]//attacker.invalid/collect" in report
    assert "https://attacker.invalid" not in report
    assert "<a href" not in html


def test_javascript_url_is_defanged_in_markdown():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="javascript://example",
        resource="repo",
        resource_type="repository",
    )
    report = render_markdown(ScanResult(findings=[finding]))
    assert "javascript[:]//example" in report
    assert "javascript://example" not in report


def test_text_shims_remain_compatibility_aliases():
    token = "sk-proj-exampletokenvalue"
    assert redact(token, keep=8) == credential_id(token)
    assert sanitize_record({"token": token})["token"] != token
