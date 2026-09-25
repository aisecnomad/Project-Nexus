"""Literal credential keys protect call defaults, reports and debug diagnostics."""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.engine import Engine
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.html import render_html
from shadowscan.reporters.json_ import render_json
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.sarif import render_sarif
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text

SECRET = "opaque-environment-credential-canary-123456"
TAIL = "opaque-environment-credential-second-fragment"

CALLS = [
    f'os.environ.setdefault("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'os.putenv("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'os.getenv("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'os.environ.get("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'os.environ.__setitem__("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'os.environb.setdefault(b"AZURE_OPENAI_API_KEY", b"{SECRET}")',
    f'os.getenv(key="AZURE_OPENAI_API_KEY", default="{SECRET}")',
    f'os.getenv(default="{SECRET}", key="AZURE_OPENAI_API_KEY")',
    f'os.putenv(value="{SECRET}", name="AZURE_OPENAI_API_KEY")',
    f'from os import getenv as read_setting; read_setting("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'import os as runtime; runtime.getenv("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'from os import environ as settings; settings.setdefault("AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'os.getenv(("AZURE_OPENAI_" "API_KEY"), "{SECRET}")',
    f'os.getenv("AZURE_OPENAI_API_\\x4bEY", "{SECRET}")',
    f'os.getenv(\n "AZURE_OPENAI_API_KEY",\n "{SECRET}"\n)',
    f'os.getenv("AZURE_OPENAI_API_KEY", ("{SECRET}" +\n "{TAIL}"))',
    f'os.getenv("AZURE_OPENAI_API_KEY", """{SECRET}\n{TAIL}""")',
    'os.getenv("AZURE_OPENAI_API_KEY", f"{str(")")}' + SECRET + '")',
    'os.getenv(default=f"{str(")")}' + SECRET + '", key="AZURE_OPENAI_API_KEY")',
    'os.getenv("AZURE_OPENAI_API_KEY", `prefix-${lookup(`)`)}}' + SECRET + '`)',
    f'os.getenv("AZURE_OPENAI_API_KEY", decode("{SECRET}", suffix="{TAIL}"))',
    f'os.getenv(# credential name\n "AZURE_OPENAI_API_KEY", "{SECRET}")',
    f'os.getenv(# credential name\n key="AZURE_OPENAI_API_KEY", default="{SECRET}")',
    f'os.getenv("AZURE_OPENAI_API_KEY", # default credential\n "{SECRET}")',
    f'os.getenv("AZURE_OPENAI_API_KEY", /* default */ "{SECRET}")',
    f'os.getenv("AZURE_OPENAI_API_KEY", `{SECRET}\n{TAIL}`)',
    f'os.getenv("AZURE_OPENAI_API_KEY", "{SECRET};{TAIL}',
    f'os.getenv("AZURE_OPENAI_API_KEY", ["{SECRET}"] +\n ["{TAIL}"]',
    f'os.getenv("AZURE_OPENAI_API_KEY", ["{SECRET}"]}}\n "{TAIL}"',
]


@pytest.mark.parametrize("source", CALLS)
def test_environment_call_withholds_entire_value_expression(source):
    safe = sanitize_text(source)
    assert SECRET not in safe and TAIL not in safe
    assert REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("source", [
    'os.getenv("PUBLIC_MODEL", "safe-model")',
    'os.getenv("AZURE_OPENAI_API_KEY")',
    'os.getenv(key="AZURE_OPENAI_API_KEY")',
    'os.getenv("AZURE_OPENAI_API_KEY",)',
    'read_setting(source, "safe-model")',
])
def test_nonsecret_defaults_and_reads_are_preserved(source):
    assert sanitize_text(source) == source


def test_neighboring_arguments_and_original_line_numbers_are_preserved():
    source = (
        f'fetch(default=("{SECRET}" +\n "{TAIL}"), key="AZURE_OPENAI_API_KEY", model="public")\n'
        'import langchain\n'
    )
    safe = sanitize_text(source)
    assert SECRET not in safe and TAIL not in safe
    assert 'key="AZURE_OPENAI_API_KEY", model="public")\n' in safe
    assert safe.splitlines()[2] == 'import langchain'
    assert sanitize_text(safe) == safe


def test_multiple_credentials_and_nested_calls_are_sanitized():
    source = (
        f'os.getenv("AZURE_OPENAI_API_KEY", "{SECRET}"); '
        f'read_setting("password", "{TAIL}")\n'
        f'client(read_setting("api_key", "{SECRET}"), model="safe")'
    )
    safe = sanitize_text(source)
    assert SECRET not in safe and TAIL not in safe
    assert 'model="safe"' in safe
    assert sanitize_text(safe) == safe


def test_credential_call_bounds_fail_closed(monkeypatch):
    monkeypatch.setattr(redaction, "_MAX_REDACTION_WORK", 64)
    with pytest.raises(SanitizationLimitError, match="credential call work limit"):
        sanitize_text('os.getenv("API_KEY", "' + SECRET * 10 + '")')
    monkeypatch.setattr(redaction, "_MAX_REDACTION_WORK", 128 * 1024 * 1024)
    with pytest.raises(SanitizationLimitError, match="credential call nesting limit"):
        sanitize_text('os.getenv("API_KEY", ' + '[' * 65 + '"private"' + ']' * 65 + ')')
    monkeypatch.setattr(redaction, "_MAX_SANITIZATION_NODES", 4)
    with pytest.raises(SanitizationLimitError, match="credential call argument limit"):
        sanitize_text('os.getenv("API_KEY", "private", 1, 2, 3, 4)')


def test_many_calls_and_long_keys_finish_within_work_bound():
    script = '''
from shadowscan.utils.redaction import REDACTED, sanitize_text
source = 'read_setting("PUBLIC_MODEL", "safe")\\n' * 10_000
assert sanitize_text(source) == source
key = 'A' * 500_000 + '_API_KEY'
safe = sanitize_text('read_setting("' + key + '", "opaque-value")')
assert 'opaque-value' not in safe and REDACTED in safe
'''
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_environment_credentials_never_reach_any_evidence_reporter(tmp_path, index, scan_secrets):
    for number, source in enumerate(CALLS):
        (tmp_path / f"agent_{number}.py").write_text('import langchain; ' + source + '\n', encoding="utf-8")
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", {
        "path": str(tmp_path), "use_git": False, "scan_secrets": scan_secrets,
    })]), index).run()
    assert result.complete and result.findings
    for render in (render_json, render_html, render_markdown, render_sarif, render_csv):
        output = render(result)
        assert SECRET not in output, render.__name__
        assert TAIL not in output, render.__name__
        if render is not render_csv:
            assert REDACTED in output, render.__name__


@pytest.mark.parametrize(("connector_cls", "record", "fetch_method"), [
    (GitHubConnector, {"full_name": "test/repo"}, "_fetch_repo"),
    (GitLabConnector, {"path_with_namespace": "test/repo"}, "_fetch"),
])
def test_debug_connector_failures_never_emit_raw_exception_or_traceback(
    tmp_path, index, caplog, monkeypatch, connector_cls, record, fetch_method,
):
    ctx = ConnectorContext(config={"token": SECRET}, index=index, workdir=str(tmp_path))
    connector = connector_cls(ctx)
    monkeypatch.setattr(connector, "collect", lambda: iter([record]))

    def failed_fetch(*args):
        # A provider can echo both configured credentials and opaque SDK values.
        # Debug logs must not expose either or the associated exception chain.
        try:
            raise ValueError(TAIL)
        except ValueError as exc:
            raise RuntimeError(SECRET) from exc

    monkeypatch.setattr(connector, fetch_method, failed_fetch)
    with caplog.at_level(logging.DEBUG, logger="shadowscan"):
        assert connector.run() == []
    assert ctx.stats.incomplete and ctx.stats.errors
    assert SECRET not in str(ctx.stats.errors)
    assert SECRET not in caplog.text and TAIL not in caplog.text
    assert "RuntimeError" in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
