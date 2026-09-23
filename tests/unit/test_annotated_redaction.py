"""Opaque credentials in Python annotations cannot enter report evidence."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text

SECRET = "opaque-synthetic-credential-for-testing"


@pytest.mark.parametrize("source", [
    f'API_KEY: str = "{SECRET}"',
    f'CLIENT_SECRET: Final[str] = "{SECRET}"',
    f'self.password: str | None = "{SECRET}"',
    f'API_KEY: "str" = "{SECRET}"',
    f'API_KEY: str = "escaped \\\" {SECRET}"',
    f'API_KEY: str = """{SECRET}\nprivate-tail"""',
    f'API_KEY: Final[\n str\n] = (\n "{SECRET}"\n)',
    f'API_KEY: str = ("{SECRET}" + "private-tail")',
    f'API_KEY: str = """{SECRET}\nprivate-tail',
    f'API_KEY: str = (\n "{SECRET}"\n',
])
def test_annotated_assignments_redact_entire_rhs_and_preserve_lines(source):
    safe = sanitize_text(source)
    assert SECRET not in safe
    assert "private-tail" not in safe
    assert REDACTED in safe
    assert source.count("\n") == safe.count("\n")
    assert sanitize_text(safe) == safe


def test_annotated_assignment_keeps_following_statements_and_safe_assignments():
    source = f'API_KEY: str = "{SECRET}"; import langchain\nmodel: str = "gpt-4o"'
    safe = sanitize_text(source)
    assert SECRET not in safe and REDACTED in safe
    assert safe.endswith('; import langchain\nmodel: str = "gpt-4o"')


def test_long_unfinished_annotation_has_bounded_work():
    # A regex combining a retrying annotation suffix with unbounded whitespace
    # previously spent quadratic work here. Tokenize the statement once.
    script = """
from shadowscan.utils.redaction import sanitize_text
source = 'API_KEY: str' + ' ' * 500_000
assert sanitize_text(source).endswith(' ' * 500_000)
assert 'opaque-credential' not in sanitize_text(source + '= "opaque-credential"')
"""
    result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2],
                            capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_annotated_credentials_never_enter_full_scan_evidence(tmp_path, run_connector, scan_secrets):
    (tmp_path / "agent.py").write_text(
        f'import langchain; API_KEY: str = "{SECRET}"\n'
        f'from crewai import Agent; CLIENT_SECRET: Final[str] = "{SECRET}"\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=scan_secrets)
    assert findings and not ctx.stats.incomplete
    exported = json.dumps([finding.to_dict() for finding in findings])
    assert SECRET not in exported
    assert "framework.langchain" in exported
    assert "framework.crewai" in exported
