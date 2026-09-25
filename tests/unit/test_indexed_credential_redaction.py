"""Indexed credentials cannot cross the source-to-report trust boundary."""

from __future__ import annotations

import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.html import render_html
from shadowscan.reporters.json_ import render_json
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.sarif import render_sarif
from shadowscan.reporters.table import print_table
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text

SECRET = "opaque-sensitive-canary-123456789"
TAIL = "additional-private-credential-fragment"


@pytest.mark.parametrize("lhs", [
    'os.environ["AZURE_OPENAI_API_KEY"]',
    "process.env['AZURE_OPENAI_API_KEY']",
    'config["service"]["password"]',
    'config["credentials"]["primary"][0]',
    'config["credentials"].primary[lookup("index")]',
    'config[\n "client_secret"\n ]',
    'config[`api_key`]',
    'config["password" /* a comment */] /* target comment */',
    'config["password" # a comment\n ] \\\n ',
    'config["password"]: str',
    'config["credentials"]["primary"]: Final[str]',
])
@pytest.mark.parametrize("rhs", [
    f'"{SECRET}"',
    f'("{SECRET}" +\n "{TAIL}")',
    f'{{"parts": ["{SECRET}", "{TAIL}"]}}',
    f'"""{SECRET}\n{TAIL}"""',
    f'`{SECRET}\n${{format("{TAIL}")}}`',
    f'"{SECRET}"\n + "{TAIL}"',
    f'"{SECRET}" +\n "{TAIL}"',
    f'/* comment\n */ "{SECRET}{TAIL}"',
    f'// comment\n "{SECRET}{TAIL}"',
    f'"{SECRET};{TAIL}',
    f'(\n "{SECRET}"\n "{TAIL}"',
    f'("{SECRET}"]\n"{TAIL}"',
])
def test_indexed_assignment_withholds_complete_expression(lhs, rhs):
    source = f'{lhs} = {rhs}'
    safe = sanitize_text(source)
    assert SECRET not in safe and TAIL not in safe
    assert REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("operator", ["=", "+=", "&&=", "||=", "??="])
def test_indexed_write_keeps_following_statements(operator):
    source = f'config["password"] {operator} "{SECRET}"; import langchain\nmodel = "public"\n'
    safe = sanitize_text(source)
    assert SECRET not in safe
    assert '; import langchain\nmodel = "public"\n' in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("source", [
    'config["model"] = "public"',
    'config["password"] == "candidate"',
    'config["password"] === "candidate"',
    'config["password"] != "candidate"',
    'config["password"]; model = "public"',
    'lookup(config["password"], model="public")',
    'config["password"]: str',
])
def test_indexed_reads_and_nonsecret_writes_remain_intact(source):
    assert sanitize_text(source) == source


def test_indexed_target_work_and_depth_fail_closed(monkeypatch):
    monkeypatch.setattr(redaction, "_MAX_REDACTION_WORK", 64)
    with pytest.raises(SanitizationLimitError, match="indexed assignment work limit"):
        sanitize_text('config["password"]' + ' ' * 100 + '= "private"')
    monkeypatch.setattr(redaction, "_MAX_REDACTION_WORK", 128 * 1024 * 1024)
    with pytest.raises(SanitizationLimitError, match="indexed assignment nesting limit"):
        sanitize_text('config["credentials"]' + '[' * 65 + '"index"' + ']' * 65 + '= "private"')


def test_many_indexes_and_long_whitespace_have_bounded_work():
    script = r'''
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text
source = 'config["password"]' + ' ' * 500_000
assert sanitize_text(source) == source
assert 'private-value' not in sanitize_text(source + '= "private-value"')
source = ('config["password"] == "candidate";\n' * 10_000)
assert sanitize_text(source) == source
try:
    sanitize_text('config["password"][' * 100_000)
except SanitizationLimitError:
    pass
else:
    raise AssertionError("deeply nested targets were accepted")
'''
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_engine_reporters_never_export_indexed_credentials(tmp_path, scan_secrets):
    (tmp_path / "agent.py").write_text(
        f'import os\nos.environ["AZURE_OPENAI_API_KEY"] = "{SECRET}"\n'
        f'import langchain; config["password"] = ("{SECRET}" + "{TAIL}")\n',
        encoding="utf-8",
    )
    (tmp_path / "annotated.py").write_text(
        f'import langchain; config["password"]: str = "{SECRET}{TAIL}"\n',
        encoding="utf-8",
    )
    (tmp_path / "agent.js").write_text(
        f'process.env["AZURE_OPENAI_API_KEY"] = "{SECRET}";\n'
        f'import {{ Agent }} from "@openai/agents"; config["credentials"][0] = "{TAIL}";\n',
        encoding="utf-8",
    )
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", {
        "path": str(tmp_path), "use_git": False, "scan_secrets": scan_secrets,
    })])).run()
    assert result.complete and result.findings
    for render in (render_json, render_sarif, render_html, render_markdown, render_csv):
        output = render(result)
        assert SECRET not in output, render.__name__
        assert TAIL not in output, render.__name__
    assert REDACTED in render_json(result)
    terminal = StringIO()
    print_table(result, Console(file=terminal, force_terminal=False, width=240), verbose=True)
    assert SECRET not in terminal.getvalue() and TAIL not in terminal.getvalue()
