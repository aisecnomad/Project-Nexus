"""Complete Python credential expressions stay out of every evidence reporter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.reporters.html import render_html
from shadowscan.reporters.json_ import render_json
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.sarif import render_sarif
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text

SECRET = "opaque-synthetic-credential-for-review"
TAIL = "private-credential-suffix"

EXPRESSIONS = [
    f'"""{SECRET}\n{TAIL}"""',
    f"'''{SECRET}\n{TAIL}'''",
    f'("{SECRET}" + "{TAIL}")',
    f'"{SECRET}" "{TAIL}"',
    f'"{SECRET}" + \\\n "{TAIL}"',
    f'"escaped \\\" {SECRET} {TAIL}"',
    f'r"escaped \\\" {SECRET} {TAIL}"',
    f'bytes("{SECRET}{TAIL}", "utf-8")',
    f'{{"part": ["{SECRET}", "{TAIL}"]}}',
    f'"{SECRET}", "{TAIL}"',
    f'"""{SECRET}\n{TAIL}',
    f'"{SECRET};{TAIL}',
    f'(\n "{SECRET}"\n "{TAIL}"',
    f'("{SECRET}"]\n"{TAIL}"',
    f'[REDACTED] + "{SECRET}{TAIL}"',
]


@pytest.mark.parametrize("rhs", EXPRESSIONS)
def test_sensitive_python_rhs_is_redacted_in_full(rhs):
    source = f'API_KEY = {rhs}'
    safe = sanitize_text(source)
    assert SECRET not in safe and TAIL not in safe
    assert REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


def test_commented_credentials_are_sanitized_without_changing_url_boundaries():
    source = f'#API_KEY = """{SECRET}"""\nhttps://example.test/?token={SECRET}&model=safe'
    safe = sanitize_text(source)
    assert SECRET not in safe
    assert safe.endswith(f'https://example.test/?token={REDACTED}&model=safe')
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


def test_sensitive_attribute_and_call_arguments_keep_neighboring_statements():
    source = (
        f'self.password = "{SECRET}"; import langchain\n'
        f'client = Client(api_key=("{SECRET}" + "{TAIL}"), model="safe-model")\n'
        'from crewai import Agent\n'
        f'client = Client(\n    api_key="{SECRET}", model="safe-model"\n)\n'
        'import autogen\n'
    )
    safe = sanitize_text(source)
    assert SECRET not in safe and TAIL not in safe
    assert '; import langchain\n' in safe
    assert ', model="safe-model")\n' in safe
    assert safe.splitlines()[2] == 'from crewai import Agent'
    assert safe.endswith('import autogen\n')
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


def test_assignment_tokenization_is_bounded_and_fails_closed(monkeypatch):
    monkeypatch.setattr(redaction, "_MAX_REDACTION_WORK", 128)
    with pytest.raises(SanitizationLimitError, match="assignment work limit"):
        sanitize_text('API_KEY = "' + SECRET * 10 + '"')


def test_long_plain_assignment_and_nonmatching_whitespace_complete_within_bound():
    script = '''
from shadowscan.utils.redaction import REDACTED, sanitize_text
source = 'API_KEY' + ' ' * 500_000
assert sanitize_text(source) == source
safe = sanitize_text(source + '= "opaque-credential"')
assert 'opaque-credential' not in safe and REDACTED in safe
'''
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("source", [
    'KEY = "{}"',
    '{"KEY": "{}", "model": "langchain"}',
    "KEY: '{}'\nmodel: langchain",
    'KEY: |\n  {}\nmodel: langchain\n',
])
def test_long_sensitive_key_redacts_opaque_source_value(source):
    key = "X" * 115 + "_API_KEY"
    original = source.replace("KEY", key).replace("{}", SECRET)
    safe = sanitize_text(original)
    assert SECRET not in safe and SECRET[:20] not in safe
    assert REDACTED in safe
    if "model: langchain" in original:
        assert "model: langchain" in safe
    assert safe.count("\n") == original.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_long_sensitive_key_never_reaches_json_or_sarif(tmp_path, scan_secrets):
    key = "X" * 115 + "_API_KEY"
    (tmp_path / "agent.py").write_text(
        f'import langchain; {key} = "{SECRET}"\n', encoding="utf-8",
    )
    (tmp_path / "agent.json").write_text(
        f'{{"{key}": "{SECRET}", "model": "langchain"}}\n', encoding="utf-8",
    )
    (tmp_path / "agent.yaml").write_text(
        f'{key}: |\n  {SECRET}\nmodel: langchain\n', encoding="utf-8",
    )
    result = Engine(ScanConfig(connectors=[ConnectorSpec(name="code.filesystem", config={
        "path": str(tmp_path), "use_git": False, "scan_secrets": scan_secrets,
    })])).run()
    assert result.complete and result.findings
    for render in (render_json, render_sarif):
        output = render(result)
        assert SECRET not in output and SECRET[:20] not in output, render.__name__
        assert REDACTED in output, render.__name__


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_complete_engine_scan_never_exports_python_credentials(tmp_path, index, scan_secrets):
    # Each expression sits beside a framework signal, forcing its line into the
    # normal filesystem evidence path before any reporter shortens the snippet.
    for number, rhs in enumerate(EXPRESSIONS):
        (tmp_path / f"agent_{number}.py").write_text(
            f'import langchain; API_KEY = {rhs}\n', encoding="utf-8",
        )
    config = ScanConfig(connectors=[ConnectorSpec(name="code.filesystem", config={
        "path": str(tmp_path), "use_git": False, "scan_secrets": scan_secrets,
    })])
    result = Engine(config, index).run()
    assert result.complete and result.findings
    assert any("framework.langchain" in finding.frameworks for finding in result.findings)
    for render in (render_json, render_sarif, render_html, render_markdown):
        output = render(result)
        assert SECRET not in output, render.__name__
        assert TAIL not in output, render.__name__
        assert REDACTED in output, render.__name__
