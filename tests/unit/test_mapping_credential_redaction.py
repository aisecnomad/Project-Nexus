"""Sensitive mapping values are redacted through their lexical boundaries."""

from __future__ import annotations

import json

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text

SECRET = "opaque-synthetic-credential"
TAIL = "opaque-private-tail"

SOURCES = [
    f'{{"api_key": "{SECRET}\\\"{TAIL}", "model": "langchain"}}',
    f"api_key: '{SECRET}''{TAIL}'\nmodel: langchain",
    f'{{"password": ["{SECRET}", "{TAIL}"], "model": "langchain"}}',
    f"{{'api_key': {{'part': ['{SECRET}', '{TAIL}']}}, 'model': 'langchain'}}",
    f'const config = {{api_key: `{SECRET}\n{TAIL}`, model: "langchain"}};',
    f'{{"api_key": "{SECRET}" + "{TAIL}", "model": "langchain"}}',
    f'{{"api_key": ("{SECRET}" "{TAIL}"), "model": "langchain"}}',
    f'{{"api_key": "{SECRET}\\\";{TAIL}',
]


@pytest.mark.parametrize("source", SOURCES)
def test_sensitive_mapping_redaction_covers_complete_value(source):
    clean = sanitize_text(source)
    assert SECRET not in clean and TAIL not in clean
    assert REDACTED in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean
    if 'langchain' in source:
        assert 'langchain' in clean


def test_mapping_credential_fingerprint_remains_stable():
    fingerprint = "credential:sha256:" + "a" * 64
    source = json.dumps({"api_key": fingerprint, "model": "langchain"})
    assert sanitize_text(source) == source


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_source_mapping_credentials_never_enter_scan_evidence(tmp_path, run_connector, scan_secrets):
    for number, source in enumerate(SOURCES):
        (tmp_path / f"agent_{number}.py").write_text(
            "import langchain; config = " + source + "\n", encoding="utf-8",
        )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=scan_secrets)
    assert findings and not ctx.stats.incomplete
    output = json.dumps([finding.to_dict() for finding in findings])
    assert "framework.langchain" in output
    assert SECRET not in output and TAIL not in output
