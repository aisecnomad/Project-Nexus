"""Opaque multiline YAML secrets never survive source sanitization."""

from __future__ import annotations

import json

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text

SECRET = "opaque-synthetic-credential"
TAIL = "opaque-private-tail"


@pytest.mark.parametrize("marker", ["|", ">", "|-", ">+", "|2+", ">-2", ""])
@pytest.mark.parametrize("key", ["api_key", '"client_secret"', "'password'"])
def test_yaml_sensitive_block_values_are_redacted(marker, key):
    source = f"{key}: {marker}\n  {SECRET}\n\n  {TAIL}\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert SECRET not in clean and TAIL not in clean
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


@pytest.mark.parametrize("prefix", ["  ", "- ", "  - "])
def test_yaml_continued_plain_secret_respects_nested_mapping_boundary(prefix):
    body = " " * (len(prefix) + 2)
    peer = " " * len(prefix)
    source = f"{prefix}api_key: {SECRET}\n{body}{TAIL}\n{peer}model: langchain\n"
    clean = sanitize_text(source)
    assert SECRET not in clean and TAIL not in clean
    assert "model: langchain" in clean
    assert sanitize_text(clean) == clean


def test_yaml_block_redaction_preserves_unrelated_blocks_and_line_locations():
    source = f"description: |\r\n  ordinary documentation\r\npassword: | # comment\r\n  {SECRET}\r\nname: public\r\n"
    clean = sanitize_text(source)
    assert "ordinary documentation" in clean and "name: public" in clean
    assert SECRET not in clean
    assert clean.count("\n") == source.count("\n")


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_yaml_source_secret_body_is_redacted_before_evidence_selection(tmp_path, run_connector, scan_secrets):
    (tmp_path / "config.yaml").write_text(
        f"api_key: |\n  {SECRET} AgentExecutor(\n  {TAIL}\nmodel: public\n"
        'nodes:\n  - type: "@n8n/n8n-nodes-langchain.agent"\n    name: Researcher\n',
        encoding="utf-8",
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=scan_secrets)
    assert findings and not ctx.stats.incomplete
    # Real operational configuration still produces evidence; code-like text
    # inside a secret cannot establish a LangChain agent.
    assert any("platform.n8n" in finding.frameworks for finding in findings)
    assert all("framework.langchain" not in finding.frameworks for finding in findings)
    output = json.dumps([finding.to_dict() for finding in findings])
    assert SECRET not in output and TAIL not in output
