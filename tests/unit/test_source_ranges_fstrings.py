"""F-string replacement expressions must remain visible on Python 3.11 and 3.12."""

from __future__ import annotations

import tokenize

import pytest

from shadowscan.connectors.code import source_ranges
from shadowscan.connectors.code.source_ranges import _legacy_fstring_ranges
from shadowscan.models import Kind


@pytest.mark.parametrize("source", [
    'f"StateGraph( is inert"',
    'rf"{{StateGraph(}} is escaped text"',
    'f"{value:StateGraph(}"',
    'f"{value!r:StateGraph(}"',
    'f"{\'StateGraph(\'}"',
])
def test_legacy_fstring_parser_masks_literal_and_string_content(source, index):
    spans, incomplete = _legacy_fstring_ranges(source, 0)
    assert not incomplete
    assert not index.match_code(source, "python", ignore_spans=spans)


@pytest.mark.parametrize("source", [
    'f"prefix {StateGraph(1)} suffix"',
    'f"{value:{StateGraph(1)}}"',
    'f"outer {f\'inner {StateGraph(1)}\'} tail"',
    'rf"\\{StateGraph(1)}"',
])
def test_legacy_fstring_parser_keeps_executable_replacements(source, index):
    spans, incomplete = _legacy_fstring_ranges(source, 0)
    assert not incomplete
    assert any(m.signature_id == "framework.langgraph" for m in index.match_code(source, "python", ignore_spans=spans))


def test_legacy_fstring_parser_marks_overdeep_nesting_incomplete():
    source = 'f"' + '{x:' * 30 + 'StateGraph(' + '}' * 30 + '"'
    spans, incomplete = _legacy_fstring_ranges(source, 0)
    assert incomplete
    assert spans == [(0, len(source))]


def test_python_311_string_token_invokes_replacement_parser(monkeypatch, index):
    # Python 3.11 emits one STRING for the entire f-string. Reproduce that
    # tokenizer API on 3.12 without requiring another interpreter locally.
    source = 'f"literal StateGraph( {StateGraph(1)}"'
    tokens = [tokenize.TokenInfo(tokenize.STRING, source, (1, 0), (1, len(source)), source)]
    monkeypatch.setattr(source_ranges.tokenize, "generate_tokens", lambda _: iter(tokens))
    spans, incomplete = source_ranges.noncode_ranges(source, "python")
    assert not incomplete
    matches = [m for m in index.match_code(source, "python", ignore_spans=spans) if m.signature_id == "framework.langgraph"]
    assert len(matches) == 1 and matches[0].line == 1


def test_unterminated_native_fstring_marks_scan_incomplete(tmp_path, run_connector):
    (tmp_path / "broken.py").write_text('text = f"{StateGraph("\n')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]
    assert ctx.stats.incomplete
    assert any("incomplete source lexical analysis" in error for error in ctx.stats.errors)


@pytest.mark.parametrize(("source", "agent"), [
    ('text = f"example StateGraph( only"\n', False),
    ('text = f"{{StateGraph(}}"\n', False),
    ('text = f"{\'StateGraph(\'}"\n', False),
    ('text = f"{value:StateGraph(}"\n', False),
    ('text = f"{StateGraph(1)}"\n', True),
    ('text = f"{value:{StateGraph(1)}}"\n', True),
    ('text = f"outer {f\'nested {StateGraph(1)}\'}"\n', True),
])
def test_filesystem_scan_fstring_text_vs_code(tmp_path, run_connector, source, agent):
    (tmp_path / "agent.py").write_text("from langgraph.graph import StateGraph\n" + source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings) == agent
