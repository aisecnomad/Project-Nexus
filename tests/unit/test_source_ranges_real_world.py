"""Constructs in real repositories that the lexers used to call ambiguous, and those that still are.

Each case came from a public repository scanned in the real-world benchmark. A scan whose lexing is
ambiguous is incomplete (exit 3), so a construct the lexer can read exactly must not be reported that
way; one it cannot read must still be.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code.source_ranges import noncode_ranges


def _ranges(source: str, language: str, dialect: str):
    return noncode_ranges(source, language, dialect, jsx=dialect in {".jsx", ".tsx"})


def _masked(source: str, spans, needle: str) -> bool:
    start = source.index(needle)
    return any(a <= start < b for a, b in spans)


# --- strings that run across lines -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("language", "dialect", "source"),
    [
        ("rust", ".rs", 'const KERNEL: &str = "\nAgentBuilder::new(x)\nend";\nfn main() {}\n'),
        ("rust", ".rs", 'let b = b"\nAgentBuilder::new(x)\n";\n'),
        ("php", ".php", "<?php\n$sql = 'SELECT\nAgentBuilder::new(x)\nFROM t';\n"),
        ("php", ".php", '<?php\n$sql = "SELECT\nAgentBuilder::new(x)\nFROM {$t}";\n'),
        ("dotnet", ".fs", 'let text = "first\nAgentBuilder::new(x)\nlast"\n'),
    ],
    ids=["rust", "rust-bytes", "php-single", "php-double", "fsharp"],
)
def test_strings_that_span_lines_are_read_exactly(language: str, dialect: str, source: str):
    spans, incomplete = _ranges(source, language, dialect)
    assert not incomplete
    assert _masked(source, spans, "AgentBuilder")


@pytest.mark.parametrize(
    ("language", "dialect", "source"),
    [
        ("rust", ".rs", 'let s = "never closed\nfn main() {}\n'),
        ("php", ".php", "<?php\n$s = 'never closed\nfunction f() {}\n"),
        ("dotnet", ".fs", 'let s = "never closed\nlet f = 1\n'),
        # Languages whose ordinary strings cannot contain a line break keep ending the walk there.
        ("java", ".java", 'class A { String s = "a\nb"; }\n'),
        ("dotnet", ".cs", 'class A { string s = "a\nb"; }\n'),
        ("go", ".go", 'package a\nvar s = "a\nb"\n'),
        ("swift", ".swift", 'let s = "a\nb"\n'),
        ("ruby", ".rb", "s = 'a\nb'\n"),
    ],
    ids=["rust-unclosed", "php-unclosed", "fsharp-unclosed", "java", "csharp", "go", "swift", "ruby"],
)
def test_unclosed_or_single_line_strings_stay_ambiguous(language: str, dialect: str, source: str):
    _, incomplete = _ranges(source, language, dialect)
    assert incomplete


def test_a_php_attribute_is_code_and_its_string_may_span_lines():
    source = (
        "<?php\nclass T {\n"
        "    #[TestDox('Container\\'s path should\n          have access')]\n"
        "    public function f(): void {}\n}\n"
    )
    spans, incomplete = _ranges(source, "php", ".php")
    assert not incomplete
    assert _masked(source, spans, "have access")
    assert not _masked(source, spans, "TestDox")


def test_a_php_hash_comment_is_still_a_comment():
    source = "<?php\n# it's a comment\nfunction f() {}\n"
    spans, incomplete = _ranges(source, "php", ".php")
    assert not incomplete
    assert _masked(source, spans, "it's")


# --- F# and C# quote forms ---------------------------------------------------------------------------


def test_fsharp_type_variables_and_primed_names_are_not_character_literals():
    source = (
        "let read raw = JsonSerializer.Deserialize<'T>(raw, opts)\n"
        "let type' = 1\n"
        "let c = 'a'\n"
        "let n = '\\n'\n"
        "let u = '\\u0041'\n"
        "let after = AgentBuilder\n"
    )
    spans, incomplete = _ranges(source, "dotnet", ".fs")
    assert not incomplete
    assert _masked(source, spans, "'a'")
    assert not _masked(source, spans, "JsonSerializer")
    assert not _masked(source, spans, "AgentBuilder")


def test_a_csharp_verbatim_string_may_open_with_an_escaped_quote():
    source = 'const string Format = @"""{0}"" is invalid, AgentBuilder";\nvar later = AgentBuilder;\n'
    spans, incomplete = _ranges(source, "dotnet", ".cs")
    assert not incomplete
    assert _masked(source, spans, "invalid")
    assert not _masked(source, spans, "later")


def test_a_csharp_raw_string_literal_still_opens_with_three_quotes():
    source = 'var raw = """\nAgentBuilder\n""";\nvar later = 1;\n'
    spans, incomplete = _ranges(source, "dotnet", ".cs")
    assert not incomplete
    assert _masked(source, spans, "AgentBuilder")


# --- JavaScript and TypeScript -----------------------------------------------------------------------

_JSX = (
    "import React from 'react';\n"
    "export const App = () => (\n"
    "  <Main>\n"
    "    <Chat model={model} />\n"
    "  </Main>\n"
    ");\n"
    "import later from 'openai';\n"
)


@pytest.mark.parametrize("dialect", [".js", ".mjs", ".cjs"])
def test_jsx_in_a_javascript_file_is_read_with_the_jsx_walk(dialect: str):
    spans, incomplete = _ranges(_JSX, "javascript", dialect)
    assert not incomplete
    assert not _masked(_JSX, spans, "later from")


def test_jsx_is_not_retried_in_typescript_where_it_is_not_valid():
    _, incomplete = _ranges(_JSX, "javascript", ".ts")
    assert incomplete


def test_a_javascript_file_the_jsx_walk_cannot_close_stays_ambiguous():
    source = _JSX + "const open = `never closed\n"
    _, incomplete = _ranges(source, "javascript", ".js")
    assert incomplete


def test_a_typescript_non_null_assertion_before_a_division_is_not_a_regular_expression():
    source = (
        "const ttl = Math.ceil(idleTTL! / this.resolution) * this.resolution;\n"
        "const share = values[index]! / total;\n"
        "const quoted = tick!   / 2 + `x`;\n"
    )
    spans, incomplete = _ranges(source, "javascript", ".ts")
    assert not incomplete
    assert not _masked(source, spans, "total")


def test_a_bang_after_a_line_break_is_still_a_prefix_operator():
    source = "const x = value\n!/re'/.test(s)\n"
    spans, incomplete = _ranges(source, "javascript", ".ts")
    assert not incomplete
    assert _masked(source, spans, "re'")


def test_the_non_null_assertion_is_typescript_only():
    # In JavaScript a "!" cannot follow an operand, so after a line break it starts a new statement.
    source = "const x = value\n!/re'/.test(s)\n"
    spans, incomplete = _ranges(source, "javascript", ".js")
    assert not incomplete
    assert _masked(source, spans, "re'")


def test_a_qt_translation_file_named_ts_is_data_not_source():
    source = '<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE TS>\n<TS><context><name>Action</name></context></TS>\n'
    spans, incomplete = _ranges(source, "javascript", ".ts")
    assert not incomplete
    assert spans == [(0, len(source))]


# --- end to end --------------------------------------------------------------------------------------


def test_scan_is_complete_when_every_lexical_construct_is_readable(tmp_path):
    (tmp_path / "kernel.rs").write_text(
        'const KERNEL: &str = "\n__global__ void f() {}\nAgentBuilder::new(example)\n";\n', encoding="utf-8"
    )
    (tmp_path / "view.php").write_text(
        "<?php\n$sql = 'SELECT\nAgentBuilder::new(example)\nFROM t';\n", encoding="utf-8"
    )
    (tmp_path / "App.js").write_text(_JSX, encoding="utf-8")
    (tmp_path / "real.py").write_text(
        'from crewai import Agent\nagent = Agent(role="writer", goal="draft")\n', encoding="utf-8"
    )

    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is True
    assert all("framework.rig" not in finding["frameworks"] for finding in report["findings"])
    assert any("framework.crewai" in finding["frameworks"] for finding in report["findings"])


def test_a_bang_after_a_closing_brace_is_a_prefix_operator_so_the_code_after_it_stays_visible():
    # "}" ends a block or an object literal; "!" after it cannot be a postfix assertion.
    source = "if (ok) {\n}\n!/'/.test(s) && new OpenAI();\nconst later = new Anthropic();\n"
    spans, incomplete = _ranges(source, "javascript", ".ts")
    assert not incomplete
    assert _masked(source, spans, "/'/")
    assert not _masked(source, spans, "OpenAI")
    assert not _masked(source, spans, "Anthropic")


def test_a_typescript_module_that_starts_with_an_xml_declaration_is_not_masked():
    source = '<?xml version="1.0"?>\nimport OpenAI from "openai";\nexport const x = 1;\n'
    spans, incomplete = _ranges(source, "javascript", ".ts")
    assert not incomplete
    assert not _masked(source, spans, "OpenAI")


def test_a_tiled_tileset_named_tsx_is_data_but_a_file_with_module_syntax_is_not():
    data = '<?xml version="1.0"?>\n<tileset name="a"><image source="a.png"/></tileset>\n'
    spans, incomplete = _ranges(data, "javascript", ".tsx")
    assert not incomplete
    assert spans == [(0, len(data))]
    code = data + 'import OpenAI from "openai";\n'
    spans, _ = _ranges(code, "javascript", ".tsx")
    assert not _masked(code, spans, "OpenAI")
