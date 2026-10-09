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
from shadowscan.connectors.code.source_ranges import _javascript_ranges, noncode_ranges


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


# Before PHP 8 a "#[" line is a comment. Read as an attribute, the apostrophe in each first comment
# below opens a string that a later apostrophe closes, and the client code between them was masked
# while the walk reported itself complete. The first file is PHP 7 only; the second is valid in both
# versions (`php -l`), with the client code in a string in PHP 8 and executed in PHP 7.
_PHP_HASH_BRACKET_COMMENTS = {
    "php7-comment": (
        "<?php\n"
        "#[TODO] don't call the API from here\n"
        "use OpenAI\\Client;\n"
        '$client = OpenAI::client(getenv("OPENAI_KEY"));\n'
        '$r = $client->chat()->create(["model" => "gpt-4o"]);\n'
        "# that's all\n"
        'echo "done";\n'
    ),
    "both-versions": (
        "<?php\n#[Deprecated('x\n$client = OpenAI::client(getenv(\"OPENAI_KEY\"));\n# ')]\nfunction f() {}\n"
    ),
}


@pytest.mark.parametrize("source", _PHP_HASH_BRACKET_COMMENTS.values(), ids=_PHP_HASH_BRACKET_COMMENTS.keys())
def test_a_php_hash_bracket_comment_cannot_mask_the_code_after_it(source: str):
    # Only what both readings mask stays masked, so the code PHP 7 runs is analyzed.
    spans, _ = _ranges(source, "php", ".php")
    assert not _masked(source, spans, "$client = ")
    assert not _masked(source, spans, "OpenAI::client")


def test_a_php_reading_that_leaves_a_string_open_is_not_used():
    # Read as an attribute, the apostrophe opens a string that never closes, which PHP 8 rejects; the
    # file is read as PHP 7 reads it, and that reading is complete.
    source = "<?php\n#[TODO] don't call the API from here\n$client = OpenAI::client();\n"
    spans, incomplete = _ranges(source, "php", ".php")
    assert not incomplete
    assert _masked(source, spans, "don't")
    assert not _masked(source, spans, "OpenAI::client")


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


# Valid sloppy-mode scripts (Node's vm.Script accepts each) in which a "<" the JSX walk would read as an
# element is a comparison or a shift: `(yield < a) > 1` and `(mask << shift) > limit`. `of` after an
# operand (here after automatic semicolon insertion) is a name too, and so is a name the walk cuts before
# a keyword at a zero-width non-joiner, a combining mark or a Unicode escape. Each closes the
# "element" with a later `b </a>/.source` and uses `await / 2` to make the plain walk ambiguous, which
# is what triggers the JSX retry. Read as JSX, the client code between them was masked and the scan
# looked complete.
_NOT_JSX = {
    "yield-comparison": (
        "var yield = 0, a = 2, b = 1;\n"
        "var t = yield <a> 1;\n"
        'const OpenAI = require("openai");\n'
        "const client = new OpenAI();\n"
        'client.chat.completions.create({model: "gpt-4o", messages: []});\n'
        "var w = await / 2 / 1;\n"
        "var u = b </a>/.source;\n"
    ),
    "await-comparison": (
        "var await = 0, a = 2, b = 1;\n"
        "var t = await <a> 1;\n"
        'const OpenAI = require("openai");\n'
        "const client = new OpenAI();\n"
        "var w = await / 2 / 1;\n"
        "var u = b </a>/.source;\n"
    ),
    "left-shift": (
        "var mask = 1, shift = 2, limit = 3;\n"
        "var r = mask<<shift>limit;\n"
        'const OpenAI = require("openai");\n'
        'new OpenAI().chat.completions.create({model: "gpt-4o", messages: []});\n'
        "var w = await / 2 / 1;\n"
        "var q = r </shift>/.source;\n"
    ),
    "of-after-asi": (
        "var of = 0, a = 2, b = 1;\n"
        "var t = b\n"
        "of <a> 1;\n"
        'const OpenAI = require("openai");\n'
        "const client = new OpenAI();\n"
        'client.chat.completions.create({model: "gpt-4o", messages: []});\n'
        "var w = await / 2 / 1;\n"
        "var u = b </a>/.source;\n"
    ),
    **{
        f"keyword-after-{kind}": (
            f"var a{joint}typeof = 0, a = 2, b = 1;\n"
            f"var t = a{joint}typeof <a> 1;\n"
            'const OpenAI = require("openai");\n'
            "const client = new OpenAI();\n"
            "var w = await / 2 / 1;\n"
            "var u = b </a>/.source;\n"
        )
        for kind, joint in (("zwnj", "\u200c"), ("combining-mark", "\u0301"), ("escape", "\\u{62}"))
    },
}


@pytest.mark.parametrize("jsx", [False, True])
@pytest.mark.parametrize("dialect", [".js", ".mjs", ".cjs"])
@pytest.mark.parametrize("source", _NOT_JSX.values(), ids=_NOT_JSX.keys())
def test_the_jsx_retry_does_not_read_a_comparison_or_a_shift_as_an_element(
    source: str, dialect: str, jsx: bool
):
    # The plain walk's ambiguity stands: the scan stays incomplete instead of masking the client. A
    # caller that asks for JSX in such a file gets the same guarded retry.
    _, incomplete = noncode_ranges(source, "javascript", dialect, jsx=jsx)
    assert incomplete


@pytest.mark.parametrize("source", _NOT_JSX.values(), ids=_NOT_JSX.keys())
def test_a_script_read_as_jsx_cannot_hide_its_client_from_a_scan(tmp_path, source: str):
    (tmp_path / "app.js").write_text(source, encoding="utf-8")
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)
    assert result.exit_code == 3, result.output
    assert report["summary"]["complete"] is False
    assert any("provider.openai" in finding["model_providers"] for finding in report["findings"])


@pytest.mark.parametrize(
    "line",
    [
        "return <b>{x}</b>;",
        "render(<b>{x}</b>, root);",
        "const make = () => <b>{x}</b>;",
        "return (<div>{x}</div>);",
        "case 1: return <b>{x}</b>;",
        "return void <b>{x}</b>;",
        "throw <b>{x}</b>;",
        "x = typeof <b>{x}</b>;",
    ],
)
def test_the_jsx_retry_still_reads_elements_after_punctuation_and_reserved_words(line: str):
    # A closing tag after an expression makes the plain walk ambiguous; the JSX walk reads the file.
    source = f"function f(x) {{\n  switch (x) {{ default: {line} }}\n}}\nconst later = new OpenAI();\n"
    assert _javascript_ranges(source)[1]
    spans, incomplete = noncode_ranges(source, "javascript", ".js")
    assert not incomplete
    assert not _masked(source, spans, "later")


def test_jsx_files_still_read_an_element_after_yield_and_await():
    # In a .jsx or .tsx file JSX is declared, so `yield <Spinner />` in a generator is an element.
    source = (
        "async function* render() {\n"
        "  yield <Spinner />;\n"
        "  const reply = await <Answer text={text} />;\n"
        "}\n"
        "const later = new OpenAI();\n"
    )
    spans, incomplete = _ranges(source, "javascript", ".jsx")
    assert not incomplete
    assert _masked(source, spans, "Spinner")
    assert not _masked(source, spans, "later")


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


_TS_ROOTED_TYPESCRIPT = {
    # `<TS>0;` is a type assertion (transpileModule reports no diagnostic for any of these).
    "type-assertion": (
        ".ts",
        "<TS>0;\n"
        "type TS = number;\n"
        'const { default: OpenAI } = await import("openai");\n'
        'const client = new OpenAI({ apiKey: "x" });\n'
        'void client.chat.completions.create({ model: "gpt-4o", messages: [] });\n',
    ),
    # Well-formed XML whose root is TS, and TypeScript whose closing tag is in a line comment.
    "well-formed-xml": (
        ".ts",
        '<TS>0; const { default: OpenAI } = await import("openai"); new OpenAI(); // </TS>\n',
    ),
    # Well-formed XML whose root is TS, and a TSX element whose child is an expression.
    "jsx-element": (
        ".tsx",
        '<TS version="2.1">{(async () => { const { default: OpenAI } = await import("openai"); '
        "new OpenAI(); })()}</TS>\n",
    ),
}


@pytest.mark.parametrize(
    ("dialect", "source"), _TS_ROOTED_TYPESCRIPT.values(), ids=_TS_ROOTED_TYPESCRIPT.keys()
)
def test_typescript_that_starts_with_a_ts_element_is_not_masked_as_a_translation(dialect: str, source: str):
    # Only an XML declaration or a document type declaration, which no TypeScript can start with,
    # makes a .ts or .tsx file an XML document.
    spans, incomplete = _ranges(source, "javascript", dialect)
    assert spans != [(0, len(source))]
    assert incomplete or not _masked(source, spans, "OpenAI")


@pytest.mark.parametrize(
    "source",
    [
        # Not well-formed: the root element is never closed.
        '<?xml version="1.0"?>\n<TS version="2.1"><context>\n',
        # Text after the root element.
        '<?xml version="1.0"?>\n<TS version="2.1"></TS>\nconst x = 1;\n',
        # A document that declares entities is not parsed.
        '<?xml version="1.0"?>\n<!DOCTYPE TS [<!ENTITY a "b">]>\n<TS>&a;</TS>\n',
    ],
    ids=["unclosed", "trailing-text", "entities"],
)
def test_a_ts_document_that_is_not_well_formed_xml_is_not_masked(source: str):
    spans, _ = _ranges(source, "javascript", ".ts")
    assert spans != [(0, len(source))]


def test_a_tiled_tileset_named_tsx_is_data_but_a_file_with_module_syntax_is_not():
    data = '<?xml version="1.0"?>\n<tileset name="a"><image source="a.png"/></tileset>\n'
    spans, incomplete = _ranges(data, "javascript", ".tsx")
    assert not incomplete
    assert spans == [(0, len(data))]
    code = data + 'import OpenAI from "openai";\n'
    spans, _ = _ranges(code, "javascript", ".tsx")
    assert not _masked(code, spans, "OpenAI")
