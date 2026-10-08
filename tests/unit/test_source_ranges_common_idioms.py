"""Common syntax that the lexical walk read as unterminated, leaving real scans incomplete.

Each case is valid source in its language. Before the fix the walk masked the
rest of the file and reported incomplete lexical analysis (exit 3).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors.code.source_ranges import JSX_DIALECTS, noncode_ranges


def _masked(source: str, language: str, dialect: str) -> list[str]:
    spans, incomplete = noncode_ranges(source, language, dialect, jsx=dialect in JSX_DIALECTS)
    assert not incomplete
    return [source[start:end] for start, end in spans]


def _visible(source: str, language: str, dialect: str, code: str) -> bool:
    spans, _ = noncode_ranges(source, language, dialect, jsx=dialect in JSX_DIALECTS)
    start = source.index(code)
    return not any(a <= start < b for a, b in spans)


# --- JavaScript and TypeScript --------------------------------------------------------------------

REACT_COMPONENT = (
    "export function Banner({ user }) {\n"
    "  return (\n"
    '    <Card title="Account">\n'
    "      <p>Don't share {user.name}'s key</p>\n"
    "    </Card>\n"
    "  );\n"
    "}\n"
    "const client = new OpenAI();\n"
)


@pytest.mark.parametrize("dialect", [".js", ".jsx", ".mjs", ".cjs"])
def test_jsx_in_javascript_files_is_lexed_as_jsx(dialect: str) -> None:
    masked = _masked(REACT_COMPONENT, "javascript", dialect)
    assert any("Don't share " in text for text in masked)
    assert _visible(REACT_COMPONENT, "javascript", dialect, "new OpenAI()")


@pytest.mark.parametrize("dialect", [".ts", ".mts", ".cts"])
def test_typescript_files_keep_type_assertions_rather_than_jsx(dialect: str) -> None:
    source = "const n = <number>value;\nconst client = new OpenAI();\n"
    assert dialect not in JSX_DIALECTS
    assert _masked(source, "javascript", dialect) == []


@pytest.mark.parametrize(
    "expression",
    ["weights[id]! / total", "lookup(id)! / 2", "this.count! / size", "value !  / 4"],
)
def test_non_null_assertion_before_division_is_not_a_regular_expression(expression: str) -> None:
    source = f"const share = {expression};\nconst client = new OpenAI();\n"
    assert _masked(source, "javascript", ".ts") == []
    assert _visible(source, "javascript", ".ts", "new OpenAI()")


def test_exclamation_after_a_line_break_is_still_a_prefix_operator() -> None:
    # Automatic semicolon insertion ends `x` before the `!`, which then negates a regular expression.
    source = "x\n!/a'b/.test(y)\nconst client = new OpenAI();\n"
    assert _masked(source, "javascript", ".ts") == ["/a'b/"]


def test_inequality_after_an_operand_still_lets_a_regular_expression_start() -> None:
    assert _masked("if (a != /x'/.source) {}\n", "javascript", ".ts") == ["/x'/"]


def test_tsx_call_signature_type_parameters_are_not_a_jsx_element() -> None:
    # No arrow function follows, so only the type-parameter rule can tell this from a JSX element.
    members = "".join(f"  option{n}?: string;\n" for n in range(20))
    source = (
        "type Select = {\n"
        "  <V extends string>(props: Props<V>): React.ReactElement | null;\n"
        f"{members}"
        "};\n"
        "export function Picker() {\n"
        '  return <Select<Option> value="it\'s" />;\n'
        "}\n"
        "const client = new OpenAI();\n"
    )
    masked = _masked(source, "javascript", ".tsx")
    assert '"it\'s"' in "".join(masked)
    assert _visible(source, "javascript", ".tsx", "new OpenAI()")


@pytest.mark.parametrize("head", ["<T = unknown>(value: T) => value", "<T extends object>(value: T): T"])
def test_tsx_defaulted_or_constrained_type_parameters_are_code(head: str) -> None:
    source = f"const f = {head};\nconst client = new OpenAI();\n"
    assert _masked(source, "javascript", ".tsx") == []


# --- Strings that span lines -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("language", "dialect", "source", "code"),
    [
        (
            "rust",
            ".rs",
            'let sql = "SELECT id\n  FROM agents";\nlet agent = AgentBuilder::new();\n',
            "AgentBuilder::new()",
        ),
        (
            "rust",
            ".rs",
            'format!("#### Steps\n\n{}", s);\nlet a = AgentBuilder::new();\n',
            "AgentBuilder::new()",
        ),
        (
            "rust",
            ".rs",
            'let b = b"line one\nline two";\nlet a = AgentBuilder::new();\n',
            "AgentBuilder::new()",
        ),
        (
            "php",
            ".php",
            '<?php\n$sql = "SELECT id\n  FROM agents";\nAiServices::builder($x);\n',
            "AiServices::",
        ),
        (
            "php",
            ".php",
            "<?php\n$sql = 'SELECT id\n  FROM agents';\nAiServices::builder($x);\n",
            "AiServices::",
        ),
        ("ruby", ".rb", 'sql = "SELECT id\n  FROM agents"\nAiServices.builder(foo)\n', "AiServices.builder"),
        ("ruby", ".rb", "sql = 'SELECT id\n  FROM agents'\nAiServices.builder(foo)\n", "AiServices.builder"),
    ],
)
def test_quoted_strings_may_span_lines(language: str, dialect: str, source: str, code: str) -> None:
    masked = _masked(source, language, dialect)
    assert any("\n" in text for text in masked)
    assert _visible(source, language, dialect, code)


def test_go_interpreted_strings_still_end_at_a_line_break() -> None:
    _, incomplete = noncode_ranges('package a\nvar q = "a\nb"\n', "go", ".go")
    assert incomplete


# --- C# raw and verbatim strings -------------------------------------------------------------------


@pytest.mark.parametrize("quotes", [3, 4, 5, 8])
def test_csharp_raw_string_closes_with_its_own_quote_count(quotes: int) -> None:
    fence = '"' * quotes
    shorter = '"' * (quotes - 1)
    source = f"var s = {fence}\n  holds {shorter} inside\n  {fence};\nAIFunctionFactory.Create(foo);\n"
    assert _masked(source, "dotnet", ".cs") == [source[source.index(fence) : source.rindex(fence) + quotes]]
    assert _visible(source, "dotnet", ".cs", "AIFunctionFactory.Create")


def test_csharp_raw_interpolation_needs_as_many_braces_as_dollars() -> None:
    source = 'var s = $$"""\n  { "tool": {{AIFunctionFactory.Create(foo)}} }\n  """;\n'
    spans, incomplete = noncode_ranges(source, "dotnet", ".cs")
    assert not incomplete
    assert _visible(source, "dotnet", ".cs", "AIFunctionFactory.Create")
    assert not _visible(source, "dotnet", ".cs", '"tool"')


def test_csharp_verbatim_string_starting_with_an_escaped_quote_is_not_raw() -> None:
    source = 'Find(stream, @"""assistant_id"":""wf_", @"""version");\nAIFunctionFactory.Create(foo);\n'
    assert _masked(source, "dotnet", ".cs") == ['@"""assistant_id"":""wf_"', '@"""version"']
    assert _visible(source, "dotnet", ".cs", "AIFunctionFactory.Create")


def test_fsharp_triple_quoted_string_always_uses_three_quotes() -> None:
    source = 'let s = """"quoted" text"""\nlet agent = AIFunctionFactory.Create(foo)\n'
    assert _masked(source, "dotnet", ".fs") == ['""""quoted" text"""']


# --- Here-documents --------------------------------------------------------------------------------


def test_php_heredoc_interpolation_stays_code() -> None:
    source = "<?php\n$prompt = <<<EOT\nAsk {$client->chat()->create($args)} and ${name}\nEOT;\nfoo();\n"
    assert _visible(source, "php", ".php", "$client->chat()")
    assert _visible(source, "php", ".php", "name}")
    assert not _visible(source, "php", ".php", "Ask")
    assert _visible(source, "php", ".php", "foo();")


def test_php_nowdoc_braces_are_text() -> None:
    source = "<?php\n$doc = <<<'EOT'\nliteral {$client->chat()}\nEOT;\nfoo();\n"
    _masked(source, "php", ".php")
    assert not _visible(source, "php", ".php", "$client->chat()")


@pytest.mark.parametrize("closing", ["    EOT, 2);", "EOT);", "\tEOT ;"])
def test_php_flexible_closing_marker_lets_code_continue_on_its_line(closing: str) -> None:
    source = f"<?php\n$x = f(<<<EOT\n    hello\n{closing}\nAiServices::builder($x);\n"
    _masked(source, "php", ".php")
    assert _visible(source, "php", ".php", "AiServices::")


def test_php_heredoc_line_starting_with_a_longer_name_does_not_close_it() -> None:
    source = "<?php\n$x = <<<EOT\nEOTX AiServices::builder($x)\nEOT;\n"
    _masked(source, "php", ".php")
    assert not _visible(source, "php", ".php", "AiServices::")


def test_ruby_heredoc_interpolation_stays_code() -> None:
    source = 'sql = <<~SQL\n  SELECT #{AiServices.builder(foo)["id"]}\n  WHERE x = \\#{literal}\nSQL\nbar\n'
    assert _visible(source, "ruby", ".rb", "AiServices.builder")
    assert not _visible(source, "ruby", ".rb", "literal}")


def test_ruby_single_quoted_heredoc_is_literal() -> None:
    source = "doc = <<~'DOC'\n  #{AiServices.builder(foo)}\nDOC\n"
    _masked(source, "ruby", ".rb")
    assert not _visible(source, "ruby", ".rb", "AiServices.builder")


def test_interpolation_continuing_on_another_line_is_still_incomplete() -> None:
    _, incomplete = noncode_ranges("sql = <<~SQL\n  SELECT #{x\n  }\nSQL\n", "ruby", ".rb")
    assert incomplete


# --- End to end ------------------------------------------------------------------------------------


def test_react_component_in_a_js_file_keeps_the_scan_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"openai": "^4.0.0"}}')
    (tmp_path / "Banner.js").write_text('import OpenAI from "openai";\n' + REACT_COMPONENT)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not ctx.stats.incomplete
    assert findings
