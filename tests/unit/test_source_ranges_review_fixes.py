"""Lexer review: constructs that hid code after the multi-line string and here-document changes.

An independent review of the lexer changes found inputs where a stray quote or
an interpolation the lexer does not parse masked real code while the file was
reported complete. Each case here must either leave the code visible or mark
the walk incomplete; legitimate multi-line strings stay complete.
"""

from __future__ import annotations

import time

import pytest

from shadowscan.connectors.code.source_ranges import JSX_DIALECTS, noncode_ranges


def _lex(text: str, language: str, dialect: str | None = None):
    return noncode_ranges(text, language, dialect, jsx=dialect in JSX_DIALECTS)


def _visible(text: str, spans, needle: str) -> bool:
    at = text.index(needle)
    return not any(start <= at < end for start, end in spans)


@pytest.mark.parametrize(
    "source",
    [
        "s = t.sub(/'/, '')\nagent = AiServices.builder(example)\n# Don't log the key\nputs 'done'\n",
        "parts = Label.split($')\nagent = AiServices.builder(example)\nputs 'it''s'\n",
        "case c\nin ?'\n  agent = AiServices.builder(example)\nend\nputs 'x'\n",
        "words = %w[don't stop]\nagent = AiServices.builder(example)\nputs 'done'\n",
    ],
    ids=["regex-quote", "global-quote", "char-literal", "percent-words"],
)
def test_ruby_stray_quote_never_hides_code_silently(source: str) -> None:
    spans, incomplete = _lex(source, "ruby")
    assert incomplete or _visible(source, spans, "AiServices.builder")


def test_rust_unicode_char_literal_before_a_quote(source: str = "") -> None:
    source = "let q = ['\\u{201C}','\"'];\nlet agent = AgentBuilder::new(example);\nlet s = raw.trim_matches('\"');\n"
    spans, incomplete = _lex(source, "rust")
    assert not incomplete and _visible(source, spans, "AgentBuilder::new")


@pytest.mark.parametrize(
    ("language", "source", "inside"),
    [
        ("rust", 'let s = "first\nsecond";\nlet agent = AgentBuilder::new(x);\n', "second"),
        ("rust", 'println!(\n    "first\nsecond"\n);\nlet agent = AgentBuilder::new(x);\n', "second"),
        ("php", '<?php\n$sql = "SELECT *\nFROM t";\n$agent = AiServices::builder();\n', "FROM t"),
        ("php", "<?php\necho 'first\nsecond';\n$agent = AiServices::builder();\n", "second"),
        ("php", '<?php\n$a = $b . "first\nsecond";\n$agent = AiServices::builder();\n', "second"),
        ("ruby", 'puts "first\nsecond"\nagent = AiServices.builder(x)\n', "second"),
        ("ruby", "x = 'first\nsecond'\nagent = AiServices.builder(x)\n", "second"),
        ("ruby", "foo(x)\n'first\nsecond'\nagent = AiServices.builder(x)\n", "second"),
    ],
)
def test_multiline_strings_at_an_expression_start_stay_complete(language, source, inside) -> None:
    spans, incomplete = _lex(source, language)
    assert not incomplete
    assert not _visible(source, spans, inside)
    assert _visible(source, spans, "Builder") if "Builder" in source else True


@pytest.mark.parametrize(
    "source",
    [
        '<?php\n$r = "Answer:\n{$a->run(AiServices.builder($example))}\n";\n',
        '<?php\n$r = "Answer: {$a->run(AiServices.builder($example))}";\n',
        '<?php\n$r = "Answer: ${a(AiServices.builder($example))}";\n',
        "<?php\n$r = `run {$a->run(AiServices.builder($example))}`;\n",
    ],
    ids=["multi-line", "one-line", "dollar-brace", "backtick"],
)
def test_php_string_interpolation_is_code(source: str) -> None:
    spans, incomplete = _lex(source, "php")
    assert not incomplete
    assert _visible(source, spans, "AiServices.builder")
    assert not _visible(source, spans, "Answer" if "Answer" in source else "run ")


def test_php_escaped_dollar_brace_is_text() -> None:
    source = '<?php\n$r = "cost: \\${AiServices.builder}";\n$x = 1;\n'
    spans, incomplete = _lex(source, "php")
    assert not incomplete and not _visible(source, spans, "AiServices.builder")


@pytest.mark.parametrize(
    "body",
    [
        "#{s.split(/}/).map { AiServices.builder(_1) }}",
        "#{[?}, AiServices.builder(x)]}",
        '#{log("#{"}"}", AiServices.builder(x))}',
        "#{ # pick }\n    AiServices.builder(x)\n  }",
        "#{%w[}].first + AiServices.builder(x)}",
    ],
    ids=["regex", "char-literal", "nested-interpolation", "comment", "percent-literal"],
)
def test_ruby_heredoc_interpolation_the_lexer_cannot_parse_is_incomplete(body: str) -> None:
    source = f"text = <<~TXT\n  {body}\nTXT\nputs text\n"
    spans, incomplete = _lex(source, "ruby")
    assert incomplete or _visible(source, spans, "AiServices.builder")


def test_ruby_heredoc_ternary_and_division_stay_complete() -> None:
    source = "text = <<~TXT\n  #{count > 1 ? 's' : ''} #{total / count}\nTXT\nputs text\n"
    _, incomplete = _lex(source, "ruby")
    assert not incomplete


def test_csharp_dollar_run_is_linear() -> None:
    source = "$" * 250_000
    started = time.monotonic()
    _lex(source, "dotnet", ".cs")
    assert time.monotonic() - started < 2.0


@pytest.mark.parametrize("dialect", [".js", ".ts"])
@pytest.mark.parametrize(
    "source",
    [
        "export default !/'/.test(s) && new OpenAI();\n",
        "if (x) {} !/'/.test(s) && new OpenAI();\n",
        "let ok = flag /* c\n */ !/'/.test(s); const c = new OpenAI();\n",
        "function f() { return !/'/.test(s) && new OpenAI(); }\n",
    ],
    ids=["after-default", "after-brace", "after-multiline-comment", "after-return"],
)
def test_prefix_not_before_a_regex_is_read_as_a_regex(source: str, dialect: str) -> None:
    spans, incomplete = _lex(source, "javascript", dialect)
    assert not incomplete and _visible(source, spans, "new OpenAI")


@pytest.mark.parametrize("dialect", [".ts", ".tsx"])
def test_typescript_non_null_assertion_before_division_still_divides(dialect: str) -> None:
    source = "const r = a[b]! / n; const s = '/'; const c = new OpenAI();\n"
    spans, incomplete = _lex(source, "javascript", dialect)
    assert not incomplete and _visible(source, spans, "new OpenAI")


def test_tsx_const_type_parameter_is_not_jsx() -> None:
    source = "const f = <const T extends object>(x: T) => x;\nconst c = new OpenAI();\n"
    spans, incomplete = _lex(source, "javascript", ".tsx")
    assert not incomplete and _visible(source, spans, "new OpenAI")
