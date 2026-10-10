"""Lexical coverage: a construct the language allows must not make a complete scan incomplete, and a
genuinely unterminated literal must still do so. Fail closed is kept; only false ambiguity goes."""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges


@pytest.mark.parametrize(
    ("language", "dialect", "text"),
    [
        # Rust allows a line break inside an ordinary string literal, and a byte string may continue a line.
        ("rust", None, 'fn f() {\n    let s = "\n{matches} matches\n";\n}\n'),
        ("rust", None, 'fn f() {\n    let s = &b"\\\n# Test\n";\n}\n'),
        # JSX in a .js file: plain lexing fails, and the JSX reading lexes completely.
        ("javascript", ".js", "function A() {\n  return <>{children}</>;\n}\n"),
        ("javascript", ".mjs", "const A = () => <>{x}</>;\n"),
        ("javascript", ".js", "export const A = () => <p>match src/*.js files</p>;\n"),
        # Plain JavaScript is unchanged by the JSX reading.
        ("javascript", ".js", "if (a < b && c > d) { x = 1; }\n"),
    ],
)
def test_constructs_the_language_allows_do_not_make_lexing_incomplete(
    language: str, dialect: str | None, text: str
) -> None:
    assert noncode_ranges(text, language, dialect)[1] is False


@pytest.mark.parametrize(
    ("language", "dialect", "text"),
    [
        ("rust", None, 'fn f() {\n    let s = "abc\n}\n'),
        ("javascript", ".js", "const s = `abc\nconst t = 1;\n"),
        ("javascript", ".js", "/* open\nconst t = 1;\n"),
    ],
)
def test_genuinely_unterminated_literals_stay_incomplete(
    language: str, dialect: str | None, text: str
) -> None:
    assert noncode_ranges(text, language, dialect)[1] is True


def test_ruby_heredoc_interpolation_stays_incomplete_and_masked() -> None:
    # Interpolated Ruby is not scanned as code: the scanner's matchers are not Ruby-aware, so a closed
    # interpolation such as #{AiServices.builder(x)} would report a Java framework in a Ruby file.
    text = "docs = <<DOC\n#{AiServices.builder(example)}\nDOC\n"
    spans, ambiguous = noncode_ranges(text, "ruby")
    index = text.index("AiServices")
    assert ambiguous is True and any(start <= index < end for start, end in spans)


def test_typescript_is_never_read_as_jsx() -> None:
    # The same text is complete as JSX in a .js file, but a .ts file has no JSX reading: it stays incomplete.
    text = "export const A = () => <p>match src/*.js files</p>;\n"
    assert noncode_ranges(text, "javascript", ".ts")[1] is True


def test_rust_multiline_string_keeps_the_scan_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "main.rs").write_text('fn main() {\n    println!("\n{x}\n");\n}\n', encoding="utf-8")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.incomplete and not ctx.stats.errors


def test_jsx_in_a_js_file_keeps_the_scan_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "App.js").write_text("export function App({ children }) {\n  return <>{children}</>;\n}\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.incomplete and not ctx.stats.errors


def test_unterminated_rust_string_still_marks_the_scan_incomplete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "main.rs").write_text('fn main() {\n    let s = "abc\n}\n', encoding="utf-8")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert ctx.stats.incomplete
