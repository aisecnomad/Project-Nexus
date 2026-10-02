"""JavaScript and TypeScript source ranges: JSX text is masked, TSX generics are not JSX, and a slash is
a regular expression or a division exactly where the language says it is."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind

VALID_TSX = {
    "type-arguments-on-child": (
        "export const A = () => (\n  <Box>\n    <Select<Option> value={v} onChange={set} />\n  </Box>\n);\n"
    ),
    "literal-type-arguments": (
        "export const B = () => (\n  <Box>\n    <Picker<'day' | 'hour'> value={u}>\n"
        "      <Item />\n    </Picker>\n  </Box>\n);\n"
    ),
    "object-type-arguments-at-expression": (
        "export const C = () => (\n  <Form<{ email: string; name: string }> onSubmit={go}>\n"
        "    <input />\n  </Form>\n);\n"
    ),
    "line-comment-with-apostrophe": (
        "export const D = () => (\n  <ul\n    // the browser's default list role\n"
        '    role="list"\n  >\n    <li>x</li>\n  </ul>\n);\n'
    ),
    "commented-out-attribute-expression": (
        "export const E = () => (\n  <input\n    // style={{\n    //   width: 1,\n    // }}\n"
        "    size={3}\n  />\n);\n"
    ),
    "block-comment-in-tag": "export const F = () => <input /* it's fine */ size={3} />;\n",
    "child-text-starting-with-parenthesis": "export const G = ({ n }: { n: number }) => <Text>({n})</Text>;\n",
}


@pytest.mark.parametrize("source", VALID_TSX.values(), ids=VALID_TSX.keys())
def test_valid_tsx_constructs_are_lexed_completely(source: str) -> None:
    _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous


def test_jsx_text_after_typed_element_stays_masked() -> None:
    source = (
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "export const View = () => (\n  <Box>\n    <Select<Option>\n"
        "      // the user's choice\n      value={v}\n    />\n"
        "    <Text>(createReactAgent( is documented here)</Text>\n  </Box>\n);\n"
        "const graph = createReactAgent({});\n"
    )
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    prose = source.index("createReactAgent( is")
    code = source.rindex("createReactAgent(")
    assert any(start <= prose < end for start, end in ignored)
    assert not any(start <= code < end for start, end in ignored)


@pytest.mark.parametrize(
    "source",
    [
        "const identity = <T>(value: T): T => value;\n",
        "const identity = <T>(value: T) => value;\n",
        "const constrained = <T extends object>(value: T): T => value;\n",
    ],
)
def test_generic_arrow_functions_are_not_jsx(source: str) -> None:
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert not any(start <= source.index("value") < end for start, end in ignored)


def test_unbalanced_type_arguments_still_fail_closed() -> None:
    _, ambiguous = noncode_ranges(
        "const v = (\n  <Box>\n    <Select<Option value={v} />\n", "javascript", ".tsx", jsx=True
    )
    assert ambiguous


def test_typed_jsx_component_file_scans_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "Agent.tsx").write_text(
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "export const Panel = () => (\n  <Box>\n    <Select<Option> value={v} />\n"
        "    <Text>({count})</Text>\n  </Box>\n);\n"
        "export const graph = createReactAgent({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        "const a = <div /* note */>{x}</div>;\n",
        "const a = <div\n  // note\n>{x}</div>;\n",
        'const a = <div title="a/" /* note */>{x}</div>;\n',
    ],
)
def test_comment_before_tag_end_does_not_self_close(source: str) -> None:
    _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous


def test_self_closing_tag_after_comment_still_closes() -> None:
    source = "const a = <Box>\n  <input /* note */ />\n</Box>;\nconst b = run();\n"
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert not any(start <= source.index("run()") < end for start, end in ignored)


# --- Regular expression or division ---------------------------------------------------------------
# A keyword-named property is an operand: `o.of / 1` divides. Treating it as a keyword turned the rest
# of the line into a "regular expression" that hid whatever code sat between two slashes.

KEYWORD_NAMES = (
    "await",
    "case",
    "delete",
    "do",
    "else",
    "in",
    "instanceof",
    "new",
    "of",
    "return",
    "throw",
    "typeof",
    "void",
    "yield",
)
CONTROL_NAMES = ("catch", "for", "if", "switch", "while", "with")
PROPERTY_FORMS = {
    "dot": ("o.{w} / 2; o.{w} / 3;", []),
    "optional-chain": ("o?.{w} / 2; o?.{w} / 3;", []),
    "newlines": ("o\n  .{w}\n  / 2; o.{w} / 3;", []),
    "block-comment": ("o. /* note */ {w} / 2; o.{w} / 3;", ["/* note */"]),
    "line-comment": ("o.// note\n{w} / 2; o.{w} / 3;", ["// note"]),
    "private-name": ("this.#{w} / 2; this.#{w} / 3;", []),
}


def _masked(source: str, *, ext: str = ".js") -> list[str]:
    """Return the complete lexing of ``source``: the text of every masked span, in order."""
    ignored, ambiguous = noncode_ranges(source, "javascript", ext)
    assert not ambiguous
    return [source[start:end] for start, end in ignored]


@pytest.mark.parametrize("word", KEYWORD_NAMES)
@pytest.mark.parametrize("form", PROPERTY_FORMS)
def test_keyword_named_property_is_divided(word: str, form: str) -> None:
    template, expected = PROPERTY_FORMS[form]
    assert _masked(template.format(w=word)) == expected


@pytest.mark.parametrize("word", CONTROL_NAMES)
@pytest.mark.parametrize("access", ["o.{w}(x) / 2; o.{w}(y) / 3;", "o?.{w}(x) / 2; o?.{w}(y) / 3;"])
def test_control_keyword_named_method_does_not_start_a_regex(word: str, access: str) -> None:
    assert _masked(access.format(w=word)) == []


REGEX_OR_DIVISION = {
    "property-chain": ("a.b.of / c.d.in / e.new / f", []),
    "regex-after-property-call": ("o.of(1); x = /re/g; o.of / 2;", ["/re/g"]),
    "of-as-variable": ("const of = 8; of / 2; of / 3;", []),
    "of-as-arrow-parameter": ("const f = of => of / 2; f(of / 3);", []),
    "of-in-parentheses-and-array": ("(of) / 2; [of / 2, of / 3];", []),
    "of-after-spread": ("f(...of / 2, ...of / 3);", []),
    "for-of-regex": ("for (const m of /re/g[Symbol.matchAll](s)) {}", ["/re/g"]),
    "for-of-array-pattern": ("for (const [a, b] of /re/g[Symbol.matchAll](s)) {}", ["/re/g"]),
    "for-of-object-pattern": ("for (const { a } of /re/g[Symbol.matchAll](s)) {}", ["/re/g"]),
    "for-await-of-regex": ("for await (const m of /re/g[Symbol.matchAll](s)) {}", ["/re/g"]),
    "spread-regex": ("x = [.../re/.exec(s)]; f(.../re2/g.exec(s));", ["/re/", "/re2/g"]),
    "spread-identifier": ("x = [...a / 2];", []),
    "spread-property": ("x = [...a.of / 2, ...b?.in / 3];", []),
    "return": ("function f(s) { return /re/.test(s); }", ["/re/"]),
    "typeof": ("x = typeof /re/;", ["/re/"]),
    "void": ("x = void /re/;", ["/re/"]),
    "delete": ("delete /re/.x;", ["/re/"]),
    "throw": ("throw /re/;", ["/re/"]),
    "new": ("x = new /re/.constructor();", ["/re/"]),
    "in": ("x = a in /re/;", ["/re/"]),
    "instanceof": ("x = a instanceof /re/.constructor;", ["/re/"]),
    "assignments": ("x = /re/g; y += /re/; z ||= /a/;", ["/re/g", "/re/", "/a/"]),
    "if-head": ("if (x) /re/.test(y);", ["/re/"]),
    "while-head": ("while (x) /re/.exec(y);", ["/re/"]),
    "for-head": ("for (;;) /re/.exec(y);", ["/re/"]),
    "else": ("if (x) y(); else /re/.test(y);", ["/re/"]),
    "do": ("do /re/.test(y); while (z);", ["/re/"]),
    "case": ("switch (x) { case /re/.test(y): break; }", ["/re/"]),
    "ternary": ("x = a ? /a/ : /b/;", ["/a/", "/b/"]),
    "arguments": ("f(/re/, /re2/g);", ["/re/", "/re2/g"]),
    "array": ("x = [/a/, /b/];", ["/a/", "/b/"]),
    "object-value": ("x = { k: /re/, j: /re2/ };", ["/re/", "/re2/"]),
    "logical-and-not": ("x = y || /a/; z = y && /b/.test(q); w = !/c/.test(q);", ["/a/", "/b/", "/c/"]),
    "arrow-body": ("const f = (x) => /re/.test(x);", ["/re/"]),
    "interpolation": ("x = `${/re/.test(y)}`;", ["`", "${", "/re/", "}", "`"]),
    "quotes-inside-regex": ("x = /'/.test(s); y = /\"/.test(s); z = /`/.test(s);", ["/'/", '/"/', "/`/"]),
    "slash-inside-class": ("x = /[/]\\//.test(s);", ["/[/]\\//"]),
    "identifiers": ("x = a / b / c;", []),
    "grouped": ("x = (a + b) / 2; y = (a) / (b);", []),
    "index": ("x = arr[0] / 2; y = m[1][2] / 3;", []),
    "numbers": ("x = 1 / 2; y = 1.5 / 2; z = 0x10 / 2; w = .5 / 2;", []),
    "postfix": ("x = a++ / 2; y = b-- / 2;", []),
    "strings-and-templates": ("x = 'a'.length / 2; y = `t`.length / 3;", ["'a'", "`", "t`"]),
    "call-results": ("x = f() / 2; y = f(g(1)) / 3;", []),
    "member-chain": ("x = a.b.c / d.e;", []),
    "compound-assignment": ("x /= 2; y /= 3;", []),
    "literals": ("x = this / 2; y = null / 1; z = true / 1;", []),
    "object-property": ("x = {a: 1}.a / 2;", []),
}


@pytest.mark.parametrize("source, expected", REGEX_OR_DIVISION.values(), ids=REGEX_OR_DIVISION.keys())
def test_slash_is_a_regex_or_a_division_where_the_language_says(source: str, expected: list[str]) -> None:
    assert _masked(source) == expected


@pytest.mark.parametrize("word", ["await", "yield"])
@pytest.mark.parametrize("gap", [" ", "\n", " /* note */ ", " // note\n"])
def test_slash_after_a_word_that_is_sometimes_a_name_is_ambiguous(word: str, gap: str) -> None:
    # `await` and `yield` are keywords in modules, generators and async functions but ordinary names in
    # a script. Without a parse a following slash cannot be classified, so the scan must not claim to be
    # complete.
    _, ambiguous = noncode_ranges(f"x = {word}{gap}/ 2;\n", "javascript", ".js")
    assert ambiguous


def test_await_and_yield_that_do_not_precede_a_slash_stay_complete() -> None:
    source = "async function f(g) { const a = await g(); return a / 2; }\nfunction* h() { yield 1; }\n"
    assert _masked(source) == []


EVASION_PAYLOAD = (
    'const OpenAI = require("openai"); const c = new OpenAI({ apiKey: loadKey() }); '
    'c.chat.completions.create({ model: "gpt-4o", messages: [] }); 2 / 1;\n'
)


def _code_report(tmp_path: Path, source: str) -> dict:
    (tmp_path / "agent.js").write_bytes(source.encode())  # exact bytes: no newline translation
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def _fingerprint(report: dict) -> list[tuple[str, tuple[str, ...], tuple[str, ...]]]:
    return [
        (f["kind"], tuple(f.get("model_providers") or ()), tuple(f.get("frameworks") or ()))
        for f in report["findings"]
    ]


@pytest.mark.parametrize(
    "prefix",
    [
        "const o = { of: 8 };\no.of / 1; ",
        "const o = { in: 8 };\no?.in / 1; ",
        "const o = { for() { return 8; } };\no.for(1) / 1; ",
        "const p = { catch() { return 8; } };\np.catch(f) / 1; ",
        "const of = 8;\nof / 1; ",
        "const f = of => of / 1;\nf(1); 1 / 1; ",
    ],
    ids=["property-of", "optional-property-in", "method-for", "method-catch", "variable-of", "parameter-of"],
)
def test_division_cannot_mask_the_code_between_two_slashes(tmp_path: Path, prefix: str) -> None:
    # The same code without the divisions is detected; the divisions must not change that, nor make the
    # scan look incomplete or empty.
    control = _code_report(tmp_path, EVASION_PAYLOAD)
    assert control["findings"], "the payload alone is detected"
    report = _code_report(tmp_path, prefix + EVASION_PAYLOAD)
    assert report["summary"]["complete"]
    assert _fingerprint(report) == _fingerprint(control)


# --- Line terminators -----------------------------------------------------------------------------
# JavaScript ends a line at LF, CR, LINE SEPARATOR and PARAGRAPH SEPARATOR (CRLF counts once). A `//`
# comment that was assumed to end only at LF hid everything after it in a CR-only file, which node runs.

LS = "\N{LINE SEPARATOR}"
PS = "\N{PARAGRAPH SEPARATOR}"
TERMINATORS = {"lf": "\n", "cr": "\r", "crlf": "\r\n", "line-separator": LS, "paragraph-separator": PS}


@pytest.mark.parametrize("terminator", TERMINATORS.values(), ids=TERMINATORS.keys())
def test_line_comment_ends_at_every_javascript_line_terminator(terminator: str) -> None:
    source = f'// note{terminator}const OpenAI = require("openai");{terminator}'
    assert _masked(source) == ["// note", '"openai"']


@pytest.mark.parametrize("terminator", TERMINATORS.values(), ids=TERMINATORS.keys())
def test_line_comment_inside_a_jsx_tag_ends_at_every_javascript_line_terminator(terminator: str) -> None:
    source = f'const a = <div // note{terminator} title="x" />;{terminator}const b = run();{terminator}'
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert not any(start <= source.index("run()") < end for start, end in ignored)


@pytest.mark.parametrize("terminator", ["\r", LS, PS], ids=["cr", "line-separator", "paragraph-separator"])
def test_unterminated_regex_stops_at_every_javascript_line_terminator(terminator: str) -> None:
    # A regular expression literal cannot contain a line terminator. The ambiguous line is masked up to
    # it and the code after it is scanned; the file is reported incomplete.
    source = f"const r = /abc{terminator}const OpenAI = require('openai');{terminator}"
    ignored, ambiguous = noncode_ranges(source, "javascript", ".js")
    assert ambiguous
    assert not any(start <= source.index("require(") < end for start, end in ignored)


def test_string_line_continuation_over_crlf_does_not_hide_following_code() -> None:
    # Backslash, CR, LF is one line continuation. Counting the CR alone ended the string at the LF and
    # turned the closing quote into the start of a "string" that hid the rest of the line.
    source = 'const s = "abc\\\r\ndef"; const OpenAI = require("openai");\r\n'
    assert _masked(source) == ['"abc\\\r\ndef"', '"openai"']


@pytest.mark.parametrize("terminator", ["\r", LS, PS], ids=["cr", "line-separator", "paragraph-separator"])
def test_line_comment_does_not_hide_the_code_of_a_file_node_runs(tmp_path: Path, terminator: str) -> None:
    source = f"// note{terminator}" + EVASION_PAYLOAD.replace("; ", f";{terminator}")
    control = _code_report(tmp_path, EVASION_PAYLOAD)
    assert control["findings"], "the payload alone is detected"
    report = _code_report(tmp_path, source)
    assert report["summary"]["complete"]
    assert _fingerprint(report) == _fingerprint(control)
