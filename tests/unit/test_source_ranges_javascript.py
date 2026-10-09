"""JavaScript and TypeScript source ranges: JSX text is masked, TSX generics are not JSX, and a slash is
a regular expression or a division exactly where the language says it is."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code import source_ranges
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind
from shadowscan.signatures.matcher import MatchTimeoutError

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
    # Brace-less JSX elements as attribute values are legal JSX; autogen-studio
    # uses them throughout (the real-world benchmark's lexer regressions).
    "braceless-element-attribute-value": (
        "export const H = () => (\n"
        '  <Tooltip title=<span>Sessions {" "}<b>{n}</b>{" "}</span>>\n'
        "    <button />\n  </Tooltip>\n);\n"
    ),
    "braceless-self-closing-attribute-value": 'export const I = () => <A b=<i/> c="d">t</A>;\n',
    "braceless-capitalized-self-closing-value": "export const J = () => <Row icon=<Plus/> wide>t</Row>;\n",
    "braceless-value-then-template-attribute": (
        "export const K = () => (\n"
        '  <CodeSection title="1. Dockerfile" description=<div><a href="https://e.x">docs</a>'
        '{" "}</div> code={`FROM python:3.10-slim\nRUN pip install .`} />\n);\n'
    ),
}


@pytest.mark.parametrize("source", VALID_TSX.values(), ids=VALID_TSX.keys())
def test_valid_tsx_constructs_are_lexed_completely(source: str) -> None:
    _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous


def test_braceless_attribute_value_text_stays_masked() -> None:
    source = (
        "export const View = () => (\n"
        '  <Tooltip title=<span>createReactAgent( is documented {" "}here</span>>\n'
        "    <button />\n  </Tooltip>\n);\n"
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "const graph = createReactAgent({});\n"
    )
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    prose = source.index("createReactAgent( is")
    code = source.rindex("createReactAgent(")
    assert any(start <= prose < end for start, end in ignored)
    assert not any(start <= code < end for start, end in ignored)


def test_braceless_attribute_file_scans_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "Guide.tsx").write_text(
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "export const Guide = () => (\n"
        '  <CodeSection title="1. Install" description=<div>Run the agent{" "}</div>'
        " code={`pip install .`} />\n);\n"
        "export const graph = createReactAgent({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not any("incomplete source lexical analysis" in w for w in ctx.stats.warnings)
    assert any(f.kind == Kind.AGENT and "framework.langgraph" in f.frameworks for f in findings)


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


@pytest.mark.parametrize(
    "source",
    [
        "if (x) { y(); }\n/'/.test(z); require('openai');\n",
        'if (x) { y(); }\n/"/.test(z);\n',
        "if (x) { y(); }\n/`/.test(z);\n",
        "if (x) { y(); }\n/[//]/.test(z); code();\n",
        "if (x) { y(); }\n/a\\//.test(z); code();\n",
        "function f() {}\n/'/.test(s);\n",
        "if (x) { y(); } /* note */ /'/.test(s);\n",
        "const f = () => { return { a: 1 } /'/ };\n",
        "const s = `${ (() => { return 1 })() }`; if (x) { y(); } /'/.test(s);\n",
    ],
    ids=[
        "single-quote",
        "double-quote",
        "backtick",
        "class-with-slashes",
        "escaped-slash",
        "function",
        "comment-between",
        "nested",
        "template",
    ],
)
def test_regex_after_a_closing_brace_that_could_hide_code_is_ambiguous(source: str) -> None:
    # After a block a slash starts a regular expression and after an object literal it divides. Telling
    # them apart needs a parse; the walk reads a division, and then a quote, a backtick or a slash in
    # the "regular expression" opens a string or a comment that hides what follows. The scan must not
    # claim to be complete.
    _, ambiguous = noncode_ranges(source, "javascript", ".js")
    assert ambiguous


@pytest.mark.parametrize(
    "source",
    [
        "if (x) { y(); }\nz();\n",
        "if (x) { y(); } // note\nz();\n",
        "if (x) { y(); } /* note */ z();\n",
        "const half = {a: 1}.a / 2;\n",
        "const t = `${a}/${b}`;\n",
        "function f() { return 1 }\nconst r = /re/.test(s);\n",
        # A slash after a brace that cannot hide anything: no closing slash, or nothing in the text
        # between the slashes that opens a string or a comment.
        "const q = {a: 1} / 2;\n",
        "const q = {a: 1} / 2 / 3;\n",
        "function f() {}\n/re/.test(s);\n",
        # JSX in a .js file is lexed as code: its self-closing slashes follow expression braces.
        "const A = () => <Foo bar={x}/>;\n",
        "const A = () => <Foo bar={x} />;\n",
        "const A = () => <Foo bar={x}/><Bar baz={y}/>;\n",
    ],
)
def test_braces_whose_following_slash_cannot_hide_code_stay_complete(source: str) -> None:
    _masked(source)  # asserts the lexing is complete


@pytest.mark.parametrize(
    "source",
    [
        "export const A = () => <Foo bar={{ c: 1 }} baz={d}/>;\n",
        "export const B = () => <span>{month}/{day}/{year}</span>;\n",
        "export const C = () => <b>{price}/mo</b>;\n",
        "export const D = () => <p><Foo a={b}/><Bar c={d}/>{e}/{f}</p>;\n",
    ],
)
def test_jsx_expression_braces_followed_by_a_slash_stay_complete(source: str) -> None:
    _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous


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


def test_regex_statement_after_a_block_is_an_incomplete_scan_not_a_clean_one(tmp_path: Path) -> None:
    # The quote in the regular expression opened a "string" that hid the rest of the line, including the
    # payload, and the scan reported no findings and a complete result.
    (tmp_path / "agent.js").write_text("if (ready) { warm(); }\n/'/.test(name); " + EVASION_PAYLOAD)
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert not report["summary"]["complete"]
    assert report["stats"][0]["errors"] == ["code.filesystem: agent.js: incomplete source lexical analysis"]


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


# --- Bounded work ---------------------------------------------------------------------------------
# Every "<" that might open a JSX element looks ahead over a bounded window. 62,500 repeats of "<A>(" took
# over a minute (and lost every result of the scan with the deadline) before the look-ahead was budgeted.
# The regular expression a slash after "}" might start is another look-ahead that is not consumed.

LIMIT, AMBIGUOUS, COMPLETE = "limit", "ambiguous", "complete"
HOSTILE = {
    "tag-then-parenthesis": ("<A>(" * 62_500, LIMIT),
    "type-arguments": ("<A<" * 83_333, LIMIT),
    "unclosed-tags": ("<div " * 50_000, AMBIGUOUS),
    "unclosed-expressions": ("<a>{" * 62_500, AMBIGUOUS),
    "unterminated-comments": ("/* " * 83_334, AMBIGUOUS),
    "generic-arrow-heads": ("<T extends X>(" * 17_857, AMBIGUOUS),
    "brace-slash-open-class": ("}/[" * 83_333, LIMIT),
    "brace-slash-quote": ("}/'" * 83_333, AMBIGUOUS),
    "backticks": ("`" * 250_000, COMPLETE),
    "braces": ("{" * 250_000, COMPLETE),
    "angle-brackets": ("<" * 250_000, COMPLETE),
    "closing-tags": ("</a>" * 62_500, COMPLETE),
}


@pytest.mark.parametrize("source, outcome", HOSTILE.values(), ids=HOSTILE.keys())
def test_hostile_jsx_ends_quickly_as_a_limit_or_an_incomplete_lexing(source: str, outcome: str) -> None:
    started = time.perf_counter()
    if outcome == LIMIT:
        with pytest.raises(MatchTimeoutError, match="look-ahead budget"):
            noncode_ranges(source, "javascript", ".tsx", jsx=True)
    else:
        _, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
        assert ambiguous is (outcome == AMBIGUOUS)
    assert time.perf_counter() - started < 5


def test_hostile_jsx_file_is_an_incomplete_scan_and_keeps_the_other_findings(tmp_path: Path) -> None:
    (tmp_path / "evil.tsx").write_text("<A>(" * 62_500)
    (tmp_path / "ok.js").write_text(EVASION_PAYLOAD)
    started = time.perf_counter()
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    assert time.perf_counter() - started < 20
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert not report["summary"]["complete"]
    assert report["stats"][0]["errors"] == [
        "code.filesystem: evil.tsx: file analysis incomplete "
        "(MatchTimeoutError: JavaScript lexical analysis look-ahead budget exceeded)"
    ]
    assert report["findings"], "the other file is still scanned"


def _realistic_component(n: int) -> str:
    return f"""\
export const Panel{n} = ({{ count, items }}: {{ count: number; items: Option[] }}) => {{
  const [value, setValue] = useState<string>("");
  const identity = <T,>(x: T): T => x;
  const constrained = <T extends object>(x: T): T => x;
  const defaulted = <T = string>(x: T): T => x;
  return (
    <Box padding={{2}}>
      {{/* heading {n} */}}
      <Text>({{count}})</Text>
      <Select<Option>
        // pick one of the options
        value={{value}}
        onChange={{(v: string) => setValue(v)}}
        options={{items.map((i) => ({{ value: i.value, label: i.label }}))}}
      />
      <ul role="list">
        {{items.map((item) => (
          <li key={{item.value}}>{{item.label}} ({{item.value}})</li>
        ))}}
      </ul>
      <Form<{{ email: string }}> onSubmit={{() => go()}}>
        <input type="text" placeholder="it's fine" />
      </Form>
      <p>Don't panic &mdash; {{count > 0 ? `${{count}} items` : "none"}} and {{count / 2}} half</p>
    </Box>
  );
}};
"""


def test_large_realistic_tsx_file_lexes_fast_and_unambiguously() -> None:
    # Element type arguments, comments between attributes, `<Text>({n})</Text>` and generic arrow
    # functions: the constructs from the field scans, repeated to 1 MB, must stay inside the budget.
    parts = ['import React, { useState } from "react";\n']
    size = 0
    while size < 1_000_000:
        parts.append(_realistic_component(len(parts)))
        size += len(parts[-1])
    source = "\n".join(parts)
    started = time.perf_counter()
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert time.perf_counter() - started < 5
    assert not ambiguous
    assert not any(start <= source.index("useState<string>") < end for start, end in ignored)
    assert any(start <= source.index("pick one of") < end for start, end in ignored)


def test_look_ahead_budget_is_proportional_to_the_input() -> None:
    small = source_ranges._LookaheadBudget(0)
    large = source_ranges._LookaheadBudget(1_000_000)
    assert 0 < small.remaining < large.remaining
    with pytest.raises(MatchTimeoutError, match="look-ahead budget"):
        small.spend(small.remaining + 1)


def test_backslash_does_not_escape_the_quote_of_a_jsx_attribute_string() -> None:
    # A JSX attribute string has no escapes, so `title="\"` is complete and the tag ends at its `>`.
    # Reading the backslash as an escape paired the quotes of the code after it with the tag's.
    source = (
        'const a = <a title="\\">x</a>;\nconst OpenAI = require("openai"); const s = \'it"s\';\n'
        "const b = (n > 1) && <b>y</b>;\n"
    )
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert [source[start:end] for start, end in ignored] == [
        '<a title="\\">',
        "x",
        "</a>",
        '"openai"',
        "'it\"s'",
        "<b>",
        "y",
        "</b>",
    ]


@pytest.mark.parametrize(
    "source",
    ["const a = <a title='it\"s' alt=\"it's\" />;\n", 'const a = <a title="line one\nline two" />;\n'],
    ids=["other-quote-inside", "spans-lines"],
)
def test_jsx_attribute_strings_may_contain_the_other_quote_and_line_breaks(source: str) -> None:
    ignored, ambiguous = noncode_ranges(source, "javascript", ".tsx", jsx=True)
    assert not ambiguous
    assert [source[start:end] for start, end in ignored] == [
        source[source.index("<a") : source.index("/>") + 2]
    ]


# --- Long regular expression literals --------------------------------------------------------------
# Generated Unicode tables (the emoji-regex package is the common one) are single regular expression
# literals of 10-60 KB. They are not suspicious, and treating them as ambiguous made a scan of any
# project that depends on them incomplete.


def _emoji_table(blocks: int) -> str:
    return "(?:" + "|".join(f"\\uD83C[\\uDF{n % 256:02X}-\\uDF{n % 256:02X}]" for n in range(blocks)) + ")"


def test_long_generated_regex_literal_is_masked_and_complete() -> None:
    table = _emoji_table(1_500)
    assert len(table) > 30_000
    source = f"module.exports = () => /{table}/g;\nconst client = require('openai');\n"
    ignored, ambiguous = noncode_ranges(source, "javascript", ".js")
    assert not ambiguous
    assert [source[start:end] for start, end in ignored] == [f"/{table}/g", "'openai'"]


def test_long_regex_literal_does_not_hide_the_line_after_it(tmp_path: Path, run_connector) -> None:
    (tmp_path / "emoji.js").write_text(
        f"module.exports = () => /{_emoji_table(1_500)}/g;\n" + EVASION_PAYLOAD,
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any("provider.openai" in finding.model_providers for finding in findings)


def test_regex_literal_beyond_the_bound_is_still_ambiguous_and_masks_only_its_line() -> None:
    limit = source_ranges._MAX_REGEX_LITERAL_LENGTH
    source = "const r = /" + "a" * limit + "/g;\nconst client = require('openai');\n"
    ignored, ambiguous = noncode_ranges(source, "javascript", ".js")
    assert ambiguous
    assert not any(start <= source.index("require(") < end for start, end in ignored)


def test_unterminated_long_regex_scan_is_linear_and_stays_on_its_line() -> None:
    # No closing slash anywhere: one failed scan per line, and the rest of that line is skipped.
    source = ("x = /" + "a" * 1_000 + "\n") * 2_000 + "x = /" + "a" * 600_000
    started = time.perf_counter()
    ignored, ambiguous = noncode_ranges(source, "javascript", ".js")
    assert time.perf_counter() - started < 5
    assert ambiguous
    assert len(ignored) == 2_001


def test_look_ahead_honours_the_per_file_time_budget(index) -> None:
    # The same checkpoints that spend the allowance poll the input's execution deadline.
    with pytest.raises(MatchTimeoutError), index.scan_budget(seconds=0.01):
        time.sleep(0.05)
        noncode_ranges("export const T = ({ n }) => <Text>({n})</Text>;", "javascript", ".tsx", jsx=True)


def test_jsx_in_plain_js_file_scans_complete(tmp_path: Path, run_connector) -> None:
    """React-in-.js (Docusaurus, CRA) must not fail closed on closing tags after expressions."""
    (tmp_path / "index.js").write_text(
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        "const Icon = ({children}) => (\n"
        '  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">\n'
        "    {children}\n  </svg>\n);\n"
        "export const graph = createReactAgent({});\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any("framework.langgraph" in f.frameworks for f in findings)
