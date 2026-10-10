"""Valid source syntax keeps coverage complete without exposing inert examples as code."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind


@pytest.mark.parametrize("prefix", ["", "b"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_rust_multiline_strings_mask_examples_and_preserve_following_code(prefix: str, newline: str) -> None:
    source = (
        f'fn main() {{ let docs = {prefix}"{newline}AgentBuilder::new(fake){newline}";'
        f"{newline}let agent = AgentBuilder::new(real); }}{newline}"
    )
    spans, ambiguous = noncode_ranges(source, "rust", ".rs")
    assert not ambiguous
    fake, real = source.index("AgentBuilder"), source.rindex("AgentBuilder")
    assert any(start <= fake < end for start, end in spans)
    assert not any(start <= real < end for start, end in spans)


@pytest.mark.parametrize(
    ("opening", "closing"),
    [
        # C raw strings (Rust 1.77): inner quotes and backslashes are text, not delimiters or escapes.
        ('cr#"say "hi"#', 'cr#"say "bye"#'),
        ('cr"C:\\"', 'cr"D:\\"'),
        # Character literals with a multi-character escape before a quote character literal.
        ("['\\u{201C}','\"']", "['\\u{201D}','\"']"),
        ("['\\x7F','\"']", "['\\x7E','\"']"),
        ("['\\u{2_0_1_C}','\"']", "['\\u{1_F_6_0_0}','\"']"),
    ],
)
def test_rust_literals_with_inner_quotes_keep_following_code_visible(
    opening: str, closing: str, tmp_path: Path, run_connector
) -> None:
    # A misread quote would open an ordinary (multiline) string that runs to the next quote and
    # masks the code between the two lines while the file still reports complete.
    source = (
        f"use rig::agent::AgentBuilder;\nconst A: X = {opening};\n"
        'fn main() { let agent = AgentBuilder::new(model).preamble("x").build(); }\n'
        f"const B: X = {closing};\n"
    )
    spans, ambiguous = noncode_ranges(source, "rust", ".rs")
    assert not ambiguous
    real = source.index("AgentBuilder::new")
    assert not any(start <= real < end for start, end in spans)
    for literal in (opening, closing):
        inner = source.index(literal) + len(literal) - 3
        assert any(start <= inner < end for start, end in spans)
    (tmp_path / "main.rs").write_text(source, encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete
    assert any(finding.kind == Kind.AGENT and "framework.rig" in finding.frameworks for finding in findings)


@pytest.mark.parametrize("dialect", [".js", ".mjs", ".cjs"])
@pytest.mark.parametrize(
    "component",
    [
        "<>{createReactAgent({})}</>",
        "<p>match src/*.js files {createReactAgent({})}</p>",
        "<div><p>src/*.js and createReactAgent(fake)</p>{createReactAgent({})}</div>",
    ],
)
def test_jsx_in_javascript_masks_text_and_preserves_expressions(dialect: str, component: str) -> None:
    source = f"const View = () => {component};\nconst agent = createReactAgent(real);\n"
    spans, ambiguous = noncode_ranges(source, "javascript", dialect)
    assert not ambiguous
    for executable in ("createReactAgent({})", "createReactAgent(real)"):
        assert not any(start <= source.index(executable) < end for start, end in spans)
    if "createReactAgent(fake)" in source:
        assert any(start <= source.index("createReactAgent(fake)") < end for start, end in spans)


@pytest.mark.parametrize("dialect", [".ts", ".mts", ".cts", None])
def test_implicit_jsx_does_not_apply_to_typescript_or_unspecified_dialect(dialect: str | None) -> None:
    assert noncode_ranges("const View = () => <p>match src/*.js files</p>;\n", "javascript", dialect)[1]


@pytest.mark.parametrize("dialect", [".ts", ".mts", ".cts"])
def test_typescript_generics_and_type_assertions_keep_executable_code_visible(dialect: str) -> None:
    source = (
        "const identity = <T>(value: T): T => value;\n"
        "const agent = <Agent>createReactAgent({});\n"
        "const constrained = <T extends object>(value: T) => createReactAgent(value);\n"
    )
    spans, ambiguous = noncode_ranges(source, "javascript", dialect)
    assert not ambiguous
    assert spans == []


# Read as JSX, the `<shift>` in `mask<<shift>` would open an element whose text runs to the
# "</shift>" in the string and hides `await /x/`, the construct that makes the file ambiguous.
_SHIFT_AND_CLOSING_TAG = (
    "const v = mask<<shift>limit;\n"
    'const { OpenAI } = await import("openai");\n'
    "const client = new OpenAI();\n"
    "const r = await /x/.test(s);\n"
    'const html = "</shift>";\n'
)
_JSX_DIALECTS = (".js", ".mjs", ".cjs", ".jsx", ".tsx")


@pytest.mark.parametrize("dialect", _JSX_DIALECTS)
@pytest.mark.parametrize("jsx", [False, True])
def test_left_shift_before_a_name_never_opens_a_jsx_element(dialect: str, jsx: bool) -> None:
    spans, ambiguous = noncode_ranges(_SHIFT_AND_CLOSING_TAG, "javascript", dialect, jsx=jsx)
    assert ambiguous
    for executable in ("new OpenAI()", "await /x/"):
        assert not any(start <= _SHIFT_AND_CLOSING_TAG.index(executable) < end for start, end in spans)
    # Plain JavaScript with the same shift still completes.
    assert noncode_ranges("const v = mask<<shift>limit;\n", "javascript", dialect, jsx=jsx) == ([], False)


@pytest.mark.parametrize("dialect", _JSX_DIALECTS)
@pytest.mark.parametrize(
    "shift",
    [
        'const PROMPT = "[INST] <<SYS>>\\nAnswer briefly.\\n<</SYS>>";',
        "const bit = 1<<n;",
        "// cat <<EOF > notes.txt",
    ],
)
def test_shift_elsewhere_in_a_file_keeps_its_jsx_reading(
    dialect: str, shift: str, tmp_path: Path, run_connector
) -> None:
    # Plain JavaScript reads the "/*" in the element text as a comment that runs to the JSDoc "*/" and
    # hides the client in between, yet completes. A `<<` in a string, a comment or a shift elsewhere
    # must not drop the file to that reading.
    source = (
        f'import OpenAI from "openai";\n{shift}\n'
        "export const Help = () => <p>Only files matching src/*.js are indexed.</p>;\n"
        "const client = new OpenAI();\n"
        'const reply = await client.chat.completions.create({ model: "gpt-4o", messages: [] });\n'
        "/** Reply helper. */\nexport default reply;\n"
    )
    # code.filesystem lexes all five dialects with JSX requested.
    spans, ambiguous = noncode_ranges(source, "javascript", dialect, jsx=True)
    assert not ambiguous
    for executable in ("new OpenAI()", "client.chat.completions.create"):
        assert not any(start <= source.index(executable) < end for start, end in spans)
    # Both readings mask the element text from its "/*" on; only what both mask stays masked.
    assert any(start <= source.index("*.js are indexed") < end for start, end in spans)
    (tmp_path / f"app{dialect}").write_text(source, encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any("provider.openai" in finding.model_providers for finding in findings)


@pytest.mark.parametrize(
    ("language", "dialect", "source"),
    [
        ("rust", ".rs", 'fn main() { let s = "abc\nAgentBuilder::new(fake);\n'),
        ("rust", ".rs", 'fn main() { let s = b"\\\nabc\nAgentBuilder::new(fake);\n'),
        ("javascript", ".js", "const s = `abc\nconst t = 1;\n"),
        ("javascript", ".mjs", "/* open\nconst t = 1;\n"),
        ("javascript", ".cjs", "const A = () => <><p>src/*.js files</p>;\n"),
        ("javascript", ".js", "const A = () => <p>src/*.js files</div>;\n"),
        ("javascript", ".js", "const A = () => <p>src/*.js files</p>;\nconst s = `open\n"),
        ("javascript", ".js", "const A = () => <p>src/*.js files</p>;\nawait / 2;\n"),
        *(("javascript", dialect, _SHIFT_AND_CLOSING_TAG) for dialect in _JSX_DIALECTS),
        ("ruby", ".rb", "docs = <<DOC\n#{AiServices.builder(example)}\nDOC\n"),
    ],
)
def test_ambiguous_or_unterminated_source_stays_incomplete(
    language: str, dialect: str, source: str, tmp_path: Path, run_connector
) -> None:
    assert noncode_ranges(source, language, dialect)[1]
    (tmp_path / f"sample{dialect}").write_text(source, encoding="utf-8")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any("incomplete source lexical analysis" in error for error in ctx.stats.errors)


@pytest.mark.parametrize(
    ("filename", "framework"),
    [("multiline.rs", "framework.rig"), ("Component.js", "framework.langgraph")],
)
def test_offline_source_fixture_keeps_real_agent_and_excludes_literal_examples(
    filename: str, framework: str, tmp_path: Path, fixtures: Path, run_connector
) -> None:
    shutil.copyfile(fixtures / "source_lexer" / filename, tmp_path / filename)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    agents = [
        finding for finding in findings if finding.kind == Kind.AGENT and framework in finding.frameworks
    ]
    assert len(agents) == 1
    code_locations = [
        evidence.location for evidence in agents[0].evidence if evidence.signal.startswith("code:")
    ]
    assert f"{filename}:8" in code_locations
    # The Rust signature also recognizes AgentBuilder in the import on line 1.
    assert set(code_locations) <= {f"{filename}:1", f"{filename}:8"}


@pytest.mark.parametrize("dialect", [".js", ".mjs", ".cjs"])
def test_a_completing_plain_reading_cannot_hide_code_that_the_jsx_reading_shows(dialect: str) -> None:
    # Plain JavaScript completes here, but reads the element text's "/*" as a comment that runs to
    # the JSDoc "*/" and swallows the client. The JSX reading shows the client, so it stays visible.
    source = (
        'import OpenAI from "openai";\n'
        "export const Help = () => <p>Only files matching src/*.js are indexed.</p>;\n"
        "const client = new OpenAI();\n"
        "/** Reply helper. */\nexport default client;\n"
    )
    spans, ambiguous = noncode_ranges(source, "javascript", dialect)
    assert not ambiguous
    assert not any(start <= source.index("new OpenAI()") < end for start, end in spans)


@pytest.mark.parametrize("dialect", [".js", ".mjs", ".cjs"])
def test_plain_javascript_without_tags_is_read_once(dialect: str, monkeypatch) -> None:
    # A file with no closing or self-closing tag is never re-read as JSX.
    from shadowscan.connectors.code import source_ranges

    calls: list[bool] = []
    original = source_ranges._javascript_ranges

    def counting(text, **options):
        calls.append(options.get("jsx", False))
        return original(text, **options)

    monkeypatch.setattr(source_ranges, "_javascript_ranges", counting)
    assert noncode_ranges("const a = b < c && d > e; // a /* b */ c\n", "javascript", dialect) == (
        [(26, 40)],
        False,
    )
    assert calls == [False]
