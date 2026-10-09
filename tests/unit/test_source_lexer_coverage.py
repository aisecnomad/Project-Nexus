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
