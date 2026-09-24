"""Examples and literal text in supported source languages are not agent code."""

from __future__ import annotations

from pathlib import Path
from time import monotonic

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind


@pytest.mark.parametrize(
    ("filename", "inert", "live"),
    [
        ("agent.go", '// agents.NewExecutor(\nvar example = `agents.NewExecutor(`\n', "agents.NewExecutor(ctx, model)\n"),
        ("agent.rs", '/* AgentBuilder /* nested AgentBuilder */ */\nlet docs = r#"AgentBuilder"#;\n', "let x = AgentBuilder::new();\n"),
        ("Agent.java", '// AiServices.builder(\nString docs = """AiServices.builder(""";\n', "AiServices.builder(Foo.class);\n"),
        ("Agent.kt", '/* AiServices.builder( */\nval docs = """AiServices.builder("""\n', "AiServices.builder(Foo::class.java)\n"),
        ("Agent.cs", '/* AIFunctionFactory.Create( */\nvar docs = @"AIFunctionFactory.Create(";\n', "AIFunctionFactory.Create(foo);\n"),
        ("agent.rb", '# AiServices.builder(\ndocs = "AiServices.builder("\n', "AiServices.builder(foo)\n"),
        ("agent.php", '<?php\n# AiServices.builder(\n$docs = "AiServices.builder(";\n', "AiServices.builder($foo);\n"),
        ("Agent.swift", '/* AiServices.builder( */\nlet docs = #"AiServices.builder("#\n', "AiServices.builder(foo)\n"),
        ("agent.dart", '// AiServices.builder(\nfinal docs = r"AiServices.builder(";\n', "AiServices.builder(foo);\n"),
    ],
)
def test_polyglot_examples_do_not_create_agents(tmp_path: Path, run_connector, filename: str, inert: str, live: str):
    path = tmp_path / filename
    path.write_text(inert)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]

    path.write_text(inert + live)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert [finding for finding in findings if finding.kind == Kind.AGENT]


def test_go_import_strings_remain_visible_but_ordinary_literals_are_ignored(tmp_path: Path, run_connector):
    (tmp_path / "main.go").write_text(
        'import (\n  "github.com/tmc/langchaingo/agents"\n  genkit "github.com/firebase/genkit/genkit"\n)\n'
        'import more "github.com/firebase/genkit/genkit"\n'
        'var docs = "agents.NewExecutor("\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert {"framework.langchaingo", "framework.genkit"} <= {
        framework for finding in findings for framework in finding.frameworks
    }
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]


def test_long_go_line_with_many_quotes_and_import_tokens_stays_bounded():
    # Hostile source need not parse as Go. Each quote and import-like token
    # previously copied/scanned the whole prefix or suffix of this line.
    source = 'import "github.com/tmc/langchaingo/agents"\nvar _ = ' + ('""+import ""+' * 40_000)
    started = monotonic()
    spans, incomplete = noncode_ranges(source, "go", ".go")
    assert monotonic() - started < 5
    assert not incomplete
    imported = source.index("github.com/")
    literal = source.index('""+import')
    assert not any(start <= imported < end for start, end in spans)
    assert any(start <= literal < end for start, end in spans)


@pytest.mark.parametrize(
    ("language", "dialect", "source", "call"),
    [
        ("ruby", ".rb", 'x = "#{AiServices.builder(foo)}"\n', "AiServices.builder(foo)"),
        ("dotnet", ".cs", 'var x = $"{AIFunctionFactory.Create(foo)}";\n', "AIFunctionFactory.Create(foo)"),
        ("java", ".kt", 'val x = "${AiServices.builder(foo)}"\n', "AiServices.builder(foo)"),
        ("swift", ".swift", 'let x = "\\(AiServices.builder(foo))"\n', "AiServices.builder(foo)"),
        ("dart", ".dart", 'var x = "${AiServices.builder(foo)}";\n', "AiServices.builder(foo)"),
    ],
)
def test_interpolation_expression_remains_code(language: str, dialect: str, source: str, call: str):
    spans, incomplete = noncode_ranges(source, language, dialect)
    assert not incomplete
    start = source.index(call)
    assert not any(a <= start < b for a, b in spans)


def test_unclosed_nested_comment_marks_source_incomplete():
    spans, incomplete = noncode_ranges("/* outer /* inner */ AiServices.builder(foo)", "rust", ".rs")
    assert incomplete
    assert spans == [(0, len("/* outer /* inner */ AiServices.builder(foo)"))]


def test_java_block_comments_end_at_first_closer_but_kotlin_supports_nesting():
    source = "/* outer /* inner */ AiServices.builder(foo) */"
    java_spans, java_incomplete = noncode_ranges(source, "java", ".java")
    assert not java_incomplete
    assert java_spans == [(0, source.index("*/") + 2)]
    kotlin_spans, kotlin_incomplete = noncode_ranges(source, "java", ".kt")
    assert not kotlin_incomplete
    assert kotlin_spans == [(0, len(source))]


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("example.rb", "docs = <<~DOC\nAiServices.builder(example)\nDOC\n"),
        ("example.php", "<?php\n$docs = <<<'DOC'\nAiServices.builder(example)\nDOC;\n"),
    ],
)
def test_heredoc_examples_are_ignored(tmp_path: Path, run_connector, filename: str, source: str):
    (tmp_path / filename).write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]


def test_fsharp_comment_cannot_hide_csharp_dereference():
    source = "var result = (*ptr).AiServices.builder(foo);\n"
    spans, incomplete = noncode_ranges(source, "dotnet", ".cs")
    assert not incomplete
    assert not spans
    source = "(* AiServices.builder(foo) *)\nAIFunctionFactory.Create(foo)\n"
    spans, incomplete = noncode_ranges(source, "dotnet", ".fs")
    assert not incomplete
    assert spans == [(0, source.index("\n"))]


def test_php_markup_is_inert_but_embedded_php_remains_code(tmp_path: Path, run_connector):
    (tmp_path / "agent.php").write_text(
        "<p>AiServices.builder(example)</p>\n"
        "<?php AiServices.builder(foo); ?>\n"
        "<p>AiServices.builder(example)</p>\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    assert any(evidence.location == "agent.php:2" for evidence in agents[0].evidence)


def test_html_only_php_template_is_inert(tmp_path: Path, run_connector):
    source = "<p>AiServices.builder(foo)</p>\n<!-- StateGraph(dict) -->\n"
    (tmp_path / "template.php").write_text(source)
    spans, incomplete = noncode_ranges(source, "php", ".php")
    assert not incomplete
    assert spans == [(0, len(source))]
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]


def test_php_echo_expression_is_executable(tmp_path: Path, run_connector):
    (tmp_path / "template.php").write_text(
        "<p>create_agent($model, $tools)</p>\n"
        "<?= create_agent($model, $tools) ?>\n"
        "<p>create_agent($model, $tools)</p>\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    agents = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert len(agents) == 1
    assert any(evidence.location == "template.php:2" for evidence in agents[0].evidence)
