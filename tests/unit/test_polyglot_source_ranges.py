"""Examples and literal text in supported source languages are not agent code."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind

# A lexical idiom without its library's import or dependency establishes nothing
# on its own (no finding, a scan note). The connector-level tests below observe
# the lexer through such idioms, so each project is anchored by an unrelated,
# declared SDK: the idiom's evidence then appears on the project finding as a
# potential framework (``code:`` evidence at the 0.6 cap), and the inert copies
# in comments and literals produce no evidence at all.
ANCHOR = "openai>=1.0\n"


def _anchor(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(ANCHOR)


def _code_evidence(findings):
    return [e for finding in findings for e in finding.evidence if e.signal.startswith("code:")]


@pytest.mark.parametrize(
    ("filename", "inert", "live"),
    [
        (
            "agent.go",
            "// agents.NewExecutor(\nvar example = `agents.NewExecutor(`\n",
            "agents.NewExecutor(ctx, model)\n",
        ),
        (
            "agent.rs",
            '/* AgentBuilder /* nested AgentBuilder */ */\nlet docs = r#"AgentBuilder"#;\n',
            "let x = AgentBuilder::new();\n",
        ),
        (
            "Agent.java",
            '// AiServices.builder(\nString docs = """AiServices.builder(""";\n',
            "AiServices.builder(Foo.class);\n",
        ),
        (
            "Agent.kt",
            '/* AiServices.builder( */\nval docs = """AiServices.builder("""\n',
            "AiServices.builder(Foo::class.java)\n",
        ),
        (
            "Agent.cs",
            '/* AIFunctionFactory.Create( */\nvar docs = @"AIFunctionFactory.Create(";\n',
            "AIFunctionFactory.Create(foo);\n",
        ),
        ("agent.rb", '# AiServices.builder(\ndocs = "AiServices.builder("\n', "AiServices.builder(foo)\n"),
        (
            "agent.php",
            '<?php\n# AiServices.builder(\n$docs = "AiServices.builder(";\n',
            "AiServices.builder($foo);\n",
        ),
        (
            "Agent.swift",
            '/* AiServices.builder( */\nlet docs = #"AiServices.builder("#\n',
            "AiServices.builder(foo)\n",
        ),
        (
            "agent.dart",
            '// AiServices.builder(\nfinal docs = r"AiServices.builder(";\n',
            "AiServices.builder(foo);\n",
        ),
    ],
)
def test_polyglot_examples_do_not_create_agents(
    tmp_path: Path, run_connector, filename: str, inert: str, live: str
):
    _anchor(tmp_path)
    path = tmp_path / filename
    path.write_text(inert)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [finding for finding in findings if finding.kind == Kind.AGENT]
    assert not _code_evidence(findings)

    path.write_text(inert + live)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    # Lexing establishes the call is source, but cannot establish its library.
    # These intentionally unbound snippets remain inspectable weak candidates:
    # evidence at the uncorroborated cap, a potential framework, never an agent.
    assert findings and all(finding.kind == Kind.FRAMEWORK_USAGE for finding in findings)
    [project] = findings
    assert project.frameworks == [] and project.metadata["potential_frameworks"]
    code = _code_evidence(findings)
    assert code and all(e.weight <= 0.6 for e in code)


@pytest.mark.parametrize(
    ("filename", "source", "signature"),
    [
        (
            "agent.go",
            'package main\nimport "github.com/tmc/langchaingo/agents"\nfunc run() { agents.NewExecutor(ctx, model) }\n',
            "framework.langchaingo",
        ),
        (
            "Agent.java",
            "import dev.langchain4j.agentic.AgenticServices;\nclass App { void run() { AgenticServices.agentBuilder(Foo.class); } }\n",
            "framework.langchain4j",
        ),
        (
            "Agent.cs",
            "using Microsoft.Extensions.AI;\nclass App { async System.Threading.Tasks.Task Run("
            "IChatClient inner, AIFunction tool) { var client = new FunctionInvokingChatClient(inner); "
            'await client.GetResponseAsync("request", new ChatOptions { Tools = [tool] }); } }\n',
            "framework.microsoft-extensions-ai",
        ),
        (
            "agent.rs",
            "use rig::agent::AgentBuilder;\nfn main() { let x = AgentBuilder::new(); }\n",
            "framework.rig",
        ),
    ],
)
def test_polyglot_agent_idioms_require_matching_library_evidence(
    tmp_path, run_connector, filename, source, signature
):
    (tmp_path / filename).write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(f.kind == Kind.AGENT and signature in f.frameworks for f in findings)


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
    class WorkBoundedText(str):
        copied = 0
        searched = 0

        def __getitem__(self, item):
            if isinstance(item, slice):
                self.copied += len(range(*item.indices(len(self))))
                # Two literals per 13-character unit with bounded lookbehind
                # need less than this linear allowance. A full prefix/suffix
                # copy per token exceeds it, independent of runner speed.
                assert self.copied <= 1024 * len(self), "source copies exceeded linear work budget"
            return super().__getitem__(item)

        def rfind(self, sub, start=0, end=None):
            begin, stop, _ = slice(start, end).indices(len(self))
            self.searched += max(0, stop - begin)
            assert self.searched <= len(self), "source searches rescanned earlier prefixes"
            return super().rfind(sub, start, end)

    source = WorkBoundedText(
        'import "github.com/tmc/langchaingo/agents"\nvar _ = ' + ('""+import ""+' * 40_000)
    )
    spans, incomplete = noncode_ranges(source, "go", ".go")
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
    _anchor(tmp_path)
    (tmp_path / "agent.php").write_text(
        "<p>AiServices.builder(example)</p>\n"
        "<?php AiServices.builder(foo); ?>\n"
        "<p>AiServices.builder(example)</p>\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)
    assert [e.location for e in _code_evidence(findings)] == ["agent.php:2"]


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
    _anchor(tmp_path)
    (tmp_path / "template.php").write_text(
        "<p>create_agent($model, $tools)</p>\n"
        "<?= create_agent($model, $tools) ?>\n"
        "<p>create_agent($model, $tools)</p>\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)
    assert [e.location for e in _code_evidence(findings)] == ["template.php:2"]


def test_ruby_block_comments_scan_in_linear_time():
    block = "=begin\nnote\n=end\nx = 1\n"
    small, large = block * 2_000, block * 32_000
    started = time.perf_counter()
    noncode_ranges(small, "ruby")
    small_time = time.perf_counter() - started
    started = time.perf_counter()
    noncode_ranges(large, "ruby")
    large_time = time.perf_counter() - started
    # Sixteen times the input must not cost more than 64 times the time (a
    # quadratic scan would cost 256 times); no absolute bound, since coverage
    # tracing on CI runners slows the loop by an interpreter-dependent factor.
    assert large_time < max(small_time, 0.005) * 64


# --- Line comments end at the language's line terminators -------------------------------------------
# Treating a comment as running to LF alone hid the code after a bare-CR (or, in C#, NEL, LINE SEPARATOR
# and PARAGRAPH SEPARATOR) line break in a file the compiler reads normally.

LS = "\N{LINE SEPARATOR}"
PS = "\N{PARAGRAPH SEPARATOR}"
CR_TERMINATORS = ("\n", "\r", "\r\n")
LINE_COMMENTS = {
    "java": ("java", ".java", "", "//", CR_TERMINATORS),
    "kotlin": ("java", ".kt", "", "//", CR_TERMINATORS),
    "swift": ("swift", ".swift", "", "//", CR_TERMINATORS),
    "dart": ("dart", ".dart", "", "//", CR_TERMINATORS),
    "csharp": ("dotnet", ".cs", "", "//", (*CR_TERMINATORS, "\x85", LS, PS)),
    "php-slashes": ("php", ".php", "<?php\n", "//", CR_TERMINATORS),
    "php-hash": ("php", ".php", "<?php\n", "#", CR_TERMINATORS),
}


def _line_comment_cases() -> list[tuple[str, str, str, str, str]]:
    return [
        (language, dialect, prefix, leader, terminator)
        for language, dialect, prefix, leader, terminators in LINE_COMMENTS.values()
        for terminator in terminators
    ]


@pytest.mark.parametrize(
    ("language", "dialect", "prefix", "leader", "terminator"),
    _line_comment_cases(),
    ids=[f"{name}-{terminator!r}" for name, case in LINE_COMMENTS.items() for terminator in case[4]],
)
def test_line_comment_ends_at_the_language_line_terminator(
    language: str, dialect: str, prefix: str, leader: str, terminator: str
):
    source = f"{prefix}{leader} note{terminator}live_code(1);{terminator}"
    ignored, ambiguous = noncode_ranges(source, language, dialect)
    assert not ambiguous
    assert [source[start:end] for start, end in ignored if start >= len(prefix)] == [f"{leader} note"]


@pytest.mark.parametrize(
    ("language", "dialect", "prefix", "leader"),
    [
        ("java", ".java", "", "//"),
        ("java", ".kt", "", "//"),
        ("dotnet", ".cs", "", "//"),
        ("swift", ".swift", "", "//"),
        ("dart", ".dart", "", "//"),
        ("go", ".go", "", "//"),
        ("rust", ".rs", "", "//"),
        ("ruby", ".rb", "", "#"),
        ("php", ".php", "<?php\n", "#"),
    ],
)
def test_line_comment_is_not_ended_by_a_character_the_language_does_not_break_on(
    language: str, dialect: str, prefix: str, leader: str
):
    # Only C# ends a comment at NEL, LINE SEPARATOR or PARAGRAPH SEPARATOR, and the Go, Rust and Ruby
    # compilers read a bare CR as white space, so the comment (and the dead text after it) runs on to LF.
    separators = ["\x85", LS, PS] if language != "dotnet" else []
    separators += ["\r"] if language in {"go", "rust", "ruby"} else []
    for separator in separators:
        source = f"{prefix}{leader} note{separator}dead_text(1);\nlive_code(2);\n"
        ignored, ambiguous = noncode_ranges(source, language, dialect)
        assert not ambiguous
        masked = [source[start:end] for start, end in ignored if start >= len(prefix)]
        assert masked == [f"{leader} note{separator}dead_text(1);"]


@pytest.mark.parametrize("escape", [r"\u000a", r"\u000A", r"\u000d", r"\uu000a", r"\\\u000a", r"\\\\\u000D"])
def test_java_unicode_escaped_line_break_ends_a_line_comment(escape: str):
    # javac translates unicode escapes before lexing, so this import is code, not comment text.
    source = f"// note {escape} import dev.langchain4j.service.AiServices;\nclass App {{}}\n"
    ignored, ambiguous = noncode_ranges(source, "java", ".java")
    assert not ambiguous
    assert [source[start:end] for start, end in ignored] == [f"// note {escape[: escape.index('u') - 1]}"]
    assert not any(start <= source.index("import dev") < end for start, end in ignored)


@pytest.mark.parametrize(
    "text", [r"\\u000a", r"\\\\u000a", r"\u000b", r"\u0009", "\\" + "u005c" + "u000a", r"\u000", r"\u00a"]
)
def test_java_text_that_is_not_a_line_break_escape_stays_in_the_comment(text: str):
    source = f"// note {text} import dev.langchain4j.service.AiServices;\nclass App {{}}\n"
    ignored, _ = noncode_ranges(source, "java", ".java")
    assert [source[start:end] for start, end in ignored] == [source.split("\n")[0]]


@pytest.mark.parametrize("leader", ["//", "#"])
def test_php_line_comment_ends_at_the_closing_tag(leader: str):
    # `?>` leaves PHP mode even inside a line comment; the next `<?php` is code again.
    source = f"<?php {leader} note ?><?php live_code(1); ?>\n"
    ignored, ambiguous = noncode_ranges(source, "php", ".php")
    assert not ambiguous
    assert f"{leader} note " in [source[start:end] for start, end in ignored]
    assert not any(start <= source.index("live_code") < end for start, end in ignored)


def test_php_code_after_a_closing_tag_in_a_comment_is_scanned(tmp_path: Path, run_connector):
    _anchor(tmp_path)
    (tmp_path / "agent.php").write_text("<?php // harmless ?><?php AiServices.builder($foo); ?>\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert findings and _code_evidence(findings)


def test_php_comments_ended_by_closing_tags_scan_in_linear_time():
    block = "<?php // note ?> "
    small, large = block * 2_000, block * 32_000
    started = time.perf_counter()
    noncode_ranges(small, "php", ".php")
    small_time = time.perf_counter() - started
    started = time.perf_counter()
    noncode_ranges(large, "php", ".php")
    large_time = time.perf_counter() - started
    assert large_time < max(small_time, 0.005) * 64


def test_java_comments_ended_by_escapes_scan_in_linear_time():
    # Every comment here is ended by its own escape, with no real line break anywhere. A search that
    # scanned ahead for the next line break before looking for the escape would rescan the rest of the
    # file for each comment (quadratic).
    block = "// \\u000a "
    small, large = block * 2_000, block * 32_000
    started = time.perf_counter()
    noncode_ranges(small, "java", ".java")
    small_time = time.perf_counter() - started
    started = time.perf_counter()
    ignored, _ = noncode_ranges(large, "java", ".java")
    large_time = time.perf_counter() - started
    assert len(ignored) == 32_000
    # Sixteen times the input must not cost more than 64 times the time (quadratic costs 256 times).
    assert large_time < max(small_time, 0.005) * 64


def test_kotlin_does_not_translate_unicode_escapes_in_comments():
    source = "// note \\u000a import dev.langchain4j.service.AiServices\nclass App\n"
    ignored, _ = noncode_ranges(source, "java", ".kt")
    assert [source[start:end] for start, end in ignored] == [source.split("\n")[0]]


@pytest.mark.parametrize("closer", [r"\u002a/", r"*\u002f", r"\u002a\u002f", r"\uuu002A/", r"\\\u002a/"])
def test_java_unicode_escapes_can_close_a_block_comment(closer: str):
    # javac translates escapes before it lexes, so "\u002a/" closes the comment
    # and the import after it is code. It used to stay masked as comment text.
    source = (
        f"/* build helpers {closer} import dev.langchain4j.service.AiServices; /* end */\nclass App {{}}\n"
    )
    ignored, ambiguous = noncode_ranges(source, "java", ".java")
    assert not ambiguous
    assert [source[start:end] for start, end in ignored] == [f"/* build helpers {closer}", "/* end */"]


@pytest.mark.parametrize("text", [r"\\u002a/", r"\u002a\\u002f", "\\" + "u005c" + "u002a/"])
def test_java_text_that_does_not_spell_a_closer_stays_in_the_block_comment(text: str):
    source = f"/* note {text} import dev.langchain4j.service.AiServices; */\nclass App {{}}\n"
    ignored, _ = noncode_ranges(source, "java", ".java")
    assert [source[start:end] for start, end in ignored] == [source.split("\n")[0]]


def test_java_unicode_escaped_quotes_end_a_string():
    source = 'String s = "\\u0022; Object a = AiServices.builder(Foo.class).build(); String t = \\u0022";\n'
    ignored, ambiguous = noncode_ranges(source, "java", ".java")
    assert not ambiguous
    assert not any(start <= source.index("AiServices") < end for start, end in ignored)


@pytest.mark.parametrize(
    "spelled", [r"\u0069mport dev.langchain4j.service.AiServices", r"new \u0041iServices()"]
)
def test_java_code_spelled_with_unicode_escapes_is_incomplete(spelled: str):
    # The matchers read the source as written, so an escaped letter in code hides it from them.
    _, ambiguous = noncode_ranges(f"class App {{ void f() {{ {spelled}; }} }}\n", "java", ".java")
    assert ambiguous


def test_java_unicode_escapes_in_literals_comments_and_blanks_stay_complete():
    source = (
        "char quote = '\\u0022';\nString s = \"caf\\u00e9 \\u0041\";\n// \\u0041 note\n"
        "int\\u0020x = 1; String caf\\u00e9 = s;\n"
    )
    ignored, ambiguous = noncode_ranges(source, "java", ".java")
    assert not ambiguous
    assert "'\\u0022'" in [source[start:end] for start, end in ignored]


def test_java_import_after_an_escaped_comment_closer_is_reported(tmp_path: Path, run_connector):
    # The import is code to javac; the comment that seemed to hold it closed at "*/".
    (tmp_path / "Bot.java").write_text(
        "package demo;\n\n/* helpers \\u002a/\nimport dev.langchain4j.service.AiServices;\n/* end */\n\n"
        "public class Bot {}\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete
    assert any(
        e.signal.startswith("import:") and e.signature == "framework.langchain4j"
        for finding in findings
        for e in finding.evidence
    )


LIVE_CALLS = {
    "Agent.java": "AiServices.builder(Foo.class);",
    "Agent.cs": "AIFunctionFactory.Create(foo);",
    "Agent.swift": "AiServices.builder(foo)",
    "Agent.dart": "AiServices.builder(foo);",
}


@pytest.mark.parametrize(
    ("filename", "comment", "terminator"),
    [
        ("Agent.java", "// harmless", "\r"),
        ("Agent.java", "// harmless \\u000a", " "),
        ("Agent.cs", "// harmless", LS),
        ("Agent.cs", "// harmless", "\x85"),
        ("Agent.swift", "// harmless", "\r"),
        ("Agent.dart", "// harmless", "\r"),
    ],
)
def test_code_after_a_comment_is_scanned_whatever_ends_the_line(
    tmp_path: Path, run_connector, filename: str, comment: str, terminator: str
):
    _anchor(tmp_path)
    (tmp_path / filename).write_bytes(f"{comment}{terminator}{LIVE_CALLS[filename]}{terminator}".encode())
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    # Lexing establishes the call is source; without a library import it stays a weak candidate.
    assert findings and _code_evidence(findings)


@pytest.mark.parametrize("hashes", [1, 2, 3, 255])
def test_swift_raw_string_delimiters_mask_their_contents(hashes: int):
    delimiter = "#" * hashes
    source = f'let docs = {delimiter}"AiServices.builder(\\(x)"{delimiter}\nAiServices.builder(foo)\n'
    ignored, ambiguous = noncode_ranges(source, "swift", ".swift")
    assert not ambiguous
    assert [source[start:end] for start, end in ignored] == [
        source[source.index(delimiter) : source.index("\n")]
    ]


def test_long_run_of_hashes_in_swift_costs_little_more_than_ordinary_text():
    # A hash is a possible raw-string delimiter, which used to cost 255 Python steps at every hash of
    # a run: tens of seconds for a megabyte. Compare against text of the same size, since an absolute
    # bound would depend on how slowly the interpreter runs under coverage tracing.
    size = 200_000
    started = time.perf_counter()
    noncode_ranges("a" * size, "swift", ".swift")
    ordinary = time.perf_counter() - started
    started = time.perf_counter()
    noncode_ranges("#" * size, "swift", ".swift")
    hashes = time.perf_counter() - started
    assert hashes < max(ordinary, 0.01) * 8


@pytest.mark.parametrize(
    "source",
    [
        "def broken(:\n    pass\nfrom langchain.agents import AgentExecutor\nAgentExecutor(agent=a)\n",
        "x = [1,\nAgentExecutor()",
    ],
)
def test_python_code_after_an_unclosed_bracket_stays_code(source: str):
    # Every token through EOF is read before the tokenizer reports the unclosed
    # bracket. Python 3.11 reports that error past the last line, 3.12+ at the
    # start of it, which used to mask that line as if it were a literal.
    assert noncode_ranges(source, "python") == ([], False)


def test_python_literals_inside_an_unclosed_bracket_are_still_masked():
    source = "x = (\n  # note AgentExecutor()\n  'AgentExecutor()'\nAgentExecutor()\n"
    spans, ambiguous = noncode_ranges(source, "python")
    assert [source[start:end] for start, end in spans] == ["# note AgentExecutor()", "'AgentExecutor()'"]
    assert not ambiguous
