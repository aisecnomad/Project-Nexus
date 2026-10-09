"""Ruby literals the lexical walk did not model, measured against Ruby's own lexer.

The post-change holdout's most common incomplete cause was Ruby source that
the walk could not finish. The cases below come from Ruby's standard library
and installed gems, not from the holdout: scored against Ripper on 1,947 files,
87 were incomplete and 38,749 code tokens were masked. Regular expressions,
percent literals other than %q/%Q, punctuation globals, character literals,
command strings and the data section were read as code, so a quote or `#`
inside them opened a string or a comment; `class << self` and `list<<item`
opened here-documents. Each case must now finish the walk, mask the literal
and leave the code after it visible.
"""

from __future__ import annotations

import time

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges

CODE = "agent = AiServices.builder(x)\n"


def _lex(source: str):
    return noncode_ranges(source, "ruby", ".rb")


def _visible(source: str, spans, needle: str) -> bool:
    at = source.index(needle)
    return not any(start <= at < end for start, end in spans)


@pytest.mark.parametrize(
    ("source", "inert"),
    [
        ("s = t.sub(/'/, '')\n", "/'/"),
        ('ok = name =~ /[#:]"/\n', '[#:]"'),
        ("case e\nwhen /can't (\\S+)/\n  1\nend\n", "can't"),
        # A spaced command name before `/` passes a regular expression (`/=` would divide-assign).
        ('key, value = line.split /:"/, 2\n', ':"'),
        ('if /mswin|"/ =~ RUBY_PLATFORM then 1 end\n', 'mswin|"'),
        ('pattern = %r{\\A[a-z]+://"}i\n', 'a-z]+://"'),
        ("words = %w[don't stop]\n", "don't"),
        ("names = %i[it's here]\n", "it's"),
        ('line = %(say "hi" # not a comment)\n', '"hi" # not'),
        ("nested = %[a [b's] c]\n", "b's"),
        ('loaded = $".find { |f| f.end_with?(".rb") }\n', '".rb"'),
        ("rest = $' if name =~ /^::/\n", "^::"),
        ('quote = c == ?" ? 1 : 2\n', '?"'),
        ("apostrophe = [?', ?#]\n", "?'"),
        ("newline = ?\\n\n", "?\\n"),
        ("out = `ls -la # don't`\n", "don't"),
    ],
    ids=[
        "regex-quote",
        "regex-hash",
        "when-regex",
        "command-regex",
        "if-regex",
        "percent-regex",
        "percent-words",
        "percent-symbols",
        "percent-string",
        "nested-delimiters",
        "global-quote",
        "global-apostrophe",
        "character-quote",
        "character-apostrophe",
        "character-escape",
        "command-string",
    ],
)
def test_ruby_literal_is_masked_and_code_after_it_stays_visible(source: str, inert: str) -> None:
    source += CODE + "puts 'done'\n"
    spans, incomplete = _lex(source)
    assert not incomplete
    assert not _visible(source, spans, inert)
    assert _visible(source, spans, "AiServices.builder")


@pytest.mark.parametrize(
    "source",
    [
        "c = p / r\n",
        "average = total / count # one 'quote\n",
        "x.size / 2\n",
        "a /= 2\n",
        "def /(other) = self\n",
        "ops = [:/, :%]\n",
        "rest = a % (b)\n",
        'label = "%s" % [name]\n',
        "x = y%w\n",
        "ok = list.include?('a') ? 'b' : 'c'\n",
        "items<<value\n",
        "class << self\n  attr_reader :name\nend\n",
        "class <<self\n  attr_reader :name\nend\n",
    ],
    ids=[
        "division-by-variable",
        "division",
        "method-division",
        "divide-assign",
        "operator-method",
        "operator-symbols",
        "modulo",
        "format",
        "modulo-name",
        "predicate-method",
        "append",
        "singleton-class",
        "singleton-class-tight",
    ],
)
def test_ruby_operators_stay_code(source: str) -> None:
    source += CODE
    spans, incomplete = _lex(source)
    assert not incomplete
    assert _visible(source, spans, "AiServices.builder")


@pytest.mark.parametrize(
    "source",
    [
        "pattern = /#{AiServices.builder(x)}/\n",
        "names = %W[a #{AiServices.builder(x)}]\n",
        "text = %Q{a #{AiServices.builder(x)} b}\n",
        "text = %Q|a #{AiServices.builder(x)} b|\n",
        "out = `run #{AiServices.builder(x)}`\n",
        'line = %(#{AiServices.builder(x)} "quoted")\n',
    ],
    ids=["regex", "word-list", "percent-q", "percent-q-unpaired", "command-string", "percent-string"],
)
def test_ruby_interpolation_inside_a_literal_is_code(source: str) -> None:
    spans, incomplete = _lex(source)
    assert not incomplete
    assert _visible(source, spans, "AiServices.builder")


@pytest.mark.parametrize(
    "body",
    [
        "#{s.split(/}/).map { AiServices.builder(_1) }}",
        "#{[?}, AiServices.builder(x)]}",
        '#{log("#{"}"}", AiServices.builder(x))}',
        "#{%w[}].first + AiServices.builder(x)}",
    ],
    ids=["regex", "char-literal", "nested-interpolation", "percent-literal"],
)
def test_ruby_heredoc_interpolation_is_lexed_as_code(body: str) -> None:
    # These were incomplete before: the here-document's expression is now lexed like other code.
    source = f"text = <<~TXT\n  {body} and 'text\nTXT\nputs text\n"
    spans, incomplete = _lex(source)
    assert not incomplete
    assert _visible(source, spans, "AiServices.builder")
    assert not _visible(source, spans, "and 'text")


def test_ruby_heredoc_interpolation_across_lines_stays_incomplete() -> None:
    source = "text = <<~TXT\n  #{ # pick }\n    AiServices.builder(x)\n  }\nTXT\nputs text\n"
    spans, incomplete = _lex(source)
    assert incomplete or _visible(source, spans, "AiServices.builder")


def test_ruby_data_section_is_text() -> None:
    source = CODE + "__END__\nSELECT 'unterminated\nAiServices.builder(y)\n"
    spans, incomplete = _lex(source)
    assert not incomplete
    assert source.index("AiServices.builder(x)") < source.index("__END__")
    assert not _visible(source, spans, "AiServices.builder(y)")


@pytest.mark.parametrize(
    "source",
    ["x = %w[a b\n", "x = /abc\n", "x = %(a (b) c\n"],
    ids=["percent", "regex", "nested"],
)
def test_unterminated_ruby_literal_is_incomplete(source: str) -> None:
    _, incomplete = _lex(source + CODE)
    assert incomplete


def test_many_ruby_literals_stay_linear() -> None:
    source = "a = /x'/ + %w[y'] + ?' + $'\n" * 40_000
    started = time.monotonic()
    _, incomplete = _lex(source)
    assert not incomplete
    assert time.monotonic() - started < 10


def test_many_heredoc_interpolations_stay_linear() -> None:
    source = "t = <<~TXT\n" + '  #{a.map { |x| "#{x}" }} text\n' * 20_000 + "TXT\n"
    started = time.monotonic()
    _, incomplete = _lex(source)
    assert not incomplete
    assert time.monotonic() - started < 10
