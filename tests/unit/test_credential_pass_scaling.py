"""The context-named credential passes of sanitize_text run in linear time.

Each record name, markup tag or command option used to search the rest of its
line or text for its value, so a long line of names was quadratic and could
exhaust the file's matching budget, leaving the scan incomplete.
"""

from __future__ import annotations

import itertools
import random
import re
import time

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, sanitize_text


def _best_time(source: str, repeats: int) -> float:
    best = float("inf")
    for _ in range(repeats):
        started = time.perf_counter()
        sanitize_text(source)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("unit", [
    '<add key="api_key" ',            # a key attribute naming a credential, value never given
    "{name: API_KEY, ",               # a record name, value field never given
    '{"name": "API_KEY", ',
    "key:",                           # a 'key:key:key...' chain of record names
    "<password><![CDATA[",            # sensitive element content in an unterminated CDATA
    "<password><![CDATA[ <password>]]>",
    '<setting name="ApiKey"> ',
    "docker login -p x ",             # '-p' read from its command
    "mysql -pabc ",
    'openaiKey = "',                  # a credential-like name before an unfinished literal
    ").apiKey(\"",                    # a method called on a call result
    'k || "',                         # a fallback default; the name is read backwards
    'f("OPENAI_API_KEY") ?? "a8f3c91d7e2b" ',
    "${TOKEN:-",                      # an unfinished shell default
    'AzureKeyCredential a = new("a8f3c91d7e2b"); ',  # a declared type, read backwards
    'X::new("a"), ',
    "{name: API_KEY, value: [REDACTED",  # a record value that is not a whole marker
    '{name: API_KEY, value: "}',       # a quoted record value read past a brace
    "tool --key a8f3c91d7e2b4f6a ",    # an option whose last word names a credential
    "openaiKey: a8f3c91d7e2b4f6a ",    # an unquoted YAML value under a credential-like name
    "--key=#",                         # options inside one word whose kept values run to its end
    "-u=#",
    "-H=#",
    "--key=[REDACTED]#",
    "-u=a:",                           # a kept user:password or header value after each ':'
    "-u=a=b:",
    "-H=a:",
    "--user=a://",
    "--api-key=$A#",                   # a reference before the next option
    "-u=%K%:",
])
def test_context_named_credential_passes_scale_linearly(unit):
    small, large = unit * 1000, unit * 4000
    small_time = _best_time(small, 3)
    large_time = _best_time(large, 1)
    # Four times the input must not cost more than ten times the time (a
    # quadratic pass costs sixteen times). The floor absorbs timer noise on
    # tiny inputs; no absolute bound, since coverage tracing slows CI runners.
    assert large_time < max(small_time, 0.02) * 10, (small_time, large_time)


# The pattern that decided whether an unquoted value was made of words.
_WORDY = re.compile(r"(?:[A-Z][a-z]+|[a-z]{3,}|[A-Z]{2,}|[0-9]+|_)+")


def test_reading_a_value_once_finds_the_words_the_pattern_found():
    for length in range(8):
        for characters in itertools.product("Aa1_-", repeat=length):
            value = "".join(characters)
            assert redaction._wordy(value) == (_WORDY.fullmatch(value) is not None), repr(value)
    rng = random.Random(20260929)
    pieces = ["A", "Z", "a", "z", "0", "9", "_", "-", ".", "=", "é", "Ä"]
    for _ in range(20_000):
        value = "".join(rng.choice(pieces) * rng.randint(1, 4) for _ in range(rng.randint(1, 6)))[:16]
        assert redaction._wordy(value) == (_WORDY.fullmatch(value) is not None), repr(value)


# A long run of one character class under a credential-like name, ended by a
# character the run rejects. The pattern above split such a run every way it
# could before it failed: at these sizes it took one to five seconds, and
# every few more characters doubled that. It read every unquoted value after
# '=' ('key=' hung too), and for a while every value after ':' as well, in
# structured values as in text.
@pytest.mark.parametrize(("prefix", "run", "suffix", "count"), [
    ("token: ", "a", ".", 46),
    ("key: ", "1", "-", 24),
    ("key=", "1", "-", 24),
    ("credential:sha256:", "a", "--auth", 44),
    ("openaiKey: ", "A", ".", 34),
    ("api_key: ", "abc", "+", 15),
])
@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_a_long_run_of_one_character_class_is_read_once(prefix, run, suffix, count, structured):
    def cost(repeats: int) -> float:
        source = prefix + run * repeats + suffix
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            if structured:
                redaction.sanitize({"note": source})
            else:
                sanitize_text(source)
            best = min(best, time.perf_counter() - started)
        return best

    assert cost(count) < max(cost(8), 0.02) * 10
    assert cost(4000) < max(cost(1000), 0.02) * 10


def test_blank_runs_inside_a_record_value_scale_linearly():
    def source(blanks: int) -> str:
        return "- name: API_KEY\n  value: opaque" + " " * blanks + "tail # note\n"

    small_time = _best_time(source(10_000), 3)
    large_time = _best_time(source(40_000), 1)
    assert large_time < max(small_time, 0.02) * 10, (small_time, large_time)
    safe = sanitize_text(source(100))
    assert "opaque" not in safe and "tail" not in safe and safe.endswith("# note\n")


# The lazy pattern a sibling line's value used to be matched with.
_LAZY_LINE_VALUE = re.compile(r"\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\r\n]*?(?=[ \t]+#|[ \t]*$)", re.MULTILINE)


def test_sibling_line_values_match_the_lazy_pattern():
    rng = random.Random(20260928)
    pieces = [" ", "\t", "#", "a", "b", '"', "'", "\r", "|", "-"]
    for _ in range(5000):
        body = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 12)))
        text = "value: " + body + rng.choice(["", "\n", "\nmore"])
        end = text.find("\n", 7)
        end = len(text) if end < 0 else end
        expected = _LAZY_LINE_VALUE.match(text, 7, end)
        span = expected.span() if expected else None
        assert redaction._record_line_value(text, 7, end) == span, repr(text)


def test_a_long_line_of_record_names_completes_in_a_full_scan(tmp_path, index):
    # 320 KB on one line; the quadratic lookup took about 84 seconds and the
    # scan was incomplete (MatchTimeoutError).
    source = "import openai\n# " + "{name: API_KEY, " * 20_000 + "\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    started = time.perf_counter()
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", {
        "path": str(tmp_path), "use_git": False,
    })]), index).run()
    elapsed = time.perf_counter() - started
    assert elapsed < 20, elapsed  # generous for slow CI runners
    assert result.complete, [error for stats in result.stats for error in stats.errors]
    assert any("OpenAI" in finding.title for finding in result.findings)


def test_a_word_of_many_options_is_withheld_past_the_limit():
    # Each kept option value is read to the end of its word, so a word of
    # option after option was quadratic ('--key=#' * 8000 took seconds). Past
    # the limit the rest of the word is withheld, never shown.
    secret = "a8f3c91d7e2b4f6a9d0c"
    source = "tool " + "--key=#" * 40 + f"--key={secret} --model gpt-4o"
    safe = sanitize_text(source)
    assert secret not in safe and safe.endswith(f"{REDACTED} --model gpt-4o")
    assert safe.count("--key=#") == redaction._CLI_WORD_OPTIONS
    assert sanitize_text(safe) == safe


def test_linear_record_and_markup_passes_still_withhold_values():
    source = (
        '{name: OPENAI_API_KEY, value: "a8f3c91d7e2b4f6a"}\n'
        "<password><![CDATA[ <apiKey>b7e2c91d4f6a8f3a</apiKey> ]]></password>\n"
        '<add key="api_key" value="c91d7e2b4f6a8f3a"/>\n'
    )
    safe = sanitize_text(source)
    assert "a8f3c91d" not in safe and "b7e2c91d" not in safe and "c91d7e2b" not in safe
    assert safe.count(REDACTED) == 3
    assert safe.count("\n") == source.count("\n")
