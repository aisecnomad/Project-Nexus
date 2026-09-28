"""Unfinished sensitive annotations are redacted in linear time.

Each ``key:`` candidate used to tokenize from its colon to the end of its
statement. When no '=' followed, the next candidate tokenized the same text
again, so a long run of unfinished annotations cost quadratic time and could
exhaust the redaction work budget, leaving the whole file incomplete.
"""

from __future__ import annotations

import random
import sys
import time

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text

UNFINISHED = "import openai\n" + "token: (\n" * 3500  # 31 KB


def test_unfinished_annotations_complete_quickly_in_a_full_scan(tmp_path, index):
    (tmp_path / "app.py").write_text(UNFINISHED, encoding="utf-8")
    started = time.perf_counter()
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    "code.filesystem",
                    {
                        "path": str(tmp_path),
                        "use_git": False,
                    },
                )
            ]
        ),
        index,
    ).run()
    elapsed = time.perf_counter() - started
    # Generous for slow CI runners; the quadratic scan took about 45 seconds.
    assert elapsed < 5, elapsed
    errors = [error for stats in result.stats for error in stats.errors]
    # The C tokenizer of Python 3.12+ refuses more than 200 nested brackets, so
    # the lexical pass fails closed there independently of redaction; only that
    # diagnostic may remain. Redaction itself must finish within its budget.
    lexical = "code.filesystem: app.py: incomplete source lexical analysis"
    if sys.version_info < (3, 12):
        assert result.complete, errors
    else:
        assert errors == [lexical], errors
    assert any("OpenAI" in finding.title for finding in result.findings)


def test_unfinished_annotations_are_withheld_without_exhausting_the_budget():
    started = time.perf_counter()
    safe = sanitize_text(UNFINISHED)
    assert time.perf_counter() - started < 5
    assert safe.startswith("import openai\ntoken: ")
    assert REDACTED in safe
    assert safe.count("\n") == UNFINISHED.count("\n")
    assert sanitize_text(safe) == safe


def _best_time(source: str, repeats: int) -> float:
    best = float("inf")
    for _ in range(repeats):
        started = time.perf_counter()
        sanitize_text(source)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize(
    "unit",
    [
        "token: x ",  # one logical line of unfinished annotations
        "token: a \\\n",  # a backslash-continued statement
        "(token: a, ",  # annotations inside an unclosed bracket
        "token: (\n",  # the 31 KB file above: one unclosed bracket per line
    ],
)
def test_unfinished_annotation_redaction_scales_linearly(unit):
    small, large = unit * 500, unit * 2000
    small_time = _best_time(small, 3)
    large_time = _best_time(large, 1)
    # Four times the input must not cost more than ten times the time (a
    # quadratic scan costs sixteen times). The floor absorbs timer noise on
    # tiny inputs; no absolute bound, since coverage tracing slows CI runners.
    assert large_time < max(small_time, 0.02) * 10, (small_time, large_time)


_PIECES = [
    "token:",
    "token: ",
    "api_key:",
    "password :",
    "x:",
    "token =",
    "token = 1",
    "cfg['token']",
    "secret: str = 'value'",
    "(",
    "(",
    "[",
    "{",
    ")",
    "]",
    "}",
    "\n",
    "\n",
    "\n  ",
    "\n\n",
    " ",
    "\t",
    "\\\n",
    "# note",
    "'",
    '"',
    '"v"',
    '"""',
    ";",
    ",",
    "+",
    "=",
    ":",
    "`",
    "//",
    "a",
    "1",
    "f'{a:>3}'",
]


def test_reused_annotation_scans_match_a_scan_per_candidate(monkeypatch):
    rng = random.Random(20260927)
    sources = ["".join(rng.choice(_PIECES) for _ in range(rng.randint(5, 80))) for _ in range(1500)]
    decisions = []
    enclosed = redaction._AssignmentScanner.enclosed_without_assignment

    def counting(self: redaction._AssignmentScanner, candidate_end: int) -> bool:
        decisions.append(enclosed(self, candidate_end))
        return decisions[-1]

    def redact(source: str) -> str:
        try:
            return redaction._redact_python_assignments(source)
        except SanitizationLimitError as exc:
            return f"limit: {exc}"

    monkeypatch.setattr(redaction._AssignmentScanner, "enclosed_without_assignment", counting)
    reused = [redact(source) for source in sources]
    monkeypatch.setattr(redaction._AssignmentScanner, "enclosed_without_assignment", lambda self, end: False)
    rescanned = [redact(source) for source in sources]
    assert reused == rescanned
    assert sum(decisions) > 100  # reuse was exercised, not merely available


@pytest.mark.parametrize(
    "unit",
    [
        "{token: a}, ",  # annotations that end at a closer, all on one line
        "(token = a, ",  # sensitive keyword arguments, all on one line
        "{token:e.token,headers:h},function f(a){return a+1};",
    ],
)
def test_candidates_on_one_long_line_scale_linearly(unit):
    small, large = unit * 1000, unit * 4000
    small_time = _best_time(small, 3)
    large_time = _best_time(large, 1)
    assert large_time < max(small_time, 0.02) * 10, (small_time, large_time)


def test_candidates_on_one_long_line_do_not_exhaust_the_budget():
    # Each candidate's scan used to read, and be charged, the rest of the
    # physical line although tokenizing stopped at the next ',' or '}'. A
    # minified line with a few thousand sensitive keys exceeded the budget
    # and every excerpt of the file was withheld as incomplete.
    mapping = sanitize_text("{token: a}, " * 20_000)
    assert mapping.count(REDACTED) == 20_000 and "token: a" not in mapping
    arguments = sanitize_text("f(" + "token = a, " * 20_000 + ")")
    assert arguments.count(REDACTED) == 20_000 and "token = a" not in arguments
    bundle = "".join(
        f"function f{n}(e,h){{return fetch(u,{{token:e.token,headers:h}})}};" + "var x=1;" * 100
        for n in range(600)
    )
    assert len(bundle) > 500_000
    assert sanitize_text(bundle).count("{token:e.token,headers:h}") == 600


_LINE_PIECES = [
    *_PIECES,
    "token = a, ",
    "(token = a, ",
    "{token: a}, ",
    "abc_def_ghi ",
    "1e5",
    "...",
    "?",
    "$",
    "<-",
]


def test_line_limited_scans_match_whole_line_scans(monkeypatch):
    rng = random.Random(20260928)
    sources = []
    for _ in range(1500):
        source = "".join(rng.choice(_LINE_PIECES) for _ in range(rng.randint(5, 80)))
        # Join some lines so long physical lines are cut at realistic limits too.
        sources.append(source.replace("\n", " ", rng.randint(0, 4)))
    cuts = []
    scan = redaction._AssignmentScanner._scan

    def counting(self: redaction._AssignmentScanner, *args: object) -> object:
        located = scan(self, *args)  # type: ignore[arg-type]
        cuts.append(located is None)
        return located

    def redact(source: str) -> str:
        try:
            return redaction._redact_python_assignments(source)
        except SanitizationLimitError as exc:
            return f"limit: {exc}"

    monkeypatch.setattr(redaction, "_SCAN_LINE_LIMIT", 1 << 40)
    whole = [redact(source) for source in sources]
    monkeypatch.setattr(redaction._AssignmentScanner, "_scan", counting)
    for limit in (1, 3, 9, 24):
        monkeypatch.setattr(redaction, "_SCAN_LINE_LIMIT", limit)
        assert [redact(source) for source in sources] == whole, limit
    assert sum(cuts) > 1000  # scans stopped near a cut were repeated, not trusted


@pytest.mark.parametrize(
    "source",
    [
        "api_key: Final[" + "[" * 150 + "\nimport langchain\n",
        "token = " + "(" * 150 + '"opaque-nested-value"' + ")" * 150 + "\nimport langchain\n",
    ],
)
def test_too_deeply_nested_sensitive_expressions_are_withheld_through_the_end(source):
    safe = sanitize_text(source)
    assert "opaque-nested-value" not in safe and "langchain" not in safe
    assert REDACTED in safe
    assert safe.count("\n") == source.count("\n")
