"""Unfinished sensitive annotations are redacted in linear time.

Each ``key:`` candidate used to tokenize from its colon to the end of its
statement. When no '=' followed, the next candidate tokenized the same text
again, so a long run of unfinished annotations cost quadratic time and could
exhaust the redaction work budget, leaving the whole file incomplete.
"""

from __future__ import annotations

import random
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
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", {
        "path": str(tmp_path), "use_git": False,
    })]), index).run()
    elapsed = time.perf_counter() - started
    # Generous for slow CI runners; the quadratic scan took about 45 seconds.
    assert elapsed < 5, elapsed
    assert result.complete, [error for stats in result.stats for error in stats.errors]
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


@pytest.mark.parametrize("unit", [
    "token: x ",          # one logical line of unfinished annotations
    "token: a \\\n",      # a backslash-continued statement
    "(token: a, ",        # annotations inside an unclosed bracket
])
def test_unfinished_annotation_redaction_scales_linearly(unit):
    small, large = unit * 500, unit * 2000
    small_time = _best_time(small, 3)
    large_time = _best_time(large, 1)
    # Four times the input must not cost more than ten times the time (a
    # quadratic scan costs sixteen times). The floor absorbs timer noise on
    # tiny inputs; no absolute bound, since coverage tracing slows CI runners.
    assert large_time < max(small_time, 0.02) * 10, (small_time, large_time)


_PIECES = [
    "token:", "token: ", "api_key:", "password :", "x:", "token =", "token = 1", "cfg['token']",
    "secret: str = 'value'", "(", "(", "[", "{", ")", "]", "}", "\n", "\n", "\n  ", "\n\n", " ", "\t",
    "\\\n", "# note", "'", '"', '"v"', '"""', ";", ",", "+", "=", ":", "`", "//", "a", "1", "f'{a:>3}'",
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


@pytest.mark.parametrize("source", [
    "api_key: Final[" + "[" * 150 + "\nimport langchain\n",
    "token = " + "(" * 150 + '"opaque-nested-value"' + ")" * 150 + "\nimport langchain\n",
])
def test_too_deeply_nested_sensitive_expressions_are_withheld_through_the_end(source):
    safe = sanitize_text(source)
    assert "opaque-nested-value" not in safe and "langchain" not in safe
    assert REDACTED in safe
    assert safe.count("\n") == source.count("\n")
