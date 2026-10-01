"""CSV reports must not start a spreadsheet formula under any common delimiter."""

from __future__ import annotations

import csv
import io
import random
import re
import time

import pytest

from shadowscan.models import Evidence, Finding, Kind, ScanResult, Surface
from shadowscan.reporters.csv_ import _safe_cell, render_csv

TRIGGERS = ("=", "+", "-", "@")
TRIMMED = ' \t\r\n\v\f\ufeff\u00a0"'

HOSTILE = [
    "x;=2+5;",
    'Agent,=HYPERLINK("https://attacker.invalid");',
    "Agent\t+cmd|' /C calc'!A0",
    "framework.langchain|@SUM(1+1)*cmd",
    "Agent; -2+3",
    'Agent; "=1+1"',
    "Agent;b\n=1+1;",
    "Agent\r\n@SUM(1)",
]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("x;=2+5;", "x;'=2+5;"),
        ("a,=1+1", "a,'=1+1"),
        ("a\t+1", "a\t'+1"),
        ("a|@SUM(1)", "a|'@SUM(1)"),
        ("a; -1+1", "a;' -1+1"),
        ('a;"=1+1"', 'a;\'"=1+1"'),
        ("a\n=1+1", "a\n'=1+1"),
        ("a\r\n=1+1", "a\r'\n'=1+1"),
        ("a;\tb", "a;'\tb"),
        ("a;\rb", "a;'\rb"),
        ("=1;=2|=3", "'=1;'=2|'=3"),
        # A no-break space may be trimmed like a space.
        ("\u00a0=1+1", "'\u00a0=1+1"),
        ("a;\u00a0+1", "a;'\u00a0+1"),
    ],
)
def test_formula_trigger_after_any_delimiter_is_neutralised(value, expected):
    assert _safe_cell(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a;b|c,d",
        "a-b=c+d@e",
        "owner@example.com",
        "a\r\nb",
        "x = 1",
        "12-3",
        "a, b; c | d",
    ],
)
def test_values_without_a_formula_cell_are_unchanged(value):
    assert _safe_cell(value) == value


@pytest.mark.parametrize("value", [0, -5, 0.5, None, True])
def test_non_text_values_are_unchanged(value):
    assert _safe_cell(value) is value


@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
def test_no_cell_starts_a_formula_whichever_delimiter_opens_the_report(delimiter):
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=HOSTILE[0],
        resource=HOSTILE[1],
        resource_type="repository",
        owner=HOSTILE[3],
        frameworks=["framework.langchain", "@SUM(1)"],
        tags=["safe", "=1+1", "\u00a0=1+1"],
        evidence=[Evidence(signal="test", description=value, weight=0.5) for value in HOSTILE],
    )

    report = render_csv(ScanResult(findings=[finding]))

    cells = [cell for row in csv.reader(io.StringIO(report), delimiter=delimiter) for cell in row]
    assert any("HYPERLINK" in cell for cell in cells)  # the value is still reported
    for cell in cells:
        assert not cell.lstrip(TRIMMED).startswith(TRIGGERS), repr(cell)


def test_comma_reader_still_recovers_each_value_behind_its_marker():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="x;=2+5;",
        resource="repo",
        resource_type="repository",
        owner="@org/team",
    )
    row = next(csv.DictReader(io.StringIO(render_csv(ScanResult(findings=[finding])))))
    assert row["title"] == "x;'=2+5;"
    assert row["owner"] == "'@org/team"


# The pattern the reporter used before the linear pass, kept as the reference
# for the documented behaviour (it rescans whitespace at every cell start).
_REFERENCE_FORMULA_CELL = re.compile(
    r"^(?=[\t\r\n])"
    r"|(?:^|(?<=[,;\t|\r\n]))(?=[\t\r]|[ \t\r\n\v\f\ufeff\u00a0\"]*[=+\-@])"
)
_TRICKY_ALPHABET = "=+-@,;|\t\r\n\v\f\"' \u00a0\ufeffa1"


def test_linear_pass_matches_the_reference_pattern_on_random_strings():
    rng = random.Random(20261001)
    for _ in range(6000):
        value = "".join(rng.choice(_TRICKY_ALPHABET) for _ in range(rng.randint(0, 14)))
        assert _safe_cell(value) == _REFERENCE_FORMULA_CELL.sub("'", value), repr(value)


@pytest.mark.parametrize(
    "value",
    [
        "\r\n" * 100_000,
        "\n" * 200_000,
        ", " * 100_000 + "=1",
        "\r\n" * 100_000 + "=1+1",
        '" ' * 100_000 + "@x",
        "\t" * 200_000,
        "a;" + " " * 200_000 + "b",
    ],
)
def test_neutralising_a_long_whitespace_run_is_linear(value):
    # The earlier pattern needed about five seconds for 40,000 characters and
    # four times as long for every doubling, so a long run in a title or owner
    # stalled "-f csv".
    started = time.perf_counter()
    cell = _safe_cell(value)
    assert time.perf_counter() - started < 1.0
    assert cell.replace("'", "") == value


def test_a_hostile_finding_title_renders_quickly():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="\r\n" * 30_000 + "=1+1",
        resource="repo",
        resource_type="repository",
    )
    started = time.perf_counter()
    report = render_csv(ScanResult(findings=[finding]))
    assert time.perf_counter() - started < 1.0
    assert next(csv.DictReader(io.StringIO(report)))["title"].endswith("'=1+1")
