"""CSV reports must not start a spreadsheet formula under any common delimiter."""

from __future__ import annotations

import csv
import io

import pytest

from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface, now_iso
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
    # A complete scan: an incomplete one leads with its status row instead.
    stats = ScanStats(connector="code.filesystem", started_at=now_iso(), finished_at=now_iso())
    row = next(csv.DictReader(io.StringIO(render_csv(ScanResult(findings=[finding], stats=[stats])))))
    assert row["title"] == "x;'=2+5;"
    assert row["owner"] == "'@org/team"
