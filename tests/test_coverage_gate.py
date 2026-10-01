"""A connector coverage gate must not pass incomplete or malformed reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tools import coverage_gate

AWS = "shadowscan/connectors/cloud/aws.py"
SLACK = "shadowscan/connectors/saas/slack.py"


@pytest.fixture
def coverage_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, Any]]:
    for name in (AWS, SLACK, "shadowscan/connectors/cloud/__init__.py"):
        source = tmp_path / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(coverage_gate, "ROOT", tmp_path)
    path = tmp_path / "coverage.json"
    monkeypatch.setattr(sys, "argv", ["coverage_gate", str(path)])
    return path, {
        "files": {
            name: {"summary": {"num_statements": 10, "percent_statements_covered": 100.0}}
            for name in (AWS, SLACK)
        }
    }


def _run(coverage_report: tuple[Path, dict[str, Any]]) -> int:
    path, report = coverage_report
    path.write_text(json.dumps(report), encoding="utf-8")
    return coverage_gate.main()


def test_complete_inventory_passes_at_statement_floor(
    coverage_report: tuple[Path, dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    _, report = coverage_report
    report["files"][AWS]["summary"]["percent_statements_covered"] = 75
    # Shared modules remain outside this gate's existing family-module scope.
    report["files"]["shadowscan/connectors/base.py"] = {
        "summary": {"num_statements": 10, "percent_statements_covered": 0}
    }
    assert _run(coverage_report) == 0
    assert "Checked 2 built-in connector modules" in capsys.readouterr().out


def test_connector_below_floor_fails(coverage_report: tuple[Path, dict[str, Any]]) -> None:
    _, report = coverage_report
    report["files"][AWS]["summary"]["percent_statements_covered"] = 74.9
    assert _run(coverage_report) == 1


@pytest.mark.parametrize("mutation", ["missing", "unexpected", "new_source"])
def test_connector_inventory_must_match_checkout(
    coverage_report: tuple[Path, dict[str, Any]], mutation: str
) -> None:
    path, report = coverage_report
    if mutation == "missing":
        del report["files"][SLACK]
    elif mutation == "unexpected":
        report["files"]["shadowscan/connectors/cloud/removed.py"] = report["files"][AWS]
    else:
        (path.parent / "shadowscan/connectors/cloud/new.py").write_text("pass\n", encoding="utf-8")
    assert _run(coverage_report) == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("num_statements", -1),
        ("num_statements", True),
        ("num_statements", 1.5),
        ("num_statements", "10"),
        ("num_statements", None),
        ("percent_statements_covered", True),
        ("percent_statements_covered", "100"),
        ("percent_statements_covered", None),
        ("percent_statements_covered", -0.1),
        ("percent_statements_covered", 100.1),
        ("percent_statements_covered", float("nan")),
        ("percent_statements_covered", float("inf")),
    ],
)
def test_invalid_connector_measurements_fail_closed(
    coverage_report: tuple[Path, dict[str, Any]], field: str, value: Any
) -> None:
    _, report = coverage_report
    report["files"][AWS]["summary"][field] = value
    assert _run(coverage_report) == 2


@pytest.mark.parametrize("entry", [None, [], {}, {"summary": []}, {"summary": {}}])
def test_invalid_connector_schema_fails_closed(
    coverage_report: tuple[Path, dict[str, Any]], entry: Any
) -> None:
    _, report = coverage_report
    report["files"][AWS] = entry
    assert _run(coverage_report) == 2


@pytest.mark.parametrize(
    "text",
    ["not JSON", "[]", "{}", '{"files": []}', '{"files": {}, "files": {}}', '{"files": 1e9999}'],
)
def test_invalid_report_fails_without_traceback(
    coverage_report: tuple[Path, dict[str, Any]], text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _ = coverage_report
    path.write_text(text, encoding="utf-8")
    assert coverage_gate.main() == 2
    assert "invalid coverage report:" in capsys.readouterr().err


def test_unreadable_report_fails_without_traceback(coverage_report: tuple[Path, dict[str, Any]]) -> None:
    assert coverage_gate.main() == 2


def test_empty_measurements_do_not_establish_coverage(
    coverage_report: tuple[Path, dict[str, Any]],
) -> None:
    _, report = coverage_report
    for details in report["files"].values():
        details["summary"]["num_statements"] = 0
    assert _run(coverage_report) == 2
