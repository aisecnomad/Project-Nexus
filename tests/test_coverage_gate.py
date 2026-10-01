"""The per-connector coverage gate (`tools/coverage_gate.py`) on synthetic coverage-JSON reports."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.coverage_gate import MIN_CONNECTOR_COVERAGE, main

ROOT = Path(__file__).resolve().parents[1]
# A minimal healthy report: one connector per kind of exempt or checked path.
BASELINE = {
    "shadowscan/cli.py": (300, 10.0),
    "shadowscan/connectors/__init__.py": (150, 10.0),
    "shadowscan/connectors/base.py": (280, 10.0),
    "shadowscan/connectors/common.py": (300, 10.0),
    "shadowscan/connectors/offline.py": (420, 10.0),
    "shadowscan/connectors/cloud/__init__.py": (0, 100.0),
    "shadowscan/connectors/cloud/aws.py": (1000, 90.0),
    "shadowscan/connectors/saas/slack.py": (300, 96.0),
}


def _report(tmp_path: Path, modules: dict[str, tuple[int, float]]) -> str:
    """Write a coverage.py JSON report (format 3 shape) and return its path."""
    files = {
        path: {
            "executed_lines": [],
            "missing_lines": [],
            "summary": {"num_statements": statements, "percent_statements_covered": percent},
        }
        for path, (statements, percent) in modules.items()
    }
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"meta": {"format": 3}, "files": files, "totals": {}}), encoding="utf-8")
    return str(path)


def test_the_floor_is_75_percent_per_connector(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert MIN_CONNECTOR_COVERAGE == 75.0
    assert main([_report(tmp_path, {**BASELINE, "shadowscan/connectors/cloud/aws.py": (1000, 75.0)})]) == 0
    assert "Checked 2 built-in connector modules" in capsys.readouterr().out
    assert main([_report(tmp_path, {**BASELINE, "shadowscan/connectors/cloud/aws.py": (1000, 74.9)})]) == 1
    assert "shadowscan/connectors/cloud/aws.py: 74.90% < 75%" in capsys.readouterr().err


@pytest.mark.parametrize(
    "module,reason",
    [
        ("shadowscan/connectors/mail/imap.py", "connector family 'mail' is not listed"),
        ("shadowscan/connectors/cloud/aws/collect.py", "nested package below a connector family"),
        ("shadowscan/connectors/registry.py", "not a listed shared helper"),
    ],
)
def test_a_module_outside_the_rule_fails_instead_of_being_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], module: str, reason: str
) -> None:
    # Fully covered and still failing: the gate cannot vouch for a module its
    # per-connector rule does not examine.
    assert main([_report(tmp_path, {**BASELINE, module: (40, 100.0)})]) == 1
    assert f"{module}: {reason}" in capsys.readouterr().err
    # A module without statements has nothing to measure, and package
    # __init__ files are exempt at any depth.
    empty = {**BASELINE, module: (0, 100.0), "shadowscan/connectors/cloud/aws/__init__.py": (5, 0.0)}
    assert main([_report(tmp_path, empty)]) == 0


def test_only_unchecked_modules_still_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = {"shadowscan/connectors/base.py": (280, 10.0), "shadowscan/connectors/mail/imap.py": (40, 100.0)}
    assert main([_report(tmp_path, report)]) == 1
    assert "connector family 'mail' is not listed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [[], ["one.json", "two.json"]],
    ids=["no-report", "two-reports"],
)
def test_usage_errors_exit_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 2
    assert "usage: python -m tools.coverage_gate COVERAGE_JSON" in capsys.readouterr().err


def test_a_report_without_connector_modules_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Absolute paths (coverage run without relative files) also match no
    # connector module; an empty measurement must never pass.
    modules = {"shadowscan/cli.py": (300, 90.0), "/abs/shadowscan/connectors/cloud/aws.py": (100, 100.0)}
    assert main([_report(tmp_path, modules)]) == 2
    assert "contains no built-in connector modules" in capsys.readouterr().err


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        json.dumps({"meta": {}}),
        json.dumps({"files": {"shadowscan/connectors/cloud/aws.py": {}}}),
    ],
    ids=["invalid-json", "no-files", "no-summary"],
)
def test_an_unreadable_report_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(content, encoding="utf-8")
    assert main([str(report)]) == 2
    assert "cannot read coverage report" in capsys.readouterr().err
    assert main([str(tmp_path / "missing.json")]) == 2


def test_module_entry_point_exit_codes(tmp_path: Path) -> None:
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "tools.coverage_gate", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

    assert run().returncode == 2
    passing = run(_report(tmp_path, BASELINE))
    assert passing.returncode == 0, passing.stderr
    assert passing.stdout.startswith("Checked 2 built-in connector modules")
    assert (
        run(_report(tmp_path, {**BASELINE, "shadowscan/connectors/saas/slack.py": (300, 12.0)})).returncode
        == 1
    )
