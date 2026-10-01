"""The per-connector coverage gate, exercised with small synthetic ``coverage json`` reports."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.coverage_gate import MIN_CONNECTOR_COVERAGE, connector_coverage, main

ROOT = Path(__file__).resolve().parents[1]


def _summary(statements: int, covered: int, branches: int = 0, covered_branches: int = 0) -> dict[str, Any]:
    return {
        "summary": {
            "num_statements": statements,
            "covered_lines": covered,
            "num_branches": branches,
            "covered_branches": covered_branches,
        }
    }


def _report(files: dict[str, dict[str, Any]], *, branch: bool = True) -> dict[str, Any]:
    return {"meta": {"format": 3, "branch_coverage": branch}, "files": files}


def _gate(tmp_path: Path, report: dict[str, Any]) -> int:
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return main([str(path)])


def test_every_connector_module_counts_at_any_depth():
    report = _report(
        {
            "shadowscan/connectors/__init__.py": _summary(10, 10),
            "shadowscan/connectors/base.py": _summary(10, 9),
            "shadowscan/connectors/common.py": _summary(10, 8),
            "shadowscan/connectors/offline.py": _summary(10, 8),
            "shadowscan/connectors/cloud/__init__.py": _summary(0, 0),
            "shadowscan/connectors/cloud/aws.py": _summary(10, 9),
            "shadowscan/connectors/code/nested/helper.py": _summary(10, 10),
            "shadowscan/engine.py": _summary(10, 0),
            "shadowscan/connectors_extra.py": _summary(10, 0),
            "tools/evaluation/evaluate.py": _summary(10, 0),
        }
    )
    assert connector_coverage(report) == {
        "shadowscan/connectors/__init__.py": 100.0,
        "shadowscan/connectors/base.py": 90.0,
        "shadowscan/connectors/common.py": 80.0,
        "shadowscan/connectors/offline.py": 80.0,
        "shadowscan/connectors/cloud/aws.py": 90.0,
        "shadowscan/connectors/code/nested/helper.py": 100.0,
    }


@pytest.mark.parametrize(
    "module",
    [
        "shadowscan/connectors/__init__.py",
        "shadowscan/connectors/base.py",
        "shadowscan/connectors/common.py",
        "shadowscan/connectors/offline.py",
        "shadowscan/connectors/code/nested/helper.py",
    ],
)
def test_shared_and_nested_modules_below_the_floor_fail(tmp_path, capsys, module):
    # These modules were outside the gate before; offline.py alone is ~700 lines.
    report = _report({"shadowscan/connectors/cloud/aws.py": _summary(10, 10), module: _summary(100, 50)})
    assert _gate(tmp_path, report) == 1
    assert f"{module}: 50.00% < 75%" in capsys.readouterr().err


def test_untaken_branches_count_against_the_floor(tmp_path, capsys):
    # Every line ran, but most conditions only went one way: (10 + 2) / (10 + 10).
    report = _report({"shadowscan/connectors/saas/slack.py": _summary(10, 10, 10, 2)})
    assert connector_coverage(report) == {"shadowscan/connectors/saas/slack.py": 60.0}
    assert _gate(tmp_path, report) == 1
    assert "slack.py: 60.00% < 75%" in capsys.readouterr().err


def test_the_floor_itself_passes_and_names_the_lowest_module(tmp_path, capsys):
    assert MIN_CONNECTOR_COVERAGE == 75.0
    report = _report(
        {
            "shadowscan/connectors/identity/okta.py": _summary(60, 45, 20, 15),
            "shadowscan/connectors/offline.py": _summary(10, 10, 2, 2),
        }
    )
    assert _gate(tmp_path, report) == 0
    out = capsys.readouterr().out
    assert "Checked 2 built-in connector modules" in out
    assert "lowest shadowscan/connectors/identity/okta.py at 75.00%" in out


@pytest.mark.parametrize(
    "report",
    [
        # Statement-only data would let a module pass on lines alone.
        _report({"shadowscan/connectors/base.py": _summary(10, 10)}, branch=False),
        # A report that measured no connector module cannot vouch for any.
        _report({"shadowscan/engine.py": _summary(10, 10)}),
        _report({"shadowscan/connectors/cloud/__init__.py": _summary(0, 0)}),
        {"files": {}},
        {"meta": {"branch_coverage": True}},
        _report({"shadowscan/connectors/base.py": {"summary": {"num_statements": 10}}}),
    ],
    ids=["statements-only", "no-connectors", "only-empty-modules", "no-meta", "no-files", "no-branch-counts"],
)
def test_reports_that_cannot_prove_connector_coverage_fail_closed(tmp_path, report):
    assert _gate(tmp_path, report) == 2


def test_unreadable_reports_and_bad_usage_fail_closed(tmp_path):
    assert main([str(tmp_path / "missing.json")]) == 2
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    assert main([str(malformed)]) == 2
    assert main([]) == 2
    assert main(["one.json", "two.json"]) == 2


def test_command_line_entry_point_reports_failure(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_report({"shadowscan/connectors/base.py": _summary(4, 1)})), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "tools.coverage_gate", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "shadowscan/connectors/base.py: 25.00% < 75%" in result.stderr
