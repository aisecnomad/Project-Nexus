"""The per-connector coverage gate, exercised with small synthetic ``coverage json`` reports."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools import coverage_gate
from tools.coverage_gate import MIN_CONNECTOR_COVERAGE, connector_coverage, connector_modules, main

ROOT = Path(__file__).resolve().parents[1]
AWS = "shadowscan/connectors/cloud/aws.py"
SLACK = "shadowscan/connectors/saas/slack.py"
BASE = "shadowscan/connectors/base.py"


def _summary(statements: int, covered: int, branches: int = 0, covered_branches: int = 0) -> dict[str, Any]:
    return {
        "summary": {
            "num_statements": statements,
            "covered_lines": covered,
            "num_branches": branches,
            "covered_branches": covered_branches,
        }
    }


def _report(files: dict[str, Any], *, branch: bool = True) -> dict[str, Any]:
    return {"meta": {"format": 3, "branch_coverage": branch}, "files": files}


@pytest.fixture
def checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty checkout root that the gate inventories instead of the repository."""
    monkeypatch.setattr(coverage_gate, "ROOT", tmp_path)
    return tmp_path


def _add_modules(checkout: Path, *paths: str) -> None:
    for path in paths:
        module = checkout / path
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_text("pass\n", encoding="utf-8")


def _gate(checkout: Path, report: Any, *, add_modules: bool = True) -> int:
    """Run the gate on ``report``; by default the checkout holds every connector module it names."""
    if add_modules and isinstance(report, dict) and isinstance(report.get("files"), dict):
        _add_modules(
            checkout, *(path for path in report["files"] if path.startswith("shadowscan/connectors/"))
        )
    path = checkout / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return main([str(path)])


def test_every_connector_module_counts_at_any_depth():
    report = _report(
        {
            "shadowscan/connectors/__init__.py": _summary(10, 10),
            BASE: _summary(10, 9),
            "shadowscan/connectors/common.py": _summary(10, 8),
            "shadowscan/connectors/offline.py": _summary(10, 8),
            "shadowscan/connectors/cloud/__init__.py": _summary(0, 0),
            AWS: _summary(10, 9),
            "shadowscan/connectors/code/nested/helper.py": _summary(10, 10),
            "shadowscan/engine.py": _summary(10, 0),
            "shadowscan/connectors_extra.py": _summary(10, 0),
            "tools/evaluation/evaluate.py": _summary(10, 0),
        }
    )
    assert connector_coverage(report) == {
        "shadowscan/connectors/__init__.py": 100.0,
        BASE: 90.0,
        "shadowscan/connectors/common.py": 80.0,
        "shadowscan/connectors/offline.py": 80.0,
        AWS: 90.0,
        "shadowscan/connectors/code/nested/helper.py": 100.0,
    }


def test_the_checkout_inventory_reaches_shared_and_nested_modules():
    modules = connector_modules(ROOT)
    assert BASE in modules and "shadowscan/connectors/offline.py" in modules
    assert any(Path(module).parent.parent.name == "connectors" for module in modules)
    assert all(module.startswith("shadowscan/connectors/") and module.endswith(".py") for module in modules)


@pytest.mark.parametrize(
    "module",
    [
        "shadowscan/connectors/__init__.py",
        BASE,
        "shadowscan/connectors/common.py",
        "shadowscan/connectors/offline.py",
        "shadowscan/connectors/code/nested/helper.py",
    ],
)
def test_shared_and_nested_modules_below_the_floor_fail(checkout, capsys, module):
    # These modules were outside the gate before; offline.py alone is ~700 lines.
    report = _report({AWS: _summary(10, 10), module: _summary(100, 50)})
    assert _gate(checkout, report) == 1
    assert f"{module}: 50.00% < 75%" in capsys.readouterr().err


def test_untaken_branches_count_against_the_floor(checkout, capsys):
    # Every line ran, but most conditions only went one way: (10 + 2) / (10 + 10).
    report = _report({SLACK: _summary(10, 10, 10, 2)})
    assert connector_coverage(report) == {SLACK: 60.0}
    assert _gate(checkout, report) == 1
    assert "slack.py: 60.00% < 75%" in capsys.readouterr().err


def test_the_floor_itself_passes_and_names_the_lowest_module(checkout, capsys):
    assert MIN_CONNECTOR_COVERAGE == 75.0
    report = _report(
        {
            "shadowscan/connectors/identity/okta.py": _summary(60, 45, 20, 15),
            "shadowscan/connectors/offline.py": _summary(10, 10, 2, 2),
            # An empty package marker is inventoried but has nothing to measure.
            "shadowscan/connectors/identity/__init__.py": _summary(0, 0),
        }
    )
    assert _gate(checkout, report) == 0
    out = capsys.readouterr().out
    assert "Checked 2 built-in connector modules" in out
    assert "lowest shadowscan/connectors/identity/okta.py at 75.00%" in out


@pytest.mark.parametrize("mutation", ["missing", "unexpected", "new_source"])
def test_the_report_must_cover_the_whole_connector_inventory(checkout, capsys, mutation):
    # A selected-test run or another checkout's report cannot vouch for the
    # modules it never measured; a module the checkout lacks is not this code.
    report = _report({AWS: _summary(10, 10), SLACK: _summary(10, 10)})
    _add_modules(checkout, AWS, SLACK)
    if mutation == "missing":
        del report["files"][SLACK]
    elif mutation == "unexpected":
        report["files"]["shadowscan/connectors/cloud/removed.py"] = _summary(10, 10)
    else:
        _add_modules(checkout, "shadowscan/connectors/cloud/new.py")
    assert _gate(checkout, report, add_modules=False) == 2
    err = capsys.readouterr().err
    assert "invalid coverage report: connector module inventory mismatch" in err
    assert {"missing": SLACK, "unexpected": "removed.py", "new_source": "new.py"}[mutation] in err


@pytest.mark.parametrize(
    "report",
    [
        # Statement-only data would let a module pass on lines alone.
        _report({BASE: _summary(10, 10)}, branch=False),
        # A report that measured no connector module cannot vouch for any.
        _report({"shadowscan/engine.py": _summary(10, 10)}),
        _report({"shadowscan/connectors/cloud/__init__.py": _summary(0, 0)}),
        {"files": {}},
        {"meta": {"branch_coverage": True}},
        _report({BASE: {"summary": {"num_statements": 10}}}),
        [],
    ],
    ids=[
        "statements-only",
        "no-connectors",
        "only-empty-modules",
        "no-meta",
        "no-files",
        "no-branch-counts",
        "list",
    ],
)
def test_reports_that_cannot_prove_connector_coverage_fail_closed(checkout, capsys, report):
    assert _gate(checkout, report) == 2
    assert "invalid coverage report:" in capsys.readouterr().err


@pytest.mark.parametrize("field", ["num_statements", "covered_lines", "num_branches", "covered_branches"])
@pytest.mark.parametrize("value", [-1, True, 1.5, "10", None], ids=repr)
def test_invalid_counts_fail_closed(checkout, capsys, field, value):
    report = _report({AWS: _summary(10, 10, 4, 4)})
    report["files"][AWS]["summary"][field] = value
    assert _gate(checkout, report) == 2
    assert f"{field} must be a nonnegative integer" in capsys.readouterr().err


@pytest.mark.parametrize("entry", [_summary(10, 11), _summary(10, 10, 4, 5)], ids=["lines", "branches"])
def test_covered_counts_above_the_totals_fail_closed(checkout, capsys, entry):
    assert _gate(checkout, _report({AWS: entry})) == 2
    assert "covered counts exceed the totals" in capsys.readouterr().err


@pytest.mark.parametrize("entry", [None, [], {}, {"summary": []}, {"summary": {}}])
def test_invalid_entries_fail_closed(checkout, entry):
    assert _gate(checkout, _report({AWS: entry})) == 2


@pytest.mark.parametrize(
    "text",
    ["not JSON", "[]", "{}", '{"files": []}', '{"files": {}, "files": {}}', '{"files": 1e9999}', "{"],
)
def test_malformed_report_text_fails_without_a_traceback(checkout, capsys, text):
    path = checkout / "coverage.json"
    path.write_text(text, encoding="utf-8")
    assert main([str(path)]) == 2
    assert "invalid coverage report:" in capsys.readouterr().err


def test_unreadable_reports_and_bad_usage_fail_closed(tmp_path):
    assert main([str(tmp_path / "missing.json")]) == 2
    assert main([]) == 2
    assert main(["one.json", "two.json"]) == 2


def test_command_line_entry_point_reports_failure(tmp_path):
    # The real inventory, every module a quarter covered.
    report = _report({module: _summary(4, 1) for module in connector_modules(ROOT)})
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "tools.coverage_gate", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"{BASE}: 25.00% < 75%" in result.stderr
