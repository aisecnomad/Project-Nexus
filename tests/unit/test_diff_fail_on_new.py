"""`shadowscan diff --fail-on-new` gates on regressions; the default stays informational."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface

_SCORES = {"critical": 90, "high": 55, "medium": 35, "low": 15, "info": 3}


def _finding(resource: str, level: str = "high") -> dict:
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=resource,
        resource=resource,
        resource_type="repository",
    ).to_dict()
    finding["risk"] = {"level": level, "score": _SCORES[level], "factors": []}
    return finding


def _report(*findings: dict, complete: bool = True) -> dict:
    report = ScanResult(
        stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01", incomplete=not complete)],
        collection_scope={
            "schema": "shadowscan.collection-scope/v1",
            "comparable": True,
            "fingerprint": "a" * 64,
        },
    ).to_dict()
    report["findings"] = list(findings)
    # Keep the summary describing the injected records, as a real report's does.
    report["summary"].update(
        total=len(findings),
        by_surface=dict(Counter(finding["surface"] for finding in findings)),
        by_kind=dict(Counter(finding["kind"] for finding in findings)),
    )
    return report


def _diff(tmp_path: Path, baseline: dict, current: dict, *extra: str):
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text(json.dumps(baseline))
    after.write_text(json.dumps(current))
    return CliRunner().invoke(main, ["diff", str(before), str(after), *extra])


def test_diff_with_new_findings_exits_zero_by_default(tmp_path):
    result = _diff(tmp_path, _report(), _report(_finding("new")))
    assert result.exit_code == 0, result.output
    assert "1 new" in result.output


def test_fail_on_new_exits_2_when_a_finding_is_new(tmp_path):
    result = _diff(tmp_path, _report(), _report(_finding("new")), "--fail-on-new")
    assert result.exit_code == 2, result.output
    assert "1 new" in result.output  # the comparison is still printed


def test_fail_on_new_exits_2_with_json_output(tmp_path):
    result = _diff(tmp_path, _report(), _report(_finding("new")), "--fail-on-new", "--json")
    assert result.exit_code == 2, result.output
    assert len(json.loads(result.output)["new"]) == 1


@pytest.mark.parametrize(
    ("before_level", "after_level", "expected"),
    [("low", "high", 2), ("medium", "critical", 2), ("high", "low", 0), ("high", "high", 0)],
)
def test_fail_on_new_gates_on_higher_severity_changes_only(tmp_path, before_level, after_level, expected):
    baseline = _report(_finding("same", before_level))
    current = _report(_finding("same", after_level))
    if before_level == after_level:
        # A change that keeps the severity level (here: score) is not a regression.
        current["findings"][0]["risk"]["score"] += 1
    result = _diff(tmp_path, baseline, current, "--fail-on-new")
    assert result.exit_code == expected, result.output


def test_fail_on_new_ignores_resolved_findings(tmp_path):
    result = _diff(tmp_path, _report(_finding("gone")), _report(), "--fail-on-new")
    assert result.exit_code == 0, result.output
    assert "1 resolved" in result.output


def test_incomplete_comparison_still_exits_3_with_fail_on_new(tmp_path):
    result = _diff(tmp_path, _report(), _report(_finding("new"), complete=False), "--fail-on-new")
    assert result.exit_code == 3, result.output


def test_fail_on_new_is_documented_in_help():
    result = CliRunner().invoke(main, ["diff", "--help"])
    assert result.exit_code == 0
    assert "--fail-on-new" in result.output and "exit 2" in " ".join(result.output.split())


def test_shadow_only_filters_display_but_not_exit_codes(tmp_path):
    """--shadow-only is a view: counts, reasons and gating cover every finding."""
    registered = _finding("registered-bot")
    registered["shadow"] = False
    shadow = _finding("shadow-agent")
    shadow["shadow"] = True
    result = _diff(tmp_path, _report(), _report(registered, shadow), "--shadow-only")
    assert result.exit_code == 0, result.output
    assert "shadow-agent" in result.output
    assert "registered-bot" not in result.output
    assert "2 new" in result.output  # counts stay unfiltered
    gated = _diff(tmp_path, _report(), _report(registered, shadow), "--shadow-only", "--fail-on-new")
    assert gated.exit_code == 2  # the non-shadow new finding still gates
    as_json = _diff(tmp_path, _report(), _report(registered, shadow), "--shadow-only", "--json")
    assert as_json.exit_code == 0
    doc = json.loads(as_json.output)
    assert len(doc["new"]) == 2  # the full comparison is always present
    assert doc["shadow_only_view"]["new"] == [shadow["id"]]
