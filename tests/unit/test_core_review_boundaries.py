"""Regression tests for configuration location and imported-report boundaries."""

from __future__ import annotations

import copy
import json
import math
import os

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports, load_report
from shadowscan.config import ScanConfig
from shadowscan.models import Finding, Kind, Risk, RiskLevel, ScanResult, ScanStats, Surface


def _report() -> dict:
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title="Agent", resource="repo/agent", resource_type="repository",
        risk=Risk(score=55, level=RiskLevel.HIGH),
    )
    return ScanResult(
        findings=[finding], stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01")],
        collection_scope={"schema": "shadowscan.collection-scope/v1", "comparable": True, "fingerprint": "a" * 64},
    ).to_dict()


def test_config_relative_globs_and_workdir_use_configuration_directory(tmp_path):
    directory = tmp_path / "deployment"
    directory.mkdir()
    config = directory / "scan.yaml"
    config.write_text("inventory: [inventory/*.yaml]\noptions:\n  workdir: working\n")
    loaded = ScanConfig.from_yaml(config)
    assert loaded.inventory == [str(directory / "inventory" / "*.yaml")]
    assert loaded.workdir == str(directory / "working")


@pytest.mark.parametrize("command", ["diff", "stubs"])
def test_report_commands_reject_symlink_inputs(tmp_path, command):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(_report()))
    link = tmp_path / "linked-report.json"
    link.symlink_to(source)
    args = (["diff", str(source), str(link), "--json"] if command == "diff" else
            ["inventory", "stubs", str(link), "-o", str(tmp_path / "stubs")])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1
    assert "Error:" in result.output and "Traceback" not in result.output


def test_stubs_validate_every_finding_before_creating_any_files(tmp_path):
    report = _report()
    report["findings"].append({"surface": "invalid-surface", "private": "do-not-echo-this"})
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report))
    destination = tmp_path / "stubs"
    result = CliRunner().invoke(main, ["inventory", "stubs", str(source), "-o", str(destination)])
    assert result.exit_code == 1
    assert "could not read a ShadowScan JSON report" in result.output
    assert "do-not-echo-this" not in result.output
    assert not destination.exists()


@pytest.mark.parametrize("score", [True, math.nan, math.inf, -1, 101])
@pytest.mark.parametrize("relation", ["new", "missing", "shared"])
def test_comparison_rejects_invalid_risk_scores_in_all_findings(score, relation):
    before, after = _report(), _report()
    after["findings"][0]["risk"]["score"] = score
    if relation == "new":
        before["findings"] = []
    elif relation == "missing":
        before, after = after, before
        after["findings"] = []
    with pytest.raises(ValueError, match="risk"):
        compare_reports(before, after)


def test_comparison_validates_security_attributes_of_missing_findings():
    before, after = _report(), _report()
    before["findings"][0]["permissions"] = "admin"
    after["findings"] = []
    with pytest.raises(ValueError, match="attributes"):
        compare_reports(before, after)


@pytest.mark.parametrize("command", ["diff", "stubs"])
def test_report_commands_reject_duplicate_json_keys(tmp_path, command):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(_report())[:-1] + ', "findings": []}')
    args = (["diff", str(source), str(source), "--json"] if command == "diff" else
            ["inventory", "stubs", str(source), "-o", str(tmp_path / "stubs")])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1
    assert "Error:" in result.output


def test_valid_comparison_does_not_mutate_reports():
    before, after = _report(), _report()
    original = copy.deepcopy((before, after))
    comparison = compare_reports(before, after)
    assert comparison["comparable"] and not comparison["changed"]
    assert (before, after) == original


@pytest.mark.parametrize("command", ["diff", "stubs"])
def test_report_commands_reject_oversized_input_before_reading(tmp_path, monkeypatch, command):
    import shadowscan.comparison as comparison

    monkeypatch.setattr(comparison, "MAX_REPORT_BYTES", 4096)
    source = tmp_path / "report.json"
    with source.open("wb") as stream:
        stream.truncate(4097)
    args = (["diff", str(source), str(source)] if command == "diff" else
            ["inventory", "stubs", str(source), "-o", str(tmp_path / "stubs")])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1 and "Error:" in result.output


def test_report_reader_rejects_fifo_without_waiting_for_writer(tmp_path):
    source = tmp_path / "report.json"
    os.mkfifo(source)
    with pytest.raises(ValueError, match="regular file"):
        load_report(source)


def test_report_reader_rejects_parent_symlinks(tmp_path):
    directory = tmp_path / "reports"
    directory.mkdir()
    (directory / "report.json").write_text(json.dumps(_report()))
    link = tmp_path / "linked-reports"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OSError):
        load_report(link / "report.json")


@pytest.mark.parametrize("command", ["diff", "stubs"])
def test_report_commands_report_excessive_nesting_safely(tmp_path, command):
    source = tmp_path / "report.json"
    source.write_text('{' + '"nested":[' + '[' * 1500 + '0' + ']' * 1501 + '}')
    args = (["diff", str(source), str(source)] if command == "diff" else
            ["inventory", "stubs", str(source), "-o", str(tmp_path / "stubs")])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1 and "Error:" in result.output
