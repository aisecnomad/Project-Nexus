"""Imported reports must preserve confidentiality and attest completion."""

from __future__ import annotations

import copy
import json
import math
import os

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports, load_report
from shadowscan.models import Finding, Kind, Risk, RiskLevel, ScanResult, ScanStats, Surface


def _report(*resources: str) -> dict:
    return ScanResult(
        findings=[Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
                          title=resource, resource=resource, resource_type="repository")
                  for resource in resources],
        stats=[ScanStats(connector="code.filesystem", started_at="2026-09-24")],
        collection_scope={"schema": "shadowscan.collection-scope/v1", "comparable": True,
                          "fingerprint": "a" * 64},
    ).to_dict()


@pytest.mark.parametrize("relation", ["new", "resolved", "unknown", "changed"])
def test_comparison_sanitizes_all_published_records_without_mutating_inputs(relation):
    before, after = _report("repo"), _report("repo")
    if relation == "new":
        before["findings"] = []
    elif relation in {"resolved", "unknown"}:
        after["findings"] = []
    if relation == "unknown":
        after["summary"]["complete"] = False
    if relation == "changed":
        after["findings"][0]["permissions"] = ["write"]
    secret = "opaque-synthetic-credential-value"
    provider_key = "sk-proj-syntheticcredentialvaluenotarealkey"
    for report in (before, after):
        for finding in report["findings"]:
            # Simulate an older/externally produced report that bypassed the
            # current model's export-time sanitization.
            finding["metadata"]["api_key"] = secret
            finding["title"] = f"Agent {secret}"
            finding["evidence"] = [{"signal": "observed", "description": f"copy {secret}",
                                    "location": f"https://example.com?token={provider_key}"}]
            finding["untrusted_extension"] = "must-not-publish-arbitrary-columns"
    original = copy.deepcopy((before, after))
    result = compare_reports(before, after)
    output = json.dumps(result)
    assert secret not in output and provider_key not in output
    assert "must-not-publish-arbitrary-columns" not in output
    assert "[REDACTED]" in output
    assert result[relation]
    assert (before, after) == original


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_diff_never_echoes_credentials_from_imported_findings(tmp_path, as_json):
    before, after = _report(), _report("repo")
    finding = after["findings"][0]
    finding["metadata"]["password"] = "opaque-cli-secret-value"
    finding["title"] = "Agent opaque-cli-secret-value"
    files = [tmp_path / "before.json", tmp_path / "after.json"]
    for path, report in zip(files, (before, after), strict=True):
        path.write_text(json.dumps(report))
    args = ["diff", *map(str, files), *(["--json"] if as_json else [])]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert "opaque-cli-secret-value" not in result.output
    assert "[REDACTED]" in result.output


@pytest.mark.parametrize("field", ["errors", "skipped", "incomplete"])
@pytest.mark.parametrize("value", [None, 0, "", {}])
def test_falsey_malformed_completion_values_cannot_resolve(field, value):
    before, after = _report("missing"), _report()
    after["stats"][0][field] = value
    result = compare_reports(before, after)
    assert not result["comparable"] and not result["resolved"]
    assert len(result["unknown"]) == 1


@pytest.mark.parametrize("field", ["errors", "skipped", "incomplete"])
@pytest.mark.parametrize("side", ["baseline", "current"])
def test_absent_completion_fields_cannot_resolve(field, side):
    before, after = _report("missing"), _report()
    (before if side == "baseline" else after)["stats"][0].pop(field)
    result = compare_reports(before, after)
    assert not result["comparable"] and not result["resolved"]
    assert len(result["unknown"]) == 1


@pytest.mark.parametrize("other_connector", ["cloud.aws", "code.filesystem"])
def test_matching_scope_hash_does_not_hide_lost_connector_statistics(other_connector):
    before, after = _report("missing"), _report()
    extra = copy.deepcopy(before["stats"][0])
    extra["connector"] = other_connector
    before["stats"].append(extra)
    result = compare_reports(before, after)
    assert not result["comparable"] and not result["resolved"]
    assert len(result["unknown"]) == 1
    assert "connector completion coverage differs" in result["reasons"]


def test_unchanged_imported_record_is_validated_before_comparison_succeeds():
    before, after = _report("repo"), _report("repo")
    before["findings"][0]["evidence"] = "malformed-private-content"
    with pytest.raises(ValueError, match="cannot be safely exported"):
        compare_reports(before, after)


@pytest.mark.parametrize("secret", ["opaque-evidence-only-secret", "s"])
def test_import_discovers_child_evidence_credentials_before_sanitizing_sibling_fields(secret):
    before, after = _report(), _report()
    # This identity has no 's' outside its protected generated id and schema.
    finding = Finding(surface=Surface.CODE, connector="code", kind=Kind.AGENT,
                      title="Agent", resource="repo", resource_type="repo").to_dict()
    finding["title"] = secret
    finding["metadata"] = {"copy": secret}
    finding["evidence"] = [{"signal": "observed", "description": "safe",
                            "attributes": {"api_key": secret}}]
    original = copy.deepcopy(finding)
    after["findings"] = [finding]
    result = compare_reports(before, after)["new"][0]
    assert result["title"] == "[REDACTED]"
    assert result["metadata"]["copy"] == "[REDACTED]"
    assert result["evidence"][0]["attributes"]["api_key"] == "[REDACTED]"
    assert result["id"] == original["id"]
    assert result["identity_schema"] == original["identity_schema"]
    assert finding == original
    # Inventory imports and direct library consumers share this boundary.
    imported = Finding.from_dict(finding).to_dict()
    assert imported["title"] == imported["metadata"]["copy"] == "[REDACTED]"


# Imported-report boundaries.
def _scored_report() -> dict:
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title="Agent", resource="repo/agent", resource_type="repository",
        risk=Risk(score=55, level=RiskLevel.HIGH),
    )
    return ScanResult(
        findings=[finding], stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01")],
        collection_scope={"schema": "shadowscan.collection-scope/v1", "comparable": True, "fingerprint": "a" * 64},
    ).to_dict()


@pytest.mark.parametrize("command", ["diff", "stubs"])
def test_report_commands_reject_symlink_inputs(tmp_path, command):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(_scored_report()))
    link = tmp_path / "linked-report.json"
    link.symlink_to(source)
    args = (["diff", str(source), str(link), "--json"] if command == "diff" else
            ["inventory", "stubs", str(link), "-o", str(tmp_path / "stubs")])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1
    assert "Error:" in result.output and "Traceback" not in result.output


def test_stubs_validate_every_finding_before_creating_any_files(tmp_path):
    report = _scored_report()
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
    before, after = _scored_report(), _scored_report()
    after["findings"][0]["risk"]["score"] = score
    if relation == "new":
        before["findings"] = []
    elif relation == "missing":
        before, after = after, before
        after["findings"] = []
    with pytest.raises(ValueError, match="risk"):
        compare_reports(before, after)


def test_comparison_validates_security_attributes_of_missing_findings():
    before, after = _scored_report(), _scored_report()
    before["findings"][0]["permissions"] = "admin"
    after["findings"] = []
    with pytest.raises(ValueError, match="attributes"):
        compare_reports(before, after)


@pytest.mark.parametrize("command", ["diff", "stubs"])
def test_report_commands_reject_duplicate_json_keys(tmp_path, command):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(_scored_report())[:-1] + ', "findings": []}')
    args = (["diff", str(source), str(source), "--json"] if command == "diff" else
            ["inventory", "stubs", str(source), "-o", str(tmp_path / "stubs")])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1
    assert "Error:" in result.output


def test_valid_comparison_does_not_mutate_reports():
    before, after = _scored_report(), _scored_report()
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
    (directory / "report.json").write_text(json.dumps(_scored_report()))
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
