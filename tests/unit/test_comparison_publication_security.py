"""Imported reports must preserve confidentiality and attest completion."""

from __future__ import annotations

import copy
import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface


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
