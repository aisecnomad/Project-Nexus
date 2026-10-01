"""Gateway finding IDs are scan-local unless the operator supplies a stable key.

``gateway.logs`` derives caller, scope and source pseudonyms from an HMAC key
that is random for each scan, so separate runs cannot be linked. A report
marks such findings with ``metadata.identity_scope``; ``diff`` must not call
them new, resolved or unknown merely because their IDs changed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface

ROWS = [
    {"api_key": "opaque-gateway-key-1", "model": "gpt-4o", "user_agent": "langchain/0.3"},
    {"service": "svc-ops", "tenant_id": "tenant-a", "model": "gpt-4o"},
    {"user": "alice@example.com", "model": "claude-3-5-sonnet", "prompt_tokens": 12},
]


@pytest.fixture(autouse=True)
def _per_run_keys(monkeypatch):
    monkeypatch.delenv("SHADOWSCAN_IDENTITY_KEY", raising=False)


def _gateway_scan(tmp_path: Path, index) -> dict:
    export = tmp_path / "gateway.jsonl"
    export.write_text(
        "".join(json.dumps({**row, "timestamp": "2026-09-22T10:00:00Z"}) + "\n" for row in ROWS)
    )
    config = ScanConfig(connectors=[ConnectorSpec("gateway.logs", {"input": str(export)}, label="gw")])
    result = Engine(config, index).run()
    assert result.complete
    return result.to_dict()


def _finding(resource: str, **metadata) -> dict:
    return Finding(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        title=f"LLM caller '{resource}'",
        resource=resource,
        resource_type="caller/service",
        metadata=metadata,
    ).to_dict()


def _report(*findings: dict) -> dict:
    report = ScanResult(
        stats=[ScanStats(connector="gateway.logs", started_at="2026-09-22")],
        collection_scope={
            "schema": "shadowscan.collection-scope/v1",
            "comparable": True,
            "fingerprint": "a" * 64,
        },
    ).to_dict()
    report["findings"] = list(findings)
    return report


def test_identical_gateway_runs_report_no_new_or_missing_findings(tmp_path, index):
    before, after = _gateway_scan(tmp_path, index), _gateway_scan(tmp_path, index)
    assert len(before["findings"]) == len(after["findings"]) == len(ROWS)
    # Per-run keys: the same callers carry different IDs in each report.
    assert not {f["id"] for f in before["findings"]} & {f["id"] for f in after["findings"]}
    comparison = compare_reports(before, after)
    assert comparison["new"] == comparison["resolved"] == comparison["unknown"] == comparison["changed"] == []
    assert all(f["metadata"]["identity_scope"] == "run" for f in before["findings"] + after["findings"])
    assert [f["id"] for f in comparison["not_comparable"]["baseline"]] == sorted(
        f["id"] for f in before["findings"]
    )
    assert [f["id"] for f in comparison["not_comparable"]["current"]] == sorted(
        f["id"] for f in after["findings"]
    )
    assert not comparison["comparable"]
    assert any("scan-local" in reason for reason in comparison["reasons"])


def test_scan_local_findings_never_resolve_even_under_a_matching_scope():
    comparison = compare_reports(
        _report(_finding("service:a", identity_scope="run"), _finding("service:kept")),
        _report(_finding("service:b", identity_scope="run"), _finding("service:kept")),
    )
    assert comparison["new"] == comparison["resolved"] == comparison["unknown"] == []
    assert [f["resource"] for f in comparison["not_comparable"]["baseline"]] == ["service:a"]
    assert [f["resource"] for f in comparison["not_comparable"]["current"]] == ["service:b"]
    assert comparison["reasons"] == [
        "2 finding(s) have scan-local identities (metadata.identity_scope) and cannot be matched across "
        "scans; set SHADOWSCAN_IDENTITY_KEY for both scans to compare gateway callers"
    ]


@pytest.mark.parametrize("scope", ["future-scope", "", 7, None])
def test_any_declared_identity_scope_this_version_cannot_match_is_scan_local(scope):
    comparison = compare_reports(_report(_finding("service:a", identity_scope=scope)), _report())
    assert comparison["resolved"] == comparison["unknown"] == []
    assert len(comparison["not_comparable"]["baseline"]) == 1 and not comparison["comparable"]


def test_same_scan_local_identity_in_both_reports_is_compared_normally():
    before = _finding("service:a", identity_scope="run")
    after = json.loads(json.dumps(before))
    after["permissions"] = ["Mail.Read"]
    comparison = compare_reports(_report(before), _report(after))
    assert comparison["comparable"] and comparison["not_comparable"] == {"baseline": [], "current": []}
    assert comparison["changed"][0]["changed_fields"] == ["permissions"]


@pytest.mark.parametrize("metadata", [{}, {"identity_scope": "keyed"}], ids=["undeclared", "keyed"])
def test_stable_identities_keep_their_comparison_semantics(metadata):
    comparison = compare_reports(
        _report(_finding("service:gone", **metadata)), _report(_finding("service:new", **metadata))
    )
    assert comparison["comparable"] and comparison["not_comparable"] == {"baseline": [], "current": []}
    assert [f["resource"] for f in comparison["resolved"]] == ["service:gone"]
    assert [f["resource"] for f in comparison["new"]] == ["service:new"]


def test_not_comparable_records_pass_the_export_boundary():
    secret = "opaque-not-comparable-secret"
    finding = _finding("service:a", identity_scope="run")
    finding["metadata"]["password"] = secret
    finding["untrusted_extension"] = "must-not-publish"
    output = json.dumps(compare_reports(_report(finding), _report()))
    assert secret not in output and "must-not-publish" not in output and "[REDACTED]" in output


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_diff_of_identical_gateway_runs_lists_not_comparable_findings(tmp_path, index, as_json):
    paths = []
    for name in ("before.json", "after.json"):
        path = tmp_path / name
        path.write_text(json.dumps(_gateway_scan(tmp_path, index)))
        paths.append(str(path))
    result = CliRunner().invoke(main, ["diff", *paths, *(["--json"] if as_json else [])])
    assert result.exit_code == 3, result.output
    if as_json:
        output = json.loads(result.output)
        assert output["new"] == [] and output["unknown"] == []
        assert (
            len(output["not_comparable"]["baseline"]) == len(output["not_comparable"]["current"]) == len(ROWS)
        )
    else:
        assert "0 new, 0 resolved, 0 unknown, 0 changed, 6 not comparable" in result.output
        assert "scan-local identities" in result.output
        lines = result.output.splitlines()
        assert sum(line.startswith("  < ") for line in lines) == len(ROWS)
        assert sum(line.startswith("  > ") for line in lines) == len(ROWS)
