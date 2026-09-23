from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import build_collection_scope, compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface


def _finding(resource: str, level: str = "high") -> dict:
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title=resource, resource=resource, resource_type="repository",
    ).to_dict()
    finding["risk"] = {"level": level, "score": 55 if level == "high" else 15, "factors": []}
    return finding


def _report(*findings: dict, complete: bool = True) -> dict:
    report = ScanResult(
        stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01", incomplete=not complete)],
        collection_scope={"schema": "shadowscan.collection-scope/v1", "comparable": True, "fingerprint": "a" * 64},
    ).to_dict()
    report["findings"] = list(findings)
    return report


def _invoke(tmp_path: Path, baseline: dict, current: dict, *extra: str):
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text(json.dumps(baseline))
    after.write_text(json.dumps(current))
    return CliRunner().invoke(main, ["diff", str(before), str(after), *extra])


def test_completed_comparable_report_can_resolve(tmp_path):
    result = _invoke(tmp_path, _report(_finding("agent")), _report(), "--json")
    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["comparable"] is True
    assert len(output["resolved"]) == 1
    assert output["unknown"] == []


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_incomplete_report_never_resolves_but_preserves_observations(tmp_path, side):
    before = _report(_finding("missing"), _finding("changed"))
    after = _report(_finding("new"), _finding("changed", "low"))
    report = before if side == "baseline" else after
    report["summary"]["complete"] = False
    report["stats"][0]["errors"] = ["access denied"]
    result = _invoke(tmp_path, before, after, "--json")
    assert result.exit_code == 3, result.output
    output = json.loads(result.output)
    assert output["resolved"] == []
    assert [finding["resource"] for finding in output["unknown"]] == ["missing"]
    assert [finding["resource"] for finding in output["new"]] == ["new"]
    assert output["changed"][0]["after"]["risk"]["level"] == "low"


@pytest.mark.parametrize("mutation", ["scope", "legacy", "bad_version", "stats_error", "no_stats"])
def test_unavailable_or_changed_scope_is_unknown(tmp_path, mutation):
    before, after = _report(_finding("agent")), _report()
    if mutation == "scope":
        after["collection_scope"]["fingerprint"] = "b" * 64
    elif mutation == "legacy":
        after.pop("collection_scope")
    elif mutation == "bad_version":
        after["collection_scope"]["schema"] = "future/v2"
    elif mutation == "stats_error":
        after["stats"][0]["errors"] = ["hidden failure despite summary"]
    else:
        after["stats"] = []
    result = _invoke(tmp_path, before, after)
    assert result.exit_code == 3, result.output
    assert "0 resolved" in result.output and "1 unknown" in result.output


def test_scope_mismatch_is_nonzero_even_without_missing_findings(tmp_path):
    before, after = _report(), _report(_finding("new"))
    after["collection_scope"]["fingerprint"] = "b" * 64
    assert _invoke(tmp_path, before, after, "--json").exit_code == 3


def test_malformed_comparison_returns_safe_cli_error(tmp_path):
    result = _invoke(tmp_path, {"findings": "private-value"}, _report())
    assert result.exit_code == 1
    assert "invalid comparison input" in result.output
    assert "private-value" not in result.output and "Traceback" not in result.output


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        compare_reports(_report(_finding("same"), _finding("same")), _report())


def test_static_scope_tracks_detection_settings_not_content(tmp_path, index):
    source = tmp_path / "records.json"
    source.write_text("[]")
    spec = ConnectorSpec("cloud.aws", {"input": str(source), "token": "private-value"})
    config = ScanConfig(connectors=[spec])
    original = build_collection_scope(config, index, [spec])
    assert original["comparable"] is True
    assert "private-value" not in json.dumps(original)
    source.write_text('[{"name": "changed-content"}]')
    config.inventory = [str(tmp_path / "different-inventory.yaml")]
    assert build_collection_scope(config, index, [spec]) == original
    config.min_confidence = 0.9
    assert build_collection_scope(config, index, [spec]) != original
    config.min_confidence = 0
    spec.config["token"] = "different-value"
    assert build_collection_scope(config, index, [spec]) != original


def test_scope_selection_order_paths_and_signature_changes(tmp_path, index):
    a = ConnectorSpec("cloud.aws", {"input": str(tmp_path / "a.json")}, label="a")
    b = ConnectorSpec("cloud.aws", {"input": str(tmp_path / "b.json")}, label="b")
    config = ScanConfig(connectors=[a, b])
    original = build_collection_scope(config, index, [a, b])
    assert build_collection_scope(config, index, [b, a]) == original
    assert build_collection_scope(config, index, [a]) != original
    moved = copy.deepcopy(a)
    moved.config["input"] = str(tmp_path / "c.json")
    assert build_collection_scope(config, index, [moved, b]) != original
    class NewIndex:
        def fingerprint(self):
            return "different signatures"
    assert build_collection_scope(config, NewIndex(), [a, b]) != original


def test_live_scope_is_explicitly_unavailable(index):
    spec = ConnectorSpec("cloud.aws", {"regions": ["us-east-1"]})
    scope = build_collection_scope(ScanConfig(connectors=[spec]), index, [spec])
    assert scope["comparable"] is False
    assert "fingerprint" not in scope


def test_engine_publishes_selected_scope_and_real_removal_resolves(tmp_path, index):
    source = tmp_path / "repo"
    source.mkdir()
    manifest = source / "requirements.txt"
    manifest.write_text("langchain==0.3.0\n")
    specs = [ConnectorSpec("code.filesystem", {"path": str(source)}), ConnectorSpec("cloud.aws")]
    config = ScanConfig(connectors=specs)
    before = Engine(config, index=index).run(only=["code.filesystem"]).to_dict()
    manifest.unlink()
    after = Engine(config, index=index).run(only=["code.filesystem"]).to_dict()
    assert before["collection_scope"]["comparable"] is True
    comparison = compare_reports(before, after)
    assert comparison["comparable"] is True and comparison["resolved"]


def test_invalid_config_does_not_echo_secret_yaml(tmp_path):
    config = tmp_path / "invalid.yaml"
    config.write_text("connectors: [ private-api-token\n")
    result = CliRunner().invoke(main, ["scan", "-c", str(config)])
    assert result.exit_code == 1 and "invalid scan configuration" in result.output
    assert "private-api-token" not in result.output and "Traceback" not in result.output


def test_invalid_set_does_not_echo_credentials():
    result = CliRunner().invoke(main, ["run", "cloud.aws", "--set", "private-api-token"])
    assert result.exit_code == 2
    assert "private-api-token" not in result.output


def test_invalid_inventory_safe_error_on_check_and_scan(tmp_path):
    inventory = tmp_path / "invalid.yaml"
    inventory.write_text("agents:\n  - agent_id: example\n    resources: private-api-token\n")
    for args in (["inventory", "check", str(inventory)], ["code", str(tmp_path), "-i", str(inventory)]):
        result = CliRunner().invoke(main, args)
        assert result.exit_code == 1
        assert "resources" in result.output
        assert "private-api-token" not in result.output and "Traceback" not in result.output
