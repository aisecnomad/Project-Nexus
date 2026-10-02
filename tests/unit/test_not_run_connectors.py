"""Reports record connectors that were disabled or left out by --only, without changing completeness."""

from __future__ import annotations

import json

from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.signatures import SignatureIndex


def _config(tmp_path) -> ScanConfig:
    (tmp_path / "requirements.txt").write_text("langchain\n")
    return ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem", {"path": str(tmp_path)}, label="repo"),
            ConnectorSpec("cloud.aws", enabled=False, label="disabled-cloud"),
            ConnectorSpec("code.filesystem", {"path": str(tmp_path)}, label="other"),
        ]
    )


def test_disabled_and_unselected_connectors_are_recorded_but_scan_stays_complete(tmp_path):
    result = Engine(_config(tmp_path), SignatureIndex([])).run(only=["repo"])

    assert result.complete
    assert result.collection_scope is not None
    assert result.collection_scope["not_run"] == [
        {"connector": "disabled-cloud", "reason": "disabled"},
        {"connector": "other", "reason": "not selected by --only"},
    ]
    assert [stat.connector for stat in result.stats] == ["repo"]


def test_nothing_is_recorded_when_every_configured_connector_ran(tmp_path):
    config = _config(tmp_path)
    config.connectors.pop(1)

    result = Engine(config, SignatureIndex([])).run()

    assert result.complete and result.collection_scope is not None
    assert "not_run" not in result.collection_scope


def test_not_run_list_does_not_change_comparability(tmp_path):
    config = _config(tmp_path)
    narrowed = Engine(config, SignatureIndex([])).run(only=["repo"]).to_dict()
    again = Engine(config, SignatureIndex([])).run(only=["repo"]).to_dict()

    assert narrowed["collection_scope"]["comparable"] is True
    assert narrowed["collection_scope"]["fingerprint"] == again["collection_scope"]["fingerprint"]
    assert compare_reports(narrowed, again)["comparable"] is True


def test_json_report_carries_the_not_run_list(tmp_path):
    cfg = tmp_path / "scan.yaml"
    (tmp_path / "requirements.txt").write_text("langchain\n")
    cfg.write_text(
        f"connectors:\n  - name: code.filesystem\n    path: {tmp_path}\n"
        "  - name: cloud.aws\n    enabled: false\n"
    )
    out = tmp_path / "report.json"

    result = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-f", "json", "-o", str(out)])

    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is True
    assert report["collection_scope"]["not_run"] == [{"connector": "cloud.aws", "reason": "disabled"}]
