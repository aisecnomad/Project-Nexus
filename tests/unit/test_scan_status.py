from __future__ import annotations

import json
from io import StringIO

from click.testing import CliRunner
from rich.console import Console

from shadowscan.cli import _exit_code, main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters.sarif import render_sarif
from shadowscan.reporters.table import print_table


def test_incomplete_scan_fails_gate_and_sarif():
    result = ScanResult(stats=[ScanStats(connector="test", started_at="2026-01-01T00:00:00Z", errors=["cannot enumerate scope"])])
    assert _exit_code(result, None) == 3
    assert _exit_code(result, "high") == 3
    invocation = json.loads(render_sarif(result))["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"


def test_empty_selection_is_not_a_clean_scan(tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text("connectors: []\n")
    result = CliRunner().invoke(main, ["scan", "-c", str(config), "--format", "json"])
    assert result.exit_code == 3
    assert json.loads(result.stdout)["summary"]["complete"] is False


def test_malformed_file_preserves_valid_findings_but_fails_scan(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": [1]}')
    (tmp_path / "agent.py").write_text("from langchain.agents import create_react_agent\n")
    output = tmp_path / "scan.sarif"
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "sarif", "-o", str(output), "--fail-on", "high"])
    assert result.exit_code == 3, result.output
    report = json.loads(output.read_text())
    assert report["runs"][0]["results"]
    assert report["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_incremental_cli_replays_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import openai\n")
    state = tmp_path / "private-state"
    args = ["code", str(repo), "--incremental", "--state-dir", str(state), "--format", "json"]
    first = CliRunner().invoke(main, args)
    second = CliRunner().invoke(main, args)
    assert first.exit_code == second.exit_code == 0, (first.output, second.output)
    a, b = json.loads(first.stdout), json.loads(second.stdout)
    assert a["findings"] == b["findings"]
    assert a["stats"][0]["cached"] is False
    assert b["stats"][0]["cached"] is True


def test_hostile_diagnostic_markup_cannot_hide_retained_findings():
    diagnostic = "invalid file: [/not-open].json"
    result = ScanResult(findings=[Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title="Retained agent finding", resource="repo", resource_type="project",
    )], stats=[ScanStats(
        connector="code.filesystem[/not-open]", started_at="2026-01-01T00:00:00Z",
        errors=[diagnostic], warnings=[diagnostic], incomplete=True,
    )])
    stream = StringIO()
    print_table(result, Console(file=stream, force_terminal=False, width=160))
    output = stream.getvalue()
    assert "Retained agent finding" in output
    assert "INCOMPLETE SCAN" in output
    assert output.count(diagnostic) == 2
    assert "code.filesystem[/not-open]" in output
    assert _exit_code(result, "high") == 3


def test_constructor_errors_redact_configured_and_environment_credentials(monkeypatch, index, caplog):
    configured = "opaque-configured-synthetic-credential-123"
    environment = "opaque-environment-synthetic-credential-456"
    monkeypatch.setenv("TEST_SHADOWSCAN_SECRET", environment)

    class BadConstructor:
        def __init__(self, ctx):
            remote_secret = ctx.get("client_secret", env="TEST_SHADOWSCAN_SECRET")
            raise RuntimeError(f"upstream rejected {ctx.require('api_key')} and {remote_secret}")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: BadConstructor)
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"api_key": configured})], parallel=1)
    result = Engine(cfg, index).run()
    output = json.dumps(result.to_dict()) + render_sarif(result) + caplog.text
    assert configured not in output and environment not in output
    assert result.stats[0].errors and result.stats[0].skipped
    assert not result.complete and _exit_code(result, None) == 3
