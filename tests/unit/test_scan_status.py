from __future__ import annotations

import json
import sys
from io import StringIO

import pytest
from click.testing import CliRunner
from rich.console import Console

from shadowscan.cli import _exit_code, main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters.sarif import render_sarif
from shadowscan.reporters.table import print_table


def test_incomplete_scan_fails_gate_and_sarif():
    result = ScanResult(
        stats=[
            ScanStats(connector="test", started_at="2026-01-01T00:00:00Z", errors=["cannot enumerate scope"])
        ]
    )
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
    result = CliRunner().invoke(
        main, ["code", str(tmp_path), "--format", "sarif", "-o", str(output), "--fail-on", "high"]
    )
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
    result = ScanResult(
        findings=[
            Finding(
                surface=Surface.CODE,
                connector="code.filesystem",
                kind=Kind.AGENT,
                title="Retained agent finding",
                resource="repo",
                resource_type="project",
            )
        ],
        stats=[
            ScanStats(
                connector="code.filesystem[/not-open]",
                started_at="2026-01-01T00:00:00Z",
                errors=[diagnostic],
                warnings=[diagnostic],
                incomplete=True,
            )
        ],
    )
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
            remote_secret = ctx.get("access_token", env="TEST_SHADOWSCAN_SECRET")
            raise RuntimeError(f"upstream rejected {ctx.require('client_secret')} and {remote_secret}")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: BadConstructor)
    cfg = ScanConfig(connectors=[ConnectorSpec("identity.entra", {"client_secret": configured})], parallel=1)
    result = Engine(cfg, index).run()
    output = json.dumps(result.to_dict()) + render_sarif(result) + caplog.text
    assert configured not in output and environment not in output
    assert result.stats[0].errors and result.stats[0].skipped
    assert not result.complete and _exit_code(result, None) == 3


@pytest.mark.parametrize(
    "selectors",
    [
        ["code.filesystem", "cloud.awz"],
        ["cloud.awz"],
        ["code.filesystem", "disabled-cloud"],
        ["disabled-cloud"],
        ["code.filesystem", "cloud.aws"],
    ],
)
def test_every_explicit_selector_must_resolve_to_enabled_connector(monkeypatch, index, selectors):
    def unexpected_lookup(*args, **kwargs):
        pytest.fail("invalid selections must fail before any connector runs")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", unexpected_lookup)
    config = ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem"),
            ConnectorSpec("cloud.aws", enabled=False, label="disabled-cloud"),
        ]
    )
    result = Engine(config, index).run(only=selectors)
    assert not result.complete and not result.findings and _exit_code(result, "high") == 3
    assert result.stats[0].connector == "engine.selection"
    assert "unknown or disabled connector selector" in result.stats[0].errors[0]
    assert result.collection_scope["comparable"] is False


def test_valid_names_and_labels_include_every_matching_enabled_instance(tmp_path, index):
    (tmp_path / "requirements.txt").write_text("langchain\n")
    specs = [
        ConnectorSpec("code.filesystem", {"path": str(tmp_path)}, label=label)
        for label in ("first", "second")
    ]
    specs.append(ConnectorSpec("cloud.aws", enabled=False))
    result = Engine(ScanConfig(connectors=specs), index).run(only=["code.filesystem", "first"])
    assert result.complete and {stat.connector for stat in result.stats} == {"first", "second"}


def test_mixed_selector_typo_fails_cli_gate(tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text(f"connectors:\n  - name: code.filesystem\n    path: {tmp_path}\n")
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "-c",
            str(config),
            "--only",
            "code.filesystem",
            "--only",
            "cloud.awz",
            "--format",
            "json",
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 3, result.output
    assert json.loads(result.stdout)["summary"]["complete"] is False


class _Abort(BaseException):
    """A non-Exception BaseException, as some asynchronous frameworks raise."""


def _raise(exc: BaseException):
    def call():
        raise exc

    return call


# A worker's SystemExit used to reach the main thread and end the scan with
# the plugin's exit status and no report: sys.exit(0) read as a clean pass.
WORKER_EXITS = {
    "sys-exit-0": (lambda: sys.exit(0), "SystemExit"),
    "sys-exit-7": (lambda: sys.exit(7), "SystemExit"),
    "raise-system-exit": (_raise(SystemExit()), "SystemExit"),
    "base-exception": (_raise(_Abort()), "_Abort"),
}


def _exiting_connector(exit_call):
    class ExitingConnector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            exit_call()

    return ExitingConnector


def _entra_config() -> ScanConfig:
    return ScanConfig(connectors=[ConnectorSpec("identity.entra", {"input": "unused.json"})], parallel=1)


@pytest.mark.parametrize(("exit_call", "raised"), WORKER_EXITS.values(), ids=list(WORKER_EXITS))
def test_connector_exit_is_an_incomplete_connector_not_a_clean_scan(monkeypatch, index, exit_call, raised):
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: _exiting_connector(exit_call))
    result = Engine(_entra_config(), index).run()
    [stats] = result.stats
    assert stats.incomplete and stats.skipped
    assert stats.errors[0].startswith(f"identity.entra: {raised}")
    assert not result.complete and _exit_code(result, None) == 3


@pytest.mark.parametrize(("exit_call", "raised"), WORKER_EXITS.values(), ids=list(WORKER_EXITS))
def test_exit_while_loading_a_plugin_is_an_incomplete_connector(monkeypatch, index, exit_call, raised):
    def lookup(*args, **kwargs):
        exit_call()

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lookup)
    result = Engine(_entra_config(), index).run()
    assert result.stats[0].errors == [f"identity.entra: connector worker failed ({raised})"]
    assert result.stats[0].skipped
    assert not result.complete and _exit_code(result, None) == 3


def test_cli_scan_with_exiting_connector_writes_report_and_exits_3(monkeypatch, tmp_path):
    exiting = _exiting_connector(lambda: sys.exit(0))
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: exiting)
    result = CliRunner().invoke(main, ["code", str(tmp_path), "-f", "json"])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert report["stats"][0]["errors"][0].startswith("code.filesystem: SystemExit")


def test_keyboard_interrupt_in_a_worker_still_stops_the_scan(monkeypatch, index):
    interrupting = _exiting_connector(_raise(KeyboardInterrupt()))
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda _: interrupting)
    with pytest.raises(KeyboardInterrupt):
        Engine(_entra_config(), index).run()
