"""Whole CLI invocation deadlines must terminate blocked work and be cancellable."""

from __future__ import annotations

import subprocess
import sys
import threading
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from shadowscan.cli import _run_and_emit, main
from shadowscan.config import ScanConfig
from shadowscan.utils.deadline import arm_job_deadline


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), -float("inf"), True, "invalid"])
def test_job_deadline_rejects_invalid_config(value):
    with pytest.raises(ValueError, match="job_deadline_seconds"):
        ScanConfig(job_deadline_seconds=value)
    with pytest.raises(ValueError, match="job_deadline_seconds"):
        ScanConfig.from_dict({"options": {"job_deadline_seconds": value}})


def test_cli_retains_yaml_deadline_and_applies_explicit_override(tmp_path, monkeypatch):
    configs = []
    monkeypatch.setattr("shadowscan.cli._run_and_emit", lambda cfg, *args, **kwargs: configs.append(cfg))
    path = tmp_path / "scan.yaml"
    path.write_text("options:\n  job_deadline_seconds: 60\nconnectors: []\n")
    runner = CliRunner()
    assert runner.invoke(main, ["scan", "--config", str(path)]).exit_code == 0
    assert configs[-1].job_deadline_seconds == 60
    assert runner.invoke(main, ["scan", "--config", str(path), "--job-deadline-seconds", "2.5"]).exit_code == 0
    assert configs[-1].job_deadline_seconds == 2.5
    assert ScanConfig().job_deadline_seconds is None


@pytest.mark.parametrize("command", ["code", "run", "scan", "gateway", "jwt"])
def test_deadline_is_available_to_each_scan_command(command):
    result = CliRunner().invoke(main, [command, "--help"])
    assert result.exit_code == 0
    assert "--job-deadline-seconds" in result.output


def test_cli_rejects_nonfinite_deadline():
    result = CliRunner().invoke(main, ["code", ".", "--job-deadline-seconds", "nan"])
    assert result.exit_code == 2
    assert "positive finite number" in result.output


@pytest.mark.parametrize("error", [None, SystemExit(0), ValueError("setup failure")])
def test_cli_cancels_watchdog_after_completion_or_failure(monkeypatch, error):
    watchdog = Mock()
    monkeypatch.setattr("shadowscan.cli.arm_job_deadline", Mock(return_value=watchdog))
    monkeypatch.setattr("shadowscan.cli._run_and_emit_with_deadline", Mock(side_effect=error))
    cfg = ScanConfig(job_deadline_seconds=1)
    if error is None:
        _run_and_emit(cfg, "json", None, 0, None)
    else:
        with pytest.raises(type(error)):
            _run_and_emit(cfg, "json", None, 0, None)
    watchdog.cancel.assert_called_once_with()


def test_disarmed_watchdog_cannot_kill_a_reused_process():
    exit_callback = Mock()
    watchdog = arm_job_deadline(60, _exit=exit_callback)
    watchdog.cancel()
    watchdog.thread.join(timeout=2)
    assert not watchdog.thread.is_alive()
    exit_callback.assert_not_called()


def test_jwt_reuses_watchdog_armed_before_stdin(monkeypatch):
    watchdog = Mock()
    arm = Mock(return_value=watchdog)
    monkeypatch.setattr("shadowscan.cli.arm_job_deadline", arm)
    monkeypatch.setattr("shadowscan.cli._run_and_emit_with_deadline", Mock(side_effect=SystemExit(0)))
    result = CliRunner().invoke(main, ["jwt", "eyJhbGciOiJub25lIn0.e30.", "--job-deadline-seconds", "1"])
    assert result.exit_code == 0, result.output
    arm.assert_called_once_with(1.0)
    watchdog.cancel.assert_called_once_with()


def test_cli_deadline_cancels_when_command_preflight_fails(monkeypatch):
    watchdog = Mock()
    arm = Mock(return_value=watchdog)
    monkeypatch.setattr("shadowscan.cli.arm_job_deadline", arm)
    result = CliRunner().invoke(main, ["run", "no.such.connector", "--job-deadline-seconds", "1"])
    assert result.exit_code == 2
    arm.assert_called_once_with(1.0)
    watchdog.cancel.assert_called_once_with()


@pytest.mark.parametrize("args", [
    ["run", "--job-deadline-seconds", "1"],
    ["code", ".", "--job-deadline-seconds", "1", "--connector-timeout-seconds", "-3"],
])
def test_cli_deadline_cancels_when_subcommand_parsing_fails(monkeypatch, args):
    watchdog = Mock()
    arm = Mock(return_value=watchdog)
    monkeypatch.setattr("shadowscan.cli.arm_job_deadline", arm)
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    arm.assert_called_once_with(1.0)
    watchdog.cancel.assert_called_once_with()


def test_locked_stderr_cannot_block_watchdog_exit(monkeypatch):
    release = threading.Event()
    exited = threading.Event()
    stderr = Mock(write=lambda text: release.wait(5))
    monkeypatch.setattr(sys, "stderr", stderr)
    watchdog = arm_job_deadline(0.01, _exit=lambda code: exited.set())
    try:
        assert exited.wait(2)
        watchdog.thread.join(timeout=2)
        assert not watchdog.thread.is_alive()
    finally:
        release.set()
        watchdog.cancel()


@pytest.mark.parametrize("stage", ["setup", "output"])
def test_cli_deadline_exits_process_with_blocked_setup_or_output(tmp_path, stage):
    marker = tmp_path / "blocked"
    script = """
import sys, time
from pathlib import Path
from types import SimpleNamespace
import shadowscan.cli as cli
from shadowscan.models import ScanResult
def block(*args, **kwargs):
    Path(sys.argv[2]).write_text('blocked')
    time.sleep(60)
if sys.argv[1] == 'setup':
    cli._plugin_registry_problems = block
else:
    cli._plugin_registry_problems = lambda: ()
    cli.Engine = lambda *a, **k: SimpleNamespace(run=lambda **kw: ScanResult(), abandoned_workers=[])
    cli._emit = block
cli.main(['code', '.', '--job-deadline-seconds', '0.2'])
"""
    result = subprocess.run(
        [sys.executable, "-c", script, stage, str(marker)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert marker.read_text() == "blocked"
    assert result.returncode == 3, result.stderr


def test_cli_deadline_exits_with_jwt_stdin_held_open():
    process = subprocess.Popen(
        [sys.executable, "-m", "shadowscan", "jwt", "--job-deadline-seconds", "0.2"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        # Keep stdin open and silent; before the fix, token collection waited
        # for EOF indefinitely and the watchdog was never armed.
        assert process.wait(timeout=8) == 3
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=3)


def test_cli_deadline_exits_with_blocked_connector_discovery(tmp_path):
    marker = tmp_path / "discovering"
    script = """
import sys, time
from pathlib import Path
import shadowscan.cli as cli
def block():
    Path(sys.argv[1]).write_text('discovering')
    time.sleep(60)
cli.available_connectors = block
cli.main(['run', 'code.filesystem', '--job-deadline-seconds', '0.2'])
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(marker)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert marker.read_text() == "discovering"
    assert result.returncode == 3, result.stderr
