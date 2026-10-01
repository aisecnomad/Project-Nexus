"""A connector raising SystemExit or another BaseException is a connector failure, not a process exit."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

import shadowscan.engine as engine_module
from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanStats, Surface, now_iso
from shadowscan.signatures import SignatureIndex

SECRET = "sk-proj-" + "b" * 40


class _Hard(BaseException):
    """Neither Exception nor KeyboardInterrupt: what a careless SDK may raise."""


def _connector(raiser):
    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            label = self.ctx.config["label"]
            if label == "bad":
                raiser()
            self.ctx.stats = ScanStats(
                connector="code.filesystem", started_at=now_iso(), finished_at=now_iso()
            )
            return [Finding(Surface.CODE, "code.filesystem", Kind.AGENT, label, label, "repository")]

    return Connector


def _config(parallel: int = 1) -> ScanConfig:
    return ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem", label="good"),
            ConnectorSpec("code.filesystem", label="bad"),
        ],
        parallel=parallel,
    )


def _exit_zero():
    raise SystemExit(0)


def _exit_text():
    raise SystemExit(f"fatal: Authorization: Bearer {SECRET}")


def _exit_none():
    raise SystemExit


def _hard():
    raise _Hard(f"token={SECRET}")


@pytest.mark.parametrize("parallel", [1, 2])
@pytest.mark.parametrize("raiser", [_exit_zero, _exit_text, _exit_none, _hard])
def test_connector_baseexception_marks_scan_incomplete_and_keeps_siblings(monkeypatch, raiser, parallel):
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(raiser))

    result = Engine(_config(parallel), SignatureIndex([])).run()

    assert not result.complete
    assert [finding.title for finding in result.findings] == ["good"]
    failed = [st for st in result.stats if st.errors]
    assert len(failed) == 1 and failed[0].incomplete
    assert SECRET not in json.dumps([st.errors for st in result.stats])


@pytest.mark.parametrize("raiser", [_exit_zero, _hard])
def test_cli_reports_exit_3_with_a_report_when_a_connector_exits(monkeypatch, tmp_path, raiser):
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(raiser))
    config = tmp_path / "scan.yaml"
    config.write_text(
        "connectors:\n"
        "  - name: code.filesystem\n    label: good\n"
        "  - name: code.filesystem\n    label: bad\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", "json", "-o", str(out)])

    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output and SECRET not in result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is False
    assert [finding["title"] for finding in report["findings"]] == ["good"]


def test_keyboard_interrupt_still_aborts_the_scan(monkeypatch):
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(interrupt))
    with pytest.raises(KeyboardInterrupt):
        Engine(_config(), SignatureIndex([])).run()


def test_engine_gives_http_clients_the_connector_deadline_and_cancellation(monkeypatch):
    from shadowscan.utils.http import HttpClient

    seen = {}

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            client = HttpClient()
            seen["deadline"], seen["cancelled"] = client.deadline, client.cancelled
            self.ctx.stats = ScanStats(
                connector="code.filesystem", started_at=now_iso(), finished_at=now_iso()
            )
            return []

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: Connector)

    Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", label="x")]), SignatureIndex([])).run()

    assert seen["deadline"] is not None and seen["cancelled"] is not None
    # The worker context is reset afterwards: clients made outside a connector have no limits.
    assert HttpClient().deadline is None and HttpClient().cancelled is None
