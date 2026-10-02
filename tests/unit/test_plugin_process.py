"""Real spawned-plugin regressions: import, completion, forced exit and IPC boundaries."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from dataclasses import asdict

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import ScanStats
from shadowscan.plugin_process import _decode_result, _encode_result, _receive
from shadowscan.signatures import SignatureIndex

ENTRY = "platform.process-probe"
MODULE = "shadowscan_process_probe"

PLUGIN = """
import os
import signal
import time
from pathlib import Path
from shadowscan.connectors.base import BaseConnector
from shadowscan.models import Finding, Kind, Surface

mode = os.environ.get("SHADOWSCAN_PROCESS_PROBE", "ok")
Path(os.environ["SHADOWSCAN_PROCESS_PID"]).write_text(str(os.getpid()))

def hang():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)

if mode == "import-hang":
    hang()
if mode == "oversized":
    import shadowscan.plugin_process as transport
    transport._encode_result = lambda data: b"x" * (transport.MAX_RESULT_BYTES + 1)
if mode == "malformed":
    import shadowscan.plugin_process as transport
    transport._encode_result = lambda data: b'{"stats": "untrusted"}'

class Connector(BaseConnector):
    name = "platform.process-probe"
    surface = Surface.LOWCODE
    description = "spawned-process test connector"
    config_keys = {}

    def collect(self):
        if self.ctx.config.get("mode", mode) == "hang":
            hang()
        if mode == "crash":
            os._exit(7)
        return [{"pid": os.getpid()}]

    def analyze(self, records):
        for record in records:
            yield Finding(
                surface=self.surface, connector=self.name, kind=Kind.AGENT,
                title="process probe", resource="probe", resource_type="test",
                metadata={"pid": record["pid"]},
            )
"""


@pytest.fixture
def installed_probe(tmp_path, monkeypatch):
    (tmp_path / f"{MODULE}.py").write_text(PLUGIN, encoding="utf-8")
    distribution = tmp_path / "shadowscan_process_probe-1.0.dist-info"
    distribution.mkdir()
    (distribution / "METADATA").write_text("Name: shadowscan-process-probe\nVersion: 1.0\n")
    (distribution / "entry_points.txt").write_text(f"[shadowscan.connectors]\n{ENTRY} = {MODULE}:Connector\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    marker = tmp_path / "pid.txt"
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PID", str(marker))
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "ok")
    return marker


def _engine(**options):
    return Engine(
        ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY], plugin_execution="process", **options),
        SignatureIndex([]),
    )


def _assert_reaped(marker):
    pid = int(marker.read_text())
    assert pid != os.getpid()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_spawned_plugin_result_and_export_without_parent_import(installed_probe, tmp_path):
    directory = tmp_path / "exports"
    engine = _engine(dump_records=str(directory))
    result = engine.run()
    assert result.complete, result.stats
    assert result.findings[0].metadata["pid"] != os.getpid()
    assert MODULE not in sys.modules
    assert engine.abandoned_workers == []
    _assert_reaped(installed_probe)
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["complete"] and manifest["exports"][0]["exported"]
    assert engine.run().complete


@pytest.mark.parametrize("mode", ["hang", "import-hang"])
def test_timeout_kills_sigterm_ignoring_plugin_and_preserves_worker_capacity(
    installed_probe, monkeypatch, mode, tmp_path
):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", mode)
    directory = tmp_path / "exports"
    engine = _engine(connector_timeout_seconds=2, dump_records=str(directory), parallel=1)
    start = time.monotonic()
    result = engine.run()
    assert time.monotonic() - start < 6
    assert not result.complete and result.findings == []
    assert "connector_timeout" in result.stats[0].errors[0]
    assert engine.abandoned_workers == []
    assert MODULE not in sys.modules
    _assert_reaped(installed_probe)
    manifest = json.loads((directory / "manifest.json").read_text())
    assert not manifest["complete"]
    assert manifest["exports"] == [
        {
            "config_ordinal": 1,
            "part": "0001",
            "connector": ENTRY,
            "label": None,
            "filename": None,
            "complete": False,
            "exported": False,
        }
    ]
    # Unlike an abandoned thread, a terminated plugin permits safe reuse.
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "ok")
    assert engine.run().complete


def test_terminated_plugin_releases_capacity_for_queued_sibling(installed_probe):
    engine = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(ENTRY, {"mode": "hang"}, label="slow"),
                ConnectorSpec(ENTRY, {"mode": "ok"}, label="queued"),
            ],
            plugins=[ENTRY],
            plugin_execution="process",
            parallel=1,
            connector_timeout_seconds=2,
        ),
        SignatureIndex([]),
    )
    result = engine.run()
    assert not result.complete
    stats = {item.connector: item for item in result.stats}
    assert stats["slow"].incomplete and not stats["queued"].incomplete
    assert len(result.findings) == 1
    assert engine.abandoned_workers == []
    _assert_reaped(installed_probe)


@pytest.mark.parametrize("mode", ["crash", "oversized", "malformed"])
def test_child_crash_or_bad_wire_result_fails_closed(installed_probe, monkeypatch, mode):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", mode)
    result = _engine().run()
    assert not result.complete and result.findings == []
    assert result.stats[0].incomplete and result.stats[0].errors
    assert MODULE not in sys.modules
    _assert_reaped(installed_probe)


def test_plugin_allowlist_still_required_without_parent_import(installed_probe):
    engine = Engine(
        ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugin_execution="process"), SignatureIndex([])
    )
    result = engine.run()
    assert not result.complete and result.findings == []
    assert not installed_probe.exists()
    assert MODULE not in sys.modules


def test_process_resource_failure_is_incomplete(installed_probe, monkeypatch):
    import shadowscan.plugin_process as transport

    def exhausted():
        raise OSError("sensitive resource diagnostic")

    monkeypatch.setattr(transport.socket, "socketpair", exhausted)
    result = _engine().run()
    assert not result.complete and result.findings == []
    assert "setup or supervision failed" in result.stats[0].errors[0]
    assert "sensitive" not in str(result.stats)


def test_partial_ipc_is_deadline_bounded():
    parent, child = socket.socketpair()
    try:
        child.sendall(b'{"partial":')
        with pytest.raises(TimeoutError):
            _receive(parent, time.monotonic() + 0.05)
    finally:
        parent.close()
        child.close()


def test_result_encoder_enforces_limit(monkeypatch):
    import shadowscan.plugin_process as transport

    monkeypatch.setattr(transport, "MAX_RESULT_BYTES", 16)
    with pytest.raises(ValueError, match="transport limit"):
        _encode_result({"result": "x" * 20})


@pytest.mark.parametrize(
    "field,value",
    [
        ("incomplete", "false"),
        ("findings", True),
        ("objects_examined", -1),
        ("errors", [42]),
        ("warnings", "ok"),
        ("started_at", []),
        ("skip_reason", {}),
    ],
)
def test_result_stats_schema_is_not_trusted(field, value):
    stats = asdict(ScanStats(ENTRY, "now"))
    stats[field] = value
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    with pytest.raises(ValueError):
        _decode_result(payload, 1, ConnectorSpec(ENTRY))


@pytest.mark.parametrize("value", [None, True, 1, [], "fork", "Process", ""])
def test_execution_backend_configuration_rejects_invalid_values(value):
    with pytest.raises(ConfigValidationError, match="plugin_execution"):
        ScanConfig.from_dict({"options": {"plugin_execution": value}})


def test_execution_backend_defaults_and_mutation_validation():
    assert ScanConfig().plugin_execution == "thread"
    config = ScanConfig.from_dict({"options": {"plugin_execution": "process"}})
    engine = Engine(config, SignatureIndex([]))
    config.plugin_execution = "fork"
    with pytest.raises(ConfigValidationError, match="plugin_execution"):
        engine.run()


def test_plugin_execution_cli_option():
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0 and "--plugin-execution" in result.output
