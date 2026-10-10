"""Real spawned-plugin regressions: import, completion, forced exit and IPC boundaries."""

from __future__ import annotations

import json
import multiprocessing
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import shadowscan
from shadowscan import engine as engine_module
from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import DERIVED_METADATA_KEYS, ScanStats
from shadowscan.plugin_process import _decode_result, _encode_result, _receive, _worker, _WorkerHandle
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
        if mode == "nondaemon-thread":
            # For example an SDK helper still waiting when collection returns.
            import threading
            threading.Thread(target=threading.Event().wait, daemon=False).start()
        if mode == "background-helper":
            # A helper program that keeps every inheritable descriptor open.
            import subprocess
            import sys
            helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], close_fds=False)
            Path(os.environ["SHADOWSCAN_PROCESS_PID"] + ".helper").write_text(str(helper.pid))
        return [{"pid": os.getpid()}]

    def analyze(self, records):
        for record in records:
            metadata = {"pid": record["pid"]}
            if mode == "metadata-types":
                import datetime
                metadata.update(seen=datetime.datetime(2026, 1, 1), scopes={"read"}, raw=b"ab")
            yield Finding(
                surface=self.surface, connector=self.name, kind=Kind.AGENT,
                title="process probe", resource="probe", resource_type="test",
                metadata=metadata,
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


# A spawned plugin re-imports the scanner and unpickles the signature index
# before it runs; on a loaded macOS runner that start-up alone can pass several
# seconds. The deadline leaves it room and the wall-clock bound scales with it.
TIMEOUT_SECONDS = 10


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


def _plugin_pid(marker, limit=30.0):
    """Wait (bounded) until the plugin has been imported in its worker."""
    end = time.monotonic() + limit
    while time.monotonic() < end:
        try:
            return int(marker.read_text())
        except (OSError, ValueError):
            time.sleep(0.05)
    raise AssertionError("plugin worker did not start")


def _exited(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:
        # An orphan that init has not reaped yet is a zombie: it no longer runs.
        with open(f"/proc/{pid}/stat") as status:
            return status.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return False


def _wait_exited(pid, limit):
    end = time.monotonic() + limit
    while not _exited(pid):
        if time.monotonic() >= end:
            return False
        time.sleep(0.05)
    return True


def _kill_leftover(pid):
    if not _exited(pid):
        os.kill(pid, signal.SIGKILL)


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


def test_worker_exports_only_into_the_prepared_private_directory(installed_probe, tmp_path, monkeypatch):
    """The child must not re-derive the export directory from raw configuration."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # A literal "~" survives `--dump-records=~/exports` and embedding callers.
    # In this working directory "./~" is a symlink the parent never validated.
    work = tmp_path / "work"
    (work / "elsewhere" / "exports").mkdir(parents=True)
    (work / "~").symlink_to(work / "elsewhere", target_is_directory=True)
    monkeypatch.chdir(work)
    result = _engine(dump_records="~/exports").run()
    assert result.complete, result.stats
    directory = home / "exports"
    manifest = json.loads((directory / "manifest.json").read_text())
    [entry] = manifest["exports"]
    assert entry["exported"] and (directory / entry["filename"]).is_file()
    assert list((work / "elsewhere" / "exports").iterdir()) == []


@pytest.mark.parametrize("mode", ["hang", "import-hang"])
def test_timeout_kills_sigterm_ignoring_plugin_and_preserves_worker_capacity(
    installed_probe, monkeypatch, mode, tmp_path
):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", mode)
    directory = tmp_path / "exports"
    engine = _engine(connector_timeout_seconds=TIMEOUT_SECONDS, dump_records=str(directory), parallel=1)
    start = time.monotonic()
    result = engine.run()
    assert time.monotonic() - start < TIMEOUT_SECONDS * 3
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


def test_lingering_non_daemon_thread_cannot_hold_result_hostage(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "nondaemon-thread")
    start = time.monotonic()
    result = _engine(connector_timeout_seconds=8).run()
    assert result.complete, result.stats
    assert len(result.findings) == 1
    assert time.monotonic() - start < 8
    _assert_reaped(installed_probe)


def test_helper_program_started_by_the_plugin_cannot_hold_the_result(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "background-helper")
    start = time.monotonic()
    try:
        result = _engine(connector_timeout_seconds=TIMEOUT_SECONDS).run()
        assert result.complete, result.stats
        assert len(result.findings) == 1
        assert time.monotonic() - start < TIMEOUT_SECONDS
        _assert_reaped(installed_probe)
    finally:
        helper = Path(str(installed_probe) + ".helper")
        if helper.exists():
            _kill_leftover(int(helper.read_text()))


def test_very_large_connector_timeout_still_runs_process_plugins(installed_probe):
    # Waits of more than about 24.8 days overflow; they are taken in slices.
    result = _engine(connector_timeout_seconds=3e6).run()
    assert result.complete, result.stats
    assert len(result.findings) == 1
    _assert_reaped(installed_probe)


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
            connector_timeout_seconds=TIMEOUT_SECONDS,
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


# Run as `python -c`: spawn then has no main module to re-import in the worker.
_DYING_SCANNER = """
import os, sys, threading, time
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.signatures import SignatureIndex

marker, entry = sys.argv[1:]

def exit_without_cleanup():
    while True:
        try:
            int(open(marker).read())
            break
        except (OSError, ValueError):
            time.sleep(0.05)
    os._exit(0)  # like the job-deadline watchdog or SIGKILL: no finally/atexit

threading.Thread(target=exit_without_cleanup, daemon=True).start()
config = ScanConfig(
    connectors=[ConnectorSpec(entry)], plugins=[entry], plugin_execution="process",
    connector_timeout_seconds=120,
)
Engine(config, SignatureIndex([])).run()
"""


def test_worker_exits_when_scanner_process_dies(installed_probe, monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "hang")
    checkout = Path(shadowscan.__file__).resolve().parents[1]
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join([str(tmp_path), str(checkout)])}
    command = [sys.executable, "-c", _DYING_SCANNER, str(installed_probe), ENTRY]
    subprocess.run(command, env=environment, timeout=60, check=True)
    pid = _plugin_pid(installed_probe)
    try:
        # The connector deadline is 120 s: only parent-death detection can stop it.
        assert _wait_exited(pid, 10), "orphaned plugin worker kept running"
    finally:
        _kill_leftover(pid)


def test_interrupted_collection_kills_worker_promptly(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "hang")

    def interrupted(self):
        _plugin_pid(installed_probe)
        raise KeyboardInterrupt

    monkeypatch.setattr(engine_module._Supervisor, "run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _engine(connector_timeout_seconds=120).run()
    pid = _plugin_pid(installed_probe)
    try:
        assert _wait_exited(pid, 10), "interrupted scan left its plugin worker running"
    finally:
        _kill_leftover(pid)


def test_worker_enforces_its_own_deadline_without_parent_supervision(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "hang")
    parent, child = socket.socketpair()
    config = ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY])
    # Leave time for spawn start-up and plugin import before the deadline.
    deadline = time.monotonic() + 4
    process = multiprocessing.get_context("spawn").Process(
        target=_worker, args=(child, config, [], 1, deadline, b"k" * 32, None), daemon=True
    )
    try:
        process.start()
        child.close()
        _plugin_pid(installed_probe)
        assert time.monotonic() < deadline, "worker started too late to reach the plugin"
        # The parent neither reads nor kills: the worker must stop by itself
        # shortly after its deadline (two seconds of cleanup grace, plus slack).
        process.join(deadline + 12 - time.monotonic())
        assert process.exitcode == 1
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)
        parent.close()
        child.close()


def test_non_json_metadata_round_trips_like_thread_mode(installed_probe, monkeypatch):
    """Transport serialization matches the JSON report for datetime, set and bytes metadata."""
    from shadowscan import connectors as registry

    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "metadata-types")
    reported = {}
    try:
        for backend in ("thread", "process"):
            config = ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY], plugin_execution=backend)
            result = Engine(config, SignatureIndex([])).run()
            assert result.complete, (backend, result.stats)
            [finding] = json.loads(result.to_json())["findings"]
            finding["metadata"].pop("pid")
            reported[backend] = finding["metadata"]
    finally:
        # The thread backend imported the probe here; keep later tests honest.
        sys.modules.pop(MODULE, None)
        registry._cache.pop(ENTRY, None)
    assert reported["process"] == reported["thread"]
    # The engine derives the autonomy block after collection, for either backend alike.
    assert reported["thread"].pop("autonomy")["schema"] == "shadowscan.autonomy/v1"
    # Threat and control references are derived from the finding at export,
    # not carried by the plugin (tests/unit/test_mappings.py covers them).
    connector_metadata = {k: v for k, v in reported["thread"].items() if k not in DERIVED_METADATA_KEYS}
    # The report renders a datetime as text and reads a set as a list and
    # bytes as text; the transport must not change that rendering.
    assert connector_metadata == {"seen": "2026-01-01 00:00:00", "scopes": ["read"], "raw": "ab"}


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
        child.sendall((100).to_bytes(8, "big") + b'{"partial":')
        with pytest.raises(TimeoutError):
            _receive(parent, time.monotonic() + 0.05)
    finally:
        parent.close()
        child.close()


def test_declared_length_ends_the_result_while_the_channel_stays_open():
    parent, child = socket.socketpair()
    try:
        payload = b'{"findings":[]}'
        child.sendall(len(payload).to_bytes(8, "big") + payload)
        start = time.monotonic()
        assert _receive(parent, time.monotonic() + 5) == payload
        assert time.monotonic() - start < 1
    finally:
        parent.close()
        child.close()


@pytest.mark.parametrize("declared,sent", [(100, b'{"truncated":'), (17 * 1024 * 1024, b"")])
def test_truncated_or_oversized_declared_result_fails_closed(declared, sent):
    parent, child = socket.socketpair()
    try:
        child.sendall(declared.to_bytes(8, "big") + sent)
        child.close()
        with pytest.raises(ValueError):
            _receive(parent, time.monotonic() + 5)
    finally:
        parent.close()


class _ClosingProcess:
    """Mimics Process.close(): the handle is cleared before the object is marked closed."""

    pid = 4242

    def __init__(self):
        self._popen = SimpleNamespace(poll=lambda: 0)
        self._closed = False
        self.closing = threading.Event()

    def is_alive(self):
        if self._closed:
            raise ValueError("process object is closed")
        return self._popen.poll() is None

    def close(self):
        self._popen = None
        self.closing.set()
        time.sleep(0.2)
        self._closed = True


def test_kill_during_worker_cleanup_waits_instead_of_failing_the_scan():
    process = _ClosingProcess()
    handle = _WorkerHandle(process)
    failures = []

    def kill_when_closing():
        process.closing.wait(5)
        try:
            handle.kill()
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion below
            failures.append(exc)

    killer = threading.Thread(target=kill_when_closing)
    killer.start()
    handle.stop()
    killer.join(5)
    assert not killer.is_alive() and failures == []


def test_result_encoder_enforces_limit(monkeypatch):
    import shadowscan.plugin_process as transport

    monkeypatch.setattr(transport, "MAX_RESULT_BYTES", 16)
    with pytest.raises(ValueError, match="transport limit"):
        _encode_result({"result": "x" * 20})


def test_result_encoder_still_rejects_nan():
    with pytest.raises(ValueError):
        _encode_result({"findings": [{"confidence": float("nan")}]})


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
