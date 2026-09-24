"""A timed-out worker cannot publish scan artifacts after cancellation."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from shadowscan import cli as cli_module
from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.engine import Engine
from shadowscan.incremental import IncrementalCache, Snapshot
from shadowscan.models import ScanResult, ScanStats, now_iso
from shadowscan.signatures import SignatureIndex


class _Records(BaseConnector):
    def collect(self):
        return []

    def analyze(self, records):
        return []


def test_cancelled_connector_cannot_publish_record_export(tmp_path):
    lock = threading.Lock()
    cancelled = threading.Event()
    source_drained = threading.Event()
    ctx = ConnectorContext(index=SignatureIndex([]), cancelled=cancelled, publication_lock=lock)
    target = tmp_path / "records.jsonl"
    errors = []

    def records():
        yield {"id": "one"}
        source_drained.set()

    def worker():
        try:
            list(_Records(ctx)._tee(records(), str(target)))
        except ConnectorError as exc:
            errors.append(exc)

    with lock:
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        assert source_drained.wait(3)
        cancelled.set()  # the engine makes this decision under the same lock
    thread.join(3)
    assert not thread.is_alive()
    assert len(errors) == 1
    assert not target.exists()
    assert not list(tmp_path.glob(".records.jsonl.*"))


@pytest.mark.skipif(__import__("os").name != "posix", reason="incremental state requires POSIX flock")
def test_cancelled_connector_cannot_publish_incremental_cache(tmp_path):
    lock = threading.Lock()
    cancelled = threading.Event()
    about_to_publish = threading.Event()
    ctx = ConnectorContext(index=SignatureIndex([]), cancelled=cancelled, publication_lock=lock)
    cache = IncrementalCache(ScanConfig(incremental=True, state_dir=str(tmp_path / "state")), SignatureIndex([]))
    snapshot = Snapshot("a" * 64, "b" * 64)
    errors = []

    def publish(source: str | Path, target: str | Path):
        about_to_publish.set()
        ctx.publish_replace(source, target)

    def worker():
        try:
            cache.save(snapshot, [], ScanStats(connector="test", started_at=now_iso()),
                       check_deadline=ctx.check_deadline, publish_replace=publish)
        except ConnectorError as exc:
            errors.append(exc)

    with lock:
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        assert about_to_publish.wait(3)
        cancelled.set()
    thread.join(3)
    assert not thread.is_alive()
    assert len(errors) == 1
    assert not (cache.directory / f"{snapshot.slot}.json").exists()
    assert not list(cache.directory.glob(".pending-*"))


def test_publication_finishes_before_cancellation_can_take_the_lock(tmp_path, monkeypatch):
    from shadowscan.connectors import base

    lock = threading.Lock()
    cancelled = threading.Event()
    in_replace = threading.Event()
    release_replace = threading.Event()
    cancel_started = threading.Event()
    ctx = ConnectorContext(index=SignatureIndex([]), cancelled=cancelled, publication_lock=lock)
    source, target = tmp_path / "pending", tmp_path / "report"
    source.write_text("sanitized")
    original_replace = base.os.replace

    def slow_replace(src, dst):
        assert not cancelled.is_set()
        in_replace.set()
        assert release_replace.wait(3)
        original_replace(src, dst)

    def cancel():
        cancel_started.set()
        with lock:
            cancelled.set()

    monkeypatch.setattr(base.os, "replace", slow_replace)
    publishing = threading.Thread(target=ctx.publish_replace, args=(source, target), daemon=True)
    publishing.start()
    assert in_replace.wait(3)
    cancelling = threading.Thread(target=cancel, daemon=True)
    cancelling.start()
    assert cancel_started.wait(3)
    assert not cancelled.is_set()
    release_replace.set()
    publishing.join(3)
    cancelling.join(3)
    assert not publishing.is_alive() and not cancelling.is_alive()
    assert target.read_text() == "sanitized" and cancelled.is_set()


def test_engine_timeout_returns_while_record_replacement_is_blocked(tmp_path, monkeypatch):
    from shadowscan.connectors import base

    replacing = threading.Event()
    release_replace = threading.Event()
    returned = threading.Event()
    worker_finished = threading.Event()
    target_paths = []
    original_replace = base.os.replace

    class ExportConnector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            target = Path(self.ctx.config["_dump_path"])
            pending = target.with_suffix(".pending")
            pending.write_text('sanitized export\n')
            try:
                self.ctx.publish_replace(pending, target)
            finally:
                worker_finished.set()
            self.ctx.dump_path = str(target)
            self.ctx.stats = ScanStats(connector="gateway.logs", started_at=now_iso(), finished_at=now_iso())
            return []

    def held_replace(source, target):
        if str(target).endswith(".jsonl"):
            target_paths.append(Path(target))
            replacing.set()
            assert release_replace.wait(6)
        original_replace(source, target)

    monkeypatch.setattr(base.os, "replace", held_replace)
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: ExportConnector)
    dump = tmp_path / "exports"
    engine = Engine(ScanConfig(connectors=[ConnectorSpec("gateway.logs")],
                               dump_records=str(dump), connector_timeout_seconds=0.2), SignatureIndex([]))
    outcome = {}

    def supervise():
        try:
            outcome["result"] = engine.run()
        except BaseException as exc:  # propagate from the test's supervisor thread
            outcome["error"] = exc
        finally:
            returned.set()

    supervisor = threading.Thread(target=supervise, daemon=True)
    supervisor.start()
    try:
        assert replacing.wait(3)
        # The replacement remains blocked. A supervisor waiting on the
        # publication lock would fail here rather than return an incomplete scan.
        assert returned.wait(2)
        assert "error" not in outcome
        result = outcome["result"]
        assert not result.complete
        assert engine.abandoned_workers == ["gateway.logs"]
        assert "may appear" in result.stats[0].warnings[0]
        manifest = json.loads((dump / "manifest.json").read_text())
        assert not manifest["complete"]
        assert manifest["exports"][0]["exported"] is False
        assert manifest["exports"][0]["filename"] is None
        assert len(target_paths) == 1 and not target_paths[0].exists()
    finally:
        release_replace.set()
        supervisor.join(3)
    assert worker_finished.wait(3)
    assert target_paths[0].read_text() == 'sanitized export\n'


def test_cli_returns_promptly_when_a_timed_out_worker_outlives_report_emission(monkeypatch):
    exit_codes = []

    class FakeEngine:
        def __init__(self, cfg, progress=None):
            self.abandoned_workers = ["slow"]

        def run(self, only=None):
            return ScanResult(stats=[ScanStats(
                connector="slow", started_at=now_iso(), finished_at=now_iso(),
                skipped=True, incomplete=True, errors=["timed out"],
            )])

    def record_exit(code):
        exit_codes.append(code)
        raise SystemExit(code)

    monkeypatch.setattr(cli_module, "Engine", FakeEngine)
    monkeypatch.setattr(cli_module.os, "_exit", record_exit)
    args = ["run", "identity.jwt", "--set", "tokens=a.b.c", "--format", "json"]
    completed = CliRunner().invoke(main, args)
    assert completed.exit_code == 3 and exit_codes == [3]

    def fail_output(*args, **kwargs):
        raise OSError("report destination unavailable")

    monkeypatch.setattr(cli_module, "_emit", fail_output)
    failed = CliRunner().invoke(main, args)
    assert failed.exit_code == 1 and exit_codes == [3, 1]
    assert "could not emit the incomplete report" in failed.output


@pytest.mark.parametrize("failure_point", ["stdout", "stderr", "diagnostic"])
@pytest.mark.parametrize("emission_fails", [False, True])
def test_cli_hard_exit_survives_broken_diagnostic_streams(monkeypatch, failure_point, emission_fails):
    calls = []

    class FakeEngine:
        def __init__(self, cfg, progress=None):
            self.abandoned_workers = ["blocked"]

        def run(self, only=None):
            return ScanResult(stats=[ScanStats(connector="blocked", started_at="now", incomplete=True)])

    def output_step(name):
        calls.append(name)
        if name == failure_point:
            raise BrokenPipeError("output consumer is unavailable")

    def emit(*args, **kwargs):
        if emission_fails:
            raise OSError("report destination is unavailable")

    def exit_process(code):
        calls.append(("exit", code))
        raise SystemExit(code)

    # Replace the CLI's sys reference, not pytest's own captured streams.
    monkeypatch.setattr(cli_module, "sys", SimpleNamespace(
        stdout=SimpleNamespace(flush=lambda: output_step("stdout")),
        stderr=SimpleNamespace(flush=lambda: output_step("stderr")),
    ))
    monkeypatch.setattr(cli_module, "err_console", SimpleNamespace(print=lambda *args: output_step("diagnostic")))
    monkeypatch.setattr(cli_module, "Engine", FakeEngine)
    monkeypatch.setattr(cli_module, "_emit", emit)
    monkeypatch.setattr(cli_module.os, "_exit", exit_process)
    with pytest.raises(SystemExit) as failure:
        cli_module._run_and_emit(ScanConfig(), "json", None, 0, None)
    expected_code = 1 if emission_fails else 3
    assert failure.value.code == expected_code
    assert calls == ["diagnostic", "stdout", "stderr", ("exit", expected_code)]
