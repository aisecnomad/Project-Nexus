"""A timed-out worker cannot publish scan artifacts after cancellation."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan import cli as cli_module
from shadowscan.cli import main
from shadowscan.config import ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
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
