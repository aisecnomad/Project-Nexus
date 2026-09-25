"""Regressions for connector isolation, bounded collection, and shared state."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from importlib.metadata import EntryPoint
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import shadowscan.connectors as registry
from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig, parse_set_options
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.engine import Engine
from shadowscan.incremental import IncrementalCache
from shadowscan.models import Finding, Kind, ScanStats, Surface, now_iso
from shadowscan.signatures import SignatureIndex

# Connector deadline for the timeout tests, in seconds. It must comfortably
# exceed the engine's per-connector prelude on a loaded host: the deadline
# starts before the connector runs, so a tiny value can expire beforehand.
CONNECTOR_DEADLINE = 0.5
# Upper bound on a held worker, so a broken test cannot hang the process.
HOLD_TIMEOUT = 30


def _warm_engine_prelude() -> None:
    """Pay the engine's one-off per-connector import costs outside a timed run.

    The connector deadline starts before the connector itself is entered. On a
    cold process the prelude imports the built-in connector module, which can
    take longer than a short deadline and expire it before the fake connector
    ever runs. The caller must already have patched the connector lookup.
    """
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", label="warm-up")]),
                    SignatureIndex([])).run()
    assert result.complete, result.stats


@pytest.mark.parametrize("name", ["allow_instance_credentials", "allow_credential_mixing"])
@pytest.mark.parametrize("value", ["false", 0, 1, None, [], {}])
def test_credentials_require_explicit_boolean_approval(name, value):
    with pytest.raises(ValueError, match=name):
        ScanConfig(**{name: value})
    with pytest.raises(ValueError, match=name):
        ScanConfig.from_dict({"options": {name: value}})


@pytest.mark.parametrize("value", [0, -1, True, None, float("nan"), float("inf"), "invalid"])
def test_connector_deadline_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="connector_timeout_seconds"):
        ScanConfig(connector_timeout_seconds=value)


def test_cli_rejects_nonfinite_deadline():
    result = CliRunner().invoke(main, ["run", "gateway.logs", "--connector-timeout-seconds", "nan"])
    assert result.exit_code == 2 and "positive finite" in result.output


def test_credential_isolation_is_applied_to_selected_connectors(monkeypatch):
    class EmptyConnector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            self.ctx.stats = ScanStats(connector="test", started_at=now_iso(), finished_at=now_iso())
            return []

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: EmptyConnector)
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem"), ConnectorSpec("cloud.aws")])
    engine = Engine(cfg, SignatureIndex([]))
    with pytest.raises(ValueError, match="allow_credential_mixing"):
        engine.run()
    assert engine.run(only=["code.filesystem"]).complete
    cfg.allow_credential_mixing = True
    assert engine.run().complete


def test_offline_exports_do_not_require_credential_mixing_approval():
    offline = ScanConfig(connectors=[
        ConnectorSpec("code.filesystem"), ConnectorSpec("cloud.aws", {"input": "aws.json"}),
    ])
    assert offline.validate_connector_isolation(offline.connectors) is None
    provider = ScanConfig(connectors=[ConnectorSpec("code.github")])
    assert provider.validate_connector_isolation(provider.connectors) is None
    # The same check still rejects the live counterpart of the offline export.
    live = ScanConfig(connectors=[ConnectorSpec("code.filesystem"), ConnectorSpec("cloud.aws")])
    with pytest.raises(ValueError, match="allow_credential_mixing"):
        live.validate_connector_isolation(live.connectors)


@pytest.mark.parametrize("approved", [False, True])
def test_instance_credentials_approval_comes_from_scan_options(monkeypatch, approved):
    seen = []

    class EmptyConnector:
        def __init__(self, ctx):
            self.ctx = ctx
            seen.append(ctx.config["allow_instance_credentials"])

        def run(self):
            self.ctx.stats = ScanStats(connector="cloud.aws", started_at=now_iso(), finished_at=now_iso())
            return []

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: EmptyConnector)
    cfg = ScanConfig(connectors=[ConnectorSpec("cloud.aws", {"allow_instance_credentials": not approved})],
                     allow_instance_credentials=approved)
    assert Engine(cfg, SignatureIndex([])).run().complete
    assert seen == [approved]


@pytest.mark.parametrize("workers", [1, 2])
def test_connector_deadline_returns_incomplete_and_discards_late_results(monkeypatch, workers):
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            if self.ctx.config["label"] == "blocked":
                started.set()
                try:
                    release.wait(HOLD_TIMEOUT)
                finally:
                    finished.set()
            self.ctx.stats = ScanStats(connector="test", started_at=now_iso(), finished_at=now_iso())
            return [Finding(Surface.CODE, "code.filesystem", Kind.AGENT,
                            self.ctx.config["label"], self.ctx.config["label"], "agent")]

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: Connector)
    _warm_engine_prelude()
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", label="blocked"),
                                 ConnectorSpec("code.filesystem", label="healthy")],
                     parallel=workers, connector_timeout_seconds=CONNECTOR_DEADLINE)
    try:
        result = Engine(cfg, SignatureIndex([])).run()
        # Sampled before the release: the engine must return while the worker is still held.
        worker_still_held = not finished.is_set()
    finally:
        release.set()
    assert started.is_set(), "the deadline expired before the blocked connector started"
    assert finished.wait(5)
    assert worker_still_held
    assert not result.complete
    blocked = next(stats for stats in result.stats if stats.connector == "blocked")
    assert "deadline" in blocked.errors[0]
    assert "cooperative" in blocked.warnings[0]
    assert {finding.resource for finding in result.findings} == ({"healthy"} if workers == 2 else set())
    assert all(finding.resource != "blocked" for finding in result.findings)


def test_timed_out_connector_preserves_queued_siblings_when_a_worker_remains(monkeypatch):
    # The second worker starts "in-flight" halfway through the blocked deadline,
    # which leaves half a deadline of margin on either side: "stagger" completes
    # well before its own deadline, and the "in-flight" deadline is still live
    # after the engine observes the blocked expiry and releases it.
    deadline = 2 * CONNECTOR_DEADLINE
    blocked_started = threading.Event()
    blocked_cancelled: dict[str, threading.Event] = {}
    release = threading.Event()
    finished = threading.Event()

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            label = self.ctx.config["label"]
            if label == "blocked":
                blocked_cancelled["event"] = self.ctx.cancelled
                blocked_started.set()
                try:
                    release.wait(HOLD_TIMEOUT)
                finally:
                    finished.set()
            elif label == "stagger":
                # Start the next worker later, so its own deadline is still
                # live when the blocked worker expires.
                time.sleep(deadline / 2)
            elif label == "in-flight":
                # Stay occupied until the engine has expired the blocked worker,
                # so the last connector is still queued at that moment.
                assert blocked_started.wait(HOLD_TIMEOUT)
                assert blocked_cancelled["event"].wait(HOLD_TIMEOUT)
            self.ctx.stats = ScanStats(connector=label, started_at=now_iso(), finished_at=now_iso())
            return [Finding(Surface.CODE, "code.filesystem", Kind.AGENT, label, label, "agent")]

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: Connector)
    _warm_engine_prelude()
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", label=label) for label in
                                 ("blocked", "stagger", "in-flight", "queued")],
                     parallel=2, connector_timeout_seconds=deadline)
    try:
        result = Engine(cfg, SignatureIndex([])).run()
    finally:
        release.set()
    assert blocked_started.is_set(), "the deadline expired before the blocked connector started"
    assert finished.wait(5)
    assert {finding.resource for finding in result.findings} == {"stagger", "in-flight", "queued"}
    by_connector = {stat.connector: stat for stat in result.stats}
    assert set(by_connector) == {"blocked", "stagger", "in-flight", "queued"}
    assert "deadline" in by_connector["blocked"].errors[0]
    assert all(not by_connector[name].skipped and not by_connector[name].incomplete for name in
               ("stagger", "in-flight", "queued"))


def test_queued_siblings_are_incomplete_if_all_workers_remain_stuck(monkeypatch):
    release = threading.Event()
    finished = {label: threading.Event() for label in ("blocked-1", "blocked-2")}
    started = []

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            label = self.ctx.config["label"]
            if label != "warm-up":
                started.append(label)
            if label.startswith("blocked"):
                try:
                    release.wait(HOLD_TIMEOUT)
                finally:
                    finished[label].set()
            self.ctx.stats = ScanStats(connector=label, started_at=now_iso(), finished_at=now_iso())
            return []

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: Connector)
    _warm_engine_prelude()
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", label=label) for label in
                                 ("blocked-1", "blocked-2", "queued")],
                     parallel=2, connector_timeout_seconds=CONNECTOR_DEADLINE)
    try:
        result = Engine(cfg, SignatureIndex([])).run()
        # Sampled before the release: the engine must not wait for either held worker.
        workers_still_held = not any(event.is_set() for event in finished.values())
    finally:
        release.set()
    assert all(event.wait(5) for event in finished.values())
    assert workers_still_held
    # Both workers were occupied by held connectors; the queued one never started.
    assert sorted(started) == ["blocked-1", "blocked-2"]
    assert all("deadline" in stat.errors[0] for stat in result.stats[:2])
    assert result.stats[2].incomplete and result.stats[2].skipped
    assert "all worker slots" in result.stats[2].errors[0]


def test_record_checkpoint_stops_after_cancellation():
    cancelled = threading.Event()
    ctx = ConnectorContext(index=SignatureIndex([]), cancelled=cancelled)
    fetched = []

    def source():
        for identity in (1, 2):
            fetched.append(identity)
            yield {"id": identity}

    records = ctx.checked_records(source())
    assert next(records) == {"id": 1}
    cancelled.set()
    with pytest.raises(ConnectorError, match="deadline"):
        next(records)
    assert fetched == [1]  # no post-timeout SDK/page fetch


def test_broken_plugin_metadata_does_not_hide_later_plugins(monkeypatch):
    class BrokenEntry:
        @property
        def name(self):
            raise RuntimeError("broken distribution metadata")

    valid = EntryPoint(name="cloud.reviewed", value="reviewed:Connector", group="shadowscan.connectors")
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [BrokenEntry(), valid])
    assert registry.available_connectors()["cloud.reviewed"] == "reviewed:Connector"


def test_ambiguous_plugin_names_never_depend_on_installation_order(monkeypatch):
    entries = [SimpleNamespace(name="cloud.reviewed", value=value) for value in
               ["reviewed:Connector", "other:Connector", "reviewed:Connector"]]
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: entries)
    assert "cloud.reviewed" not in registry.available_connectors()
    assert "code.filesystem" in registry.available_connectors()


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_incremental_lock_contention_does_not_wait_or_replace_cache(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "requirements.txt").write_text("langchain\n")
    spec = ConnectorSpec("code.filesystem", {"path": str(source), "use_git": False})
    cfg = ScanConfig(connectors=[spec], incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, SignatureIndex([]))
    snapshot = cache.snapshot(spec)
    assert snapshot is not None
    stats = ScanStats(connector=spec.id, started_at=now_iso(), finished_at=now_iso())
    cache.save(snapshot, [], stats)
    cache_path = cache.directory / f"{snapshot.slot}.json"
    original = cache_path.read_bytes()
    lock_path = cache.directory / f"{snapshot.slot}.lock"
    process = subprocess.Popen([
        sys.executable, "-c",
        "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX); "
        "print('locked',flush=True); sys.stdin.read(1)", str(lock_path),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == "locked"
        before = time.monotonic()
        assert cache.load(spec, snapshot) is None
        cache.save(snapshot, [], stats)
        assert time.monotonic() - before < 1
        assert cache_path.read_bytes() == original
    finally:
        process.communicate("x", timeout=3)
    assert cache.load(spec, snapshot) is not None
    assert json.loads(cache_path.read_text())["fingerprint"] == snapshot.fingerprint


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_incremental_lock_symlink_is_rejected(tmp_path):
    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, SignatureIndex([]))
    from shadowscan.incremental import Snapshot
    snapshot = Snapshot("a" * 64, "b" * 64)
    target = tmp_path / "target"
    target.write_text("unchanged")
    (cache.directory / f"{snapshot.slot}.lock").symlink_to(target)
    assert cache.load(ConnectorSpec("code.filesystem"), snapshot) is None
    cache.save(snapshot, [], ScanStats(connector="test", started_at=now_iso()))
    assert target.read_text() == "unchanged"
    assert not (cache.directory / f"{snapshot.slot}.json").exists()


def test_completed_future_after_deadline_cannot_report_success(monkeypatch):
    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            self.ctx.stats = ScanStats(connector="test", started_at=now_iso(), finished_at=now_iso())
            return []

    def progress(connector, message):
        if message != "starting":
            time.sleep(0.03)

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: Connector)
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem")], connector_timeout_seconds=0.01)
    result = Engine(cfg, SignatureIndex([]), progress=progress).run()
    assert not result.complete
    assert "deadline" in result.stats[0].errors[0]


def test_cache_cannot_publish_after_deadline(tmp_path):
    from shadowscan.incremental import Snapshot
    cfg = ScanConfig(incremental=True, state_dir=str(tmp_path / "state"))
    cache = IncrementalCache(cfg, SignatureIndex([]))
    snapshot = Snapshot("a" * 64, "b" * 64)
    calls = 0

    def check_deadline():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ConnectorError("connector completion deadline exceeded")

    with pytest.raises(ConnectorError, match="deadline"):
        cache.save(snapshot, [], ScanStats(connector="test", started_at=now_iso()), check_deadline=check_deadline)
    assert calls == 2
    assert not (cache.directory / f"{snapshot.slot}.json").exists()
    assert not list(cache.directory.glob(".pending-*"))


def test_gcp_credentials_file_is_relative_to_scan_config(tmp_path):
    config = ScanConfig.from_dict({"connectors": [{"name": "cloud.gcp", "credentials_file": "adc.json"}]},
                                  source=str(tmp_path / "scan.yaml"))
    assert config.connectors[0].config["credentials_file"] == str(tmp_path / "adc.json")


def test_cli_applies_explicit_credential_and_deadline_options(monkeypatch):
    received = []
    monkeypatch.setattr("shadowscan.cli._run_and_emit", lambda cfg, *args, **kwargs: received.append(cfg))
    result = CliRunner().invoke(main, [
        "run", "cloud.aws", "--allow-instance-credentials", "--allow-credential-mixing",
        "--connector-timeout-seconds", "2.5",
    ])
    assert result.exit_code == 0, result.output
    assert received[0].allow_instance_credentials is True
    assert received[0].allow_credential_mixing is True
    assert received[0].connector_timeout_seconds == 2.5


def test_cli_retains_yaml_approvals_unless_explicitly_denied(monkeypatch, tmp_path):
    received = []
    monkeypatch.setattr("shadowscan.cli._run_and_emit", lambda cfg, *args, **kwargs: received.append(cfg))
    path = tmp_path / "scan.yaml"
    path.write_text("options:\n  allow_instance_credentials: true\n  allow_credential_mixing: true\n"
                    "  connector_timeout_seconds: 600\nconnectors: [cloud.aws]\n")
    runner = CliRunner()
    assert runner.invoke(main, ["scan", "--config", str(path)]).exit_code == 0
    assert received[-1].allow_instance_credentials and received[-1].allow_credential_mixing
    assert received[-1].connector_timeout_seconds == 600
    assert runner.invoke(main, ["scan", "--config", str(path), "--deny-instance-credentials",
                                "--deny-credential-mixing"]).exit_code == 0
    assert not received[-1].allow_instance_credentials and not received[-1].allow_credential_mixing


@pytest.mark.parametrize("account_id", ["012345678901", "123456789012"])
def test_set_preserves_account_id_lexical_form(account_id):
    assert parse_set_options([f"account_id={account_id}", "cloudtrail_days=3"]) == {
        "account_id": account_id, "cloudtrail_days": 3,
    }


@pytest.mark.parametrize("account_id", ["012345678901", "123456789012"])
def test_cli_preserves_account_id_for_provider_scope_check(monkeypatch, account_id):
    received = []
    monkeypatch.setattr("shadowscan.cli._run_and_emit", lambda cfg, *args, **kwargs: received.append(cfg))
    result = CliRunner().invoke(main, ["run", "cloud.aws", "--set", f"account_id={account_id}"])
    assert result.exit_code == 0, result.output
    assert received[0].connectors[0].config["account_id"] == account_id
