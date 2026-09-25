"""The whole-file and line-oriented offline readers share one confined open path.

Both readers, and the policy reader, must refuse a symlink in any path
component and anything that is not a regular file, enforce their own byte
limits, and read a normal file identically.
"""

from __future__ import annotations

import gc
import os
import stat
from pathlib import Path

import pytest

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.models import ScanStats, Surface
from shadowscan.utils.files import NotRegularFileError, changed_since, open_confined_file, read_policy_text

DATA = b'{"a":1}\n{"b":2}\n'


class _Probe(BaseConnector):
    name = "test.reader"
    surface = Surface.CODE

    def collect(self):
        return []

    def analyze(self, records):
        return []


def _probe(index, **config) -> _Probe:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01T00:00:00Z")
    probe = _Probe(ctx)
    probe._offline_bytes_read = 0
    return probe


def _lines(probe: _Probe, path: Path) -> bytes:
    return "".join(probe._iter_bounded_lines(path, probe._offline_budget())).encode()


def _assert_all_readers_refuse(probe: _Probe, path: Path, *, reason: str) -> None:
    """Every reader fails closed on ``path``; ``reason`` is the offline error substring."""
    assert probe._read_offline_bytes(path, probe._offline_budget()) is None
    assert probe._read_offline_bytes(path) is None
    assert _lines(probe, path) == b""
    assert probe.ctx.stats.incomplete
    assert probe.ctx.stats.errors and probe.ctx.stats.warnings
    assert all(reason in message for message in probe.ctx.stats.errors)
    with pytest.raises((OSError, ValueError)):
        read_policy_text(path)


def test_readers_return_identical_bytes_for_regular_file(tmp_path, index):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index)

    with_budget = probe._read_offline_bytes(source, probe._offline_budget())
    without_budget = probe._read_offline_bytes(source)

    assert with_budget == without_budget == _lines(probe, source) == DATA
    assert read_policy_text(source) == DATA.decode()
    assert not probe.ctx.stats.incomplete
    assert not probe.ctx.stats.errors and not probe.ctx.stats.warnings


def test_readers_refuse_symlinked_file(tmp_path, index):
    target = tmp_path / "outside.jsonl"
    target.write_bytes(DATA)
    link = tmp_path / "records.jsonl"
    link.symlink_to(target)
    probe = _probe(index)

    _assert_all_readers_refuse(probe, link, reason="could not be securely read")

    assert all("could not be read" in warning for warning in probe.ctx.stats.warnings)
    with pytest.raises(OSError):
        read_policy_text(link)


def test_readers_refuse_symlinked_directory_component(tmp_path, index):
    real = tmp_path / "real"
    real.mkdir()
    (real / "records.jsonl").write_bytes(DATA)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    through_link = linked / "records.jsonl"
    assert through_link.is_file() and not through_link.is_symlink()
    probe = _probe(index)

    _assert_all_readers_refuse(probe, through_link, reason="could not be securely read")

    with pytest.raises(OSError):
        read_policy_text(through_link)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable on this platform")
def test_readers_refuse_fifo_without_blocking(tmp_path, index):
    fifo = tmp_path / "records.jsonl"
    os.mkfifo(fifo)
    probe = _probe(index)

    _assert_all_readers_refuse(probe, fifo, reason="offline input is not a regular file")

    assert all("offline input is not a regular file" in warning for warning in probe.ctx.stats.warnings)
    with pytest.raises(NotRegularFileError, match="policy input is not a regular file"):
        read_policy_text(fifo)
    assert issubclass(NotRegularFileError, ValueError)


def _character_device(tmp_path: Path) -> Path | None:
    """A character device reachable without symlinks: a fresh node when permitted, else a system one."""
    candidates: list[Path] = []
    if hasattr(os, "mknod") and hasattr(os, "makedev"):
        created = tmp_path / "device"
        try:
            os.mknod(created, stat.S_IFCHR | 0o600, os.makedev(1, 3))
        except OSError:
            pass
        else:
            candidates.append(created)
    candidates.extend((Path("/dev/null"), Path("/dev/zero")))
    for candidate in candidates:
        try:
            if not stat.S_ISCHR(os.stat(candidate).st_mode):
                continue
        except OSError:
            continue
        if not any(part.is_symlink() for part in (candidate, *candidate.parents)):
            return candidate
    return None


def test_readers_refuse_device(tmp_path, index):
    device = _character_device(tmp_path)
    if device is None:
        pytest.skip("no plain character device available")
    probe = _probe(index)

    _assert_all_readers_refuse(probe, device, reason="offline input is not a regular file")

    with pytest.raises(NotRegularFileError):
        read_policy_text(device)


def test_readers_refuse_directory(tmp_path, index):
    probe = _probe(index)

    _assert_all_readers_refuse(probe, tmp_path, reason="offline input is not a regular file")


def test_whole_file_reader_enforces_per_file_limit(tmp_path, index):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index, max_input_file_bytes=len(DATA) - 1, max_input_bytes=1024)

    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert probe.ctx.stats.incomplete
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_file_bytes reached; oversized offline input was skipped"
    ]

    probe = _probe(index, max_input_file_bytes=len(DATA), max_input_bytes=1024)
    assert probe._read_offline_bytes(source, probe._offline_budget()) == DATA


def test_whole_file_reader_enforces_aggregate_budget(tmp_path, index):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_bytes(DATA)
    second.write_bytes(DATA)
    probe = _probe(index, max_input_bytes=len(DATA) + 1, max_input_file_bytes=1024)
    budget = probe._offline_budget()

    assert probe._read_offline_bytes(first, budget) == DATA
    assert budget.bytes_read == len(DATA)
    assert probe._read_offline_bytes(second, budget) is None
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_bytes reached; oversized offline input was skipped"
    ]

    # Without a budget the connector-wide counter is charged and the file is an error.
    probe = _probe(index, max_input_bytes=len(DATA) + 1, max_input_file_bytes=1024)
    assert probe._read_offline_bytes(first) == DATA
    assert probe._offline_bytes_read == len(DATA)
    assert probe._read_offline_bytes(second) is None
    assert probe.ctx.stats.errors == ["test.reader: offline input exceeds the byte limit"]


def test_line_reader_enforces_per_file_limit_before_reading(tmp_path, index):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    probe = _probe(index, max_input_file_bytes=len(DATA) - 1, max_input_bytes=1024)

    assert _lines(probe, source) == b""
    assert probe.ctx.stats.incomplete
    assert probe.ctx.stats.warnings == [f"test.reader: max_input_file_bytes ({len(DATA) - 1}) reached"]


def test_line_reader_streams_records_up_to_the_aggregate_budget(tmp_path, index):
    """The two readers bound the aggregate budget differently on purpose.

    The line reader charges the budget per line and yields the records that
    fit; the whole-file reader rejects the same file outright.
    """
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    first_line = DATA.splitlines(keepends=True)[0]
    probe = _probe(index, max_input_bytes=len(first_line), max_input_file_bytes=1024)

    lines = list(probe._iter_bounded_lines(source, probe._offline_budget()))

    assert lines == [first_line.decode()]
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_bytes reached; remaining offline input was skipped"
    ]

    probe = _probe(index, max_input_bytes=len(first_line), max_input_file_bytes=1024)
    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert probe.ctx.stats.warnings == [
        "test.reader: max_input_bytes reached; oversized offline input was skipped"
    ]


def test_readers_report_a_file_rewritten_during_the_read(tmp_path, index, monkeypatch):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    monkeypatch.setattr("shadowscan.connectors.base.changed_since", lambda before, fd: True)
    probe = _probe(index)

    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert _lines(probe, source) == DATA
    assert probe.ctx.stats.errors == [
        "test.reader: offline input changed while being read",
        "test.reader: offline input changed while being read",
    ]
    assert probe.ctx.stats.incomplete


def test_changed_since_detects_rewrite_of_the_open_descriptor(tmp_path):
    source = tmp_path / "policy.yaml"
    source.write_bytes(DATA)

    with open_confined_file(source) as (stream, before):
        assert not changed_since(before, stream.fileno())
        with source.open("ab") as writer:
            writer.write(b"extra\n")
        assert changed_since(before, stream.fileno())


def test_open_confined_file_fails_closed_without_platform_support(tmp_path, index, monkeypatch):
    source = tmp_path / "records.jsonl"
    source.write_bytes(DATA)
    monkeypatch.setattr(os, "supports_dir_fd", set(os.supports_dir_fd) - {os.open})
    probe = _probe(index)

    with pytest.raises(ValueError, match="unavailable on this platform"), open_confined_file(source):
        pass
    assert probe._read_offline_bytes(source, probe._offline_budget()) is None
    assert _lines(probe, source) == b""
    assert probe.ctx.stats.errors == ["test.reader: secure file access is unavailable on this platform"]
    assert probe.ctx.stats.warnings == [
        "test.reader: offline input could not be read (secure file access is unavailable on this platform)"
    ]

    monkeypatch.setattr(os, "supports_dir_fd", set(os.supports_dir_fd) | {os.open})
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(ValueError, match="unavailable on this platform"), open_confined_file(source):
        pass


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="descriptor table is not observable")
def test_open_confined_file_releases_descriptors_on_every_path(tmp_path, index):
    regular = tmp_path / "records.jsonl"
    regular.write_bytes(DATA)
    link = tmp_path / "link.jsonl"
    link.symlink_to(regular)
    probe = _probe(index)

    gc.collect()
    before = set(os.listdir("/proc/self/fd"))
    assert probe._read_offline_bytes(regular, probe._offline_budget()) == DATA
    assert _lines(probe, regular) == DATA
    assert probe._read_offline_bytes(link) is None
    assert _lines(probe, link) == b""
    assert probe._read_offline_bytes(tmp_path) is None
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo.jsonl"
        os.mkfifo(fifo)
        assert _lines(probe, fifo) == b""
    with pytest.raises(OSError):
        read_policy_text(tmp_path / "missing.yaml")
    gc.collect()

    assert set(os.listdir("/proc/self/fd")) == before
