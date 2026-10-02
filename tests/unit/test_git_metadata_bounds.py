"""Opt-in Git enrichment bounds decoded output and retained identity fields."""

from __future__ import annotations

import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code import filesystem as fs_module
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.engine import Engine
from shadowscan.models import ScanStats
from shadowscan.utils import git as git_module
from shadowscan.utils.git import (
    MAX_METADATA_OUTPUT_BYTES,
    MetadataOutputLimitError,
    MetadataTimeoutError,
    run_bounded_metadata,
    safe_git_env,
)


def _context(index, **options):
    ctx = ConnectorContext(config={"use_git": True, **options}, index=index)
    ctx.stats = ScanStats(connector="code.filesystem", started_at="2026-10-01T00:00:00Z")
    return ctx


def _wait_for_exit_without_reaping(pid: int) -> None:
    """Block until ``pid`` has exited, leaving it unreaped: the group then holds a zombie."""
    if hasattr(os, "waitid"):
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
        return
    if hasattr(select, "kqueue"):  # Darwin has no os.waitid
        queue = select.kqueue()
        try:
            exit_event = select.kevent(
                pid,
                filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT,
            )
            assert queue.control([exit_event], 1, 30), "the child did not exit within 30 seconds"
        finally:
            queue.close()
        return
    pytest.skip("this platform cannot observe a child's exit without reaping it")


def _record_processes(monkeypatch):
    started = []
    original = subprocess.Popen

    def record(*args, **kwargs):
        proc = original(*args, **kwargs)
        started.append(proc)
        return proc

    monkeypatch.setattr(git_module.subprocess, "Popen", record)
    return started


def _assert_cleaned(started):
    assert len(started) == 1
    proc = started[0]
    assert proc.poll() is not None
    assert proc.stdout.closed and proc.stderr.closed


def test_metadata_reader_replaces_invalid_utf8_and_drops_stderr(index):
    output = run_bounded_metadata(
        [sys.executable, "-c", "import os; os.write(1, b'Jos\\xff'); os.write(2, b'diagnostic')"],
        safe_git_env(),
        _context(index),
    )
    assert output.returncode == 0 and output.stdout == "Jos�" and output.stderr == ""


def test_metadata_reader_accepts_exact_combined_output_limit(index):
    output = run_bounded_metadata(
        [sys.executable, "-c", "import os; os.write(1, b'a' * 512); os.write(2, b'b' * 512)"],
        safe_git_env(),
        _context(index),
        max_bytes=1024,
    )
    assert output.stdout == "a" * 512 and output.stderr == ""


def test_metadata_reader_preserves_nonzero_status_without_diagnostic_contents(index, monkeypatch):
    started = _record_processes(monkeypatch)
    output = run_bounded_metadata(
        [sys.executable, "-c", "import os; os.write(2, b'private diagnostic'); raise SystemExit(2)"],
        safe_git_env(),
        _context(index),
    )
    assert output.returncode == 2 and output.stdout == "" and output.stderr == ""
    _assert_cleaned(started)


@pytest.mark.parametrize("stdout_bytes,stderr_bytes", [(1025, 0), (0, 1025), (512, 513)])
def test_metadata_reader_rejects_combined_output_overflow_and_reaps_process(
    index, monkeypatch, stdout_bytes, stderr_bytes
):
    started = _record_processes(monkeypatch)
    command = (
        f"import os,time; os.write(1,b'a'*{stdout_bytes}); os.write(2,b'b'*{stderr_bytes}); time.sleep(60)"
    )
    with pytest.raises(MetadataOutputLimitError, match="^git metadata output limit exceeded$"):
        run_bounded_metadata([sys.executable, "-c", command], safe_git_env(), _context(index), max_bytes=1024)
    _assert_cleaned(started)


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only")
def test_metadata_reader_overflow_from_an_exited_child_keeps_its_diagnostic(index, monkeypatch):
    """A child that exits before the reader trips the limit is already a zombie.

    Darwin's killpg() then fails with EPERM instead of ESRCH, which must not
    replace the output-limit diagnostic; Linux reports success for the same
    group. Reaping is waited for explicitly so the test is deterministic on
    both platforms rather than depending on pipe capacity and timing.
    """
    started = _record_processes(monkeypatch)
    original = git_module.subprocess.Popen

    def exited_before_reading(*args, **kwargs):
        proc = original(*args, **kwargs)
        # Wait for the exit without reaping: the group now holds one zombie.
        _wait_for_exit_without_reaping(proc.pid)
        return proc

    monkeypatch.setattr(git_module.subprocess, "Popen", exited_before_reading)
    command = "import os; os.write(1, b'a' * 1025)"
    with pytest.raises(MetadataOutputLimitError, match="^git metadata output limit exceeded$"):
        run_bounded_metadata([sys.executable, "-c", command], safe_git_env(), _context(index), max_bytes=1024)
    _assert_cleaned(started)


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only")
def test_metadata_reader_overflow_survives_a_refused_group_signal(index, monkeypatch):
    """Darwin also refuses killpg() for a group holding a zombie helper while the child runs.

    The child is then killed by pid: the output-limit diagnostic stays and no
    process is left behind.
    """
    started = _record_processes(monkeypatch)

    def refused(pgid, sig):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(git_module.os, "killpg", refused)
    command = "import os, time; os.write(1, b'a' * 1025); time.sleep(30)"
    with pytest.raises(MetadataOutputLimitError, match="^git metadata output limit exceeded$"):
        run_bounded_metadata([sys.executable, "-c", command], safe_git_env(), _context(index), max_bytes=1024)
    _assert_cleaned(started)


@pytest.mark.parametrize("close_pipes", [False, True])
def test_metadata_reader_times_out_with_open_or_closed_pipes(index, monkeypatch, close_pipes):
    started = _record_processes(monkeypatch)
    command = "import os,time; " + ("os.close(1); os.close(2); " if close_pipes else "") + "time.sleep(60)"
    with pytest.raises(MetadataTimeoutError, match="^git metadata completion deadline exceeded$"):
        run_bounded_metadata([sys.executable, "-c", command], safe_git_env(), _context(index), timeout=0.1)
    _assert_cleaned(started)


def test_metadata_reader_cooperatively_cancels_and_reaps_process(index, monkeypatch):
    started = _record_processes(monkeypatch)
    ctx = _context(index)
    ctx.cancelled = threading.Event()
    timer = threading.Timer(0.1, ctx.cancelled.set)
    timer.start()
    try:
        with pytest.raises(ConnectorError, match="connector completion deadline exceeded"):
            run_bounded_metadata(
                [sys.executable, "-c", "import time; time.sleep(60)"], safe_git_env(), ctx, timeout=10
            )
    finally:
        timer.cancel()
        timer.join()
    _assert_cleaned(started)


def test_metadata_reader_uses_connector_deadline_before_subprocess_timeout(index, monkeypatch):
    started = _record_processes(monkeypatch)
    ctx = _context(index)
    ctx.deadline = time.monotonic() + 0.1
    with pytest.raises(ConnectorError, match="connector completion deadline exceeded"):
        run_bounded_metadata(
            [sys.executable, "-c", "import time; time.sleep(60)"], safe_git_env(), ctx, timeout=10
        )
    _assert_cleaned(started)


@pytest.mark.parametrize("field,limit", [(0, 1024), (1, 1024), (2, 64)])
def test_git_info_rejects_oversized_identity_fields(tmp_path, index, monkeypatch, field, limit):
    (tmp_path / ".git").mkdir()
    fields = ["Author", "author@example.test", "2026-10-01T00:00:00Z"]
    fields[field] = "a" * (limit + 1)
    monkeypatch.setattr(
        fs_module,
        "run_bounded_metadata",
        Mock(return_value=subprocess.CompletedProcess([], 0, stdout="\x00".join(fields), stderr="")),
    )
    ctx = _context(index)
    assert FilesystemConnector(ctx)._git_info(tmp_path, ".") == {}
    assert ctx.stats.incomplete and ctx.stats.warnings == [
        "code.filesystem: git metadata field limit exceeded; enrichment skipped"
    ]


def test_git_info_accepts_identity_fields_at_the_limit(tmp_path, index, monkeypatch):
    (tmp_path / ".git").mkdir()
    fields = ["A" * 1024, "a" * 1024, "2026-10-01T00:00:00Z"]
    monkeypatch.setattr(
        fs_module,
        "run_bounded_metadata",
        Mock(return_value=subprocess.CompletedProcess([], 0, stdout="\x00".join(fields), stderr="")),
    )
    ctx = _context(index)
    result = FilesystemConnector(ctx)._git_info(tmp_path, ".")
    assert result["last_author"] == fields[0] and result["last_author_email"] == fields[1]
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("fields", [["a", "b"], ["a", "b", "2026-10-01T00:00:00Z", "extra"]])
def test_git_info_rejects_ambiguous_field_counts(tmp_path, index, monkeypatch, fields):
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(
        fs_module,
        "run_bounded_metadata",
        Mock(return_value=subprocess.CompletedProcess([], 0, stdout="\x00".join(fields), stderr="")),
    )
    ctx = _context(index)
    assert FilesystemConnector(ctx)._git_info(tmp_path, ".") == {}
    assert ctx.stats.incomplete and "invalid fields" in ctx.stats.warnings[0]


def _repository_with_author(root: Path, author_chars: int):
    env = safe_git_env()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True, env=env)
    (root / "requirements.txt").write_text("langgraph\n")
    subprocess.run(
        ["git", "-C", str(root), "add", "requirements.txt"], check=True, capture_output=True, env=env
    )
    tree = subprocess.check_output(["git", "-C", str(root), "write-tree"], env=env).strip()
    commit = (
        b"tree "
        + tree
        + b"\nauthor "
        + b"A" * author_chars
        + b" <author@example.test> 1790812800 +0000\n"
        + b"committer Author <author@example.test> 1790812800 +0000\n\nInitial\n"
    )
    sha = subprocess.check_output(
        ["git", "-C", str(root), "hash-object", "-t", "commit", "-w", "--stdin"], input=commit, env=env
    ).strip()
    subprocess.run(["git", "-C", str(root), "update-ref", "HEAD", sha], check=True, env=env)


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize("author_chars", [1025, MAX_METADATA_OUTPUT_BYTES * 2])
def test_engine_preserves_code_findings_but_rejects_excessive_git_metadata(tmp_path, author_chars):
    _repository_with_author(tmp_path, author_chars)
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    name="code.filesystem",
                    config={
                        "path": str(tmp_path),
                        "use_git": True,
                        "max_file_size": 1024,
                    },
                )
            ],
            parallel=1,
        )
    ).run()
    assert not result.complete
    assert any("framework.langgraph" in finding.frameworks for finding in result.findings)
    assert all("last_author" not in finding.metadata for finding in result.findings)
    assert any("limit exceeded" in warning for stats in result.stats for warning in stats.warnings)
    assert len(result.to_json()) < 10_000


@pytest.mark.requires_git_2_45
def test_engine_accepts_normal_git_history(tmp_path):
    _repository_with_author(tmp_path, 24)
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    name="code.filesystem",
                    config={
                        "path": str(tmp_path),
                        "use_git": True,
                    },
                )
            ],
            parallel=1,
        )
    ).run()
    assert result.complete and result.findings
    assert all(finding.metadata["last_author"] == "A" * 24 for finding in result.findings)


@pytest.mark.parametrize("max_bytes", [True, 0, -1, 1.5])
def test_metadata_output_limits_are_validated_before_process_start(index, monkeypatch, max_bytes):
    launch = Mock(side_effect=AssertionError("invalid limit must fail before process start"))
    monkeypatch.setattr(git_module.subprocess, "Popen", launch)
    with pytest.raises(ValueError, match="metadata max_bytes must be a positive integer"):
        run_bounded_metadata(["git"], safe_git_env(), _context(index), max_bytes=max_bytes)
    launch.assert_not_called()


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), float("nan"), "1"])
def test_metadata_timeout_is_validated_before_process_start(index, monkeypatch, timeout):
    launch = Mock(side_effect=AssertionError("invalid timeout must fail before process start"))
    monkeypatch.setattr(git_module.subprocess, "Popen", launch)
    with pytest.raises(ValueError, match="metadata timeout must be positive and finite"):
        run_bounded_metadata(["git"], safe_git_env(), _context(index), timeout=timeout)
    launch.assert_not_called()


def test_metadata_reader_refuses_platforms_without_supported_pipe_selection(index, monkeypatch):
    ctx, env = _context(index), safe_git_env()
    launch = Mock(side_effect=AssertionError("unsupported platform must not start process"))
    monkeypatch.setattr(git_module.subprocess, "Popen", launch)
    with monkeypatch.context() as patch:
        patch.setattr(git_module.os, "name", "nt")
        with pytest.raises(ValueError, match="bounded Git metadata access is unavailable on this platform"):
            run_bounded_metadata(["git"], env, ctx)
    launch.assert_not_called()
