"""Observed checkout size is checked during and after a remote clone."""

from __future__ import annotations

import os
import sys
import time

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.models import ScanStats
from shadowscan.utils.git import CloneSizeError, _clone_disk_usage, run_bounded_clone


@pytest.mark.parametrize(
    "cls,record",
    [
        (
            GitHubConnector,
            {"full_name": "org/repo", "size": 1, "clone_url": "https://github.com/org/repo.git"},
        ),
        (
            GitLabConnector,
            {
                "id": 1,
                "path_with_namespace": "org/repo",
                "statistics": {"repository_size": 1024},
                "http_url_to_repo": "https://gitlab.com/org/repo.git",
            },
        ),
    ],
)
def test_remote_clone_over_observed_limit_uses_incomplete_api_fallback(
    tmp_path,
    monkeypatch,
    index,
    cls,
    record,
):
    cap = 1024 * 1024
    ctx = ConnectorContext(config={"clone_max_bytes": cap}, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    original = run_bounded_clone
    code = (
        "import pathlib,sys,time; "
        "p=pathlib.Path(sys.argv[1]); p.mkdir(); "
        "(p/'oversize').write_bytes(b'x' * 2097152); time.sleep(10)"
    )

    def write_instead_of_git(cmd, env, context, timeout, *, destination, max_bytes):
        assert max_bytes == cap
        return original(
            [sys.executable, "-c", code, destination],
            os.environ.copy(),
            context,
            timeout,
            destination=destination,
            max_bytes=max_bytes,
        )

    # GitHub and GitLab share the clone in the remote-repository base connector.
    monkeypatch.setattr("shadowscan.connectors.code.remote.run_bounded_clone", write_instead_of_git)
    monkeypatch.setattr(connector, "_fetch_via_api", lambda repo, tmp: tmp)
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path)
    assert not (tmp_path / "repo").exists(), "the partial checkout must be removed"
    assert ctx.stats.incomplete
    assert any("observed clone size exceeds clone_max_bytes" in msg for msg in ctx.stats.warnings)


def test_clone_size_is_checked_after_git_exits(tmp_path, index):
    # The writer exits before the first 100 ms poll. A successful return from
    # wait() still requires an on-disk check before accepting the checkout.
    checkout = tmp_path / "repo"
    code = (
        "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(); "
        "(p/'oversize').write_bytes(b'x' * 2097152)"
    )
    ctx = ConnectorContext(index=index)
    with pytest.raises(CloneSizeError, match="observed clone size exceeds clone_max_bytes"):
        run_bounded_clone(
            [sys.executable, "-c", code, str(checkout)],
            os.environ.copy(),
            ctx,
            timeout=5,
            destination=str(checkout),
            max_bytes=1024 * 1024,
        )


def test_checkout_below_observed_limit_is_accepted(tmp_path, index):
    checkout = tmp_path / "repo"
    code = (
        "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(); (p/'source.py').write_bytes(b'x' * 8192)"
    )
    assert run_bounded_clone(
        [sys.executable, "-c", code, str(checkout)],
        os.environ.copy(),
        ConnectorContext(index=index),
        timeout=5,
        destination=str(checkout),
        max_bytes=1024 * 1024,
    )
    assert (checkout / "source.py").stat().st_size == 8192


def test_clone_measurement_does_not_follow_repository_symlinks(tmp_path):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "huge").write_bytes(b"x" * (2 * 1024 * 1024))
    try:
        (checkout / "link").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")
    assert _clone_disk_usage(str(checkout), 1024 * 1024) < 1024 * 1024
    with pytest.raises(CloneSizeError, match="destination is an unexpected symlink"):
        _clone_disk_usage(str(checkout / "link"), 1024 * 1024)


@pytest.mark.skipif(os.name != "posix", reason="process-group assertion uses POSIX signals")
def test_clone_size_limit_stops_transport_descendants(tmp_path, index):
    checkout = tmp_path / "repo"
    survivor = tmp_path / "survivor"
    code = (
        "import pathlib, subprocess, sys, time; "
        "p=pathlib.Path(sys.argv[1]); p.mkdir(); "
        "subprocess.Popen([sys.executable, '-c', "
        "'import pathlib,time,sys;time.sleep(0.8);pathlib.Path(sys.argv[1]).write_text(\"survived\")', "
        "sys.argv[2]]); (p/'oversize').write_bytes(b'x' * 2097152); time.sleep(10)"
    )
    ctx = ConnectorContext(index=index)
    with pytest.raises(CloneSizeError, match="observed clone size exceeds clone_max_bytes"):
        run_bounded_clone(
            [sys.executable, "-c", code, str(checkout), str(survivor)],
            os.environ.copy(),
            ctx,
            timeout=5,
            destination=str(checkout),
            max_bytes=1024 * 1024,
        )
    time.sleep(1)
    assert not survivor.exists(), "the clone's child process must not survive size rejection"
