"""Remote repository clone budgets and honest coverage reporting."""

from __future__ import annotations

import base64
import hashlib
import os
import sys
import time
from threading import Event, Timer
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.models import Kind, ScanStats
from shadowscan.utils import git as git_module
from shadowscan.utils.git import CloneTimeoutError, run_bounded_clone
from shadowscan.utils.http import HttpError


@pytest.mark.parametrize("cls,record", [
    (GitHubConnector, {"full_name": "org/repo", "size": 2}),
    (GitLabConnector, {"path_with_namespace": "org/repo", "statistics": {"repository_size": 2048}}),
])
def test_oversized_repository_uses_incomplete_api_fallback(tmp_path, monkeypatch, index, cls, record):
    ctx = ConnectorContext(config={"clone_max_bytes": 1024}, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    clone = Mock(side_effect=AssertionError("oversized clone must not launch"))
    monkeypatch.setattr(connector, "_clone", clone)
    monkeypatch.setattr(connector, "_fetch_via_api", lambda repo, tmp: tmp)
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path)
    assert ctx.stats.incomplete
    assert any("exceeds clone_max_bytes" in message for message in ctx.stats.warnings)
    clone.assert_not_called()


def test_gitlab_requests_size_when_group_listing_omits_statistics(tmp_path, monkeypatch, index):
    ctx = ConnectorContext(config={"clone_max_bytes": 1024}, index=index)
    ctx.stats = ScanStats(connector="code.gitlab", started_at="2026-01-01T00:00:00Z")
    connector = GitLabConnector(ctx)
    connector.http.try_get_json = Mock(return_value={"statistics": {"repository_size": 2048}})
    clone = Mock(side_effect=AssertionError("oversized clone must not launch"))
    monkeypatch.setattr(connector, "_clone", clone)
    monkeypatch.setattr(connector, "_fetch_via_api", lambda repo, tmp: tmp)
    assert connector._fetch({"id": 123, "path_with_namespace": "org/repo"}, str(tmp_path)) == str(tmp_path)
    connector.http.try_get_json.assert_called_once_with("/projects/123", params={"statistics": "true"})
    assert ctx.stats.incomplete
    clone.assert_not_called()


@pytest.mark.parametrize("cls,record", [
    (GitHubConnector, {"full_name": "org/repo", "size": 1}),
    (GitLabConnector, {"path_with_namespace": "org/repo", "statistics": {"repository_size": 1024}}),
])
def test_known_size_below_cap_can_complete(tmp_path, monkeypatch, index, cls, record):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    monkeypatch.setattr(connector, "_clone", lambda repo, dest: True)
    monkeypatch.setattr(
        f"{cls.__module__}.read_git_snapshot",
        lambda path, timeout: {"commit_sha": "a" * 40, "tree_sha": "b" * 40},
    )
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path / "repo")
    assert not ctx.stats.incomplete
    assert record["source_snapshot"]["commit_sha"] == "a" * 40


@pytest.mark.parametrize("cls,record", [
    (GitHubConnector, {"full_name": "org/repo", "size": 1}),
    (GitLabConnector, {"path_with_namespace": "org/repo", "id": 123}),
])
def test_requested_clone_without_git_uses_incomplete_api_fallback(tmp_path, monkeypatch, index, cls, record):
    ctx = ConnectorContext(config={"mode": "clone"}, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    monkeypatch.setattr(f"{cls.__module__}.shutil.which", lambda name: None)
    clone = Mock(side_effect=AssertionError("git is unavailable"))
    monkeypatch.setattr(connector, "_clone", clone)
    monkeypatch.setattr(connector, "_fetch_via_api", lambda repo, tmp: tmp)
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path)
    assert ctx.stats.incomplete
    assert any("git is unavailable" in message for message in ctx.stats.warnings)
    clone.assert_not_called()


def test_unknown_code_provider_mode_is_rejected(index):
    for cls in (GitHubConnector, GitLabConnector):
        with pytest.raises(ConnectorError, match="mode must be"):
            cls(ConnectorContext(config={"mode": "unknown"}, index=index))


@pytest.mark.parametrize("cls,record", [
    (GitHubConnector, {"full_name": "org/repo"}),
    (GitLabConnector, {"path_with_namespace": "org/repo", "id": 123}),
])
def test_unknown_size_uses_api_without_cloning(tmp_path, monkeypatch, index, cls, record):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    if cls is GitLabConnector:
        connector.http.try_get_json = Mock(return_value={})
    clone = Mock(side_effect=AssertionError("a repository without a size estimate must not be cloned"))
    monkeypatch.setattr(connector, "_clone", clone)
    monkeypatch.setattr(connector, "_fetch_via_api", lambda repo, tmp: tmp)
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path)
    assert ctx.stats.incomplete
    assert any("size metadata unavailable" in message for message in ctx.stats.warnings)
    clone.assert_not_called()


@pytest.mark.parametrize("cls,record", [
    (GitHubConnector, {"full_name": "org/repo", "size": 0}),
    (GitLabConnector, {"path_with_namespace": "org/repo", "statistics": {"repository_size": 0}}),
])
def test_zero_size_is_a_valid_estimate(tmp_path, monkeypatch, index, cls, record):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    if cls is GitLabConnector:
        connector.http.try_get_json = Mock(side_effect=AssertionError("valid zero size needs no detail lookup"))
    monkeypatch.setattr(connector, "_clone", lambda repo, dest: True)
    monkeypatch.setattr(
        f"{cls.__module__}.read_git_snapshot",
        lambda path, timeout: {"commit_sha": "a" * 40, "tree_sha": "b" * 40},
    )
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path / "repo")
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("cls,record", [
    (GitHubConnector, {"full_name": "org/repo", "size": 1}),
    (GitLabConnector, {"path_with_namespace": "org/repo", "statistics": {"repository_size": 1}}),
])
def test_failed_partial_clone_is_removed_before_api_fallback(tmp_path, monkeypatch, index, cls, record):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)

    def partial_clone(repo, dest):
        os.makedirs(dest)
        with open(os.path.join(dest, "stale-agent.py"), "w") as output:
            output.write("stale")
        return False

    def api_fetch(repo, tmp):
        assert not (tmp_path / "repo").exists()
        return tmp

    monkeypatch.setattr(connector, "_clone", partial_clone)
    monkeypatch.setattr(connector, "_fetch_via_api", api_fetch)
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path)
    assert ctx.stats.incomplete


def test_github_partial_clone_symlink_cannot_redirect_api_fallback(tmp_path, monkeypatch, index):
    outside = tmp_path / "outside"
    outside.mkdir()
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="code.github", started_at="2026-01-01T00:00:00Z")
    connector = GitHubConnector(ctx)

    def unsafe_clone(repo, dest):
        os.symlink(outside, dest)
        return False

    monkeypatch.setattr(connector, "_clone", unsafe_clone)
    fallback = Mock(side_effect=AssertionError("API fallback must not write through the symlink"))
    monkeypatch.setattr(connector, "_fetch_via_api", fallback)
    with pytest.raises(ConnectorError, match="symlink"):
        connector._fetch_repo({"full_name": "org/repo", "size": 1}, str(tmp_path))
    assert outside.is_dir()
    assert ctx.stats.incomplete
    fallback.assert_not_called()


def test_github_api_fallback_keeps_valid_blob_and_marks_partial_tree_incomplete(tmp_path, index):
    ctx = ConnectorContext(config={"mode": "api"}, index=index)
    ctx.stats = ScanStats(connector="code.github", started_at="2026-01-01T00:00:00Z")
    connector = GitHubConnector(ctx)
    source = b"from crewai import Agent\n"
    blob_id = hashlib.sha1(f"blob {len(source)}\0".encode() + source).hexdigest()
    tree = {"truncated": True, "tree": [
        {"type": "blob", "mode": "100644", "path": "agents/valid.py", "sha": blob_id, "size": len(source)},
        {"type": "blob", "mode": "100644", "path": "agents/invalid.py", "sha": "invalid", "size": 24},
        {"type": "blob", "mode": "120000", "path": "agents/link.py", "sha": "b" * 40},
    ]}

    def response(path, **kwargs):
        if "/git/trees/" in path:
            return tree
        assert path.endswith(f"/git/blobs/{blob_id}")
        return {"encoding": "base64", "content": base64.b64encode(source).decode()}

    connector.http.try_get_json = Mock(side_effect=response)
    local = connector._fetch_via_api({"full_name": "org/repo", "default_branch": "main"}, str(tmp_path))
    assert local is not None
    assert (tmp_path / "repo/agents/valid.py").read_bytes() == source
    assert not (tmp_path / "repo/agents/invalid.py").exists()
    assert not (tmp_path / "repo/agents/link.py").exists()
    assert ctx.stats.incomplete
    assert connector.http.try_get_json.call_count == 2


def test_github_repo_secrets_preserve_valid_names_when_optional_endpoint_is_denied(index):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector="code.github", started_at="2026-01-01T00:00:00Z")
    connector = GitHubConnector(ctx)

    def list_names(path, **kwargs):
        if path.endswith("/actions/variables"):
            raise HttpError(403, "https://api.github.com/repos/org/repo/actions/variables")
        if path.endswith("/actions/secrets"):
            return iter([{"name": "OPENAI_API_KEY"}, {"name": "OPENAI_API_KEY"}])
        return iter([])

    connector.http.paginate_link = Mock(side_effect=list_names)
    findings = list(connector._repo_level_findings({
        "full_name": "org/repo", "owner": {"login": "org"}, "html_url": "https://github.com/org/repo",
    }))
    assert len(findings) == 1
    assert findings[0].kind is Kind.SECRET
    assert findings[0].metadata["secret_names"] == ["OPENAI_API_KEY"]
    assert ctx.stats.incomplete
    assert any("metadata HTTP 403" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("cls,record", [
    (GitHubConnector, {"full_name": "org/repo", "size": 1, "clone_url": "https://github.com/org/repo.git"}),
    (GitLabConnector, {"path_with_namespace": "org/repo", "statistics": {"repository_size": 1},
                       "http_url_to_repo": "https://gitlab.com/org/repo.git"}),
])
def test_clone_timeout_marks_api_fallback_incomplete(tmp_path, monkeypatch, index, cls, record):
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    monkeypatch.setattr(f"{cls.__module__}.run_bounded_clone", Mock(side_effect=CloneTimeoutError("timed out")))
    monkeypatch.setattr(connector, "_fetch_via_api", lambda repo, tmp: tmp)
    fetch = connector._fetch_repo if cls is GitHubConnector else connector._fetch
    assert fetch(record, str(tmp_path)) == str(tmp_path)
    assert ctx.stats.incomplete


@pytest.mark.parametrize("setting,value", [
    ("clone_max_bytes", 0), ("clone_max_bytes", True), ("clone_max_bytes", 1.25),
    ("clone_timeout_seconds", 0), ("clone_timeout_seconds", float("inf")),
    ("clone_timeout_seconds", float("nan")),
])
def test_invalid_clone_limits_rejected(index, setting, value):
    for cls in (GitHubConnector, GitLabConnector):
        with pytest.raises(ValueError, match=setting):
            cls(ConnectorContext(config={setting: value}, index=index))


def test_windows_clone_shutdown_requests_descendant_termination(monkeypatch):
    class FakeProc:
        pid = 123
        killed = False

        def poll(self):
            return None if not self.killed else -9

        def kill(self):
            self.killed = True

        def wait(self, timeout):
            return -9

    proc = FakeProc()
    taskkill = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(git_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(git_module.subprocess, "run", taskkill)
    git_module._stop_clone(proc)
    assert taskkill.call_args.args[0] == ["taskkill", "/F", "/T", "/PID", "123"]
    assert proc.killed


@pytest.mark.skipif(os.name != "posix", reason="process-group assertion uses POSIX signals")
def test_clone_timeout_kills_git_transport_subprocess(tmp_path, index):
    marker = tmp_path / "spawned"
    survivor = tmp_path / "survivor"
    code = (
        "import pathlib, subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', "
        "'import pathlib,time,sys;time.sleep(0.9);pathlib.Path(sys.argv[1]).write_text(\"survived\")', "
        "sys.argv[2]]); pathlib.Path(sys.argv[1]).write_text('started'); time.sleep(10)"
    )
    ctx = ConnectorContext(index=index)
    started = time.monotonic()
    with pytest.raises(CloneTimeoutError):
        run_bounded_clone([sys.executable, "-c", code, str(marker), str(survivor)],
                          os.environ.copy(), ctx, timeout=0.4)
    assert time.monotonic() - started < 3
    assert marker.exists(), "the descendant should have launched before the deadline"
    time.sleep(1)
    assert not survivor.exists(), "a child process must not survive the clone timeout"


@pytest.mark.skipif(os.name != "posix", reason="process-group assertion uses POSIX signals")
def test_clone_cancellation_kills_child_process(tmp_path, index):
    pidfile = tmp_path / "pid"
    ctx = ConnectorContext(index=index, cancelled=Event())
    command = [sys.executable, "-c", "import os,pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(10)", str(pidfile)]
    timer = Timer(0.35, ctx.cancelled.set)
    timer.start()
    try:
        with pytest.raises(ConnectorError, match="deadline"):
            run_bounded_clone(command, os.environ.copy(), ctx, timeout=5)
    finally:
        timer.cancel()
    assert pidfile.exists()
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)
