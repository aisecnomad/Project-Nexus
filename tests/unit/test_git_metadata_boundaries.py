"""Git history and local checkout authority cannot originate in API payloads."""

from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.models import ScanStats
from shadowscan.utils.git import (
    clone_environment,
    metadata_git_argv_prefix,
    metadata_git_env,
    read_git_snapshot,
    safe_git_env,
)


def _context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="code.filesystem", started_at="2026-09-23T00:00:00Z")
    return ctx


def test_metadata_policy_is_distinct_from_clone_policy(monkeypatch):
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "https:ext:file")
    monkeypatch.setenv("GIT_NO_LAZY_FETCH", "0")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "protocol.ext.allow")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "always")
    env = metadata_git_env()
    assert env["GIT_ALLOW_PROTOCOL"] == ""
    assert env["GIT_NO_LAZY_FETCH"] == "1"
    assert env["GIT_OPTIONAL_LOCKS"] == "0"
    assert env["GIT_PROTOCOL_FROM_USER"] == "0"
    config = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert config["protocol.allow"] == "never"
    assert config["core.hooksPath"] == os.devnull
    assert config["credential.helper"] == ""
    assert config["core.fsmonitor"] == "false"
    assert "protocol.ext.allow" not in config
    assert "--no-lazy-fetch" in metadata_git_argv_prefix()
    assert "--no-pager" in metadata_git_argv_prefix()
    assert "--literal-pathspecs" in metadata_git_argv_prefix()
    clone = clone_environment("https://github.com", "synthetic-token", "x-access-token")
    assert "GIT_ALLOW_PROTOCOL" not in clone
    assert "GIT_NO_LAZY_FETCH" not in clone


def test_read_git_snapshot_returns_checked_out_commit_and_tree_without_inherited_config(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = safe_git_env()
    for args in (
        ["init", "--quiet"],
        ["config", "user.email", "scanner@example.test"],
        ["config", "user.name", "Scanner Test"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)
    (repo / "requirements.txt").write_text("langchain\n")
    subprocess.run(["git", "-C", str(repo), "add", "requirements.txt"], check=True, capture_output=True, env=env)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "source"],
        check=True, capture_output=True, env=env,
    )
    expected = {
        "commit_sha": subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{commit}"], check=True, capture_output=True, text=True, env=env,
        ).stdout.strip(),
        "tree_sha": subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], check=True, capture_output=True, text=True, env=env,
        ).stdout.strip(),
    }
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "wrong.git"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.repositoryformatversion")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "9999")
    assert read_git_snapshot(repo) == expected


@pytest.mark.parametrize("output", ["main\n", "../outside\n", "a" * 39 + "\n"])
def test_read_git_snapshot_rejects_non_object_ids(monkeypatch, tmp_path, output):
    monkeypatch.setattr(
        "shadowscan.utils.git.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output),
    )
    assert read_git_snapshot(tmp_path) is None


@pytest.mark.parametrize("connector_type", [FilesystemConnector, GitHubConnector, GitLabConnector])
def test_default_scan_does_not_execute_git_for_offline_metadata(tmp_path, index, monkeypatch, connector_type):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "requirements.txt").write_text("langchain\n")
    calls = Mock(side_effect=AssertionError("default metadata scanning must not run Git"))
    monkeypatch.setattr(subprocess, "run", calls)
    config = {"path": str(repo)} if connector_type is FilesystemConnector else {"input": str(tmp_path)}
    connector = connector_type(_context(index, **config))
    findings = connector.run()
    assert findings and not connector.ctx.stats.incomplete
    calls.assert_not_called()


@pytest.mark.parametrize("value", ["true", "false", 1, [], {}])
def test_metadata_requires_explicit_boolean_opt_in(index, value):
    with pytest.raises(ConnectorError, match="use_git must be a boolean"):
        FilesystemConnector(_context(index, use_git=value))


def test_opt_in_metadata_uses_offline_policy_even_with_local_transport_config(tmp_path, index, monkeypatch):
    (tmp_path / ".git").mkdir()
    # Inspect the policy without executing a helper, transport, or attacker code.
    (tmp_path / ".git" / "config").write_text('[protocol "ext"]\nallow = always\n')
    call = Mock(return_value=SimpleNamespace(returncode=0, stdout="Known|known@example.test|2026-09-23T00:00:00Z\n"))
    monkeypatch.setattr(subprocess, "run", call)
    connector = FilesystemConnector(_context(index, use_git=True))
    assert connector._git_info(tmp_path, ".")["last_author_email"] == "known@example.test"
    cmd = call.call_args.args[0]
    assert cmd[:len(metadata_git_argv_prefix())] == metadata_git_argv_prefix()
    assert cmd[-2:] == ["--", "."]
    assert {"--no-show-signature", "--no-ext-diff", "--no-textconv"} <= set(cmd)
    assert call.call_args.kwargs["env"]["GIT_ALLOW_PROTOCOL"] == ""
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("failure", ["unsupported", "missing-history", "timeout", "missing-git"])
def test_requested_metadata_failure_is_incomplete_without_unsafe_retry(tmp_path, index, monkeypatch, failure):
    (tmp_path / ".git").mkdir()
    call = Mock(return_value=SimpleNamespace(returncode=129 if failure == "unsupported" else 128, stdout=""))
    if failure == "timeout":
        call.side_effect = subprocess.TimeoutExpired("git", 20)
    elif failure == "missing-git":
        call.side_effect = FileNotFoundError()
    monkeypatch.setattr(subprocess, "run", call)
    connector = FilesystemConnector(_context(index, use_git=True))
    assert connector._git_info(tmp_path, ".") == {}
    assert connector.ctx.stats.incomplete
    assert "Git 2.45+" in connector.ctx.stats.warnings[0]
    assert call.call_count == 1


def test_metadata_failure_preserves_code_findings(tmp_path, index, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("langchain\n")
    call = Mock(return_value=SimpleNamespace(returncode=128, stdout=""))
    monkeypatch.setattr(subprocess, "run", call)
    connector = FilesystemConnector(_context(index, path=str(tmp_path), use_git=True))
    findings = connector.run()
    assert any("framework.langchain" in finding.frameworks for finding in findings)
    assert connector.ctx.stats.incomplete and connector.ctx.stats.warnings


@pytest.mark.parametrize("marker_kind", ["file", "symlink"])
def test_external_git_metadata_is_rejected_before_process_start(tmp_path, index, monkeypatch, marker_kind):
    marker = tmp_path / ".git"
    if marker_kind == "file":
        marker.write_text("gitdir: /outside/metadata\n")
    else:
        marker.symlink_to(tmp_path / "missing")
    call = Mock(side_effect=AssertionError("external metadata must not run Git"))
    monkeypatch.setattr(subprocess, "run", call)
    connector = FilesystemConnector(_context(index, use_git=True))
    assert connector._git_info(tmp_path, ".") == {}
    assert connector.ctx.stats.incomplete
    call.assert_not_called()


@pytest.mark.parametrize("connector_type", [GitHubConnector, GitLabConnector])
@pytest.mark.parametrize("enumeration", ["explicit", "group"])
def test_live_repository_fields_cannot_scan_local_paths_or_select_internal_kinds(tmp_path, index, monkeypatch, connector_type, enumeration):
    private = tmp_path / "private"
    private.mkdir()
    (private / "requirements.txt").write_text("langchain\n")
    fetched = tmp_path / "fetched"
    fetched.mkdir()
    (fetched / "requirements.txt").write_text("crewai\n")
    github = connector_type is GitHubConnector
    config_key = ("repos" if github else "projects") if enumeration == "explicit" else ("org" if github else "group")
    config_value = ["team/repo"] if enumeration == "explicit" else "team"
    connector = connector_type(_context(index, **{config_key: config_value}))
    payload = {"id": 1, "full_name": "team/repo", "path_with_namespace": "team/repo",
               "_local_path": str(private), "_kind": "service_account"}
    connector.http.try_get_json = Mock(return_value=payload)
    connector.http.paginate_link = Mock(return_value=iter([payload]))
    if not github:
        monkeypatch.setattr(connector, "_group_identities", Mock(return_value=iter([])))
    records = list(connector.collect())
    assert len(records) == 1 and not any(key.startswith("_") for key in records[0])
    fetch = Mock(return_value=str(fetched))
    metadata = Mock(return_value=iter([]))
    monkeypatch.setattr(connector, "_fetch_repo" if github else "_fetch", fetch)
    monkeypatch.setattr(connector, "_repo_level_findings" if github else "_project_level", metadata)
    findings = list(connector.analyze(records))
    assert findings
    assert "framework.crewai" in {fw for finding in findings for fw in finding.frameworks}
    assert "framework.langchain" not in {fw for finding in findings for fw in finding.frameworks}
    fetch.assert_called_once()
    metadata.assert_called_once()


@pytest.mark.parametrize("connector_type", [GitHubConnector, GitLabConnector])
def test_plain_dictionary_cannot_supply_offline_scan_authority(tmp_path, index, monkeypatch, connector_type):
    (tmp_path / "requirements.txt").write_text("langchain\n")
    connector = connector_type(_context(index))
    fetch = Mock(return_value=None)
    monkeypatch.setattr(connector, "_fetch_repo" if connector_type is GitHubConnector else "_fetch", fetch)
    payload = {"id": 1, "full_name": "team/repo", "path_with_namespace": "team/repo",
               "_local_path": str(tmp_path), "_kind": "service_account"}
    assert not list(connector.analyze([payload]))
    fetch.assert_called_once()


@pytest.mark.parametrize("connector_type", [GitHubConnector, GitLabConnector])
def test_offline_records_keep_authority_outside_serializable_payload(tmp_path, index, connector_type):
    child = tmp_path / "repo"
    child.mkdir()
    connector = connector_type(_context(index))
    record = next(connector.load_offline(str(tmp_path)))
    assert record.local_path == str(child)
    assert "_local_path" not in json.loads(json.dumps(record))


def test_gitlab_metadata_kind_and_scope_are_assigned_by_collector(index, monkeypatch):
    connector = GitLabConnector(_context(index))
    record = {"id": 1, "name": "agent", "_kind": "duo", "_local_path": "/private", "group": "wrong"}
    monkeypatch.setattr(connector, "_optional_list", Mock(side_effect=[[record], [record], []]))
    monkeypatch.setattr(connector.http, "try_get_json", Mock(return_value={}))
    records = list(connector._group_identities("expected"))
    assert [record["_kind"] for record in records] == ["service_account", "group_access_token"]
    assert all(record["group"] == "expected" and "_local_path" not in record for record in records)
    assert len(list(connector.analyze(records))) == 2
