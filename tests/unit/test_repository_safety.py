"""Availability and process isolation regressions for untrusted repositories."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code import filesystem
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.connectors.code.ownership import OwnershipBudget, OwnershipLimitError, codeowners_match
from shadowscan.incremental import _git_state, _HashBudget
from shadowscan.models import ScanStats
from shadowscan.utils.git import clone_environment, safe_git_env, validate_git_ref


def test_codeowners_overlapping_stars_finish_in_a_bounded_subprocess():
    # Both adjacent and separated stars previously backtracked exponentially.
    result = subprocess.run([
        sys.executable, "-c",
        "from shadowscan.connectors.code.ownership import codeowners_match; "
        "assert not codeowners_match('*' * 12 + 'b', 'a' * 45 + '.py'); "
        "assert not codeowners_match('*a' * 24 + 'b', 'a' * 80 + '.py')",
    ], capture_output=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr.decode()


def test_codeowners_path_matching_does_not_recurse():
    assert codeowners_match("/" + "**/" * 600 + "agent.py", "agent.py")


def test_codeowners_work_limit_stops_polynomial_worst_case():
    with pytest.raises(OwnershipLimitError):
        codeowners_match("*" + "a" * 200 + "b", "a" * 1_000, OwnershipBudget(2_000))


def test_codeowners_exhaustion_keeps_findings_and_marks_ownership_incomplete(tmp_path, run_connector, monkeypatch):
    (tmp_path / "CODEOWNERS").write_text("*.py @owner\n")
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    monkeypatch.setattr(filesystem, "OwnershipBudget", lambda _remaining: OwnershipBudget(1))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert all(finding.owner is None for finding in findings)
    assert ctx.stats.incomplete
    assert sum("CODEOWNERS processing budget" in issue for issue in ctx.stats.errors) == 1


def test_codeowners_rule_limit_never_uses_partial_rules(tmp_path, run_connector, monkeypatch):
    (tmp_path / "CODEOWNERS").write_text("*.py @incorrect\n*.py @correct\n")
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    monkeypatch.setattr(filesystem, "MAX_RULES", 1)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert findings and all(finding.owner is None for finding in findings)
    assert ctx.stats.incomplete
    assert any("CODEOWNERS rule limit" in issue for issue in ctx.stats.errors)


@pytest.mark.parametrize("branch", [" main", "main ", "main.", "heads/.hidden", "heads.lock/main"])
def test_git_ref_validation_never_rewrites_or_accepts_invalid_components(branch):
    assert validate_git_ref(branch) is None


def test_git_environment_discards_injected_configs_and_execution_overrides(monkeypatch):
    hostile = {
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url.file:///tmp/evil.insteadOf",
        "GIT_CONFIG_VALUE_0": "https://github.com/", "GIT_CONFIG_KEY_999": "core.hooksPath",
        "GIT_CONFIG_VALUE_999": "/tmp/evil", "GIT_TEMPLATE_DIR": "/tmp/evil",
        "GIT_DIR": "/tmp/evil", "GIT_EXEC_PATH": "/tmp/evil", "GIT_ASKPASS": "/tmp/evil",
        "SSH_ASKPASS": "/tmp/evil", "GIT_SSL_NO_VERIFY": "true",
    }
    for key, value in hostile.items():
        monkeypatch.setenv(key, value)
    env = safe_git_env()
    assert not hostile.keys() & env.keys()
    clone_env = clone_environment("https://github.com", "synthetic-token", "x-access-token")
    config = {
        clone_env[f"GIT_CONFIG_KEY_{i}"]: clone_env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(clone_env["GIT_CONFIG_COUNT"]))
    }
    assert config["core.hooksPath"] == os.devnull
    assert config["protocol.allow"] == "never"
    assert config["protocol.https.allow"] == "always"
    assert config["credential.helper"] == ""
    assert config["http.followRedirects"] == "false"
    assert base64.b64decode(config["http.https://github.com/.extraheader"].split()[-1]) == b"x-access-token:synthetic-token"
    assert "GIT_CONFIG_KEY_999" not in clone_env


@pytest.mark.parametrize("provider", ["github", "gitlab"])
@pytest.mark.parametrize("branch", ["release/1.2", "--upload-pack=evil"])
def test_clone_callers_enforce_hooks_auth_and_branch_validation(provider, branch, index, monkeypatch):
    cls = GitHubConnector if provider == "github" else GitLabConnector
    ctx = ConnectorContext(config={"token": "synthetic-token"}, index=index)
    ctx.stats = ScanStats(connector=f"code.{provider}", started_at="2026-09-23T00:00:00Z")
    connector = cls(ctx)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(cmd=cmd, **kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    repo = {
        "full_name": "acme/app", "default_branch": branch,
        "clone_url": "https://github.com/acme/app.git",
        "http_url_to_repo": "https://gitlab.com/acme/app.git",
    }
    assert connector._clone(repo, "/tmp/dest")
    assert captured["cmd"][:3] == ["git", "-c", f"core.hooksPath={os.devnull}"]
    assert all("synthetic-token" not in item for item in captured["cmd"])
    assert ("--branch" in captured["cmd"]) is (branch == "release/1.2")
    assert ctx.stats.incomplete is (branch != "release/1.2")
    assert captured["env"]["GIT_CONFIG_GLOBAL"] == os.devnull


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_api_fetch_never_silently_changes_unsupported_branch(provider, index, monkeypatch):
    cls = GitHubConnector if provider == "github" else GitLabConnector
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=f"code.{provider}", started_at="2026-09-23T00:00:00Z")
    connector = cls(ctx)

    def unexpected(*args, **kwargs):
        pytest.fail("Invalid branch must not result in a request for different content")

    monkeypatch.setattr(connector.http, "try_get_json", unexpected)
    monkeypatch.setattr(connector.http, "paginate_link", unexpected)
    assert connector._fetch_via_api({"full_name": "acme/app", "id": 1, "default_branch": " main"}, "/tmp/unused") is None
    assert ctx.stats.incomplete


def test_metadata_and_incremental_git_ignore_inherited_repo_and_config(tmp_path, index, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = safe_git_env()
    (repo / "agent.py").write_text("from crewai import Agent\n")
    for args in (
        ["init", "--quiet"], ["config", "user.email", "expected@example.test"],
        ["config", "user.name", "Expected Author"], ["add", "agent.py"],
        ["-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "initial"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "wrong.git"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.repositoryformatversion")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "9999")
    connector = FilesystemConnector(ConnectorContext(config={"use_git": True}, index=index))
    metadata = connector._git_info(repo, ".")
    assert metadata["last_author_email"] == "expected@example.test"
    assert _git_state(repo, _HashBudget())
