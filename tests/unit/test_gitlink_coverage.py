"""Unavailable submodule contents must not become a complete empty scan."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code import filesystem, remote
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.models import ScanStats
from shadowscan.utils import git as git_utils
from shadowscan.utils.git import declared_submodule_paths, read_gitlink_paths, safe_git_env


def _scan(root, index, **config):
    connector = FilesystemConnector(ConnectorContext(config={"path": str(root), **config}, index=index))
    findings = connector.run()
    return findings, connector.ctx.stats


def _declare(root: Path, path="agents/hidden"):
    (root / ".gitmodules").write_text(
        f'[submodule "agent"]\n\tpath = "{path}"\n\turl = https://example.invalid/agent.git\n'
    )


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], env=safe_git_env(), capture_output=True, text=True, check=True
    ).stdout.strip()


def _repository(root, *, declarations=True, gitlink=True):
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.name", "Synthetic test")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / "requirements.txt").write_text("requests\n")
    if gitlink:
        _git(root, "update-index", "--add", "--cacheinfo", "160000," + "a" * 40 + ",agents/hidden")
    if declarations:
        _declare(root)
    _git(root, "add", "requirements.txt", *([".gitmodules"] if declarations else []))
    _git(
        root,
        *("-c", "commit.gpgsign=false", "-c", "maintenance.auto=false"),
        *("commit", "-qm", "synthetic source"),
    )
    return root


@pytest.mark.parametrize("state", ["missing", "empty", "materialized"])
@pytest.mark.parametrize("strict", [False, True])
def test_default_local_scan_checks_declarations_without_executing_git(
    tmp_path, index, monkeypatch, state, strict
):
    _declare(tmp_path)
    module = tmp_path / "agents" / "hidden"
    if state != "missing":
        module.mkdir(parents=True)
    if state == "materialized":
        (module / "requirements.txt").write_text("langgraph\n")
    forbidden = Mock(side_effect=AssertionError("default local scans may not execute Git"))
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    findings, stats = _scan(tmp_path, index, strict_coverage=strict)
    assert stats.incomplete is (state != "materialized")
    assert bool(findings) is (state == "materialized")
    if state != "materialized":
        assert "submodule agents/hidden" in (stats.errors if strict else stats.warnings)[0]
    forbidden.assert_not_called()


@pytest.mark.parametrize("exclude", [["agents"], ["agents/hidden"], ["agents/*"], ["*.gitmodules"]])
def test_explicit_exclusions_keep_submodule_paths_out_of_scope(tmp_path, index, exclude):
    _declare(tmp_path)
    _, stats = _scan(tmp_path, index, exclude=exclude)
    assert not stats.incomplete


def test_nested_materialized_module_exposes_missing_nested_declaration(tmp_path, index):
    _declare(tmp_path)
    module = tmp_path / "agents" / "hidden"
    module.mkdir(parents=True)
    _declare(module, "nested/agent")
    _, stats = _scan(tmp_path, index)
    assert stats.incomplete
    assert any("agents/hidden/nested/agent" in warning for warning in stats.warnings)


@pytest.mark.parametrize(
    "text",
    [
        '[submodule "bad"]\npath = ../outside\n',
        '[submodule "bad"]\npath = /outside\n',
        '[submodule "bad"]\npath = "unterminated\n',
        '[submodule "bad"]\nurl = https://example.invalid/repo\n',
        '[submodule "a"]\npath = x\n[submodule "b"]\npath = x\n',
        '[submodule "a"]\npath = x\npath = y\n',
        "[submodule.legacy]\npath = agents/hidden\n",
        '[DEFAULT]\npath = x\n[submodule "a"]\n',
        "not a git configuration\n",
    ],
)
def test_malformed_declarations_are_incomplete_and_keep_neighbor_findings(tmp_path, index, text):
    (tmp_path / ".gitmodules").write_text(text)
    (tmp_path / "requirements.txt").write_text("langgraph\n")
    findings, stats = _scan(tmp_path, index)
    assert findings and stats.incomplete
    assert "declarations safely" in stats.warnings[0]


def test_long_blank_runs_are_refused_before_the_quadratic_parser(monkeypatch):
    # ConfigParser rescans a blank run before "=" from each of its positions, in C
    # and holding the GIL: a 1 MiB line used to freeze the process for over an hour.
    monkeypatch.setattr(
        git_utils.ConfigParser, "read_string", Mock(side_effect=AssertionError("parser reached"))
    )
    hostile = '[submodule "x"]\n\tpath = x\n\ta' + " " * 4096 + "b\n"
    with pytest.raises(ValueError, match="blank"):
        declared_submodule_paths(hostile)
    with pytest.raises(ValueError, match="blank"):
        declared_submodule_paths('[submodule "x"]\n\tpath = "x' + "\t" * 33 + 'y"\n')


def test_hostile_declarations_end_in_linear_time_as_a_coverage_gap(tmp_path, index):
    (tmp_path / ".gitmodules").write_text('[submodule "x"]\n\tpath = x\n\ta' + " " * 40_000 + "b\n")
    (tmp_path / "requirements.txt").write_text("langgraph\n")
    started = time.monotonic()
    findings, stats = _scan(tmp_path, index)
    assert time.monotonic() - started < 2  # about 8 s before the run of blanks was refused
    assert findings and stats.incomplete
    assert "declarations safely" in stats.warnings[0]


def test_ordinary_blank_runs_still_parse():
    # Indentation and column alignment, up to the limit, and any number of blank lines.
    text = '[submodule "agent"]\n' + "\t" * 8 + "path" + " " * 32 + "=" + " " * 32 + "agents/hidden\n"
    assert declared_submodule_paths(text + "\n" * 100) == ["agents/hidden"]


def test_oversized_declarations_fail_closed(tmp_path, index, monkeypatch):
    _declare(tmp_path)
    monkeypatch.setattr(filesystem, "MAX_GITMODULES_BYTES", 16)
    _, stats = _scan(tmp_path, index)
    assert stats.incomplete and "declarations safely" in stats.warnings[0]


def test_submodule_and_declaration_symlinks_are_never_followed(tmp_path, index):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("langgraph\n")
    root = tmp_path / "root"
    root.mkdir()
    _declare(root, "linked")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    findings, stats = _scan(root, index)
    assert not findings and stats.incomplete
    assert any("submodule linked" in warning for warning in stats.warnings)
    (root / ".gitmodules").unlink()
    _declare(outside)
    (root / ".gitmodules").symlink_to(outside / ".gitmodules")
    _, stats = _scan(root, index)
    assert any("declarations safely" in warning for warning in stats.warnings)


def test_git_quoted_paths_preserve_spaces_and_ignore_urls_and_includes():
    assert declared_submodule_paths(
        '[include]\npath = /not/read\n[submodule "name"]\n'
        'path = " agent # name " # trailing comment\nurl = ext::not-executed\n'
    ) == [" agent # name "]


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize("gitlink", [False, True])
def test_opted_in_git_inventory_covers_committed_gitlinks_without_declarations(tmp_path, index, gitlink):
    root = _repository(tmp_path / "repo", declarations=False, gitlink=gitlink)
    assert read_gitlink_paths(root) == (["agents/hidden"] if gitlink else [])
    _, stats = _scan(root, index, use_git=True)
    assert stats.incomplete is gitlink


@pytest.mark.requires_git_2_45
def test_tree_inventory_does_not_execute_repository_fsmonitor(tmp_path):
    root = _repository(tmp_path / "repo", declarations=False, gitlink=True)
    hook = tmp_path / "monitor"
    marker = tmp_path / "executed"
    hook.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
    hook.chmod(0o700)
    _git(root, "config", "core.fsmonitor", str(hook))
    assert read_gitlink_paths(root) == ["agents/hidden"]
    assert not marker.exists()


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize("provider", [GitHubConnector, GitLabConnector])
@pytest.mark.parametrize("declarations", [False, True])
def test_provider_clone_marks_unmaterialized_gitlinks_incomplete(
    tmp_path, index, monkeypatch, provider, declarations
):
    source = _repository(tmp_path / "source", declarations=declarations)
    ctx = ConnectorContext(config={"mode": "clone"}, index=index, workdir=str(tmp_path))
    ctx.stats = ScanStats(connector=provider.name, started_at="2026-10-01T00:00:00Z")
    connector = provider(ctx)
    record = {
        "id": 7,
        "full_name": "acme/repo",
        "path_with_namespace": "acme/repo",
        "default_branch": "main",
        "size": 1,
        "statistics": {"repository_size": 1024},
        "clone_url": "https://github.com/acme/repo.git",
        "http_url_to_repo": "https://gitlab.com/acme/repo.git",
        "owner": {"login": "acme"},
    }

    def local_transport(cmd, env, context, timeout, **limits):
        # Exercise the production clone flags and subsequent snapshot/scan
        # path, substituting only the network transport with a local fixture.
        assert "--recurse-submodules" not in cmd
        subprocess.run(
            [*cmd[:-2], source.as_uri(), cmd[-1]], env=safe_git_env(), check=True, capture_output=True
        )
        return True

    monkeypatch.setattr(remote, "validate_url", lambda url, origin: url)
    monkeypatch.setattr(remote, "run_bounded_clone", local_transport)
    findings = list(connector._analyze_repository(record, connector._fetch, lambda repo: []))
    assert not findings and ctx.stats.incomplete
    assert record["source_snapshot"]["capture_method"] == "git-clone"
    assert sum("submodule agents/hidden" in warning for warning in ctx.stats.warnings) == 1


@pytest.mark.parametrize("reason", ["timeout", "output", "malformed", "failure"])
def test_gitlink_inventory_bounds_process_time_output_and_result(tmp_path, monkeypatch, reason):
    (tmp_path / ".git").mkdir()
    programs = {
        "timeout": "import time; time.sleep(10)",
        "output": "import sys; sys.stdout.write('x'*10000)",
        "malformed": "import sys; sys.stdout.write('not-index-output\\0')",
        "failure": "raise SystemExit(1)",
    }
    monkeypatch.setattr(
        git_utils, "metadata_git_argv_prefix", lambda: [sys.executable, "-c", programs[reason]]
    )
    monkeypatch.setattr(git_utils, "_MAX_GITLINK_OUTPUT_BYTES", 1024)
    started = time.monotonic()
    assert read_gitlink_paths(tmp_path, timeout=0.1 if reason == "timeout" else 3) is None
    assert time.monotonic() - started < 5


def test_unavailable_git_inventory_is_incomplete_and_keeps_findings(tmp_path, index, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("langgraph\n")
    monkeypatch.setattr(filesystem, "read_gitlink_paths", lambda *a, **kw: None)
    monkeypatch.setattr(FilesystemConnector, "_git_info", lambda *a: {})
    findings, stats = _scan(tmp_path, index, use_git=True)
    assert findings and stats.incomplete
    assert "could not inventory gitlinks safely" in stats.warnings[0]


@pytest.mark.parametrize("marker", ["gitfile", "symlink", "broken-symlink"])
@pytest.mark.parametrize("strict", [False, True])
def test_external_git_marker_is_incomplete_without_findings_or_subprocess(
    tmp_path, index, monkeypatch, marker, strict
):
    root = tmp_path / "source"
    root.mkdir()
    outside = tmp_path / "metadata"
    if marker == "gitfile":
        (root / ".git").write_text(f"gitdir: {outside}\n")
    else:
        if marker == "symlink":
            outside.mkdir()
        (root / ".git").symlink_to(outside, target_is_directory=True)
    forbidden = Mock(side_effect=AssertionError("external Git metadata must not start a subprocess"))
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    findings, stats = _scan(root, index, use_git=True, strict_coverage=strict)
    assert not findings and stats.incomplete
    assert any(
        "could not inventory gitlinks safely" in diagnostic
        for diagnostic in (stats.errors if strict else stats.warnings)
    )
    forbidden.assert_not_called()


def test_plain_source_directory_without_git_marker_stays_complete(tmp_path, index, monkeypatch):
    (tmp_path / "app.py").write_text('print("ordinary application")\n')
    forbidden = Mock(side_effect=AssertionError("a plain source directory needs no Git subprocess"))
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    findings, stats = _scan(tmp_path, index, use_git=True)
    assert not findings and not stats.incomplete
    forbidden.assert_not_called()
