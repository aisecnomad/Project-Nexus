"""Tests for incremental diff-based scanning (Priority 4c).

Covers ``validate_diff_base``, ``diff_changed_files``, the
``_diff_included`` filter, and end-to-end diff-mode scanning through
``run_connector``.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.utils.git import safe_git_env

# ------------------------------------------------------------------ helpers


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = env or safe_git_env()
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def _init_repo(root: Path) -> None:
    """Create a minimal git repo with one commit on ``main``."""
    env = safe_git_env()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True, env=env)
    _git(root, "config", "user.email", "test@example.test", env=env)
    _git(root, "config", "user.name", "Test", env=env)
    # Git 2.47+ runs auto-maintenance detached after a commit; its lock file in
    # .git/objects can vanish mid-walk and make the metadata preflight refuse
    # the repository. The other git-metadata tests disable it the same way.
    _git(root, "config", "maintenance.auto", "false", env=env)
    _git(root, "config", "gc.auto", "0", env=env)
    (root / "requirements.txt").write_text("langchain\n")
    (root / "app.py").write_text("import langchain\n")
    _git(root, "add", ".", env=env)
    _git(root, "commit", "-m", "initial", "--quiet", env=env)
    _git(root, "branch", "-M", "main", env=env)


# =========================================================================
# validate_diff_base
# =========================================================================


class TestValidateDiffBase:
    """Unit tests for the diff-base ref validator."""

    @pytest.fixture(autouse=True)
    def _import(self):
        from shadowscan.utils.git import validate_diff_base

        self.validate = validate_diff_base

    @pytest.mark.parametrize(
        "ref",
        [
            "main",
            "HEAD",
            "HEAD~1",
            "HEAD~3",
            "main^2",
            "origin/main",
            "v1.0.0",
            "abc1234",
            "a" * 40,
            "feature/branch-name",
            "release/2.0",
        ],
    )
    def test_valid_refs(self, ref: str) -> None:
        assert self.validate(ref) == ref

    @pytest.mark.parametrize(
        "ref",
        [
            "",
            None,
            42,
            "-n",
            "--option",
            "@{upstream}",
            "ref@{0}",
            "a//b",
            "/absolute",
            "trailing/",
            "trailing.",
            "a\\b",
            "a" * 256,
        ],
    )
    def test_invalid_refs(self, ref) -> None:
        assert self.validate(ref) is None


# =========================================================================
# diff_changed_files
# =========================================================================


@pytest.mark.requires_git_2_45
class TestDiffChangedFiles:
    """Unit tests for ``diff_changed_files``."""

    @pytest.fixture(autouse=True)
    def _imports(self):
        from shadowscan.utils.git import DiffError, diff_changed_files

        self.diff = diff_changed_files
        self.DiffError = DiffError

    @pytest.fixture()
    def repo(self, tmp_path: Path) -> Path:
        root = tmp_path / "repo"
        root.mkdir()
        _init_repo(root)
        return root

    @pytest.fixture()
    def ctx(self, index):
        from shadowscan.connectors.base import ConnectorContext

        return ConnectorContext(config={}, index=index)

    def test_no_changes(self, repo: Path, ctx) -> None:
        result = self.diff(repo, "main", ctx)
        assert result == frozenset()

    def test_detects_changed_files(self, repo: Path, ctx) -> None:
        (repo / "new_file.py").write_text("print('hello')\n")
        (repo / "app.py").write_text("import langchain\nprint('updated')\n")
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "add files", "--quiet")
        result = self.diff(repo, "main~1", ctx)
        assert "new_file.py" in result
        assert "app.py" in result
        assert "requirements.txt" not in result

    @pytest.mark.parametrize("name", [" agent.py", "agent.py ", "agent\npart.py", "agent\tpart.py"])
    def test_preserves_exact_filename(self, repo: Path, ctx, name: str) -> None:
        (repo / name).write_text("from crewai import Agent\nworker = Agent()\n")
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "add agent", "--quiet")
        assert self.diff(repo, "main~1", ctx) == frozenset({name})

    def test_invalid_ref_raises(self, repo: Path, ctx) -> None:
        with pytest.raises(self.DiffError, match="invalid diff-base ref"):
            self.diff(repo, "--evil", ctx)

    def test_not_git_repo_raises(self, tmp_path: Path, ctx) -> None:
        plain = tmp_path / "plain"
        plain.mkdir()
        with pytest.raises(self.DiffError, match="not a git repository"):
            self.diff(plain, "main", ctx)

    def test_unresolvable_ref_raises(self, repo: Path, ctx) -> None:
        with pytest.raises(self.DiffError):
            self.diff(repo, "nonexistent_branch_xyz", ctx)

    def test_path_traversal_excluded(self, repo: Path, ctx) -> None:
        (repo / "safe.py").write_text("x = 1\n")
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "safe", "--quiet")
        result = self.diff(repo, "main~1", ctx)
        for path in result:
            assert ".." not in path.split("/")
            assert not path.startswith("/")


# =========================================================================
# _diff_included
# =========================================================================


class TestDiffIncluded:
    """Unit tests for the ``_diff_included`` static method."""

    @pytest.fixture(autouse=True)
    def _cls(self):
        self.included = FilesystemConnector._diff_included

    def test_changed_file_included(self) -> None:
        diff = frozenset({"src/app.py", "lib/util.js"})
        assert self.included("src/app.py", diff)

    def test_unchanged_file_excluded(self) -> None:
        diff = frozenset({"src/app.py"})
        assert not self.included("src/other.py", diff)

    def test_manifest_always_included(self) -> None:
        diff = frozenset({"src/app.py"})
        assert self.included("requirements.txt", diff)
        assert self.included("package.json", diff)
        assert self.included("go.mod", diff)
        assert self.included("sub/Pipfile", diff)

    def test_env_file_always_included(self) -> None:
        diff = frozenset({"src/app.py"})
        assert self.included(".env", diff)
        assert self.included(".env.local", diff)
        assert self.included("config/.env.production", diff)

    def test_regular_file_not_included(self) -> None:
        diff = frozenset({"src/app.py"})
        assert not self.included("README.md", diff)
        assert not self.included("src/utils.py", diff)


# =========================================================================
# End-to-end: diff-mode scan
# =========================================================================


@pytest.mark.requires_git_2_45
class TestDiffModeScan:
    """Integration tests: a diff-based scan via ``run_connector``."""

    @pytest.fixture()
    def repo(self, tmp_path: Path) -> Path:
        root = tmp_path / "repo"
        root.mkdir()
        _init_repo(root)
        return root

    def test_diff_scan_tags_findings(self, repo: Path, run_connector) -> None:
        """A scan with diff_base should tag findings with ``diff-scan``."""
        (repo / "agent.py").write_text(
            "from langchain.agents import AgentExecutor\nagent = AgentExecutor()\n"
        )
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "add agent", "--quiet")

        findings, ctx = run_connector("code.filesystem", path=str(repo), diff_base="main~1")
        assert findings, "expected at least one finding"
        for f in findings:
            assert "diff-scan" in f.tags
            assert "diff_scan" in f.metadata
            assert f.metadata["diff_scan"]["base_ref"] == "main~1"
            assert isinstance(f.metadata["diff_scan"]["changed_files"], int)

    def test_diff_scan_fallback_on_bad_ref(self, repo: Path, run_connector) -> None:
        """An unresolvable diff-base falls back to a full scan (no crash)."""
        findings, ctx = run_connector("code.filesystem", path=str(repo), diff_base="nonexistent_branch")
        for f in findings:
            assert "diff-scan" not in f.tags

    def test_diff_scan_empty_diff(self, repo: Path, run_connector) -> None:
        """When no files changed, the scan should still succeed (no findings from diff)."""
        findings, ctx = run_connector("code.filesystem", path=str(repo), diff_base="main")
        diff_tagged = [f for f in findings if "diff-scan" in f.tags]
        if diff_tagged:
            for f in diff_tagged:
                assert f.metadata["diff_scan"]["changed_files"] == 0


# =========================================================================
# config key registration
# =========================================================================


def test_diff_base_is_registered_config_key() -> None:
    """``diff_base`` must be a documented config key."""
    keys = FilesystemConnector.config_keys
    assert "diff_base" in keys


# =========================================================================
# A diff-scoped scan is never a repository inventory
# =========================================================================

_CREW_AGENT = (
    "from crewai import Agent, Crew, Task\n"
    'researcher = Agent(role="r", goal="g", backstory="b")\n'
    'crew = Crew(agents=[researcher], tasks=[Task(description="d", agent=researcher)])\n'
    "crew.kickoff()\n"
)


def _diff_reports(monkeypatch, changed: set[str]) -> None:
    """Have the connector see ``changed`` as the committed diff, whatever Git is installed."""
    import shadowscan.utils.git as git_utils

    monkeypatch.setattr(git_utils, "diff_changed_files", lambda root, ref, ctx, **_: frozenset(changed))


def test_diff_scoped_reports_are_not_comparable_and_never_resolve(tmp_path: Path, monkeypatch) -> None:
    """A diff window that skips an existing agent must not read as its resolution."""
    from click.testing import CliRunner

    from shadowscan.cli import main
    from shadowscan.comparison import compare_reports

    repo = tmp_path / "repo"
    (repo / "svc").mkdir(parents=True)
    (repo / "svc" / "agent.py").write_text(_CREW_AGENT)
    (repo / "README.md").write_text("# service\n")
    reports = []
    # The agent's branch, then a later branch that changes only the README.
    for number, changed in enumerate(({"svc/agent.py"}, {"README.md"})):
        _diff_reports(monkeypatch, changed)
        out = tmp_path / f"report{number}.json"
        result = CliRunner().invoke(
            main, ["code", str(repo), "--diff-base", "main", "--format", "json", "--output", str(out)]
        )
        assert result.exit_code == 0, result.output
        reports.append(json.loads(out.read_text()))
    first, second = reports
    agents = [finding for finding in first["findings"] if finding["kind"] == "agent"]
    assert len(agents) == 1
    assert second["findings"] == []
    for report in reports:
        assert report["collection_scope"]["comparable"] is False
        assert report["collection_scope"]["reason"] == "diff-scoped collection is not a repository inventory"
        warnings = [warning for stat in report["stats"] for warning in stat["warnings"]]
        assert any("not a repository inventory" in warning for warning in warnings), warnings
    comparison = compare_reports(first, second)
    assert comparison["comparable"] is False
    assert comparison["resolved"] == []
    assert [finding["id"] for finding in comparison["unknown"]] == [agents[0]["id"]]


def test_diff_scoped_scan_is_never_replayed_from_the_incremental_cache(
    tmp_path: Path, index, monkeypatch
) -> None:
    """Squashing commits changes the diff but not the working tree the cache fingerprints."""
    from shadowscan.config import ConnectorSpec, ScanConfig
    from shadowscan.engine import Engine
    from shadowscan.models import Kind

    repo = tmp_path / "repo"
    (repo / "svc").mkdir(parents=True)
    (repo / "svc" / "agent.py").write_text(_CREW_AGENT)
    (repo / "README.md").write_text("# service\n")
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo), "diff_base": "HEAD~1"})],
        incremental=True,
        state_dir=str(tmp_path / "state"),
        parallel=1,
    )
    _diff_reports(monkeypatch, {"README.md"})
    first = Engine(config, index).run()
    assert not first.findings
    _diff_reports(monkeypatch, {"README.md", "svc/agent.py"})
    second = Engine(config, index).run()
    stats = next(stat for stat in second.stats if stat.connector == "code.filesystem")
    assert not stats.cached
    assert any(finding.kind == Kind.AGENT for finding in second.findings)


@pytest.mark.parametrize(
    "remote", [["--github-repo", "octo/example"], ["--github-org", "octo"], ["--gitlab-group", "group"]]
)
def test_diff_base_without_local_paths_is_a_usage_error(remote: list[str]) -> None:
    from click.testing import CliRunner

    from shadowscan.cli import main

    result = CliRunner().invoke(main, ["code", *remote, "--diff-base", "main"])
    # A usage error (exit 1 in this CLI), not a ConfigValidationError traceback.
    assert result.exit_code == 1, result.output
    assert "--diff-base applies only to local PATHS" in result.output
    assert isinstance(result.exception, SystemExit)


def test_diff_base_with_remote_repositories_applies_only_to_local_paths(tmp_path: Path, monkeypatch) -> None:
    from click.testing import CliRunner

    import shadowscan.cli as cli

    captured = []
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: captured.append(config))
    result = CliRunner().invoke(
        cli.main,
        [
            "code",
            str(tmp_path),
            "--github-repo",
            "octo/example",
            "--gitlab-group",
            "group",
            "--diff-base",
            "main",
        ],
    )
    assert result.exit_code == 0, result.output
    specs = {spec.name: spec.config for spec in captured[0].connectors}
    assert specs["code.filesystem"]["diff_base"] == "main"
    assert "diff_base" not in specs["code.github"]
    assert "diff_base" not in specs["code.gitlab"]


def test_non_utf8_diff_output_is_a_diff_error(tmp_path: Path, index, monkeypatch) -> None:
    """Undecodable diff output takes the documented full-scan fallback instead of failing the connector."""
    import shadowscan.utils.git as git_utils
    from shadowscan.connectors.base import ConnectorContext

    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(git_utils, "require_local_git_metadata", lambda root, timeout: None)

    def undecodable(*args, **kwargs):
        raise UnicodeDecodeError("utf-8", b"notes_\xff.txt", 6, 7, "invalid start byte")

    monkeypatch.setattr(git_utils, "run_bounded_metadata", undecodable)
    with pytest.raises(git_utils.DiffError, match="not valid UTF-8"):
        git_utils.diff_changed_files(tmp_path, "main", ConnectorContext(config={}, index=index))


@pytest.mark.requires_git_2_45
def test_non_utf8_changed_path_falls_back_to_a_full_scan(tmp_path: Path, run_connector) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "agent.py").write_text(_CREW_AGENT)
    _git(repo, "add", "agent.py")
    # Stage the non-UTF-8 name through the index so no filesystem has to accept it.
    blob = _git(repo, "hash-object", "-w", "agent.py").stdout.strip()
    subprocess.run(
        [
            b"git",
            b"-C",
            os.fsencode(repo),
            b"update-index",
            b"--add",
            b"--cacheinfo",
            b"100644," + blob.encode() + b",notes_\xff.txt",
        ],
        check=True,
        capture_output=True,
        env=safe_git_env(),
    )
    _git(repo, "commit", "-m", "add agent", "--quiet")

    findings, ctx = run_connector("code.filesystem", path=str(repo), diff_base="main~1")

    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert any("not valid UTF-8" in warning and "full scan" in warning for warning in ctx.stats.warnings)
    assert any(
        finding.kind.value == "agent" and "framework.crewai" in finding.frameworks for finding in findings
    )
    assert all("diff-scan" not in finding.tags for finding in findings)
