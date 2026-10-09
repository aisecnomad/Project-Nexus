"""Tests for incremental diff-based scanning (Priority 4c).

Covers ``validate_diff_base``, ``diff_changed_files``, the
``_diff_included`` filter, and end-to-end diff-mode scanning through
``run_connector``.
"""

from __future__ import annotations

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
