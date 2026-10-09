"""The real-world runner must not continue on a tool-mutated corpus."""

from pathlib import Path

import pytest

from tools.benchmark import realworld_run as runner


@pytest.mark.parametrize("mutation", ["head", "ignored", "git-error"])
def test_post_tool_verification_rejects_all_checkout_changes(tmp_path, monkeypatch, mutation):
    spec = runner.RepoSpec(
        "sample", "https://example.test/sample", "a" * 40, "none", "none", "easy", "fixture"
    )
    (tmp_path / spec.repo_id / ".git").mkdir(parents=True)

    def git(args: list[str], cwd: Path | None = None) -> tuple[int, str]:
        assert cwd == tmp_path / spec.repo_id
        if args == ["rev-parse", "HEAD"]:
            return 0, "b" * 40 if mutation == "head" else spec.sha
        assert args == ["status", "--porcelain", "--untracked-files=all", "--ignored"]
        if mutation == "git-error":
            return 1, ""
        return 0, "!! ignored.json" if mutation == "ignored" else ""

    monkeypatch.setattr(runner, "_git", git)
    with pytest.raises(RuntimeError, match="corpus integrity changed after fixture-tool"):
        runner.verify_after_tool([spec], tmp_path, "fixture-tool")


def test_post_tool_verification_accepts_pinned_clean_checkout(tmp_path, monkeypatch):
    spec = runner.RepoSpec(
        "sample", "https://example.test/sample", "a" * 40, "none", "none", "easy", "fixture"
    )
    (tmp_path / spec.repo_id / ".git").mkdir(parents=True)
    monkeypatch.setattr(
        runner, "_git", lambda args, cwd=None: (0, spec.sha if args[0] == "rev-parse" else "")
    )
    runner.verify_after_tool([spec], tmp_path, "fixture-tool")
