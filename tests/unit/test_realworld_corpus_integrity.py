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


def test_report_never_presents_errored_negative_scans_as_clean():
    # An incomplete scan of a `none` repository is not a clean result. The
    # report lists those scans and gives specificity over completed scans only.
    from tools.benchmark.realworld_report import render

    text = render(Path(__file__).resolve().parents[2] / "tools" / "benchmark" / "results-realworld")
    assert "Errors count as misses" not in text
    assert "| Project Nexus ShadowScan | 4/9 | 4/5 |" in text
