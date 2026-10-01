"""CODEOWNERS matching, evidence ownership and the ownership step budget."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code import filesystem as fs_module
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.ownership import MAX_OWNERSHIP_STEPS, OwnershipBudget, codeowners_match
from shadowscan.models import ScanStats, now_iso


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_codeowners_globs_apply_to_evidence_files_in_last_match_order(tmp_path: Path, run_connector):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text(
        "* @default\n*.py @python\n/src/** @src\n/src/special.py @special\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "special.py").write_text("from langchain import agents\n")
    (tmp_path / "src" / "other.py").write_text("from langchain import agents\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner is None  # two evidence files have different owners
    assert project.metadata["codeowners_by_file"] == {
        "src/other.py": "@src",
        "src/special.py": "@special",
    }


def test_codeowners_basename_glob_owns_nested_source(tmp_path: Path, run_connector):
    (tmp_path / "CODEOWNERS").write_text("*.py @python\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "agent.py").write_text("from langchain import agents\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner == "@python"


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("/docs/", "docs/guides/start.md", True),
        ("/docs/", "nested/docs/start.md", False),
        ("apps/", "nested/apps/start.md", True),
        ("/apps/", "nested/apps/start.md", False),
        ("docs/*", "docs/start.md", True),
        ("docs/*", "docs/guides/start.md", False),
        ("**/logs", "deeply/nested/logs/agent.py", True),
    ],
)
def test_codeowners_directory_and_root_patterns(pattern, path, expected):
    assert codeowners_match(pattern, path) is expected


def test_codeowners_later_ownerless_rule_clears_owner(tmp_path: Path, run_connector):
    (tmp_path / "CODEOWNERS").write_text("/apps/ @team\n/apps/github\n")
    (tmp_path / "apps" / "github").mkdir(parents=True)
    (tmp_path / "apps" / "github" / "agent.py").write_text("from langchain import agents\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner is None


def test_codeowners_large_monorepo_resolves_owners_without_exhausting_the_budget(tmp_path, index):
    rules = ["* @org/everyone"] + [f"/services/service-{i}/ @org/team-{i}" for i in range(2000)]
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("\n".join(rules) + "\n")
    for j in range(120):
        package = tmp_path / "packages" / f"pkg-{j}" / "src" / "agents"
        package.mkdir(parents=True)
        (package / "orchestrator.py").write_text("from crewai import Agent\n")
    started = time.monotonic()
    findings, ctx = _run(index, tmp_path)
    assert time.monotonic() - started < 20
    assert not any("budget exceeded" in error for error in ctx.stats.errors)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner == "@org/everyone"


def test_codeowners_aggregate_budget_marks_later_ownership_incomplete(tmp_path, index, monkeypatch):
    (tmp_path / "CODEOWNERS").write_text("* @org/everyone\n")
    monkeypatch.setattr(fs_module, "MAX_ROOT_OWNERSHIP_STEPS", 24)
    ctx = ConnectorContext(config={"path": str(tmp_path)}, index=index)
    ctx.stats = ScanStats(connector="code.filesystem", started_at=now_iso())
    connector = FilesystemConnector(ctx)

    owners = [connector._owner_for(tmp_path, f"file-{i}.py") for i in range(20)]
    assert owners[0] == "@org/everyone"
    assert owners[-1] is None
    assert connector._ownership_steps_remaining[tmp_path] == 0
    assert any("CODEOWNERS" in error and "ownership incomplete" in error for error in ctx.stats.errors)
    errors_before = len(ctx.stats.errors)
    assert connector._owner_for(tmp_path, "still-unknown.py") is None
    assert len(ctx.stats.errors) == errors_before


@pytest.mark.parametrize(
    "pattern, path, expected",
    [
        ("/services/api/", "services/api/main.py", True),
        ("/services/api/", "packages/api/main.py", False),
        ("/**/api/", "packages/api/x.py", True),
        ("*.py", "a/b/c.py", True),
        ("/docs/*.md", "docs/readme.md", True),
        ("/docs/*.md", "src/docs/readme.md", False),
        ("services/*/agents/", "services/x/agents/run.py", True),
    ],
)
def test_codeowners_first_selector_short_circuit_preserves_semantics(pattern, path, expected):
    assert codeowners_match(pattern, path) is expected


def test_codeowners_non_matching_anchored_rule_is_nearly_free():
    budget = OwnershipBudget()
    assert not codeowners_match("/services/api/", "packages/api/main.py", budget)
    assert budget.remaining >= MAX_OWNERSHIP_STEPS - 5
