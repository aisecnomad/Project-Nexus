"""Symbolic links that lose no coverage: dangling, test code, document and directory aliases.

In the real-world benchmark, 11 of 183 scans were incomplete because of a
symbolic link. Every link pointed inside the repository: skill directories
shared between coding agents (`.claude/skills -> ../.agents/skills`), a README
or plan document linked from another directory, a model configuration linked
under a second provider, test fixtures, and two dangling links. Links are still
never followed; each rule below decides from the real paths.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")

SKILL = "---\nname: translate\ndescription: Translate strings\n---\nTranslate the UI strings.\n"


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _link(root: Path, rel: str, target: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, path)


def _scan(run_connector, root: Path, **config):
    return run_connector("code.filesystem", path=str(root), use_git=False, **config)


def test_dangling_link_inside_the_tree_is_noted(tmp_path: Path, run_connector) -> None:
    _write(tmp_path, {"app.py": "print('x')\n"})
    _link(tmp_path, ".activate.sh", "venv/bin/activate")
    _, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete
    assert any("dangling symbolic link .activate.sh" in w for w in ctx.stats.warnings)


def test_dangling_link_outside_the_tree_stays_a_gap(tmp_path: Path, run_connector) -> None:
    root = tmp_path / "repo"
    _write(root, {"app.py": "print('x')\n"})
    _link(root, "secrets.env", "../outside/missing.env")
    _, ctx = _scan(run_connector, root)
    assert ctx.stats.incomplete


def test_link_in_test_code_follows_the_test_code_policy(tmp_path: Path, run_connector) -> None:
    # A configuration alias under another name is a gap elsewhere (see below).
    _write(tmp_path, {"tests/data/settings.yml": "model: gpt-4o\n"})
    _link(tmp_path, "tests/links/config.yaml", "../data/settings.yml")
    _, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete
    assert any("symbolic link tests/links/config.yaml in test code" in w for w in ctx.stats.warnings)
    _, strict = _scan(run_connector, tmp_path, strict_coverage=True)
    assert strict.stats.incomplete


def test_directory_link_between_test_fixtures_is_covered(tmp_path: Path, run_connector) -> None:
    _write(tmp_path, {"testdata/source/config.json": '{"a": 1}\n'})
    _link(tmp_path, "testdata/links/folder-link", "../source")
    _, ctx = _scan(run_connector, tmp_path, strict_coverage=True)
    assert not ctx.stats.incomplete


@pytest.mark.parametrize(
    ("link", "target"),
    [
        ("docs/guide/README.md", "../../README.md"),
        ("PLAN-video.md", "docs/plans/2026-05-24-video.md"),
        ("providers/azure/models/codestral.toml", "../../mistral/models/codestral.toml"),
    ],
    ids=["readme", "plan", "same-name-config"],
)
def test_document_and_same_name_configuration_aliases_are_covered(
    tmp_path: Path, run_connector, link: str, target: str
) -> None:
    real = (Path(link).parent / target).as_posix()
    _write(tmp_path, {os.path.normpath(real): "name = 'x'\n"})
    _link(tmp_path, link, target)
    _, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete, ctx.stats.warnings


def test_configuration_alias_under_another_name_stays_a_gap(tmp_path: Path, run_connector) -> None:
    _write(tmp_path, {"config/base.yaml": "model: gpt-4o\n"})
    _link(tmp_path, "config/settings.yaml", "base.yaml")
    _, ctx = _scan(run_connector, tmp_path)
    assert ctx.stats.incomplete


def test_shared_skill_directory_is_covered_and_keeps_its_alias_evidence(
    tmp_path: Path, run_connector
) -> None:
    _write(tmp_path, {".agents/skills/translate/SKILL.md": SKILL})
    _link(tmp_path, ".claude/skills", "../.agents/skills")
    findings, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    locations = {e.location.split(":")[0] for f in findings for e in f.evidence}
    assert ".claude/skills/translate/SKILL.md" in locations


@pytest.mark.parametrize(
    ("files", "link", "target"),
    [
        (
            {"tools/agents/reviewer.md": "---\nname: reviewer\n---\nReview.\n"},
            ".claude/agents",
            "../tools/agents",
        ),
        (
            {"shared/skills/x/SKILL.md": SKILL, "shared/skills/x/package.json": '{"name": "x"}'},
            ".claude/skills",
            "../shared/skills",
        ),
        ({"shared/skills/x/SKILL.md": SKILL}, "tests/skills", "../shared/skills"),
        ({"shared/x/SKILL.md": SKILL}, "shared/x/loop", ".."),
    ],
    ids=["agent-definition-directory", "nested-project", "test-classification", "cycle"],
)
def test_directory_links_that_change_how_files_are_read_stay_gaps(
    tmp_path: Path, run_connector, files, link: str, target: str
) -> None:
    _write(tmp_path, files)
    _link(tmp_path, link, target)
    _, ctx = _scan(run_connector, tmp_path, include_tests=True)
    assert ctx.stats.incomplete


def test_directory_link_with_a_link_inside_stays_a_gap(tmp_path: Path, run_connector) -> None:
    _write(tmp_path, {"shared/skills/x/SKILL.md": SKILL})
    _link(tmp_path, "shared/skills/x/extra.md", "SKILL.md")
    _link(tmp_path, ".claude/skills", "../shared/skills")
    _, ctx = _scan(run_connector, tmp_path)
    assert ctx.stats.incomplete
