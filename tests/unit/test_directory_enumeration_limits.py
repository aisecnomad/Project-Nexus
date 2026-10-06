"""Enumeration limits apply before names accumulate, even when no source file is read."""

from __future__ import annotations

import threading

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code import filesystem as filesystem_module
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.connectors.code.walk import _WalkBudget, _WalkLimitError


def test_listing_limit_stops_before_retaining_excess_names(tmp_path, monkeypatch):
    examined: list[int] = []
    retained: list[int] = []

    class Entry:
        def __init__(self, number):
            self.number = number

        def is_dir(self):
            return False

        @property
        def name(self):
            retained.append(self.number)
            return f"file-{self.number}.py"

    class Listing:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def __iter__(self):
            for number in range(100_000):
                examined.append(number)
                yield Entry(number)

    monkeypatch.setattr(filesystem_module.os, "scandir", lambda path: Listing())
    with pytest.raises(_WalkLimitError, match=r"max_entries \(3\)"):
        next(filesystem_module._walk_directories(tmp_path, pytest.fail, budget=_WalkBudget(3)))
    assert examined == [0, 1, 2, 3]
    assert retained == [0, 1, 2]


@pytest.mark.parametrize("kind", ["directories", "ignored-files"])
def test_entry_limit_marks_directory_only_and_ignored_sources_incomplete(tmp_path, run_connector, kind):
    for number in range(4):
        path = tmp_path / f"entry-{number}"
        if kind == "directories":
            path.mkdir()
        else:
            path.write_text("ignored\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), max_entries=2, exclude=["*"])
    assert findings == []
    assert ctx.stats.incomplete
    assert any("max_entries (2)" in message for message in ctx.stats.errors)


def test_entry_limit_retains_findings_from_directories_already_assessed(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    child = tmp_path / "child"
    child.mkdir()
    for number in range(4):
        (child / f"ignored-{number}.txt").write_text("ordinary text\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), max_entries=3)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert ctx.stats.incomplete
    assert any("max_entries (3)" in message for message in ctx.stats.errors)


@pytest.mark.parametrize("directory", [True, False], ids=["directories", "ignored-files"])
@pytest.mark.parametrize("stop", ["cancelled", "deadline"])
def test_enumeration_checks_completion_while_entries_are_ignored(
    tmp_path, index, monkeypatch, directory, stop
):
    cancelled = threading.Event()
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "exclude": ["*"]},
        index=index,
        cancelled=cancelled,
    )
    examined: list[int] = []

    class Entry:
        name = "ignored"

        def is_dir(self):
            if stop == "cancelled":
                cancelled.set()
            else:
                ctx.deadline = 0.0
            return directory

    class Listing:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def __iter__(self):
            for number in range(100_000):
                examined.append(number)
                yield Entry()

    monkeypatch.setattr(filesystem_module.os, "scandir", lambda path: Listing())
    assert FilesystemConnector(ctx).run() == []
    assert examined == [0, 1]
    assert ctx.stats.incomplete
    assert ctx.stats.skipped
    assert ctx.stats.errors == ["connector completion deadline exceeded"]


def test_max_files_keeps_its_file_limit_independently(tmp_path, run_connector):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), max_files=1, max_entries=100)
    assert findings and ctx.stats.incomplete
    assert any("max_files (1)" in message for message in ctx.stats.errors)
    assert not any("max_entries" in message for message in ctx.stats.errors)


@pytest.mark.parametrize("connector_type", [GitHubConnector, GitLabConnector])
def test_hosted_repository_scans_forward_the_enumeration_limit(index, connector_type):
    connector = connector_type(ConnectorContext(config={"max_entries": 17}, index=index))
    assert connector._filesystem_options()["max_entries"] == 17
