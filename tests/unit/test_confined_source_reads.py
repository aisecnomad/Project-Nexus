"""Local code scans read every file relative to the opened scan root.

The walk lists directories by path. A directory that is replaced by a link to
somewhere else after it was listed must not redirect the read: each path
component below the root is opened without following links, so the read
fails, the gap is reported, and content outside the tree is never analyzed.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.utils.files import open_confined_directory, open_confined_file
from shadowscan.utils.text import read_text

OUTSIDE_AGENT = "from crewai import Agent\nAgent(role='researcher')\n"


def _run(index, root: Path, **config: object):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_directory_swapped_for_a_link_after_the_walk_is_never_read(tmp_path, index, monkeypatch):
    root = tmp_path / "repository"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "package.json").write_text('{"name": "pkg"}\n')
    (root / "main.py").write_text("print('hello')\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package.json").write_text('{"dependencies": {"@langchain/langgraph": "^0.2"}}\n')
    walk = FilesystemConnector._iter_entries

    def walked_then_swapped(self, scan_root):
        entries = list(walk(self, scan_root))  # the walk sees the real directory
        (root / "pkg").rename(tmp_path / "moved")
        (root / "pkg").symlink_to(outside, target_is_directory=True)
        yield from entries

    monkeypatch.setattr(FilesystemConnector, "_iter_entries", walked_then_swapped)
    findings, ctx = _run(index, root)
    assert not any("framework.langgraph" in finding.frameworks for finding in findings)
    assert ctx.stats.incomplete
    assert ctx.stats.errors == ["code.filesystem: pkg/package.json: file could not be read"]


def test_scan_root_is_opened_once_and_files_below_it_are_read(tmp_path, index, monkeypatch):
    (tmp_path / "svc" / "agents").mkdir(parents=True)
    (tmp_path / "svc" / "agents" / "crew.py").write_text(OUTSIDE_AGENT)
    opened: list[Path] = []
    original = open_confined_directory

    def recording(path):
        opened.append(Path(path))
        return original(path)

    monkeypatch.setattr("shadowscan.connectors.code.filesystem.open_confined_directory", recording)
    findings, ctx = _run(index, tmp_path)
    assert opened == [tmp_path]
    assert not ctx.stats.incomplete
    assert any("framework.crewai" in finding.frameworks for finding in findings)


@pytest.mark.parametrize("label", [None, "github:example/service"])
def test_scan_root_that_cannot_be_opened_safely_is_incomplete(tmp_path, index, monkeypatch, label):
    (tmp_path / "crew.py").write_text(OUTSIDE_AGENT)

    def replaced(path):
        raise OSError("too many levels of symbolic links")

    monkeypatch.setattr("shadowscan.connectors.code.filesystem.open_confined_directory", replaced)
    findings, ctx = _run(index, tmp_path, **({"label": label} if label else {}))
    assert findings == [] and ctx.stats.objects_examined == 0
    assert ctx.stats.incomplete
    # Like its findings, a labeled root is named by the label, not its local path.
    assert ctx.stats.errors == [
        f"code.filesystem: {label or tmp_path}: could not open the scan root without following links",
    ]


def test_single_file_root_is_read_relative_to_its_directory(tmp_path, index):
    source = tmp_path / "crew.py"
    source.write_text(OUTSIDE_AGENT)
    findings, ctx = _run(index, source)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any("framework.crewai" in finding.frameworks for finding in findings)


def test_read_text_below_a_directory_refuses_links_in_every_component(tmp_path):
    (tmp_path / "real" / "nested").mkdir(parents=True)
    (tmp_path / "real" / "nested" / "file.txt").write_text("content")
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    (tmp_path / "real" / "alias.txt").symlink_to(tmp_path / "real" / "nested" / "file.txt")
    directory = open_confined_directory(tmp_path)
    try:
        errors: list[str] = []
        assert read_text(PurePosixPath("real/nested/file.txt"), 100, errors, dir_fd=directory) == "content"
        for relative in ("linked/nested/file.txt", "real/alias.txt"):
            assert read_text(PurePosixPath(relative), 100, errors, dir_fd=directory) is None
        assert errors == ["file could not be read"] * 2
        errors.clear()
        for relative in ("../file.txt", str(tmp_path / "real" / "nested" / "file.txt"), "."):
            assert read_text(PurePosixPath(relative), 100, errors, dir_fd=directory) is None
        assert errors == ["file path must stay below its directory"] * 3
        errors.clear()
        assert read_text(PurePosixPath("real/nested"), 100, errors, dir_fd=directory) is None
        assert errors == ["not a regular file"]
    finally:
        os.close(directory)


def test_confined_directory_refuses_a_linked_ancestor(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(OSError):
        os.close(open_confined_directory(tmp_path / "linked"))
    directory = open_confined_directory(tmp_path / "real")
    os.close(directory)


def test_confined_file_below_a_directory_leaves_the_directory_open(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.txt").write_bytes(b"data")
    directory = open_confined_directory(tmp_path)
    try:
        for _ in range(2):
            with open_confined_file(PurePosixPath("a/b.txt"), dir_fd=directory) as (stream, info):
                assert stream.read() == b"data" and info.st_size == 4
        os.fstat(directory)  # still open and owned by the caller
    finally:
        os.close(directory)
