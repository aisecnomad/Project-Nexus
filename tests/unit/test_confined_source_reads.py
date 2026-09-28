"""Local code scans read every file relative to the opened scan root.

The walk lists directories by path. A directory that is replaced by a link to
somewhere else after it was listed must not redirect the read: each path
component below the root is opened without following links, so the read
fails, the gap is reported, and content outside the tree is never analyzed.
Directories are opened only for traversal, so like a read by path this needs
no read permission on them: a checkout below a mode 0711 home directory is
scanned completely.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path, PurePosixPath

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.utils.files import open_confined_directory, open_confined_file, read_policy_text
from shadowscan.utils.text import read_text

OUTSIDE_AGENT = "from crewai import Agent\nAgent(role='researcher')\n"
LINK_REASON = "a path component is a link or not a directory"


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
        raise OSError(errno.ELOOP, "Too many levels of symbolic links", str(path))

    monkeypatch.setattr("shadowscan.connectors.code.filesystem.open_confined_directory", replaced)
    findings, ctx = _run(index, tmp_path, **({"label": label} if label else {}))
    assert findings == [] and ctx.stats.objects_examined == 0
    assert ctx.stats.incomplete
    # Like its findings, a labeled root is named by the label, not its local path.
    assert ctx.stats.errors == [
        f"code.filesystem: {label or tmp_path}: could not open the scan root safely ({LINK_REASON})",
    ]


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (PermissionError(errno.EACCES, "Permission denied"), "permission denied"),
        (PermissionError(errno.EPERM, "Operation not permitted"), "permission denied"),
        (FileNotFoundError(errno.ENOENT, "No such file or directory"), "not found"),
        (NotADirectoryError(errno.ENOTDIR, "Not a directory"), LINK_REASON),
        (OSError(errno.EIO, "Input/output error"), "EIO"),
        (OSError("no error number"), "OSError"),
        (
            ValueError("secure file access is unavailable on this platform"),
            "secure file access is unavailable on this platform",
        ),
    ],
)
def test_scan_root_open_failure_names_its_reason_not_its_path(tmp_path, index, monkeypatch, failure, reason):
    (tmp_path / "crew.py").write_text(OUTSIDE_AGENT)

    def replaced(path):
        if isinstance(failure, OSError) and failure.errno is not None:
            raise type(failure)(failure.errno, failure.strerror, str(path))
        raise failure

    monkeypatch.setattr("shadowscan.connectors.code.filesystem.open_confined_directory", replaced)
    findings, ctx = _run(index, tmp_path, label="repository")
    assert findings == [] and ctx.stats.incomplete
    assert ctx.stats.errors == [
        f"code.filesystem: repository: could not open the scan root safely ({reason})",
    ]
    assert str(tmp_path) not in "".join(ctx.stats.errors)


def _traverse_only(monkeypatch: pytest.MonkeyPatch, *names: str) -> list[int]:
    """Make opening the directories ``names`` fail unless they are opened only for traversal.

    This is what the kernel does for a directory with search but no read
    permission (mode 0711 seen by another user): ``O_PATH`` opens succeed, and
    ``O_RDONLY`` opens fail with ``EACCES``. Returns the flags of each open.
    """
    real_open = os.open
    flags_seen: list[int] = []

    def opener(path, flags, mode=0o777, *, dir_fd=None):
        if os.fspath(path) in names and dir_fd is not None:
            flags_seen.append(flags)
            if not flags & getattr(os, "O_PATH", 0):
                raise PermissionError(errno.EACCES, "Permission denied", path)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", opener)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, opener})
    return flags_seen


def _repository_below_traverse_only_home(tmp_path: Path) -> Path:
    repository = tmp_path / "home" / "alice" / "repository"
    (repository / "agents").mkdir(parents=True)
    (repository / "agents" / "crew.py").write_text(OUTSIDE_AGENT)
    (repository / "CODEOWNERS").write_text("*.py @alice-team\n")
    return repository


@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="traversal-only directory opens need O_PATH")
@pytest.mark.parametrize("single_file", [False, True], ids=["directory-root", "single-file-root"])
def test_scan_below_a_traverse_only_ancestor_is_complete(tmp_path, index, monkeypatch, single_file):
    repository = _repository_below_traverse_only_home(tmp_path)
    # A single file is read relative to its directory, which is traverse-only too.
    flags_seen = _traverse_only(monkeypatch, "alice", "agents")
    findings, ctx = _run(index, repository / "agents" / "crew.py" if single_file else repository)
    assert not ctx.stats.incomplete and ctx.stats.errors == []
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    if not single_file:
        project = next(finding for finding in findings if finding.resource_type == "project")
        assert project.owner == "@alice-team"  # CODEOWNERS is read below the same ancestor
    assert flags_seen and all(flags & os.O_NOFOLLOW and flags & os.O_DIRECTORY for flags in flags_seen)


@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="traversal-only directory opens need O_PATH")
def test_confined_file_reads_below_a_traverse_only_ancestor(tmp_path, monkeypatch):
    (tmp_path / "home" / "alice").mkdir(parents=True)
    policy = tmp_path / "home" / "alice" / "policy.yaml"
    policy.write_text("rules: []\n")
    _traverse_only(monkeypatch, "alice")
    assert read_policy_text(policy) == "rules: []\n"
    directory = open_confined_directory(tmp_path / "home" / "alice")
    try:
        errors: list[str] = []
        assert read_text(PurePosixPath("policy.yaml"), 100, errors, dir_fd=directory) == "rules: []\n"
        assert errors == []
    finally:
        os.close(directory)


def _search_only(directory: Path) -> bool:
    """Drop read permission on ``directory``; False when this process can read it anyway."""
    directory.chmod(0o311)
    try:
        os.close(os.open(directory, os.O_RDONLY | os.O_DIRECTORY))
    except PermissionError:
        return True
    return False  # root, or CAP_DAC_READ_SEARCH: directory permissions are not enforced


# Where neither exists, a directory above the root is opened for reading.
_SEARCH_ONLY_ANCESTORS = hasattr(os, "O_PATH") or hasattr(os, "O_NOFOLLOW_ANY")


def test_scan_below_a_real_search_only_ancestor_is_complete(tmp_path, index):
    repository = _repository_below_traverse_only_home(tmp_path)
    home = tmp_path / "home" / "alice"
    try:
        if not _search_only(home):
            pytest.skip("this process bypasses directory read permission")
        findings, ctx = _run(index, repository)
        single_findings, single_ctx = _run(index, repository / "agents" / "crew.py")
    finally:
        home.chmod(0o755)
    if not _SEARCH_ONLY_ANCESTORS:
        # Such a platform cannot open the root below this ancestor: it fails closed.
        for scan in (ctx, single_ctx):
            assert scan.stats.incomplete and len(scan.stats.errors) == 1
            assert scan.stats.errors[0].endswith("could not open the scan root safely (permission denied)")
        return
    assert not ctx.stats.incomplete and ctx.stats.errors == []
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    project = next(finding for finding in findings if finding.resource_type == "project")
    assert project.owner == "@alice-team"
    assert not single_ctx.stats.incomplete and single_ctx.stats.errors == []
    assert any("framework.crewai" in finding.frameworks for finding in single_findings)


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
    (tmp_path / "real" / "nested").mkdir(parents=True)
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    for linked in (tmp_path / "linked", tmp_path / "linked" / "nested"):
        with pytest.raises(OSError):
            os.close(open_confined_directory(linked))
    directory = open_confined_directory(tmp_path / "real" / "nested")
    os.close(directory)


def test_without_o_path_the_root_is_opened_in_one_no_follow_any_call(tmp_path, monkeypatch):
    # macOS has no O_PATH. Its O_NOFOLLOW_ANY makes the kernel refuse a link in
    # any component of the path, which, like an open by path, needs only
    # search permission on the ancestors. XNU fails the open with EINVAL when
    # O_NOFOLLOW is passed as well, so the call must not carry it.
    native = hasattr(os, "O_NOFOLLOW_ANY")
    nofollow_any = getattr(os, "O_NOFOLLOW_ANY", 0x20000000)
    monkeypatch.delattr(os, "O_PATH", raising=False)
    monkeypatch.setattr(os, "O_NOFOLLOW_ANY", nofollow_any, raising=False)
    real_open = os.open
    calls: list[tuple[str, int, int | None]] = []

    def opener(path, flags, mode=0o777, *, dir_fd=None):
        calls.append((os.fspath(path), flags, dir_fd))
        # A kernel without the flag does not get it; the recorded call is the check.
        return real_open(path, flags if native else flags & ~nofollow_any, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", opener)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, opener})
    os.close(open_confined_directory(tmp_path))
    assert calls == [(str(tmp_path.absolute()), os.O_RDONLY | nofollow_any | os.O_DIRECTORY, None)]
    assert not calls[0][1] & os.O_NOFOLLOW


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
