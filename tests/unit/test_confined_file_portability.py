"""Kernel no-follow-any file access and actual macOS home/temp smoke tests.

The flag-routing tests run on every host. They do not emulate APFS or claim
that Linux validates Darwin's kernel semantics; the native tests below do.
"""

from __future__ import annotations

import errno
import os
import sys
import tempfile
from pathlib import Path, PurePosixPath

import pytest

from shadowscan.utils.files import (
    NotRegularFileError,
    open_confined_directory,
    open_confined_file,
    read_policy_text,
)


@pytest.fixture
def darwin_opens(monkeypatch):
    native = hasattr(os, "O_NOFOLLOW_ANY")
    nofollow_any = getattr(os, "O_NOFOLLOW_ANY", 0x20000000)
    monkeypatch.delattr(os, "O_PATH", raising=False)
    monkeypatch.setattr(os, "O_NOFOLLOW_ANY", nofollow_any, raising=False)
    original = os.open
    calls = []
    descriptors = []

    def opener(path, flags, mode=0o777, *, dir_fd=None):
        calls.append((os.fspath(path), flags, dir_fd))
        assert flags & nofollow_any
        assert not flags & os.O_NOFOLLOW  # XNU rejects these flags together.
        assert flags & os.O_NONBLOCK  # Opening an attacker-provided FIFO must not hang.
        assert not flags & os.O_DIRECTORY  # No ancestor is opened for reading.
        fd = original(path, flags if native else flags & ~nofollow_any, mode, dir_fd=dir_fd)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(os, "open", opener)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, opener})
    return calls, descriptors


def test_nofollow_any_file_uses_one_open_without_directory_reads(tmp_path, darwin_opens):
    source = tmp_path / "policy.yaml"
    source.write_text("rules: []\n")
    calls, descriptors = darwin_opens
    assert read_policy_text(source) == "rules: []\n"
    assert calls == [(str(source), os.O_RDONLY | os.O_NOFOLLOW_ANY | os.O_NONBLOCK, None)]
    with pytest.raises(OSError) as exc:
        os.fstat(descriptors[0])
    assert exc.value.errno == errno.EBADF


def test_nofollow_any_relative_file_keeps_the_callers_directory(tmp_path, monkeypatch):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "input.json").write_bytes(b"[]")
    directory = open_confined_directory(tmp_path)
    original = os.open
    native = hasattr(os, "O_NOFOLLOW_ANY")
    nofollow_any = getattr(os, "O_NOFOLLOW_ANY", 0x20000000)
    monkeypatch.delattr(os, "O_PATH", raising=False)
    monkeypatch.setattr(os, "O_NOFOLLOW_ANY", nofollow_any, raising=False)
    calls = []

    def opener(path, flags, mode=0o777, *, dir_fd=None):
        calls.append((os.fspath(path), flags, dir_fd))
        return original(path, flags if native else flags & ~nofollow_any, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", opener)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, opener})
    try:
        with open_confined_file(PurePosixPath("nested/input.json"), dir_fd=directory) as (stream, info):
            assert stream.read() == b"[]" and info.st_size == 2
        assert calls == [("nested/input.json", os.O_RDONLY | nofollow_any | os.O_NONBLOCK, directory)]
        os.fstat(directory)
        with pytest.raises(FileNotFoundError), open_confined_file("missing.json", dir_fd=directory):
            pass
        os.fstat(directory)  # The caller owns it on failures, too.
    finally:
        os.close(directory)


@pytest.mark.parametrize("path", [".", "../input.json", "nested/../../input.json", "/input.json"])
def test_nofollow_any_relative_paths_cannot_escape(path, darwin_opens):
    calls, _ = darwin_opens
    with (
        pytest.raises(ValueError, match="must stay below its directory"),
        open_confined_file(path, dir_fd=123),
    ):
        pass
    assert calls == []


@pytest.mark.parametrize("error", [errno.EPERM, errno.EINVAL, errno.ELOOP])
def test_nofollow_any_open_errors_never_retry_with_weaker_flags(tmp_path, monkeypatch, error):
    monkeypatch.delattr(os, "O_PATH", raising=False)
    monkeypatch.setattr(os, "O_NOFOLLOW_ANY", 0x20000000, raising=False)
    calls = []

    def denied(path, flags, mode=0o777, *, dir_fd=None):
        calls.append((path, flags, dir_fd))
        raise OSError(error, "denied")

    monkeypatch.setattr(os, "open", denied)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, denied})
    with pytest.raises(OSError) as exc, open_confined_file(tmp_path / "input.json"):
        pass
    assert exc.value.errno == error
    assert len(calls) == 1 and calls[0][1] & os.O_NOFOLLOW_ANY


@pytest.mark.parametrize("failure", ["fstat", "fdopen"])
def test_nofollow_any_closes_file_on_setup_errors(tmp_path, darwin_opens, monkeypatch, failure):
    source = tmp_path / "policy.yaml"
    source.write_text("rules: []\n")
    _, descriptors = darwin_opens
    fstat = os.fstat

    def failed(*args, **kwargs):
        raise OSError(errno.EIO, "setup failed")

    monkeypatch.setattr(os, failure, failed)
    with pytest.raises(OSError, match="setup failed"), open_confined_file(source):
        pass
    assert len(descriptors) == 1
    with pytest.raises(OSError) as exc:
        fstat(descriptors[0])
    assert exc.value.errno == errno.EBADF


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_nofollow_any_rejects_fifo_and_closes_descriptor(tmp_path, darwin_opens):
    fifo = tmp_path / "input.json"
    os.mkfifo(fifo)
    _, descriptors = darwin_opens
    with pytest.raises(NotRegularFileError), open_confined_file(fifo):
        pass
    with pytest.raises(OSError) as exc:
        os.fstat(descriptors[0])
    assert exc.value.errno == errno.EBADF


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the real Darwin kernel and filesystem")
@pytest.mark.parametrize("location", ["home", "temp"])
def test_native_macos_home_and_temp_confined_reads(location, record_property):
    # Resolve the trusted fixture parent: /var is an ordinary system symlink,
    # and the production helper intentionally rejects all ordinary symlinks.
    base = Path.home().resolve() if location == "home" else Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="shadowscan-portability-", dir=base) as temporary:
        root = Path(temporary)
        (root / "nested").mkdir()
        source = root / "nested" / "input.json"
        source.write_text("[]\n")
        assert read_policy_text(source) == "[]\n"
        directory = open_confined_directory(root)
        try:
            with open_confined_file(PurePosixPath("nested/input.json"), dir_fd=directory) as (stream, info):
                assert stream.read() == b"[]\n" and info.st_size == 3
            (root / "linked").symlink_to(root / "nested", target_is_directory=True)
            (root / "alias.json").symlink_to(source)
            for path in (PurePosixPath("linked/input.json"), PurePosixPath("alias.json")):
                with pytest.raises(OSError), open_confined_file(path, dir_fd=directory):
                    pass
                with pytest.raises(OSError), open_confined_file(root / path):
                    pass
            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            with pytest.raises(NotRegularFileError), open_confined_file(fifo):
                pass
            os.fstat(directory)
        finally:
            os.close(directory)

        # Diagnose the report's exact old directory flags without assuming
        # that every macOS/APFS installation must return EPERM for them.
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
        directory = os.open(source.anchor, flags)
        try:
            try:
                for component in source.parts[1:-1]:
                    child = os.open(component, flags, dir_fd=directory)
                    os.close(directory)
                    directory = child
            except OSError as exc:
                record_property("legacy_component_open_errno", exc.errno)
            else:
                record_property("legacy_component_open_errno", 0)
        finally:
            os.close(directory)


@pytest.mark.skipif(sys.platform != "darwin", reason="requires native Darwin permission checks")
def test_native_macos_policy_below_search_only_ancestor(tmp_path):
    root = tmp_path.resolve()
    ancestor = root / "search-only"
    ancestor.mkdir()
    source = ancestor / "policy.yaml"
    source.write_text("rules: []\n")
    directory = open_confined_directory(root)
    ancestor.chmod(0o311)
    try:
        try:
            probe = os.open(ancestor, os.O_RDONLY | os.O_DIRECTORY)
        except PermissionError:
            pass
        else:
            os.close(probe)
            pytest.skip("this process bypasses directory read permissions")
        # A read by name needs search permission on the ancestor, not read.
        assert source.read_text() == "rules: []\n"
        assert read_policy_text(source) == "rules: []\n"
        with open_confined_file(PurePosixPath("search-only/policy.yaml"), dir_fd=directory) as (stream, _):
            assert stream.read() == b"rules: []\n"
    finally:
        ancestor.chmod(0o755)
        os.close(directory)
