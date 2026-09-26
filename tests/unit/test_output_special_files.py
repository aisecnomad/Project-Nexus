"""Report outputs must never replace a device node, pipe or other special file.

Renaming a private temporary file over an existing path is right for regular
files, but for ``-o /dev/null`` run as root it replaces the system's null
device with a regular file. These tests use a named pipe, a pseudo-terminal
and a socket so a regression cannot damage the host running them.
"""

from __future__ import annotations

import errno
import json
import os
import select
import socket
import stat
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.utils import output
from shadowscan.utils.output import write_private_text


def _drain(fd: int) -> bytes:
    chunks = []
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError as exc:
            if exc.errno == errno.EAGAIN:
                break
            raise
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def test_report_to_named_pipe_is_written_in_place(tmp_path):
    pipe = tmp_path / "report.pipe"
    os.mkfifo(pipe)
    # A non-blocking reader lets the writer open the pipe, and lets a
    # regression that renames over the pipe fail instead of hanging.
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        write_private_text(pipe, "report body")
        assert stat.S_ISFIFO(os.lstat(pipe).st_mode)
        assert _drain(reader) == b"report body"
    finally:
        os.close(reader)
    assert [entry.name for entry in tmp_path.iterdir()] == ["report.pipe"]


def test_report_to_character_device_is_written_in_place():
    termios = pytest.importorskip("termios")
    try:
        controller, terminal = os.openpty()
    except OSError:
        pytest.skip("pseudo-terminals are unavailable")
    try:
        device = os.ttyname(terminal)
        attrs = termios.tcgetattr(terminal)
        attrs[1] &= ~termios.OPOST  # deliver the bytes unchanged
        termios.tcsetattr(terminal, termios.TCSANOW, attrs)
        write_private_text(device, "report body")
        assert stat.S_ISCHR(os.lstat(device).st_mode)
        ready, _, _ = select.select([controller], [], [], 5)
        assert ready, "nothing was written to the character device"
        assert os.read(controller, 1024) == b"report body"
    finally:
        os.close(terminal)
        os.close(controller)


def test_report_refuses_a_socket_without_replacing_it():
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        path = Path(directory) / "s"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(path))
            with pytest.raises(ValueError, match="non-regular"):
                write_private_text(path, "report body")
            assert stat.S_ISSOCK(os.lstat(path).st_mode)
            assert sorted(entry.name for entry in Path(directory).iterdir()) == ["s"]
        finally:
            server.close()


def test_report_refuses_a_directory_without_touching_it(tmp_path):
    target = tmp_path / "reports"
    target.mkdir()
    (target / "kept").write_text("kept")
    with pytest.raises(ValueError, match="non-regular"):
        write_private_text(target, "report body")
    assert (target / "kept").read_text() == "kept"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["reports"]


def test_in_place_write_rechecks_the_opened_file_type(tmp_path, monkeypatch):
    # Simulate a regular file swapped in after the type check: the in-place
    # path must not write it without the atomic private-mode replacement.
    target = tmp_path / "report"
    target.write_text("previous")
    monkeypatch.setattr(output, "_existing_mode", lambda path: stat.S_IFIFO | 0o600)
    with pytest.raises(ValueError, match="changed type"):
        write_private_text(target, "report body")
    assert target.read_text() == "previous"


def test_cli_report_to_named_pipe_keeps_the_pipe(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    pipe = tmp_path / "report.pipe"
    os.mkfifo(pipe)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        result = CliRunner().invoke(main, ["code", str(source), "--format", "json", "-o", str(pipe)])
        received = _drain(reader)
    finally:
        os.close(reader)
    assert result.exit_code == 0, result.output
    assert stat.S_ISFIFO(os.lstat(pipe).st_mode)
    assert "findings" in json.loads(received)
