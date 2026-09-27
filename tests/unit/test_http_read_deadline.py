"""A response body must arrive within a wall-clock deadline, not just per read."""

from __future__ import annotations

import json
import socket
import threading
import time
from unittest.mock import Mock

import pytest
import requests
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.utils.http import DEFAULT_TIMEOUT, HttpClient


def client(**kwargs):
    return HttpClient("https://8.8.8.8", session=Mock(headers={}), **kwargs)


def slow_response(*chunks, delay):
    """A body whose later chunks arrive after ``delay`` seconds each."""
    result = requests.Response()
    result.status_code = 200
    result._content_consumed = True

    def iter_content(chunk_size):
        for number, chunk in enumerate(chunks):
            if number:
                time.sleep(delay)
            yield chunk

    result.iter_content = iter_content
    result.close = Mock()
    return result


def test_default_read_deadline_is_derived_from_the_client_timeout():
    assert client().read_deadline == 2 * DEFAULT_TIMEOUT
    assert client(timeout=5).read_deadline == 10


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, "30", None])
def test_client_timeout_must_be_a_positive_finite_number(timeout):
    with pytest.raises(ValueError, match="timeout must be a positive finite number"):
        client(timeout=timeout)


def test_body_completed_after_the_read_deadline_is_rejected():
    result = slow_response(b'{"items": ', b"[]}", delay=0.3)
    http = client(timeout=0.05)  # 0.1 second body deadline
    with pytest.raises(ValueError, match="exceeds the read deadline"):
        http.read_response_bytes(result)
    result.close.assert_called_once()


def test_body_within_the_read_deadline_is_returned():
    result = slow_response(b'{"items": ', b"[]}", delay=0.01)
    assert client(timeout=5).read_json_response(result) == {"items": []}
    result.close.assert_called_once()


def test_watchdog_shuts_down_a_blocked_read_and_its_end_of_body_is_not_trusted():
    shut_down = threading.Event()

    class Raw:
        def shutdown(self):
            shut_down.set()

    def blocked(chunk_size):
        # Model urllib3 filling one chunk from a slow-drip server: nothing is
        # returned until the socket is shut down, which then reads as a clean
        # end of a close-delimited body.
        shut_down.wait(10)
        yield b"{}"

    result = slow_response(delay=0)
    result.raw = Raw()
    result.iter_content = blocked
    started = time.monotonic()
    with pytest.raises(ValueError, match="exceeds the read deadline"):
        client(timeout=0.05).read_response_bytes(result)
    assert shut_down.is_set() and time.monotonic() - started < 5
    result.close.assert_called_once()


def test_transport_error_after_the_deadline_reports_only_the_deadline():
    class Raw:
        def __init__(self):
            self.shut_down = threading.Event()

        def shutdown(self):
            self.shut_down.set()

    raw = Raw()

    def aborted(chunk_size):
        raw.shut_down.wait(10)
        raise requests.exceptions.ChunkedEncodingError("reset while reading https://example.test/?token=secret")
        yield b""  # pragma: no cover

    result = slow_response(delay=0)
    result.raw = raw
    result.iter_content = aborted
    with pytest.raises(ValueError, match="exceeds the read deadline") as caught:
        client(timeout=0.05).read_response_bytes(result)
    assert caught.value.__context__ is None and "secret" not in str(caught.value)


def test_transport_error_before_the_deadline_is_unchanged():
    def reset(chunk_size):
        raise requests.exceptions.ChunkedEncodingError("connection reset")
        yield b""  # pragma: no cover

    result = slow_response(delay=0)
    result.iter_content = reset
    with pytest.raises(requests.exceptions.ChunkedEncodingError):
        client().read_response_bytes(result)
    result.close.assert_called_once()


def test_live_connector_read_deadline_marks_the_scan_incomplete(monkeypatch, tmp_path):
    """The deadline takes the same fail-closed path as other HTTP limits (exit 3)."""

    def request(session, method, url, **kwargs):
        result = slow_response(b'{"object": "list", "results": [], ', b'"has_more": false}', delay=0.5)
        result.url = url
        return result

    # 0.15 second deadline for the default 30 second timeout.
    monkeypatch.setattr("shadowscan.utils.http.READ_DEADLINE_FACTOR", 0.005, raising=False)
    monkeypatch.setattr(
        "shadowscan.utils.http.socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))],
    )
    monkeypatch.setattr(requests.Session, "request", request)
    monkeypatch.setenv("NOTION_TOKEN", "synthetic-notion-token")
    output = tmp_path / "report.json"

    result = CliRunner().invoke(main, ["run", "saas.notion", "--format", "json", "-o", str(output)])

    assert result.exit_code == 3, result.output
    report = json.loads(output.read_text())
    assert report["summary"]["complete"] is False
    errors = [error for stats in report["stats"] for error in stats["errors"]]
    assert any("exceeds the read deadline" in error for error in errors), errors
    assert "synthetic-notion-token" not in output.read_text()
