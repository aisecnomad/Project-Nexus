"""HttpClient retries: rate-limit hints, jittered backoff and capped delays."""

from __future__ import annotations

import time
from unittest.mock import Mock

import pytest
import requests

from shadowscan.utils.http import MAX_RETRY_DELAY, HttpClient, HttpError, _rate_limited, _retry_delay


def _response(status: int, headers: dict[str, str] | None = None, body: bytes = b'{"ok": true}') -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp.headers.update(headers or {})
    resp._content = body
    resp._content_consumed = True  # type: ignore[attr-defined]
    return resp


class _ScriptedSession(requests.Session):
    def __init__(self, *responses: requests.Response):
        super().__init__()
        self.scripted = list(responses)
        self.calls = 0

    def request(self, method, url, **kwargs):  # type: ignore[override]
        self.calls += 1
        return self.scripted.pop(0)


@pytest.fixture
def sleep(monkeypatch):
    mock = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", mock)
    return mock


def _client(*responses: requests.Response) -> tuple[HttpClient, _ScriptedSession]:
    session = _ScriptedSession(*responses)
    return HttpClient("https://api.github.com", session=session), session


def test_primary_rate_limit_403_waits_for_reset_then_succeeds(sleep):
    reset = str(int(time.time()) + 30)
    http, session = _client(_response(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}), _response(200))
    assert http.get_json("/orgs/acme/repos") == {"ok": True} and session.calls == 2
    (delay,), _ = sleep.call_args
    assert 29 <= delay <= MAX_RETRY_DELAY


def test_secondary_rate_limit_403_honors_retry_after(sleep):
    http, _ = _client(_response(403, {"Retry-After": "7"}), _response(200))
    assert http.get_json("/search/code") == {"ok": True}
    (delay,), _ = sleep.call_args
    assert 7 <= delay <= 8


def test_permission_403_is_not_retried(sleep):
    http, session = _client(_response(403), _response(200))
    with pytest.raises(HttpError):
        http.get_json("/orgs/acme/repos")
    assert session.calls == 1 and not sleep.called


def test_backoff_without_hints_is_jittered_within_bounds():
    delays = {_retry_delay(_response(503), attempt=3) for _ in range(200)}
    assert all(4 <= d <= 8 for d in delays) and len(delays) > 50


def test_every_delay_is_capped():
    far = str(int(time.time()) + 3600)
    assert _retry_delay(_response(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": far}), 1) == MAX_RETRY_DELAY
    assert _retry_delay(_response(429, {"Retry-After": "999999"}), 1) == MAX_RETRY_DELAY
    assert _rate_limited(_response(403, {"Retry-After": "1"})) and not _rate_limited(_response(404, {"Retry-After": "1"}))
