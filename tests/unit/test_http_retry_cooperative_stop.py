"""Retry back-off never outlives the connector's cooperative deadline."""

from __future__ import annotations

import time

import pytest

from shadowscan.connectors.base import ConnectorError
from shadowscan.utils import http
from shadowscan.utils.http import _sleep_cooperatively, reset_cooperative_stop, set_cooperative_stop


def test_sleep_is_interrupted_by_the_installed_stop_check():
    def stop():
        raise ConnectorError("connector completion deadline exceeded")

    token = set_cooperative_stop(stop)
    try:
        started = time.monotonic()
        with pytest.raises(ConnectorError):
            _sleep_cooperatively(30)
        assert time.monotonic() - started < 2
    finally:
        reset_cooperative_stop(token)


def test_sleep_without_a_stop_check_waits_once_for_the_requested_time(monkeypatch):
    slept = []
    monkeypatch.setattr(http.time, "sleep", lambda s: slept.append(s))
    _sleep_cooperatively(2.5)
    assert slept == [2.5]


def test_sleep_with_a_stop_check_is_sliced_so_the_deadline_is_consulted(monkeypatch):
    slept = []
    checks = []
    monkeypatch.setattr(http.time, "sleep", lambda s: slept.append(s))
    clock = iter([0.0, 0.0, 1.0, 2.0, 2.5, 3.0])
    monkeypatch.setattr(http.time, "monotonic", lambda: next(clock))
    token = set_cooperative_stop(lambda: checks.append(True))
    try:
        _sleep_cooperatively(2.5)
    finally:
        reset_cooperative_stop(token)
    assert slept and all(0 < s <= 1.0 for s in slept)
    assert len(checks) >= len(slept)
