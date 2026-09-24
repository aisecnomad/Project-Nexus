"""Scheduler contention must not be mistaken for hostile regex execution."""

from __future__ import annotations

import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import regex

from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.matcher import _MAX_CONTENTION_RETRIES, MatchTimeoutError, _finditer, _run_regex


def test_other_thread_cpu_between_iterator_creation_and_consumption_is_retried(monkeypatch):
    monkeypatch.setattr("shadowscan.signatures.matcher.REGEX_TIMEOUT_SECONDS", 0.02)

    def occupy_cpu():
        until = time.thread_time() + 0.06
        while time.thread_time() < until:
            pass

    class PreemptedPattern:
        calls = 0

        def finditer(self, text, **kwargs):
            self.calls += 1
            scanner = regex.compile(r"(?i)langchain").finditer(text, **kwargs)
            if self.calls == 1:
                # regex charges this other thread's CPU to the suspended
                # scanner, even with concurrent=False and a tiny literal input.
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(occupy_cpu).result()
            return scanner

    pattern = PreemptedPattern()
    with SignatureIndex([]).scan_budget(seconds=1):
        matches = _finditer(pattern, "langchain/0.3", "framework.langchain", 3)
    assert [match.group() for match in matches] == ["langchain"]
    assert pattern.calls == 2


def test_persistent_low_cpu_contention_has_a_finite_retry_limit():
    attempts = []

    def always_timeout(timeout):
        attempts.append(timeout)
        raise TimeoutError

    with pytest.raises(MatchTimeoutError, match="incomplete"):
        _run_regex(always_timeout, "custom.pattern")
    assert len(attempts) == _MAX_CONTENTION_RETRIES + 1
    assert all(later <= earlier for earlier, later in zip(attempts, attempts[1:], strict=False))


def test_multiple_preemptions_retain_live_result_within_original_cpu_and_wall_budgets():
    attempts = 0

    def temporarily_preempted(timeout):
        nonlocal attempts
        attempts += 1
        if attempts <= 5:
            raise TimeoutError("other worker charged to regex iterator")
        return "client-99"

    with SignatureIndex([]).scan_budget(seconds=1):
        assert _run_regex(temporarily_preempted, "coding-agent.cline") == "client-99"
    assert attempts == 6


def test_contention_retry_cannot_restart_the_input_wall_deadline(monkeypatch):
    now = time.monotonic()
    monkeypatch.setattr("shadowscan.signatures.matcher.time.monotonic", lambda: now)
    attempts = 0

    def expire_deadline(timeout):
        nonlocal now, attempts
        attempts += 1
        now += 3
        raise TimeoutError

    with pytest.raises(MatchTimeoutError, match="input execution budget"), SignatureIndex([]).scan_budget():
        _run_regex(expire_deadline, "custom.pattern")
    assert attempts == 1


def test_retries_share_the_original_current_thread_cpu_budget(monkeypatch):
    cpu = 0.0
    monkeypatch.setattr("shadowscan.signatures.matcher.time.thread_time", lambda: cpu)
    attempts = []

    def consume_budget(timeout):
        nonlocal cpu
        attempts.append(timeout)
        if len(attempts) == 1:
            cpu += 0.03
            raise TimeoutError
        cpu += 0.07
        return "must not escape after cumulative exhaustion"

    with pytest.raises(MatchTimeoutError, match="incomplete"):
        _run_regex(consume_budget, "custom.pattern")
    assert attempts == pytest.approx([0.1, 0.07])


def test_genuinely_expensive_regex_is_preempted_without_retry():
    code = r'''
import regex
import shadowscan.signatures.matcher as matcher
matcher.REGEX_TIMEOUT_SECONDS = 0.03
class CountingPattern:
    calls = 0
    def finditer(self, text, **kwargs):
        self.calls += 1
        return regex.compile('(a+)+$').finditer(text, **kwargs)
pattern = CountingPattern()
try:
    matcher._finditer(pattern, 'a' * 50000 + '!', 'custom.expensive', 3)
except matcher.MatchTimeoutError:
    assert pattern.calls == 1, pattern.calls
    print('preempted once')
else:
    raise AssertionError('expected a bounded failure')
'''
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "preempted once"
