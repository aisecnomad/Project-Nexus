"""YAML manifest matching retains its own deadline under instrumented parallel work."""

from __future__ import annotations

import time

import pytest

from shadowscan.connectors.code import manifests
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.matcher import MatchTimeoutError, _run_regex


def test_yaml_manifest_collection_has_its_own_bounded_pattern_budget(monkeypatch):
    """A covered YAML pass may exceed the signature matcher's 100 ms CPU cap."""
    original = manifests._YAML_REPO

    class InstrumentedPattern:
        def finditer(self, *args, **kwargs):
            matches = list(original.finditer(*args, **kwargs))
            until = time.thread_time() + 0.12
            while time.thread_time() < until:
                pass
            return iter(matches)

    monkeypatch.setattr(manifests, "_YAML_REPO", InstrumentedPattern())
    result = manifests.parse_manifest("compose.yaml", "services:\n  agent:\n    image: example/agent:1\n")
    assert result is not None and not result.errors
    assert [(artifact.kind, artifact.value) for artifact in result.artifacts] == [("image", "example/agent:1")]

def test_manifest_override_keeps_the_active_input_deadline(monkeypatch):
    now = time.monotonic()
    monkeypatch.setattr("shadowscan.signatures.matcher.time.monotonic", lambda: now)
    timeouts = []

    def run(timeout):
        nonlocal now
        timeouts.append(timeout)
        now += 0.03
        return "match"

    with pytest.raises(MatchTimeoutError, match="input execution budget"), SignatureIndex([]).scan_budget(seconds=0.02):
        _run_regex(run, "YAML manifest", max_seconds=1.0)
    assert len(timeouts) == 1 and 0 < timeouts[0] <= 0.02
