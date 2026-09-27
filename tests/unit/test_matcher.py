"""Signature matcher input budgets and match positions."""

from __future__ import annotations

import pytest

from shadowscan.signatures import SignatureIndex
from shadowscan.signatures import matcher as matcher_module
from shadowscan.signatures.loader import signature_from_dict
from shadowscan.signatures.matcher import MatchTimeoutError


def _index(pattern="token"):
    return SignatureIndex([signature_from_dict({
        "id": "custom.test",
        "category": "framework",
        "signals": [{"type": "code", "patterns": [pattern]}],
    })])


def test_explicit_scan_budget_is_not_silently_capped_at_default(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(matcher_module.time, "monotonic", lambda: clock[0])
    original = matcher_module._finditer

    def delayed_match(*args, **kwargs):
        clock[0] = 3.0  # valid for the requested 5-second budget, not the default 2
        return original(*args, **kwargs)

    monkeypatch.setattr(matcher_module, "_finditer", delayed_match)
    index = _index()
    with index.scan_budget(seconds=5):
        assert [m.value for m in index.match_code("token")] == ["token"]


def test_unscoped_matching_still_opens_default_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(matcher_module.time, "monotonic", lambda: clock[0])
    original = matcher_module._finditer

    def delayed_match(*args, **kwargs):
        clock[0] = 3.0
        return original(*args, **kwargs)

    monkeypatch.setattr(matcher_module, "_finditer", delayed_match)
    with pytest.raises(MatchTimeoutError, match="input execution budget"):
        _index().match_code("token")


def test_signature_match_starting_at_newline_has_original_line_number():
    matches = _index(r"\n+token").match_code("prefix\n\ntoken")
    assert [(m.value, m.line) for m in matches] == [("\n\ntoken", 1)]
