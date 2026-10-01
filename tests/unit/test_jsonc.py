"""Lenient JSON (JSONC) loading: comment stripping only when needed, in linear time."""

from __future__ import annotations

import time

import pytest

from shadowscan.utils.jsonc import load_json_lenient


def test_lenient_json_is_linear_on_unterminated_strings():
    # Every quote inside an unterminated string used to restart the string
    # token, so escaped quotes made stripping quadratic in the line length.
    text = '{"a": 1, "b": "' + '\\"' * 50_000 + "\n}"
    started = time.perf_counter()
    with pytest.raises(ValueError):
        load_json_lenient(text)
    assert time.perf_counter() - started < 2


def test_lenient_json_loader_only_strips_comments_when_needed():
    assert load_json_lenient('{"a": 1}') == {"a": 1}
    assert load_json_lenient('{"a": 1, // comment\n "b": [1,],}') == {"a": 1, "b": [1]}
    with pytest.raises(ValueError):
        load_json_lenient("{nope")
