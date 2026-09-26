"""Performance paths must return exactly what the exhaustive paths return."""

from __future__ import annotations

import pytest

from shadowscan.signatures import matcher


@pytest.mark.parametrize(("statement", "language"), [
    ("from openai import OpenAI", "python"),
    ("from agents import Agent", "python"),
    ("import os", "python"),
    ("import { example } from '@anthropic-ai/sdk'", "javascript"),
])
def test_statement_import_cache_matches_uncached_results(index, statement, language):
    expected = [(m.signature_id, m.value, m.weight) for m in index.match_imports(statement, language)]
    first = index.match_import_statement(statement, language)
    assert [(m.signature_id, m.value, m.weight) for m in first] == expected
    assert index.match_import_statement(statement, language) is first  # served from the cache


def test_statement_import_cache_is_bounded(index, monkeypatch):
    monkeypatch.setattr(matcher, "_STATEMENT_CACHE_LIMIT", 3)
    index._statement_imports.clear()
    for number in range(10):
        index.match_import_statement(f"import module_{number}", "python")
    assert len(index._statement_imports) <= 3


def test_regex_plan_keeps_pack_order_and_quotas(index):
    text = "\n".join(["from openai import OpenAI", "client = OpenAI()"] + ["client.chat.completions.create()"] * 6)
    matches = index.match_code(text, "python")
    per_signal: dict[int, int] = {}
    for m in matches:
        per_signal[id(m.signal)] = per_signal.get(id(m.signal), 0) + 1
    assert per_signal and max(per_signal.values()) <= 3
    order = [(sig.id, id(s)) for sig, s in index._by_type["code"]]
    positions = [order.index((m.signature_id, id(m.signal))) for m in matches]
    assert positions == sorted(positions)
