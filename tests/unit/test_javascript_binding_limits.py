"""The JavaScript import binder's limits and exclusions, exercised through the public entry point."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import (
    MAX_BOUND_CALLS,
    MAX_CALL_TEXT,
    SourceBudgetExceeded,
    bound_source_matches,
)

IMPORT = 'import OpenAI from "openai";\n'


@pytest.fixture(autouse=True)
def _pattern_budget_beyond_runner_stalls(monkeypatch):
    # These tests exercise the binder's call and text limits. Without a scan
    # deadline each regex call gets the 0.1 s per-pattern budget, a separate
    # fail-closed guard with its own matcher tests; a garbage-collection pause
    # or runner stall past it ended the binder with TimeoutError before the
    # limit under test was reached (test 3.12 on CI). The work itself takes
    # about 5 ms here.
    monkeypatch.setattr(
        "shadowscan.connectors.code.source_semantics.pattern_timeout", lambda default=0.1: 5.0
    )


def _matches(index, text: str) -> list[tuple[str, str, int | None]]:
    ignored, _ = noncode_ranges(text, "javascript")
    matches = bound_source_matches(index, text, "javascript", ignored)
    return [(m.signature_id, m.signal.type, m.line) for m in matches]


def test_bound_calls_beyond_the_limit_stop_the_binder(index):
    within = IMPORT + "OpenAI();\n" * MAX_BOUND_CALLS
    assert ("provider.openai", "import", 1) in _matches(index, within)
    with pytest.raises(SourceBudgetExceeded, match="source binding call limit exceeded"):
        _matches(index, within + "OpenAI();\n")


def test_a_call_without_balanced_arguments_is_not_evidence(index):
    request = "OpenAI.chat.completions.create({ tools: [lookup] "
    balanced = _matches(index, IMPORT + request + "})\n")
    unbalanced = _matches(index, IMPORT + request + "x" * MAX_CALL_TEXT + "\n})\n")
    assert ("provider.openai", "code", 2) in balanced  # a request offering tools
    assert unbalanced and all(line == 1 for _, _, line in unbalanced)


def test_declarations_in_comments_bind_nothing(index):
    text = '// const OpenAI = require("openai");\n/* import OpenAI from "openai"; */\nOpenAI();\n'
    assert _matches(index, text) == []
    assert _matches(index, text.replace("// ", "").replace("/* ", "").replace(" */", ""))
