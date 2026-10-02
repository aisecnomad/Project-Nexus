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


def test_call_text_limit_analyzes_only_that_call_partially(index, tmp_path, run_connector):
    request = "OpenAI.chat.completions.create({ tools: [lookup] "
    balanced = _matches(index, IMPORT + request + "})\n")
    assert ("provider.openai", "code", 2) in balanced  # a request offering tools
    # A call longer than the limit is read from its first MAX_CALL_TEXT
    # characters, as the Python binder reads one: the binder keeps running and
    # the file's other calls keep their evidence, where it used to discard every
    # bound call of the file. An option past the limit is unread, so the scan
    # stays incomplete, as it was.
    over_limit = IMPORT + request + "x" * MAX_CALL_TEXT + "\n})\n" + request + "})\n"
    ignored, _ = noncode_ranges(over_limit, "javascript")
    truncated: list[int] = []
    found = bound_source_matches(index, over_limit, "javascript", ignored, truncated=truncated)
    assert truncated == [2]
    assert ("provider.openai", "code", 4) in [(m.signature_id, m.signal.type, m.line) for m in found]
    (tmp_path / "app.js").write_text(over_limit)
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False
    )
    assert context.stats.incomplete
    gaps = [error for error in context.stats.errors if "app.js" in error]
    assert len(gaps) == 1 and "line 2" in gaps[0] and f"first {MAX_CALL_TEXT} characters" in gaps[0]
    assert "coverage is incomplete" in gaps[0]
    assert any(
        e.location == "app.js:4" and e.signal.startswith("code:") for f in findings for e in f.evidence
    )


def test_call_text_limit_in_test_code_follows_the_test_discount(tmp_path, run_connector):
    over_limit = IMPORT + "OpenAI.chat.completions.create({ tools: [lookup] " + "x" * MAX_CALL_TEXT + "})\n"
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "app.test.js").write_text(over_limit)
    for strict in (False, True):
        _, context = run_connector(
            "code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False, strict_coverage=strict
        )
        assert not context.stats.errors and context.stats.incomplete is strict
        assert any(
            "app.test.js: import-bound call at line 2" in warning for warning in context.stats.warnings
        )


def test_unbalanced_call_at_the_end_of_the_source_is_partial(index):
    truncated: list[int] = []
    text = IMPORT + "const client = new OpenAI(\n"
    ignored, _ = noncode_ranges(text, "javascript")
    bound_source_matches(index, text, "javascript", ignored, truncated=truncated)
    assert truncated == [2]


def test_long_genkit_flow_keeps_the_files_bound_evidence(tmp_path, run_connector):
    # A Genkit flow body is the argument of defineFlow: real flows pass 8 KiB.
    steps = "".join(f"    const step{number} = await fetch(`/api/{number}`);\n" for number in range(200))
    source = (
        'import { genkit, z } from "genkit";\nimport { googleAI } from "@genkit-ai/googleai";\n\n'
        "const ai = genkit({ plugins: [googleAI()] });\n\n"
        'export const menuFlow = ai.defineFlow({ name: "menu" }, async (input) => {\n'
        + steps
        + "    return input;\n});\n"
    )
    (tmp_path / "flow.ts").write_text(source)
    findings, context = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False
    )
    # Still a coverage gap (the flow's options past the limit are unread), but the
    # genkit() constructor and the file's other bound evidence are kept.
    assert context.stats.incomplete
    assert any("flow.ts" in error and "line 6" in error for error in context.stats.errors)
    evidence = [e for f in findings for e in f.evidence if e.signature == "framework.genkit"]
    assert any(e.signal.startswith("code:") and e.location == "flow.ts:4" for e in evidence)


def test_declarations_in_comments_bind_nothing(index):
    text = '// const OpenAI = require("openai");\n/* import OpenAI from "openai"; */\nOpenAI();\n'
    assert _matches(index, text) == []
    assert _matches(index, text.replace("// ", "").replace("/* ", "").replace(" */", ""))
