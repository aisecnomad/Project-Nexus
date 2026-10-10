"""The current SDK idiom corpus: labeled positives, hard negatives and honest gaps."""

from __future__ import annotations

from tools.evaluation.evaluate import DEFAULT_CORPUS, evaluate, load_corpus

CORPUS = DEFAULT_CORPUS.with_name("current_idioms_corpus.json")


def test_current_idiom_cases_are_authored_and_labeled_with_explicit_selectors() -> None:
    meta, cases, _ = load_corpus(CORPUS)
    assert meta["type"] == "synthetic" and "no copied third party code" in meta["provenance"].lower()
    assert not any(case.source for case in cases)
    assert sum(case.present for case in cases) >= 15 and sum(not case.present for case in cases) >= 6
    gaps = [case for case in cases if case.known_gap]
    # The waiver budget is exactly the documented misses, each explained in place.
    assert meta["known_gap_policy"]["max_count"] == len(gaps)
    assert all("Known gap:" in case.description for case in gaps)
    for case in cases:
        if case.present and not case.known_gap:
            selectors = case.assertions["expected_findings"]
            assert any(selector["kind"] == "agent" for selector in selectors), case.id
    rules = next(case for case in cases if case.id == "vendored-llm-detection-rules")
    assert rules.assertions == {"exact_findings": []}


def test_current_idiom_corpus_passes_with_only_its_documented_gap() -> None:
    report = evaluate(CORPUS)
    assert report["passed"]
    assert report["metrics"]["all"] | {"tp": 16, "fp": 0, "fn": 1, "tn": 11} == report["metrics"]["all"]
    # The MCP server cases pin the exact capability set: the protocol's tool-use
    # and mcp-server, nothing the arithmetic tools do not imply; the client
    # next to an HTTP server class keeps tool-use alone.
    servers = [row for row in report["cases"] if row["family"] == "mcp-server"]
    assert len(servers) == 4 and all(row["correct"] for row in servers)
    assert report["known_gaps"]["failing"] == ["ai-sdk7-single-step-imported-tool"]
    assert report["known_gaps"]["passing"] == [] and report["known_gaps"]["regressions"] == []
