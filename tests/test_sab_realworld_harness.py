"""Signature recall of the author-written real-world benchmark harness."""

from __future__ import annotations

from benchmarks.sab_realworld.corpus import CASES, RealWorldCase
from benchmarks.sab_realworld.harness import _check_expectations, label_signatures


def _case(expected: list[str]) -> RealWorldCase:
    return RealWorldCase(
        id="case",
        category="framework",
        family="family",
        label="agent",
        difficulty="easy",
        description="d",
        source={},
        files={},
        expected_signatures=expected,
    )


def test_package_labels_match_the_signature_ids_findings_carry(index):
    # Labels are package or product names; findings carry signature IDs. Comparing
    # the two directly made every recall 0.
    scan = {
        "detected": True,
        "agentic": True,
        "items": [{"signatures": ["framework.crewai", "provider.openai", "coding-agent.sourcegraph-cody"]}],
    }
    checks = _check_expectations(_case(["crewai", "langchain-openai", "cody", "letta"]), scan, index)
    assert checks["found_expected_signatures"] == ["cody", "crewai", "langchain-openai"]
    assert checks["missed_expected_signatures"] == ["letta"]
    assert checks["signature_recall"] == 0.75


def test_every_corpus_label_names_a_shipped_signature(index):
    unmatched = sorted(
        {label for case in CASES for label in case.expected_signatures if not label_signatures(label, index)}
    )
    # These packages have no signature: a case expecting them records a miss.
    assert unmatched == ["azure-ai-search", "langchainrb"]
