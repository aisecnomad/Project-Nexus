"""A release holdout must not reuse development labels, gaps or source bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.evaluation.accept import accept
from tools.evaluation.evaluate import DEFAULT_CORPUS, CorpusError, load_corpus


def _inputs(root: Path) -> tuple[Path, Path, Path, dict]:
    cases = [
        {"id": "positive", "family": "agent", "description": "Positive holdout",
         "files": {"agent.py": "from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n# private fixture\n"},
         "target": {"kind": "agent"}, "present": True},
        {"id": "negative", "family": "agent", "description": "Negative holdout",
         "files": {"plain.py": "def quiet():\n    return 'private fixture'\n"},
         "target": {"kind": "agent"}, "present": False},
    ]
    corpus = {"schema": 1, "metadata": {"name": "fixture", "type": "adjudicated",
              "provenance": "Unit fixture, not representative field evidence"}, "cases": cases}
    return root / "holdout.json", root / "policy.json", root / "annotations.json", corpus


def _freeze(corpus: Path, policy: Path, annotations: Path, data: dict) -> None:
    corpus.write_text(json.dumps(data), encoding="utf-8")
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    bounds = {"min_positive_cases": 1, "min_negative_cases": 1,
              "min_precision_lower95": 0.01, "min_recall_lower95": 0.01,
              "min_specificity_lower95": 0.01}
    policy.write_text(json.dumps({"schema": 1, "corpus_sha256": digest,
                                  "groups": {"all": bounds, "agent": bounds}}), encoding="utf-8")
    annotations.write_text(json.dumps({
        "schema": 1, "corpus_sha256": digest,
        "method": "independent-human-double-label-before-scan",
        "selection": "Unit fixture selected before scoring, not field evidence",
        "reviewers": [{"id": reviewer, "labels": [
            {"case_id": case["id"], "present": case["present"], "reason": "Reviewed the fixture"}
            for case in data["cases"]]}
            for reviewer in ("reviewer_one", "reviewer_two")],
        "adjudications": [],
    }), encoding="utf-8")


def test_ai_labeled_adjudicated_corpus_is_rejected_before_scan(tmp_path: Path) -> None:
    source = DEFAULT_CORPUS.with_name("independent_corpus.json")
    annotations = DEFAULT_CORPUS.with_name("independent_annotations.json")
    policy = tmp_path / "policy.json"
    bounds = {"min_positive_cases": 1, "min_negative_cases": 1,
              "min_precision_lower95": 0.01, "min_recall_lower95": 0.01,
              "min_specificity_lower95": 0.01}
    policy.write_text(json.dumps({"schema": 1, "corpus_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                  "groups": {"all": bounds}}), encoding="utf-8")
    with pytest.raises(CorpusError, match="human-labeled holdout"):
        accept(source, policy, annotations)


def test_known_gap_and_bundled_source_cannot_pass_acceptance(tmp_path: Path) -> None:
    corpus, policy, annotations, data = _inputs(tmp_path)
    data["cases"][0]["known_gap"] = True
    _freeze(corpus, policy, annotations, data)
    with pytest.raises(CorpusError, match="known gaps"):
        accept(corpus, policy, annotations)

    data["cases"][0].pop("known_gap")
    _, cases, _ = load_corpus(DEFAULT_CORPUS)
    reused = next(case.files["agent.py"] for case in cases if case.id == "py-langgraph-agent")
    data["cases"][0]["files"] = {"agent.py": reused}
    _freeze(corpus, policy, annotations, data)
    with pytest.raises(CorpusError, match="reuses a bundled evaluated source"):
        accept(corpus, policy, annotations)
