"""Acceptance-gate boundaries: bundled and AI-labeled corpora cannot pass."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.evaluation.accept import accept, main, wilson_lower95
from tools.evaluation.evaluate import DEFAULT_CORPUS, CorpusError, load_corpus


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _policy(digest: str, **group_overrides: object) -> dict:
    group = {
        "min_positive_cases": 1,
        "min_negative_cases": 1,
        "min_precision_lower95": 0.5,
        "min_recall_lower95": 0.5,
        "min_specificity_lower95": 0.5,
    }
    group.update(group_overrides)
    return {"schema": 1, "corpus_sha256": digest, "groups": {"all": group, "agent": dict(group)}}


def _adjudicated(files: dict[str, str], *, present: bool = False) -> dict:
    return {
        "schema": 1,
        "metadata": {
            "name": "private-holdout",
            "type": "adjudicated",
            "provenance": "unit test fixture; not a field sample",
        },
        "cases": [
            {
                "id": "holdout-plain",
                "family": "agent",
                "description": "A deliberately plain source file",
                "files": files,
                "target": {"kind": "agent"},
                "present": present,
            }
        ],
    }


def test_wilson_lower95_is_undefined_without_attempts():
    assert wilson_lower95(0, 0) is None
    lower_perfect = wilson_lower95(1, 1)
    assert lower_perfect is not None and 0 < lower_perfect < 1
    lower_zero = wilson_lower95(0, 40)
    assert lower_zero is not None and lower_zero == 0


def test_accept_rejects_bundled_synthetic_corpus(tmp_path: Path):
    policy = _write(tmp_path / "policy.json", _policy("0" * 64))
    annotations = _write(tmp_path / "ann.json", {"method": "independent-human-double-label-before-scan"})
    with pytest.raises(CorpusError, match="bundled"):
        accept(DEFAULT_CORPUS, policy, annotations)


def test_accept_rejects_bundled_public_corpus(tmp_path: Path):
    policy = _write(tmp_path / "policy.json", _policy("0" * 64))
    annotations = _write(tmp_path / "ann.json", {"method": "independent-human-double-label-before-scan"})
    with pytest.raises(CorpusError, match="bundled"):
        accept(DEFAULT_CORPUS.with_name("public_corpus.json"), policy, annotations)


def test_accept_rejects_bundled_independent_corpus_even_though_typed_adjudicated(tmp_path: Path):
    policy = _write(tmp_path / "policy.json", _policy("0" * 64))
    annotations = DEFAULT_CORPUS.with_name("independent_annotations.json")
    with pytest.raises(CorpusError, match="bundled"):
        accept(DEFAULT_CORPUS.with_name("independent_corpus.json"), policy, annotations)


def test_accept_rejects_synthetic_type_outside_the_bundle(tmp_path: Path):
    corpus = _write(
        tmp_path / "holdout.json",
        {
            "schema": 1,
            "metadata": {"name": "copied", "type": "synthetic", "provenance": "unit test"},
            "cases": [
                {
                    "id": "plain-code",
                    "family": "agent",
                    "description": "A deliberately plain source file",
                    "files": {"plain.py": "pass\n"},
                    "target": {"kind": "agent"},
                    "present": False,
                }
            ],
        },
    )
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    policy = _write(tmp_path / "policy.json", _policy(digest))
    annotations = _write(tmp_path / "ann.json", {"method": "independent-human-double-label-before-scan"})
    with pytest.raises(CorpusError, match="adjudicated"):
        accept(corpus, policy, annotations)


def test_accept_rejects_ai_labeled_ledger_for_a_private_adjudicated_corpus(tmp_path: Path):
    corpus = _write(tmp_path / "holdout.json", _adjudicated({"plain.py": "pass\n"}))
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    policy = _write(tmp_path / "policy.json", _policy(digest))
    annotations = _write(tmp_path / "ann.json", {"method": "independent-ai-double-label-before-scan"})
    with pytest.raises(CorpusError, match="human-double-label"):
        accept(corpus, policy, annotations)


def test_accept_rejects_policy_digest_mismatch(tmp_path: Path):
    corpus = _write(tmp_path / "holdout.json", _adjudicated({"plain.py": "pass\n"}))
    policy = _write(tmp_path / "policy.json", _policy("ab" * 32))
    annotations = _write(tmp_path / "ann.json", {"method": "independent-human-double-label-before-scan"})
    with pytest.raises(CorpusError, match="SHA-256"):
        accept(corpus, policy, annotations)


def test_cli_refuses_bundled_independent_corpus(tmp_path: Path):
    policy = _write(tmp_path / "policy.json", _policy("0" * 64))
    assert (
        main(
            [
                "--corpus",
                str(DEFAULT_CORPUS.with_name("independent_corpus.json")),
                "--policy",
                str(policy),
                "--annotations",
                str(DEFAULT_CORPUS.with_name("independent_annotations.json")),
            ]
        )
        == 2
    )


# A release holdout must not reuse development labels, gaps or source bytes.
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
    # Copy outside the repository so this checks the human-label declaration,
    # independently of the earlier repository-local holdout rejection.
    source = tmp_path / "copied_corpus.json"
    annotations = tmp_path / "copied_annotations.json"
    source.write_bytes(DEFAULT_CORPUS.with_name("independent_corpus.json").read_bytes())
    annotations.write_bytes(DEFAULT_CORPUS.with_name("independent_annotations.json").read_bytes())
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
