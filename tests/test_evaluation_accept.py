"""Acceptance-gate boundaries: bundled and AI-labeled corpora cannot pass."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.evaluation.accept import accept, main, wilson_lower95
from tools.evaluation.evaluate import DEFAULT_CORPUS, CorpusError


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
