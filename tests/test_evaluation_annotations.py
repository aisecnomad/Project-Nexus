"""Recorded independent labels cannot drift silently with scanner changes."""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

import pytest

from tools.evaluation.annotations import validate_annotations
from tools.evaluation.evaluate import CorpusError, evaluate


def _write(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def annotated_corpus(tmp_path):
    cases = []
    for i in range(24):
        name = f"example_{i}.py"
        text = "pass\n"
        repo = f"example/repo-{i % 3}"
        revision = "a" * 40
        cases.append({
            "id": f"case-{i:02}", "family": "agent", "description": "Unit fixture, not a public benchmark",
            "files": {name: text}, "target": {"kind": "agent"}, "present": i < 8,
            "source": {
                "repo": repo, "commit": revision, "path": name,
                "url": f"https://github.com/{repo}/blob/{revision}/{name}",
                "sha256": hashlib.sha256(text.encode()).hexdigest(), "license": "MIT",
                "label_evidence": "Test fixture for integrity validation only",
            },
        })
    corpus = _write(tmp_path / "corpus.json", {
        "schema": 1, "metadata": {"name": "test", "type": "adjudicated", "provenance": "unit fixture"},
        "cases": cases,
    })
    ledger = {
        "schema": 1, "corpus_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
        "method": "independent-ai-double-label-before-scan", "selection": "Unit fixture only",
        "reviewers": [{"id": reviewer, "labels": [
            {"case_id": case["id"], "present": case["present"], "reason": "Fixture annotation"}
            for case in cases
        ]} for reviewer in ("first", "second")],
        "adjudications": [],
    }
    return corpus, tmp_path / "labels.json", ledger


def test_two_reviewers_and_negative_heavy_counts(annotated_corpus):
    corpus, path, ledger = annotated_corpus
    report = validate_annotations(corpus, _write(path, ledger))
    assert (report["positive_cases"], report["negative_cases"], report["initial_agreement"]) == (8, 16, 1)


def test_adjudicated_evaluation_cannot_bypass_ledger(annotated_corpus):
    corpus, _, _ = annotated_corpus
    with pytest.raises(CorpusError, match="require.*annotation"):
        evaluate(corpus)


def test_changed_corpus_invalidates_frozen_labels(annotated_corpus):
    corpus, path, ledger = annotated_corpus
    corpus.write_text(corpus.read_text() + "\n")
    with pytest.raises(CorpusError, match="digest mismatch"):
        validate_annotations(corpus, _write(path, ledger))


def test_evaluation_uses_the_exact_snapshot_verified_by_annotations(annotated_corpus, monkeypatch):
    corpus, path, ledger = annotated_corpus
    module = importlib.import_module("tools.evaluation.evaluate")
    original_load = module.load_corpus

    def replace_after_first_read(source):
        snapshot = original_load(source)
        # Simulate a concurrent edit between the evaluator's read and the
        # annotation validator's independent read of the same pathname.
        changed = json.loads(corpus.read_text())
        changed["cases"][0]["description"] = "A different frozen snapshot"
        _write(corpus, changed)
        ledger["corpus_sha256"] = hashlib.sha256(corpus.read_bytes()).hexdigest()
        _write(path, ledger)
        return snapshot

    monkeypatch.setattr(module, "load_corpus", replace_after_first_read)
    monkeypatch.setattr(module, "_scan_case", lambda *args: pytest.fail("unverified snapshot was scanned"))
    with pytest.raises(CorpusError, match="changed between evaluation and annotation"):
        evaluate(corpus, annotations=path)


@pytest.mark.parametrize("method", [[], {}, None, True])
def test_malformed_method_fails_as_validation_error(annotated_corpus, method):
    corpus, path, ledger = annotated_corpus
    ledger["method"] = method
    with pytest.raises(CorpusError, match="annotation method"):
        validate_annotations(corpus, _write(path, ledger))


def test_disagreement_requires_explicit_source_based_resolution(annotated_corpus):
    corpus, path, ledger = annotated_corpus
    ledger["reviewers"][1]["labels"][0]["present"] = False
    with pytest.raises(CorpusError, match="unresolved"):
        validate_annotations(corpus, _write(path, ledger))
    ledger["adjudications"] = [{"case_id": "case-00", "present": True, "reason": "Explicit source-based adjudication"}]
    result = validate_annotations(corpus, _write(path, ledger))
    assert result["adjudicated_disagreements"] == 1
    assert result["initial_agreement"] == pytest.approx(23 / 24)


@pytest.mark.parametrize("tamper", ["duplicate-reviewer", "missing-label", "duplicate-label", "changed-label", "fabricated-adjudication"])
def test_annotation_integrity_failures(annotated_corpus, tamper):
    corpus, path, ledger = annotated_corpus
    if tamper == "duplicate-reviewer":
        ledger["reviewers"][1]["id"] = "first"
    elif tamper == "missing-label":
        ledger["reviewers"][1]["labels"].pop()
    elif tamper == "duplicate-label":
        ledger["reviewers"][1]["labels"][1] = ledger["reviewers"][1]["labels"][0]
    elif tamper == "changed-label":
        for reviewer in ledger["reviewers"]:
            reviewer["labels"][0]["present"] = False
    else:
        ledger["adjudications"] = [{"case_id": "case-00", "present": True, "reason": "No disagreement existed"}]
    with pytest.raises(CorpusError):
        validate_annotations(corpus, _write(path, ledger))
