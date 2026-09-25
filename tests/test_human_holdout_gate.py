"""Mechanics-only fixtures; these declarations do not represent real human reviews."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from tools.evaluation.evaluate import DEFAULT_CORPUS, CorpusError, load_corpus
from tools.evaluation.holdout_gate import assess, load_policy, main


def _write(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _refreeze(corpus: Path, annotations: Path, policy: Path) -> None:
    data = json.loads(policy.read_text())
    data["corpus_sha256"] = hashlib.sha256(corpus.read_bytes()).hexdigest()
    data["annotations_sha256"] = hashlib.sha256(annotations.read_bytes()).hexdigest()
    _write(policy, data)


@pytest.fixture
def holdout(tmp_path: Path) -> tuple[Path, Path, Path]:
    cases = []
    for number in range(24):
        present = number < 8
        name = f"example_{number}.py"
        source = (
            f"from agents import Agent\nagent_{number} = Agent(name='Assistant {number}')\n"
            if present else f"def ordinary_job_{number}(value):\n    return value + {number}\n"
        )
        repo = f"fixture/repo-{number % 4}"
        revision = "e" * 40
        cases.append({
            "id": f"case-{number:02}", "family": "agent", "description": "Synthetic integrity test only",
            "files": {name: source}, "target": {"kind": "agent"}, "present": present,
            "source": {
                "repo": repo, "commit": revision, "path": name,
                "url": f"https://github.com/{repo}/blob/{revision}/{name}",
                "sha256": hashlib.sha256(source.encode()).hexdigest(), "license": "MIT",
                "label_evidence": "Mechanical test fixture, no actual human review",
            },
        })
    corpus = _write(tmp_path / "corpus.json", {
        "schema": 1,
        "metadata": {"name": "fake test fixture", "type": "adjudicated", "provenance": "not a real evaluation"},
        "cases": cases,
    })
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    annotations = _write(tmp_path / "annotations.json", {
        "schema": 1, "corpus_sha256": digest,
        "method": "independent-human-double-label-before-scan",
        "selection": "Mechanical validation fixture only; no people labeled this corpus.",
        "reviewers": [
            {"id": reviewer, "labels": [
                {"case_id": case["id"], "present": case["present"], "reason": "Unit test fixture"}
                for case in cases
            ]} for reviewer in ("reviewer-a", "reviewer-b")
        ],
        "adjudications": [],
    })
    policy = _write(tmp_path / "policy.json", {
        "schema": 1, "corpus_sha256": digest,
        "annotations_sha256": hashlib.sha256(annotations.read_bytes()).hexdigest(),
        "target_kinds": ["agent"],
        "minimums": {"positive": 8, "negative": 16, "repositories": 4},
        "max_errors": {"false_positive": 0, "false_negative": 0},
        "per_kind": {
            "agent": {
                "minimums": {"positive": 8, "negative": 16},
                "max_errors": {"false_positive": 0, "false_negative": 0},
            },
        },
    })
    return corpus, annotations, policy


def test_private_receipt_records_exact_frozen_inputs_and_metrics(holdout, tmp_path: Path):
    corpus, annotations, policy = holdout
    output = tmp_path / "receipt.json"
    assert main(["--corpus", str(corpus), "--annotations", str(annotations),
                 "--policy", str(policy), "--output", str(output)]) == 0
    result = json.loads(output.read_text())
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert result["passed"] and result["reasons"] == []
    assert result["by_kind"]["agent"]["tp"] == 8
    assert result["by_kind"]["agent"]["tn"] == 16
    assert len(result["excluded_corpora"]) == 3
    assert result["policy_sha256"] == hashlib.sha256(policy.read_bytes()).hexdigest()
    assert result["evaluation"]["corpus"]["sha256"] == result["policy"]["corpus_sha256"]
    assert result["annotations_sha256"] == result["policy"]["annotations_sha256"]
    assert main(["--corpus", str(corpus), "--annotations", str(annotations),
                 "--policy", str(policy), "--output", str(output)]) == 2


def test_threshold_failure_keeps_a_reproducible_receipt(holdout, tmp_path: Path):
    corpus, annotations, policy = holdout
    data = json.loads(policy.read_text())
    data["minimums"]["positive"] = 9
    _write(policy, data)
    receipt = tmp_path / "failed.json"
    assert main(["--corpus", str(corpus), "--annotations", str(annotations),
                 "--policy", str(policy), "--output", str(receipt)]) == 1
    assert json.loads(receipt.read_text())["reasons"] == ["positive: 8 < minimum 9"]


def test_per_kind_minima_and_error_caps_block_misleading_aggregate(holdout):
    corpus, annotations, policy = holdout
    data = json.loads(corpus.read_text())
    data["cases"][0]["target"] = {"kind": "mcp-server"}  # positive source only builds an AI agent
    data["cases"][8]["target"] = {"kind": "mcp-server"}  # benign negative
    _write(corpus, data)
    ledger = json.loads(annotations.read_text())
    ledger["corpus_sha256"] = hashlib.sha256(corpus.read_bytes()).hexdigest()
    _write(annotations, ledger)
    criteria = json.loads(policy.read_text())
    criteria["target_kinds"] = ["agent", "mcp-server"]
    criteria["max_errors"]["false_negative"] = 1
    criteria["per_kind"]["agent"]["minimums"] = {"positive": 7, "negative": 15}
    criteria["per_kind"]["mcp-server"] = {
        "minimums": {"positive": 2, "negative": 1},
        "max_errors": {"false_positive": 0, "false_negative": 0},
    }
    _write(policy, criteria)
    _refreeze(corpus, annotations, policy)

    report = assess(corpus, annotations, policy)
    assert report["evaluation"]["metrics"]["all"]["fn"] == 1  # permitted in aggregate
    assert report["by_kind"]["mcp-server"]["fn"] == 1
    assert report["passed"] is False
    assert "mcp-server positive: 1 < minimum 2" in report["reasons"]
    assert "mcp-server false_negative: 1 > limit 0" in report["reasons"]


def test_ai_labels_and_changed_policy_digest_fail_before_scan(holdout):
    corpus, annotations, policy = holdout
    ledger = json.loads(annotations.read_text())
    ledger["selection"] += " Newly changed after policy freeze."
    _write(annotations, ledger)
    with pytest.raises(CorpusError, match="annotation ledger digest"):
        assess(corpus, annotations, policy)
    ledger["method"] = "independent-ai-double-label-before-scan"
    _write(annotations, ledger)
    _refreeze(corpus, annotations, policy)
    with pytest.raises(CorpusError, match="human double labeling"):
        assess(corpus, annotations, policy)
    policy_data = json.loads(policy.read_text())
    policy_data["corpus_sha256"] = "0" * 64
    _write(policy, policy_data)
    with pytest.raises(CorpusError, match="frozen policy"):
        assess(corpus, annotations, policy)


def test_known_source_overlap_and_additional_history_are_rejected(holdout, tmp_path: Path):
    corpus, annotations, policy = holdout
    with pytest.raises(CorpusError, match="previously evaluated corpus"):
        assess(corpus, annotations, policy, excluded=[corpus])

    historical = json.loads(corpus.read_text())
    historical["cases"] = [historical["cases"][0]]
    prior = _write(tmp_path / "prior.json", historical)
    with pytest.raises(CorpusError, match="previously evaluated source file"):
        assess(corpus, annotations, policy, excluded=[prior])

    known = json.loads(DEFAULT_CORPUS.with_name("independent_corpus.json").read_text())["cases"][0]
    updated = json.loads(corpus.read_text())
    updated["cases"][0]["files"] = known["files"]
    updated["cases"][0]["source"] = known["source"]
    _write(corpus, updated)
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    ledger = json.loads(annotations.read_text())
    ledger["corpus_sha256"] = digest
    _write(annotations, ledger)
    _refreeze(corpus, annotations, policy)
    with pytest.raises(CorpusError, match="previously evaluated source file"):
        assess(corpus, annotations, policy)


def test_strict_policy_parser_rejects_duplicate_and_boolean_integer(holdout):
    _, _, policy = holdout
    data = json.loads(policy.read_text())
    data["max_errors"]["false_positive"] = True
    _write(policy, data)
    with pytest.raises(CorpusError, match="false_positive"):
        load_policy(policy)
    data["max_errors"]["false_positive"] = 0
    del data["per_kind"]["agent"]
    _write(policy, data)
    with pytest.raises(CorpusError, match="per_kind"):
        load_policy(policy)
    policy.write_text('{"schema":1,"schema":1}', encoding="utf-8")
    with pytest.raises(CorpusError, match="unambiguous"):
        load_policy(policy)


def test_duplicate_holdout_content_cannot_inflate_case_count(holdout):
    corpus, annotations, policy = holdout
    data = json.loads(corpus.read_text())
    repeated = next(iter(data["cases"][0]["files"].values()))
    data["cases"][1]["files"]["example_1.py"] = repeated
    data["cases"][1]["source"]["sha256"] = hashlib.sha256(repeated.encode()).hexdigest()
    _write(corpus, data)
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    ledger = json.loads(annotations.read_text())
    ledger["corpus_sha256"] = digest
    _write(annotations, ledger)
    _refreeze(corpus, annotations, policy)
    with pytest.raises(CorpusError, match="duplicate source file"):
        assess(corpus, annotations, policy)


def test_corpus_requires_a_declared_and_verifiable_source_digest(holdout):
    corpus, _, _ = holdout
    data = json.loads(corpus.read_text())
    data["cases"][0]["files"]["example_0.py"] += "# changed\n"
    _write(corpus, data)
    with pytest.raises(CorpusError, match="digest mismatch"):
        load_corpus(corpus)
