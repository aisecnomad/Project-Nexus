"""Exact source reuse cannot inflate either acceptance gate's sample counts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from shadowscan.models import Kind
from tools.acceptance.verify import EvidenceError, _exclude_evaluated_cases
from tools.evaluation import accept as legacy
from tools.evaluation.evaluate import Case, CorpusError
from tools.evaluation.sources import SourceIndex, SourceOverlapError

POSITIVE = "from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n# source independence regression\n"
NEGATIVE = "def local_calculation():\n    return 'source independence regression'\n"


def _case(case_id: str, files: dict[str, str], source: dict[str, str] | None = None) -> Case:
    return Case(case_id, "agent", "Synthetic overlap check, not field evidence", files,
                Kind.AGENT, None, False, {}, source)


def _check(cases: list[Case], gate: str) -> None:
    if gate == "legacy":
        legacy._exclude_bundled_sources(cases, "f" * 64)
    else:
        _exclude_evaluated_cases(cases, "f" * 64, Path("."), [])


@pytest.mark.parametrize("gate", ["legacy", "production"])
@pytest.mark.parametrize("overlap", ["same-path", "renamed", "partial-multifile", "location", "blank"])
def test_both_gates_reject_source_reuse(gate: str, overlap: str) -> None:
    first = _case("first", {"agent.py": POSITIVE})
    second = _case("second", {"agent.py": POSITIVE})
    if overlap == "renamed":
        second.files.clear()
        second.files["renamed.py"] = POSITIVE
    elif overlap == "partial-multifile":
        first.files["first_context.py"] = "first_context = 'unique'\n"
        second.files["second_context.py"] = "second_context = 'different'\n"
    elif overlap == "location":
        first = _case("first", {"agent.py": POSITIVE},
                      {"repo": "test/private", "commit": "a" * 40, "path": "agent.py"})
        second = _case("second", {"agent.py": NEGATIVE},
                       {"repo": "TEST/PRIVATE", "commit": "a" * 40, "path": "agent.py"})
    elif overlap == "blank":
        first = _case("first", {"one.py": ""})
        second = _case("second", {"two.py": " \n\t", "three.py": "\n"})
    with pytest.raises((CorpusError, EvidenceError), match="duplicate_holdout_source"):
        _check([first, second], gate)


@pytest.mark.parametrize("gate", ["legacy", "production"])
def test_distinct_cases_can_share_empty_scaffolding_and_duplicate_files_within_one_case(gate: str) -> None:
    # Each case contributes one outcome regardless of identical copies inside
    # it. Common empty package markers do not turn distinct samples into copies.
    first = _case("first", {"one/agent.py": POSITIVE, "two/agent.py": POSITIVE, "__init__.py": ""})
    second = _case("second", {"plain.py": NEGATIVE, "__init__.py": ""})
    _check([first, second], gate)


def test_shared_index_preserves_strict_prior_overlap_including_blank_files() -> None:
    prior = _case("prior", {"package/__init__.py": "", "agent.py": POSITIVE})
    current = _case("current", {"different/__init__.py": "", "plain.py": NEGATIVE})
    index = SourceIndex()
    index.add([prior], "a" * 64)
    with pytest.raises(SourceOverlapError, match="holdout_reuses_evaluated_source"):
        index.check_holdout([current], "b" * 64)


def test_legacy_accept_rejects_two_sources_renamed_into_two_hundred_cases_before_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    cases = [{
        "id": f"case-{number}", "family": "agent", "description": "Synthetic repeated sample",
        "files": {f"renamed-{number}.py": POSITIVE if number < 100 else NEGATIVE},
        "target": {"kind": "agent"}, "present": number < 100,
    } for number in range(200)]
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({
        "schema": 1, "metadata": {"name": "repeated-fixture", "type": "adjudicated",
                                  "provenance": "Synthetic regression, not independent human evidence"},
        "cases": cases,
    }), encoding="utf-8")
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    bounds = {"min_positive_cases": 100, "min_negative_cases": 100,
              "min_precision_lower95": 0.95, "min_recall_lower95": 0.95,
              "min_specificity_lower95": 0.95}
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema": 1, "corpus_sha256": digest,
                                  "groups": {"all": bounds, "agent": bounds}}), encoding="utf-8")
    annotations = tmp_path / "annotations.json"
    annotations.write_text(json.dumps({"schema": 1, "corpus_sha256": digest,
        "method": "independent-human-double-label-before-scan",
        "selection": "Synthetic unit fixture, not actual independent human review",
        "reviewers": [{"id": reviewer, "labels": [
            {"case_id": case["id"], "present": case["present"], "reason": "Synthetic fixture label"}
            for case in cases]} for reviewer in ("fixture_one", "fixture_two")],
        "adjudications": []}), encoding="utf-8")
    monkeypatch.setattr(legacy, "evaluate", lambda *args, **kwargs: pytest.fail("duplicate corpus reached scanner"))
    with pytest.raises(CorpusError, match="duplicate_holdout_source"):
        legacy.accept(corpus, policy, annotations)
    assert legacy.main(["--corpus", str(corpus), "--policy", str(policy),
                        "--annotations", str(annotations)]) == 2
    error = capsys.readouterr().err
    assert "duplicate_holdout_source" in error
    assert "renamed-" not in error and "source independence regression" not in error
