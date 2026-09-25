"""Verify evaluation counts, corpus boundaries, and offline scanner integration."""

from __future__ import annotations

import hashlib
import importlib
import json
import stat
from pathlib import Path

import pytest

from tools.evaluation.accept import accept, wilson_lower95
from tools.evaluation.accept import main as acceptance_main
from tools.evaluation.benchmark import benchmark
from tools.evaluation.evaluate import (
    DEFAULT_CORPUS,
    CorpusError,
    calibration,
    evaluate,
    load_corpus,
    main,
    summarize,
)


def _corpus(
    files: dict[str, str],
    *,
    present: bool = False,
    assertions: dict | None = None,
    known_gap: bool | None = None,
) -> dict:
    case: dict = {
        "id": "plain-code",
        "family": "agent",
        "description": "A deliberately plain source file",
        "files": files,
        "target": {"kind": "agent", "signature": "framework.langgraph"},
        "present": present,
        "assertions": assertions or {},
    }
    if known_gap is not None:
        case["known_gap"] = known_gap
    return {
        "schema": 1,
        "metadata": {"name": "test", "type": "synthetic", "provenance": "unit test"},
        "cases": [case],
    }


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_bundled_corpus_has_positive_and_hard_negative_labels():
    meta, cases, digest = load_corpus(DEFAULT_CORPUS)
    assert meta["type"] == "synthetic" and len(digest) == 64
    assert len(cases) >= 25 and {c.family for c in cases} >= {"agent", "mcp-server", "framework-usage"}
    for family in {c.family for c in cases}:
        assert {c.present for c in cases if c.family == family} == {True, False}
    assert {"mcp-empty-json", "mcp-disabled-json", "py-comment-agent", "ts-block-comment-agent"} <= {
        c.id for c in cases
    }


def test_lexer_and_toml_layout_cases_have_distinct_narrow_labels():
    _, cases, _ = load_corpus(DEFAULT_CORPUS)
    by_id = {case.id: case for case in cases}
    for case_id in (
        "py-fstring-interpolated-agent",
        "js-regex-then-agent",
        "mcp-toml-table-active",
        "mcp-toml-dotted-active",
    ):
        assert by_id[case_id].present
    for case_id in ("py-fstring-literal-agent", "jsx-text-agent"):
        assert not by_id[case_id].present
    assert "{StateGraph(dict)}" in by_id["py-fstring-interpolated-agent"].files["agent.py"]
    assert "{{StateGraph(dict)}}" in by_id["py-fstring-literal-agent"].files["agent.py"]
    assert "const graph = new StateGraph()" in by_id["js-regex-then-agent"].files["agent.js"]
    for case_id in ("mcp-toml-table-active", "mcp-toml-dotted-active"):
        assert by_id[case_id].assertions == {"server_count": 1, "server_names": ["active"]}


def test_pinned_public_snapshots_have_verifiable_source_attribution():
    public = DEFAULT_CORPUS.with_name("public_corpus.json")
    meta, cases, _ = load_corpus(public)
    assert meta["type"] == "public-pinned"
    assert len(cases) == 5
    assert len({case.source["commit"] for case in cases}) == 2
    assert {case.present for case in cases} == {True, False}
    assert all(case.source["url"].startswith("https://github.com/") for case in cases)


def test_realistic_corpus_has_multi_file_cases_and_documented_gaps():
    meta, cases, _ = load_corpus(DEFAULT_CORPUS.with_name("realistic_corpus.json"))
    assert meta["type"] == "synthetic"
    assert len(cases) >= 30
    assert sum(c.present for c in cases) >= 14 and sum(not c.present for c in cases) >= 14
    assert all(3 <= len(c.files) <= 8 for c in cases)
    assert not any(c.source for c in cases)
    # Every documented gap explains itself; placeholder cases forbid secret findings.
    for case in cases:
        if case.known_gap:
            assert "Known gap:" in case.description
        if case.family == "secret" and not case.present:
            assert case.assertions.get("max_secret_findings") == 0
    assert {"readme-key-rotation-tutorial"} <= {
        c.id for c in cases if c.known_gap
    }


def test_counts_have_explicit_undefined_denominators():
    rows = [
        {"family": "one", "present": True, "predicted": True},
        {"family": "one", "present": True, "predicted": False},
        {"family": "one", "present": False, "predicted": True},
        {"family": "one", "present": False, "predicted": False},
        {"family": "two", "present": False, "predicted": False},
    ]
    result = summarize(rows)
    assert result["one"] == {
        "cases": 4,
        "positive_cases": 2,
        "negative_cases": 2,
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "specificity": 0.5,
    }
    assert result["two"]["precision"] is None
    assert result["two"]["recall"] is None


def test_aggregate_family_cannot_grow_the_input_while_summarizing():
    rows = [{"family": "all", "present": False, "predicted": False}]
    with pytest.raises(CorpusError, match="reserved"):
        summarize(rows)
    assert len(rows) == 1


def test_reserved_aggregate_family_is_rejected_before_scanning(tmp_path: Path):
    data = _corpus({"plain.py": "pass\n"})
    data["cases"][0]["family"] = "all"
    with pytest.raises(CorpusError, match="reserved"):
        load_corpus(_write(tmp_path / "data.json", data))


def test_calibration_proxies_cover_each_score_once():
    rows = [
        {"score": score, "present": label}
        for score, label in [(0.0, False), (0.5, True), (0.7, False), (0.85, True), (1.0, True)]
    ]
    result = calibration(rows)
    assert [b["count"] for b in result["bins"]] == [1, 1, 1, 2]
    assert result["brier_proxy"] == pytest.approx((0 + 0.25 + 0.49 + 0.0225 + 0) / 5)
    assert result["ece_proxy"] == pytest.approx((0 + 0.5 + 0.7 + 2 * 0.075) / 5)


@pytest.mark.parametrize("bad_name", ["../escape.py", "/absolute.py", "a\\b.py", "x/../escape.py"])
def test_corpus_rejects_escaping_file_paths(tmp_path: Path, bad_name: str):
    with pytest.raises(CorpusError):
        load_corpus(_write(tmp_path / "data.json", _corpus({bad_name: "text"})))


def test_corpus_rejects_duplicate_json_keys(tmp_path: Path):
    path = tmp_path / "data.json"
    path.write_text('{"schema":1,"schema":1,"cases":[]}', encoding="utf-8")
    with pytest.raises(CorpusError, match="unambiguous"):
        load_corpus(path)


def test_corpus_rejects_symlinked_parent_and_oversized_input(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    path = _write(real / "data.json", _corpus({"plain.py": "pass\n"}))
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(CorpusError):
        load_corpus(link / path.name)
    path.write_text(" " * 2_000_001, encoding="utf-8")
    with pytest.raises(CorpusError):
        load_corpus(path)


def test_corpus_rejects_non_boolean_label_and_invalid_assertions(tmp_path: Path):
    data = _corpus({"plain.py": "pass\n"})
    data["cases"][0]["present"] = 1
    with pytest.raises(CorpusError, match="boolean"):
        load_corpus(_write(tmp_path / "data.json", data))
    data["cases"][0]["present"] = False
    data["cases"][0]["assertions"] = {"server_count": True}
    with pytest.raises(CorpusError, match="server_count"):
        load_corpus(_write(tmp_path / "data.json", data))
    data["cases"][0]["assertions"] = {"max_secret_findings": -1}
    with pytest.raises(CorpusError, match="max_secret_findings"):
        load_corpus(_write(tmp_path / "data.json", data))
    data["cases"][0]["assertions"] = {}
    data["cases"][0]["known_gap"] = "yes"
    with pytest.raises(CorpusError, match="known_gap"):
        load_corpus(_write(tmp_path / "data.json", data))


def test_public_snapshot_digest_is_verified(tmp_path: Path):
    value = json.loads(DEFAULT_CORPUS.with_name("public_corpus.json").read_text())
    first = value["cases"][0]
    first["files"][first["source"]["path"]] += "extra"
    with pytest.raises(CorpusError, match="digest mismatch"):
        load_corpus(_write(tmp_path / "tampered.json", value))


@pytest.mark.parametrize("path", [[], {}, 1, None])
def test_public_snapshot_malformed_path_is_a_validation_error(tmp_path: Path, path):
    value = json.loads(DEFAULT_CORPUS.with_name("public_corpus.json").read_text())
    value["cases"][0]["source"]["path"] = path
    with pytest.raises(CorpusError, match="source attribution"):
        load_corpus(_write(tmp_path / "malformed.json", value))


def test_evaluation_end_to_end_with_isolated_offline_files(tmp_path: Path):
    corpus = _write(
        tmp_path / "data.json",
        _corpus(
            {"plain.py": "def hello():\n    return 1\n"},
            assertions={"max_agent_findings": 0, "server_count": 0},
        ),
    )
    report = evaluate(corpus, repeats=2)
    assert report["passed"] is True
    assert report["metrics"]["all"]["tn"] == 1
    assert report["cases"][0]["assertion_failures"] == []
    assert report["performance"]["scans"] == 2
    assert report["performance"]["files_per_pass"] == 1
    assert report["performance"]["median_scan_ms"] >= 0
    assert report["corpus"]["sha256"]
    assert len(report["implementation"]["scanner_source_sha256"]) == 64
    assert len(report["implementation"]["signature_sha256"]) == 64


def test_structural_assertion_causes_regression_even_when_label_matches(tmp_path: Path):
    corpus = _write(tmp_path / "data.json", _corpus({"plain.py": "pass\n"}, assertions={"server_count": 1}))
    result = evaluate(corpus)
    assert result["metrics"]["all"]["tn"] == 1
    assert result["passed"] is False
    assert "active MCP server count" in result["cases"][0]["assertion_failures"][0]


def test_known_gap_is_counted_in_metrics_but_does_not_fail_the_run(tmp_path: Path):
    corpus = _write(tmp_path / "data.json", _corpus({"plain.py": "pass\n"}, present=True, known_gap=True))
    report = evaluate(corpus)
    assert report["metrics"]["all"]["fn"] == 1 and report["metrics"]["all"]["recall"] == 0.0
    assert report["cases"][0]["known_gap"] is True and report["cases"][0]["correct"] is False
    assert report["known_gaps"] == {
        "count": 1,
        "failing": ["plain-code"],
        "passing": [],
        "regressions": [],
    }
    assert report["passed"] is True
    assert main(["--corpus", str(corpus)]) == 0


def test_passing_known_gap_is_reported_for_flag_removal(tmp_path: Path):
    corpus = _write(tmp_path / "data.json", _corpus({"plain.py": "pass\n"}, known_gap=True))
    report = evaluate(corpus)
    assert report["known_gaps"]["passing"] == ["plain-code"]
    assert report["known_gaps"]["failing"] == []
    assert report["passed"] is True


def test_unflagged_case_defaults_to_regression(tmp_path: Path):
    corpus = _write(tmp_path / "data.json", _corpus({"plain.py": "pass\n"}, present=True))
    report = evaluate(corpus)
    assert report["cases"][0]["known_gap"] is False
    assert report["known_gaps"] == {"count": 0, "failing": [], "passing": [], "regressions": ["plain-code"]}
    assert report["passed"] is False


def test_max_secret_findings_assertion_catches_a_credential(tmp_path: Path):
    # Public deterministic fixture: no token or random secret is stored in the repository.
    synthetic_key = "sk-" + "proj-" + hashlib.sha256(b"Project-Nexus-public-synthetic-test-key").hexdigest()
    files = {"config.py": f'OPENAI_API_KEY = "{synthetic_key}"\n'}
    corpus = _write(tmp_path / "data.json", _corpus(files, assertions={"max_secret_findings": 0}))
    report = evaluate(corpus)
    assert report["metrics"]["all"]["tn"] == 1
    assert report["passed"] is False
    assert "secret findings: expected at most 0; got 1" in report["cases"][0]["assertion_failures"]


def test_cli_exits_on_wrong_label_and_writes_private_report(tmp_path: Path):
    corpus = _write(tmp_path / "data.json", _corpus({"plain.py": "pass\n"}, present=True))
    output = tmp_path / "result.json"
    assert main(["--corpus", str(corpus), "--output", str(output)]) == 1
    assert output.exists() and stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text())["metrics"]["all"]["fn"] == 1
    assert main(["--corpus", str(corpus), "--output", str(output)]) == 2  # no silent overwrite


def test_cli_returns_invalid_input_status(tmp_path: Path):
    assert main(["--corpus", str(tmp_path / "missing.json")]) == 2


def test_benchmark_counts_all_files_across_repeat_runs():
    report = benchmark(files=25, runs=2)
    assert report["files"] == 25
    assert report["project_manifests"] == 20
    assert report["finding_count"] >= 1
    assert report["runs"] == 2 and len(report["elapsed_seconds"]) == 2
    assert report["files_per_second_at_median"] > 0


def test_benchmark_rejects_unbounded_work():
    with pytest.raises(ValueError, match="files"):
        benchmark(files=10_001)
    with pytest.raises(ValueError, match="runs"):
        benchmark(runs=11)


def _acceptance_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    data = _corpus({"plain.py": "pass\n"}, assertions={"max_agent_findings": 0})
    data["metadata"]["type"] = "adjudicated"
    data["metadata"]["provenance"] = "held-out analyst labels; reviewed externally"
    data["cases"].append(
        {
            "id": "plain-other",
            "family": "agent",
            "description": "Second negative control",
            "files": {"other.py": "def ordinary():\n    return 1\n"},
            "target": {"kind": "agent", "signature": "framework.langgraph"},
            "present": False,
            "assertions": {"max_agent_findings": 0},
        }
    )
    data["cases"].append(
        {
            "id": "active-graph",
            "family": "agent",
            "description": "Active graph construction",
            "files": {"agent.py": "from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n# separately selected acceptance case\n"},
            "target": {"kind": "agent", "signature": "framework.langgraph"},
            "present": True,
        }
    )
    corpus = _write(tmp_path / "holdout.json", data)
    group = {
        "min_positive_cases": 1,
        "min_negative_cases": 2,
        "min_precision_lower95": 0.2,
        "min_recall_lower95": 0.2,
        "min_specificity_lower95": 0.2,
    }
    policy = _write(
        tmp_path / "policy.json",
        {
            "schema": 1,
            "corpus_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
            "groups": {"all": group, "agent": group},
        },
    )
    annotations = _write(
        tmp_path / "holdout-annotations.json",
        {
            "schema": 1,
            "corpus_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
            "method": "independent-human-double-label-before-scan",
            "selection": "Small source-reviewed unit fixture; not a benchmark.",
            "reviewers": [
                {
                    "id": reviewer,
                    "labels": [
                        {"case_id": case["id"], "present": case["present"], "reason": "Reviewed the source fixture before scoring."}
                        for case in data["cases"]
                    ],
                }
                for reviewer in ("reviewer_one", "reviewer_two")
            ],
            "adjudications": [],
        },
    )
    return corpus, policy, annotations


def test_wilson_lower_bound_is_defined_only_for_observations():
    assert wilson_lower95(0, 0) is None
    assert wilson_lower95(1, 1) == pytest.approx(0.206549314, rel=1e-6)
    assert wilson_lower95(0, 1) == pytest.approx(0)


def test_external_adjudicated_acceptance_gate_and_private_summary(tmp_path: Path):
    corpus, policy, annotations = _acceptance_inputs(tmp_path)
    report = accept(corpus, policy, annotations)
    assert report["passed"] is True
    assert report["groups"]["agent"]["counts"]["tp"] == 1
    assert report["groups"]["agent"]["counts"]["tn"] == 2
    assert report["groups"]["all"]["lower95"]["recall"] > 0.2
    output = tmp_path / "private.json"
    args = ["--corpus", str(corpus), "--policy", str(policy), "--annotations", str(annotations), "--output", str(output)]
    assert acceptance_main(args) == 0
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert acceptance_main(args) == 2  # refuse to overwrite an audit artifact


def test_acceptance_rejects_mismatched_digest_synthetic_labels_and_missing_group(tmp_path: Path):
    corpus, policy, annotations = _acceptance_inputs(tmp_path)
    data = json.loads(policy.read_text())
    data["corpus_sha256"] = "0" * 64
    _write(policy, data)
    assert acceptance_main(["--corpus", str(corpus), "--policy", str(policy), "--annotations", str(annotations)]) == 2
    data["corpus_sha256"] = hashlib.sha256(corpus.read_bytes()).hexdigest()
    del data["groups"]["agent"]
    _write(policy, data)
    assert acceptance_main(["--corpus", str(corpus), "--policy", str(policy), "--annotations", str(annotations)]) == 2
    _write(policy, {**data, "groups": {"all": data["groups"]["all"], "agent": data["groups"]["all"]}})
    labels = json.loads(corpus.read_text())
    labels["metadata"]["type"] = "synthetic"
    _write(corpus, labels)
    assert acceptance_main(["--corpus", str(corpus), "--policy", str(policy), "--annotations", str(annotations)]) == 2


def test_acceptance_fails_when_bound_or_case_floor_is_not_met(tmp_path: Path):
    corpus, policy, annotations = _acceptance_inputs(tmp_path)
    data = json.loads(policy.read_text())
    data["groups"]["agent"]["min_recall_lower95"] = 0.9
    data["groups"]["agent"]["min_positive_cases"] = 10
    _write(policy, data)
    report = accept(corpus, policy, annotations)
    assert report["case_assertions_passed"] is True
    assert report["passed"] is False
    assert any("recall lower95" in item for item in report["groups"]["agent"]["failures"])
    assert any("positive_cases" in item for item in report["groups"]["agent"]["failures"])
    assert acceptance_main(["--corpus", str(corpus), "--policy", str(policy), "--annotations", str(annotations)]) == 1


def test_acceptance_uses_predeclared_error_budget_instead_of_perfect_labels(tmp_path: Path, monkeypatch):
    corpus, policy, annotations = _acceptance_inputs(tmp_path)
    labels = json.loads(corpus.read_text())
    labels["cases"].append(
        {
            "id": "missed-graph",
            "family": "agent",
            "description": "Active graph construction with simulated missed observation",
            "files": {"missed.py": "from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n# distinct missed acceptance case\n"},
            "target": {"kind": "agent", "signature": "framework.langgraph"},
            "present": True,
        }
    )
    _write(corpus, labels)
    ledger = json.loads(annotations.read_text())
    ledger["corpus_sha256"] = hashlib.sha256(corpus.read_bytes()).hexdigest()
    for reviewer in ledger["reviewers"]:
        reviewer["labels"].append(
            {"case_id": "missed-graph", "present": True, "reason": "Reviewed the source fixture before scoring."}
        )
    _write(annotations, ledger)
    data = json.loads(policy.read_text())
    data["corpus_sha256"] = hashlib.sha256(corpus.read_bytes()).hexdigest()
    for group in data["groups"].values():
        group["min_recall_lower95"] = 0.05
    _write(policy, data)
    evaluation_module = importlib.import_module("tools.evaluation.evaluate")
    original_scan = evaluation_module._scan_case

    def simulated_miss(case, root, index):
        duration, findings = original_scan(case, root, index)
        return duration, [] if case.id == "missed-graph" else findings

    monkeypatch.setattr(evaluation_module, "_scan_case", simulated_miss)
    report = accept(corpus, policy, annotations)
    assert report["all_labels_matched"] is False
    assert report["case_assertions_passed"] is True
    assert report["groups"]["all"]["counts"]["fn"] == 1
    assert report["passed"] is True


@pytest.mark.parametrize("bad_value", [0, float("nan"), True, "0.95"])
def test_acceptance_rejects_nonpositive_or_ambiguous_bounds(tmp_path: Path, bad_value):
    corpus, policy, annotations = _acceptance_inputs(tmp_path)
    data = json.loads(policy.read_text())
    data["groups"]["all"]["min_precision_lower95"] = bad_value
    _write(policy, data)
    assert acceptance_main(["--corpus", str(corpus), "--policy", str(policy), "--annotations", str(annotations)]) == 2


def test_acceptance_checks_method_on_the_evaluated_ledger(tmp_path: Path, monkeypatch):
    import importlib

    corpus, policy, annotations = _acceptance_inputs(tmp_path)
    module = importlib.import_module("tools.evaluation.accept")
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    # A ledger replaced after human-method preflight must not get human status.
    monkeypatch.setattr(module, "evaluate", lambda *args, **kwargs: {
        "corpus": {"sha256": digest},
        "annotation_validation": {"method": "independent-ai-double-label-before-scan"},
    })
    with pytest.raises(CorpusError, match="evaluated ledger"):
        accept(corpus, policy, annotations)


def test_acceptance_annotation_preflight_is_bounded(tmp_path: Path):
    from tools.evaluation.annotations import MAX_ANNOTATION_BYTES

    corpus, policy, annotations = _acceptance_inputs(tmp_path)
    annotations.write_text('{"method":"independent-human-double-label-before-scan","padding":"' +
                           'x' * MAX_ANNOTATION_BYTES + '"}')
    with pytest.raises(CorpusError, match="annotations"):
        accept(corpus, policy, annotations)
