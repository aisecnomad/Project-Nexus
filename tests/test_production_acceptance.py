"""Synthetic evidence exercises validation only; none of these fixtures is live evidence.

Human/transport declarations in these private test artifacts are deliberately
simulated. Passing them must never be reported as actual production acceptance.
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from shadowscan import __version__
from tools.acceptance import verify as gate
from tools.evaluation.annotations import validate_annotations
from tools.evaluation.evaluate import load_corpus, summarize

NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)
SOURCE = "1" * 64
SIGNATURE = "2" * 64
CANARY = "3" * 64


def stamp(hours: int) -> str:
    return (NOW - timedelta(hours=hours)).isoformat()


def write_artifact(root: Path, name: str, data: dict) -> dict:
    raw = json.dumps(data, sort_keys=True)
    (root / name).write_text(raw, encoding="utf-8")
    return {"path": name, "sha256": hashlib.sha256(raw.encode()).hexdigest()}


def write_manifest(root: Path, manifest: dict) -> Path:
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "_source_fingerprint", lambda: SOURCE)
    monkeypatch.setattr(gate, "_source_provenance", lambda: {"source_sha256": CANARY})
    monkeypatch.setattr(gate, "get_index", lambda **kwargs: SimpleNamespace(fingerprint=lambda: SIGNATURE))
    cases = []
    for number in range(21):
        contents = f"# Synthetic unit-test snapshot {number}; never field evidence.\n"
        repo = f"synthetic-test/repo-{number % 3}"
        commit = "a" * 40
        cases.append({"id": f"test-{number}", "family": "test", "description": "Simulated gate evidence",
                      "files": {"main.py": contents}, "target": {"kind": "agent"}, "present": number < 7,
                      "source": {"repo": repo, "commit": commit, "path": "main.py", "license": "CC0-1.0",
                                 "url": f"https://github.com/{repo}/blob/{commit}/main.py",
                                 "sha256": hashlib.sha256(contents.encode()).hexdigest(),
                                 "label_evidence": "Simulated labels, never human field validation."}})
    corpus = {"schema": 1, "metadata": {"name": "Synthetic gate fixture", "type": "adjudicated",
                                         "provenance": "Synthetic test; never production evidence."}, "cases": cases}
    corpus_ref = write_artifact(tmp_path, "corpus.json", corpus)
    labels = [{"case_id": case["id"], "present": case["present"], "reason": "Simulated label for gate test."} for case in cases]
    annotations = {"schema": 1, "corpus_sha256": corpus_ref["sha256"],
                   "method": "independent-human-double-label-before-scan", "selection": "Simulated unit-test declaration.",
                   "reviewers": [{"id": "test-human-one", "labels": labels}, {"id": "test-human-two", "labels": labels}],
                   "adjudications": []}
    annotation_ref = write_artifact(tmp_path, "annotations.json", annotations)
    ledger = validate_annotations(tmp_path / "corpus.json", tmp_path / "annotations.json")
    metadata, loaded_cases, digest = load_corpus(tmp_path / "corpus.json")
    rows = [{"id": case.id, "family": case.family, "description": case.description, "source": case.source,
             "target": {"kind": case.kind.value, "signature": case.signature}, "present": case.present,
             "predicted": case.present, "score": float(case.present), "correct": True,
             "assertion_failures": [], "median_ms": 1.0,
             "findings": [{"kind": "agent", "signatures": [], "confidence": 1.0}] if case.present else []}
            for case in loaded_cases]
    report = {"schema": 1, "corpus": {**metadata, "sha256": digest}, "annotation_validation": ledger,
              "implementation": {"scanner_version": __version__, "scanner_source_sha256": SOURCE,
                                 "signature_sha256": SIGNATURE, "python": "3.11", "platform": "synthetic-test"},
              "cases": rows, "metrics": summarize(rows), "calibration": {}, "performance": {}, "passed": True}
    report_ref = write_artifact(tmp_path, "evaluation.json", report)
    manifest = {"schema": gate.SCHEMA, "reviewer": "test-operator", "reviewed_at": stamp(1),
                "policy": {"frozen_at": stamp(24), "max_age_hours": 48, "min_cases": 20, "min_positive_cases": 7,
                           "min_negative_cases": 14, "min_precision": 0.9, "min_recall": 0.9, "min_specificity": 0.9},
                "evaluation": {"corpus": corpus_ref, "annotations": annotation_ref, "report": report_ref,
                               "population": "test-only", "evaluated_at": stamp(2), "holdout_frozen_at": stamp(20),
                               "human_reviewed": True, "never_used_for_tuning": True},
                "deployments": [{"connector": "code.filesystem", "scope": {"population": "test-only"}}]}
    return tmp_path, manifest, report


def add_provider(root: Path, manifest: dict, connector: str = "saas.slack") -> None:
    scope = {"team_id": "TTEST"} if connector == "saas.slack" else {
        "account_id": "111122223333", "regions": ["us-east-1"], "services": ["lambda"]}
    resources = [f"slack:app:A{n}" if connector == "saas.slack" else
                 f"arn:aws:lambda:us-east-1:111122223333:function:test{n}" for n in range(2)]
    deployment = {"connector": connector, "scope": scope}
    for complete in (True, False):
        expectation = "complete" if complete else "permission-denied"
        receipt = {"schema": "shadowscan.tenant-canary-report/v1", "mode": "live", "expectation": expectation,
                   "status": "LIVE_PASS", "live_acceptance": complete, "started_at": stamp(3),
                   "scanner": {"version": __version__, "source_sha256": CANARY, "commit": None, "dirty": True},
                   "signature_sha256": SIGNATURE, "connector": connector, "expected_scope": scope,
                   "ground_truth": {"owner": "test-reviewer", "reviewed_at": stamp(20), "source": "synthetic unit test",
                                    "independent_of_scanner": True}, "limitations": "Synthetic test only.",
                   "abandoned_workers": 0, "passed": True, "scope_verified": True,
                   "observed_scope_ids": [scope.get("team_id", scope.get("account_id"))],
                   "collection_complete": complete, "classified_permission_denial": not complete,
                   "objects_examined": 3 if complete else 1, "diagnostic_count": 0 if complete else 1,
                   "controls": [{"id": f"test-control-{n}", "rationale": "Test control only.",
                                 "expected": {"resource": resources[n], "present": n == 0,
                                              **({"kind": "cloud-resource"} if n == 0 else {})},
                                 "collected_records": 1, "observed_kinds": ["cloud-resource"] if n == 0 else [],
                                 "passed": True} for n in range(2)] if complete else [],
                   "finished_at": stamp(2), "collection_started_at": stamp(3), "collection_finished_at": stamp(2)}
        key = "complete" if complete else "permission_denied"
        deployment[key] = {"artifact": write_artifact(root, f"{connector}-{key}.json", receipt), "process_exit_code": 0,
                           "real_tenant_transport": True, "principal_ref": f"test-{key}", "separate_process": True}
    manifest["deployments"].append(deployment)


def change_receipt(root: Path, manifest: dict, key: str, update) -> None:
    ref = manifest["deployments"][-1][key]["artifact"]
    receipt = json.loads((root / ref["path"]).read_text())
    update(receipt)
    manifest["deployments"][-1][key]["artifact"] = write_artifact(root, ref["path"], receipt)


def test_consistent_code_only_evidence_is_scoped_and_explicitly_not_certification(evidence):
    root, manifest, _ = evidence
    result = gate.verify(write_manifest(root, manifest), now=NOW)
    assert result["status"] == "EVIDENCE_CONSISTENT"
    assert result["live_receipt_count"] == 0
    assert result["evaluation"]["cases"] == 21
    assert "not authenticated proof" in result["limitations"]
    assert "test-operator" not in json.dumps(result)
    assert "test-only" not in json.dumps(result)


@pytest.mark.parametrize("connector", ["saas.slack", "cloud.aws"])
def test_consistent_synthetic_receipt_pairs_are_checked_without_network(evidence, connector):
    root, manifest, _ = evidence
    add_provider(root, manifest, connector)
    result = gate.verify(write_manifest(root, manifest), now=NOW)
    assert result["live_receipt_count"] == 2
    assert result["deployment_count"] == 2


@pytest.mark.parametrize(("field", "value", "error"), [
    ("mode", "replay", "live_passing_receipt_required"),
    ("status", "LIVE_NOT_RUN", "live_passing_receipt_required"),
    ("collection_complete", False, "canary_expectation_mismatch"),
    ("live_acceptance", False, "canary_expectation_mismatch"),
    ("abandoned_workers", 1, "canary_incomplete"),
    ("signature_sha256", "0" * 64, "canary_implementation_mismatch"),
    ("observed_scope_ids", ["TOTHER"], "canary_scope_mismatch"),
    ("diagnostic_count", 1, "canary_incomplete"),
    ("started_at", stamp(100), "stale_or_future_evidence"),
    ("finished_at", stamp(-1), "stale_or_future_evidence"),
    ("finished_at", stamp(4), "invalid_canary_time_order"),
    ("controls", [], "canary_controls_missing"),
])
def test_receipt_rejections(evidence, field, value, error):
    root, manifest, _ = evidence
    add_provider(root, manifest)
    change_receipt(root, manifest, "complete", lambda receipt: receipt.update({field: value}))
    with pytest.raises(gate.EvidenceError, match=error):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_denial_requires_incomplete_and_classified_denial(evidence):
    root, manifest, _ = evidence
    add_provider(root, manifest)
    change_receipt(root, manifest, "permission_denied", lambda receipt: receipt.update(classified_permission_denial=False))
    with pytest.raises(gate.EvidenceError, match="canary_expectation_mismatch"):
        gate.verify(write_manifest(root, manifest), now=NOW)


@pytest.mark.parametrize("key", ["principal_ref", "real_tenant_transport", "process_exit_code", "separate_process"])
def test_execution_declarations_are_required(evidence, key):
    root, manifest, _ = evidence
    add_provider(root, manifest)
    manifest["deployments"][-1]["permission_denied"][key] = {
        "principal_ref": "test-complete", "real_tenant_transport": False,
        "process_exit_code": 1, "separate_process": False}[key]
    with pytest.raises(gate.EvidenceError):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_receipt_age_is_relative_to_current_time_not_review_time(evidence):
    root, manifest, _ = evidence
    add_provider(root, manifest)
    manifest["reviewed_at"] = stamp(40)
    manifest["evaluation"]["evaluated_at"] = stamp(42)
    manifest["evaluation"]["holdout_frozen_at"] = stamp(45)
    manifest["policy"]["frozen_at"] = stamp(46)
    change_receipt(root, manifest, "complete", lambda receipt: receipt.update(started_at=stamp(60)))
    with pytest.raises(gate.EvidenceError, match="stale_or_future_evidence"):
        gate.verify(write_manifest(root, manifest), now=NOW)


@pytest.mark.parametrize("connector", ["cloud.azure", "code.github", "saas.teams", "gateway.logs"])
def test_unsupported_intended_connectors_fail_closed(evidence, connector):
    root, manifest, _ = evidence
    manifest["deployments"].append({"connector": connector, "scope": {}})
    with pytest.raises(gate.EvidenceError, match="unsupported_intended_connector"):
        gate.verify(write_manifest(root, manifest), now=NOW)


@pytest.mark.parametrize("field", ["human_reviewed", "never_used_for_tuning"])
def test_holdout_declarations_cannot_be_false(evidence, field):
    root, manifest, _ = evidence
    manifest["evaluation"][field] = False
    with pytest.raises(gate.EvidenceError, match="human_holdout_declaration_required"):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_ai_labels_are_not_accepted_as_human(evidence):
    root, manifest, _ = evidence
    path = root / "annotations.json"
    annotations = json.loads(path.read_text())
    annotations["method"] = "independent-ai-double-label-before-scan"
    manifest["evaluation"]["annotations"] = write_artifact(root, path.name, annotations)
    with pytest.raises(gate.EvidenceError, match="human_annotation_ledger_required"):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_case_labels_and_metrics_are_recomputed(evidence):
    root, manifest, report = evidence
    report["cases"][0]["present"] = False
    manifest["evaluation"]["report"] = write_artifact(root, "evaluation.json", report)
    with pytest.raises(gate.EvidenceError, match="evaluation_label_mismatch"):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_metrics_cannot_hide_misses(evidence):
    root, manifest, report = evidence
    row = report["cases"][0]
    row.update(predicted=False, correct=False, findings=[])
    report["passed"] = False
    manifest["evaluation"]["report"] = write_artifact(root, "evaluation.json", report)
    with pytest.raises(gate.EvidenceError, match="inconsistent_evaluation_metrics"):
        gate.verify(write_manifest(root, manifest), now=NOW)
    report["metrics"] = summarize(report["cases"])
    manifest["evaluation"]["report"] = write_artifact(root, "evaluation.json", report)
    with pytest.raises(gate.EvidenceError, match="metric_threshold_not_met"):
        gate.verify(write_manifest(root, manifest), now=NOW)
    manifest["policy"]["min_recall"] = 0.85
    assert gate.verify(write_manifest(root, manifest), now=NOW)["status"] == "EVIDENCE_CONSISTENT"


@pytest.mark.parametrize("change,error", [
    (lambda data: data["policy"].update(min_cases=22), "sample_threshold_not_met"),
    (lambda data: data["policy"].update(frozen_at=stamp(1)), "holdout_or_policy_not_frozen_before_evaluation"),
    (lambda data: data["policy"].update(max_age_hours=True), "invalid_maximum_age"),
    (lambda data: data["evaluation"].update(evaluated_at=stamp(100)), "stale_or_future_evidence"),
    (lambda data: data["deployments"][0]["scope"].update(population="another-estate"), "holdout_population_mismatch"),
    (lambda data: data["deployments"].append(copy.deepcopy(data["deployments"][0])), "duplicate_intended_scope"),
    (lambda data: data["evaluation"]["report"].update(sha256="0" * 64), "artifact_digest_mismatch"),
])
def test_manifest_rejections(evidence, change, error):
    root, manifest, _ = evidence
    change(manifest)
    with pytest.raises(gate.EvidenceError, match=error):
        gate.verify(write_manifest(root, manifest), now=NOW)


@pytest.mark.parametrize("raw", ['{"schema": 1, "schema": 2}', '{"x": NaN}', '{"x": 1e10000}',
                                  '[' * 40 + '0' + ']' * 40])
def test_json_is_duplicate_free_finite_and_depth_bounded(tmp_path, raw):
    path = tmp_path / "manifest.json"
    path.write_text(raw)
    with pytest.raises(gate.EvidenceError):
        gate.verify(path, now=NOW)


def test_symlink_and_oversize_inputs_are_rejected(tmp_path):
    target = tmp_path / "data.json"
    target.write_text('{}')
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        gate.verify(link, now=NOW)
    target.write_text(' ' * (gate.MAX_BYTES + 1))
    with pytest.raises(ValueError, match="byte limit"):
        gate.verify(target, now=NOW)


def test_cli_failure_never_echoes_sensitive_values(tmp_path, capsys):
    path = tmp_path / "manifest.json"
    path.write_text('{"credentials": "opaque-sensitive-marker", "credentials": "second-secret"}')
    output = tmp_path / "decision.json"
    assert gate.main([str(path), "--output", str(output)]) == 1
    serialized = output.read_text() + capsys.readouterr().out
    assert "opaque-sensitive-marker" not in serialized and "second-secret" not in serialized
    assert "EVIDENCE_REJECTED" in serialized
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("field", ["scanner_source_sha256", "signature_sha256"])
def test_evaluation_cannot_be_reused_after_implementation_changes(evidence, field):
    root, manifest, report = evidence
    report["implementation"][field] = "f" * 64
    manifest["evaluation"]["report"] = write_artifact(root, "evaluation.json", report)
    with pytest.raises(gate.EvidenceError, match="evaluation_implementation_mismatch"):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_ledger_must_match_report_labels(evidence):
    root, manifest, report = evidence
    report["annotation_validation"]["method"] = "independent-ai-double-label-before-scan"
    manifest["evaluation"]["report"] = write_artifact(root, "evaluation.json", report)
    with pytest.raises(gate.EvidenceError, match="evaluation_label_provenance_mismatch"):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_malformed_evaluation_is_structured_rejection(evidence, monkeypatch):
    root, manifest, _ = evidence
    manifest["evaluation"] = None
    # CLI uses real time; policy freshness is independent of this malformed shape.
    monkeypatch.setattr(gate, "_fresh", lambda *args: NOW)
    path = write_manifest(root, manifest)
    output = root / "decision.json"
    assert gate.main([str(path), "--output", str(output)]) == 1
    assert json.loads(output.read_text())["reason"] == "invalid_evaluation_object"


def test_aws_control_resource_must_belong_to_declared_scope(evidence):
    root, manifest, _ = evidence
    add_provider(root, manifest, "cloud.aws")
    change_receipt(root, manifest, "complete", lambda receipt: receipt["controls"][0]["expected"].update(
        resource="arn:aws:lambda:us-east-1:999988887777:function:another-tenant"))
    with pytest.raises(gate.EvidenceError, match="canary_control_scope_mismatch"):
        gate.verify(write_manifest(root, manifest), now=NOW)


@pytest.mark.parametrize("provider", ["aws", "slack"])
def test_actual_producer_shape_and_date_only_ground_truth_are_compatible(evidence, provider):
    # Generate a genuine replay report, then adapt ONLY this private test fixture
    # to simulate the live branch. This is not retained as live tenant evidence.
    from tools.canaries.run import load_config, run

    root, manifest, _ = evidence
    connector = "cloud.aws" if provider == "aws" else "saas.slack"
    add_provider(root, manifest, connector)
    config_path = Path(__file__).resolve().parents[1] / "examples" / "canaries" / f"{provider}-replay.yaml"
    producer = run(load_config(config_path))
    assert producer["status"] == "REPLAY_PASS"
    deployment = manifest["deployments"][-1]
    deployment["scope"] = producer["expected_scope"]
    producer.update(mode="live", status="LIVE_PASS", live_acceptance=True,
                    started_at=stamp(3), finished_at=stamp(2),
                    collection_started_at=stamp(3), collection_finished_at=stamp(2), signature_sha256=SIGNATURE)
    producer["scanner"]["source_sha256"] = CANARY
    deployment["complete"]["artifact"] = write_artifact(root, "producer-shape.json", producer)
    change_receipt(root, manifest, "permission_denied", lambda receipt: receipt.update(
        expected_scope=producer["expected_scope"], observed_scope_ids=producer["observed_scope_ids"]))
    assert gate.verify(write_manifest(root, manifest), now=NOW)["live_receipt_count"] == 2
    producer.update(mode="replay", status="REPLAY_PASS", live_acceptance=False)
    deployment["complete"]["artifact"] = write_artifact(root, "producer-shape.json", producer)
    with pytest.raises(gate.EvidenceError, match="live_passing_receipt_required"):
        gate.verify(write_manifest(root, manifest), now=NOW)


def test_control_from_unselected_service_is_rejected(evidence):
    root, manifest, _ = evidence
    add_provider(root, manifest, "cloud.aws")
    change_receipt(root, manifest, "complete", lambda receipt: receipt["controls"][0]["expected"].update(
        resource="arn:aws:bedrock:us-east-1:111122223333:agent/other-service"))
    with pytest.raises(gate.EvidenceError, match="canary_control_service_mismatch"):
        gate.verify(write_manifest(root, manifest), now=NOW)
