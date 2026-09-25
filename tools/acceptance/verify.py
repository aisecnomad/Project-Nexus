"""Check deployment evidence; operator declarations are not authenticated attestations.

No credentials, provider APIs, sampled source execution or network access are used.
A passing result establishes consistency with an operator's declared acceptance
policy, not independent certification, transport authenticity or estate coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import tempfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.connectors.cloud.aws import KNOWN_SERVICES
from shadowscan.models import Kind
from shadowscan.signatures import get_index
from shadowscan.utils.files import read_policy_text
from shadowscan.utils.output import write_private_text
from tools.canaries.run import _source_provenance
from tools.evaluation.annotations import validate_annotations
from tools.evaluation.evaluate import (
    DEFAULT_CORPUS as DEFAULT_CORPUS,
)
from tools.evaluation.evaluate import (
    Case,
    _assertions,
    _source_fingerprint,
    known_gaps,
    load_corpus,
    summarize,
)
from tools.evaluation.sources import SourceOverlapError, bundled_source_index

SCHEMA = "shadowscan.production-evidence/v1"
REPORT_SCHEMA = "shadowscan.production-evidence-report/v1"
MAX_BYTES = 2 * 1024 * 1024
LIMITATION = (
    "Checks artifact consistency and declared thresholds only. Human independence, "
    "holdout freshness, real tenant transport, process exits and principal separation "
    "are operator declarations, not authenticated proof. A pass is not certification "
    "or permission to deploy, and applies only to the declared population/scopes. "
    "Overlap checks cover exact bytes and known or declared prior corpora; near duplicates "
    "and undisclosed prior evaluations require human review."
)


class EvidenceError(ValueError):
    """Stable error codes only; never interpolate untrusted evidence into output."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise EvidenceError(code)


def _keys(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    _require(isinstance(value, dict), "invalid_object")
    _require(required <= set(value) <= required | (optional or set()), "missing_or_unknown_fields")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise EvidenceError("nonfinite_json_number")


def _read(path: Path) -> tuple[Any, str]:
    raw = read_policy_text(path, max_bytes=MAX_BYTES)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise EvidenceError("invalid_json") from exc
    # Cap nesting and aggregate fields after the bounded JSON parse. Finite float
    # validation also rejects JSON exponents that overflow to infinity.
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        _require(depth <= 32 and count <= 100_000, "json_structure_limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            _require(math.isfinite(item), "nonfinite_json_number")
    return value, raw


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", value))


def _sha(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _time(value: Any) -> datetime:
    _require(isinstance(value, str) and len(value) <= 40, "invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("invalid_timestamp") from exc
    _require(parsed.tzinfo is not None, "timestamp_requires_timezone")
    return parsed.astimezone(UTC)


def _review_before(value: Any, before: datetime) -> bool:
    # Canary configs permit calendar review dates. Compare those to the UTC
    # collection date; timestamp values retain their explicit timezone precision.
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            return date.fromisoformat(value) <= before.date()
        except ValueError:
            return False
    return _time(value) <= before


def _fresh(value: Any, now: datetime, age: timedelta) -> datetime:
    parsed = _time(value)
    _require(now - age <= parsed <= now, "stale_or_future_evidence")
    return parsed


def _artifact(ref: Any, base: Path) -> tuple[dict[str, Any], str]:
    _keys(ref, {"path", "sha256"})
    _require(isinstance(ref["path"], str) and 0 < len(ref["path"]) <= 2048 and _sha(ref["sha256"]),
             "invalid_artifact_reference")
    path = Path(ref["path"])
    data, raw = _read(path if path.is_absolute() else base / path)
    _require(hashlib.sha256(raw.encode("utf-8")).hexdigest() == ref["sha256"], "artifact_digest_mismatch")
    _require(isinstance(data, dict), "invalid_artifact")
    return data, raw


def _policy(policy: Any, now: datetime) -> timedelta:
    _keys(policy, {"frozen_at", "max_age_hours", "min_cases", "min_positive_cases", "min_negative_cases",
                   "min_precision", "min_recall", "min_specificity"}, {"per_kind"})
    _require(_time(policy["frozen_at"]) <= now, "future_policy")
    _require(type(policy["max_age_hours"]) is int and 1 <= policy["max_age_hours"] <= 720,
             "invalid_maximum_age")
    for name in ("min_cases", "min_positive_cases", "min_negative_cases"):
        _require(type(policy[name]) is int and 1 <= policy[name] <= 500, "invalid_sample_threshold")
    _require(policy["min_cases"] >= 20, "insufficient_minimum_sample")
    for name in ("min_precision", "min_recall", "min_specificity"):
        _require(type(policy[name]) in (float, int) and 0 < policy[name] <= 1, "invalid_metric_threshold")
    if "per_kind" in policy:
        kinds = policy["per_kind"]
        _require(isinstance(kinds, dict) and 1 <= len(kinds) <= len(Kind)
                 and set(kinds) <= {kind.value for kind in Kind}, "invalid_kind_policy")
        for limits in kinds.values():
            _keys(limits, {"min_positive_cases", "min_negative_cases", "max_false_positives", "max_false_negatives"})
            for name in ("min_positive_cases", "min_negative_cases"):
                _require(type(limits[name]) is int and 1 <= limits[name] <= 500, "invalid_kind_policy")
            for name in ("max_false_positives", "max_false_negatives"):
                _require(type(limits[name]) is int and 0 <= limits[name] <= 500, "invalid_kind_policy")
    return timedelta(hours=policy["max_age_hours"])


def _exclude_evaluated_cases(cases: list[Case], corpus_digest: str, base: Path,
                             additional: Any) -> None:
    """Prevent exact source reuse across known and declared prior evaluations.

    Each corpus remains bounded by the same validator used for the holdout. This
    can detect identical bytes and recorded locations, not near duplicates or an
    operator's failure to disclose another private evaluation corpus.
    """
    # summarize() uses "all" for its aggregate group; using that as a case
    # family would append to its input while iterating and never terminate.
    _require(all(case.family != "all" for case in cases), "reserved_evaluation_family")
    _require(isinstance(additional, list) and len(additional) <= 32, "invalid_prior_corpora")
    sources = bundled_source_index()
    with tempfile.TemporaryDirectory(prefix="nexus-prior-evaluations-") as temp:
        for number, ref in enumerate(additional):
            _, raw = _artifact(ref, base)
            snapshot = Path(temp) / f"prior-{number}.json"
            snapshot.write_text(raw, encoding="utf-8")
            _, prior, digest = load_corpus(snapshot)
            sources.add(prior, digest)

    try:
        sources.check_holdout(cases, corpus_digest)
    except SourceOverlapError as exc:
        raise EvidenceError(str(exc)) from exc


def _evaluation(evidence: Any, base: Path, policy: dict[str, Any], now: datetime,
                age: timedelta, source_sha: str, signature_sha: str) -> dict[str, Any]:
    _keys(evidence, {"corpus", "annotations", "report", "population", "evaluated_at", "holdout_frozen_at",
                     "human_reviewed", "never_used_for_tuning"}, {"prior_corpora"})
    _require(_identifier(evidence["population"]), "invalid_population")
    _require(evidence["human_reviewed"] is True and evidence["never_used_for_tuning"] is True,
             "human_holdout_declaration_required")
    evaluated = _fresh(evidence["evaluated_at"], now, age)
    frozen = _time(evidence["holdout_frozen_at"])
    _require(_time(policy["frozen_at"]) <= frozen <= evaluated, "holdout_or_policy_not_frozen_before_evaluation")
    corpus, corpus_raw = _artifact(evidence["corpus"], base)
    annotations, annotation_raw = _artifact(evidence["annotations"], base)
    report, _ = _artifact(evidence["report"], base)
    _require(annotations.get("method") == "independent-human-double-label-before-scan",
             "human_annotation_ledger_required")
    _require(isinstance(corpus.get("metadata"), dict) and corpus["metadata"].get("type") == "adjudicated",
             "adjudicated_holdout_required")
    # Reject the aggregate family before invoking annotation/corpus validators:
    # newer evaluators reject it themselves, and the acceptance gate must retain
    # its stable private error code across both validation orders.
    candidate_cases = corpus.get("cases")
    if isinstance(candidate_cases, list):
        _require(not any(isinstance(case, dict) and case.get("family") == "all"
                         for case in candidate_cases), "reserved_evaluation_family")
    # Work from the same bounded bytes whose digests were checked. Existing corpus
    # and ledger validators reopen files; private snapshots prevent a source file
    # change between digest validation and semantic validation.
    with tempfile.TemporaryDirectory(prefix="nexus-acceptance-") as temp:
        corpus_path, annotation_path = Path(temp) / "corpus.json", Path(temp) / "annotations.json"
        corpus_path.write_text(corpus_raw, encoding="utf-8")
        annotation_path.write_text(annotation_raw, encoding="utf-8")
        ledger = validate_annotations(corpus_path, annotation_path)
        metadata, cases, digest = load_corpus(corpus_path)
    _exclude_evaluated_cases(cases, digest, base, evidence.get("prior_corpora", []))
    _require(not any(case.known_gap for case in cases), "known_gap_not_allowed_in_holdout")
    _keys(report, {"schema", "corpus", "annotation_validation", "implementation", "cases", "metrics",
                   "known_gaps", "calibration", "performance", "passed"})
    _require(type(report["schema"]) is int and report["schema"] == 1, "unsupported_evaluation_schema")
    _require(report["corpus"] == {**metadata, "sha256": digest} and report["annotation_validation"] == ledger,
             "evaluation_label_provenance_mismatch")
    implementation = report["implementation"]
    _keys(implementation, {"scanner_version", "scanner_source_sha256", "signature_sha256", "python", "platform"})
    _require(implementation["scanner_version"] == __version__
             and implementation["scanner_source_sha256"] == source_sha
             and implementation["signature_sha256"] == signature_sha, "evaluation_implementation_mismatch")
    rows = report["cases"]
    _require(isinstance(rows, list) and len(rows) == len(cases), "evaluation_case_mismatch")
    expected = {case.id: case for case in cases}
    seen: set[str] = set()
    for row in rows:
        _keys(row, {"id", "family", "description", "source", "target", "present", "predicted", "score",
                    "known_gap",
                    "correct", "assertion_failures", "findings", "median_ms"})
        _require(isinstance(row["id"], str) and row["id"] in expected and row["id"] not in seen,
                 "evaluation_case_mismatch")
        seen.add(row["id"])
        case = expected[row["id"]]
        _require(row["family"] == case.family and row["source"] == case.source
                 and row["target"] == {"kind": case.kind.value, "signature": case.signature}
                 and type(row["present"]) is bool and row["present"] == case.present
                 and type(row["predicted"]) is bool and type(row["correct"]) is bool,
                 "evaluation_label_mismatch")
        _require(row["known_gap"] is False, "known_gap_not_allowed_in_holdout")
        _require(row["assertion_failures"] == [], "evaluation_assertion_failure")
        _require(row["correct"] == (row["present"] == row["predicted"]), "inconsistent_evaluation_result")
        _require(isinstance(row["findings"], list), "invalid_evaluation_findings")
        matched = []
        for finding in row["findings"]:
            _require(isinstance(finding, dict) and isinstance(finding.get("signatures"), list),
                     "invalid_evaluation_findings")
            if finding.get("kind") == case.kind.value and (case.signature is None or case.signature in finding["signatures"]):
                matched.append(finding)
        _require(row["predicted"] == bool(matched), "inconsistent_evaluation_prediction")
        _require(not _assertions(case, row["findings"]), "evaluation_assertion_failure")
    _require(type(report["passed"]) is bool and report["passed"] == all(row["correct"] for row in rows),
             "inconsistent_evaluation_result")
    metrics = summarize(rows)
    _require(report["metrics"] == metrics, "inconsistent_evaluation_metrics")
    _require(report["known_gaps"] == known_gaps(rows), "inconsistent_evaluation_result")
    _require(report["known_gaps"]["count"] == 0, "known_gap_not_allowed_in_holdout")
    overall = metrics["all"]
    for name in ("cases", "positive_cases", "negative_cases"):
        _require(overall[name] >= policy[f"min_{name}"], "sample_threshold_not_met")
    for name in ("precision", "recall", "specificity"):
        _require(overall[name] is not None and overall[name] >= policy[f"min_{name}"], "metric_threshold_not_met")
    by_kind: dict[str, Any] = {}
    for kind in sorted({case.kind.value for case in cases}):
        selected = [{**row, "family": kind} for row in rows if row["target"]["kind"] == kind]
        by_kind[kind] = summarize(selected)[kind]
    if "per_kind" in policy:
        _require(set(policy["per_kind"]) == set(by_kind), "kind_policy_scope_mismatch")
        for kind, counts in by_kind.items():
            limits = policy["per_kind"][kind]
            _require(counts["positive_cases"] >= limits["min_positive_cases"]
                     and counts["negative_cases"] >= limits["min_negative_cases"], "kind_sample_threshold_not_met")
            _require(counts["fp"] <= limits["max_false_positives"]
                     and counts["fn"] <= limits["max_false_negatives"], "kind_error_budget_exceeded")
    return {"cases": overall["cases"], "positive_cases": overall["positive_cases"],
            "negative_cases": overall["negative_cases"], "precision": overall["precision"],
            "recall": overall["recall"], "specificity": overall["specificity"], "by_kind": by_kind}


def _scope(connector: Any, scope: Any) -> None:
    _require(isinstance(connector, str) and connector in {"code.filesystem", "cloud.aws", "saas.slack"},
             "unsupported_intended_connector")
    if connector == "code.filesystem":
        _keys(scope, {"population"})
        _require(_identifier(scope["population"]), "invalid_population")
    elif connector == "cloud.aws":
        _keys(scope, {"account_id", "regions", "services"})
        _require(isinstance(scope["account_id"], str) and bool(re.fullmatch(r"[0-9]{12}", scope["account_id"])),
                 "invalid_aws_scope")
        for name in ("regions", "services"):
            values = scope[name]
            _require(isinstance(values, list) and 1 <= len(values) <= 64
                     and all(isinstance(value, str) for value in values) and len(values) == len(set(values)),
                     "invalid_aws_scope")
        _require(all(re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", value) for value in scope["regions"])
                 and set(scope["services"]) <= KNOWN_SERVICES, "invalid_aws_scope")
        _require(scope["regions"] == sorted(scope["regions"]) and scope["services"] == sorted(scope["services"]),
                 "scope_lists_must_be_sorted")
    else:
        _keys(scope, {"team_id"})
        _require(isinstance(scope["team_id"], str) and bool(re.fullmatch(r"T[A-Z0-9]+", scope["team_id"])),
                 "invalid_slack_scope")


def _receipt(ref: Any, base: Path, connector: str, scope: dict[str, Any], expectation: str,
             now: datetime, age: timedelta, canary_source_sha: str, signature_sha: str, reviewed: datetime) -> str:
    _keys(ref, {"artifact", "process_exit_code", "real_tenant_transport", "principal_ref", "separate_process"})
    _require(type(ref["process_exit_code"]) is int and ref["process_exit_code"] == 0,
             "canary_process_failed")
    _require(ref["real_tenant_transport"] is True and ref["separate_process"] is True,
             "real_transport_declaration_required")
    _require(_identifier(ref["principal_ref"]), "invalid_principal_reference")
    receipt, _ = _artifact(ref["artifact"], base)
    _keys(receipt, {"schema", "mode", "expectation", "status", "live_acceptance", "started_at", "scanner",
                    "signature_sha256", "connector", "expected_scope", "ground_truth", "limitations",
                    "abandoned_workers", "passed", "scope_verified", "observed_scope_ids", "collection_complete",
                    "classified_permission_denial", "objects_examined", "diagnostic_count", "controls", "finished_at",
                    "collection_started_at", "collection_finished_at"})
    _require(receipt["schema"] == "shadowscan.tenant-canary-report/v1" and receipt["mode"] == "live"
             and receipt["status"] == "LIVE_PASS" and receipt["expectation"] == expectation,
             "live_passing_receipt_required")
    _require(receipt["connector"] == connector and receipt["expected_scope"] == scope, "canary_scope_mismatch")
    scanner = receipt["scanner"]
    _keys(scanner, {"version", "source_sha256", "commit", "dirty"})
    _require(scanner["version"] == __version__ and scanner["source_sha256"] == canary_source_sha
             and receipt["signature_sha256"] == signature_sha, "canary_implementation_mismatch")
    start = _fresh(receipt["started_at"], now, age)
    finish = _fresh(receipt["finished_at"], now, age)
    _require(start <= _time(receipt["collection_started_at"]) <= _time(receipt["collection_finished_at"]) <= finish <= reviewed,
             "invalid_canary_time_order")
    truth = receipt["ground_truth"]
    _keys(truth, {"owner", "reviewed_at", "source", "independent_of_scanner"})
    _require(truth["independent_of_scanner"] is True and isinstance(truth["owner"], str) and bool(truth["owner"].strip())
             and isinstance(truth["source"], str) and bool(truth["source"].strip())
             and _review_before(truth["reviewed_at"], start), "independent_canary_controls_required")
    expected_id = scope["account_id"] if connector == "cloud.aws" else scope["team_id"]
    observed = receipt["observed_scope_ids"]
    _require(isinstance(observed, list) and bool(observed) and all(value == expected_id for value in observed),
             "canary_scope_mismatch")
    _require(receipt["passed"] is True and receipt["scope_verified"] is True
             and type(receipt["abandoned_workers"]) is int and receipt["abandoned_workers"] == 0,
             "canary_incomplete")
    for name in ("objects_examined", "diagnostic_count"):
        _require(type(receipt[name]) is int and receipt[name] >= 0, "invalid_canary_counts")
    complete = expectation == "complete"
    _require(receipt["live_acceptance"] is complete and receipt["collection_complete"] is complete
             and receipt["classified_permission_denial"] is (not complete), "canary_expectation_mismatch")
    if not complete:
        _require(receipt["diagnostic_count"] > 0 and receipt["controls"] == [], "canary_denial_missing")
        return str(ref["principal_ref"])
    _require(receipt["diagnostic_count"] == 0 and receipt["objects_examined"] > 0, "canary_incomplete")
    controls = receipt["controls"]
    _require(isinstance(controls, list) and 2 <= len(controls) <= 1000, "canary_controls_missing")
    polarities: set[bool] = set()
    ids: set[str] = set()
    resources: set[str] = set()
    for control in controls:
        _keys(control, {"id", "rationale", "expected", "collected_records", "observed_kinds", "passed"})
        expected = control["expected"]
        _keys(expected, {"resource", "present"}, {"kind"})
        _require(_identifier(control["id"]) and control["id"] not in ids
                 and isinstance(expected["resource"], str) and bool(expected["resource"])
                 and expected["resource"] not in resources, "duplicate_or_invalid_canary_control")
        if connector == "cloud.aws":
            arn = expected["resource"].split(":", 5)
            _require(len(arn) == 6 and arn[0] == "arn" and arn[1] in {"aws", "aws-cn", "aws-us-gov"}
                     and arn[3] in scope["regions"] and arn[4] == scope["account_id"], "canary_control_scope_mismatch")
            families = {"lambda": ("lambda", "function:"), "bedrock": ("bedrock", "agent/"),
                        "bedrock-agentcore": ("agentcore", "runtime/"), "ecs": ("ecs", "task-definition/"),
                        "sagemaker": ("sagemaker", "endpoint/"), "states": ("stepfunctions", "stateMachine:")}
            family = families.get(arn[2])
            _require(family is not None and family[0] in scope["services"]
                     and arn[5].startswith(family[1]) and len(arn[5]) > len(family[1]),
                     "canary_control_service_mismatch")
        else:
            _require(bool(re.fullmatch(r"slack:app:A[A-Z0-9]+", expected["resource"])), "invalid_slack_control_resource")
        _require(isinstance(control["rationale"], str) and bool(control["rationale"].strip()),
                 "canary_control_rationale_required")
        ids.add(control["id"])
        resources.add(expected["resource"])
        _require(type(expected["present"]) is bool and control["passed"] is True
                 and type(control["collected_records"]) is int and control["collected_records"] > 0
                 and isinstance(control["observed_kinds"], list), "canary_control_not_observed")
        polarities.add(expected["present"])
        if expected["present"]:
            _require(expected.get("kind") in {kind.value for kind in Kind}
                     and expected["kind"] in control["observed_kinds"], "canary_positive_missing")
        else:
            _require("kind" not in expected and control["observed_kinds"] == [], "canary_negative_detected")
    _require(polarities == {False, True}, "canary_controls_missing")
    return str(ref["principal_ref"])


def verify(manifest: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Raise EvidenceError on missing/invalid evidence; return no raw artifact data."""
    current = now or datetime.now(UTC)
    _require(current.tzinfo is not None, "timestamp_requires_timezone")
    current = current.astimezone(UTC)
    data, raw = _read(manifest)
    _keys(data, {"schema", "reviewer", "reviewed_at", "policy", "evaluation", "deployments"})
    _require(data["schema"] == SCHEMA, "unsupported_manifest_schema")
    _require(_identifier(data["reviewer"]), "reviewer_declaration_required")
    age = _policy(data["policy"], current)
    reviewed = _fresh(data["reviewed_at"], current, age)
    _require(isinstance(data["evaluation"], dict), "invalid_evaluation_object")
    _require(_time(data["evaluation"].get("evaluated_at")) <= reviewed, "review_precedes_evaluation")
    deployments = data["deployments"]
    _require(isinstance(deployments, list) and 1 <= len(deployments) <= 32, "intended_deployments_required")
    # Check coverage declarations before reading evidence, so unsupported connectors
    # cannot accidentally inherit a code/AWS/Slack acceptance result.
    seen: set[str] = set()
    for deployment in deployments:
        _keys(deployment, {"connector", "scope"}, {"complete", "permission_denied"})
        _scope(deployment["connector"], deployment["scope"])
        key = json.dumps([deployment["connector"], deployment["scope"]], sort_keys=True)
        _require(key not in seen, "duplicate_intended_scope")
        seen.add(key)
    signature_sha = get_index(reload=True).fingerprint()
    source_sha = _source_fingerprint()
    metrics = _evaluation(data["evaluation"], manifest.parent, data["policy"], current, age, source_sha, signature_sha)
    canary_source_sha = _source_provenance()["source_sha256"]
    canary_count = 0
    for deployment in deployments:
        connector, scope = deployment["connector"], deployment["scope"]
        if connector == "code.filesystem":
            _keys(deployment, {"connector", "scope"})
            _require(scope["population"] == data["evaluation"]["population"], "holdout_population_mismatch")
            continue
        _keys(deployment, {"connector", "scope", "complete", "permission_denied"})
        principals = [_receipt(deployment[name], manifest.parent, connector, scope, expectation,
                               current, age, canary_source_sha, signature_sha, reviewed)
                      for name, expectation in (("complete", "complete"), ("permission_denied", "permission-denied"))]
        _require(principals[0] != principals[1], "separate_restricted_principal_required")
        canary_count += 2
    return {"schema": REPORT_SCHEMA, "status": "EVIDENCE_CONSISTENT", "checked_at": current.isoformat(),
            "manifest_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "scanner_source_sha256": source_sha, "signature_sha256": signature_sha,
            "deployment_count": len(deployments), "live_receipt_count": canary_count,
            "evaluation": metrics, "limitations": LIMITATION}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", required=True, type=Path, help="private JSON decision; parent must exist")
    args = parser.parse_args(argv)
    try:
        report = verify(args.manifest)
        code = 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
        # Underlying corpus validators may include source labels in exception text;
        # never echo them, paths, reviewer declarations, principal refs or contents.
        report = {"schema": REPORT_SCHEMA, "status": "EVIDENCE_REJECTED",
                  "reason": str(exc) if isinstance(exc, EvidenceError) else "invalid_or_missing_evidence",
                  "limitations": LIMITATION}
        code = 1
    try:
        write_private_text(args.output, json.dumps(report, indent=2, allow_nan=False) + "\n")
    except (ValueError, OSError):
        print("EVIDENCE_OUTPUT_ERROR")
        return 2
    print(report["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
