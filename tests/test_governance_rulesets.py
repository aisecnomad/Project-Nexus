"""Ruleset remediation must preserve policy and never manufacture live assurance."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.governance.rulesets import REPOSITORY, RULESETS, prepare_payload, verify_readback
from tools.governance_check import GITHUB_ACTIONS_APP_ID, check_ruleset

ROOT = Path(__file__).resolve().parents[1]


def _snapshot(ruleset_id: int = 23913372) -> dict[str, Any]:
    return json.loads((ROOT / ".github/rulesets/observed" / f"{ruleset_id}.json").read_text())


def _rule(snapshot: dict[str, Any], name: str) -> dict[str, Any]:
    return next(rule for rule in snapshot["rules"] if rule["type"] == name)


def _readback(payload: dict[str, Any], ruleset_id: int = 23913372) -> dict[str, Any]:
    return {**copy.deepcopy(payload), "id": ruleset_id, "source_type": "Repository", "source": REPOSITORY}


@pytest.mark.parametrize("ruleset_id", RULESETS)
def test_committed_update_matches_observed_settings_and_preserves_existing_rules(ruleset_id: int) -> None:
    source = _snapshot(ruleset_id)
    original = copy.deepcopy(source)
    payload = prepare_payload(source, ruleset_id=ruleset_id)
    committed = json.loads((ROOT / ".github/rulesets" / f"{ruleset_id}.update.json").read_text())
    assert source == original
    assert committed == payload
    assert payload["enforcement"] == "active" and payload["bypass_actors"] == []
    assert payload["conditions"] == source["conditions"]
    review = _rule(payload, "pull_request")["parameters"]
    assert review["required_approving_review_count"] >= 1
    assert review["dismiss_stale_reviews_on_push"] is True
    assert review["require_last_push_approval"] is True
    assert review["required_review_thread_resolution"] is True
    if ruleset_id == 23913372:
        assert check_ruleset(payload) == []
        minimum = json.loads((ROOT / ".github/rulesets/require-ci-and-review.json").read_text())
        assert payload == minimum
    for rule in source["rules"]:
        if rule["type"] not in {"pull_request", "required_status_checks"}:
            assert rule == _rule(payload, rule["type"])
    verify_readback(_readback(payload, ruleset_id), payload, ruleset_id=ruleset_id)
    assert prepare_payload(_readback(payload, ruleset_id), ruleset_id=ruleset_id) == payload


def test_plan_keeps_stricter_review_parameters_additional_checks_and_unknown_rules() -> None:
    source = _snapshot()
    review = _rule(source, "pull_request")["parameters"]
    review.update(
        required_approving_review_count=3,
        require_code_owner_review=True,
        require_last_push_approval=True,
        required_review_thread_resolution=True,
    )
    extra = {"context": "external security approval", "integration_id": 12345}
    _rule(source, "required_status_checks")["parameters"]["required_status_checks"].append(extra)
    source["rules"].append({"type": "future_policy", "parameters": {"retain": ["strict"]}})
    payload = prepare_payload(source, ruleset_id=23913372)
    assert _rule(payload, "pull_request")["parameters"] == review
    checks = _rule(payload, "required_status_checks")["parameters"]
    assert extra in checks["required_status_checks"]
    assert {check["context"] for check in checks["required_status_checks"]} >= {
        "test (3.11)",
        "test (3.12)",
        "analyze",
        "CI gate",
    }
    assert checks["strict_required_status_checks_policy"] is True
    assert checks["do_not_enforce_on_create"] is False
    assert all(
        check["integration_id"] == GITHUB_ACTIONS_APP_ID
        for check in checks["required_status_checks"]
        if check["context"] != extra["context"]
    )
    assert _rule(payload, "future_policy") == source["rules"][-1]


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 23892853),
        ("id", True),
        ("source", "somebody/else"),
        ("source_type", "Organization"),
        ("name", "Unexpected name"),
        ("target", "tag"),
        ("rules", []),
        ("rules", [{"type": "required_signatures"}]),
        ("conditions", {"ref_name": {"include": ["refs/heads/develop"], "exclude": []}}),
        ("conditions", {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": ["refs/heads/main"]}}),
    ],
)
def test_plan_refuses_wrong_identity_or_scope_and_missing_existing_controls(field: str, value: Any) -> None:
    source = _snapshot()
    source[field] = value
    with pytest.raises(ValueError):
        prepare_payload(source, ruleset_id=23913372)


@pytest.mark.parametrize("count", [True, -1, 1.5, "1", None])
def test_plan_refuses_ambiguous_approval_counts(count: Any) -> None:
    source = _snapshot()
    _rule(source, "pull_request")["parameters"]["required_approving_review_count"] = count
    with pytest.raises(ValueError, match="approval count"):
        prepare_payload(source, ruleset_id=23913372)


def test_plan_refuses_duplicate_rules_or_missing_existing_status_contexts() -> None:
    source = _snapshot()
    source["rules"].append(copy.deepcopy(source["rules"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        prepare_payload(source, ruleset_id=23913372)
    source = _snapshot()
    _rule(source, "required_status_checks")["parameters"]["required_status_checks"].pop()
    with pytest.raises(ValueError, match="existing CI or CodeQL"):
        prepare_payload(source, ruleset_id=23913372)


@pytest.mark.parametrize("binding", [True, 0, -1, 42, 15368.0, "15368"])
def test_plan_refuses_to_replace_a_conflicting_or_malformed_check_binding(binding: Any) -> None:
    source = _snapshot()
    checks = _rule(source, "required_status_checks")["parameters"]["required_status_checks"]
    checks[0]["integration_id"] = binding
    original = copy.deepcopy(source)
    with pytest.raises(ValueError, match="conflicting app binding"):
        prepare_payload(source, ruleset_id=23913372)
    assert source == original


@pytest.mark.parametrize("binding", [None, GITHUB_ACTIONS_APP_ID])
def test_plan_pins_unbound_checks_and_preserves_the_expected_app(binding: int | None) -> None:
    source = _snapshot()
    checks = _rule(source, "required_status_checks")["parameters"]["required_status_checks"]
    checks[0]["integration_id"] = binding
    checks[1].pop("integration_id", None)
    payload = prepare_payload(source, ruleset_id=23913372)
    assert check_ruleset(payload) == []


@pytest.mark.parametrize(
    "weakening",
    ["disabled", "bypass", "approval", "stale", "last_push", "threads", "gate", "unbound", "strict", "rule"],
)
def test_readback_rejects_disabled_or_weakened_controls(weakening: str) -> None:
    payload = prepare_payload(_snapshot(), ruleset_id=23913372)
    actual = _readback(payload)
    if weakening == "disabled":
        actual["enforcement"] = "disabled"
    elif weakening == "bypass":
        actual["bypass_actors"] = [{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}]
    elif weakening in {"approval", "stale", "last_push", "threads"}:
        review = _rule(actual, "pull_request")["parameters"]
        field = {
            "approval": "required_approving_review_count",
            "stale": "dismiss_stale_reviews_on_push",
            "last_push": "require_last_push_approval",
            "threads": "required_review_thread_resolution",
        }[weakening]
        review[field] = 0 if weakening == "approval" else False
    elif weakening in {"gate", "unbound", "strict"}:
        checks = _rule(actual, "required_status_checks")["parameters"]
        if weakening == "gate":
            checks["required_status_checks"].pop()
        elif weakening == "unbound":
            checks["required_status_checks"][0].pop("integration_id")
        else:
            checks["strict_required_status_checks_policy"] = False
    else:
        actual["rules"] = [rule for rule in actual["rules"] if rule["type"] != "required_signatures"]
    with pytest.raises(ValueError):
        verify_readback(actual, payload, ruleset_id=23913372)


def test_readback_rejects_an_unreviewed_rule_change_and_an_insecure_expected_payload() -> None:
    payload = prepare_payload(_snapshot(), ruleset_id=23913372)
    actual = _readback(payload)
    _rule(actual, "code_quality")["parameters"]["severity"] = "errors"
    with pytest.raises(ValueError, match="readback differs"):
        verify_readback(actual, payload, ruleset_id=23913372)
    expected = copy.deepcopy(payload)
    expected["enforcement"] = "disabled"
    with pytest.raises(ValueError, match="expected policy"):
        verify_readback(_readback(expected), expected, ruleset_id=23913372)


@pytest.mark.parametrize(
    "rule_name,parameter,value",
    [
        ("pull_request", "required_approving_review_count", True),
        ("pull_request", "required_approving_review_count", 1.0),
        ("pull_request", "dismiss_stale_reviews_on_push", 1),
        ("required_status_checks", "strict_required_status_checks_policy", 1),
        ("required_status_checks", "do_not_enforce_on_create", 0),
    ],
)
def test_readback_distinguishes_boolean_controls_from_numeric_values(
    rule_name: str, parameter: str, value: Any
) -> None:
    payload = prepare_payload(_snapshot(), ruleset_id=23913372)
    actual = _readback(payload)
    _rule(actual, rule_name)["parameters"][parameter] = value
    with pytest.raises(ValueError, match="readback differs"):
        verify_readback(actual, payload, ruleset_id=23913372)


def test_cli_prepares_new_file_but_refuses_overwrite_or_ambiguous_json(tmp_path: Path) -> None:
    source = tmp_path / "snapshot.json"
    output = tmp_path / "update.json"
    source.write_text(json.dumps(_snapshot()))
    command = [
        sys.executable,
        "-m",
        "tools.governance.rulesets",
        "plan",
        "--input",
        str(source),
        "--output",
        str(output),
        "--ruleset-id",
        "23913372",
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0 and "no repository settings were changed" in result.stdout
    written = output.read_bytes()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0 and output.read_bytes() == written
    output.unlink()
    source.write_text('{"id":23913372,"id":23892853}')
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0 and not output.exists()


def test_cli_verify_is_nonzero_for_the_observed_disabled_ruleset(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.governance.rulesets",
            "verify",
            "--ruleset-id",
            "23913372",
            "--input",
            str(ROOT / ".github/rulesets/observed/23913372.json"),
            "--expected",
            str(ROOT / ".github/rulesets/23913372.update.json"),
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 and "readback differs" in result.stderr
