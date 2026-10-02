"""Disabled, bypassable or partial rules must not qualify as enforced review."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.governance_check import check_ruleset, main

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy():
    return json.loads((ROOT / ".github/rulesets/require-ci-and-review.json").read_text())


def parameters(policy, name):
    return next(rule["parameters"] for rule in policy["rules"] if rule["type"] == name)


def test_recommended_policy_and_api_metadata_are_accepted(policy):
    assert check_ruleset({**policy, "id": 23913372, "updated_at": "2026-10-01"}) == []
    policy["rules"].append({"type": "required_linear_history"})
    parameters(policy, "pull_request")["required_approving_review_count"] = 2
    assert check_ruleset(policy) == []


@pytest.mark.parametrize("enforcement", ["disabled", "evaluate", None])
def test_disabled_or_evaluation_rules_are_not_enforcement(policy, enforcement):
    policy["enforcement"] = enforcement
    assert "ruleset_not_active" in check_ruleset(policy)


def test_bypass_or_scope_exclusion_prevents_policy_acceptance(policy):
    policy["bypass_actors"] = [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
    assert "bypass_actors_not_empty" in check_ruleset(policy)
    policy["bypass_actors"] = []
    policy["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
    assert "main_scope_not_explicit" in check_ruleset(policy)


@pytest.mark.parametrize("change", ["missing_gate", "unbound_gate", "non_strict"])
def test_partial_or_spoofable_ci_checks_fail(policy, change):
    checks = parameters(policy, "required_status_checks")
    gate = next(check for check in checks["required_status_checks"] if check["context"] == "CI gate")
    if change == "missing_gate":
        checks["required_status_checks"].remove(gate)
    elif change == "unbound_gate":
        gate.pop("integration_id")
    else:
        checks["strict_required_status_checks_policy"] = False
    assert check_ruleset(policy)


@pytest.mark.parametrize(
    "field,value",
    [
        ("required_approving_review_count", 0),
        ("required_approving_review_count", True),
        ("dismiss_stale_reviews_on_push", False),
        ("require_last_push_approval", False),
        ("required_review_thread_resolution", False),
    ],
)
def test_non_author_final_revision_review_is_required(policy, field, value):
    parameters(policy, "pull_request")[field] = value
    assert check_ruleset(policy)


def test_malformed_and_duplicate_rules_fail_without_reflecting_values(policy):
    for malformed in (None, [], {"rules": None}, {"rules": ["sensitive-value"]}):
        assert "sensitive-value" not in repr(check_ruleset(malformed))
        assert check_ruleset(malformed)
    policy["rules"].append(copy.deepcopy(policy["rules"][0]))
    assert "duplicate_rule_types" in check_ruleset(policy)


@pytest.mark.parametrize(
    "tools",
    [
        [],
        None,
        [{"tool": "other", "security_alerts_threshold": "all", "alerts_threshold": "all"}],
        [{"tool": "CodeQL", "security_alerts_threshold": "none", "alerts_threshold": "errors"}],
        [{"tool": "CodeQL", "security_alerts_threshold": "medium_or_higher", "alerts_threshold": "none"}],
        [{"tool": "CodeQL", "security_alerts_threshold": [], "alerts_threshold": "errors"}],
        [{"tool": "CodeQL", "security_alerts_threshold": "all", "alerts_threshold": {}}],
    ],
)
def test_codeql_rule_must_block_alerts_instead_of_merely_existing(policy, tools):
    parameters(policy, "code_scanning")["code_scanning_tools"] = tools
    assert "codeql_alert_gate_required" in check_ruleset(policy)


def test_cli_checks_snapshot_and_rejects_ambiguous_json(policy, tmp_path, capsys):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(policy))
    assert main([str(path)]) == 0
    policy["enforcement"] = "disabled"
    path.write_text(json.dumps(policy))
    assert main([str(path)]) == 1
    path.write_text('{"enforcement":"disabled","enforcement":"active"}')
    assert main([str(path)]) == 2
    assert "unambiguous" in capsys.readouterr().err
