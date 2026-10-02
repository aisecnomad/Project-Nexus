"""Policy evidence must not turn disabled or weakened rulesets into protection."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from tools.governance.verify import GovernanceError, load_ruleset, main, verify_ruleset

DEFINITION = Path(__file__).resolve().parents[1] / ".github/rulesets/require-ci-and-codeql.json"


def _snapshot() -> dict[str, Any]:
    return json.loads(DEFINITION.read_text()) | {
        "id": 23913372,
        "source_type": "Repository",
        "source": "aisecnomad/Project-Nexus",
    }


def _parameters(snapshot: dict[str, Any], kind: str) -> dict[str, Any]:
    return next(rule["parameters"] for rule in snapshot["rules"] if rule["type"] == kind)


def test_import_definition_and_snapshot_report_different_assurance_scopes() -> None:
    definition = load_ruleset(DEFINITION)
    with pytest.raises(GovernanceError, match="wrong_ruleset_id"):
        verify_ruleset(definition)
    result = verify_ruleset(definition, definition=True)
    assert result["scope"] == "uninstalled_definition"
    assert result["ruleset_id"] is None
    assert "does not authenticate" in result["limitation"]
    result = verify_ruleset(_snapshot())
    assert result["scope"] == "supplied_ruleset_snapshot"
    assert result["required_checks"] == ["CI gate", "analyze", "test (3.11)", "test (3.12)"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 23892853),
        ("id", 23913372.0),
        ("source_type", "Organization"),
        ("source", "another/repository"),
        ("target", "tag"),
        ("enforcement", "disabled"),
        ("enforcement", "evaluate"),
        ("bypass_actors", None),
        ("bypass_actors", [{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}]),
        ("rules", []),
    ],
)
def test_wrong_identity_or_unenforced_ruleset_fails(field: str, value: Any) -> None:
    snapshot = _snapshot()
    snapshot[field] = value
    with pytest.raises(GovernanceError):
        verify_ruleset(snapshot)


@pytest.mark.parametrize(
    "refs",
    [
        {"include": ["refs/heads/develop"], "exclude": []},
        {"include": ["~DEFAULT_BRANCH"], "exclude": ["refs/heads/main"]},
        {"include": ["~DEFAULT_BRANCH"], "exclude": ["refs/heads/release/*"]},
        {"include": "~DEFAULT_BRANCH", "exclude": []},
        {"include": ["~DEFAULT_BRANCH"]},
    ],
)
def test_missing_default_or_any_exclusions_cannot_establish_applicability(refs: dict[str, Any]) -> None:
    snapshot = _snapshot()
    snapshot["conditions"]["ref_name"] = refs
    with pytest.raises(GovernanceError):
        verify_ruleset(snapshot)


@pytest.mark.parametrize("context", ["CI gate", "analyze", "test (3.11)", "test (3.12)"])
def test_every_existing_and_aggregate_required_check_is_retained(context: str) -> None:
    snapshot = _snapshot()
    params = _parameters(snapshot, "required_status_checks")
    params["required_status_checks"] = [
        item for item in params["required_status_checks"] if item["context"] != context
    ]
    with pytest.raises(GovernanceError, match="required_check_missing"):
        verify_ruleset(snapshot)


@pytest.mark.parametrize("context", ["CI gate", "analyze", "test (3.11)", "test (3.12)"])
@pytest.mark.parametrize("integration_id", [None, 12345, "15368", 15368.0, True, "missing"])
def test_required_checks_cannot_be_satisfied_by_an_unbound_or_wrong_integration(
    context: str, integration_id: Any
) -> None:
    snapshot = _snapshot()
    checks = _parameters(snapshot, "required_status_checks")["required_status_checks"]
    check = next(item for item in checks if item["context"] == context)
    if integration_id == "missing":
        del check["integration_id"]
    else:
        check["integration_id"] = integration_id
    with pytest.raises(GovernanceError, match="required_check_not_bound_to_github_actions"):
        verify_ruleset(snapshot)


@pytest.mark.parametrize(
    ("kind", "field", "value"),
    [
        ("pull_request", "required_approving_review_count", 0),
        ("pull_request", "required_approving_review_count", True),
        ("pull_request", "dismiss_stale_reviews_on_push", False),
        ("pull_request", "dismiss_stale_reviews_on_push", "true"),
        ("pull_request", "require_last_push_approval", False),
        ("pull_request", "required_review_thread_resolution", False),
        ("pull_request", "require_extra_approval_for_unattributed_changes", False),
        ("required_status_checks", "strict_required_status_checks_policy", False),
        ("required_status_checks", "do_not_enforce_on_create", True),
        ("code_quality", "severity", "errors"),
        ("copilot_code_review", "review_on_push", False),
        ("copilot_code_review", "review_draft_pull_requests", False),
    ],
)
def test_weakened_existing_and_independent_review_policy_fails(kind: str, field: str, value: Any) -> None:
    snapshot = _snapshot()
    _parameters(snapshot, kind)[field] = value
    with pytest.raises(GovernanceError):
        verify_ruleset(snapshot)


@pytest.mark.parametrize(
    "kind",
    ["deletion", "non_fast_forward", "required_linear_history", "required_signatures", "code_scanning"],
)
def test_preserved_branch_and_scanning_protections_cannot_disappear(kind: str) -> None:
    snapshot = _snapshot()
    snapshot["rules"] = [rule for rule in snapshot["rules"] if rule["type"] != kind]
    with pytest.raises(GovernanceError, match="required_protection_missing"):
        verify_ruleset(snapshot)


@pytest.mark.parametrize("threshold", ["high_or_higher", "critical", "none"])
def test_codeql_security_floor_cannot_be_weakened(threshold: str) -> None:
    snapshot = _snapshot()
    _parameters(snapshot, "code_scanning")["code_scanning_tools"][0]["security_alerts_threshold"] = threshold
    with pytest.raises(GovernanceError, match="codeql_security_threshold_weakened"):
        verify_ruleset(snapshot)


def test_stricter_and_unrelated_policies_are_accepted_without_mutation() -> None:
    snapshot = _snapshot()
    _parameters(snapshot, "pull_request")["required_approving_review_count"] = 2
    _parameters(snapshot, "pull_request")["require_code_owner_review"] = True
    _parameters(snapshot, "required_status_checks")["required_status_checks"].append(
        {"context": "additional-security-gate", "integration_id": 15368}
    )
    _parameters(snapshot, "code_scanning")["code_scanning_tools"][0]["security_alerts_threshold"] = "all"
    snapshot["rules"].append(
        {"type": "commit_message_pattern", "parameters": {"operator": "starts_with", "pattern": "fix:"}}
    )
    before = copy.deepcopy(snapshot)
    assert verify_ruleset(snapshot)["approving_review_count"] == 2
    assert snapshot == before


@pytest.mark.parametrize("duplicate", ["rule", "check"])
def test_ambiguous_duplicate_policy_is_rejected(duplicate: str) -> None:
    snapshot = _snapshot()
    if duplicate == "rule":
        snapshot["rules"].append(copy.deepcopy(snapshot["rules"][0]))
    else:
        params = _parameters(snapshot, "required_status_checks")
        params["required_status_checks"].append({"context": "CI gate"})
    with pytest.raises(GovernanceError, match="duplicate"):
        verify_ruleset(snapshot)


@pytest.mark.parametrize(
    "content",
    ['{"enforcement":"active","enforcement":"disabled"}', '{"id":NaN}', '{"unrelated":1e999}'],
)
def test_ambiguous_json_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "rules.json"
    path.write_text(content)
    with pytest.raises(GovernanceError):
        load_ruleset(path)


def test_cli_fails_disabled_snapshot_and_does_not_echo_untrusted_text(tmp_path: Path, capsys: Any) -> None:
    snapshot = _snapshot()
    snapshot["enforcement"] = "disabled\x1b]untrusted"
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(snapshot))
    assert main(["--ruleset", str(path)]) == 1
    captured = capsys.readouterr()
    assert "ruleset_not_active" in captured.err
    assert "untrusted" not in captured.err
    assert not captured.out


def test_cli_success_is_explicitly_offline(tmp_path: Path, capsys: Any) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(_snapshot()))
    assert main(["--ruleset", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scope"] == "supplied_ruleset_snapshot"
    assert "No repository settings were changed" in report["limitation"]


def test_cli_invalid_or_symlink_input_fails_closed(tmp_path: Path, capsys: Any) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("[not-json")
    assert main(["--ruleset", str(path)]) == 2
    link = tmp_path / "link.json"
    link.symlink_to(DEFINITION)
    assert main(["--ruleset", str(link), "--definition"]) == 2
    assert not capsys.readouterr().out
