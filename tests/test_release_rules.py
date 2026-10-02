"""Current settings verification and administrator patch preparation fail closed."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.release.rules import MAIN_RULESET_ID, prepare_update, verify_receipt, verify_ruleset

REPOSITORY = "aisecnomad/Project-Nexus"


def _ruleset() -> dict[str, Any]:
    return {
        "id": MAIN_RULESET_ID,
        "name": "Require CI and CodeQL",
        "source_type": "Repository",
        "source": REPOSITORY,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": False,
                    "require_extra_approval_for_unattributed_changes": True,
                    "allowed_merge_methods": ["merge", "squash", "rebase"],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": "test (3.11)", "integration_id": 123},
                        {"context": "test (3.12)", "integration_id": 123},
                        {"context": "analyze"},
                        {"context": "CI gate"},
                    ],
                },
            },
            {
                "type": "code_scanning",
                "parameters": {
                    "code_scanning_tools": [
                        {
                            "tool": "CodeQL",
                            "security_alerts_threshold": "medium_or_higher",
                            "alerts_threshold": "errors",
                        }
                    ]
                },
            },
            {"type": "code_quality", "parameters": {"severity": "warnings"}},
            {"type": "required_signatures"},
            {"type": "non_fast_forward"},
        ],
        "current_user_can_bypass": "never",
        "node_id": "unverified incidental metadata",
    }


def _parameters(ruleset: dict[str, Any], rule_type: str) -> dict[str, Any]:
    return next(rule["parameters"] for rule in ruleset["rules"] if rule["type"] == rule_type)


def _verify(ruleset: Any) -> dict[str, Any]:
    return verify_ruleset(ruleset, repository=REPOSITORY, default_branch="main")


@pytest.mark.parametrize("ref", ["~DEFAULT_BRANCH", "refs/heads/main"])
@pytest.mark.parametrize("threshold", ["medium_or_higher", "all"])
def test_verified_receipt_preserves_settings_without_claiming_human_review(ref: str, threshold: str) -> None:
    ruleset = _ruleset()
    ruleset["conditions"]["ref_name"]["include"] = [ref]
    _parameters(ruleset, "code_scanning")["code_scanning_tools"][0]["security_alerts_threshold"] = threshold
    receipt = _verify(ruleset)
    assert verify_receipt(receipt, repository=REPOSITORY) == receipt
    assert receipt["ruleset_id"] == MAIN_RULESET_ID
    assert "not evidence" in receipt["scope"]
    assert "completed independent human review" in receipt["scope"]
    assert "node_id" not in receipt["ruleset"]
    ruleset["rules"].clear()
    assert receipt["ruleset"]["rules"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", True),
        ("id", float(MAIN_RULESET_ID)),
        ("id", MAIN_RULESET_ID + 1),
        ("source", "attacker/fork"),
        ("source_type", "Organization"),
        ("target", "tag"),
        ("enforcement", "disabled"),
        ("enforcement", "evaluate"),
        ("enforcement", "enabled"),
        ("name", ""),
        ("bypass_actors", None),
        ("bypass_actors", {}),
        ("bypass_actors", [{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}]),
        ("conditions", {}),
        ("conditions", {"ref_name": {"include": ["~ALL"], "exclude": []}}),
        ("conditions", {"ref_name": {"include": ["refs/heads/*"], "exclude": []}}),
        ("conditions", {"ref_name": {"include": ["refs/heads/main"], "exclude": ["refs/heads/main"]}}),
        ("conditions", {"ref_name": {"include": ["refs/heads/main"], "exclude": []}, "other": {}}),
        ("rules", []),
        ("rules", ["required_signatures"]),
    ],
)
def test_verifier_rejects_wrong_identity_inactive_rules_and_ambiguous_branch_matches(
    field: str, value: Any
) -> None:
    with pytest.raises(ValueError):
        _verify(_ruleset() | {field: value})


def test_verifier_requires_bypass_actors_visibility_and_object_input() -> None:
    ruleset = _ruleset()
    ruleset.pop("bypass_actors")
    with pytest.raises(ValueError, match="omission cannot prove no bypass"):
        _verify(ruleset)
    with pytest.raises(ValueError, match="object"):
        _verify([])


@pytest.mark.parametrize(
    "rule_type,field,value",
    [
        ("pull_request", "required_approving_review_count", 0),
        ("pull_request", "required_approving_review_count", True),
        ("pull_request", "required_approving_review_count", 1.0),
        ("pull_request", "required_approving_review_count", "1"),
        ("pull_request", "dismiss_stale_reviews_on_push", False),
        ("pull_request", "dismiss_stale_reviews_on_push", 1),
        ("pull_request", "require_last_push_approval", "false"),
        ("pull_request", "required_review_thread_resolution", None),
        ("required_status_checks", "strict_required_status_checks_policy", False),
        ("required_status_checks", "strict_required_status_checks_policy", 1),
        ("required_status_checks", "do_not_enforce_on_create", "false"),
        ("required_status_checks", "required_status_checks", [{"context": "analyze"}]),
        ("required_status_checks", "required_status_checks", [{"context": "CI gate"}]),
        ("required_status_checks", "required_status_checks", []),
        ("required_status_checks", "required_status_checks", [{"context": True}]),
        (
            "required_status_checks",
            "required_status_checks",
            [{"context": "analyze", "integration_id": True}],
        ),
        ("code_scanning", "code_scanning_tools", []),
        (
            "code_scanning",
            "code_scanning_tools",
            [{"tool": "CodeQL", "security_alerts_threshold": "medium_or_higher", "alerts_threshold": "bad"}],
        ),
        (
            "code_scanning",
            "code_scanning_tools",
            [{"tool": "CodeQL", "security_alerts_threshold": "high_or_higher", "alerts_threshold": "errors"}],
        ),
        (
            "code_scanning",
            "code_scanning_tools",
            [{"tool": "CodeQL", "security_alerts_threshold": "none", "alerts_threshold": "errors"}],
        ),
        (
            "code_scanning",
            "code_scanning_tools",
            [{"tool": "Other", "security_alerts_threshold": "all", "alerts_threshold": "errors"}],
        ),
    ],
)
def test_verifier_rejects_weakened_or_malformed_security_controls(
    rule_type: str, field: str, value: Any
) -> None:
    ruleset = _ruleset()
    _parameters(ruleset, rule_type)[field] = value
    with pytest.raises(ValueError):
        _verify(ruleset)


@pytest.mark.parametrize(
    "rule_type",
    ["pull_request", "required_status_checks", "code_scanning", "required_signatures", "non_fast_forward"],
)
def test_verifier_rejects_missing_controls(rule_type: str) -> None:
    ruleset = _ruleset()
    ruleset["rules"] = [rule for rule in ruleset["rules"] if rule["type"] != rule_type]
    with pytest.raises(ValueError, match="require"):
        _verify(ruleset)


def test_verifier_rejects_duplicate_rules_contexts_and_nonfinite_extra_fields() -> None:
    ruleset = _ruleset()
    ruleset["rules"].append(copy.deepcopy(ruleset["rules"][0]))
    with pytest.raises(ValueError, match="duplicate merge"):
        _verify(ruleset)
    ruleset = _ruleset()
    _parameters(ruleset, "required_status_checks")["required_status_checks"].append({"context": "CI gate"})
    with pytest.raises(ValueError, match="duplicate status"):
        _verify(ruleset)
    ruleset = _ruleset()
    ruleset["extra"] = float("nan")
    with pytest.raises(ValueError, match="finite"):
        _verify(ruleset)


def test_prepare_activates_same_ruleset_additively_and_preserves_stronger_settings() -> None:
    original = _ruleset()
    original["enforcement"] = "disabled"
    _parameters(original, "pull_request")["required_approving_review_count"] = 2
    _parameters(original, "pull_request")["require_last_push_approval"] = True
    checks = _parameters(original, "required_status_checks")["required_status_checks"]
    checks.pop()
    original_copy = copy.deepcopy(original)
    body = prepare_update(original, repository=REPOSITORY, default_branch="main")
    assert original == original_copy
    assert set(body) == {"name", "target", "enforcement", "bypass_actors", "conditions", "rules"}
    assert body["name"] == original["name"]
    assert body["enforcement"] == "active"
    assert _parameters(body, "required_status_checks")["required_status_checks"] == checks + [
        {"context": "CI gate"}
    ]
    expected = copy.deepcopy(original)
    expected["enforcement"] = "active"
    _parameters(expected, "required_status_checks")["required_status_checks"].append({"context": "CI gate"})
    assert body == {key: expected[key] for key in body}
    assert _verify(original | body)
    assert prepare_update(original | body, repository=REPOSITORY, default_branch="main") == body


@pytest.mark.parametrize("case", ["bypass", "weak-approval", "missing-bypass", "wrong-id", "no-analyze"])
def test_prepare_refuses_to_rewrite_unsafe_existing_settings(case: str) -> None:
    ruleset = _ruleset()
    if case == "bypass":
        ruleset["bypass_actors"] = [{"actor_type": "User", "actor_id": 123, "bypass_mode": "always"}]
    elif case == "weak-approval":
        _parameters(ruleset, "pull_request")["required_approving_review_count"] = 0
    elif case == "missing-bypass":
        ruleset.pop("bypass_actors")
    elif case == "wrong-id":
        ruleset["id"] += 1
    else:
        _parameters(ruleset, "required_status_checks")["required_status_checks"] = [{"context": "CI gate"}]
    with pytest.raises(ValueError):
        prepare_update(ruleset, repository=REPOSITORY, default_branch="main")


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "fork/repo"),
        ("ruleset_id", MAIN_RULESET_ID + 1),
        ("ruleset_id", True),
        ("schema_version", True),
    ],
)
def test_saved_receipt_rejects_wrong_identity(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="release source or ruleset"):
        verify_receipt(_verify(_ruleset()) | {field: value}, repository=REPOSITORY)


def test_saved_receipt_rechecks_rules_and_rejects_added_claims() -> None:
    receipt = _verify(_ruleset())
    receipt["ruleset"]["enforcement"] = "disabled"
    with pytest.raises(ValueError, match="active"):
        verify_receipt(receipt, repository=REPOSITORY)
    with pytest.raises(ValueError, match="differs"):
        verify_receipt(_verify(_ruleset()) | {"human_review": True}, repository=REPOSITORY)


def _command(tmp_path: Path, action: str) -> tuple[list[str], Path, Path]:
    source = tmp_path / "ruleset.json"
    output = tmp_path / "result.json"
    return (
        [
            sys.executable,
            "-m",
            "tools.release.rules",
            action,
            "--input",
            str(source),
            "--output",
            str(output),
            "--repository",
            REPOSITORY,
            "--default-branch",
            "main",
        ],
        source,
        output,
    )


@pytest.mark.parametrize("action", ["verify", "prepare"])
def test_cli_succeeds_with_valid_input_and_refuses_unsafe_input(tmp_path: Path, action: str) -> None:
    command, source, output = _command(tmp_path, action)
    source.write_text(json.dumps(_ruleset()), encoding="utf-8")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    saved = json.loads(output.read_text())
    assert saved["ruleset_id"] == MAIN_RULESET_ID if action == "verify" else saved["enforcement"] == "active"
    output.unlink()
    source.write_text(json.dumps(_ruleset() | {"source": "attacker/fork"}), encoding="utf-8")
    assert subprocess.run(command, capture_output=True, text=True, check=False).returncode != 0
    assert not output.exists()


@pytest.mark.parametrize(
    "body",
    ['{"id":1,"id":23913372}', '{"id":23913372,"diagnostic":NaN}', '{"id":23913372,"diagnostic":1e999}'],
)
def test_cli_rejects_duplicate_or_nonfinite_json(tmp_path: Path, body: str) -> None:
    command, source, output = _command(tmp_path, "verify")
    source.write_text(body, encoding="utf-8")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "bounded, unambiguous JSON with finite numbers" in result.stderr
    assert not output.exists()
