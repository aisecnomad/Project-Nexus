"""Verify supplied merge rules and prepare an additive administrator PUT body.

This module is offline: it never calls GitHub or changes repository settings.
Use a full ruleset GET response. GitHub may omit bypass_actors for callers
without write access to the ruleset; an omitted field cannot prove no bypass.
Verification establishes the supplied current settings only, not historical
enforcement, a completed human review, or a release authorization.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

from shadowscan.utils.files import read_policy_text
from shadowscan.utils.safe_json import strict_json_loads
from tools.governance_check import GITHUB_ACTIONS_APP_ID, REQUIRED_CHECKS, check_ruleset

MAIN_RULESET_ID = 23913372
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_PUT_FIELDS = ("name", "target", "enforcement", "bypass_actors", "conditions", "rules")
_SNAPSHOT_FIELDS = ("id", "source_type", "source", *_PUT_FIELDS)
_SCOPE = (
    "Supplied current merge-rule settings only; not evidence of historical enforcement, "
    "completed independent human review, or authorization to publish."
)


def _load_json(path: Path) -> Any:
    try:
        return strict_json_loads(read_policy_text(path, max_bytes=8 * 1024 * 1024))
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise ValueError("ruleset input must be bounded, unambiguous JSON with finite numbers") from None


def _boolean(parameters: dict[str, Any], field: str) -> bool:
    value = parameters.get(field)
    if type(value) is not bool:
        raise ValueError(f"merge rules require a Boolean {field}")
    return value


def _validate_ruleset(
    ruleset: Any,
    *,
    repository: str,
    ruleset_id: int,
    default_branch: str,
    require_active: bool = True,
    require_ci_gate: bool = True,
) -> dict[str, Any]:
    if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
        raise ValueError("invalid repository")
    if type(ruleset_id) is not int or ruleset_id < 1:
        raise ValueError("ruleset ID must be a positive integer")
    if default_branch != "main":
        raise ValueError("repository default branch must be main")
    if not isinstance(ruleset, dict):
        raise ValueError("ruleset response must be an object")
    if type(ruleset.get("id")) is not int or ruleset["id"] != ruleset_id:
        raise ValueError("ruleset ID does not match")
    if ruleset.get("source_type") != "Repository" or ruleset.get("source") != repository:
        raise ValueError("ruleset repository source does not match")
    if not isinstance(ruleset.get("name"), str) or not ruleset["name"].strip():
        raise ValueError("ruleset name must be a nonempty string")
    if ruleset.get("target") != "branch":
        raise ValueError("ruleset must target branches")
    enforcement = ruleset.get("enforcement")
    if enforcement not in ("active", "disabled", "evaluate") or (require_active and enforcement != "active"):
        raise ValueError("merge rules must have active enforcement")
    if "bypass_actors" not in ruleset:
        raise ValueError("full ruleset response must expose bypass_actors; omission cannot prove no bypass")
    if ruleset["bypass_actors"] != []:
        raise ValueError("merge rules must have an explicit empty bypass_actors list")
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict) or set(conditions) != {"ref_name"}:
        raise ValueError("merge rules must have unambiguous branch conditions")
    refs = conditions["ref_name"]
    if (
        not isinstance(refs, dict)
        or set(refs) != {"include", "exclude"}
        or refs["include"] not in (["~DEFAULT_BRANCH"], ["refs/heads/main"])
        or refs["exclude"] != []
    ):
        raise ValueError("merge rules must match exactly main or the default branch without exclusions")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("merge rules must contain a nonempty rule list")
    by_type: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str) or not rule["type"]:
            raise ValueError("merge rule must be an object with a type")
        if rule["type"] in by_type:
            raise ValueError("duplicate merge rule types are ambiguous")
        by_type[rule["type"]] = rule
    for rule_type in ("pull_request", "required_status_checks", "code_scanning"):
        if rule_type not in by_type or not isinstance(by_type[rule_type].get("parameters"), dict):
            raise ValueError(f"merge rules require {rule_type} parameters")
    for rule_type in ("required_signatures", "non_fast_forward"):
        if rule_type not in by_type or by_type[rule_type].get("parameters", {}) != {}:
            raise ValueError(f"merge rules require {rule_type}")
    approval = by_type["pull_request"]["parameters"]
    for field in (
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
        "required_review_thread_resolution",
    ):
        _boolean(approval, field)
    if "require_extra_approval_for_unattributed_changes" in approval:
        _boolean(approval, "require_extra_approval_for_unattributed_changes")
    count = approval.get("required_approving_review_count")
    if type(count) is not int or count < 1 or approval["dismiss_stale_reviews_on_push"] is not True:
        raise ValueError("merge rules require at least one approval and stale-review dismissal")
    checks = by_type["required_status_checks"]["parameters"]
    if _boolean(checks, "strict_required_status_checks_policy") is not True:
        raise ValueError("merge rules require strict status checks")
    if "do_not_enforce_on_create" in checks:
        _boolean(checks, "do_not_enforce_on_create")
    contexts = checks.get("required_status_checks")
    if not isinstance(contexts, list) or not contexts:
        raise ValueError("merge rules require status check contexts")
    names: set[str] = set()
    for check in contexts:
        if (
            not isinstance(check, dict)
            or not isinstance(check.get("context"), str)
            or not check["context"].strip()
        ):
            raise ValueError("required status check context must be a nonempty string")
        integration = check.get("integration_id")
        if integration is not None and (type(integration) is not int or integration < 1):
            raise ValueError("required status check integration_id must be a positive integer or null")
        if check["context"] in names:
            raise ValueError("duplicate status check contexts are ambiguous")
        names.add(check["context"])
    if "analyze" not in names or (require_ci_gate and "CI gate" not in names):
        raise ValueError("merge rules require CI gate and analyze status checks")
    tools = by_type["code_scanning"]["parameters"].get("code_scanning_tools")
    if not isinstance(tools, list) or not tools:
        raise ValueError("merge rules require code scanning tools")
    codeql = False
    for tool in tools:
        if (
            not isinstance(tool, dict)
            or not isinstance(tool.get("tool"), str)
            or not tool["tool"].strip()
            or tool.get("alerts_threshold") not in ("none", "errors", "errors_and_warnings", "all")
            or tool.get("security_alerts_threshold")
            not in ("none", "critical", "high_or_higher", "medium_or_higher", "all")
        ):
            raise ValueError("code scanning tool thresholds must be valid")
        if tool["tool"] == "CodeQL" and tool["security_alerts_threshold"] in ("medium_or_higher", "all"):
            codeql = True
    if not codeql:
        raise ValueError("merge rules require CodeQL to block medium or higher security alerts")
    # Reject non-JSON and non-finite values even in extra, preserved rule fields.
    try:
        strict_json_loads(json.dumps(ruleset, allow_nan=False))
    except (ValueError, TypeError, RecursionError):
        raise ValueError("ruleset fields must be unambiguous JSON with finite numbers") from None
    return ruleset


def verify_ruleset(
    ruleset: Any, *, repository: str, default_branch: str, ruleset_id: int = MAIN_RULESET_ID
) -> dict[str, Any]:
    """Verify settings with the caller's observed repository default branch."""
    checked = _validate_ruleset(
        ruleset, repository=repository, ruleset_id=ruleset_id, default_branch=default_branch
    )
    failures = check_ruleset(checked)
    if failures:
        raise ValueError("minimum merge policy failed: " + ", ".join(failures))
    return {
        "schema_version": 1,
        "repository": repository,
        "default_branch": default_branch,
        "ruleset_id": ruleset_id,
        "ruleset": {key: copy.deepcopy(checked[key]) for key in _SNAPSHOT_FIELDS},
        "scope": _SCOPE,
    }


def verify_receipt(receipt: Any, *, repository: str, ruleset_id: int = MAIN_RULESET_ID) -> dict[str, Any]:
    """Revalidate the snapshot and its repository/ruleset identity."""
    if (
        not isinstance(receipt, dict)
        or type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != 1
        or receipt.get("repository") != repository
        or receipt.get("default_branch") != "main"
        or type(receipt.get("ruleset_id")) is not int
        or receipt["ruleset_id"] != ruleset_id
    ):
        raise ValueError("saved merge-rule evidence does not match the release source or ruleset")
    verified = verify_ruleset(
        receipt.get("ruleset"), repository=repository, ruleset_id=ruleset_id, default_branch="main"
    )
    if receipt != verified:
        raise ValueError("saved merge-rule evidence differs from its verified settings")
    return verified


def prepare_update(
    ruleset: Any, *, repository: str, default_branch: str, ruleset_id: int = MAIN_RULESET_ID
) -> dict[str, Any]:
    """Tighten the same ruleset to the shared minimum without weakening rules."""
    checked = _validate_ruleset(
        ruleset,
        repository=repository,
        ruleset_id=ruleset_id,
        default_branch=default_branch,
        require_active=False,
        require_ci_gate=False,
    )
    body = {key: copy.deepcopy(checked[key]) for key in _PUT_FIELDS}
    body["enforcement"] = "active"
    approval = next(rule for rule in body["rules"] if rule["type"] == "pull_request")["parameters"]
    approval["require_last_push_approval"] = True
    approval["required_review_thread_resolution"] = True
    checks = next(rule for rule in body["rules"] if rule["type"] == "required_status_checks")
    contexts = checks["parameters"]["required_status_checks"]
    by_context = {check["context"]: check for check in contexts}
    for name in sorted(REQUIRED_CHECKS):
        if name not in by_context:
            contexts.append({"context": name, "integration_id": GITHUB_ACTIONS_APP_ID})
        else:
            check = by_context[name]
            integration = check.get("integration_id")
            if integration is not None and integration != GITHUB_ACTIONS_APP_ID:
                raise ValueError("required status check has a conflicting app binding")
            check["integration_id"] = GITHUB_ACTIONS_APP_ID
    if not any(rule["type"] == "deletion" for rule in body["rules"]):
        body["rules"].append({"type": "deletion"})
    scanning = next(rule for rule in body["rules"] if rule["type"] == "code_scanning")
    for tool in scanning["parameters"]["code_scanning_tools"]:
        if tool["tool"] == "CodeQL" and tool["alerts_threshold"] == "none":
            tool["alerts_threshold"] = "errors"
    verify_ruleset(
        checked | body, repository=repository, ruleset_id=ruleset_id, default_branch=default_branch
    )
    return body


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "prepare"):
        command = commands.add_parser(name)
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--repository", required=True)
        command.add_argument(
            "--default-branch", required=True, help="Repository default branch from readback"
        )
        command.add_argument("--ruleset-id", type=int, default=MAIN_RULESET_ID)
    args = parser.parse_args()
    try:
        action = verify_ruleset if args.command == "verify" else prepare_update
        result = action(
            _load_json(args.input),
            repository=args.repository,
            default_branch=args.default_branch,
            ruleset_id=args.ruleset_id,
        )
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
