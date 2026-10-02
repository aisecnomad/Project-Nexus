"""Check a downloaded repository ruleset against the reviewed merge-policy floor.

This command never contacts GitHub or changes repository settings. Supplied JSON
cannot establish its own authenticity, freshness, reviewer identity or effective
branch protection; retain authenticated API readbacks and review those separately.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

from shadowscan.utils.files import read_policy_text

REPOSITORY = "aisecnomad/Project-Nexus"
RULESET_ID = 23913372
GITHUB_ACTIONS_INTEGRATION_ID = 15368
MAX_BYTES = 1024 * 1024
REQUIRED_CHECKS = {"CI gate", "analyze", "test (3.11)", "test (3.12)"}
REQUIRED_RULES = {
    "pull_request",
    "required_status_checks",
    "code_scanning",
    "code_quality",
    "copilot_code_review",
    "deletion",
    "non_fast_forward",
    "required_linear_history",
    "required_signatures",
}
LIMITATION = (
    "Checks supplied JSON only; does not authenticate GitHub, freshness, effective "
    "branch protection or independent human approval. No repository settings were changed."
)


class GovernanceError(ValueError):
    """Fixed diagnostics keep untrusted API text out of terminal output."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GovernanceError(message)


def _object(value: Any) -> dict[str, Any]:
    _require(isinstance(value, dict), "expected_object")
    return dict(value)


def _array(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise GovernanceError("expected_array")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise GovernanceError("nonfinite_json_number")


def _finite_float(value: str) -> float:
    number = float(value)
    _require(math.isfinite(number), "nonfinite_json_number")
    return number


def load_ruleset(path: Path) -> dict[str, Any]:
    """Read one bounded, symlink-free JSON object without ambiguous keys."""
    value = json.loads(
        read_policy_text(path, max_bytes=MAX_BYTES),
        object_pairs_hook=_pairs,
        parse_constant=_constant,
        parse_float=_finite_float,
    )
    return _object(value)


def verify_ruleset(value: Any, *, definition: bool = False) -> dict[str, Any]:
    """Validate a snapshot, or explicitly validate an uninstalled import definition.

    Unknown additional rules and stricter settings are retained and accepted.
    Duplicate rule types/check contexts are rejected rather than guessing which
    one GitHub will enforce. An omitted bypass list cannot prove there are none.
    """
    ruleset = _object(value)
    if not definition:
        _require(type(ruleset.get("id")) is int and ruleset["id"] == RULESET_ID, "wrong_ruleset_id")
        _require(ruleset.get("source_type") == "Repository", "wrong_ruleset_source_type")
        _require(ruleset.get("source") == REPOSITORY, "wrong_ruleset_repository")
    _require(ruleset.get("target") == "branch", "ruleset_must_target_branches")
    _require(ruleset.get("enforcement") == "active", "ruleset_not_active")
    _require(ruleset.get("bypass_actors") == [], "bypass_list_missing_or_not_empty")
    conditions = _object(ruleset.get("conditions"))
    _require(set(conditions) == {"ref_name"}, "unsupported_ruleset_conditions")
    refs = _object(conditions.get("ref_name"))
    included = refs.get("include")
    _require(
        isinstance(included, list)
        and all(isinstance(ref, str) for ref in included)
        and "~DEFAULT_BRANCH" in included,
        "default_branch_not_included",
    )
    _require(refs.get("exclude") == [], "branch_exclusions_missing_or_not_empty")
    raw_rules = _array(ruleset.get("rules"))
    _require(bool(raw_rules), "rules_missing")
    rules: dict[str, dict[str, Any]] = {}
    for raw_rule in raw_rules:
        rule = _object(raw_rule)
        kind = rule.get("type")
        if not isinstance(kind, str) or not kind:
            raise GovernanceError("invalid_rule_type")
        _require(kind not in rules, "duplicate_rule_type")
        rules[kind] = rule
    _require(rules.keys() >= REQUIRED_RULES, "required_protection_missing")

    review = _object(rules["pull_request"].get("parameters"))
    count = review.get("required_approving_review_count")
    _require(type(count) is int and 1 <= count <= 10, "independent_approval_required")
    for name in (
        "dismiss_stale_reviews_on_push",
        "require_last_push_approval",
        "required_review_thread_resolution",
        "require_extra_approval_for_unattributed_changes",
    ):
        _require(review.get(name) is True, f"review_policy_required:{name}")

    status = _object(rules["required_status_checks"].get("parameters"))
    _require(status.get("strict_required_status_checks_policy") is True, "up_to_date_branch_required")
    _require(status.get("do_not_enforce_on_create") is False, "creation_must_enforce_checks")
    checks = _array(status.get("required_status_checks"))
    contexts: set[str] = set()
    for raw_check in checks:
        check = _object(raw_check)
        context = check.get("context")
        if not isinstance(context, str) or not context:
            raise GovernanceError("invalid_check_context")
        _require(context not in contexts, "duplicate_check_context")
        if context in REQUIRED_CHECKS:
            integration = check.get("integration_id")
            _require(
                type(integration) is int and integration == GITHUB_ACTIONS_INTEGRATION_ID,
                "required_check_not_bound_to_github_actions",
            )
        contexts.add(context)
    _require(contexts >= REQUIRED_CHECKS, "required_check_missing")

    scanning = _array(_object(rules["code_scanning"].get("parameters")).get("code_scanning_tools"))
    codeql = [tool for tool in scanning if isinstance(tool, dict) and tool.get("tool") == "CodeQL"]
    _require(len(codeql) == 1, "unambiguous_codeql_rule_required")
    _require(
        codeql[0].get("security_alerts_threshold") in ("all", "medium_or_higher"),
        "codeql_security_threshold_weakened",
    )
    _require(
        codeql[0].get("alerts_threshold") in ("all", "errors_and_warnings", "errors"),
        "codeql_alert_threshold_weakened",
    )
    quality = _object(rules["code_quality"].get("parameters"))
    _require(quality.get("severity") == "warnings", "code_quality_threshold_weakened")
    copilot = _object(rules["copilot_code_review"].get("parameters"))
    _require(copilot.get("review_on_push") is True, "existing_push_review_missing")
    _require(copilot.get("review_draft_pull_requests") is True, "existing_draft_review_missing")
    return {
        "policy_met": True,
        "scope": "uninstalled_definition" if definition else "supplied_ruleset_snapshot",
        "repository": REPOSITORY,
        "ruleset_id": None if definition else RULESET_ID,
        "required_checks": sorted(contexts),
        "approving_review_count": count,
        "limitation": LIMITATION,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ruleset", required=True, type=Path, help="downloaded ruleset JSON")
    parser.add_argument(
        "--definition", action="store_true", help="check an import definition; never claim live enforcement"
    )
    args = parser.parse_args(argv)
    try:
        result = verify_ruleset(load_ruleset(args.ruleset), definition=args.definition)
    except GovernanceError as exc:
        print(f"Governance policy failed: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, RecursionError):
        print("Governance input invalid or unreadable", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
