"""Check a bounded GitHub ruleset snapshot against the minimum merge policy.

This offline check does not fetch or update repository settings. Only a fresh
snapshot from the repository API can describe live enforcement.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from shadowscan.utils.files import read_policy_text
from shadowscan.utils.safe_json import strict_json_loads

REQUIRED_CHECKS = frozenset({"CI gate", "analyze", "test (3.11)", "test (3.12)"})
GITHUB_ACTIONS_APP_ID = 15368


def check_ruleset(snapshot: Any) -> list[str]:
    """Return fixed diagnostic codes; never reflect untrusted settings values."""
    if not isinstance(snapshot, dict):
        return ["invalid_ruleset"]
    failures = []
    if snapshot.get("enforcement") != "active":
        failures.append("ruleset_not_active")
    if snapshot.get("target") != "branch":
        failures.append("not_a_branch_ruleset")
    conditions = snapshot.get("conditions")
    refs = conditions.get("ref_name") if isinstance(conditions, dict) else None
    if (
        not isinstance(conditions, dict)
        or set(conditions) != {"ref_name"}
        or not isinstance(refs, dict)
        or set(refs) != {"include", "exclude"}
        or refs.get("include") not in (["~DEFAULT_BRANCH"], ["refs/heads/main"])
        or refs.get("exclude") != []
    ):
        failures.append("main_scope_not_explicit")
    if snapshot.get("bypass_actors") != []:
        failures.append("bypass_actors_not_empty")
    rows = snapshot.get("rules")
    if not isinstance(rows, list) or any(
        not isinstance(row, dict) or not isinstance(row.get("type"), str) for row in rows
    ):
        return [*failures, "invalid_rules"]
    rules = {row["type"]: row for row in rows}
    if len(rules) != len(rows):
        return [*failures, "duplicate_rule_types"]
    review = rules.get("pull_request", {}).get("parameters")
    if not isinstance(review, dict):
        failures.append("pull_request_review_required")
    else:
        count = review.get("required_approving_review_count")
        if type(count) is not int or count < 1:
            failures.append("non_author_approval_required")
        for field in (
            "dismiss_stale_reviews_on_push",
            "require_last_push_approval",
            "required_review_thread_resolution",
        ):
            if review.get(field) is not True:
                failures.append(field + "_required")
    checks = rules.get("required_status_checks", {}).get("parameters")
    if not isinstance(checks, dict):
        failures.append("status_checks_required")
    else:
        if checks.get("strict_required_status_checks_policy") is not True:
            failures.append("up_to_date_branch_required")
        required = checks.get("required_status_checks")
        if not isinstance(required, list) or any(not isinstance(check, dict) for check in required):
            failures.append("invalid_status_checks")
        else:
            for name in sorted(REQUIRED_CHECKS):
                matches = [check for check in required if check.get("context") == name]
                if (
                    len(matches) != 1
                    or type(matches[0].get("integration_id")) is not int
                    or matches[0]["integration_id"] != GITHUB_ACTIONS_APP_ID
                ):
                    failures.append("required_check_missing_or_unbound")
    for name in ("deletion", "non_fast_forward", "required_signatures", "code_scanning"):
        if name not in rules:
            failures.append(name + "_required")
    for name in ("deletion", "non_fast_forward", "required_signatures"):
        if name in rules and rules[name].get("parameters", {}) != {}:
            failures.append("invalid_rule_parameters")
    scanning = rules.get("code_scanning", {}).get("parameters")
    tools = scanning.get("code_scanning_tools") if isinstance(scanning, dict) else None
    if not isinstance(tools, list) or not any(
        isinstance(tool, dict)
        and tool.get("tool") == "CodeQL"
        and tool.get("security_alerts_threshold") in ("medium_or_higher", "all")
        and tool.get("alerts_threshold") in ("errors", "errors_and_warnings", "all")
        for tool in tools
    ):
        failures.append("codeql_alert_gate_required")
    return sorted(set(failures))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path, help="ruleset JSON from a fresh GitHub API read")
    args = parser.parse_args(argv)
    try:
        snapshot = strict_json_loads(read_policy_text(args.snapshot, max_bytes=256_000))
        failures = check_ruleset(snapshot)
    except (OSError, ValueError, RecursionError):
        print("Cannot read an unambiguous bounded ruleset snapshot.", file=sys.stderr)
        return 2
    if failures:
        print("Merge policy check failed: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("Snapshot meets the minimum merge policy; freshness and human review need separate verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
