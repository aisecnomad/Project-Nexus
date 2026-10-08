"""Prepare ruleset PUT payloads and compare administrator-fetched readback JSON.

This helper never contacts GitHub, authenticates evidence, or changes settings.
Fetch a fresh ruleset response before preparing a payload; review the diff before
an administrator applies it. A file matching the policy is not proof that GitHub
has applied it, and enforced approvals are not evidence of independent review.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from shadowscan.utils.files import read_policy_text
from shadowscan.utils.safe_json import strict_json_loads
from tools.governance_check import GITHUB_ACTIONS_APP_ID, REQUIRED_CHECKS, check_ruleset

REPOSITORY = "aisecnomad/Project-Nexus"
RULESETS = {23892853: "Protect main", 23913372: "Require CI and CodeQL"}
_FIELDS = ("name", "target", "enforcement", "bypass_actors", "conditions", "rules")
_CHECKS = set(REQUIRED_CHECKS)


def _load(path: Path) -> Any:
    return strict_json_loads(read_policy_text(path, max_bytes=1024 * 1024))


def _canonical(value: Any) -> str:
    # Python equality treats True, 1 and 1.0 as equal; policy JSON must not.
    return json.dumps(value, sort_keys=True, allow_nan=False)


def _rules(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a nonempty list")
    indexed: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            raise ValueError("each rule must have a type")
        name = rule["type"]
        if name in indexed:
            raise ValueError("duplicate rule types are not supported")
        indexed[name] = rule
    for name in ("pull_request", "non_fast_forward", "required_signatures"):
        if name not in indexed:
            raise ValueError(f"missing existing {name} rule; review changed source settings")
    return indexed


def _parameters(rule: dict[str, Any]) -> dict[str, Any]:
    parameters = rule.get("parameters")
    if not isinstance(parameters, dict):
        raise ValueError("rule parameters must be an object")
    return parameters


def _scope(payload: dict[str, Any]) -> None:
    conditions = payload.get("conditions")
    if not isinstance(conditions, dict) or not isinstance(conditions.get("ref_name"), dict):
        raise ValueError("missing branch conditions")
    names = conditions["ref_name"]
    include = names.get("include")
    if (
        payload.get("target") != "branch"
        or not isinstance(include, list)
        or not all(isinstance(value, str) for value in include)
        or not {"~DEFAULT_BRANCH", "refs/heads/main"}.intersection(include)
        or names.get("exclude") != []
    ):
        raise ValueError("ruleset must cover main without branch exclusions")


def _payload(snapshot: Any, ruleset_id: int, *, allow_missing_bypass: bool = False) -> dict[str, Any]:
    if (
        ruleset_id not in RULESETS
        or not isinstance(snapshot, dict)
        or type(snapshot.get("id")) is not int
        or snapshot["id"] != ruleset_id
        or snapshot.get("source_type") != "Repository"
        or snapshot.get("source") != REPOSITORY
        or snapshot.get("name") != RULESETS[ruleset_id]
    ):
        raise ValueError("ruleset response does not match the expected repository and ruleset")
    fields = tuple(field for field in _FIELDS if not (allow_missing_bypass and field == "bypass_actors"))
    if missing := [field for field in fields if field not in snapshot]:
        # GitHub returns bypass_actors only to a caller with write access to the
        # ruleset, so the read-only audit token gets a partial response. An
        # omitted field is unknown assurance, never an empty setting.
        raise ValueError(
            "ruleset response omits " + ", ".join(missing) + "; the reading identity cannot see every "
            "managed setting, so an administrator must verify a complete readback"
        )
    payload = copy.deepcopy({field: snapshot[field] for field in _FIELDS if field in snapshot})
    _scope(payload)
    _rules(payload)
    return payload


def prepare_payload(snapshot: Any, *, ruleset_id: int) -> dict[str, Any]:
    """Preserve the source policy while strengthening its review and CI controls."""
    payload = _payload(snapshot, ruleset_id)
    payload["enforcement"] = "active"
    payload["bypass_actors"] = []
    rules = _rules(payload)
    review = _parameters(rules["pull_request"])
    count = review.get("required_approving_review_count")
    if type(count) is not int or count < 0:
        raise ValueError("required approval count must be a nonnegative integer")
    review["required_approving_review_count"] = max(1, count)
    review["dismiss_stale_reviews_on_push"] = True
    review["require_last_push_approval"] = True
    review["required_review_thread_resolution"] = True
    if ruleset_id == 23913372:
        if "required_status_checks" not in rules:
            raise ValueError("missing existing status checks; review changed source settings")
        checks = _parameters(rules["required_status_checks"])
        required = checks.get("required_status_checks")
        if not isinstance(required, list) or not all(
            isinstance(check, dict) and isinstance(check.get("context"), str) for check in required
        ):
            raise ValueError("required status checks must contain named contexts")
        contexts = {check["context"] for check in required}
        if not (_CHECKS - {"CI gate"}).issubset(contexts):
            raise ValueError("existing CI or CodeQL checks are missing; review changed source settings")
        for name in sorted(_CHECKS):
            matches = [check for check in required if check["context"] == name]
            if len(matches) > 1:
                raise ValueError("duplicate required CI or CodeQL contexts; review changed source settings")
            if matches:
                integration = matches[0].get("integration_id")
                if integration is not None and (
                    type(integration) is not int or integration != GITHUB_ACTIONS_APP_ID
                ):
                    raise ValueError(
                        "required status check has a conflicting app binding; review source settings"
                    )
                matches[0]["integration_id"] = GITHUB_ACTIONS_APP_ID
            else:
                required.append({"context": name, "integration_id": GITHUB_ACTIONS_APP_ID})
        checks["strict_required_status_checks_policy"] = True
        checks["do_not_enforce_on_create"] = False
        if "deletion" not in rules:
            payload["rules"].append({"type": "deletion"})
        if failures := check_ruleset(payload):
            raise ValueError("prepared policy fails the minimum merge policy: " + ", ".join(failures))
    return payload


def _validate_expected(expected: Any, ruleset_id: int) -> None:
    if not isinstance(expected, dict) or set(expected) != set(_FIELDS):
        raise ValueError("expected policy must be a reviewed PUT payload")
    projected = {
        **expected,
        "id": ruleset_id,
        "source_type": "Repository",
        "source": REPOSITORY,
    }
    if _canonical(prepare_payload(projected, ruleset_id=ruleset_id)) != _canonical(expected):
        raise ValueError("expected policy is missing active enforcement, review, bypass or CI controls")


def verify_readback(snapshot: Any, expected: Any, *, ruleset_id: int) -> None:
    """Reject wrong identity, weakened policies, or any unreviewed settings change."""
    _validate_expected(expected, ruleset_id)
    actual = _payload(snapshot, ruleset_id)
    if _canonical(actual) != _canonical(expected):
        changed = [field for field in _FIELDS if _canonical(actual[field]) != _canonical(expected[field])]
        raise ValueError("readback differs from reviewed payload: " + ", ".join(changed))


def observe_readback(snapshot: Any, expected: Any, *, ruleset_id: int) -> dict[str, Any]:
    """Check visible settings without treating an omitted bypass list as empty.

    Only bypass_actors may be withheld. Every visible managed field must match
    the same secure expected policy used by the strict complete-readback gate.
    This observation is not a release receipt or evidence of human review.
    """
    _validate_expected(expected, ruleset_id)
    actual = _payload(snapshot, ruleset_id, allow_missing_bypass=True)
    changed = [field for field in actual if _canonical(actual[field]) != _canonical(expected[field])]
    if changed:
        raise ValueError("readback differs from reviewed payload: " + ", ".join(changed))
    unknown = [field for field in _FIELDS if field not in actual]
    return {
        "schema_version": 1,
        "repository": REPOSITORY,
        "ruleset_id": ruleset_id,
        "scope": "ruleset-settings-only",
        "status": "partial" if unknown else "complete",
        "visible_controls_match": True,
        "complete_readback_verified": not unknown,
        "verified_fields": list(actual),
        "unknown_fields": unknown,
        "administrator_readback_required": bool(unknown),
        "limitations": (
            "Snapshot settings only; does not authenticate origin, freshness, historical enforcement, "
            "other protections, independent review or deployment acceptance. "
            "A partial observation cannot replace strict complete-readback verification."
        ),
    }


def _write_observation(report: dict[str, Any], output: Path, summary: Path | None) -> None:
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    if summary is not None:
        # Use fixed text instead of copying an untrusted API/error string into Markdown.
        descriptions = {
            "partial": "Visible controls match. Bypass actors are UNKNOWN; administrator readback REQUIRED.",
            "complete": "Complete ruleset settings match; this does not establish review or acceptance.",
            "failed": "Verification FAILED. Inspect the retained observation and workflow logs.",
        }
        with summary.open("a", encoding="utf-8") as stream:
            stream.write(f"- Ruleset {report['ruleset_id']}: {descriptions[report['status']]}\n")


def _observe_cli(args: argparse.Namespace) -> None:
    report: dict[str, Any]
    try:
        if args.read_failed:
            raise ValueError("ruleset API read failed; no snapshot assurance is available")
        report = observe_readback(_load(args.input), _load(args.expected), ruleset_id=args.ruleset_id)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        report = {
            "schema_version": 1,
            "repository": REPOSITORY,
            "ruleset_id": args.ruleset_id,
            "scope": "ruleset-settings-only",
            "status": "failed",
            "visible_controls_match": False,
            "complete_readback_verified": False,
            "verified_fields": [],
            "unknown_fields": list(_FIELDS),
            "administrator_readback_required": True,
            "error": str(exc),
        }
    _write_observation(report, args.output, args.summary)
    print(f"Ruleset {args.ruleset_id}: {report['status']} settings assurance; see {args.output}")
    if report["status"] == "partial":
        print("Bypass actors are UNKNOWN; a separately verified administrator readback is REQUIRED.")
    if report["status"] == "failed":
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="generate a PUT payload without changing GitHub")
    plan.add_argument("--input", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--ruleset-id", type=int, choices=RULESETS, required=True)
    verify = subparsers.add_parser("verify", help="compare fetched readback to the reviewed payload")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--expected", type=Path, required=True)
    verify.add_argument("--ruleset-id", type=int, choices=RULESETS, required=True)
    observe = subparsers.add_parser(
        "observe", help="check visible settings; report withheld bypass assurance"
    )
    observe.add_argument("--input", type=Path, required=True)
    observe.add_argument("--expected", type=Path, required=True)
    observe.add_argument("--ruleset-id", type=int, choices=RULESETS, required=True)
    observe.add_argument("--output", type=Path, required=True)
    observe.add_argument("--summary", type=Path)
    observe.add_argument(
        "--read-failed", action="store_true", help="record a failed API read without trusting it"
    )
    args = parser.parse_args()
    try:
        if args.command == "observe":
            _observe_cli(args)
            return
        snapshot = _load(args.input)
        if args.command == "plan":
            payload = prepare_payload(snapshot, ruleset_id=args.ruleset_id)
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n")
            print("Prepared a review payload; no repository settings were changed.")
        else:
            verify_readback(snapshot, _load(args.expected), ruleset_id=args.ruleset_id)
            print("Readback JSON matches the reviewed active policy; evidence origin requires verification.")
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
