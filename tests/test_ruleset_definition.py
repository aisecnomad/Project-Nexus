"""Keep the versioned main-branch ruleset importable and in step with the workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULESET = ROOT / ".github" / "rulesets" / "main.json"
WORKFLOWS = ROOT / ".github" / "workflows"
# GitHub Actions' app ID: a check reported by any other app or by a plain
# commit status must not satisfy the requirement.
GITHUB_ACTIONS_APP_ID = 15368


def _ruleset() -> dict[str, Any]:
    data = json.loads(RULESET.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _rule(ruleset: dict[str, Any], rule_type: str) -> dict[str, Any]:
    matches = [rule for rule in ruleset["rules"] if rule["type"] == rule_type]
    assert len(matches) == 1, f"expected exactly one {rule_type} rule"
    return matches[0]


def _check_names() -> set[str]:
    """Display names GitHub reports for each workflow job, expanding one-axis matrices."""
    names: set[str] = set()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        jobs = yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs", {})
        for job_id, job in jobs.items():
            name = job.get("name", job_id)
            matrix = (job.get("strategy") or {}).get("matrix") or {}
            axes = [values for key, values in matrix.items() if key not in {"include", "exclude"}]
            if len(axes) == 1 and "${{" not in name:
                names.update(f"{name} ({value})" for value in axes[0])
            else:
                names.add(name)
    return names


def test_ruleset_targets_main_and_cannot_be_bypassed() -> None:
    ruleset = _ruleset()
    assert ruleset["target"] == "branch"
    assert ruleset["enforcement"] == "active"
    assert ruleset["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    # A bypass list would let the author merge without the review below.
    assert ruleset["bypass_actors"] == []
    _rule(ruleset, "deletion")
    _rule(ruleset, "non_fast_forward")


def test_ruleset_requires_an_approval_of_the_final_revision() -> None:
    parameters = _rule(_ruleset(), "pull_request")["parameters"]
    assert parameters["required_approving_review_count"] >= 1
    assert parameters["dismiss_stale_reviews_on_push"] is True
    assert parameters["require_last_push_approval"] is True


def test_required_checks_exist_and_come_from_github_actions() -> None:
    parameters = _rule(_ruleset(), "required_status_checks")["parameters"]
    assert parameters["strict_required_status_checks_policy"] is True
    checks = parameters["required_status_checks"]
    contexts = [check["context"] for check in checks]
    assert {"CI gate", "analyze"} <= set(contexts)
    assert len(contexts) == len(set(contexts))
    # A renamed job would leave a required check that never reports.
    assert set(contexts) <= _check_names()
    assert {check["integration_id"] for check in checks} == {GITHUB_ACTIONS_APP_ID}
