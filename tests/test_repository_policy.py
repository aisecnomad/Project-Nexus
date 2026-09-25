"""Guard workflow privileges, manual publication, and valid issue-form labels."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
WORKFLOWS = sorted((GITHUB / "workflows").glob("*.yml"))
FORMS = sorted(path for path in (GITHUB / "ISSUE_TEMPLATE").glob("*.yml") if path.name != "config.yml")
ACTION_PIN = re.compile(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}")
# Privileges belong only to the job that needs them, never to every workflow.
WRITE_SCOPES = {
    ("codeql.yml", "analyze"): {"security-events"},
    ("scorecard.yml", "analysis"): {"security-events", "id-token"},
    ("release.yml", "attest"): {"attestations", "id-token"},
    ("docs.yml", "deploy"): {"pages", "id-token"},
    ("stale.yml", "stale"): {"issues", "pull-requests"},
    ("labels.yml", "sync"): {"issues"},
}


class _UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate keys before PyYAML silently discards policy entries."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    "while reading a repository YAML file", node.start_mark,
                    f"duplicate YAML key {key!r}", key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _load(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)


@pytest.mark.parametrize("contents", [
    "name: Detection\nlabels: [detection]\nlabels: [bug]\n",
    "permissions:\n  contents: read\n  contents: write\n",
])
def test_policy_loader_rejects_duplicate_keys(tmp_path: Path, contents: str) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate YAML key"):
        _load(path)


def _triggers(workflow: dict[str, Any]) -> Any:
    # PyYAML's YAML 1.1 parser treats the unquoted key `on` as True.
    return workflow.get("on", workflow.get(True, {}))


def _write_scopes(permissions: Any) -> set[str]:
    if permissions == "read-all":
        return set()
    assert isinstance(permissions, dict), "permissions must be explicit and must not use write-all"
    assert all(level in {"read", "write", "none"} for level in permissions.values())
    return {scope for scope, level in permissions.items() if level == "write"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_workflows_use_pinned_actions_and_scoped_permissions(path: Path) -> None:
    workflow = _load(path)
    assert "permissions" in workflow
    assert not _write_scopes(workflow["permissions"]), "top-level permissions must be read-only"
    assert "pull_request_target" not in _triggers(workflow)
    for name, job in workflow["jobs"].items():
        assert type(job.get("timeout-minutes")) is int and job["timeout-minutes"] > 0, name
        permissions = job.get("permissions", workflow["permissions"])
        assert _write_scopes(permissions) <= WRITE_SCOPES.get((path.name, name), set()), name
        for step in job.get("steps", []):
            action = step.get("uses")
            if action:
                assert ACTION_PIN.fullmatch(action), f"{name}: unpinned action {action}"
                if action.startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False, name
            script = step.get("run", "")
            assert not re.search(r"\$\{\{\s*github\.(?:event\.|head_ref\b)", script), name


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_workflows_do_not_publish_releases_packages_or_tags(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for marker in (
        "pypa/gh-action-pypi-publish", "softprops/action-gh-release", "ncipollo/release-action",
        "twine upload", "gh release create", "git push --tags", "git push origin v",
    ):
        assert marker not in text, f"publication is a manual maintainer action: {marker}"


def test_pages_requires_explicit_manual_publication_from_main() -> None:
    workflow = _load(GITHUB / "workflows" / "docs.yml")
    triggers = _triggers(workflow)
    assert "pull_request" in triggers, "documentation changes must be checked before merge"
    publish = triggers["workflow_dispatch"]["inputs"]["publish"]
    assert publish["type"] == "boolean" and publish["default"] is False
    deploy = workflow["jobs"]["deploy"]
    expression = deploy.get("if", "").strip().removeprefix("${{").removesuffix("}}").strip()
    clauses = {re.sub(r"\s+", " ", clause.strip()).replace('"', "'") for clause in expression.split("&&")}
    assert clauses == {
        "github.event_name == 'workflow_dispatch'", "inputs.publish", "github.ref == 'refs/heads/main'",
    }, "Pages deployment must require a manual dispatch, publish=true, and the main branch"
    assert "build" in ([deploy["needs"]] if isinstance(deploy["needs"], str) else deploy["needs"])


def test_stale_automation_never_closes_issues_or_pull_requests() -> None:
    workflow = _load(GITHUB / "workflows" / "stale.yml")
    steps = [
        step for job in workflow["jobs"].values() for step in job.get("steps", [])
        if step.get("uses", "").startswith("actions/stale@")
    ]
    assert steps
    for step in steps:
        options = step["with"]
        for kind in ("issue", "pr"):
            assert options.get(f"days-before-{kind}-close", options.get("days-before-close")) == -1
        assert options.get("exempt-draft-pr") is True
        exempt = {label.strip() for label in options.get("exempt-issue-labels", "").split(",")}
        assert {"security", "pinned", "bug"} <= exempt


def test_labels_are_well_formed_and_unique() -> None:
    entries = _load(GITHUB / "labels.yml")
    assert isinstance(entries, list) and entries
    names = []
    for label in entries:
        assert isinstance(label, dict)
        assert isinstance(label.get("name"), str) and label["name"].strip()
        names.append(label["name"].casefold())
        assert isinstance(label.get("color"), str) and re.fullmatch(r"[0-9a-fA-F]{6}", label["color"])
        description = label.get("description", "")
        assert isinstance(description, str) and len(description) <= 100
    assert len(names) == len(set(names))


@pytest.mark.parametrize("path", FORMS, ids=lambda path: path.name)
def test_issue_forms_are_valid_and_only_apply_defined_labels(path: Path) -> None:
    form = _load(path)
    assert form.get("name") and form.get("description")
    labels = {label["name"] for label in _load(GITHUB / "labels.yml")}
    assert set(form.get("labels", [])) <= labels
    body = form.get("body")
    assert isinstance(body, list) and body
    identifiers = []
    for element in body:
        kind = element.get("type")
        assert kind in {"markdown", "input", "textarea", "dropdown", "checkboxes"}
        attributes = element.get("attributes")
        assert isinstance(attributes, dict)
        if kind == "markdown":
            assert attributes.get("value")
            continue
        identifier = element.get("id")
        assert isinstance(identifier, str) and identifier
        identifiers.append(identifier)
        assert attributes.get("label")
        if kind in {"dropdown", "checkboxes"}:
            options = attributes.get("options")
            assert isinstance(options, list) and options
            if kind == "checkboxes":
                assert all(isinstance(option, dict) and option.get("label") for option in options)
    assert len(identifiers) == len(set(identifiers))


def test_label_sync_only_mutates_labels_from_main() -> None:
    workflow = _load(GITHUB / "workflows" / "labels.yml")
    job = workflow["jobs"]["sync"]
    assert job.get("if") == "github.ref == 'refs/heads/main'"
    assert _write_scopes(job["permissions"]) == {"issues"}
    install = next(step["run"] for step in job["steps"] if step.get("name", "").startswith("Install hash-locked PyYAML"))
    sync = next(step["run"] for step in job["steps"] if step.get("name", "").startswith("Create or update every label"))
    assert "python -m venv" in install and "requirements.lock" in install
    assert "--require-hashes --only-binary=:all:" in install
    assert '"$RUNNER_TEMP/labels-venv/bin/python" - <<' in sync
