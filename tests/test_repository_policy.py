"""Guard workflow privileges, manual publication, and valid issue-form labels."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
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
    """Reject duplicate keys without treating GitHub's `on` key as a boolean."""

    # Copy the resolver table before changing it; leave PyYAML's global loader
    # untouched. GitHub uses YAML 1.2 booleans, unlike SafeLoader's YAML 1.1.
    yaml_implicit_resolvers = {
        initial: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
        for initial, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
        return super().construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _parse(text: str) -> Any:
    return yaml.load(text, Loader=_UniqueKeyLoader)


def _load(path: Path) -> Any:
    return _parse(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "text",
    [
        "labels: [bug]\nlabels: [detection]\n",
        "jobs:\n  check:\n    permissions: {}\n    permissions: {contents: write}\n",
        "permissions:\n  contents: read\n  contents: write\n",
        "on: [push]\non: [workflow_dispatch]\n",
    ],
)
def test_yaml_policy_loading_rejects_duplicate_keys(text: str) -> None:
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        _parse(text)


def test_yaml_policy_loading_preserves_on_and_real_boolean_values() -> None:
    data = _parse("on: [push]\npublish: false\nenabled: true\n")
    assert data["on"] == ["push"]
    assert data["publish"] is False
    assert data["enabled"] is True
    # The local policy loader must not change behavior for other YAML consumers.
    assert yaml.safe_load("on: [push]\n") == {True: ["push"]}


def test_yaml_policy_loading_rejects_unsafe_object_tags() -> None:
    with pytest.raises(yaml.constructor.ConstructorError):
        _parse("!!python/object/apply:builtins.str [unsafe]\n")


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
        for key, value in (job.get("env") or {}).items():
            assert not re.search(r"\$\{\{\s*(?:runner|steps)\.", str(value)), (
                f"{name}: job env {key} uses a context available only after runner allocation"
            )
        permissions = job.get("permissions", workflow["permissions"])
        assert _write_scopes(permissions) <= WRITE_SCOPES.get((path.name, name), set()), name
        if "uses" in job:
            # Same-repository reusable workflows resolve at the caller's commit.
            # Their own jobs are checked here for timeouts, actions and scopes.
            target = job["uses"]
            assert re.fullmatch(r"\./\.github/workflows/[\w-]+\.yml", target), name
            called = ROOT / target
            assert called in WORKFLOWS and "workflow_call" in _triggers(_load(called)), name
            assert not job.get("secrets"), "reusable CI must not inherit secrets"
        else:
            assert type(job.get("timeout-minutes")) is int and job["timeout-minutes"] > 0, name
        for step in job.get("steps", []):
            action = step.get("uses")
            if action:
                assert ACTION_PIN.fullmatch(action), f"{name}: unpinned action {action}"
                if action.startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False, name
            script = step.get("run", "")
            assert not re.search(r"\$\{\{\s*github\.(?:event\.|head_ref\b)", script), name


def test_ci_gate_waits_for_every_job_and_cannot_skip_failed_dependencies() -> None:
    jobs = _load(GITHUB / "workflows" / "ci.yml")["jobs"]
    gate = jobs["gate"]
    assert gate["name"] == "CI gate", "keep the required-check context stable"
    assert gate["if"] == "always()", "failed or skipped jobs must still be evaluated"
    assert set(gate["needs"]) == set(jobs) - {"gate"}
    assert not any(job.get("continue-on-error") for job in jobs.values())
    assert not any(step.get("continue-on-error") for step in gate["steps"])
    for name in ("docs", "test-macos", "test"):
        assert "if" not in jobs[name], f"{name} must always run"
    assert jobs["dco"]["if"] == "github.event_name == 'pull_request'"
    assert jobs["dco"]["uses"] == "./.github/workflows/dco.yml"
    assert set(_triggers(_load(GITHUB / "workflows" / "dco.yml"))) == {"workflow_call"}


@pytest.mark.parametrize(
    "event,docs,macos,tests,dco,passes",
    [
        ("pull_request", "success", "success", "success", "success", True),
        ("push", "success", "success", "success", "skipped", True),
        ("pull_request", "success", "success", "failure", "success", False),
        ("pull_request", "success", "success", "cancelled", "success", False),
        ("pull_request", "success", "success", "skipped", "success", False),
        ("pull_request", "failure", "success", "success", "success", False),
        ("pull_request", "cancelled", "success", "success", "success", False),
        ("pull_request", "skipped", "success", "success", "success", False),
        ("pull_request", "success", "failure", "success", "success", False),
        ("pull_request", "success", "cancelled", "success", "success", False),
        ("pull_request", "success", "skipped", "success", "success", False),
        ("pull_request", "success", "success", "success", "failure", False),
        ("pull_request", "success", "success", "success", "cancelled", False),
        ("pull_request", "success", "success", "success", "skipped", False),
        ("pull_request", "success", "success", "", "success", False),
        ("push", "success", "success", "failure", "skipped", False),
        ("push", "success", "success", "success", "failure", False),
        ("workflow_dispatch", "success", "success", "success", "skipped", False),
    ],
)
def test_ci_gate_executes_fail_closed(
    event: str, docs: str, macos: str, tests: str, dco: str, passes: bool
) -> None:
    gate = _load(GITHUB / "workflows" / "ci.yml")["jobs"]["gate"]
    script = gate["steps"][0]["run"]
    # Execute the committed workflow script, including failed/cancelled/skipped
    # matrix results; a conditional that accidentally skips the gate is unsafe.
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "EVENT_NAME": event,
            "DOCS_RESULT": docs,
            "MACOS_RESULT": macos,
            "TEST_RESULT": tests,
            "DCO_RESULT": dco,
        },
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr


@pytest.mark.parametrize(
    "case,passes",
    [
        ("signed", True),
        ("mixed_case", True),
        ("divergent", True),
        ("unsigned", False),
        ("forged", False),
        ("missing_base", False),
        ("missing_head", False),
        ("malformed_base", False),
        ("malformed_head", False),
        ("missing_context", False),
        ("push_context", False),
        ("empty_range", False),
        ("disconnected", False),
        ("range_error", False),
    ],
)
def test_dco_executes_against_real_commit_ranges(tmp_path: Path, case: str, passes: bool) -> None:
    git_path = shutil.which("git")
    assert git_path is not None
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "DCO Reviewer",
        "GIT_AUTHOR_EMAIL": "reviewer@example.test",
        "GIT_COMMITTER_NAME": "DCO Reviewer",
        "GIT_COMMITTER_EMAIL": "reviewer@example.test",
    }

    def git(*args: str, extra_env: dict[str, str] | None = None) -> str:
        return subprocess.run(
            [git_path, "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={os.devnull}", *args],
            cwd=tmp_path,
            env={**env, **(extra_env or {})},
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()

    git("init", "-q", "--initial-branch=main")
    git("commit", "--allow-empty", "-qm", "Base")
    base = git("rev-parse", "HEAD")
    signed = "Change\n\nSigned-off-by: DCO Reviewer <reviewer@example.test>"
    message = "Change" if case == "unsigned" else signed
    if case == "mixed_case":
        message = signed.replace("reviewer@example.test", "ReViewer@Example.Test")
    if case == "divergent":
        git("checkout", "-qb", "feature")
    if case == "disconnected":
        git("checkout", "--orphan", "unrelated")
    extra = {"GIT_AUTHOR_EMAIL": ".*", "GIT_COMMITTER_EMAIL": ".*"} if case == "forged" else {}
    git("commit", "--allow-empty", "-qm", message, extra_env=extra)
    head = git("rev-parse", "HEAD")
    if case == "divergent":
        git("checkout", "-q", "main")
        git("commit", "--allow-empty", "-qm", "Main advanced")
        base = git("rev-parse", "HEAD")
    if case == "missing_base":
        base = "0" * 40
    elif case == "malformed_base":
        base = "HEAD~1"
    if case == "missing_head":
        head = "1" * 40
    elif case == "malformed_head":
        head = "--all"
    if case == "empty_range":
        head = base
    event = "" if case == "missing_context" else "push" if case == "push_context" else "pull_request"
    run_env = {**env, "EVENT_NAME": event, "BASE_SHA": base, "HEAD_SHA": head}
    if case == "range_error":
        # Refs remain valid; fail the enumeration itself to exercise error
        # propagation that process substitution previously discarded.
        wrapper_dir = tmp_path / "bin"
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "git"
        wrapper.write_text(
            f'#!/bin/sh\nif [ "$1" = "rev-list" ]; then exit 2; fi\nexec {shlex.quote(git_path)} "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        run_env["PATH"] = str(wrapper_dir) + os.pathsep + os.environ["PATH"]
    steps = _load(GITHUB / "workflows" / "dco.yml")["jobs"]["check"]["steps"]
    script = next(step["run"] for step in steps if "run" in step)
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=tmp_path,
        env=run_env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr
    assert ("All commits signed off." in result.stdout) is passes


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_workflows_do_not_publish_releases_packages_or_tags(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for marker in (
        "pypa/gh-action-pypi-publish",
        "softprops/action-gh-release",
        "ncipollo/release-action",
        "twine upload",
        "gh release create",
        "git push --tags",
        "git push origin v",
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
        "github.event_name == 'workflow_dispatch'",
        "inputs.publish",
        "github.ref == 'refs/heads/main'",
    }, "Pages deployment must require a manual dispatch, publish=true, and the main branch"
    assert "build" in ([deploy["needs"]] if isinstance(deploy["needs"], str) else deploy["needs"])


def test_stale_automation_never_closes_issues_or_pull_requests() -> None:
    workflow = _load(GITHUB / "workflows" / "stale.yml")
    steps = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
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
    # Steps are found by what they run, not by their display names.
    scripts = [step.get("run", "") for step in job["steps"]]
    install = next(index for index, script in enumerate(scripts) if "python -m venv" in script)
    assert "requirements.lock" in scripts[install]
    assert "--require-hashes --only-binary=:all:" in scripts[install]
    parsers = [index for index, script in enumerate(scripts) if "import yaml" in script]
    assert parsers, "no step parses .github/labels.yml"
    for index in parsers:
        assert index > install and '"$RUNNER_TEMP/labels-venv/bin/python" - <<' in scripts[index]
