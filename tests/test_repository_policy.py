"""Guard workflow privileges, manual publication, the container build, and valid issue-form labels.

Each policy rule is a small function that takes one file's text or parsed data
and returns the violations it finds, so the tests below can run the same check
on the real tree and on a mutated copy that proves the rule still bites.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"


def _workflow_files(directory: Path) -> list[Path]:
    """Every file GitHub runs from a workflows directory, in either YAML spelling."""
    return sorted(path for path in directory.glob("*.y*ml") if path.is_file())


WORKFLOWS = _workflow_files(GITHUB / "workflows")
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
# The aggregate floor AGENTS.md and CONTRIBUTING.md document.
COVERAGE_FLOOR = 80.0
# The only expression that may cancel an in-progress run of a push-triggered
# workflow: a newer pull-request push supersedes the older run, while every
# main push run finishes and leaves a complete record for its commit.
PULL_REQUEST_ONLY_CANCELLATION = "${{ github.event_name == 'pull_request' }}"
# Push-triggered workflows whose superseded push runs may be cancelled, and why.
CANCELLABLE_PUSH_RUNS = {
    "docs.yml": "it only rebuilds the site; CI's docs job builds every main commit, "
    "and release evidence cites CI and CodeQL runs only",
}
# Explicit, justified exceptions to the failure-suppression rule, keyed by the
# workflow and the exact stripped `run:` line.
SUPPRESSION_EXCEPTIONS = {
    (
        "dco.yml",
        'if [ "$(git rev-list --min-parents=2 --max-parents=2 -1 "$sha" 2>/dev/null || true)" = "$sha" ]; then',
    ): "a failed merge probe prints nothing, so the commit counts as a non-merge and its sign-off is checked",
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


def _trigger_names(workflow: dict[str, Any]) -> set[str]:
    triggers = _triggers(workflow)
    return {triggers} if isinstance(triggers, str) else {str(name) for name in triggers or ()}


def _write_scopes(permissions: Any) -> set[str]:
    if permissions == "read-all":
        return set()
    assert isinstance(permissions, dict), "permissions must be explicit and must not use write-all"
    assert all(level in {"read", "write", "none"} for level in permissions.values())
    return {scope for scope, level in permissions.items() if level == "write"}


def _scope_violations(owner: str, permissions: Any, allowed: set[str]) -> list[str]:
    if permissions == "read-all":
        return []
    if not isinstance(permissions, dict):
        return [f"{owner}: permissions must be an explicit mapping, not {permissions!r} (no write-all)"]
    problems = [
        f"{owner}: permission {scope} has unknown level {level!r}"
        for scope, level in permissions.items()
        if level not in {"read", "write", "none"}
    ]
    granted = {scope for scope, level in permissions.items() if level == "write"}
    if granted - allowed:
        problems.append(f"{owner}: write scopes {sorted(granted - allowed)} are not allowed here")
    return problems


def _trigger_violations(workflow: dict[str, Any]) -> list[str]:
    # Both run with the base repository's secrets and write token in response to
    # activity an outside contributor controls.
    forbidden = _trigger_names(workflow) & {"pull_request_target", "workflow_run"}
    return [f"forbidden trigger {name}" for name in sorted(forbidden)]


def _job_violations(workflow_name: str, workflow: dict[str, Any]) -> list[str]:
    """Permissions, timeouts, reusable-workflow calls and action pins of every job."""
    if "permissions" not in workflow:
        return ["the workflow must declare top-level permissions"]
    problems = _scope_violations("workflow", workflow["permissions"], set())
    for name, job in workflow["jobs"].items():
        for key, value in (job.get("env") or {}).items():
            if re.search(r"\$\{\{\s*(?:runner|steps)\.", str(value)):
                problems.append(
                    f"{name}: job env {key} uses a context available only after runner allocation"
                )
        allowed = WRITE_SCOPES.get((workflow_name, name), set())
        problems += _scope_violations(name, job.get("permissions", workflow["permissions"]), allowed)
        if "uses" in job:
            # Same-repository reusable workflows resolve at the caller's commit.
            # Their own jobs are checked here for timeouts, actions and scopes.
            target = job["uses"]
            called = ROOT / target
            if not re.fullmatch(r"\./\.github/workflows/[\w-]+\.ya?ml", target) or called not in WORKFLOWS:
                problems.append(f"{name}: calls {target}, which is not a workflow in this repository")
            elif "workflow_call" not in _trigger_names(_load(called)):
                problems.append(f"{name}: calls {target}, which has no workflow_call trigger")
            if job.get("secrets"):
                problems.append(f"{name}: reusable CI must not inherit secrets")
        elif type(job.get("timeout-minutes")) is not int or job["timeout-minutes"] <= 0:
            problems.append(f"{name}: needs a positive integer timeout-minutes")
        for step in job.get("steps", []):
            action = step.get("uses")
            if not action:
                continue
            if not ACTION_PIN.fullmatch(action):
                problems.append(f"{name}: unpinned action {action}")
            if (
                action.startswith("actions/checkout@")
                and (step.get("with") or {}).get("persist-credentials") is not False
            ):
                problems.append(f"{name}: checkout must set persist-credentials: false")
    return problems


def _concurrency_violations(workflow_name: str, workflow: dict[str, Any]) -> list[str]:
    """A newer push must never cancel the run that records an earlier push."""
    if "push" not in _trigger_names(workflow) or workflow_name in CANCELLABLE_PUSH_RUNS:
        return []
    blocks = [("workflow", workflow.get("concurrency"))]
    blocks += [(name, job.get("concurrency")) for name, job in workflow["jobs"].items()]
    problems = []
    for owner, block in blocks:
        # Absent, or a bare group name: cancel-in-progress defaults to false.
        cancel = block.get("cancel-in-progress", False) if isinstance(block, dict) else False
        if cancel is False:
            continue
        if isinstance(cancel, str) and " ".join(cancel.replace('"', "'").split()) == (
            PULL_REQUEST_ONLY_CANCELLATION
        ):
            continue
        problems.append(
            f"{owner}: cancel-in-progress {cancel!r} lets a newer push cancel a push run; "
            f"use {PULL_REQUEST_ONLY_CANCELLATION}"
        )
    return problems


# `|| true` and its spellings, linters told to exit 0, and audits told to skip a
# vulnerability all turn a failing gate green.
_SUPPRESSION = re.compile(r"\|\|\s*(?:true\b|:(?![\w:])|exit\s+0\b)|--exit-zero\b|--ignore-vuln\b")
_COVERAGE_FLOOR_ARGUMENT = re.compile(r"(?<![\w-])--(?:cov-)?fail-under(?:=|\s+)(\S+)")
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
# Values that the workflow author or the runner controls. Event payload text,
# branch and tag names, dispatch inputs, step outputs, env and toJSON dumps
# reach a shell only through `env:`, where the shell treats them as data.
_TRUSTED_RUN_EXPRESSION = re.compile(
    r"(?:matrix|runner)\.[\w-]+"
    r"|github\.(?:sha|run_id|run_number|run_attempt|repository|workflow|event_name|server_url|api_url)"
)


def _run_violations(workflow_name: str, workflow: dict[str, Any]) -> list[str]:
    """Steps must not hide a failure, lower a coverage floor or interpolate untrusted text."""
    problems = []
    for name, job in workflow["jobs"].items():
        if job.get("continue-on-error") not in (None, False):
            problems.append(f"{name}: job sets continue-on-error")
        for step in job.get("steps", []):
            if step.get("continue-on-error") not in (None, False):
                problems.append(
                    f"{name}: step {step.get('name') or step.get('run') or step.get('uses')} "
                    "sets continue-on-error"
                )
            script = step.get("run")
            if not isinstance(script, str):
                continue
            for expression in _EXPRESSION.findall(script):
                if not _TRUSTED_RUN_EXPRESSION.fullmatch(expression.strip()):
                    problems.append(
                        f"{name}: run interpolates ${{{{{expression}}}}}; pass the value through env:"
                    )
            for line in (line.strip() for line in script.splitlines()):
                if _SUPPRESSION.search(line) and (workflow_name, line) not in SUPPRESSION_EXCEPTIONS:
                    problems.append(f"{name}: `{line}` suppresses a failure")
                for match in _COVERAGE_FLOOR_ARGUMENT.finditer(line):
                    try:
                        lowered = float(match.group(1)) < COVERAGE_FLOOR
                    except ValueError:
                        lowered = True
                    if lowered:
                        problems.append(f"{name}: `{line}` sets the coverage floor below {COVERAGE_FLOOR:g}%")
    return problems


# Publication is a manual maintainer action (AGENTS.md). No workflow publishes a
# package, release, image or tag; that includes the release-evidence workflow,
# which builds and attests a review bundle only.
_PUBLICATION = {
    "GitHub release": re.compile(
        r"\bgh\s+release\s+(?:create|upload|edit)\b|softprops/action-gh-release|ncipollo/release-action"
    ),
    "package upload": re.compile(
        r"\btwine\s+upload\b|\b(?:uv|poetry|flit|hatch|pdm)\s+publish\b|pypi-publish"
    ),
    "image push": re.compile(r"\bdocker\s+(?:image\s+)?push\b|docker/build-push-action"),
    "git push": re.compile(r"\bgit\s+(?:-{1,2}[\w.-]+(?:[=\s]\S+)?\s+)*push\b"),
    "release or ref API call": re.compile(r"\bgh\s+api\b[^\n]*/(?:releases|git/refs|git/tags)\b"),
}


def _publication_violations(text: str) -> list[str]:
    return [
        f"{kind}: `{match.group()}` publishes; publication is a manual maintainer action"
        for kind, pattern in _PUBLICATION.items()
        for match in pattern.finditer(text)
    ]


def _workflow_violations(path: Path) -> list[str]:
    """Every policy violation in one workflow file; empty when the file complies."""
    workflow = _load(path)
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        return [f"{path.name} is not a workflow with a jobs mapping"]
    return [
        *_trigger_violations(workflow),
        *_job_violations(path.name, workflow),
        *_concurrency_violations(path.name, workflow),
        *_run_violations(path.name, workflow),
        *_publication_violations(path.read_text(encoding="utf-8")),
    ]


def _dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """`(INSTRUCTION, arguments)` pairs, continuation lines joined, comments dropped."""
    instructions = []
    pending = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        keyword, _, arguments = (pending + stripped).partition(" ")
        instructions.append((keyword.upper(), arguments.strip()))
        pending = ""
    if pending:
        keyword, _, arguments = pending.strip().partition(" ")
        instructions.append((keyword.upper(), arguments.strip()))
    return instructions


# Options that may accompany an unhashed `pip install --no-deps` of local source.
_LOCAL_INSTALL_OPTIONS = {
    "--no-deps",
    "--no-cache-dir",
    "--no-build-isolation",
    "--no-index",
    "-q",
    "--quiet",
}


def _pip_install_is_hash_checked(command: str) -> bool:
    """`pip install` verifies hashes, or installs only local source without dependencies."""
    tokens = command.split()
    if "--require-hashes" in tokens:
        return True
    arguments = tokens[tokens.index("install") + 1 :]
    options = [token for token in arguments if token.startswith("-")]
    paths = [token for token in arguments if not token.startswith("-")]
    return (
        "--no-deps" in options
        and set(options) <= _LOCAL_INSTALL_OPTIONS
        and bool(paths)
        and all(token.startswith(("/", ".")) for token in paths)
    )


def _dockerfile_violations(text: str) -> list[str]:
    problems = []
    stages: set[str] = set()
    user: str | None = None
    for keyword, arguments in _dockerfile_instructions(text):
        if keyword == "FROM":
            tokens = [token for token in arguments.split() if not token.startswith("--")]
            image = tokens[0] if tokens else ""
            if (
                image.lower() not in stages
                and image != "scratch"
                and not re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", image)
            ):
                problems.append(f"FROM {image} is not pinned by an image digest")
            if len(tokens) == 3 and tokens[1].lower() == "as":
                stages.add(tokens[2].lower())
            user = None  # every stage starts as root
        elif keyword == "USER":
            user = arguments.split(":", 1)[0].strip()
        elif keyword == "ADD" and re.search(r"(?:^|\s)(?:(?:https?|git)://|git@)", arguments):
            problems.append(f"ADD fetches a remote source: {arguments}")
        elif keyword == "RUN":
            for command in re.split(r"&&|\|\||;|\|", arguments):
                if re.search(r"\bpip3?\s+install\b", command) and not _pip_install_is_hash_checked(command):
                    problems.append(f"pip install without --require-hashes: {command.strip()}")
    if user is None or user in {"root", "0"}:
        problems.append(f"the final stage runs as {user or 'root (no USER)'}; end with a non-root USER")
    return problems


def _dockerignore_violations(text: str) -> list[str]:
    """The build context is an allow-list: exclude everything, re-include files."""
    patterns = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    problems = []
    if not patterns or patterns[0] not in {"*", "**"}:
        problems.append(".dockerignore must start with `*` or `**` and re-include an allow-list")
    for pattern in patterns:
        if not pattern.startswith("!"):
            continue
        target = pattern[1:]
        # A re-included directory readmits every file below it, bytecode and
        # untracked files included.
        if target.endswith("/") or target.rsplit("/", 1)[-1] in {"*", "**"} or (ROOT / target).is_dir():
            problems.append(f".dockerignore re-includes the directory {pattern}; re-include files instead")
    return problems


def _violations(path: Path) -> list[str]:
    """Policy violations in a workflow, the Dockerfile or .dockerignore."""
    if path.name == "Dockerfile":
        return _dockerfile_violations(path.read_text(encoding="utf-8"))
    if path.name == ".dockerignore":
        return _dockerignore_violations(path.read_text(encoding="utf-8"))
    return _workflow_violations(path)


def test_workflow_discovery_includes_both_yaml_spellings(tmp_path: Path) -> None:
    # GitHub runs `.yaml` workflows too; a policy that globbed only `*.yml`
    # would let a `.yaml` file bypass every check below.
    assert WORKFLOWS, "no workflows found; every parametrised workflow test would be empty"
    listed = {path.name for path in (GITHUB / "workflows").iterdir() if path.suffix in {".yml", ".yaml"}}
    assert {path.name for path in WORKFLOWS} == listed
    for name in ("ci.yml", "evil.yaml", "notes.txt"):
        (tmp_path / name).write_text("{}\n", encoding="utf-8")
    assert [path.name for path in _workflow_files(tmp_path)] == ["ci.yml", "evil.yaml"]


def test_an_added_yaml_workflow_is_checked_like_any_other(tmp_path: Path) -> None:
    evil = tmp_path / "evil.yaml"
    evil.write_text(
        "on: pull_request_target\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 5\n"
        "    steps:\n"
        "      - uses: actions/checkout@v7\n"
        "      - run: gh release create v0.1.1 dist/*\n",
        encoding="utf-8",
    )
    assert _workflow_files(tmp_path) == [evil]
    problems = "\n".join(_violations(evil))
    for expected in ("pull_request_target", "write-all", "unpinned action", "GitHub release"):
        assert expected in problems, problems


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_workflows_use_pinned_actions_and_scoped_permissions(path: Path) -> None:
    workflow = _load(path)
    assert not [*_trigger_violations(workflow), *_job_violations(path.name, workflow)]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_workflow_steps_cannot_hide_failures_or_interpolate_untrusted_text(path: Path) -> None:
    assert not _run_violations(path.name, _load(path))


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_push_runs_are_not_cancelled_by_a_newer_push(path: Path) -> None:
    assert not _concurrency_violations(path.name, _load(path))


def test_ci_cancels_only_superseded_pull_request_runs() -> None:
    concurrency = _load(GITHUB / "workflows" / "ci.yml")["concurrency"]
    assert (
        concurrency["group"] == "${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}"
    )
    assert concurrency["cancel-in-progress"] == PULL_REQUEST_ONLY_CANCELLATION


def test_policy_exceptions_still_name_real_lines() -> None:
    for workflow, line in SUPPRESSION_EXCEPTIONS:
        script = "\n".join(
            step.get("run", "")
            for job in _load(GITHUB / "workflows" / workflow)["jobs"].values()
            for step in job.get("steps", [])
        )
        assert line in {candidate.strip() for candidate in script.splitlines()}, f"stale exception: {line}"
    for workflow in CANCELLABLE_PUSH_RUNS:
        assert "push" in _trigger_names(_load(GITHUB / "workflows" / workflow)), (
            f"stale exemption: {workflow}"
        )


def test_ci_enforces_the_documented_coverage_floors() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["tool"]["coverage"]["report"]["fail_under"] >= COVERAGE_FLOOR
    jobs = _load(GITHUB / "workflows" / "ci.yml")["jobs"]
    for name in ("test", "test-macos"):
        scripts = [step.get("run", "") for step in jobs[name]["steps"]]
        # Either spelling runs the same suite; the macOS job uses the console
        # entry point on purpose, to prove it imports the checkout-only tools.
        assert any(
            re.search(r"(?:^|\s)(?:python -m )?pytest\b", script) and "--cov-fail-under=80" in script
            for script in scripts
        ), name
        assert any("python -m tools.coverage_gate" in script for script in scripts), name


def test_container_build_is_digest_pinned_hash_locked_and_non_root() -> None:
    assert not _violations(ROOT / "Dockerfile")
    assert not _violations(ROOT / ".dockerignore")


def _replace(old: str, new: str) -> Callable[[str], str]:
    def mutate(text: str) -> str:
        assert old in text, f"the mutation no longer applies: {old!r} is not in the file"
        return text.replace(old, new, 1)

    return mutate


_SELF_SCAN = "run: shadowscan scan -c examples/shadowscan.offline.yaml --format sarif -o shadowscan.sarif"


@pytest.mark.parametrize(
    "source,mutate,expected",
    [
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("  pull_request:\n", "  pull_request:\n  workflow_run:\n    workflows: [Docs]\n"),
            "forbidden trigger workflow_run",
            id="workflow_run-trigger",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("  pull_request:\n", "  pull_request_target:\n"),
            "forbidden trigger pull_request_target",
            id="pull_request_target-trigger",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("permissions:\n  contents: read\nconcurrency:", "permissions: write-all\nconcurrency:"),
            "write-all",
            id="write-all",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7"),
            "unpinned action",
            id="unpinned-action",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(
                "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "cancel-in-progress: true"
            ),
            "lets a newer push cancel a push run",
            id="cancel-every-run",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("== 'pull_request' }}", "!= 'pull_request' }}"),
            "lets a newer push cancel a push run",
            id="cancel-push-runs",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("  docs:\n    runs-on:", "  docs:\n    continue-on-error: true\n    runs-on:"),
            "docs: job sets continue-on-error",
            id="job-continue-on-error",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(
                "      - run: ruff check shadowscan tests tools\n",
                "      - run: ruff check shadowscan tests tools\n        continue-on-error: true\n",
            ),
            "sets continue-on-error",
            id="step-continue-on-error",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("pip-audit --skip-editable --progress-spinner off", "pip-audit --skip-editable || true"),
            "suppresses a failure",
            id="or-true",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("run: ruff check shadowscan", "run: ruff check --exit-zero shadowscan"),
            "suppresses a failure",
            id="exit-zero",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("pip-audit --skip-editable", "pip-audit --ignore-vuln PYSEC-0000-0 --skip-editable"),
            "suppresses a failure",
            id="ignore-vuln",
        ),
        pytest.param(
            ".github/workflows/dco.yml",
            _replace("2>/dev/null || true)", "2>/dev/null || :)"),
            "suppresses a failure",
            id="changed-exception-line",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("--cov-fail-under=80", "--cov-fail-under=10"),
            "coverage floor below 80%",
            id="coverage-floor",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(
                "run: mkdocs build --strict", 'run: mkdocs build --strict --site-dir "${{ inputs.site }}"'
            ),
            "interpolates ${{ inputs.site }}",
            id="inputs-interpolation",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(
                "run: python -m shadowscan.signatures.validate",
                'run: echo "${{ github.ref_name }}" && python -m shadowscan.signatures.validate',
            ),
            "interpolates ${{ github.ref_name }}",
            id="ref_name-interpolation",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("run: mkdocs build --strict", "run: echo '${{ toJSON(github.event) }}' && mkdocs build"),
            "interpolates ${{ toJSON(github.event) }}",
            id="event-json-interpolation",
        ),
        pytest.param(
            ".github/workflows/dco.yml",
            _replace(
                'echo "All commits signed off."', 'echo "${{ github.event.pull_request.title }} signed off."'
            ),
            "interpolates ${{ github.event.pull_request.title }}",
            id="event-title-interpolation",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace(
                "        run: sha256sum --check SHA256SUMS\n",
                "        run: sha256sum --check SHA256SUMS && uv publish --trusted-publishing always ./*.whl\n",
            ),
            "package upload",
            id="uv-publish-in-oidc-job",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(_SELF_SCAN, _SELF_SCAN + " && python -m twine upload dist/*"),
            "package upload",
            id="twine-upload",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace("actions/upload-artifact@", "pypa/gh-action-pypi-publish@"),
            "package upload",
            id="pypi-publish-action",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(_SELF_SCAN, _SELF_SCAN + " && gh release create v0.1.1 dist/*.whl"),
            "GitHub release",
            id="gh-release-create",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(_SELF_SCAN, _SELF_SCAN + " && git push origin --tags"),
            "git push",
            id="git-push-tags",
        ),
        pytest.param(
            ".github/workflows/ci.yml",
            _replace(_SELF_SCAN, _SELF_SCAN + " && docker push ghcr.io/example/shadowscan:ci"),
            "image push",
            id="docker-push",
        ),
        pytest.param(
            "Dockerfile",
            lambda text: re.sub(r"@sha256:[0-9a-f]{64}", "", text, count=1),
            "is not pinned by an image digest",
            id="unpinned-base-image",
        ),
        pytest.param("Dockerfile", _replace("USER 65532:65532", "USER root"), "runs as root", id="root-user"),
        pytest.param("Dockerfile", _replace("USER 65532:65532\n", ""), "runs as root", id="no-user"),
        pytest.param("Dockerfile", lambda text: text + "USER 0\n", "runs as 0", id="final-root-user"),
        pytest.param(
            "Dockerfile",
            _replace(
                "WORKDIR /opt/shadowscan\n",
                "WORKDIR /opt/shadowscan\nADD https://example.invalid/t.tgz /opt/\n",
            ),
            "ADD fetches a remote source",
            id="remote-add",
        ),
        pytest.param(
            "Dockerfile",
            _replace("pip install --no-cache-dir --require-hashes", "pip install --no-cache-dir"),
            "pip install without --require-hashes",
            id="unhashed-pip-install",
        ),
        pytest.param(
            "Dockerfile",
            _replace("--no-build-isolation /opt/shadowscan", "--no-build-isolation /opt/shadowscan requests"),
            "pip install without --require-hashes",
            id="unhashed-no-deps-package",
        ),
        pytest.param(
            ".dockerignore",
            _replace("\n**\n", "\n"),
            "must start with `*` or `**`",
            id="deny-list-dockerignore",
        ),
        pytest.param(
            ".dockerignore",
            lambda text: text + "!shadowscan/\n",
            "re-includes the directory !shadowscan/",
            id="directory-reinclude",
        ),
    ],
)
def test_policy_checks_reject_a_mutated_copy_of_a_real_file(
    tmp_path: Path, source: str, mutate: Callable[[str], str], expected: str
) -> None:
    original = ROOT / source
    assert not _violations(original), "the unmutated file must comply"
    mutated = tmp_path / original.name
    mutated.write_text(mutate(original.read_text(encoding="utf-8")), encoding="utf-8")
    problems = _violations(mutated)
    assert any(expected in problem for problem in problems), problems


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
        ("dependabot", True),
        ("dependabot_unsigned", False),
        ("dependabot_forged", False),
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
    if case.startswith("dependabot"):
        # Dependabot commits are authored by GitHub's app identity and signed
        # off as support@github.com. Only that pairing passes: an unsigned
        # Dependabot commit fails, and so does a human commit that borrows the
        # bot's sign-off.
        bot_signed = "Bump\n\nSigned-off-by: dependabot[bot] <support@github.com>"
        message = "Bump" if case == "dependabot_unsigned" else bot_signed
        if case != "dependabot_forged":
            extra = {
                "GIT_AUTHOR_NAME": "dependabot[bot]",
                "GIT_AUTHOR_EMAIL": "49699333+dependabot[bot]@users.noreply.github.com",
                "GIT_COMMITTER_NAME": "GitHub",
                "GIT_COMMITTER_EMAIL": "noreply@github.com",
            }
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
    assert not _publication_violations(path.read_text(encoding="utf-8"))


def test_release_workflow_stays_a_manual_evidence_bundle() -> None:
    workflow = _load(GITHUB / "workflows" / "release.yml")
    assert _trigger_names(workflow) == {"workflow_dispatch"}
    assert "Deliberately produces a review bundle only." in (GITHUB / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    # Only the attestation job holds an OIDC token, and it never checks out or
    # runs repository code.
    for name, job in workflow["jobs"].items():
        if (job.get("permissions") or {}).get("id-token") == "write":
            assert name == "attest"
            assert not any(step.get("uses", "").startswith("actions/checkout@") for step in job["steps"])
    assert workflow["jobs"]["publication-input"]["permissions"] == {}


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
