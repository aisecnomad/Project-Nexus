"""Guard workflow privileges, manual publication, the container build, and valid issue-form labels.

Each policy rule is a small function that takes one file's text or parsed data
and returns the violations it finds, so the tests below can run the same check
on the real tree and on a mutated copy that proves the rule still bites.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools.container.verify import verify_bundle, verify_database
from tools.coverage_gate import MIN_CONNECTOR_COVERAGE

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
    ("release.yml", "publish"): {"id-token"},
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
SUPPRESSION_EXCEPTIONS: dict[tuple[str, str], str] = {}


@pytest.mark.parametrize("fail_check", [False, True])
@pytest.mark.parametrize("relative_tmpdir", [False, True])
def test_wheel_validation_uses_private_workspace_and_always_cleans_up(
    tmp_path: Path, fail_check: bool, relative_tmpdir: bool
) -> None:
    """Exercise the real recipe without downloading or installing packages."""
    if shutil.which("make") is None:
        pytest.skip("make is required for the development-tooling check")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    shutil.copyfile(ROOT / "Makefile", checkout / "Makefile")
    (checkout / "dist").mkdir()
    (checkout / "dist" / "nexusshadowscan-0.1.1-py3-none-any.whl").touch()
    shared_temp = tmp_path / "shared temp"
    shared_temp.mkdir()
    previous = shared_temp / "shadowscan-wheel-test"
    previous.mkdir()
    sentinel = previous / "keep.txt"
    sentinel.write_text("another invocation's files", encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    python = fake_bin / "python"
    python.write_text(
        f"#!{sys.executable}\n"
        "import os, shutil, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "temporary_root = Path(os.environ['WHEEL_TEST_ROOT'])\n"
        "if args[:2] == ['-m', 'venv']:\n"
        "    target = Path(args[2])\n"
        "    assert target.parent.parent == temporary_root\n"
        "    assert target.parent.stat().st_mode & 0o777 == 0o700\n"
        "    assert not target.exists(), 'must not reuse an existing environment'\n"
        "    (target / 'bin').mkdir(parents=True)\n"
        "    for command in ('python', 'shadowscan'):\n"
        "        shutil.copyfile(__file__, target / 'bin' / command)\n"
        "        (target / 'bin' / command).chmod(0o700)\n"
        "elif args == ['-m', 'pip', 'check'] and os.environ['FAIL_WHEEL_CHECK'] == '1':\n"
        "    sys.exit(23)\n"
        "elif args in (['-m', 'shadowscan.signatures.validate'], ['--help']):\n"
        "    assert Path.cwd() == Path(__file__).parents[2]\n"
        "    assert Path.cwd().parent == temporary_root\n",
        encoding="utf-8",
    )
    python.chmod(0o700)
    result = subprocess.run(
        ["make", "--no-print-directory", "-o", "build", "wheel-validate"],
        cwd=checkout,
        env={
            **os.environ,
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "TMPDIR": os.path.relpath(shared_temp, checkout) if relative_tmpdir else str(shared_temp),
            "WHEEL_TEST_ROOT": str(shared_temp),
            "FAIL_WHEEL_CHECK": "1" if fail_check else "0",
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert (result.returncode != 0) is fail_check, result.stdout + result.stderr
    assert sentinel.read_text(encoding="utf-8") == "another invocation's files"
    assert list(shared_temp.iterdir()) == [previous], "temporary workspace leaked on exit"


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
# release, image or tag, and only one step uploads a package: the pinned
# trusted-publishing action in release.yml's `publish` job, which runs only when
# the maintainer dispatches it and approves its protected environment.
# _release_publish_violations pins those gates; the same step anywhere else, or
# any other upload command, is still a violation.
SANCTIONED_UPLOAD = ("release.yml", "publish")
_TRUSTED_PUBLISH_ACTION = re.compile(r"pypa/gh-action-pypi-publish@[0-9a-f]{40}")
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


def _without_sanctioned_upload(workflow_name: str, workflow: dict[str, Any], text: str) -> str:
    """The workflow text minus one copy of the sanctioned upload step, when that job has exactly one."""
    if workflow_name != SANCTIONED_UPLOAD[0]:
        return text
    job = workflow["jobs"].get(SANCTIONED_UPLOAD[1])
    steps = job.get("steps", []) if isinstance(job, dict) else []
    uploads = [step.get("uses", "") for step in steps if "pypi-publish" in step.get("uses", "")]
    if len(uploads) != 1 or not _TRUSTED_PUBLISH_ACTION.fullmatch(uploads[0]):
        return text
    # One copy only: a second copy of the same step in another job stays a violation.
    return text.replace(f"uses: {uploads[0]}", "", 1)


def _if_clauses(job: dict[str, Any]) -> set[str]:
    expression = str(job.get("if", "")).strip().removeprefix("${{").removesuffix("}}").strip()
    return {re.sub(r"\s+", " ", clause.strip()).replace('"', "'") for clause in expression.split("&&")}


_PUBLISH_DISPATCH = {"inputs.publish != 'none'", "github.ref == 'refs/heads/main'"}
_BUILD_OR_INSTALL = re.compile(r"\b(?:pip|python[\d.]*|setup\.py|twine|uv)\b")


def _release_publish_violations(workflow: dict[str, Any]) -> list[str]:
    """The package upload stays manual, approved, tagged and fed only the attested wheel."""
    problems = []
    triggers = _triggers(workflow)
    dispatch = triggers.get("workflow_dispatch") if isinstance(triggers, dict) else None
    publish_input = ((dispatch or {}).get("inputs") or {}).get("publish") or {}
    if (
        publish_input.get("type") != "choice"
        or publish_input.get("default") != "none"
        or publish_input.get("options") != ["none", "testpypi", "pypi"]
    ):
        problems.append("the publish input must be a choice of none, testpypi or pypi that defaults to none")
    jobs = workflow["jobs"]
    for name in ("publication-gate", "publish"):
        job = jobs.get(name)
        if not isinstance(job, dict):
            problems.append(f"{name}: job is missing")
            continue
        if _if_clauses(job) != _PUBLISH_DISPATCH:
            problems.append(f"{name}: must run only when the maintainer dispatches publish on main")
        if any(step.get("uses", "").startswith("actions/checkout@") for step in job.get("steps", [])):
            problems.append(f"{name}: must not check out source")
    gate = jobs.get("publication-gate")
    if isinstance(gate, dict):
        if gate.get("permissions") != {"contents": "read"}:
            problems.append("publication-gate: needs contents read only")
        script = "\n".join(step.get("run", "") for step in gate.get("steps", []))
        if (
            '"repos/$GITHUB_REPOSITORY/commits/tags/v$version"' not in script
            or 'if [ "$tagged" != "$GITHUB_SHA" ]; then' not in script
        ):
            problems.append(
                "publication-gate: a pypi upload must require tag v<version> on the reviewed commit"
            )
    publish = jobs.get("publish")
    if isinstance(publish, dict):
        needs = publish.get("needs", [])
        if not {"publication-input", "publication-gate"} <= set([needs] if isinstance(needs, str) else needs):
            problems.append("publish: must wait for the publication gate")
        if publish.get("permissions") != {"id-token": "write"}:
            problems.append("publish: the OIDC token must be its only permission")
        environment = publish.get("environment")
        if not isinstance(environment, dict) or environment.get("name") != "${{ inputs.publish }}":
            problems.append("publish: must wait for approval in the protected environment named by publish")
        steps = publish.get("steps", [])
        downloads = [step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")]
        if not downloads or any(
            (step.get("with") or {}).get("artifact-ids")
            != "${{ needs.publication-input.outputs.artifact_id }}"
            for step in downloads
        ):
            problems.append("publish: must upload only the attested publication-input artifact")
        script = "\n".join(step.get("run", "") for step in steps)
        if "sha256sum --check SHA256SUMS" not in script:
            problems.append("publish: must verify the attested digests before uploading")
        if _BUILD_OR_INSTALL.search(script):
            problems.append("publish: must not build, install or upload with its own commands")
    return problems


def _workflow_violations(path: Path) -> list[str]:
    """Every policy violation in one workflow file; empty when the file complies."""
    workflow = _load(path)
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        return [f"{path.name} is not a workflow with a jobs mapping"]
    text = _without_sanctioned_upload(path.name, workflow, path.read_text(encoding="utf-8"))
    return [
        *_trigger_violations(workflow),
        *_job_violations(path.name, workflow),
        *_concurrency_violations(path.name, workflow),
        *_run_violations(path.name, workflow),
        *_publication_violations(text),
        *(_release_publish_violations(workflow) if path.name == SANCTIONED_UPLOAD[0] else []),
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


# Options that may accompany an unhashed `pip install --no-deps` or `pip wheel --no-deps` of
# local source. A --wheel-dir argument is a path, so it must be local too.
_LOCAL_INSTALL_OPTIONS = {
    "--no-deps",
    "--no-cache-dir",
    "--no-build-isolation",
    "--no-index",
    "--wheel-dir",
    "-q",
    "--quiet",
}


def _pip_install_is_hash_checked(command: str) -> bool:
    """`pip install` or `pip wheel` verifies hashes, or uses only local source without dependencies."""
    tokens = command.split()
    if "--require-hashes" in tokens:
        return True
    subcommand = next(index for index, token in enumerate(tokens) if token in {"install", "wheel"})
    arguments = tokens[subcommand + 1 :]
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
                pip = re.search(r"\bpip3?(?:\s+--python\s+\S+)?\s+(install|wheel)\b", command)
                if pip and not _pip_install_is_hash_checked(command):
                    problems.append(f"pip {pip.group(1)} without --require-hashes: {command.strip()}")
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
    # Pull requests share one group per number; every other run has its own, so
    # GitHub never replaces a pending main run with a newer one.
    assert concurrency["group"] == (
        "${{ github.workflow }}-${{ github.event_name == 'pull_request' && "
        "github.event.pull_request.number || github.run_id }}"
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


def test_local_make_targets_enforce_the_same_coverage_floors_as_ci() -> None:
    """`make check` is documented as the local copy of CI, so its floors cannot be lower."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    floors = [float(value) for value in re.findall(r"--cov-fail-under=(\d+(?:\.\d+)?)", makefile)]
    assert floors, "the Makefile test target no longer enforces an aggregate coverage floor"
    assert min(floors) >= COVERAGE_FLOOR
    assert re.search(r"^\s+python -m tools\.coverage_gate\b", makefile, re.M)


def test_container_build_is_digest_pinned_hash_locked_and_non_root() -> None:
    assert not _violations(ROOT / "Dockerfile")
    assert not _violations(ROOT / ".dockerignore")


def _replace(old: str, new: str) -> Callable[[str], str]:
    def mutate(text: str) -> str:
        assert old in text, f"the mutation no longer applies: {old!r} is not in the file"
        return text.replace(old, new, 1)

    return mutate


def _replace_last(old: str, new: str) -> Callable[[str], str]:
    def mutate(text: str) -> str:
        assert old in text, f"the mutation no longer applies: {old!r} is not in the file"
        head, _, tail = text.rpartition(old)
        return head + new + tail

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
            _replace('git cat-file -e "${HEAD_SHA}^{commit}"', 'git cat-file -e "${HEAD_SHA}^{commit}" || :'),
            "suppresses a failure",
            id="dco-suppressed-ref-check",
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
            ".github/workflows/release.yml",
            _replace("actions/upload-artifact@", "pypa/gh-action-pypi-publish@"),
            "package upload",
            id="second-upload-outside-publish-job",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace('          cp -- "${wheels[0]}" dist/\n', "          python -m twine upload dist/*\n"),
            "package upload",
            id="twine-upload-in-publish-job",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace(
                "          mkdir dist\n", "          mkdir dist\n          pip wheel --no-deps -w dist .\n"
            ),
            "must not build, install or upload",
            id="rebuild-in-publish-job",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace("        default: none\n", "        default: pypi\n"),
            "defaults to none",
            id="publish-by-default",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace_last(
                "    if: inputs.publish != 'none' && github.ref == 'refs/heads/main'\n",
                "    if: github.ref == 'refs/heads/main'\n",
            ),
            "publish: must run only when the maintainer dispatches publish",
            id="publish-without-dispatch-choice",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace("      name: ${{ inputs.publish }}\n", "      name: release\n"),
            "protected environment named by publish",
            id="publish-outside-protected-environment",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace('if [ "$tagged" != "$GITHUB_SHA" ]; then', 'if [ -z "$tagged" ]; then'),
            "require tag v<version> on the reviewed commit",
            id="publish-without-tag-on-reviewed-commit",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace_last(
                "artifact-ids: ${{ needs.publication-input.outputs.artifact_id }}",
                "artifact-ids: ${{ needs.build.outputs.artifact_id }}",
            ),
            "only the attested publication-input artifact",
            id="publish-unassembled-artifact",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace(
                "    permissions:\n      id-token: write\n    steps:\n      - uses: actions/download",
                "    permissions:\n      id-token: write\n      contents: write\n    steps:\n      - uses: actions/download",
            ),
            "publish: the OIDC token must be its only permission",
            id="publish-with-write-token",
        ),
        pytest.param(
            ".github/workflows/release.yml",
            _replace_last(
                "      - name: Stage only the attested wheel\n",
                "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
                "        with:\n          persist-credentials: false\n"
                "      - name: Stage only the attested wheel\n",
            ),
            "publish: must not check out source",
            id="checkout-in-publish-job",
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
            _replace(
                "--python /opt/venv/bin/python install --no-cache-dir --require-hashes",
                "--python /opt/venv/bin/python install --no-cache-dir",
            ),
            "pip install without --require-hashes",
            id="unhashed-pip-install",
        ),
        pytest.param(
            "Dockerfile",
            _replace(
                "/opt/wheel/nexusshadowscan-*.whl",
                "/opt/wheel/nexusshadowscan-*.whl requests",
            ),
            "pip install without --require-hashes",
            id="unhashed-no-deps-package",
        ),
        pytest.param(
            "Dockerfile",
            _replace("wheel --no-cache-dir --no-deps", "wheel --no-cache-dir"),
            "pip wheel without --require-hashes",
            id="unhashed-wheel-dependencies",
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
    for name in ("docs", "test-macos", "test", "container-security"):
        assert "if" not in jobs[name], f"{name} must always run"
    assert jobs["dco"]["if"] == "github.event_name == 'pull_request'"
    assert jobs["dco"]["uses"] == "./.github/workflows/dco.yml"
    assert set(_triggers(_load(GITHUB / "workflows" / "dco.yml"))) == {"workflow_call"}


@pytest.mark.parametrize(
    "event,docs,macos,tests,dco,passes",
    [
        ("pull_request", "success", "success", "success", "success", True),
        ("push", "success", "success", "success", "skipped", True),
        ("schedule", "success", "success", "success", "skipped", True),
        ("schedule", "success", "success", "failure", "skipped", False),
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
            "CONTAINER_RESULT": "success",
        },
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr


def test_one_linux_leg_enforces_both_coverage_floors_and_every_leg_runs_the_suite() -> None:
    jobs = _load(GITHUB / "workflows" / "ci.yml")["jobs"]
    matrix = jobs["test"]["strategy"]["matrix"]
    # Exactly one include entry, extending an existing leg rather than adding one.
    (leg,) = matrix["include"]
    assert leg == {"python": leg["python"], "coverage": True} and leg["python"] in matrix["python"]
    steps = jobs["test"]["steps"]
    pytest_steps = [
        step for step in steps if re.search(r"(?:^|\s)(?:python -m )?pytest\b", step.get("run", ""))
    ]
    traced = [step for step in pytest_steps if "--cov=shadowscan" in step["run"]]
    assert [step.get("if") for step in traced] == ["${{ matrix.coverage }}"]
    assert "--cov-fail-under=80" in traced[0]["run"]
    gate = [step for step in steps if "python -m tools.coverage_gate" in step.get("run", "")]
    assert [step.get("if") for step in gate] == ["${{ matrix.coverage }}"]
    assert steps.index(gate[0]) > steps.index(traced[0])
    # Every other leg, and macOS, still runs the whole suite (no selection flags).
    untraced = [step for step in pytest_steps if step not in traced]
    assert [(step.get("if"), step["run"].strip()) for step in untraced] == [
        ("${{ !matrix.coverage }}", "python -m pytest -q")
    ]
    # macOS runs the whole suite through the console entry point, which must
    # import the checkout-only tools packages without a caller-supplied PYTHONPATH.
    macos = [
        step for step in jobs["test-macos"]["steps"] if re.search(r"(?:^|\s)pytest\b", step.get("run", ""))
    ]
    assert [(step.get("if"), step["run"].strip()) for step in macos][-1] == (None, "pytest -q")


def test_coverage_floors_count_branches_and_are_not_lowered() -> None:
    coverage = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["coverage"]
    assert coverage["run"]["branch"] is True
    assert coverage["report"]["fail_under"] >= 80
    assert MIN_CONNECTOR_COVERAGE >= 75


def _secret_check_step() -> str:
    """The committed Linux CI step that scans every tracked file with tools/check_secrets.py."""
    steps = _load(GITHUB / "workflows" / "ci.yml")["jobs"]["test"]["steps"]
    (step,) = [step for step in steps if "tools/check_secrets.py" in step.get("run", "")]
    assert "if" not in step, "the secret check runs on every Linux leg"
    assert "git ls-files -z | xargs -0 python tools/check_secrets.py" in step["run"]
    return str(step["run"])


def test_ci_secret_check_scans_tracked_files_only(tmp_path: Path) -> None:
    script = _secret_check_step()
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    shutil.copy(ROOT / "tools" / "check_secrets.py", repo / "tools")
    token = "ghp_" + "A1b2C3d4" * 4 + "E5f6"  # shaped like a GitHub token; not a credential
    planted = {
        "app.py": "print('ok')\n",
        "tests/test_fixture.py": f"TOKEN = {token!r}\n",  # explicitly approved synthetic value
        "shadowscan/signatures/data/pack.yaml": f"example: {token}\n",  # explicitly approved synthetic value
    }
    for name, text in planted.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    from tools.check_secrets import digest

    approvals = [
        {"path": name, "family": "GitHub token", "sha256": digest(token), "reason": "Synthetic fixture."}
        for name in planted
        if name != "app.py"
    ]
    (repo / "tools" / "secret_allowlist.json").write_text(
        json.dumps({"version": 1, "entries": approvals}), encoding="utf-8"
    )
    (repo / "untracked.py").write_text(f"TOKEN = {token!r}\n", encoding="utf-8")
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args, cwd=repo, env=env, capture_output=True, text=True, timeout=120, check=False
        )

    assert run("git", "init", "-q").returncode == 0
    assert run("git", "add", "tools", *planted).returncode == 0
    clean = run("bash", "-e", "-c", script)
    assert clean.returncode == 0, clean.stdout + clean.stderr
    (repo / "notes.md").write_text(token, encoding="utf-8")
    assert run("git", "add", "notes.md").returncode == 0
    leaked = run("bash", "-e", "-c", script)
    assert leaked.returncode != 0 and "notes.md:1: possible hardcoded GitHub token" in leaked.stdout, (
        leaked.stdout + leaked.stderr
    )
    assert "untracked.py" not in leaked.stdout


def test_ci_secret_check_passes_on_this_checkout() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    result = subprocess.run(
        ["bash", "-e", "-c", _secret_check_step()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("container", ["failure", "cancelled", "skipped", ""])
def test_ci_gate_blocks_unavailable_container_assurance(container: str) -> None:
    script = _load(GITHUB / "workflows" / "ci.yml")["jobs"]["gate"]["steps"][0]["run"]
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "EVENT_NAME": "pull_request",
            "DOCS_RESULT": "success",
            "MACOS_RESULT": "success",
            "TEST_RESULT": "success",
            "DCO_RESULT": "success",
            "CONTAINER_RESULT": container,
        },
    )
    assert result.returncode != 0
    assert "CONTAINER_RESULT" in result.stderr


def test_container_scan_uses_verified_tool_fresh_database_and_exact_image() -> None:
    job = _load(GITHUB / "workflows" / "ci.yml")["jobs"]["container-security"]
    env = job["env"]
    assert env["TRIVY_VERSION"] == "0.74.0"
    assert env["TRIVY_SHA256"] == "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
    steps = job["steps"]
    script = "\n".join(step.get("run", "") for step in steps)
    assert "sha256sum --check --strict" in script
    assert script.index("sha256sum --check --strict") < script.index("tar --extract")
    assert "--max-time 180" in script and "--retry-max-time 240" in script
    assert "docker image inspect --format '{{.Id}}'" in script
    assert "--download-db-only" in script and "timeout 300s" in script
    assert "--skip-db-update" in script and "--image-src docker" in script
    assert "--severity HIGH,CRITICAL --exit-code 1" in script
    assert "--ignore-unfixed=false" in script and "--pkg-types os,library" in script
    assert "--format cyclonedx" in script and '"$CONTAINER_IMAGE_ID"' in script
    assert "python -m tools.container.verify database" in script
    assert "python -m tools.container.verify bundle" in script
    # Repository XML is parsed by Python's bundled expat, which the image scan cannot see.
    assert "pyexpat.EXPAT_VERSION" in script and "assert expat >= (2, 8, 5)" in script
    assert '--scan-exit "$scan_exit" --os-type wolfi' in script
    assert not any("cache@" in step.get("uses", "") for step in steps)
    assert not any(step.get("continue-on-error") for step in steps)
    upload = steps[-1]
    assert upload["if"] == "always()"
    assert upload["with"]["if-no-files-found"] == "error"


def test_container_updates_installed_base_packages_before_dependency_install() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    build, runtime = dockerfile.split("\nFROM ", 2)[1:]
    # The interpreter may carry a temporary revision pin, identical in both stages.
    python = r"python-3\.12(?:=(?P<pin>\S+) python-3\.12-base=(?P=pin))?"
    build_add = re.search(rf"&& apk add --no-cache {python} py3\.12-pip\n", build)
    runtime_add = re.search(rf"&& apk add --no-cache {python} git ", runtime)
    assert build_add and runtime_add, "both stages install python-3.12 (and pip or git) with apk"
    assert build_add["pin"] == runtime_add["pin"], "the build and runtime interpreters must match"
    assert build.index("RUN apk upgrade --no-cache") < build_add.start()
    assert runtime.index("RUN apk upgrade --no-cache") < runtime_add.start()
    # pip and the build tools never reach the runtime stage.
    assert "pip" not in runtime.split("RUN apk upgrade", 1)[1].split("\nCOPY --from=build")[0].replace(
        "python-3.12", ""
    )


def test_container_stages_share_one_reviewed_base_digest() -> None:
    images = [
        arguments.split()[0]
        for keyword, arguments in _dockerfile_instructions((ROOT / "Dockerfile").read_text(encoding="utf-8"))
        if keyword == "FROM"
    ]
    assert len(images) == 2 and images[0] == images[1]
    assert re.fullmatch(r"chainguard/wolfi-base:latest@sha256:[0-9a-f]{64}", images[0])


def test_container_build_removes_setuid_and_setgid_bits_and_checks_none_remain() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split("\nFROM ", 2)[2]
    strip = runtime.index("&& find / -xdev -type f -perm /6000 -exec chmod a-s {} +")
    check = runtime.index('&& test -z "$(find / -xdev -type f -perm /6000 -print -quit)"')
    assert runtime.index("apk add --no-cache python-3.12") < strip < check < runtime.index("USER 65532:65532")


def _container_evidence(tmp_path: Path) -> tuple[str, datetime]:
    image_id = "sha256:" + "a" * 64
    now = datetime(2026, 10, 2, 5, tzinfo=UTC)
    documents = {
        "image-inspect.json": [
            {"Id": image_id, "Config": {"Labels": {"org.opencontainers.image.revision": "d" * 40}}}
        ],
        "database-metadata.json": {
            "Version": 2,
            "UpdatedAt": (now - timedelta(hours=6)).isoformat(),
            "DownloadedAt": now.isoformat(),
        },
        "trivy-version.json": {"Version": "0.74.0"},
        "container-sbom.cdx.json": {
            "bomFormat": "CycloneDX",
            "metadata": {
                "component": {
                    "type": "container",
                    "properties": [
                        {"name": "aquasecurity:trivy:ImageID", "value": image_id},
                        {
                            "name": "aquasecurity:trivy:Labels:org.opencontainers.image.revision",
                            "value": "d" * 40,
                        },
                    ],
                }
            },
            "components": [
                {"purl": "pkg:apk/wolfi/git@2.55.0-r0?arch=x86_64&distro=20230201"},
                {"purl": "pkg:pypi/nexusshadowscan@0.1.1"},
            ],
        },
        "container-vulnerabilities.json": {
            "ArtifactType": "container_image",
            "Metadata": {"ImageID": image_id},
            "Results": [
                {"Class": "os-pkgs", "Type": "wolfi", "Packages": [{"Name": "git"}]},
                {"Class": "lang-pkgs", "Type": "python-pkg", "Packages": [{"Name": "requests"}]},
            ],
        },
    }
    for filename, document in documents.items():
        (tmp_path / filename).write_text(json.dumps(document), encoding="utf-8")
    (tmp_path / "database-sha256.txt").write_text("b" * 64 + "\n", encoding="utf-8")
    return image_id, now


@pytest.mark.parametrize(
    "case",
    [
        "passed",
        "vulnerable-unfixed",
        "scanner-error",
        "scanner-timeout",
        "stale-database",
        "future-database",
        "old-download",
        "missing-os",
        "missing-python",
        "missing-scanner",
        "wrong-image",
        "wrong-inspection",
        "wrong-source",
        "wrong-sbom-image",
        "wrong-sbom-source",
        "wrong-version",
        "empty-report",
        "hidden-vulnerability",
        "inconsistent-exit",
        "duplicate-key",
    ],
)
def test_container_evidence_cannot_accept_incomplete_or_mismatched_scans(tmp_path: Path, case: str) -> None:
    image_id, now = _container_evidence(tmp_path)
    scan_exit = 0
    report_path = tmp_path / "container-vulnerabilities.json"
    report = json.loads(report_path.read_text())
    if case in {"vulnerable-unfixed", "hidden-vulnerability"}:
        report["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-TEST-0001", "Severity": "HIGH", "FixedVersion": "", "PkgName": "login"}
        ]
        scan_exit = 1 if case == "vulnerable-unfixed" else 0
    elif case == "scanner-error":
        scan_exit = 2
    elif case == "scanner-timeout":
        scan_exit = 124
    elif case in {"stale-database", "future-database", "old-download"}:
        metadata = json.loads((tmp_path / "database-metadata.json").read_text())
        field = "DownloadedAt" if case == "old-download" else "UpdatedAt"
        delta = timedelta(hours=49 if case == "stale-database" else 2)
        metadata[field] = (now + delta if case == "future-database" else now - delta).isoformat()
        (tmp_path / "database-metadata.json").write_text(json.dumps(metadata))
    elif case in {"missing-os", "missing-python"}:
        report["Results"] = report["Results"][1:] if case == "missing-os" else report["Results"][:1]
    elif case == "missing-scanner":
        sbom_path = tmp_path / "container-sbom.cdx.json"
        sbom = json.loads(sbom_path.read_text())
        sbom["components"] = sbom["components"][:1]
        sbom_path.write_text(json.dumps(sbom))
    elif case == "wrong-image":
        report["Metadata"]["ImageID"] = "sha256:" + "c" * 64
    elif case == "wrong-inspection":
        (tmp_path / "image-inspect.json").write_text(json.dumps([{"Id": "sha256:" + "c" * 64}]))
    elif case == "wrong-source":
        inspection_path = tmp_path / "image-inspect.json"
        inspection = json.loads(inspection_path.read_text())
        inspection[0]["Config"]["Labels"]["org.opencontainers.image.revision"] = "f" * 40
        inspection_path.write_text(json.dumps(inspection))
    elif case in {"wrong-sbom-image", "wrong-sbom-source"}:
        sbom_path = tmp_path / "container-sbom.cdx.json"
        sbom = json.loads(sbom_path.read_text())
        index = 0 if case == "wrong-sbom-image" else 1
        sbom["metadata"]["component"]["properties"][index]["value"] = "wrong"
        sbom_path.write_text(json.dumps(sbom))
    elif case == "wrong-version":
        (tmp_path / "trivy-version.json").write_text(json.dumps({"Version": "0.69.4"}))
    elif case == "empty-report":
        report = {}
    elif case == "inconsistent-exit":
        scan_exit = 1
    report_path.write_text(json.dumps(report))
    if case == "duplicate-key":
        report_path.write_text('{"Metadata":{},"Metadata":{}}')
    arguments = {
        "image_id": image_id,
        "source_sha": "d" * 40,
        "scanner_version": "0.74.0",
        "scanner_sha256": "e" * 64,
        "scan_exit": scan_exit,
        "os_type": "wolfi",
        "now": now,
    }
    if case not in {"passed", "vulnerable-unfixed"}:
        with pytest.raises(ValueError):
            verify_bundle(tmp_path, **arguments)
        return
    manifest = verify_bundle(tmp_path, **arguments)
    assert manifest["image_id"] == image_id
    assert manifest["status"] == ("blocked" if case == "vulnerable-unfixed" else "passed")
    assert len(manifest["files"]) == 6
    blocking = [(item["vulnerability"], item["package"]) for item in manifest["blocking_vulnerabilities"]]
    assert blocking == ([("CVE-TEST-0001", "login")] if case == "vulnerable-unfixed" else [])


@pytest.mark.parametrize("os_type", ["debian", "alpine"])
def test_container_evidence_must_inventory_the_declared_operating_system(
    tmp_path: Path, os_type: str
) -> None:
    # A Wolfi report and inventory never satisfy a Debian expectation, and an
    # undeclared family is refused rather than checked loosely.
    image_id, now = _container_evidence(tmp_path)
    with pytest.raises(ValueError, match="debian packages|unsupported operating-system"):
        verify_bundle(
            tmp_path,
            image_id=image_id,
            source_sha="d" * 40,
            scanner_version="0.74.0",
            scanner_sha256="e" * 64,
            scan_exit=0,
            os_type=os_type,
            now=now,
        )


def test_database_verification_requires_a_real_digest(tmp_path: Path) -> None:
    _, now = _container_evidence(tmp_path)
    (tmp_path / "database-sha256.txt").write_text("invalid\n")
    with pytest.raises(ValueError, match="database digest"):
        verify_database(tmp_path, now=now)


@pytest.mark.parametrize("vulnerable", [False, True])
def test_container_evidence_cli_retains_blocked_results_and_fails_the_job(
    tmp_path: Path, vulnerable: bool
) -> None:
    image_id, _ = _container_evidence(tmp_path)
    current = datetime.now(UTC).isoformat()
    (tmp_path / "database-metadata.json").write_text(
        json.dumps({"Version": 2, "UpdatedAt": current, "DownloadedAt": current})
    )
    if vulnerable:
        path = tmp_path / "container-vulnerabilities.json"
        report = json.loads(path.read_text())
        report["Results"][0]["Vulnerabilities"] = [
            {
                "VulnerabilityID": "CVE-TEST-0001",
                "Severity": "CRITICAL",
                "FixedVersion": "",
                # Report text reaches the CI log: a line break must not start a workflow command.
                "PkgName": "login\n::error::forged",
                "InstalledVersion": "1:4.17.4-2",
                "Status": "affected",
            }
        ]
        path.write_text(json.dumps(report))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.container.verify",
            "bundle",
            str(tmp_path),
            "--image-id",
            image_id,
            "--source-sha",
            "d" * 40,
            "--scanner-version",
            "0.74.0",
            "--scanner-sha256",
            "e" * 64,
            "--scan-exit",
            "1" if vulnerable else "0",
            "--os-type",
            "wolfi",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == (1 if vulnerable else 0), result.stdout + result.stderr
    manifest = json.loads((tmp_path / "container-evidence.json").read_text())
    assert manifest["status"] == ("blocked" if vulnerable else "passed")
    if vulnerable:
        assert "blocked by 1 HIGH/CRITICAL vulnerabilities" in result.stderr
        assert (
            "  CVE-TEST-0001 CRITICAL wolfi:login?::error::forged 1:4.17.4-2 status=affected" in result.stderr
        )
        assert not any(line.startswith("::") for line in result.stderr.splitlines())


@pytest.mark.parametrize(
    "case,passes",
    [
        ("signed", True),
        ("signed_merge", True),
        ("unsigned_merge", False),
        ("mixed_case", True),
        ("divergent", True),
        ("unsigned", False),
        ("forged", False),
        ("dependabot", True),
        ("dependabot_metadata", True),
        ("signed_after_divider", True),
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
            [git_path, "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={os.devnull}"]
            + ["-c", "maintenance.auto=false", *args],
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
    if case == "signed_after_divider":
        # A '---' line is text in a commit message, not a patch divider.
        message = "Change\n\n---\nNotes\n\nSigned-off-by: DCO Reviewer <reviewer@example.test>"
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
        if case == "dependabot_metadata":
            # Dependabot's own message: a '---' line opens its YAML metadata
            # before the sign-off.
            message = (
                "build(deps): bump coverage from 7.16.1 to 7.16.2\n\nBumps coverage.\n\n---\n"
                "updated-dependencies:\n- dependency-name: coverage\n  dependency-version: 7.16.2\n...\n\n"
                "Signed-off-by: dependabot[bot] <support@github.com>"
            )
        if case != "dependabot_forged":
            extra = {
                "GIT_AUTHOR_NAME": "dependabot[bot]",
                "GIT_AUTHOR_EMAIL": "49699333+dependabot[bot]@users.noreply.github.com",
                "GIT_COMMITTER_NAME": "GitHub",
                "GIT_COMMITTER_EMAIL": "noreply@github.com",
            }
    git("commit", "--allow-empty", "-qm", message, extra_env=extra)
    head = git("rev-parse", "HEAD")
    if case in {"signed_merge", "unsigned_merge"}:
        # A valid merge commit can add content that neither parent authored.
        # Certifying the feature parent must not certify these extra changes.
        introduced = tmp_path / "merge-only.txt"
        introduced.write_text("New content authored in the merge\n", encoding="utf-8")
        git("add", introduced.name)
        tree = git("write-tree")
        merge_message = signed if case == "signed_merge" else "Unsigned merge"
        head = git("commit-tree", tree, "-p", base, "-p", head, "-m", merge_message)
        assert git("show", f"{head}:{introduced.name}") == "New content authored in the merge"
        assert len(git("show", "-s", "--format=%P", head).split()) == 2
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
    text = _without_sanctioned_upload(path.name, _load(path), path.read_text(encoding="utf-8"))
    assert not _publication_violations(text)


def test_the_sanctioned_upload_is_the_only_exemption() -> None:
    """Without its one exemption, release.yml has exactly one package upload and nothing else."""
    text = (GITHUB / "workflows" / "release.yml").read_text(encoding="utf-8")
    violations = _publication_violations(text)
    assert len(violations) == 1 and violations[0].startswith("package upload: `pypi-publish`"), violations


def test_release_workflow_uploads_only_through_the_gated_publish_job() -> None:
    workflow = _load(GITHUB / "workflows" / "release.yml")
    assert _trigger_names(workflow) == {"workflow_dispatch"}
    assert not _release_publish_violations(workflow)
    # Only the attestation and publish jobs hold an OIDC token, and neither
    # checks out or runs repository code.
    for name, job in workflow["jobs"].items():
        if (job.get("permissions") or {}).get("id-token") == "write":
            assert name in {"attest", "publish"}
            assert not any(step.get("uses", "").startswith("actions/checkout@") for step in job["steps"])
    assert workflow["jobs"]["publication-input"]["permissions"] == {}


_REVIEWED = "a" * 40


@pytest.mark.parametrize(
    "target,wheels,tagged,tamper,passes",
    [
        pytest.param("pypi", ["0.1.1"], _REVIEWED, False, True, id="pypi-tag-on-reviewed-commit"),
        pytest.param("pypi", ["0.1.1"], "b" * 40, False, False, id="pypi-tag-elsewhere"),
        pytest.param("pypi", ["0.1.1"], None, False, False, id="pypi-without-tag"),
        pytest.param("testpypi", ["0.1.1"], None, False, True, id="testpypi-rehearsal-without-tag"),
        pytest.param("pypi", ["0.2.0rc1"], _REVIEWED, False, True, id="pypi-release-candidate"),
        pytest.param("testpypi", ["0.1.1.dev0"], None, False, False, id="development-version"),
        pytest.param("testpypi", ["0.1.1+local"], None, False, False, id="local-version"),
        pytest.param("testpypi", ["0.1.0", "0.1.1"], None, False, False, id="two-wheels"),
        pytest.param("testpypi", [], None, False, False, id="no-wheel"),
        pytest.param("pypi", ["0.1.1"], _REVIEWED, True, False, id="tampered-wheel"),
    ],
)
def test_publication_gate_executes_fail_closed(
    tmp_path: Path, target: str, wheels: list[str], tagged: str | None, tamper: bool, passes: bool
) -> None:
    """Run the committed gate script against a stub `gh` that answers the tag lookup."""
    gate = _load(GITHUB / "workflows" / "release.yml")["jobs"]["publication-gate"]
    script = next(step["run"] for step in gate["steps"] if "run" in step)
    candidate = tmp_path / "publication-input"
    candidate.mkdir()
    for version in wheels:
        (candidate / f"nexusshadowscan-{version}-py3-none-any.whl").write_bytes(version.encode())
    sums = subprocess.run(
        ["sha256sum", *sorted(path.name for path in candidate.iterdir())],
        cwd=candidate,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    (candidate / "SHA256SUMS").write_text(sums, encoding="utf-8")
    if tamper:
        for path in candidate.glob("*.whl"):
            path.write_bytes(b"substituted after attestation")
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "gh").write_text(
        "#!/bin/bash\n"
        'expected="api repos/aisecnomad/Project-Nexus/commits/tags/v$EXPECTED_VERSION --jq .sha"\n'
        '[ "$*" = "$expected" ] || { echo "unexpected gh call: $*" >&2; exit 64; }\n'
        '[ -n "$TAGGED" ] || { echo "HTTP 404: No commit found for SHA" >&2; exit 1; }\n'
        'printf "%s\\n" "$TAGGED"\n',
        encoding="utf-8",
    )
    (stub / "gh").chmod(0o700)
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=candidate,
        env={
            "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
            "GH_TOKEN": "not-a-real-token",
            "PUBLISH": target,
            "GITHUB_REPOSITORY": "aisecnomad/Project-Nexus",
            "GITHUB_SHA": _REVIEWED,
            "EXPECTED_VERSION": wheels[-1] if wheels else "",
            "TAGGED": tagged or "",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr
    assert "unexpected gh call" not in result.stderr
    if passes:
        assert f"to {target} from {_REVIEWED}" in result.stdout


@pytest.mark.parametrize(
    "job,step", [("publication-input", "Verify the exact attested"), ("publish", "Stage only the attested")]
)
@pytest.mark.parametrize("count", [1, 2])
def test_release_steps_require_exactly_one_wheel(tmp_path: Path, job: str, step: str, count: int) -> None:
    """Regression: `[ n -eq 1 ] && [ -f w ]` let two wheels through, because `set -e` ignores `a` in `a && b`."""
    steps = _load(GITHUB / "workflows" / "release.yml")["jobs"][job]["steps"]
    script = next(entry["run"] for entry in steps if entry.get("name", "").startswith(step))
    candidate = tmp_path / "publication-input"
    (candidate / "attestations").mkdir(parents=True)
    for name in ("provenance.json", "sbom.json"):
        (candidate / "attestations" / name).write_text("{}", encoding="utf-8")
    for version in ("0.1.1", "0.1.0")[:count]:
        (candidate / f"nexusshadowscan-{version}-py3-none-any.whl").write_bytes(version.encode())
    sums = subprocess.run(
        ["sha256sum", *sorted(path.name for path in candidate.glob("*.whl"))],
        cwd=candidate,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    (candidate / "SHA256SUMS").write_text(sums, encoding="utf-8")
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=candidate if job == "publication-input" else tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is (count == 1), result.stdout + result.stderr
    if job == "publish" and count == 1:
        assert [path.name for path in (tmp_path / "dist").iterdir()] == [
            "nexusshadowscan-0.1.1-py3-none-any.whl"
        ]


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
