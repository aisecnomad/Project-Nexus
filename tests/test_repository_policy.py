"""The community, CI and policy files stay consistent with each other and with the code.

These tests read the checked-in repository rather than the installed package. They
fail when a document links to a file or heading that does not exist, a workflow
step is unpinned or holds more permissions than AGENTS.md allows, an issue form
applies a label the tracker does not define, the local tooling drifts from the CI
gates, or a documented count no longer matches the shipped signature packs and
connectors. Run them alone with ``make policy``.
"""

from __future__ import annotations

import functools
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest
import yaml

from shadowscan.connectors import builtin_connector_names

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
WORKFLOW_FILES = sorted((GITHUB / "workflows").glob("*.yml"))
ISSUE_FORM_FILES = sorted(path for path in (GITHUB / "ISSUE_TEMPLATE").glob("*.yml") if path.name != "config.yml")
ADVISORY_URL = "https://github.com/aisecnomad/Project-Nexus/security/advisories/new"

# Files GitHub's community profile and the OpenSSF Scorecard look for, plus the
# project's own governance set. Each must exist and carry content.
COMMUNITY_FILES = (
    "README.md",
    "LICENSE",
    "NOTICE",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "ROADMAP.md",
    "CODEOWNERS",
    "CITATION.cff",
    "AGENTS.md",
    ".editorconfig",
    ".gitattributes",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/dependabot.yml",
    ".github/labels.yml",
)

# Write scopes a job may hold, each tied to a workflow that needs it: CodeQL and
# Scorecard upload SARIF, the release-evidence workflow attests, Pages deploys,
# the stale and label jobs edit issues. Nothing here may push, tag, publish a
# package or create a release: AGENTS.md makes release a manual maintainer step.
JOB_WRITE_SCOPES_ALLOWED = frozenset(
    {"security-events", "id-token", "attestations", "pages", "issues", "pull-requests"}
)
PUBLISHING_MARKERS = (
    "pypa/gh-action-pypi-publish",
    "softprops/action-gh-release",
    "ncipollo/release-action",
    "twine upload",
    "gh release create",
    "git push --tags",
    "git push origin v",
)
STEP_TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}


# --- Markdown helpers -------------------------------------------------------


def _markdown_files() -> list[Path]:
    files = sorted(ROOT.glob("*.md"))
    for folder in (".github", "docs", "examples", "tools"):
        files.extend(sorted((ROOT / folder).rglob("*.md")))
    return files


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


_FENCE = re.compile(r"^(`{3,}|~{3,})")


def _prose_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, line)`` for every line outside a fenced code block."""
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        match = _FENCE.match(line.lstrip())
        if match is not None:
            marker = match.group(1)[0]
            if fence is None:
                fence = marker
                continue
            if marker == fence:
                fence = None
                continue
        if fence is None:
            yield number, line


_INLINE_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_REFERENCE_LINK = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)")
_INLINE_CODE = re.compile(r"`[^`]*`")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _link_targets(text: str) -> Iterator[tuple[int, str]]:
    for number, line in _prose_lines(text):
        prose = _INLINE_CODE.sub("", line)
        for match in _INLINE_LINK.finditer(prose):
            yield number, match.group(1)
        reference = _REFERENCE_LINK.match(prose)
        if reference is not None:
            yield number, reference.group(1)


def _is_external(target: str) -> bool:
    return target.startswith("//") or _SCHEME.match(target) is not None


def _resolve(source: Path, target: str) -> tuple[Path, str | None]:
    path_part, _, anchor = target.partition("#")
    path_part = unquote(path_part)
    if not path_part:
        return source, anchor or None
    if path_part.startswith("/"):
        return (ROOT / path_part.lstrip("/")).resolve(), anchor or None
    return (source.parent / path_part).resolve(), anchor or None


_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$")
_ATTR_ID = re.compile(r"\{\s*#([^\s}]+)\s*\}\s*$")
_MARKDOWN_LINK_TEXT = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def _github_slug(heading: str) -> str:
    text = re.sub(r"[^\w\- ]", "", heading.lower())
    return text.replace(" ", "-")


def _mkdocs_slug(heading: str) -> str:
    text = re.sub(r"[^\w\s-]", "", heading).strip().lower()
    return re.sub(r"[-\s]+", "-", text)


@functools.cache
def _anchors(path: Path) -> frozenset[str]:
    """Heading anchors GitHub or MkDocs would generate for a Markdown file."""
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    for _, line in _prose_lines(_read(path)):
        match = _HEADING.match(line)
        if match is None:
            continue
        heading = match.group(1)
        explicit = _ATTR_ID.search(heading)
        if explicit is not None:
            anchors.add(explicit.group(1).lower())
            heading = heading[: explicit.start()]
        heading = _MARKDOWN_LINK_TEXT.sub(r"\1", heading)
        heading = heading.replace("`", "").replace("*", "").strip()
        slug = _github_slug(heading)
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
        anchors.add(_mkdocs_slug(heading))
    return frozenset(anchors)


# --- YAML helpers -----------------------------------------------------------


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(_read(path))


def _jobs(workflow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return workflow.get("jobs") or {}


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return job.get("steps") or []


def _triggers(workflow: dict[str, Any]) -> list[str]:
    # PyYAML reads the bare key ``on`` as boolean True (YAML 1.1).
    triggers = workflow.get("on", workflow.get(True))
    if isinstance(triggers, dict):
        return list(triggers)
    if isinstance(triggers, list):
        return [str(item) for item in triggers]
    return [str(triggers)]


def _is_read_only(permissions: Any) -> bool:
    if permissions == "read-all":
        return True
    if isinstance(permissions, dict):
        return all(value in ("read", "none") for value in permissions.values())
    return False


@functools.lru_cache(maxsize=1)
def _labels() -> dict[str, dict[str, Any]]:
    entries = _load_yaml(GITHUB / "labels.yml")
    assert isinstance(entries, list) and entries, ".github/labels.yml must be a non-empty list"
    return {entry["name"]: entry for entry in entries}


@functools.lru_cache(maxsize=1)
def _pyproject() -> dict[str, Any]:
    return tomllib.loads(_read(ROOT / "pyproject.toml"))


def _workflow_id(path: Path) -> str:
    return path.name


def _relative_id(path: Path) -> str:
    return str(path.relative_to(ROOT))


# --- Community profile ------------------------------------------------------


@pytest.mark.parametrize("name", COMMUNITY_FILES)
def test_community_file_exists_with_content(name: str) -> None:
    path = ROOT / name
    assert path.is_file(), f"{name} is missing"
    assert path.stat().st_size > 0, f"{name} is empty"


def test_security_policy_has_the_sections_github_and_reporters_expect() -> None:
    anchors = _anchors(ROOT / "SECURITY.md")
    for anchor in ("supported-versions", "reporting", "trust-boundary"):
        assert anchor in anchors, f"SECURITY.md lacks a '{anchor}' heading"
    text = _read(ROOT / "SECURITY.md")
    assert ADVISORY_URL in text, "SECURITY.md must link the private advisory form"


@pytest.mark.parametrize(
    "name",
    ["SECURITY.md", "SUPPORT.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "MAINTAINERS.md"],
)
def test_private_reporting_channel_is_linked_everywhere_reports_are_routed(name: str) -> None:
    text = _read(ROOT / name)
    assert ADVISORY_URL in text or "SECURITY.md#reporting" in text, (
        f"{name} must link the private advisory form or the SECURITY.md reporting section"
    )


@pytest.mark.parametrize("name", ["README.md", "CONTRIBUTING.md", "SUPPORT.md", "GOVERNANCE.md"])
def test_code_of_conduct_is_linked_from_entry_points(name: str) -> None:
    assert "CODE_OF_CONDUCT.md" in _read(ROOT / name), f"{name} must link the code of conduct"


def test_code_of_conduct_is_the_contributor_covenant_with_an_enforcement_channel() -> None:
    text = _read(ROOT / "CODE_OF_CONDUCT.md")
    assert "Contributor Covenant" in text
    # SUPPORT.md and the docs deep-link to this heading.
    assert "reporting-a-concern" in _anchors(ROOT / "CODE_OF_CONDUCT.md")
    assert ADVISORY_URL in text


def test_citation_matches_the_package_metadata() -> None:
    citation = _load_yaml(ROOT / "CITATION.cff")
    project = _pyproject()["project"]
    assert citation["version"] == project["version"]
    assert citation["license"] == project["license"]["text"]
    assert citation["repository-code"] == project["urls"]["Repository"]
    assert citation["url"] == project["urls"]["Documentation"]


def test_codeowners_paths_exist() -> None:
    for line in _read(ROOT / "CODEOWNERS").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pattern = line.split()[0]
        if pattern == "*":
            continue
        target = ROOT / pattern.strip("/")
        assert target.exists(), f"CODEOWNERS names {pattern}, which does not exist"


# --- Markdown links ----------------------------------------------------------


@pytest.mark.parametrize("markdown", _markdown_files(), ids=_relative_id)
def test_relative_markdown_links_resolve(markdown: Path) -> None:
    problems: list[str] = []
    for number, target in _link_targets(_read(markdown)):
        if _is_external(target):
            continue
        resolved, anchor = _resolve(markdown, target)
        if not resolved.exists():
            problems.append(f"line {number}: {target} -> {resolved.relative_to(ROOT)} does not exist")
            continue
        if anchor and resolved.suffix == ".md" and anchor.lower() not in _anchors(resolved):
            problems.append(f"line {number}: {target} -> no heading produces #{anchor}")
    assert not problems, f"{markdown.relative_to(ROOT)}:\n  " + "\n  ".join(problems)


def test_issue_form_links_reference_forms_that_exist() -> None:
    forms = {path.name for path in ISSUE_FORM_FILES}
    for markdown in _markdown_files():
        for match in re.finditer(r"template=([\w.-]+\.yml)", _read(markdown)):
            assert match.group(1) in forms, f"{markdown.relative_to(ROOT)} links missing form {match.group(1)}"


# --- Issue forms and labels -------------------------------------------------


def test_labels_are_well_formed_and_unique() -> None:
    entries = _load_yaml(GITHUB / "labels.yml")
    names = [entry.get("name") for entry in entries]
    assert len(set(names)) == len(names), "duplicate label names"
    for entry in entries:
        assert isinstance(entry.get("name"), str) and entry["name"].strip(), entry
        assert re.fullmatch(r"[0-9a-fA-F]{6}", str(entry.get("color"))), f"{entry['name']}: color must be six hex digits"
        description = entry.get("description", "")
        assert isinstance(description, str) and 0 < len(description) <= 100, f"{entry['name']}: description"


@pytest.mark.parametrize("form", ISSUE_FORM_FILES, ids=_workflow_id)
def test_issue_form_is_well_formed_and_uses_defined_labels(form: Path) -> None:
    data = _load_yaml(form)
    assert data.get("name") and data.get("description"), f"{form.name}: name and description are required"
    assert data.get("labels"), f"{form.name}: apply at least one label so triage can filter"
    for label in data["labels"]:
        assert label in _labels(), f"{form.name}: label {label!r} is not defined in .github/labels.yml"
    body = data.get("body")
    assert isinstance(body, list) and body, f"{form.name}: body must be a non-empty list"
    ids = [element.get("id") for element in body if element.get("type") != "markdown"]
    assert all(ids) and len(set(ids)) == len(ids), f"{form.name}: every input needs a unique id"
    for element in body:
        kind = element.get("type")
        assert kind in STEP_TYPES, f"{form.name}: unknown element type {kind!r}"
        attributes = element.get("attributes")
        assert isinstance(attributes, dict), f"{form.name}: {kind} element without attributes"
        if kind == "markdown":
            assert attributes.get("value"), f"{form.name}: empty markdown block"
            continue
        assert attributes.get("label"), f"{form.name}: {element.get('id')} needs a label"
        if kind == "dropdown":
            assert isinstance(attributes.get("options"), list) and attributes["options"], element.get("id")
        if kind == "checkboxes":
            options = attributes.get("options")
            assert isinstance(options, list) and all(option.get("label") for option in options), element.get("id")


def test_issue_chooser_disables_blank_issues_and_routes_security_privately() -> None:
    config = _load_yaml(GITHUB / "ISSUE_TEMPLATE" / "config.yml")
    assert config.get("blank_issues_enabled") is False
    links = config.get("contact_links") or []
    for link in links:
        assert link.get("name") and link.get("about"), link
        assert str(link.get("url")).startswith("https://"), link
    assert any(link["url"] == ADVISORY_URL for link in links), "chooser must offer the private advisory"
    assert any(link["url"].endswith("/SUPPORT.md") for link in links), "chooser must offer SUPPORT.md"


def test_stale_automation_never_closes_pull_requests() -> None:
    workflow = _load_yaml(GITHUB / "workflows" / "stale.yml")
    steps = [step for job in _jobs(workflow).values() for step in _steps(job) if "actions/stale@" in step.get("uses", "")]
    assert steps, "stale.yml must use actions/stale"
    for step in steps:
        options = step.get("with") or {}
        pr_close = options.get("days-before-pr-close", options.get("days-before-close"))
        assert pr_close == -1, "pull requests are never closed by automation"
        assert options.get("days-before-stale", 0) >= 60, "give reporters at least 60 quiet days before a stale mark"
        issue_close = options.get("days-before-issue-close", options.get("days-before-close"))
        assert issue_close == -1 or issue_close >= 30, "issues get at least 30 days after the stale notice"
        exempt = str(options.get("exempt-issue-labels", ""))
        assert "security" in exempt and "pinned" in exempt


# --- Workflows ---------------------------------------------------------------

_USES_LINE = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>[^#\s]+)\s*(?P<comment>#.*)?$")
_PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=_workflow_id)
def test_actions_are_pinned_to_a_full_commit_sha_with_a_version_comment(workflow: Path) -> None:
    problems: list[str] = []
    seen = 0
    for number, line in enumerate(_read(workflow).splitlines(), start=1):
        match = _USES_LINE.match(line)
        if match is None:
            continue
        seen += 1
        ref = match.group("ref").strip("'\"")
        if not _PINNED.match(ref):
            problems.append(f"line {number}: {ref} is not owner/repo@<40-hex-sha>")
        if not re.search(r"#\s*v?\d", match.group("comment") or ""):
            problems.append(f"line {number}: {ref} needs a version comment such as '# v4.2.2'")
    assert seen, f"{workflow.name} uses no actions; the pin check found nothing to check"
    assert not problems, f"{workflow.name}:\n  " + "\n  ".join(problems)


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=_workflow_id)
def test_checkouts_do_not_persist_credentials(workflow: Path) -> None:
    for job_name, job in _jobs(_load_yaml(workflow)).items():
        for step in _steps(job):
            if step.get("uses", "").startswith("actions/checkout@"):
                options = step.get("with") or {}
                assert options.get("persist-credentials") is False, f"{workflow.name}:{job_name} checkout persists credentials"


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=_workflow_id)
def test_top_level_permissions_are_explicit_and_read_only(workflow: Path) -> None:
    data = _load_yaml(workflow)
    assert "permissions" in data, f"{workflow.name} must declare top-level permissions"
    assert _is_read_only(data["permissions"]), f"{workflow.name} grants write permissions to every job; scope them per job"


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=_workflow_id)
def test_job_write_permissions_stay_within_the_allowed_scopes(workflow: Path) -> None:
    for job_name, job in _jobs(_load_yaml(workflow)).items():
        permissions = job.get("permissions")
        if permissions is None:
            continue
        assert permissions != "write-all", f"{workflow.name}:{job_name} must not request write-all"
        if isinstance(permissions, dict):
            writes = {scope for scope, level in permissions.items() if level == "write"}
            unexpected = writes - JOB_WRITE_SCOPES_ALLOWED
            assert not unexpected, f"{workflow.name}:{job_name} writes {sorted(unexpected)}; add the scope here with its reason"


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=_workflow_id)
def test_every_job_has_a_timeout(workflow: Path) -> None:
    for job_name, job in _jobs(_load_yaml(workflow)).items():
        assert isinstance(job.get("timeout-minutes"), int), f"{workflow.name}:{job_name} needs timeout-minutes"


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=_workflow_id)
def test_no_dangerous_trigger_or_script_injection(workflow: Path) -> None:
    data = _load_yaml(workflow)
    assert "pull_request_target" not in _triggers(data), f"{workflow.name} uses pull_request_target"
    for job_name, job in _jobs(data).items():
        for step in _steps(job):
            script = step.get("run")
            if isinstance(script, str):
                assert "${{ github.event." not in script, (
                    f"{workflow.name}:{job_name} interpolates event data into a shell script; pass it through env"
                )


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=_workflow_id)
def test_no_workflow_publishes_a_release_package_or_tag(workflow: Path) -> None:
    text = _read(workflow)
    for marker in PUBLISHING_MARKERS:
        assert marker not in text, f"{workflow.name} contains {marker!r}; release is a manual maintainer action"


def test_ci_matrix_covers_every_classified_python_version() -> None:
    ci = _load_yaml(GITHUB / "workflows" / "ci.yml")
    matrix = {str(version) for version in ci["jobs"]["test"]["strategy"]["matrix"]["python"]}
    classified = {
        classifier.rsplit("::", 1)[1].strip()
        for classifier in _pyproject()["project"]["classifiers"]
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", classifier)
    }
    assert matrix == classified, f"CI tests {sorted(matrix)} but pyproject classifies {sorted(classified)}"


# --- Local tooling mirrors CI -----------------------------------------------


def _ci_run_lines() -> list[str]:
    lines: list[str] = []
    for job in _jobs(_load_yaml(GITHUB / "workflows" / "ci.yml")).values():
        for step in _steps(job):
            script = step.get("run")
            if isinstance(script, str):
                lines.extend(line.strip() for line in script.splitlines())
    return lines


def _first_tool_arguments(lines: list[str], tool: str) -> set[str]:
    for line in lines:
        if line.startswith(f"{tool} "):
            return set(line.split()[1:])
    raise AssertionError(f"no {tool} invocation found")


def test_makefile_lint_and_typecheck_paths_match_ci() -> None:
    ci = _ci_run_lines()
    makefile = [line.strip() for line in _read(ROOT / "Makefile").splitlines()]
    assert _first_tool_arguments(makefile, "mypy") == _first_tool_arguments(ci, "mypy"), "make typecheck drifted from CI"
    ci_ruff = {arg for arg in _first_tool_arguments(ci, "ruff") if arg != "check"}
    make_ruff = {arg for arg in _first_tool_arguments(makefile, "ruff") if arg != "check"}
    assert make_ruff == ci_ruff, "make lint drifted from CI"


def test_makefile_evaluates_the_same_corpora_as_ci() -> None:
    ci_corpora = set(re.findall(r"--corpus (\S+)", "\n".join(_ci_run_lines())))
    make_corpora = set(re.findall(r"--corpus (\S+)", _read(ROOT / "Makefile")))
    assert make_corpora == ci_corpora, f"make evaluate runs {sorted(make_corpora)} but CI runs {sorted(ci_corpora)}"
    for corpus in ci_corpora:
        assert (ROOT / corpus).is_file(), f"CI references a missing corpus {corpus}"


def test_pre_commit_hooks_run_the_same_ruff_and_mypy_as_ci() -> None:
    config = _load_yaml(ROOT / ".pre-commit-config.yaml")
    revisions = {repo["repo"].rsplit("/", 1)[1]: str(repo["rev"]).lstrip("v") for repo in config["repos"] if "rev" in repo}
    constraints = dict(
        re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)$", _read(ROOT / "requirements-ci-constraints.txt"), re.MULTILINE)
    )
    assert revisions["ruff-pre-commit"] == constraints["ruff"], "pre-commit ruff rev differs from the CI pin"
    assert revisions["mirrors-mypy"] == constraints["mypy"], "pre-commit mypy rev differs from the CI pin"


def test_docs_toolchain_is_hash_locked_and_wheel_only() -> None:
    lock = _read(ROOT / "requirements-docs.lock")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock, re.MULTILINE)
    assert pins, "requirements-docs.lock has no pins"
    assert lock.count("--hash=sha256:") >= len(pins), "every docs dependency needs at least one hash"
    docs_extra = _pyproject()["project"]["optional-dependencies"]["docs"]
    locked = {name.lower(): version for name, version in pins}
    for requirement in docs_extra:
        name, _, floor = requirement.partition(">=")
        assert locked.get(name.lower()) == floor, f"{requirement} and requirements-docs.lock disagree"
    install = "--require-hashes --only-binary=:all: -r requirements-docs.lock"
    for workflow in ("docs.yml", "ci.yml"):
        assert install in _read(GITHUB / "workflows" / workflow), f"{workflow} must install docs tools from the lock"
    assert install in _read(ROOT / "Makefile"), "make docs must install docs tools from the lock"


# --- Documented counts match the code ---------------------------------------

_COUNT_CLAIM = re.compile(r"(\d+) signatures / (\d+) signals")
_CONNECTOR_CLAIM = re.compile(r"\*\*(\d+) connectors\*\*")


def _current_docs() -> list[Path]:
    return [
        path
        for path in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
        if "hardening-logs" not in path.parts
    ]


def test_documented_signature_counts_match_the_shipped_packs(index) -> None:
    signatures = list(index.signatures.values())
    actual = (len(signatures), sum(len(signature.signals) for signature in signatures))
    claims = [(path, match) for path in _current_docs() for match in _COUNT_CLAIM.finditer(_read(path))]
    assert claims, "README should state the signature and signal counts"
    for path, match in claims:
        claimed = (int(match.group(1)), int(match.group(2)))
        assert claimed == actual, f"{path.relative_to(ROOT)} claims {claimed}, packs ship {actual}"


def test_documented_connector_count_matches_the_registry() -> None:
    actual = len(builtin_connector_names())
    claims = [(path, int(match.group(1))) for path in _current_docs() for match in _CONNECTOR_CLAIM.finditer(_read(path))]
    for path, claimed in claims:
        assert claimed == actual, f"{path.relative_to(ROOT)} claims {claimed} connectors, registry has {actual}"
