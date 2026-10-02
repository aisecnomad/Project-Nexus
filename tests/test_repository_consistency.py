"""The documents, tooling and metadata stay consistent with each other and the code.

`test_repository_policy.py` guards workflow privileges and issue-form structure.
This module covers the rest of the repository's self-consistency: every relative
Markdown link and heading anchor resolves, the community files GitHub and the
OpenSSF Scorecard look for exist, `CITATION.cff` matches `pyproject.toml`, the
CI matrix matches the classifiers, the Makefile and pre-commit hooks run what CI
runs, every CodeQL action step is pinned to the same release, the docs toolchain
comes from its lock everywhere, and documented counts, the README's demo output,
CSV report markers and the HTTP read deadline match the shipped code. Run both
modules with ``make policy``.
"""

from __future__ import annotations

import functools
import itertools
import json
import os
import re
import shutil
import subprocess
import textwrap
import tomllib
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from urllib.parse import unquote

import pytest
import yaml

from shadowscan.config import ScanConfig
from shadowscan.connectors import ConnectorContext, builtin_connector_names, get_connector_class
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.common import MAX_PAGES
from shadowscan.engine import Engine
from shadowscan.models import ScanStats
from shadowscan.reporters.csv_ import _safe_cell
from shadowscan.utils import http

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
# GitHub runs both YAML spellings; test_repository_policy.py checks the glob.
WORKFLOWS = sorted(path for path in (GITHUB / "workflows").glob("*.y*ml") if path.is_file())
FORMS = sorted(path for path in (GITHUB / "ISSUE_TEMPLATE").glob("*.yml") if path.name != "config.yml")
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
    ".github/ISSUE_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/dependabot.yml",
    ".github/labels.yml",
    "requirements.lock",
    "requirements-build.lock",
    "requirements-ci.lock",
    "requirements-docs.lock",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(_read(path))


@functools.cache
def _pyproject() -> dict[str, Any]:
    return tomllib.loads(_read(ROOT / "pyproject.toml"))


def _relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


# --- Markdown -----------------------------------------------------------------


def _markdown_files() -> list[Path]:
    files = sorted(ROOT.glob("*.md"))
    for folder in (".github", "docs", "examples", "tools"):
        files.extend(sorted((ROOT / folder).rglob("*.md")))
    return files


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
    return re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")


def _mkdocs_slug(heading: str) -> str:
    return re.sub(r"[-\s]+", "-", re.sub(r"[^\w\s-]", "", heading).strip().lower())


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


@pytest.mark.parametrize("markdown", _markdown_files(), ids=_relative)
def test_relative_markdown_links_and_anchors_resolve(markdown: Path) -> None:
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
    assert not problems, f"{_relative(markdown)}:\n  " + "\n  ".join(problems)


def test_issue_form_links_reference_forms_that_exist() -> None:
    forms = {path.name for path in FORMS}
    for markdown in _markdown_files():
        for match in re.finditer(r"template=([\w.-]+\.yml)", _read(markdown)):
            assert match.group(1) in forms, f"{_relative(markdown)} links missing form {match.group(1)}"


def test_issue_template_index_lists_every_form() -> None:
    index = _read(GITHUB / "ISSUE_TEMPLATE.md")
    for form in FORMS:
        assert f"template={form.name}" in index, f".github/ISSUE_TEMPLATE.md does not link {form.name}"
    assert ADVISORY_URL in index, "the issue index must route security reports to the private advisory"


class _MkDocsLoader(yaml.SafeLoader):
    """Reads mkdocs.yml, ignoring Material's ``!!python/name`` tags."""


_MkDocsLoader.add_multi_constructor("tag:yaml.org,2002:python/name:", lambda loader, suffix, node: None)


def _nav_pages(entries: Any) -> Iterator[str]:
    if isinstance(entries, str):
        yield entries
    elif isinstance(entries, list):
        for entry in entries:
            yield from _nav_pages(entry)
    elif isinstance(entries, dict):
        for value in entries.values():
            yield from _nav_pages(value)


def test_every_documentation_page_is_reachable_from_the_site_navigation() -> None:
    """A page missing from the nav is built but unreachable on the published site."""
    config = yaml.load(_read(ROOT / "mkdocs.yml"), Loader=_MkDocsLoader)  # a SafeLoader subclass
    listed = set(_nav_pages(config["nav"]))
    pages = {path.relative_to(ROOT / "docs").as_posix() for path in (ROOT / "docs").rglob("*.md")}
    assert not pages - listed, f"docs pages missing from the mkdocs nav: {sorted(pages - listed)}"
    assert not listed - pages, f"mkdocs nav entries without a page: {sorted(listed - pages)}"


# --- Community profile ---------------------------------------------------------


@pytest.mark.parametrize("name", COMMUNITY_FILES)
def test_community_file_exists_with_content(name: str) -> None:
    path = ROOT / name
    assert path.is_file(), f"{name} is missing"
    assert path.stat().st_size > 0, f"{name} is empty"


def test_security_policy_has_the_sections_reporters_expect() -> None:
    anchors = _anchors(ROOT / "SECURITY.md")
    for anchor in ("trust-boundary", "supported-versions", "reporting"):
        assert anchor in anchors, f"SECURITY.md lacks a '{anchor}' heading"
    assert ADVISORY_URL in _read(ROOT / "SECURITY.md")


@pytest.mark.parametrize(
    "name", ["SECURITY.md", "SUPPORT.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "MAINTAINERS.md"]
)
def test_private_reporting_channel_is_reachable_from_every_entry_point(name: str) -> None:
    text = _read(ROOT / name)
    assert ADVISORY_URL in text or "SECURITY.md#reporting" in text, (
        f"{name} must link the private advisory form or the SECURITY.md reporting section"
    )


@pytest.mark.parametrize("name", ["README.md", "CONTRIBUTING.md", "SUPPORT.md", "GOVERNANCE.md"])
def test_code_of_conduct_is_linked_from_entry_points(name: str) -> None:
    assert "CODE_OF_CONDUCT.md" in _read(ROOT / name), f"{name} must link the code of conduct"


def test_code_of_conduct_is_the_contributor_covenant_with_a_reporting_route() -> None:
    text = _read(ROOT / "CODE_OF_CONDUCT.md")
    assert "Contributor Covenant" in text
    assert "reporting-a-concern" in _anchors(ROOT / "CODE_OF_CONDUCT.md"), (
        "SUPPORT.md deep-links this heading"
    )
    assert ADVISORY_URL in text


def test_citation_matches_the_package_metadata() -> None:
    citation = _load_yaml(ROOT / "CITATION.cff")
    project = _pyproject()["project"]
    assert citation["version"] == project["version"]
    license = project["license"]
    assert citation["license"] == (license if isinstance(license, str) else license["text"])
    assert citation["repository-code"] == project["urls"]["Repository"]
    assert citation["url"] == project["urls"]["Documentation"]


def test_codeowners_paths_exist() -> None:
    for line in _read(ROOT / "CODEOWNERS").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pattern = line.split()[0]
        if pattern != "*":
            assert (ROOT / pattern.strip("/")).exists(), f"CODEOWNERS names {pattern}, which does not exist"


# --- CI, tooling and supply-chain parity --------------------------------------


def _ci_run_lines() -> list[str]:
    lines: list[str] = []
    for job in (_load_yaml(GITHUB / "workflows" / "ci.yml").get("jobs") or {}).values():
        for step in job.get("steps") or []:
            script = step.get("run")
            if isinstance(script, str):
                lines.extend(line.strip() for line in script.splitlines())
    return lines


def _first_tool_arguments(lines: list[str], tool: str) -> set[str]:
    for line in lines:
        if line.startswith(f"{tool} "):
            return set(line.split()[1:])
    raise AssertionError(f"no {tool} invocation found")


def test_ci_matrix_covers_every_classified_python_version() -> None:
    ci = _load_yaml(GITHUB / "workflows" / "ci.yml")
    matrix = {str(version) for version in ci["jobs"]["test"]["strategy"]["matrix"]["python"]}
    classified = {
        classifier.rsplit("::", 1)[1].strip()
        for classifier in _pyproject()["project"]["classifiers"]
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", classifier)
    }
    assert matrix == classified, f"CI tests {sorted(matrix)} but pyproject classifies {sorted(classified)}"


def test_distribution_rename_preserves_cli_and_plugin_contract() -> None:
    project = _pyproject()["project"]
    assert project["name"] == "project-nexus-shadowscan"
    assert project["scripts"] == {"shadowscan": "shadowscan.cli:main"}
    assert "shadowscan.connectors" in project["entry-points"]
    assert project["optional-dependencies"]["all"] == [f"{project['name']}[cloud,dev,docs]"]
    for path in (
        ROOT / "docs/getting-started/install.md",
        ROOT / "examples/github-action-code-scan.yml",
        ROOT / "Makefile",
        GITHUB / "workflows/ci.yml",
        GITHUB / "workflows/release.yml",
    ):
        text = _read(path)
        assert "project_nexus_shadowscan-*.whl" in text
        assert "/shadowscan-*.whl" not in text


def test_makefile_lint_and_typecheck_paths_match_ci() -> None:
    ci = _ci_run_lines()
    makefile = [line.strip() for line in _read(ROOT / "Makefile").splitlines()]
    assert _first_tool_arguments(makefile, "mypy") == _first_tool_arguments(ci, "mypy"), (
        "make typecheck drifted from CI"
    )
    ci_ruff = {arg for arg in _first_tool_arguments(ci, "ruff") if arg != "check"}
    make_ruff = {arg for arg in _first_tool_arguments(makefile, "ruff") if arg != "check"}
    assert make_ruff == ci_ruff, "make lint drifted from CI"


@pytest.mark.parametrize("target", ["wheel-validate", "coverage-gate"])
@pytest.mark.parametrize("fails", [False, True])
def test_make_validation_uses_private_temporary_paths_and_always_cleans_up(
    tmp_path: Path, target: str, fails: bool
) -> None:
    """Execute the actual recipe while stubbing costly package/coverage tools."""
    make = shutil.which("make")
    assert make is not None
    source = tmp_path / "checkout"
    source.mkdir()
    shutil.copyfile(ROOT / "Makefile", source / "Makefile")
    (source / "dist").mkdir()
    (source / "dist/project_nexus_shadowscan-0.1.1-py3-none-any.whl").touch()
    scratch = tmp_path / "temporary files"
    scratch.mkdir()
    # Another run's directory must remain untouched, even when validation fails.
    previous = scratch / "shadowscan-wheel-test"
    previous.mkdir()
    sentinel = previous / "retain"
    sentinel.write_text("another developer's environment", encoding="utf-8")
    binary = tmp_path / "bin"
    binary.mkdir()
    shim = binary / "python"
    shim.write_text(
        textwrap.dedent("""\
            #!/bin/bash
            set -euo pipefail
            if [ "${1:-}" = -m ] && [ "${2:-}" = venv ]; then
                printf '%s\\n' "$3" >> "$TOOL_LOG"
                mkdir -p "$3/bin"
                cp "$0" "$3/bin/python"
                cp "$0" "$3/bin/shadowscan"
            elif [ "${2:-}" = coverage ]; then
                printf '%s\\n' "$5" >> "$TOOL_LOG"
                printf '{}\\n' > "$5"
            fi
            if [ "${2:-}" = "$FAIL_MODULE" ]; then exit 9; fi
            """),
        encoding="utf-8",
    )
    shim.chmod(0o700)
    log = tmp_path / "tool.log"
    module = "shadowscan.signatures.validate" if target == "wheel-validate" else "tools.coverage_gate"
    result = subprocess.run(
        [make, "--no-print-directory", "-o", "build", target],
        cwd=source,
        env={
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "TMPDIR": str(scratch),
            "TOOL_LOG": str(log),
            "FAIL_MODULE": module if fails else "never",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode != 0) is fails, result.stdout + result.stderr
    paths = [Path(path) for path in log.read_text(encoding="utf-8").splitlines()]
    assert len(paths) == 1
    # The wheel recipe builds its environment inside a private directory; the
    # coverage recipe writes a private file.
    private = paths[0].parent if target == "wheel-validate" else paths[0]
    assert private.parent == scratch
    assert private != previous
    assert not private.exists(), "temporary validation artifacts survive completion"
    assert sentinel.read_text(encoding="utf-8") == "another developer's environment"


def test_make_wheel_validation_rejects_stale_multiple_wheels(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    shutil.copyfile(ROOT / "Makefile", tmp_path / "Makefile")
    wheels = tmp_path / "dist"
    wheels.mkdir()
    for version in ("0.1.0", "0.1.1"):
        (wheels / f"project_nexus_shadowscan-{version}-py3-none-any.whl").touch()
    result = subprocess.run(
        [make, "--no-print-directory", "-o", "build", "wheel-validate"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "requires exactly one scanner wheel" in result.stderr


def test_makefile_evaluates_the_same_corpora_as_ci() -> None:
    ci_corpora = set(re.findall(r"--corpus (\S+)", "\n".join(_ci_run_lines())))
    make_corpora = set(re.findall(r"--corpus (\S+)", _read(ROOT / "Makefile")))
    assert make_corpora == ci_corpora, (
        f"make evaluate runs {sorted(make_corpora)} but CI runs {sorted(ci_corpora)}"
    )
    for corpus in ci_corpora:
        assert (ROOT / corpus).is_file(), f"CI references a missing corpus {corpus}"


def _lock_audit_loop(text: str) -> str:
    """The `for lock in ...; do pip-audit ...; done` loop, without shell and make syntax."""
    flat = " ".join(text.replace("\\\n", " ").replace("$$", "$").replace(";", " ").split())
    match = re.search(r"for lock in .*? done", flat)
    assert match is not None, "no lock audit loop found"
    return match.group()


def test_make_audit_checks_the_environment_and_every_lock_like_ci() -> None:
    """`make check` must not pass while CI's audit of the hash locks fails."""
    makefile = _read(ROOT / "Makefile")
    recipe = makefile.split("\naudit:", 1)[1].split("\n.PHONY", 1)[0]
    ci_script = "\n".join(_ci_run_lines())
    for command in ("pip-audit --skip-editable --progress-spinner off",):
        assert command in recipe and command in ci_script
    assert _lock_audit_loop(recipe) == _lock_audit_loop(ci_script)
    locks = re.search(r"for lock in (.*?) do", _lock_audit_loop(recipe))
    assert locks is not None
    assert set(locks.group(1).split()) == {path.name for path in ROOT.glob("requirements*.lock")}
    assert "set -e; for lock in" in recipe, "the first failing lock must fail make audit"


def test_changelog_has_no_relative_links() -> None:
    """The docs site includes CHANGELOG.md from docs/changelog.md, so a relative link breaks one rendering."""
    prose = re.sub(r"`[^`\n]*`", "", _read(ROOT / "CHANGELOG.md"))  # code spans show link syntax, not links
    links = re.findall(r"\]\((?!https?://|mailto:|#)([^)\s]+)\)", prose)
    assert not links, f"name the file in a code span instead of linking it: {sorted(set(links))}"


def test_make_secrets_runs_the_ci_credential_check_and_is_part_of_make_check() -> None:
    """The credential hook only protects a commit if the local gate runs what CI runs."""
    makefile = _read(ROOT / "Makefile")
    command = "git ls-files -z | xargs -0 python tools/check_secrets.py"
    recipe = makefile.split("\nsecrets:", 1)[1].split("\n.PHONY", 1)[0]
    assert command in recipe
    assert command in "\n".join(_ci_run_lines())
    check = re.search(r"^check:(.*?)##", makefile, re.M)
    assert check is not None and "secrets" in check.group(1).split()


def test_pre_commit_hooks_are_immutable_and_match_ci_versions() -> None:
    config_text = _read(ROOT / ".pre-commit-config.yaml")
    revisions = {
        match.group("name"): (match.group("sha"), match.group("version"))
        for match in re.finditer(
            r"^  - repo: https://github\.com/[^/]+/(?P<name>[\w-]+)\n"
            r"    rev: (?P<sha>[0-9a-f]{40}) # v(?P<version>\S+)$",
            config_text,
            re.MULTILINE,
        )
    }
    assert {"pre-commit-hooks", "ruff-pre-commit", "mirrors-mypy"} <= revisions.keys()
    assert all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha, _ in revisions.values())
    constraints = dict(
        re.findall(
            r"^([A-Za-z0-9_.-]+)==(\S+)$", _read(ROOT / "requirements-ci-constraints.txt"), re.MULTILINE
        )
    )
    assert revisions["ruff-pre-commit"][1] == constraints["ruff"], (
        "pre-commit ruff version differs from the CI pin"
    )
    assert revisions["mirrors-mypy"][1] == constraints["mypy"], (
        "pre-commit mypy version differs from the CI pin"
    )
    for package in ("types-PyYAML", "types-requests"):
        pin = f"{package}=={constraints[package]}"
        assert pin in config_text, f"pre-commit additional dependency is not pinned: {package}"
    runtime = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", _read(ROOT / "requirements.lock"), re.MULTILINE))
    assert f"click=={runtime['click']}" in config_text, (
        "pre-commit mypy must type-check against the locked click version"
    )


def test_docs_toolchain_is_hash_locked_everywhere_it_is_installed() -> None:
    lock = _read(ROOT / "requirements-docs.lock")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock, re.MULTILINE)
    assert pins, "requirements-docs.lock has no pins"
    assert lock.count("--hash=sha256:") >= len(pins), "every docs dependency needs at least one hash"
    locked = {name.lower(): version for name, version in pins}
    for requirement in _pyproject()["project"]["optional-dependencies"]["docs"]:
        name, _, floor = requirement.partition(">=")
        # The lock pins the distribution; an extra ("mkdocstrings[python]")
        # names its handler, locked under its own name.
        name = name.partition("[")[0]
        assert locked.get(name.lower()) == floor, f"{requirement} and requirements-docs.lock disagree"
    install = "--require-hashes --only-binary=:all: -r requirements-docs.lock"
    for workflow in ("docs.yml", "ci.yml"):
        assert install in _read(GITHUB / "workflows" / workflow), (
            f"{workflow} must install docs tools from the lock"
        )
    assert install in _read(ROOT / "Makefile"), "make docs must install docs tools from the lock"
    for workflow in WORKFLOWS:
        assert "mkdocs-material==" not in _read(workflow), f"{workflow.name} pins mkdocs outside the lock"


@pytest.mark.parametrize(
    "left,right",
    tuple(
        itertools.combinations(
            (
                "requirements.lock",
                "requirements-build.lock",
                "requirements-ci.lock",
                "requirements-docs.lock",
            ),
            2,
        )
    ),
)
def test_combined_toolchain_locks_agree_on_shared_versions(left: str, right: str) -> None:
    # make install and CI combine these locks. Independently valid locks can
    # otherwise make the documented hash-locked install impossible to resolve.
    locks = []
    for filename in (left, right):
        pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", _read(ROOT / filename), re.MULTILINE)
        locks.append({re.sub(r"[-_.]+", "-", name).lower(): version for name, version in pins})
    for package in sorted(locks[0].keys() & locks[1].keys()):
        assert locks[0][package] == locks[1][package], f"{package}: {left} and {right} have conflicting pins"


def test_ci_toolchain_is_exactly_pinned_and_hash_locked_everywhere() -> None:
    lock = _read(ROOT / "requirements-ci.lock")
    locked = {
        name.lower().replace("_", "-").replace(".", "-"): version
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock, re.MULTILINE)
    }
    assert locked, "requirements-ci.lock has no pins"
    assert lock.count("--hash=sha256:") >= len(locked), "every CI dependency needs at least one hash"
    constraints = {
        name.lower().replace("_", "-").replace(".", "-"): version
        for name, version in re.findall(
            r"^([A-Za-z0-9_.-]+)==([^\s;]+)(?:\s*;.*)?$",
            _read(ROOT / "requirements-ci-constraints.txt"),
            re.MULTILINE,
        )
    }
    assert constraints.items() <= locked.items(), "CI lock drifted from its reviewed direct constraints"
    for requirement in (
        _pyproject()["project"]["dependencies"] + _pyproject()["project"]["optional-dependencies"]["dev"]
    ):
        name = re.split(r"[<>=!\[; ]", requirement, maxsplit=1)[0]
        normalized = name.lower().replace("_", "-").replace(".", "-")
        assert normalized in locked, f"CI lock omits direct requirement {requirement}"
    install = "--require-hashes --only-binary=:all: -r requirements-ci.lock"
    assert install in _read(ROOT / "Makefile")
    assert install in _read(GITHUB / "workflows" / "ci.yml")
    assert "-r requirements-ci.lock" in _read(GITHUB / "workflows" / "release.yml")


_USES_LINE = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>[^#\s]+)\s*(?P<comment>#.*)?$")
_PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@(?P<sha>[0-9a-f]{40})$")


@pytest.mark.parametrize("example", sorted((ROOT / "examples").glob("*.yml")), ids=lambda path: path.name)
def test_example_workflows_pin_actions_to_commit_shas(example: Path) -> None:
    """Consumer examples are copied verbatim, so every action they use is pinned like the workflows."""
    problems: list[str] = []
    for number, line in enumerate(_read(example).splitlines(), start=1):
        match = _USES_LINE.match(line)
        if match is None:
            continue
        ref = match.group("ref").strip("'\"")
        if not _PINNED.match(ref):
            problems.append(f"line {number}: {ref} is not pinned to a 40-character commit SHA")
        if not re.search(r"#\s*v?\d", match.group("comment") or ""):
            problems.append(f"line {number}: {ref} needs a version comment")
    assert not problems, f"{_relative(example)}:\n  " + "\n  ".join(problems)


def test_example_action_pins_match_the_repository_workflows() -> None:
    """An action pinned in both places must point at the same commit."""

    def pins(paths):
        found: dict[str, set[str]] = {}
        for path in paths:
            for line in _read(path).splitlines():
                match = _USES_LINE.match(line)
                if match is None:
                    continue
                name, _, sha = match.group("ref").partition("@")
                found.setdefault(name, set()).add(sha)
        return found

    repository = pins(WORKFLOWS)
    for name, shas in pins(sorted((ROOT / "examples").glob("*.yml"))).items():
        if name in repository:
            assert shas <= repository[name], (
                f"examples pin {name} to {sorted(shas)} but workflows use {sorted(repository[name])}"
            )


def test_dependabot_moves_the_example_action_pins_with_the_workflows() -> None:
    """One grouped update covers both, so the pin-equality test above does not fail every bump."""
    updates = _load_yaml(GITHUB / "dependabot.yml")["updates"]
    (actions,) = [update for update in updates if update["package-ecosystem"] == "github-actions"]
    assert {"/", "/examples"} <= set(actions.get("directories") or [actions.get("directory")])
    assert any(group.get("patterns") == ["*"] for group in actions["groups"].values())


def test_example_workflow_runs_python_modules_outside_the_scanned_checkout() -> None:
    """``python -m`` imports from its working directory first, and the example scans untrusted code."""
    workflow = _load_yaml(ROOT / "examples" / "github-action-code-scan.yml")
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    modules = [step for step in steps if re.search(r"\bpython3? -m\b", step.get("run", ""))]
    assert modules, "the example should install and validate the scanner with python -m"
    for step in modules:
        assert step.get("working-directory") == "${{ runner.temp }}", (
            f"step {step.get('name')!r} runs `python -m` inside the scanned checkout"
        )


def test_secret_check_runs_on_the_same_files_in_the_hook_and_ci() -> None:
    """The script owns its exclusions, so the hook and CI cannot drift apart."""
    hooks = {
        hook["id"]: hook
        for repo in _load_yaml(ROOT / ".pre-commit-config.yaml")["repos"]
        for hook in repo.get("hooks", [])
    }
    hook = hooks["no-hardcoded-secrets"]
    assert hook["entry"] == "python tools/check_secrets.py"
    assert hook.get("types") == ["text"], "the hook must scan every text file"
    assert not {"exclude", "files", "types_or"} & hook.keys(), "exclusions belong in the script"
    steps = [
        step
        for job in _load_yaml(GITHUB / "workflows" / "ci.yml")["jobs"].values()
        for step in job.get("steps") or []
        if "tools/check_secrets.py" in str(step.get("run", ""))
    ]
    assert len(steps) == 1, "CI must run the secret check exactly once per test job"
    lines = [line.strip() for line in steps[0]["run"].splitlines()]
    assert lines[0] == "set -euo pipefail", "a failed `git ls-files` must fail the step"
    assert "git ls-files -z | xargs -0 python tools/check_secrets.py" in lines


def test_pre_commit_hooks_select_files_with_types_or() -> None:
    """`types` is an AND filter; a hook listing two types would never run."""
    config = _load_yaml(ROOT / ".pre-commit-config.yaml")
    for repo in config["repos"]:
        for hook in repo.get("hooks", []):
            types = hook.get("types") or []
            assert len(types) <= 1, f"hook {hook['id']} lists {types} under `types`; use `types_or`"


def test_blind_except_suppressions_give_a_reason() -> None:
    """Every suppressed broad `except` (ruff BLE001) states why it is intentional."""
    bare = [
        f"{path.relative_to(ROOT)}:{number}"
        for directory in ("shadowscan", "tools", "tests")
        for path in sorted((ROOT / directory).rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if re.search(r"#\s*noqa:\s*BLE001(?!\s+-\s+\S)", line)
    ]
    assert not bare, f"write `# noqa: BLE001 - <reason>`: {bare}"


def test_dev_extra_is_fully_pinned_for_ci() -> None:
    """Every development dependency must occur in a hash-locked CI input."""
    pinned = {
        name.lower().replace("_", "-")
        for text in (
            _read(ROOT / "requirements-ci.lock"),
            _read(ROOT / "requirements.lock"),
            _read(ROOT / "requirements-build.lock"),
        )
        for name in re.findall(r"^([A-Za-z0-9_.-]+)==", text, re.MULTILINE)
    }
    for requirement in _pyproject()["project"]["optional-dependencies"]["dev"]:
        name = re.split(r"[<>=!\[; ]", requirement, maxsplit=1)[0].lower().replace("_", "-")
        assert name in pinned, f"[dev] requirement {requirement} has no exact pin in the constraints or lock"


def test_codeql_action_steps_share_one_release() -> None:
    """init, analyze and upload-sarif must run the same CodeQL Action release."""
    pins: dict[str, set[str]] = {}
    for workflow in WORKFLOWS:
        for match in re.finditer(
            r"github/codeql-action/([\w-]+)@([0-9a-f]{40})\s*#\s*(v\S+)", _read(workflow)
        ):
            pins.setdefault(match.group(2), set()).add(f"{workflow.name}:{match.group(1)} {match.group(3)}")
    assert pins, "no CodeQL Action steps found"
    assert len(pins) == 1, "CodeQL Action steps are pinned to different releases: " + "; ".join(
        f"{sha[:12]} -> {sorted(uses)}" for sha, uses in pins.items()
    )


# --- Documented counts match the code -----------------------------------------

# A claim about the shipped total: a signature count stated with its signal
# count ("215 signatures / 1001 signals", "178 signatures, 790 signals"), or
# one stated as the whole set ("all 212 signatures", "ships 215 signatures",
# "215 built-in signatures"). Other prose may count a subset ("two packs add
# 12 signatures") without claiming the total. Matching runs on text with its
# whitespace collapsed, so a claim wrapped across lines is still found.
_NUMBER = r"(\d[\d,]*)"
_PAIRED_SIGNATURE_CLAIM = re.compile(rf"\b{_NUMBER} signatures ?(?:/|,|and) ?{_NUMBER} signals\b")
_TOTAL_SIGNATURE_CLAIM = re.compile(
    rf"\b(?:all|ships|ship|bundles|includes) {_NUMBER} signatures\b"
    rf"|\b{_NUMBER} (?:bundled|built-in|shipped) signatures\b"
)
_CONNECTOR_CLAIM = re.compile(r"\*\*(\d+) connectors\*\*")


def _count(text: str) -> int:
    return int(text.replace(",", ""))


def _signature_claims(text: str) -> list[tuple[int, int | None]]:
    """``(signatures, signals or None)`` for every total-count claim in a document."""
    text = " ".join(text.split())
    claims: list[tuple[int, int | None]] = [
        (_count(match.group(1)), _count(match.group(2))) for match in _PAIRED_SIGNATURE_CLAIM.finditer(text)
    ]
    for match in _TOTAL_SIGNATURE_CLAIM.finditer(text):
        claims.append((_count(match.group(1) or match.group(2)), None))
    return claims


@pytest.mark.parametrize(
    "text,claims",
    [
        ("215 signatures / 1001 signals, YAML-defined", [(215, 1001)]),
        ("signature validation (178\n  signatures, 790 signals)", [(178, 790)]),
        ("216 signatures and 1,001 signals", [(216, 1001)]),
        ("shadowscan signatures list   # show all 212 signatures", [(212, None)]),
        ("ShadowScan ships 215\nsignatures / 1001 signals.", [(215, 1001), (215, None)]),
        ("the 215 built-in signatures", [(215, None)]),
        ("two packs add 12 signatures; 3 signatures share one prefix", []),
        ("the validator rejected 2 signatures", []),
    ],
)
def test_signature_count_claims_are_recognised(text: str, claims: list[tuple[int, int | None]]) -> None:
    assert _signature_claims(text) == claims


# Root documents that describe the current tree. The site includes RELEASE_NOTES.md, SECURITY.md and
# GOVERNANCE.md as snippets, so a stale number there is published too. CHANGELOG.md is a dated log
# that quotes earlier counts and is left out.
_CURRENT_ROOT_DOCS = ("README.md", "RELEASE_NOTES.md", "SECURITY.md", "GOVERNANCE.md", "CONTRIBUTING.md")


def _current_docs() -> list[Path]:
    """Documents that describe the current tree; dated review logs may quote old numbers."""
    return [
        path
        for path in [*(ROOT / name for name in _CURRENT_ROOT_DOCS), *sorted((ROOT / "docs").rglob("*.md"))]
        if "hardening-logs" not in path.parts and not re.search(r"review-\d{4}-\d{2}-\d{2}", path.name)
    ]


def test_documented_signature_counts_match_the_shipped_packs(index) -> None:
    signatures = list(index.signatures.values())
    actual = (len(signatures), sum(len(signature.signals) for signature in signatures))
    claims = [(path, claim) for path in _current_docs() for claim in _signature_claims(_read(path))]
    assert any(path.name == "README.md" and signals is not None for path, (_, signals) in claims), (
        "README should state the signature and signal counts"
    )
    for path, (count, signals) in claims:
        assert count == actual[0] and signals in (None, actual[1]), (
            f"{_relative(path)} claims {count} signatures"
            + (f" / {signals} signals" if signals is not None else "")
            + f"; packs ship {actual[0]} / {actual[1]}. Describe a subset without "
            "'all', 'ships' or 'built-in' if it is not the shipped total."
        )


def test_documented_connector_counts_match_the_registry() -> None:
    actual = len(builtin_connector_names())
    claims = [(path, match) for path in _current_docs() for match in _CONNECTOR_CLAIM.finditer(_read(path))]
    assert claims, "a doc should state the connector count in bold (**N connectors**)"
    for path, match in claims:
        assert int(match.group(1)) == actual, (
            f"{_relative(path)} claims {match.group(1)} connectors, registry has {actual}"
        )


# Connector configuration keys that may stay undocumented, each with a reason.
# Keep this empty unless a key is deliberately internal.
_UNDOCUMENTED_CONNECTOR_KEYS: dict[str, str] = {}


def test_every_connector_configuration_key_is_documented() -> None:
    """Every key `shadowscan connectors --json` lists is named in docs/connectors*.md."""
    docs = "\n".join(
        _read(path)
        for path in [ROOT / "docs" / "connectors.md", *sorted((ROOT / "docs" / "connectors").glob("*.md"))]
    )
    listed = set()
    missing = []
    for name in builtin_connector_names():
        connector = get_connector_class(name)
        for key in {**connector.config_keys, **connector.shared_config_keys}:
            listed.add(f"{name}.{key}")
            # Backticked as `key`, `key: value` or `key=value`.
            if f"{name}.{key}" not in _UNDOCUMENTED_CONNECTOR_KEYS and not re.search(
                rf"`{re.escape(key)}[`:= ]", docs
            ):
                missing.append(f"{name}.{key}")
    assert not missing, f"document these connector configuration keys in docs/connectors*.md: {missing}"
    assert _UNDOCUMENTED_CONNECTOR_KEYS.keys() <= listed, "stale undocumented-key exemptions"


def test_documented_realistic_corpus_file_range_matches_the_corpus() -> None:
    cases = json.loads(_read(ROOT / "tools" / "evaluation" / "realistic_corpus.json"))["cases"]
    counts = [len(case["files"]) for case in cases]
    match = re.search(
        r"snapshots \((\d+) to (\d+) files each\)", " ".join(_read(ROOT / "docs" / "evaluation.md").split())
    )
    assert match is not None, "docs/evaluation.md should state the realistic corpus file range"
    assert (int(match.group(1)), int(match.group(2))) == (min(counts), max(counts)), (
        f"docs/evaluation.md claims {match.group(0)!r}; the corpus has {min(counts)} to {max(counts)} files per case"
    )


def _gcp_pagination(index) -> dict[str, int]:
    """The page limits the GCP connector applies, measured by paging until it stops.

    Every response offers a fresh page token, so each paginated call runs to the
    connector's own cap. Nothing leaves the process: the transport is a stub.
    """
    connector = GcpConnector(ConnectorContext(config={"max_pages": 1_000_000}, index=index))
    connector.ctx.stats = ScanStats(connector="cloud.gcp", started_at="2026-01-01T00:00:00Z")
    tokens = itertools.count()
    connector._get = Mock(
        side_effect=lambda url, **params: {"items": [], "nextPageToken": f"t{next(tokens)}"}
    )
    list(connector._pages("https://compute.googleapis.com/compute/v1/projects", "items"))
    connector.http = Mock()
    connector.http.post_json.side_effect = lambda url, json: {
        "entries": [],
        "nextPageToken": f"t{next(tokens)}",
    }
    list(connector._collect_audit("demo"))
    default = GcpConnector(ConnectorContext(config={}, index=index)).max_pages
    return {
        "default": default,
        "lists": connector._get.call_count,
        "audit": connector.http.post_json.call_count,
    }


def test_documented_gcp_pagination_caps_match_the_connector(index) -> None:
    """Both GCP pages and the connector's own help state the caps it applies.

    Regression for a real fork: docs/connectors/cloud.md once dropped the caps
    sentence that docs/connectors.md still carried, understating GCP's
    collection limits on the page the site navigation links to.
    """
    pages = _gcp_pagination(index)
    caps = (
        f"resource lists stop at {pages['lists']} pages and "
        f"audit-log queries at {pages['audit']} pages regardless"
    )
    # Every connector caps max_pages at MAX_PAGES; the docs state both bounds.
    bounds = (
        f"default and maximum {MAX_PAGES}"
        if pages["default"] == MAX_PAGES
        else f"default {pages['default']}, maximum {MAX_PAGES}"
    )
    default = f"`max_pages` ({bounds})"
    for path in (ROOT / "docs" / "connectors.md", ROOT / "docs" / "connectors" / "cloud.md"):
        assert any(default in text and caps in text for text in _paragraphs(path)), (
            f"{_relative(path)} must say in one paragraph that {default} applies and that {caps}"
        )
    help_text = " ".join(GcpConnector.config_keys["max_pages"].split())
    assert f"capped at {MAX_PAGES}" in help_text and f"default {pages['default']}" in help_text
    assert caps in help_text


# --- Documented report and transport behaviour matches the code --------------

# How the documents name each character after which the CSV reporter can put a
# formula marker inside a cell.
_CSV_SEPARATOR_NAMES = {
    ",": "`,`",
    ";": "`;`",
    "|": "`|`",
    "\t": "tab",
    "\n": "line break",
    "\r": "line break",
}
_READ_DEADLINE_CLAIM = re.compile(r"within (\w+) the client timeout \((\d+) seconds by default\)")
_READ_DEADLINE_FACTORS = {"twice": 2}


def _paragraphs(path: Path) -> list[str]:
    """Blank-line separated blocks of a document, each on one line."""
    return [" ".join(block.split()) for block in re.split(r"\n[ \t]*\n", _read(path))]


def test_documented_csv_markers_match_the_reporter() -> None:
    # Consumers strip the markers the documents describe. A consumer told only
    # about a leading marker corrupts every value with a marker inside it.
    candidates = [chr(code) for code in range(1, 128)] + ["\x85", "\xa0", "\u2028", "\u2029"]
    # A control character is rendered visibly in the cell; only a "'" before
    # the formula marks it.
    inside = {sep for sep in candidates if _safe_cell(f"a{sep}=1") == f"a{sep}'=1"}
    assert inside, "the CSV reporter no longer marks a formula inside a cell; update this test"
    unnamed = inside - _CSV_SEPARATOR_NAMES.keys()
    assert not unnamed, f"name {sorted(unnamed)!r} here and in the CSV documentation"
    names = sorted({_CSV_SEPARATOR_NAMES[sep] for sep in inside})
    claims = [
        (path, paragraph)
        for path in _current_docs()
        for paragraph in _paragraphs(path)
        if "csv" in paragraph.lower() and "`'`" in paragraph
    ]
    assert any(path.name == "README.md" for path, _ in claims), "README should describe the CSV markers"
    for path, paragraph in claims:
        missing = [name for name in names if name not in paragraph]
        assert not missing, f"{_relative(path)} describes CSV markers without the separators {missing}"


def test_documented_http_read_deadline_matches_the_client() -> None:
    claims = [
        (path, match)
        for path in _current_docs()
        for paragraph in _paragraphs(path)
        for match in _READ_DEADLINE_CLAIM.finditer(paragraph)
    ]
    assert any(path.name == "SECURITY.md" for path, _ in claims), "SECURITY.md should state the read deadline"
    expected = (http.READ_DEADLINE_FACTOR, http.DEFAULT_TIMEOUT * http.READ_DEADLINE_FACTOR)
    for path, match in claims:
        claimed = (_READ_DEADLINE_FACTORS.get(match.group(1)), int(match.group(2)))
        assert claimed == expected, f"{_relative(path)} says {match.group(0)!r}; the client uses {expected}"


_FIXTURE_CLAIM = re.compile(r"(\d+) of (\d+) connectors ship fixtures")


def test_documented_fixture_connector_count_matches_the_demo_configuration() -> None:
    demo = yaml.safe_load((ROOT / "examples" / "shadowscan.offline.yaml").read_text(encoding="utf-8"))
    configured = {entry["name"] for entry in demo["connectors"]}
    assert configured <= set(builtin_connector_names())
    actual = (len(configured), len(builtin_connector_names()))
    claims = [(path, match) for path in _current_docs() for match in _FIXTURE_CLAIM.finditer(_read(path))]
    assert claims, "the README should state how many connectors the offline demo covers"
    for path, match in claims:
        claimed = (int(match.group(1)), int(match.group(2)))
        assert claimed == actual, f"{_relative(path)} claims {claimed}, the demo configures {actual}"


_DEMO_COMMAND = "$ shadowscan scan -c examples/shadowscan.offline.yaml --max-rows "
_DEMO_TOTALS = re.compile(r"(\d+) findings  •  (\d+) shadow \(inventory: (\d+) registered agents\)")
_DEMO_LEVELS = re.compile(r"\b(critical|high|medium|low|info) (\d+)\b")
_DEMO_SURFACES = re.compile(r"\b(cloud|code|gateway|identity|lowcode|saas) (\d+)\b")
_DEMO_ROW = re.compile(r"^ ([A-Z]+) +(\d+)  (\S+) +(\S+) +(\S+) +(.+?)\s*$", re.MULTILINE)


def test_readme_demo_output_matches_the_offline_demo(index) -> None:
    """The README's abridged example is the current result of the bundled offline demo."""
    readme = _read(ROOT / "README.md")
    start = readme.index(_DEMO_COMMAND)
    block = readme[start : readme.index("```", start)]
    max_rows = int(block[len(_DEMO_COMMAND) :].split(None, 1)[0])
    header, _, table = block.partition("╰")
    totals = _DEMO_TOTALS.search(header)
    assert totals, "the README demo output should state the totals line"
    result = Engine(ScanConfig.from_yaml(ROOT / "examples" / "shadowscan.offline.yaml"), index).run()
    findings = result.findings
    assert tuple(map(int, totals.groups())) == (
        len(findings),
        sum(1 for f in findings if f.shadow),
        result.inventory_size,
    ), "README demo totals are stale; rerun the command it shows"
    levels = Counter(f.risk.level.value for f in findings)
    surfaces = Counter(f.surface.value for f in findings)
    # The header is abridged: every number it shows must be current, not every number must be shown.
    for name, count in _DEMO_LEVELS.findall(header):
        assert levels[name] == int(count), f"README demo shows {name} {count}; the demo has {levels[name]}"
    for name, count in _DEMO_SURFACES.findall(header):
        assert surfaces[name] == int(count), (
            f"README demo shows {name} {count}; the demo has {surfaces[name]}"
        )
    expected = [
        (
            f.risk.level.value.upper(),
            f.risk.score,
            "SHADOW" if f.shadow else f.registry_match,
            f.surface.value,
            f.kind.value,
            f.title,
        )
        for f in findings[:max_rows]
    ]
    shown = [(lvl, int(score), *rest) for lvl, score, *rest in _DEMO_ROW.findall(table)]
    assert shown == expected, "README demo rows are stale; rerun the command it shows"


def test_connector_configuration_reference_is_current() -> None:
    """docs/connectors/reference.md is generated from every built-in connector's keys."""
    from tools.connector_reference import REFERENCE, render

    assert REFERENCE.read_text(encoding="utf-8") == render(), (
        "docs/connectors/reference.md is stale; run `make connector-reference`"
    )
