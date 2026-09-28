"""The documents, tooling and metadata stay consistent with each other and the code.

`test_repository_policy.py` guards workflow privileges and issue-form structure.
This module covers the rest of the repository's self-consistency: every relative
Markdown link and heading anchor resolves, the community files GitHub and the
OpenSSF Scorecard look for exist, `CITATION.cff` matches `pyproject.toml`, the
CI matrix matches the classifiers, the Makefile and pre-commit hooks run what CI
runs, every CodeQL action step is pinned to the same release, the docs toolchain
comes from its lock everywhere, and documented counts, CSV report markers and
the HTTP read deadline match the shipped code. Run both modules with
``make policy``.
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
from shadowscan.reporters.csv_ import _safe_cell
from shadowscan.utils import http

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
WORKFLOWS = sorted((GITHUB / "workflows").glob("*.yml"))
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


def test_makefile_evaluates_the_same_corpora_as_ci() -> None:
    ci_corpora = set(re.findall(r"--corpus (\S+)", "\n".join(_ci_run_lines())))
    make_corpora = set(re.findall(r"--corpus (\S+)", _read(ROOT / "Makefile")))
    assert make_corpora == ci_corpora, (
        f"make evaluate runs {sorted(make_corpora)} but CI runs {sorted(ci_corpora)}"
    )
    for corpus in ci_corpora:
        assert (ROOT / corpus).is_file(), f"CI references a missing corpus {corpus}"


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


def test_docs_toolchain_is_hash_locked_everywhere_it_is_installed() -> None:
    lock = _read(ROOT / "requirements-docs.lock")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock, re.MULTILINE)
    assert pins, "requirements-docs.lock has no pins"
    assert lock.count("--hash=sha256:") >= len(pins), "every docs dependency needs at least one hash"
    locked = {name.lower(): version for name, version in pins}
    for requirement in _pyproject()["project"]["optional-dependencies"]["docs"]:
        name, _, floor = requirement.partition(">=")
        assert locked.get(name.lower()) == floor, f"{requirement} and requirements-docs.lock disagree"
    install = "--require-hashes --only-binary=:all: -r requirements-docs.lock"
    for workflow in ("docs.yml", "ci.yml"):
        assert install in _read(GITHUB / "workflows" / workflow), (
            f"{workflow} must install docs tools from the lock"
        )
    assert install in _read(ROOT / "Makefile"), "make docs must install docs tools from the lock"
    for workflow in WORKFLOWS:
        assert "mkdocs-material==" not in _read(workflow), f"{workflow.name} pins mkdocs outside the lock"


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
    """Consumer examples are copied verbatim; Dependabot does not track examples/."""
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


def test_pre_commit_hooks_select_files_with_types_or() -> None:
    """`types` is an AND filter; a hook listing two types would never run."""
    config = _load_yaml(ROOT / ".pre-commit-config.yaml")
    for repo in config["repos"]:
        for hook in repo.get("hooks", []):
            types = hook.get("types") or []
            assert len(types) <= 1, f"hook {hook['id']} lists {types} under `types`; use `types_or`"


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

_COUNT_CLAIM = re.compile(r"(\d+) signatures / (\d+) signals")
_BARE_SIGNATURE_CLAIM = re.compile(r"\b(\d+) signatures\b")
_CONNECTOR_CLAIM = re.compile(r"\*\*(\d+) connectors\*\*")


def _current_docs() -> list[Path]:
    """Documents that describe the current tree; dated review logs may quote old numbers."""
    return [
        path
        for path in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
        if "hardening-logs" not in path.parts and not re.search(r"review-\d{4}-\d{2}-\d{2}", path.name)
    ]


def test_documented_signature_counts_match_the_shipped_packs(index) -> None:
    signatures = list(index.signatures.values())
    actual = (len(signatures), sum(len(signature.signals) for signature in signatures))
    claims = [(path, match) for path in _current_docs() for match in _COUNT_CLAIM.finditer(_read(path))]
    assert claims, "README should state the signature and signal counts"
    for path, match in claims:
        claimed = (int(match.group(1)), int(match.group(2)))
        assert claimed == actual, f"{_relative(path)} claims {claimed}, packs ship {actual}"
    for path in _current_docs():
        for _, line in _prose_lines(_read(path)):
            for match in _BARE_SIGNATURE_CLAIM.finditer(line):
                assert int(match.group(1)) == actual[0], (
                    f"{_relative(path)} says {match.group(0)}, packs ship {actual[0]}"
                )


def test_documented_connector_counts_match_the_registry() -> None:
    actual = len(builtin_connector_names())
    claims = [(path, match) for path in _current_docs() for match in _CONNECTOR_CLAIM.finditer(_read(path))]
    assert claims, "a doc should state the connector count in bold (**N connectors**)"
    for path, match in claims:
        assert int(match.group(1)) == actual, (
            f"{_relative(path)} claims {match.group(1)} connectors, registry has {actual}"
        )


def test_gcp_pagination_caps_are_not_dropped_from_the_per_surface_page() -> None:
    """Regression for a real fork: docs/connectors/cloud.md once dropped the
    max_pages / 500-page / 50-page-audit-log-cap sentence that docs/connectors.md
    still documents, understating GCP's collection limits on the page readers
    actually navigate to from the site nav.
    """
    canonical = _read(ROOT / "docs" / "connectors.md")
    per_surface = _read(ROOT / "docs" / "connectors" / "cloud.md")
    sentence = "resource lists stop at 500 pages and audit-log\nqueries at 50 pages regardless."
    assert sentence in canonical, "docs/connectors.md no longer documents the GCP pagination caps"
    assert sentence in per_surface, (
        "docs/connectors/cloud.md is missing the GCP pagination caps documented in docs/connectors.md"
    )


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
    inside = {sep for sep in candidates if _safe_cell(f"a{sep}=1") != f"a{sep}=1"}
    assert inside, "the CSV reporter no longer marks a formula inside a cell; update this test"
    unnamed = inside - _CSV_SEPARATOR_NAMES.keys()
    assert not unnamed, f"name {sorted(unnamed)!r} here and in the CSV documentation"
    names = sorted({_CSV_SEPARATOR_NAMES[sep] for sep in inside})
    claims = [
        (path, paragraph)
        for path in [ROOT / "SECURITY.md", *_current_docs()]
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
        for path in [ROOT / "SECURITY.md", *_current_docs()]
        for paragraph in _paragraphs(path)
        for match in _READ_DEADLINE_CLAIM.finditer(paragraph)
    ]
    assert any(path.name == "SECURITY.md" for path, _ in claims), "SECURITY.md should state the read deadline"
    expected = (http.READ_DEADLINE_FACTOR, http.DEFAULT_TIMEOUT * http.READ_DEADLINE_FACTOR)
    for path, match in claims:
        claimed = (_READ_DEADLINE_FACTORS.get(match.group(1)), int(match.group(2)))
        assert claimed == expected, f"{_relative(path)} says {match.group(0)!r}; the client uses {expected}"
