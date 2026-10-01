"""Declared names in direct requirements take precedence over URL guesses."""

from __future__ import annotations

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.manifests import parse_requirements
from shadowscan.engine import Engine
from shadowscan.models import Kind

DIRECT_REQUIREMENTS = [
    "crewai @ https://example.org/artifacts/package.whl",
    "crewai[tools] @ https://example.org/artifacts/package.whl#sha256=012345 ; python_version >= '3.11'",
    "crewai [tools, telemetry] @ git+https://example.org/acme/unrelated.git@main#subdirectory=src ; sys_platform == 'linux'",
    "crewai @ git+ssh://git@example.org/acme/unrelated.git@main#egg=langgraph",
    "crewai@file:///workspace/packages/unrelated.whl",
    "crewai @ ../packages/unrelated.whl",
]


@pytest.mark.parametrize("requirement", DIRECT_REQUIREMENTS)
def test_named_direct_ref_preserves_declared_name_spec_and_source_line(requirement):
    result = parse_requirements(f"# ignored comment\n\n  {requirement}  \n")

    assert not result.errors
    assert [(dep.ecosystem, dep.name, dep.spec, dep.line) for dep in result.deps] == [
        ("pypi", "crewai", requirement, 3)
    ]


@pytest.mark.parametrize(
    ("requirement", "name", "spec"),
    [
        ("requests>=2.0 # explanatory comment", "requests", ">=2.0"),
        (
            "langchain[community]>=0.3 ; python_version >= '3.11'",
            "langchain",
            ">=0.3 ; python_version >= '3.11'",
        ),
        (
            "git+https://example.org/acme/other.git#egg=crewai",
            "crewai",
            "git+https://example.org/acme/other.git#egg=crewai",
        ),
        (
            "-e git+https://example.org/acme/other.git@main#egg=langgraph",
            "langgraph",
            "git+https://example.org/acme/other.git@main#egg=langgraph",
        ),
        (
            "--editable git+ssh://git@example.org/acme/other.git#egg=crewai",
            "crewai",
            "git+ssh://git@example.org/acme/other.git#egg=crewai",
        ),
        (
            "git+https://example.org/acme/crewai.git@main",
            "crewai",
            "git+https://example.org/acme/crewai.git@main",
        ),
    ],
)
def test_plain_and_bare_vcs_requirements_keep_existing_behavior(requirement, name, spec):
    result = parse_requirements(requirement)

    assert not result.errors
    assert [(dep.name, dep.spec, dep.line) for dep in result.deps] == [(name, spec, 1)]


def test_comments_and_pip_options_are_not_dependencies():
    result = parse_requirements(
        "# crewai @ https://example.org/artifacts/package.whl\n"
        "--index-url https://example.org/crewai\n"
        "-r other-requirements.txt\n"
        "\n"
    )
    assert not result.deps and not result.errors


@pytest.mark.parametrize("entrypoint", ["filesystem", "engine"])
@pytest.mark.parametrize("requirement", DIRECT_REQUIREMENTS[:4])
def test_direct_requirement_is_discovered_with_manifest_evidence(tmp_path, index, entrypoint, requirement):
    (tmp_path / "requirements.txt").write_text(f"# sample project\n\n{requirement}\n", encoding="utf-8")
    config = {"path": str(tmp_path), "use_git": False}
    if entrypoint == "engine":
        result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", config)]), index).run()
        assert result.complete
        findings = result.findings
        stats = result.stats[0]
    else:
        ctx = ConnectorContext(config=config, index=index)
        findings = FilesystemConnector(ctx).run()
        stats = ctx.stats
        assert not stats.incomplete

    assert not stats.errors
    projects = [finding for finding in findings if finding.resource_type == "project"]
    assert len(projects) == 1
    project = projects[0]
    assert project.kind == Kind.FRAMEWORK_USAGE
    assert project.frameworks == ["framework.crewai"]
    assert project.metadata["dependencies_matched"] == ["pypi:crewai"]
    expected_snippet = f"pypi: crewai {requirement}".replace("git+ssh://git@", "git+ssh://[REDACTED]@")
    assert any(
        evidence.signal == "dependency:framework.crewai"
        and evidence.location == "requirements.txt:3"
        and evidence.snippet == expected_snippet
        for evidence in project.evidence
    )


@pytest.mark.parametrize(
    "requirement",
    [
        "requests @ https://example.org/acme/crewai.git",
        "requests @ git+https://example.org/acme/other.git#egg=crewai",
    ],
)
def test_url_basename_or_egg_cannot_override_unrelated_declared_name(tmp_path, index, requirement):
    parsed = parse_requirements(requirement)
    assert [(dep.name, dep.spec) for dep in parsed.deps] == [("requests", requirement)]
    (tmp_path / "requirements.txt").write_text(requirement + "\n", encoding="utf-8")

    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})]),
        index,
    ).run()

    assert result.complete
    assert not result.findings
