"""Regressions for code discovery, ownership and bounded enumeration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import _codeowners_match
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector, _GitLabMetadata
from shadowscan.connectors.code.manifests import parse_requirements
from shadowscan.models import Kind, ScanStats


def test_generic_server_urls_are_not_mcp_configs(tmp_path: Path, run_connector):
    (tmp_path / "settings.json").write_text(json.dumps({"servers": {"prod": {"url": "https://api.example.test"}}}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if f.kind == Kind.MCP_SERVER or "protocol.mcp" in f.frameworks]


def test_explicit_mcp_servers_remain_detected(tmp_path: Path, run_connector):
    (tmp_path / "mcp.json").write_text(json.dumps({"servers": {"prod": {"url": "https://api.example.test/mcp"}}}))
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    assert [f.metadata["servers"][0]["name"] for f in findings if f.kind == Kind.MCP_SERVER] == ["prod"]


def test_vcs_egg_fragments_and_editable_dependencies():
    result = parse_requirements(
        "git+https://github.com/acme/other.git#egg=crewai\n"
        "-e git+https://github.com/acme/other.git@main#egg=langgraph\n"
        "langchain>=0.3 # explanatory comment\n"
    )
    assert {(dep.name, dep.line) for dep in result.deps} == {
        ("crewai", 1), ("langgraph", 2), ("langchain", 3)
    }


def test_codeowners_globs_apply_to_evidence_files_in_last_match_order(tmp_path: Path, run_connector):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text(
        "* @default\n*.py @python\n/src/** @src\n/src/special.py @special\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "special.py").write_text("from langchain import agents\n")
    (tmp_path / "src" / "other.py").write_text("from langchain import agents\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner is None  # two evidence files have different owners
    assert project.metadata["codeowners_by_file"] == {
        "src/other.py": "@src",
        "src/special.py": "@special",
    }


def test_codeowners_basename_glob_owns_nested_source(tmp_path: Path, run_connector):
    (tmp_path / "CODEOWNERS").write_text("*.py @python\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "agent.py").write_text("from langchain import agents\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner == "@python"


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("/docs/", "docs/guides/start.md", True),
        ("/docs/", "nested/docs/start.md", False),
        ("apps/", "nested/apps/start.md", True),
        ("/apps/", "nested/apps/start.md", False),
        ("docs/*", "docs/start.md", True),
        ("docs/*", "docs/guides/start.md", False),
        ("**/logs", "deeply/nested/logs/agent.py", True),
    ],
)
def test_codeowners_directory_and_root_patterns(pattern, path, expected):
    assert _codeowners_match(pattern, path) is expected


def test_codeowners_later_ownerless_rule_clears_owner(tmp_path: Path, run_connector):
    (tmp_path / "CODEOWNERS").write_text("/apps/ @team\n/apps/github\n")
    (tmp_path / "apps" / "github").mkdir(parents=True)
    (tmp_path / "apps" / "github" / "agent.py").write_text("from langchain import agents\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner is None


def test_group_variables_keep_all_names_in_one_finding(index):
    connector = GitLabConnector(ConnectorContext(index=index))
    findings = list(connector.analyze([
        _GitLabMetadata("group_variable", {"group": "team", "key": "OPENAI_API_KEY", "masked": True}),
        _GitLabMetadata("group_variable", {"group": "team", "key": "ANTHROPIC_API_KEY", "masked": False}),
        _GitLabMetadata("group_variables", {"group": "team", "variables": [
            {"key": "GEMINI_API_KEY", "masked": True},
            {"key": 42, "masked": False},
        ]}),
    ]))
    assert len(findings) == 1
    assert set(findings[0].metadata["variable_names"]) == {
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"
    }
    assert "unmasked-ci-variable" in findings[0].tags


def test_group_collection_redacts_all_variable_values(index):
    connector = GitLabConnector(ConnectorContext(index=index))
    connector._optional_list = Mock(side_effect=[[], [], [
        {"key": "OPENAI_API_KEY", "value": "synthetic-secret-1"},
        {"key": "ANTHROPIC_API_KEY", "value": "synthetic-secret-2"},
    ]])
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}
    records = list(connector._group_identities("team"))
    assert len(records) == 1 and records[0]["_kind"] == "group_variables"
    assert [var["key"] for var in records[0]["variables"]] == ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
    assert "synthetic-secret" not in str(records)


@pytest.mark.parametrize(
    "cls,key,records,identity",
    [
        (GitHubConnector, "repos", ["acme/one", "acme/two"], "full_name"),
        (GitLabConnector, "projects", ["acme/one", "acme/two"], "id"),
    ],
)
def test_explicit_repository_caps_are_enforced(cls, key, records, identity, index):
    limit = "max_repos" if cls is GitHubConnector else "max_projects"
    ctx = ConnectorContext(config={key: records, limit: 1}, index=index)
    ctx.stats = ScanStats(connector=cls.name, started_at="2026-01-01T00:00:00Z")
    connector = cls(ctx)
    connector.http = Mock()
    connector.http.try_get_json.return_value = {identity: "acme/one" if cls is GitHubConnector else 1}
    assert len(list(connector.collect())) == 1
    assert connector.http.try_get_json.call_count == 1
    assert ctx.stats.incomplete and any(limit in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("cls,key", [(GitHubConnector, "max_repos"), (GitLabConnector, "max_projects")])
def test_invalid_repository_caps_rejected(cls, key, index):
    from shadowscan.connectors.base import ConnectorError

    with pytest.raises(ConnectorError, match=key):
        cls(ConnectorContext(config={key: 0}, index=index))


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
def test_offline_repo_caps_mark_partial_coverage(tmp_path: Path, connector: str, run_connector):
    for name in ("one", "two"):
        repo = tmp_path / name
        repo.mkdir()
        (repo / "requirements.txt").write_text("langchain\n")
    limit = "max_repos" if connector == "code.github" else "max_projects"
    findings, ctx = run_connector(connector, input=str(tmp_path), use_git=False, **{limit: 1})
    assert len([f for f in findings if f.resource_type == "project"]) == 1
    assert ctx.stats.incomplete and any(limit in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
def test_nested_filesystem_respects_scan_timeout(tmp_path: Path, connector: str, run_connector):
    checkout = tmp_path / "one"
    checkout.mkdir()
    (checkout / "requirements.txt").write_text("langchain\n")
    findings, ctx = run_connector(connector, input=str(tmp_path), scan_timeout=61)
    assert not findings and ctx.stats.incomplete
    assert any("scan_timeout" in error for error in ctx.stats.errors)
