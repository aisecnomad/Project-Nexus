"""Regression cases for hostile repository inputs and report-safe evidence."""

from __future__ import annotations

import json
import os
import time

import pytest
import regex

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code import manifests
from shadowscan.connectors.code.filesystem import FilesystemConnector, _parse_mcp_servers
from shadowscan.models import Kind
from shadowscan.utils.text import read_text


def test_malformed_manifest_preserves_same_file_and_neighbor_findings(tmp_path, run_connector):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": [1], "devDependencies": {"@langchain/langgraph": "^0.2"},
    }))
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    frameworks = {framework for finding in findings for framework in finding.frameworks}
    assert {"framework.langgraph", "framework.crewai"} <= frameworks
    assert any("package.json" in issue and "dependencies must be an object" in issue for issue in ctx.stats.errors)


@pytest.mark.parametrize(("name", "text"), [
    ("package.json", "null"),
    ("composer.json", "[]"),
    ("pyproject.toml", 'project = "invalid"'),
    ("Pipfile", 'packages = ["langchain"]'),
    ("Cargo.toml", 'dependencies = ["rig-core"]'),
    ("environment.yml", "dependencies: 42"),
])
def test_invalid_manifest_shapes_are_explicit(name, text):
    result = manifests.parse_manifest(name, text)
    assert result is not None and result.errors


def test_invalid_notebook_cells_do_not_hide_valid_code(tmp_path, run_connector):
    (tmp_path / "research.ipynb").write_text(json.dumps({"cells": [
        1, {"cell_type": "code", "source": [42]},
        {"cell_type": "code", "source": ["from crewai import Agent\n"]},
    ]}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert ctx.stats.errors


def test_bad_mcp_shapes_are_isolated_and_other_servers_survive(tmp_path, run_connector):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "invalid": {"env": 7, "headers": [1], "args": 2, "remotes": [1]},
        "valid": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]},
    }}))
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    mcp = next(finding for finding in findings if finding.kind == Kind.MCP_SERVER)
    assert "valid" in {server["name"] for server in mcp.metadata["servers"]}
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert ctx.stats.errors


def test_bad_agent_card_does_not_suppress_later_secret_findings(tmp_path, run_connector):
    (tmp_path / "agent-card.json").write_text('{"name": "invalid", "skills": 42}')
    (tmp_path / "agent.py").write_text(
        'from langgraph.graph import StateGraph\n'
        'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop"\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any(finding.kind == Kind.SECRET for finding in findings)
    assert any("agent-card.json" in issue for issue in ctx.stats.errors)


def test_mcp_json_comments_do_not_rewrite_url_strings():
    errors = []
    servers = _parse_mcp_servers(".mcp.json", '''{
      // This client permits JSONC.
      "mcpServers": {"remote": {"url": "https://example.test/a/*literal*/b",},},
    }''', errors)
    assert not errors
    assert servers[0]["url"] == "https://example.test/a/*literal*/b"


def test_credentials_removed_before_truncated_snippets_and_metadata(tmp_path, run_connector):
    source_secret = "SYNTHETIC_SOURCE_VALUE_" + "X" * 250
    env_secret = "SYNTHETIC_ENV_VALUE_12345678"
    argv_secret = "SYNTHETIC_ARG_VALUE_12345678"
    url_secret = "SYNTHETIC_URL_VALUE_12345678"
    (tmp_path / "agent.py").write_text(
        'from langgraph.graph import StateGraph; API_KEY = "' + source_secret + '"\n'
    )
    (tmp_path / "langgraph.json").write_text(json.dumps({
        "graphs": {"agent": "./agent.py:graph"}, "env": {"PRIVATE_SETTING": env_secret},
    }))
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"remote": {
        "command": "tools", "args": ["--token", argv_secret],
        "url": "https://example.test/mcp?api_key=" + url_secret,
        "env": {"PRIVATE_SETTING": env_secret},
    }}}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    serialized = json.dumps([finding.to_dict() for finding in findings])
    assert not ctx.stats.errors
    for secret in (source_secret[:35], env_secret, argv_secret, url_secret):
        assert secret not in serialized
    assert "PRIVATE_SETTING" in serialized
    assert "[REDACTED]" in serialized


def test_mcp_projection_retains_sibling_credential_context(tmp_path, run_connector):
    secret = "SYNTHETIC_DUPLICATE_MCP_12345678"
    shared_secret = "SYNTHETIC_SHARED_MCP_12345678"
    (tmp_path / ".mcp.json").write_text(json.dumps({"api_key": shared_secret, "mcpServers": {"remote": {
        "command": "tool-" + secret, "args": ["connect", secret],
        "url": "https://example.test/" + secret,
        "env": {"API_KEY": secret}, "autoApprove": [secret],
    }, "sibling": {"command": "tool", "args": ["connect", shared_secret, secret]}}}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    serialized = json.dumps([finding.to_dict() for finding in findings])
    assert secret not in serialized
    assert shared_secret not in serialized
    mcp = next(finding for finding in findings if finding.kind == Kind.MCP_SERVER)
    assert mcp.metadata["servers"][0]["args"] == ["connect", "[REDACTED]"]


@pytest.mark.parametrize("filename", ["agent-card.json", "declarativeAgent.json"])
def test_agent_manifest_projection_retains_sibling_credential_context(tmp_path, run_connector, filename):
    secret = "SYNTHETIC_DUPLICATE_MANIFEST_12345678"
    (tmp_path / filename).write_text(json.dumps({
        "name": "agent " + secret, "api_key": secret,
        "description": "Credential copied here: " + secret,
        "instructions": "Use " + secret, "url": "https://example.test/" + secret,
        "version": "1.0", "capabilities": [] if filename == "declarativeAgent.json" else {},
        "skills": [{"id": "summary", "name": "Summarize"}],
    }))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert any(finding.resource_type == "agent-manifest" for finding in findings)
    assert secret not in json.dumps([finding.to_dict() for finding in findings])


def test_codeowners_cannot_follow_symlink_outside_root(tmp_path, run_connector):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("* @must-not-be-read\n")
    (repo / "CODEOWNERS").symlink_to(outside)
    (repo / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(repo), use_git=False)
    assert findings and all(finding.owner is None for finding in findings)
    assert any("CODEOWNERS" in issue for issue in ctx.stats.errors)


def test_codeowners_parent_symlink_is_not_followed(tmp_path, run_connector):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "CODEOWNERS").write_text("* @must-not-be-read\n")
    (repo / ".github").symlink_to(outside, target_is_directory=True)
    (repo / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(repo), use_git=False)
    assert findings and all(finding.owner is None for finding in findings)
    assert ctx.stats.errors


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_source_symlink_is_skipped_and_marks_scan_incomplete(tmp_path, run_connector, kind, strict):
    repo = tmp_path / "repo"
    repo.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    (private / "agent.py").write_text("from crewai import Agent  # private business notes\n")
    (repo / "good.py").write_text("from langgraph.graph import StateGraph\n")
    if kind == "file":
        (repo / "agent.py").symlink_to(private / "agent.py")
    else:
        (repo / "agent").symlink_to(private, target_is_directory=True)

    findings, ctx = run_connector("code.filesystem", path=str(repo), use_git=False, strict_coverage=strict)
    assert any("framework.langgraph" in finding.frameworks for finding in findings)
    assert not any("private business notes" in str(finding.to_dict()) for finding in findings)
    # The link is never followed. Content outside the repository is reported as
    # skipped; strict_coverage makes that incomplete coverage.
    assert ctx.stats.incomplete is strict
    diagnostics = ctx.stats.errors if strict else ctx.stats.warnings
    assert any("symbolic link" in issue for issue in diagnostics)


def test_explicitly_excluded_symlink_is_outside_scan_scope(tmp_path, run_connector):
    private = tmp_path / "private"
    private.mkdir()
    (private / "agent.py").write_text("from crewai import Agent\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "excluded.py").symlink_to(private / "agent.py")
    (repo / "good.py").write_text("from langgraph.graph import StateGraph\n")

    findings, ctx = run_connector("code.filesystem", path=str(repo), exclude=["*excluded.py"], use_git=False)
    assert any("framework.langgraph" in finding.frameworks for finding in findings)
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("kind", ["root", "ancestor", "dotdot"])
def test_symlink_in_selected_root_cannot_read_outside(tmp_path, run_connector, kind):
    repo = tmp_path / "repo"
    repo.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    (private / "agent.py").write_text("from crewai import Agent  # private business notes\n")
    (repo / "linked").symlink_to(private, target_is_directory=True)
    selected = {
        "root": repo / "linked",
        "ancestor": repo / "linked" / "agent.py",
        "dotdot": repo / "linked" / ".." / "agent.py",
    }[kind]
    findings, ctx = run_connector("code.filesystem", path=str(selected), use_git=False)
    assert findings == []
    assert ctx.stats.incomplete
    assert any("symbolic link" in issue for issue in ctx.stats.errors)


def test_codeowners_cache_scoped_to_each_scan_root(tmp_path, run_connector):
    roots = []
    for name in ("one", "two"):
        root = tmp_path / name
        root.mkdir()
        (root / "CODEOWNERS").write_text(f"* @{name}\n")
        (root / "agent.py").write_text("from crewai import Agent\n")
        roots.append(str(root))
    findings, ctx = run_connector("code.filesystem", paths=roots, use_git=False)
    assert not ctx.stats.errors
    assert {finding.owner for finding in findings} == {"@one", "@two"}


def test_codeowners_and_source_share_file_size_limit(tmp_path, run_connector):
    (tmp_path / "CODEOWNERS").write_text("* @oversize" + " " * 500)
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), max_file_size=100, use_git=False)
    assert findings and all(finding.owner is None for finding in findings)
    assert any("max_file_size" in issue for issue in ctx.stats.errors)


def test_read_text_rejects_symlinks_and_special_files(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("safe")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    errors = []
    assert read_text(link, 100, errors) is None and errors
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        errors.clear()
        assert read_text(fifo, 100, errors) is None and errors


def test_file_count_limit_marks_scan_incomplete(tmp_path, run_connector):
    (tmp_path / "a.py").write_text("from crewai import Agent\n")
    (tmp_path / "b.py").write_text("from langgraph.graph import StateGraph\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), max_files=1, use_git=False)
    assert findings
    assert any("max_files" in issue for issue in ctx.stats.errors)


def test_regex_timeout_isolates_file_and_preserves_neighbor(tmp_path, index, monkeypatch):
    original = index.match_imports

    def fail_one(text, language):
        if "HOSTILE_INPUT" in text:
            raise TimeoutError("test matching budget")
        return original(text, language)

    monkeypatch.setattr(index, "match_imports", fail_one)
    (tmp_path / "a.py").write_text("HOSTILE_INPUT")
    (tmp_path / "b.py").write_text("from crewai import Agent\n")
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert any("a.py" in issue and "TimeoutError" in issue for issue in ctx.stats.errors)


def test_manifest_regex_execution_has_timeout(monkeypatch):
    # Substitute a deliberately expensive expression to verify execution bounds
    # still cover regex-based manifests, such as Gradle dependency declarations.
    # POM dependencies now use an XML parser rather than a regex.
    monkeypatch.setattr(manifests, "_GRADLE_DEP", regex.compile(r"(a+)+$"))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        manifests.parse_manifest("build.gradle", "a" * 100_000 + "!")
    assert time.monotonic() - started < 2


def test_pom_entity_expansion_is_rejected_without_parsing():
    pom = (
        '<!DOCTYPE project [<!ENTITY large "' + "a" * 100_000 + '">]>'
        '<project><dependencies><dependency><groupId>&large;</groupId>'
        '<artifactId>langchain4j</artifactId></dependency></dependencies></project>'
    )
    started = time.monotonic()
    result = manifests.parse_manifest("pom.xml", pom)
    assert result is not None and not result.deps
    assert any("DTD/entity declarations are unsupported" in issue for issue in result.errors)
    assert time.monotonic() - started < 2


def test_repository_source_is_never_executed(tmp_path, run_connector):
    marker = tmp_path / "executed"
    (tmp_path / "setup.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\ninstall_requires=['crewai']\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert findings and not ctx.stats.errors
    assert not marker.exists()
