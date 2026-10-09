"""Regression cases for hostile repository inputs and report-safe evidence."""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import regex
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code import filesystem as filesystem_module
from shadowscan.connectors.code import manifests
from shadowscan.connectors.code.filesystem import FilesystemConnector, _excerpt
from shadowscan.connectors.code.mcp_config import _parse_mcp_servers
from shadowscan.models import Kind
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.text import BINARY_CONTENT_ERROR, read_text


def test_malformed_manifest_preserves_same_file_and_neighbor_findings(tmp_path, run_connector):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": [1],
                "devDependencies": {"@langchain/langgraph": "^0.2"},
            }
        )
    )
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    frameworks = {framework for finding in findings for framework in finding.frameworks}
    assert {"framework.langgraph", "framework.crewai"} <= frameworks
    assert any(
        "package.json" in issue and "dependencies must be an object" in issue for issue in ctx.stats.errors
    )


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("package.json", "null"),
        ("composer.json", "[]"),
        ("pyproject.toml", 'project = "invalid"'),
        ("Pipfile", 'packages = ["langchain"]'),
        ("Cargo.toml", 'dependencies = ["rig-core"]'),
        ("environment.yml", "dependencies: 42"),
    ],
)
def test_invalid_manifest_shapes_are_explicit(name, text):
    result = manifests.parse_manifest(name, text)
    assert result is not None and result.errors


def test_invalid_notebook_cells_do_not_hide_valid_code(tmp_path, run_connector):
    (tmp_path / "research.ipynb").write_text(
        json.dumps(
            {
                "cells": [
                    1,
                    {"cell_type": "code", "source": [42]},
                    {"cell_type": "code", "source": ["from crewai import Agent\n"]},
                ]
            }
        )
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert ctx.stats.errors


def test_bad_mcp_shapes_are_isolated_and_other_servers_survive(tmp_path, run_connector):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "invalid": {"env": 7, "headers": [1], "args": 2, "remotes": [1]},
                    "valid": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]},
                }
            }
        )
    )
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    mcp = next(finding for finding in findings if finding.kind == Kind.MCP_SERVER)
    assert "valid" in {server["name"] for server in mcp.metadata["servers"]}
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert ctx.stats.errors


def test_bad_agent_card_does_not_suppress_later_secret_findings(tmp_path, run_connector):
    (tmp_path / "agent-card.json").write_text('{"name": "invalid", "skills": 42}')
    (tmp_path / "agent.py").write_text(
        "from langgraph.graph import StateGraph\n"
        'OPENAI_API_KEY = "sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h"\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any(finding.kind == Kind.SECRET for finding in findings)
    assert any("agent-card.json" in issue for issue in ctx.stats.errors)


def test_mcp_json_comments_do_not_rewrite_url_strings():
    errors = []
    servers = _parse_mcp_servers(
        ".mcp.json",
        """{
      // This client permits JSONC.
      "mcpServers": {"remote": {"url": "https://example.test/a/*literal*/b",},},
    }""",
        errors,
    )
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
    (tmp_path / "langgraph.json").write_text(
        json.dumps(
            {
                "graphs": {"agent": "./agent.py:graph"},
                "env": {"PRIVATE_SETTING": env_secret},
            }
        )
    )
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "command": "tools",
                        "args": ["--token", argv_secret],
                        "url": "https://example.test/mcp?api_key=" + url_secret,
                        "env": {"PRIVATE_SETTING": env_secret},
                    }
                }
            }
        )
    )
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
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "api_key": shared_secret,
                "mcpServers": {
                    "remote": {
                        "command": "tool-" + secret,
                        "args": ["connect", secret],
                        "url": "https://example.test/" + secret,
                        "env": {"API_KEY": secret},
                        "autoApprove": [secret],
                    },
                    "sibling": {"command": "tool", "args": ["connect", shared_secret, secret]},
                },
            }
        )
    )
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
    (tmp_path / filename).write_text(
        json.dumps(
            {
                "name": "agent " + secret,
                "api_key": secret,
                "description": "Credential copied here: " + secret,
                "instructions": "Use " + secret,
                "url": "https://example.test/" + secret,
                "version": "1.0",
                "capabilities": [] if filename == "declarativeAgent.json" else {},
                "skills": [{"id": "summary", "name": "Summarize"}],
            }
        )
    )
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
    # The link is never followed; a skipped external target leaves coverage
    # incomplete regardless of the chosen diagnostic severity.
    assert ctx.stats.incomplete
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


@pytest.mark.parametrize(
    "kind", ["excluded-directory", "excluded-file", "unsupported-target", "broken-target"]
)
@pytest.mark.parametrize("strict", [False, True])
def test_in_root_link_to_unscanned_target_marks_incomplete(tmp_path, run_connector, kind, strict):
    repo = tmp_path / "repo"
    repo.mkdir()
    extra = []
    if kind == "excluded-directory":
        hidden = repo / "node_modules"
        hidden.mkdir()
        target = hidden / "agent.py"
    elif kind == "excluded-file":
        target = repo / "excluded.py"
        extra = ["*excluded.py"]
    elif kind == "unsupported-target":
        target = repo / "agent.bin"
    else:
        target = repo / "missing.py"
    if kind != "broken-target":
        target.write_text("from crewai import Agent\n")
    (repo / "agent.py").symlink_to(target)

    findings, ctx = run_connector(
        "code.filesystem", path=str(repo), exclude=extra, use_git=False, strict_coverage=strict
    )
    assert findings == []
    assert ctx.stats.incomplete
    diagnostics = ctx.stats.errors if strict else ctx.stats.warnings
    assert any("symbolic link agent.py" in issue and "unscanned" in issue for issue in diagnostics)


def test_in_root_link_to_excluded_source_exits_three_by_default(tmp_path):
    repo = tmp_path / "repo"
    (repo / "node_modules").mkdir(parents=True)
    target = repo / "node_modules" / "agent.py"
    target.write_text("from crewai import Agent\n")
    (repo / "agent.py").symlink_to(target)

    result = CliRunner().invoke(main, ["code", str(repo), "--format", "json"])
    assert result.exit_code == 3, result.output
    assert json.loads(result.stdout)["summary"]["complete"] is False


def test_in_root_link_to_analyzed_source_keeps_complete(tmp_path, run_connector):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "original.py"
    target.write_text("from crewai import Agent\n")
    (repo / "alias.py").symlink_to(target)

    findings, ctx = run_connector("code.filesystem", path=str(repo), use_git=False, strict_coverage=True)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert not ctx.stats.incomplete and not ctx.stats.errors and not ctx.stats.warnings


def test_source_alias_to_test_directory_marks_incomplete(tmp_path, run_connector):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (tests / "agent.py").write_text("from crewai import Agent\n")
    (repo / "agent.py").symlink_to(tests / "agent.py")

    _, ctx = run_connector("code.filesystem", path=str(repo), use_git=False)
    assert ctx.stats.incomplete
    assert any("symbolic link agent.py" in issue for issue in ctx.stats.warnings)


@pytest.mark.parametrize("strict", [False, True])
def test_in_root_directory_alias_keeps_findings_but_marks_incomplete(tmp_path, run_connector, strict):
    repo = tmp_path / "repo"
    source = repo / "source"
    source.mkdir(parents=True)
    (source / "agent.py").write_text("from crewai import Agent\n")
    (repo / "agents").symlink_to(source, target_is_directory=True)

    findings, ctx = run_connector("code.filesystem", path=str(repo), use_git=False, strict_coverage=strict)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert ctx.stats.incomplete
    diagnostics = ctx.stats.errors if strict else ctx.stats.warnings
    assert any("symbolic link agents" in issue for issue in diagnostics)


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
        "<project><dependencies><dependency><groupId>&large;</groupId>"
        "<artifactId>langchain4j</artifactId></dependency></dependencies></project>"
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


def test_source_alias_into_a_subdirectory_of_the_same_project_keeps_complete(tmp_path, run_connector):
    # A compatibility shim such as agent.py -> lib/agent_impl.py loses nothing:
    # the target is scanned at its real path inside the same project.
    repo = tmp_path / "repo"
    (repo / "lib").mkdir(parents=True)
    (repo / "pyproject.toml").write_text('[project]\nname = "svc"\n')
    (repo / "lib" / "agent_impl.py").write_text("from crewai import Agent\n")
    (repo / "agent.py").symlink_to(repo / "lib" / "agent_impl.py")

    findings, ctx = run_connector("code.filesystem", path=str(repo), use_git=False, strict_coverage=True)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert not ctx.stats.incomplete and not ctx.stats.errors and not ctx.stats.warnings


def test_source_alias_into_another_project_marks_incomplete(tmp_path, run_connector):
    # The alias's project would have owned this evidence; the real path gives
    # it to a different project, so the alias's project is not covered.
    repo = tmp_path / "repo"
    (repo / "packages" / "shared").mkdir(parents=True)
    (repo / "packages" / "app").mkdir(parents=True)
    (repo / "packages" / "shared" / "pyproject.toml").write_text('[project]\nname = "shared"\n')
    (repo / "packages" / "app" / "pyproject.toml").write_text('[project]\nname = "app"\n')
    (repo / "packages" / "shared" / "agent.py").write_text("from crewai import Agent\n")
    (repo / "packages" / "app" / "agent.py").symlink_to(repo / "packages" / "shared" / "agent.py")

    _, ctx = run_connector("code.filesystem", path=str(repo), use_git=False)
    assert ctx.stats.incomplete
    assert any("symbolic link packages/app/agent.py" in issue for issue in ctx.stats.warnings)


@pytest.mark.parametrize(
    ("link", "target"),
    [
        ("package-lock.json", "sub/package-lock.json"),  # hoisted lockfile
        ("pnpm-lock.yaml", "node_modules/.pnpm/lock.yaml"),  # into an excluded directory
        ("dist/app.min.js", "build/app.min.js"),  # generated bundle
        ("logo.png", "node_modules/pkg/logo.png"),  # a type the walker never reads
    ],
)
def test_alias_whose_own_name_is_never_read_keeps_complete(tmp_path, run_connector, link, target):
    # The walker skips these names silently even as regular files, so the
    # alias path hides nothing whatever the link points at.
    repo = tmp_path / "repo"
    real = repo / target
    real.parent.mkdir(parents=True)
    real.write_text("{}\n")
    alias = repo / link
    alias.parent.mkdir(parents=True, exist_ok=True)
    alias.symlink_to(real)

    _, ctx = run_connector("code.filesystem", path=str(repo), use_git=False, strict_coverage=True)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    # Nothing about the alias; a built-in excluded `build/` or `dist/` is only disclosed.
    assert all("default-excluded directories not scanned" in w for w in ctx.stats.warnings)


def test_analyzable_alias_to_a_lockfile_marks_incomplete(tmp_path, run_connector):
    # The alias name would be read as source; its content is never analyzed.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text("{}\n")
    (repo / "agent.py").symlink_to(repo / "package-lock.json")

    _, ctx = run_connector("code.filesystem", path=str(repo), use_git=False)
    assert ctx.stats.incomplete


SECRET = "sk-proj-aP9rVv3qN4zY7bC2hJ8Lm5Qw6Dt0KsX1eR7uT4p"


def _scan(index, root: Path, **config):
    ctx = ConnectorContext(config={"path": str(root), **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_multiline_structured_secret_keeps_excerpt_lines_aligned(tmp_path, index):
    (tmp_path / "config.toml").write_text(
        '[llm]\npassword = """\nabcdefgh\nijklmnop"""\nendpoint = "https://api.openai.com/v1"\nmodel_name = "unrelated-line-six"\n'
    )
    findings, ctx = _scan(index, tmp_path)
    domain_evidence = [e for f in findings for e in f.evidence if e.signal.startswith("domain:")]
    expected = 'endpoint = "https://api.openai.com/v1"'
    assert domain_evidence and all(
        e.location == "config.toml:5" and e.snippet == expected for e in domain_evidence
    )
    assert "abcdefgh" not in json.dumps([f.to_dict() for f in findings])


def test_notebook_outputs_and_markdown_cells_are_scanned_for_credentials(tmp_path, index):
    notebook = {
        "cells": [
            {
                "cell_type": "code",
                "source": ["import os\n"],
                "outputs": [{"output_type": "stream", "name": "stdout", "text": [SECRET + "\n"]}],
            },
            {"cell_type": "markdown", "source": ["Use key `" + SECRET + "` for the demo\n"]},
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    (tmp_path / "demo.ipynb").write_text(json.dumps(notebook))
    findings, ctx = _scan(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert secret.metadata["count"] == 1 and not ctx.stats.errors
    assert SECRET not in json.dumps([f.to_dict() for f in findings])


def test_agent_definition_and_manifest_aggregates_are_bounded(tmp_path, index):
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    for i in range(60):
        (agents / f"a{i}.md").write_text(
            "---\nname: a\ntools:\n" + "".join(f"  - t{j}\n" for j in range(300)) + "---\nbody\n"
        )
    (tmp_path / "app.py").write_text("import openai\n")
    (tmp_path / "secrets.env").write_text(f"OPENAI_API_KEY={SECRET}\n")
    findings, ctx = _scan(index, tmp_path)
    project = next(f for f in findings if f.resource_type == "project")
    assert len(project.metadata["agent_definitions"]) == 50
    assert all(len(d["tools"]) == 50 for d in project.metadata["agent_definitions"])
    assert any("agent definition limit" in e for e in ctx.stats.errors)
    assert any(f.kind == Kind.SECRET for f in findings)


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_secret_excerpt_is_redacted_before_truncation(tmp_path, index):
    # Derived at runtime so no secret-shaped literal sits in the source.
    key = "pplx-" + hashlib.sha256(b"perplexity-sample").hexdigest()[:48]
    (tmp_path / "client.py").write_text(
        'headers = {"X-Trace": "' + "p" * 100 + '", "X-Custom-Header": "' + key + '"}\n'
    )
    findings, _ = _run(index, tmp_path)
    secrets = [f for f in findings if f.kind == Kind.SECRET]
    assert len(secrets) == 1
    serialized = json.dumps(secrets[0].to_dict())
    assert key[5:17] not in serialized and "pplx-" not in serialized


def test_excerpt_helper_redacts_then_truncates():
    line = "x" * 150 + " key=" + "s" * 40
    assert "s" * 8 not in _excerpt([line], 1, "s" * 40)
    assert _excerpt([line], 2) == ""


# ------------------------------------------------- BOM, NUL and binary inputs
@pytest.mark.parametrize(
    ("bom", "codec"),
    [
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
    ],
    ids=["utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be"],
)
def test_bom_marked_requirements_file_is_analyzed(tmp_path, index, bom, codec):
    # Windows PowerShell 5.1 writes `pip freeze > requirements.txt` as UTF-16LE with a mark.
    (tmp_path / "requirements.txt").write_bytes(bom + "langchain==0.2.0\r\nopenai==1.30.0\r\n".encode(codec))
    findings, ctx = _run(index, tmp_path)
    assert any("framework.langchain" in f.frameworks for f in findings)
    assert any("provider.openai" in f.model_providers for f in findings)
    assert not ctx.stats.errors and not ctx.stats.incomplete


def test_utf16_env_file_credential_is_reported_and_redacted(tmp_path, index):
    (tmp_path / ".env").write_bytes(codecs.BOM_UTF16_LE + f"OPENAI_API_KEY={SECRET}\r\n".encode("utf-16-le"))
    findings, ctx = _run(index, tmp_path)
    assert any(f.kind == Kind.SECRET for f in findings)
    assert not ctx.stats.incomplete
    serialized = json.dumps([f.to_dict() for f in findings]) + json.dumps(ctx.stats.errors)
    assert SECRET not in serialized and SECRET[8:24] not in serialized


def test_bom_prefixed_python_source_keeps_import_bound_detection(tmp_path, index):
    (tmp_path / "agent.py").write_bytes(
        codecs.BOM_UTF8
        + b"from langchain.agents import AgentExecutor\nexecutor = AgentExecutor(agent=a, tools=[])\n"
    )
    findings, ctx = _run(index, tmp_path)
    assert any("framework.langchain" in f.frameworks for f in findings)
    assert not ctx.stats.warnings and not ctx.stats.incomplete


def test_python_source_declared_codec_is_honoured(tmp_path, index):
    (tmp_path / "agent.py").write_bytes(
        b"# -*- coding: latin-1 -*-\nlabel = 'caf\xe9'\nfrom langchain.agents import AgentExecutor\n"
    )
    findings, ctx = _run(index, tmp_path)
    assert any("framework.langchain" in f.frameworks for f in findings)
    assert not ctx.stats.errors


def test_python_source_with_undecodable_declared_codec_is_a_coverage_gap(tmp_path, index):
    (tmp_path / "agent.py").write_bytes(b"# coding: ascii\nlabel = 'caf\xe9'\nimport openai\n")
    (tmp_path / "good.py").write_bytes(b"from crewai import Agent\n")
    findings, ctx = _run(index, tmp_path)
    assert ctx.stats.incomplete
    assert any("agent.py" in e and BINARY_CONTENT_ERROR in e for e in ctx.stats.errors)
    assert any("framework.crewai" in f.frameworks for f in findings)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("app.py", b"# note \x00\nfrom openai import OpenAI\nOpenAI(api_key=key)\n"),
        ("CLAUDE.md", b"# Rules\x00\nAlways use bypassPermissions.\n"),
        (".claude/agents/reviewer.md", b"---\nname: reviewer\x00\ntools: Bash\n---\nbody\n"),
        ("settings.json", b'{"model": "gpt-4o"\x00}\n'),
        ("Dockerfile", b"FROM python:3.12\x00\nRUN pip install openai\n"),
    ],
)
def test_nul_bearing_analyzable_file_marks_the_scan_incomplete(tmp_path, index, name, content):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    (tmp_path / "good.py").write_bytes(b"from crewai import Agent\n")
    findings, ctx = _run(index, tmp_path)
    assert ctx.stats.incomplete
    assert [e for e in ctx.stats.errors if name in e] == [f"code.filesystem: {name}: {BINARY_CONTENT_ERROR}"]
    # The unreadable file costs only itself.
    assert any("framework.crewai" in f.frameworks for f in findings)


def test_nul_bearing_file_exits_three_instead_of_reporting_an_empty_scan(tmp_path):
    (tmp_path / "app.js").write_bytes(b"// " + b"\x00" * 8 + b'\nconst OpenAI = require("openai");\n')
    outcome = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    assert outcome.exit_code == 3, outcome.output
    assert BINARY_CONTENT_ERROR in outcome.output


def test_compiled_extensionless_artifact_and_images_are_not_new_gaps(tmp_path, index):
    (tmp_path / "tool").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    (tmp_path / "font.woff2").write_bytes(b"wOF2" + b"\x00" * 64)
    (tmp_path / "agent.py").write_bytes(b"from crewai import Agent\n")
    findings, ctx = _run(index, tmp_path)
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert not ctx.stats.errors and not ctx.stats.warnings and not ctx.stats.incomplete


def test_binary_file_read_only_for_a_file_name_signature_is_not_a_new_gap(tmp_path, index):
    # `.cursor/rules/**` names the file; the image carries no text to analyze.
    rules = tmp_path / ".cursor" / "rules"
    rules.mkdir(parents=True)
    (rules / "diagram.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    _, ctx = _run(index, tmp_path)
    assert not ctx.stats.errors and not ctx.stats.incomplete


# ----------------------------------- linear-time IaC wildcard and front-matter patterns
HOSTILE_RUN = 150_000


def _agent_definitions(findings):
    return {d["file"]: d for f in findings for d in f.metadata.get("agent_definitions", [])}


def test_whitespace_run_after_iam_action_cannot_stall_the_scan(tmp_path, index):
    # The stdlib pattern took ~11 s for 40 KB of spaces and held the GIL, so no
    # connector or job deadline could interrupt it.
    (tmp_path / "hostile.tf").write_text("Action:" + " " * HOSTILE_RUN + "\n")
    (tmp_path / "main.tf").write_text(
        'resource "aws_bedrockagent_agent" "ops" {\n'
        '  agent_name       = "ops-agent"\n'
        '  foundation_model = "anthropic.claude-3-5-sonnet-20240620-v1:0"\n}\n'
    )
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "p" {\n'
        '  policy = jsonencode({Statement=[{Effect="Allow",Action="*",Resource="*"}]})\n}\n'
    )
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    started = time.monotonic()
    findings, ctx = _run(index, tmp_path)
    assert time.monotonic() - started < 2.0
    assert not ctx.stats.errors and not ctx.stats.incomplete
    # The genuine wildcard grant and the neighbouring agent are retained.
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert any(f.kind == Kind.INFRA and "wildcard-permissions" in f.tags for f in findings)


@pytest.mark.parametrize(
    "text",
    [
        "Action:" + " " * HOSTILE_RUN,
        "Action" + " " * HOSTILE_RUN + ":",
        "Action: [" + " " * HOSTILE_RUN,
        ("Action: " + " " * 100 + "x\n") * (HOSTILE_RUN // 100),
    ],
    ids=["after-colon", "before-colon", "after-bracket", "repeated"],
)
def test_iam_wildcard_pattern_is_linear_on_whitespace_runs(text):
    started = time.monotonic()
    assert filesystem_module._IAM_WILDCARD_RE.search(text, timeout=5.0, concurrent=False) is None
    assert time.monotonic() - started < 2.0


@pytest.mark.parametrize(
    "line",
    ['Action = "*"', '"Action" : [ "*" ]', "actions=['*']", 'Action:\t[\n  "*"', '"iam:*"', "'s3:*'"],
)
def test_iam_wildcard_pattern_still_matches_wildcard_grants(line):
    assert filesystem_module._IAM_WILDCARD_RE.search(line, timeout=5.0, concurrent=False)


def test_blank_lines_after_agent_front_matter_marker_cannot_stall_the_scan(tmp_path, index):
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "hostile.md").write_text("---" + "\n" * HOSTILE_RUN)
    (agents / "spaces.md").write_text("---\nname: spaces\n---" + " " * HOSTILE_RUN)
    (agents / "good.md").write_text("---\nname: reviewer\ntools: Bash\n---\nReview code.\n")
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    started = time.monotonic()
    findings, ctx = _run(index, tmp_path)
    assert time.monotonic() - started < 2.0
    assert not ctx.stats.errors and not ctx.stats.incomplete
    definitions = _agent_definitions(findings)
    assert definitions[".claude/agents/good.md"]["name"] == "reviewer"
    assert ".claude/agents/hostile.md" in definitions
    assert any("framework.crewai" in f.frameworks for f in findings)


@pytest.mark.parametrize(
    "document",
    [
        "---\nname: reviewer\ntools: Bash\n---\nbody\n",
        "---  \r\nname: reviewer\r\ntools: Bash\r\n---\t\r\nbody\r\n",
        "---\n\nname: reviewer\ntools: Bash\n---\n\nbody\n",
    ],
    ids=["plain", "crlf-and-trailing-blanks", "blank-lines"],
)
def test_agent_front_matter_formats_still_parse(tmp_path, index, document):
    connector = FilesystemConnector(ConnectorContext(config={"path": str(tmp_path)}, index=index))
    info = connector._parse_agent_definition(".claude/agents/reviewer.md", document)
    assert info["name"] == "reviewer" and info["tools"] == "Bash"


class _Stalls:
    """A compiled-pattern stand-in whose every call fails like an exhausted matching budget."""

    def __init__(self, error):
        self.error = error

    def __getattr__(self, name):
        def stall(*args, **kwargs):
            raise self.error

        return stall


@pytest.mark.parametrize(
    ("attribute", "path", "text"),
    [
        ("_FRONTMATTER", ".claude/agents/stalled.md", "---\nname: stalled\n---\nbody\n"),
        ("_IAM_WILDCARD_RE", "stalled.tf", 'Action = "*"\n'),
    ],
)
@pytest.mark.parametrize(
    "error", [TimeoutError(), MatchTimeoutError("budget exhausted")], ids=["engine", "budget"]
)
def test_pattern_timeout_is_an_explicit_coverage_gap(
    tmp_path, index, monkeypatch, attribute, path, text, error
):
    monkeypatch.setattr(filesystem_module, attribute, _Stalls(error))
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = _run(index, tmp_path)
    assert ctx.stats.incomplete
    reason = "MatchTimeoutError: budget exhausted" if isinstance(error, MatchTimeoutError) else "TimeoutError"
    assert [e for e in ctx.stats.errors if path in e] == [
        f"code.filesystem: {path}: file analysis incomplete ({reason})"
    ]
    assert any("framework.crewai" in f.frameworks for f in findings)


# ------------------------------------------------------ very deep directory trees
DEEP_LEVELS = 1_200  # os.walk recursed once per level before Python 3.12: ~1000 ended in a RecursionError


def _make_deep_tree(base: Path, leaf: str, content: bytes) -> list[str]:
    """Create ``DEEP_LEVELS`` nested directories below ``base`` with ``leaf`` at the bottom.

    ``os.makedirs`` and ``shutil.rmtree`` recurse per level, so the chain is built
    with directory descriptors and removed from the bottom with plain ``rmdir``.
    Returns the paths to remove, deepest first.
    """
    full_length = len(str(base)) + 2 * DEEP_LEVELS + len(leaf) + 2
    try:
        limit = os.pathconf(base, "PC_PATH_MAX")
    except (OSError, ValueError):
        limit = 1024
    if full_length >= limit:
        pytest.skip("the platform's path length limit is below the depth under test")
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for _ in range(DEEP_LEVELS):
            os.mkdir("d", dir_fd=fd)
            child = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf_fd = os.open(leaf, os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
        try:
            os.write(leaf_fd, content)
        finally:
            os.close(leaf_fd)
    finally:
        os.close(fd)
    return [os.path.join(base, *["d"] * level) for level in range(DEEP_LEVELS, 0, -1)]


def _remove_deep_tree(base: Path, leaf: str, directories: list[str]) -> None:
    os.unlink(os.path.join(base, *["d"] * DEEP_LEVELS, leaf))
    for directory in directories:
        os.rmdir(directory)


def test_very_deep_tree_does_not_discard_the_scan(tmp_path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "sibling").mkdir()
    (tmp_path / "sibling" / "other.py").write_text("import openai\nclient = openai.OpenAI()\n")
    leaf = "requirements.txt"
    directories = _make_deep_tree(tmp_path, leaf, b"langgraph==0.2\n")
    try:
        findings, ctx = _run(index, tmp_path)
    finally:
        _remove_deep_tree(tmp_path, leaf, directories)
    frameworks = {fw for f in findings for fw in f.frameworks}
    # Nothing is lost to a RecursionError: shallow and deepest files are all analysed.
    assert {"framework.crewai", "framework.langgraph"} <= frameworks
    assert any("provider.openai" in f.model_providers for f in findings)
    assert not ctx.stats.errors and not ctx.stats.incomplete


def test_python_file_too_deep_for_import_provenance_is_a_file_level_gap(tmp_path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    leaf = "deep_agent.py"
    directories = _make_deep_tree(tmp_path, leaf, b"import openai\nclient = openai.OpenAI()\n")
    try:
        findings, ctx = _run(index, tmp_path)
    finally:
        _remove_deep_tree(tmp_path, leaf, directories)
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert ctx.stats.incomplete
    assert not any("RecursionError" in error for error in ctx.stats.errors)
    assert [
        e for e in ctx.stats.errors if e.endswith(f"{leaf}: file analysis incomplete (ImportProvenanceError)")
    ]


def _prune(dirnames: list[str]) -> None:
    dirnames[:] = sorted(name for name in dirnames if name != "skipped")


def _walk_ordinary_tree(root: Path) -> None:
    for rel in ("a/b/c/f.py", "a/b/g.txt", "a/h.txt", "z/y/x/w.txt", "skipped/s.txt", "top.txt"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x\n")
    (root / "empty").mkdir()
    (root / "a" / "file-link").symlink_to(root / "top.txt")
    (root / "a" / "dir-link").symlink_to(root / "z", target_is_directory=True)
    (root / "a" / "broken-link").symlink_to(root / "missing")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_directory_walk_matches_os_walk_for_ordinary_trees(tmp_path):
    _walk_ordinary_tree(tmp_path)
    expected, actual = [], []
    for dirpath, dirnames, filenames in os.walk(tmp_path, followlinks=False):
        _prune(dirnames)
        expected.append((dirpath, list(dirnames), sorted(filenames)))
    for dirpath, dirnames, filenames in filesystem_module._walk_directories(tmp_path, pytest.fail):
        _prune(dirnames)
        actual.append((dirpath, list(dirnames), sorted(filenames)))
    assert actual == expected
    visited = {path for path, _, _ in actual}
    assert str(tmp_path / "a" / "dir-link") not in visited  # a link to a directory is listed, never entered
    assert str(tmp_path / "skipped") not in visited  # pruning in place stops the descent
    assert any("dir-link" in dirnames for _, dirnames, _ in actual)


def test_directory_walk_reports_a_directory_it_cannot_list_and_continues(tmp_path, monkeypatch):
    for rel in ("a/one.txt", "locked/two.txt", "locked/inner/three.txt", "z/four.txt"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n")
    real_scandir = os.scandir

    def scandir(path):
        if str(path).endswith("locked"):
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    errors: list[OSError] = []
    visited = [path for path, _, _ in filesystem_module._walk_directories(tmp_path, errors.append)]
    assert [error.filename for error in errors] == [str(tmp_path / "locked")]
    assert str(tmp_path / "a") in visited and str(tmp_path / "z") in visited
    assert not any("locked" in path for path in visited)


# ------------------------------------------- names that are not valid UTF-8
def _write_bytes_named(base: Path, name: bytes, content: bytes | None) -> None:
    """Create a file (or, with no content, a directory) whose name is raw bytes."""
    target = os.fsencode(base) + b"/" + name
    try:
        if content is None:
            os.mkdir(target)
        else:
            with open(target, "wb") as handle:
                handle.write(content)
    except OSError:
        pytest.skip("the filesystem cannot create a name that is not valid UTF-8")


def _non_utf8_tree(root: Path) -> None:
    _write_bytes_named(root, b"agent-\xff\xfe.py", b"from crewai import Agent\n")
    _write_bytes_named(root, b"d\xe9", None)
    _write_bytes_named(
        root, b"d\xe9/.mcp.json", b'{"mcpServers": {"tool": {"command": "npx", "args": ["-y", "tool"]}}}'
    )
    _write_bytes_named(root, b"proj\xe9", None)
    _write_bytes_named(root, b"proj\xe9/pyproject.toml", b'[project]\nname = "proj"\n')
    _write_bytes_named(root, b"proj\xe9/app.py", b"import openai\nclient = openai.OpenAI()\n")


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def test_non_utf8_names_are_escaped_in_findings_and_the_files_are_still_scanned(tmp_path, index):
    _non_utf8_tree(tmp_path)
    findings, ctx = _run(index, tmp_path)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert any(f.kind == Kind.MCP_SERVER for f in findings)
    assert any("provider.openai" in f.model_providers for f in findings)
    # The bytes that are not UTF-8 are shown as \xNN escapes: no lone surrogate reaches a reporter.
    strings = [text for f in findings for text in _strings(f.to_dict())] + ctx.stats.warnings
    for text in strings:
        text.encode("utf-8")
    assert any("agent-\\xff\\xfe.py:1" in text for text in strings)
    assert any(text == "d\\xe9/.mcp.json" for text in strings)
    assert any("proj\\xe9/app.py:1" in text for text in strings)


@pytest.mark.parametrize("fmt", ["table", "csv", "html", "json", "markdown", "sarif"])
def test_every_reporter_renders_a_repository_with_non_utf8_names(tmp_path, fmt):
    repo = tmp_path / "repo"
    repo.mkdir()
    _non_utf8_tree(repo)
    output = tmp_path / f"report.{fmt}"
    result = CliRunner().invoke(main, ["code", str(repo), "--format", fmt, "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert output.read_text(encoding="utf-8")


# ------------------------------------------------------- numeric limits
@pytest.mark.parametrize("option", ["max_file_size", "max_files", "max_entries"])
@pytest.mark.parametrize("value", [True, False, 1.9, 0, -5, "abc", [100]], ids=repr)
def test_integer_limits_reject_booleans_fractions_and_non_numbers(tmp_path, run_connector, option, value):
    # `max_file_size: true` was a 1-byte limit that skipped every file, and 1.9 became 1.
    with pytest.raises(ConnectorError) as raised:
        run_connector("code.filesystem", path=str(tmp_path), **{option: value})
    assert str(raised.value) == f"code.filesystem: {option} must be a positive integer"


@pytest.mark.parametrize("value", [True, 0, -1, 61, float("nan"), float("inf"), "soon", [2]], ids=repr)
def test_scan_timeout_must_be_a_bounded_number_of_seconds(tmp_path, run_connector, value):
    with pytest.raises(ConnectorError) as raised:
        run_connector("code.filesystem", path=str(tmp_path), scan_timeout=value)
    assert (
        str(raised.value)
        == "code.filesystem: scan_timeout must be a number of seconds above 0 and at most 60"
    )


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"max_file_size": 2048, "max_files": 10, "scan_timeout": 0.5}, (2048, 10, 0.5)),
        ({"max_file_size": "2048", "max_files": 10.0, "scan_timeout": "60"}, (2048, 10, 60.0)),
    ],
)
def test_numeric_limits_keep_accepting_numbers_and_numeric_text(config, expected):
    connector = FilesystemConnector(ConnectorContext(config={"path": ".", **config}))
    assert (connector.max_file_size, connector.max_files, connector.scan_timeout) == expected


# ------------------------------------------------------- list-typed options
@pytest.mark.parametrize(
    "value",
    ["vendor/*", "vendor", "", 5, True, {"vendor": 1}, ["vendor", 3], [None], ["  "], [""], [["vendor"]]],
    ids=repr,
)
def test_exclude_must_be_a_list_of_non_empty_strings(tmp_path, run_connector, value):
    # A bare string used to be iterated per character: "vendor/*" became the
    # patterns "/" and "*", which exclude everything from a scan reported complete.
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    with pytest.raises(ConnectorError) as raised:
        run_connector("code.filesystem", path=str(tmp_path), exclude=value)
    assert str(raised.value) == "code.filesystem: exclude must be a list of non-empty strings"


@pytest.mark.parametrize("value", ["*.png", 5, ["*.png", 1], [""], [None]], ids=repr)
def test_oversize_skip_globs_must_be_a_list_of_non_empty_strings(tmp_path, run_connector, value):
    with pytest.raises(ConnectorError) as raised:
        run_connector("code.filesystem", path=str(tmp_path), oversize_skip_globs=value)
    assert str(raised.value) == "code.filesystem: oversize_skip_globs must be a list of file name globs"


@pytest.mark.parametrize("value", ["/tmp", 5, ["ok", 3], [None], [""]], ids=repr)
def test_paths_must_be_a_list_of_non_empty_strings(tmp_path, run_connector, value):
    # A bare string was iterated per character, so "/tmp" scanned the root "/".
    with pytest.raises(ConnectorError) as raised:
        run_connector("code.filesystem", paths=value)
    assert str(raised.value) == "code.filesystem: paths must be a list of non-empty strings"


@pytest.mark.parametrize("value", [None, [], ["vendor"], ("vendor",), ["vendor", "*.min.js", "src/legacy/*"]])
def test_exclude_still_accepts_lists_of_names_and_globs(tmp_path, run_connector, value):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "app.py").write_text("from langgraph.graph import StateGraph\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), exclude=value, use_git=False)
    assert any("framework.langgraph" in f.frameworks for f in findings)
    assert not ctx.stats.errors and not ctx.stats.incomplete


def test_cli_exclude_options_reach_the_connector_as_a_list(tmp_path):
    repo = tmp_path / "repo"
    (repo / "legacy").mkdir(parents=True)
    (repo / "legacy" / "agent.py").write_text("from crewai import Agent\n")
    (repo / "app.py").write_text("from langgraph.graph import StateGraph\n")
    output = tmp_path / "report.json"
    argv = [
        "code",
        str(repo),
        "--exclude",
        "legacy",
        "--exclude",
        "*.tmp",
        "--format",
        "json",
        "-o",
        str(output),
    ]
    assert CliRunner().invoke(main, argv).exit_code == 0
    assert set(json.loads(output.read_text())["summary"]["frameworks"]) == {"framework.langgraph"}


def test_bare_string_exclude_set_on_the_command_line_fails_closed_without_echoing_it(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text("from crewai import Agent\n")
    output = tmp_path / "report.json"
    argv = ["run", "code.filesystem", "--set", f"path={repo}", "--set", "exclude=vendor/*"]
    result = CliRunner().invoke(main, [*argv, "--format", "json", "-o", str(output)])
    assert result.exit_code == 3, result.output
    report = json.loads(output.read_text())
    assert report["summary"]["complete"] is False
    errors = [error for stats in report["stats"] for error in stats["errors"]]
    assert errors and all("exclude must be a list of non-empty strings" in error for error in errors)
    assert "vendor/*" not in json.dumps(report)


# ------------------------------------------------------- planted files and link trees
def test_planted_whitespace_runs_do_not_stall_iac_or_front_matter_matching(tmp_path, index):
    # ``Action:`` followed by a long run of blank space, and a front matter
    # opener followed by a long run of blank lines, used to backtrack
    # quadratically in stdlib patterns outside the matching budget (minutes
    # per file at the default size limit, then a discarded connector result).
    (tmp_path / "main.tf").write_text("Action:" + " " * 400_000 + "\n")
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "planner.md").write_text("---\n" + "\n" * 400_000)
    (tmp_path / "crew.py").write_text("from crewai import Agent\n")
    started = time.monotonic()
    findings, ctx = _scan(index, tmp_path, use_git=False)
    assert time.monotonic() - started < 5
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any("framework.crewai" in finding.frameworks for finding in findings)


def test_bounded_iac_and_front_matter_patterns_keep_their_matches():
    from shadowscan.connectors.code.filesystem import _FRONTMATTER, _IAM_WILDCARD_RE

    for text in ('Action: "*"', 'Action = ["*"]', '"Action": [ "*" ]', '"bedrock:*"'):
        assert _IAM_WILDCARD_RE.search(text), text
    assert not _IAM_WILDCARD_RE.search('Action: "s3:GetObject"')
    assert _FRONTMATTER.match("---\nname: x\n---\nbody").group(1) == "name: x"
    assert _FRONTMATTER.match("---  \r\nname: x\r\n---\r\nbody").group(1) == "name: x\r"
    assert _FRONTMATTER.match("---\nname: x\n---") is None


def _link_tree(root: Path, count: int) -> None:
    (root / "real.py").write_text("from crewai import Agent\n")
    links = root / "links"
    links.mkdir()
    for number in range(count):
        os.symlink("../real.py", links / f"alias{number}.py")


def test_symbolic_links_count_toward_max_files(tmp_path, index):
    _link_tree(tmp_path, 50)
    findings, ctx = _scan(index, tmp_path, max_files=20, use_git=False)
    # The regular file is examined first; the links then exhaust the cap.
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert any("max_files (20) reached" in issue for issue in ctx.stats.errors)


def test_symbolic_link_checks_stop_at_the_connector_deadline(tmp_path, index, monkeypatch):
    _link_tree(tmp_path, 200)
    original = FilesystemConnector._link_target_is_scanned

    def slow(self, rel, target, root, walk=None):
        time.sleep(0.01)
        return original(self, rel, target, root, walk)

    monkeypatch.setattr(FilesystemConnector, "_link_target_is_scanned", slow)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=time.monotonic() + 1.5
    )
    started = time.monotonic()
    FilesystemConnector(ctx).run()
    # 200 links at 10 ms each would overrun a 1.5 s deadline; the walk stops
    # cooperatively and records the gap instead.
    assert time.monotonic() - started < 1.5
    assert any("deadline reached while checking symbolic links" in issue for issue in ctx.stats.errors)


def test_links_in_one_directory_list_their_ancestors_once(tmp_path, index, monkeypatch):
    _link_tree(tmp_path, 300)
    listed: list[str] = []
    real_listdir = os.listdir

    def counting_listdir(path="."):
        listed.append(str(path))
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", counting_listdir)
    _scan(index, tmp_path, use_git=False)
    # One listing of the links directory serves every link in it; before,
    # each link listed every ancestor again (quadratic in the link count).
    assert listed.count(str(tmp_path / "links")) <= 2


def test_notebook_credential_in_a_code_cell_is_counted_once(tmp_path, index):
    notebook = {
        "cells": [
            {"cell_type": "code", "source": ['API_KEY = "' + SECRET + '"\n'], "outputs": []},
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    (tmp_path / "demo.ipynb").write_text(json.dumps(notebook))
    findings, ctx = _scan(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    # The raw document repeats the cell at another line number; that is the
    # same credential, not a second one.
    assert secret.metadata["count"] == 1 and not ctx.stats.errors
    assert len([e for e in secret.evidence if e.signal.startswith("secret")]) == 1


@pytest.mark.parametrize(
    ("bom", "encoding"),
    [
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
    ],
)
@pytest.mark.parametrize(
    ("name", "text"),
    [("agent.py", "# résumé\nfrom crewai import Agent\n"), ("requirements.txt", "# résumé\ncrewai>=1\n")],
)
def test_bom_source_and_manifest_keep_detection(tmp_path, run_connector, bom, encoding, name, text):
    (tmp_path / name).write_bytes(bom + text.encode(encoding))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert not ctx.stats.incomplete and not ctx.stats.errors


def test_bom_decoding_keeps_raw_byte_limit(tmp_path):
    path = tmp_path / "agent.py"
    path.write_bytes(codecs.BOM_UTF16_LE + "from crewai import Agent\n".encode("utf-16-le"))
    errors = []
    assert read_text(path, 30, errors) is None
    assert errors == ["file exceeds max_file_size"]


@pytest.mark.parametrize("case", ["iam", "frontmatter"])
def test_hostile_iac_and_frontmatter_finish_in_external_timeout_with_neighbor_detection(tmp_path, case):
    # A separate process enforces the regression timeout even if a stdlib
    # expression regresses to holding the GIL and blocks Python watchdogs.
    relative = "attack.tf" if case == "iam" else ".claude/agents/attack.md"
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    text = "Action = " + " " * 262_144 + "!" if case == "iam" else "---" + "\n" * 262_144 + "!"
    target.write_text(text)
    (tmp_path / "neighbor.py").write_text("from crewai import Agent\n")
    script = """
import json, sys
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
ctx = ConnectorContext(config={'path': sys.argv[1], 'use_git': False, 'scan_timeout': 0.5})
findings = FilesystemConnector(ctx).run()
print(json.dumps({'frameworks': [v for f in findings for v in f.frameworks],
                  'errors': ctx.stats.errors}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    result = json.loads(completed.stdout)
    assert "framework.crewai" in result["frameworks"]


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_agent_definition_frontmatter_keeps_multiline_metadata(tmp_path, index, newline):
    ctx = ConnectorContext(config={"path": str(tmp_path)}, index=index)
    connector = FilesystemConnector(ctx)
    text = newline.join(["--- \t", "", "name: reviewer", "tools:", "  - Read", "--- \t", "Body"])
    info = connector._parse_agent_definition(".claude/agents/reviewer.md", text)
    assert info["name"] == "reviewer" and info["tools"] == ["Read"]


@pytest.mark.parametrize(
    ("name", "commented", "active"),
    [
        (
            "Dockerfile",
            "FROM python:3.12\n# RUN curl https://api.openai.com/v1/chat/completions\n"
            "# ENV OPENAI_API_KEY=example\n",
            "FROM python:3.12\nRUN curl https://api.openai.com/v1/chat/completions\n"
            "ENV OPENAI_API_KEY=example\n",
        ),
        (
            "build.gradle.kts",
            '/*\nval endpoint = "https://api.openai.com/v1/chat/completions"\n'
            'val OPENAI_API_KEY = "example"\n*/\n',
            'val endpoint = "https://api.openai.com/v1/chat/completions"\nval OPENAI_API_KEY = "example"\n',
        ),
    ],
)
def test_manifest_comment_provider_signals_do_not_establish_active_use(
    tmp_path, run_connector, name, commented, active
):
    path = tmp_path / name
    path.write_text(commented)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not any("provider.openai" in finding.model_providers for finding in findings)
    assert not ctx.stats.incomplete
    path.write_text(active)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("provider.openai" in finding.model_providers for finding in findings)
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("name", ["Dockerfile", "build.gradle.kts"])
def test_manifest_comments_still_expose_committed_credentials(tmp_path, run_connector, name):
    key = "sk-proj-" + hashlib.sha256(b"comment-credential-regression").hexdigest()
    comment = f'OPENAI_API_KEY = "{key}"'
    text = f"# {comment}\n" if name == "Dockerfile" else f"/* {comment} */\n"
    (tmp_path / name).write_text(text)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    secrets = [finding for finding in findings if finding.kind == Kind.SECRET]
    assert secrets and not ctx.stats.incomplete
    assert key not in json.dumps([finding.to_dict() for finding in findings])
