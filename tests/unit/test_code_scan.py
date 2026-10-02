from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, normalize_connector_config, validate_connector_config
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import (
    DEFAULT_EXCLUDES,
    DISCLOSED_DEFAULT_EXCLUDES,
    FilesystemConnector,
    _nearest_root,
)
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.models import Kind
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import signature_from_dict


def _by_kind(findings):
    out = {}
    for f in findings:
        out.setdefault(f.kind, []).append(f)
    return out


def test_sample_repo_scan(run_connector, fixtures):
    findings, ctx = run_connector("code.filesystem", path=str(fixtures / "sample_repo"), label="fixture")
    assert not ctx.stats.errors
    kinds = _by_kind(findings)
    projects = {f.metadata["path"]: f for f in kinds[Kind.AGENT] if f.resource_type == "project"}
    research = projects["services/research-agent"]
    assert {"framework.langgraph", "framework.langchain", "protocol.mcp", "observability.langsmith"} <= set(
        research.frameworks
    )
    assert {"provider.openai", "provider.anthropic"} <= set(research.model_providers)
    assert {"tool-use", "code-exec", "browsing", "memory"} <= set(research.capabilities)
    assert research.owner == "@acme/data-science"  # CODEOWNERS
    support = projects["services/support-bot"]
    assert "framework.vercel-ai-sdk" in support.frameworks and "protocol.mcp" in support.frameworks
    root = projects["."]
    assert {
        "framework.microsoft-agent-framework",
        "framework.langchain4j",
        "framework.spring-ai",
        "framework.langchaingo",
    } <= set(root.frameworks)
    # notebook code cells are scanned
    assert "framework.crewai" in root.frameworks

    mcp = {f.metadata["path"]: f for f in kinds[Kind.MCP_SERVER]}
    assert set(mcp) == {".mcp.json", ".cursor/mcp.json"}
    servers = {s["name"]: s for s in mcp[".mcp.json"].metadata["servers"]}
    assert servers["github"]["secrets_inline"] is True
    assert servers["zapier"]["transport"] == "http"
    assert "inline-secrets" in mcp[".mcp.json"].tags
    assert mcp[".cursor/mcp.json"].metadata["client"] == "Cursor"

    cfg = kinds[Kind.AGENT_CONFIG]
    claude = next(f for f in cfg if "coding-agent.claude-code" in f.frameworks)
    assert ".claude/agents/reviewer.md" in claude.metadata["files"]
    assert claude.metadata["agent_definitions"][0]["name"] == "code-reviewer"
    assert "autonomous" in claude.capabilities  # bypassPermissions / Bash(*)

    secrets = kinds[Kind.SECRET]
    assert len(secrets) == 1 and secrets[0].metadata["path"] == "services/research-agent/app/config.py"
    assert {"provider.openai", "provider.anthropic"} <= set(secrets[0].model_providers)
    for e in secrets[0].evidence:
        assert "sk-proj-3OoFmQTsHfOvesPLUXvRXpfToFF2XPOcdJ2kMQJ2g0" not in (
            e.description + (e.snippet or "")
        ), "secret must be redacted"

    infra = {f.metadata["path"]: f for f in kinds[Kind.INFRA]}
    assert "cloud.aws-bedrock-agents" in infra["infra/terraform/bedrock.tf"].frameworks
    assert "ops-provisioning-04" in infra["infra/terraform/bedrock.tf"].metadata["names"]
    assert {"platform.litellm", "platform.n8n"} <= set(infra["infra/docker-compose.yml"].frameworks)

    cards = [f for f in kinds[Kind.AGENT] if f.resource_type == "agent-manifest"]
    a2a = next(f for f in cards if "protocol.a2a" in f.frameworks)
    assert a2a.metadata["agent_card"]["skills"] == ["Request quote", "Issue purchase order"]
    assert "no-auth-declared" in a2a.tags
    wf = kinds[Kind.WORKFLOW]
    assert len(wf) == 1 and "platform.n8n" in wf[0].frameworks


def test_scan_ignores_noise_dirs_and_binary(tmp_path: Path, run_connector):
    (tmp_path / "node_modules" / "langchain").mkdir(parents=True)
    (tmp_path / "node_modules" / "langchain" / "index.js").write_text("import { OpenAI } from 'openai'")
    (tmp_path / "app.bin").write_bytes(b"\x00\x01" + b"from langchain import x" * 10)
    (tmp_path / "README.md").write_text("plain readme")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert findings == [] and not ctx.stats.errors


def test_scan_detects_frameworks_from_source_only(tmp_path: Path, run_connector):
    (tmp_path / "bot.py").write_text(
        "from strands import Agent\nfrom strands_tools import shell\nagent = Agent(model='us.anthropic.claude-3-7-sonnet', tools=[shell])\nagent('deploy')\n"
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    f = findings[0]
    assert f.kind == Kind.AGENT and "framework.aws-strands" in f.frameworks and "code-exec" in f.capabilities


def test_project_root_walk_uses_active_ancestors_for_nested_and_wide_repos(tmp_path: Path, index):
    for relative in ("first", "first/nested", "second"):
        project = tmp_path / relative
        project.mkdir(parents=True, exist_ok=True)
        (project / "pyproject.toml").write_text("[project]\nname='example'\n")
        (project / "bot.py").write_text("from langchain import agents\n")
    files = FilesystemConnector(ConnectorContext(config={"path": str(tmp_path)}, index=index))._iter_files(
        tmp_path
    )
    assigned = {rel: project for rel, _, project in files if rel.endswith("bot.py")}
    assert assigned == {
        "first/bot.py": "first",
        "first/nested/bot.py": "first/nested",
        "second/bot.py": "second",
    }

    active = ["."]
    for number in range(4000):
        sibling = f"repo-{number}"
        assert _nearest_root(sibling, active) == "."
        active.append(sibling)
        assert _nearest_root(f"{sibling}/src", active) == sibling
        assert len(active) == 2  # completed sibling roots must not accumulate


def test_mcp_toml_and_vscode_variants(tmp_path: Path, run_connector):
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        '[mcp_servers.fs]\ncommand = "npx"\nargs = ["-y", "@modelcontextprotocol/server-filesystem"]\n'
    )
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(
        json.dumps({"servers": {"remote": {"type": "http", "url": "http://tools.internal:8080/mcp"}}})
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    mcp = {f.metadata["path"]: f for f in findings if f.kind == Kind.MCP_SERVER}
    assert mcp[".codex/config.toml"].metadata["client"] == "OpenAI Codex"
    assert mcp[".vscode/mcp.json"].metadata["servers"][0]["url"].startswith("http://")


def test_same_text_from_distinct_signals_retains_agent_capabilities(tmp_path):
    index = SignatureIndex(
        [
            signature_from_dict(
                {
                    "id": "custom.agent",
                    "category": "framework",
                    "signals": [
                        {
                            "type": "import",
                            "languages": ["python"],
                            "patterns": [r"^from custom_sdk import execute_agent\b"],
                            "weight": 0.8,
                        },
                        {"type": "code", "patterns": [r"execute_agent\("], "weight": 0.5},
                        {
                            "type": "code",
                            "patterns": [r"execute_agent\("],
                            "weight": 0.95,
                            "agent_indicator": True,
                            "capabilities": ["code-exec"],
                        },
                    ],
                }
            )
        ]
    )
    (tmp_path / "agent.py").write_text("from custom_sdk import execute_agent\nexecute_agent()\n")
    context = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(context).run()
    project = next(f for f in findings if f.resource_type == "project")
    assert project.kind == Kind.AGENT
    assert "code-exec" in project.capabilities
    code_evidence = [e for e in project.evidence if e.signal == "code:custom.agent"]
    assert len(code_evidence) == 2
    assert {e.weight for e in code_evidence} == {0.5, 0.95}


SECRET = "sk-proj-aP9rVv3qN4zY7bC2hJ8Lm5Qw6Dt0KsX1eR7uT4p"


def _scan(index, root: Path, **config):
    ctx = ConnectorContext(config={"path": str(root), **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_directory_exclusion_names_do_not_skip_files(tmp_path, index):
    (tmp_path / "build").write_text(f"#!/bin/sh\nexport OPENAI_API_KEY={SECRET}\n")
    for config in ({}, {"exclude": ["*.log"]}):
        findings, ctx = _scan(index, tmp_path, **config)
        assert any(f.kind == Kind.SECRET for f in findings) and ctx.stats.objects_examined == 1
    (tmp_path / "build").unlink()
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.py").write_text(f"KEY = '{SECRET}'\n")
    findings, _ = _scan(index, tmp_path)
    assert not findings, "the build directory itself is still excluded"


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_duplicate_manifest_and_text_observations_count_once(tmp_path, index):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nENV OPENAI_API_KEY=\n")
    findings, _ = _run(index, tmp_path)
    project = next(f for f in findings if f.resource_type == "project")
    env_evidence = [e for e in project.evidence if e.signal == "env:provider.openai"]
    assert len(env_evidence) == 1
    assert project.confidence < 0.85  # a single mention is not a confirmed agent
    (tmp_path / "Dockerfile").unlink()
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h\n")
    findings, _ = _run(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert secret.metadata["count"] == 1 and len(secret.evidence) == 1


DIFY_APP = {
    "kind": "app",
    "app": {"mode": "chat"},
    "model_config": {"model": {"provider": "openai", "name": "gpt-4o"}},
}


def test_fixture_workflow_export_is_test_code_only(tmp_path: Path, run_connector) -> None:
    (tmp_path / "app.json").write_text(json.dumps(DIFY_APP))
    fixtures = tmp_path / "api" / "tests" / "fixtures" / "workflow"
    fixtures.mkdir(parents=True)
    (fixtures / "app.json").write_text(json.dumps(DIFY_APP))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    workflows = [f for f in findings if f.kind == Kind.WORKFLOW]
    assert len(workflows) == 2
    deployed = next(f for f in workflows if "fixtures" not in f.resource)
    fixture = next(f for f in workflows if "fixtures" in f.resource)
    assert "test-code-only" not in deployed.tags
    assert "test-code-only" in fixture.tags
    assert fixture.confidence < deployed.confidence


def test_include_tests_restores_fixture_workflow_weight(tmp_path: Path, run_connector) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "app.json").write_text(json.dumps(DIFY_APP))
    (tmp_path / "app.json").write_text(json.dumps(DIFY_APP))
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False, include_tests=True)
    workflows = [f for f in findings if f.kind == Kind.WORKFLOW]
    assert len(workflows) == 2
    assert not any("test-code-only" in f.tags for f in workflows)
    assert workflows[0].confidence == workflows[1].confidence


def _project_resources(findings) -> set[str]:
    return {f.resource for f in findings if f.kind in {Kind.FRAMEWORK_USAGE, Kind.AGENT}}


def test_module_named_setup_py_is_not_a_project_root(tmp_path: Path, run_connector) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "sdk"\ndependencies = ["openai"]\n')
    package = tmp_path / "src" / "sdk" / "tracing"
    package.mkdir(parents=True)
    (package / "setup.py").write_text(
        "import threading\n\nLOCK = threading.Lock()\n\n\ndef setup(app):\n    return app\n"
    )
    (package / "export.py").write_text("from openai import OpenAI\n\nclient = OpenAI()\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    resources = _project_resources(findings)
    assert resources == {str(tmp_path)}


@pytest.mark.parametrize(
    "script",
    [
        'from setuptools import setup\n\nsetup(name="tool", install_requires=["openai"])\n',
        'from distutils.core import setup\n\nsetup(name="tool")\n',
    ],
)
def test_packaging_setup_py_still_marks_a_project(tmp_path: Path, run_connector, script: str) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "monorepo"\n')
    tool = tmp_path / "tools" / "tool"
    tool.mkdir(parents=True)
    (tool / "setup.py").write_text(script)
    (tool / "run.py").write_text("from openai import OpenAI\n\nclient = OpenAI()\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert str(tool) in _project_resources(findings)


# ------------------------------------------------- default-excluded directories
def _frameworks(findings):
    return {framework for finding in findings for framework in finding.frameworks}


def _default_exclusion_repo(root: Path, name: str) -> None:
    (root / name).mkdir()
    (root / name / "agent.py").write_text("from crewai import Agent\n")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("from langgraph.graph import StateGraph\n")


def test_disclosed_names_are_a_subset_of_the_default_excludes():
    assert DISCLOSED_DEFAULT_EXCLUDES < DEFAULT_EXCLUDES
    quiet = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "site-packages", "__pycache__", ".idea"}
    assert quiet <= DEFAULT_EXCLUDES and not quiet & DISCLOSED_DEFAULT_EXCLUDES


@pytest.mark.parametrize("name", sorted(DISCLOSED_DEFAULT_EXCLUDES))
def test_default_excluded_directory_is_disclosed_and_can_be_scanned(tmp_path, run_connector, name):
    _default_exclusion_repo(tmp_path, name)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    # `src/` is unaffected; the skipped directory is named, and the scan is still complete.
    assert "framework.langgraph" in _frameworks(findings) and "framework.crewai" not in _frameworks(findings)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert ctx.stats.warnings == [
        f"code.filesystem: default-excluded directories not scanned: {name} (1); "
        "set default_excludes: false to scan them"
    ]
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, default_excludes=False
    )
    assert {"framework.langgraph", "framework.crewai"} <= _frameworks(findings)
    assert not ctx.stats.incomplete and not ctx.stats.warnings and not ctx.stats.errors


def test_default_excluded_directories_are_counted_by_name_at_any_depth(tmp_path, run_connector):
    for rel in ("a/bin/x.py", "b/bin/y.py", "c/vendor/z.py", "d/node_modules/n.js", "e/.git/config"):
        (tmp_path / rel).parent.mkdir(parents=True)
        (tmp_path / rel).write_text("x = 1\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    # Quiet names (dependency trees, VCS metadata) are skipped without comment.
    assert ctx.stats.warnings == [
        "code.filesystem: default-excluded directories not scanned: bin (2), vendor (1); "
        "set default_excludes: false to scan them"
    ]


def test_empty_or_absent_default_excluded_directories_are_not_disclosed(tmp_path, run_connector):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("from crewai import Agent\n")
    (tmp_path / "bin").mkdir()
    (tmp_path / "dist" / "nested" / "deeper").mkdir(parents=True)
    (tmp_path / "vendor").mkdir()
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.errors and not ctx.stats.incomplete


def test_explicitly_excluded_default_name_is_not_disclosed(tmp_path, run_connector):
    for name in ("vendor", "bin"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "x.py").write_text("x = 1\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, exclude=["vendor"])
    assert ctx.stats.warnings == [
        "code.filesystem: default-excluded directories not scanned: bin (1); "
        "set default_excludes: false to scan them"
    ]


def test_explicit_exclude_still_applies_when_defaults_are_off(tmp_path, run_connector):
    _default_exclusion_repo(tmp_path, "vendor")
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, default_excludes=False, exclude=["vendor"]
    )
    assert "framework.crewai" not in _frameworks(findings) and not ctx.stats.warnings


def test_version_control_metadata_stays_excluded_when_defaults_are_off(tmp_path, run_connector):
    # Its index and objects are binary: scanning them would make every checkout incomplete.
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "index").write_bytes(b"DIRC\x00\x00\x00\x02" + b"\x00" * 64)
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, default_excludes=False
    )
    assert "framework.crewai" in _frameworks(findings)
    assert not ctx.stats.errors and not ctx.stats.incomplete and not ctx.stats.warnings


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_symlink_named_like_a_disclosed_directory_is_not_probed(tmp_path, run_connector):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "agent.py").write_text("from crewai import Agent\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "vendor").symlink_to(outside, target_is_directory=True)
    findings, ctx = run_connector("code.filesystem", path=str(repo), use_git=False)
    assert not findings and not ctx.stats.warnings


def test_default_excludes_must_be_a_boolean(tmp_path, run_connector):
    with pytest.raises(Exception, match="default_excludes must be a boolean"):
        run_connector("code.filesystem", path=str(tmp_path), default_excludes="false")
    assert "default_excludes" in FilesystemConnector.config_keys


def test_default_exclusion_disclosure_is_per_root_and_names_the_root_of_a_multi_root_scan(
    tmp_path, run_connector
):
    roots = []
    for index_number in (1, 2):
        root = tmp_path / f"repo{index_number}"
        root.mkdir()
        (root / "vendor").mkdir()
        (root / "vendor" / "x.py").write_text("x = 1\n")
        roots.append(str(root))
    _, ctx = run_connector("code.filesystem", paths=roots, use_git=False)
    assert len(ctx.stats.warnings) == 2
    assert all("default-excluded directories not scanned: vendor (1)" in w for w in ctx.stats.warnings)
    assert any("repo1" in w for w in ctx.stats.warnings) and any("repo2" in w for w in ctx.stats.warnings)


def _cli_report(tmp_path: Path, *args: str) -> tuple[int, dict]:
    output = tmp_path / "report.json"
    argv = ["code", str(tmp_path / "repo"), *args, "--format", "json", "-o", str(output)]
    result = CliRunner().invoke(main, argv)
    return result.exit_code, json.loads(output.read_text())


def test_cli_no_default_excludes_scans_the_built_in_excluded_directories(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _default_exclusion_repo(repo, "bin")
    code, report = _cli_report(tmp_path)
    assert code == 0 and report["summary"]["complete"] is True
    assert "framework.crewai" not in report["summary"]["frameworks"]
    warnings = [w for stats in report["stats"] for w in stats["warnings"]]
    assert any("default-excluded directories not scanned: bin (1)" in w for w in warnings)

    code, report = _cli_report(tmp_path, "--no-default-excludes")
    assert code == 0 and report["summary"]["complete"] is True
    assert {"framework.crewai", "framework.langgraph"} <= set(report["summary"]["frameworks"])
    assert not [w for stats in report["stats"] for w in stats["warnings"]]


@pytest.mark.parametrize("name", ["code.filesystem", "code.github", "code.gitlab"])
def test_default_excludes_is_a_listed_boolean_option_of_every_code_connector(name):
    validate_connector_config(name, {"default_excludes": False})
    # Environment interpolation yields strings; they are normalized, not guessed.
    assert normalize_connector_config(name, {"default_excludes": "false"})["default_excludes"] is False
    with pytest.raises(ConfigValidationError, match="default_excludes"):
        normalize_connector_config(name, {"default_excludes": "off"})


@pytest.mark.parametrize(
    ("cls", "config"), [(GitHubConnector, {"org": "acme"}), (GitLabConnector, {"group": "acme"})]
)
def test_remote_checkout_scans_receive_the_default_excludes_option(cls, config):
    connector = cls(ConnectorContext(config={**config, "default_excludes": False}))
    assert connector._filesystem_options()["default_excludes"] is False


# ------------------------------------------------- Python that does not parse
_LANGCHAIN_AGENT = "from langchain.agents import AgentExecutor\nexecutor = AgentExecutor(agent=a, tools=[])\n"


def _parses(source: str) -> bool:
    try:
        ast.parse(source)
    except SyntaxError:
        return False
    return True


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pep695.py", "type Alias = int\n" + _LANGCHAIN_AGENT),  # Python 3.12 syntax
        ("python2.py", 'print "starting"\n' + _LANGCHAIN_AGENT),
        ("broken.py", "def broken(:\n    pass\n" + _LANGCHAIN_AGENT),
    ],
)
def test_python_that_does_not_parse_warns_that_the_import_binder_was_skipped(
    tmp_path, run_connector, name, content
):
    if name.endswith(".py") and _parses(content):
        pytest.skip("the running Python can parse this snippet")
    (tmp_path / name).write_text(content)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    # Not a gap in what was asked of the scan (the lexical evidence stays), but never silent.
    assert ctx.stats.warnings == [
        f"code.filesystem: {name}: import-bound analysis skipped (source did not parse); "
        "lexical evidence retained"
    ]
    assert not ctx.stats.errors and not ctx.stats.incomplete
    # The construction is kept as lexical evidence, corroborated by the import, as in a
    # language without a binder; it used to be dropped, leaving only "LLM usage".
    assert any(
        finding.kind == Kind.AGENT and "framework.langchain" in finding.frameworks for finding in findings
    )


def _notebook(*cells: str) -> str:
    return json.dumps({"cells": [{"cell_type": "code", "source": [cell]} for cell in cells]})


@pytest.mark.parametrize(
    "setup",
    [
        "%pip install langchain langchain-openai\n",
        "!pip install langchain\n",
        "%matplotlib inline\n%load_ext autoreload\n",
        "%%time\nimport json\n",
        "for package in ['langchain']:\n    !pip install {package}\n",
    ],
    ids=["pip-magic", "shell", "line-magics", "cell-magic", "indented-shell"],
)
def test_notebook_magics_and_shell_lines_keep_the_import_binder(tmp_path, run_connector, setup):
    # IPython rewrites these lines before Python sees them. They used to make the
    # whole notebook unparseable, so its agent construction became "LLM usage".
    (tmp_path / "agent.ipynb").write_text(_notebook(setup, _LANGCHAIN_AGENT))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.errors
    assert any(finding.kind == Kind.AGENT for finding in findings)


def test_percent_continuation_lines_in_a_notebook_are_python(tmp_path, run_connector):
    # "% name" continuing an expression is the modulo operator, not a magic.
    cell = 'greeting = ("Hello %s"\n            % name)\n' + _LANGCHAIN_AGENT
    (tmp_path / "agent.ipynb").write_text(_notebook(cell))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.errors
    assert any(finding.kind == Kind.AGENT for finding in findings)


@pytest.mark.parametrize(
    "broken",
    [
        'notes = """scratch cell, left unfinished\n',  # used to mask every later cell: no finding at all
        "params = dict(\n",
        '%%bash\necho "it\'s done"\n',
    ],
    ids=["unterminated-string", "unclosed-bracket", "shell-cell"],
)
def test_one_broken_notebook_cell_does_not_hide_the_others(tmp_path, run_connector, broken):
    # Jupyter runs each cell on its own: a cell that does not parse fails alone.
    (tmp_path / "agent.ipynb").write_text(_notebook(broken, _LANGCHAIN_AGENT))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "code.filesystem: agent.ipynb: import-bound analysis skipped for notebook cell 1, which does not "
        "parse; lexical evidence retained"
    ]
    assert any(finding.kind == Kind.AGENT for finding in findings)


def test_a_broken_notebook_cell_keeps_its_own_construction(tmp_path, run_connector):
    setup = "from langchain.agents import AgentExecutor\n"
    broken = "executor = AgentExecutor(agent=a, tools=[])\nresult = (\n"
    (tmp_path / "agent.ipynb").write_text(_notebook(setup, broken))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert any("notebook cell 2" in warning for warning in ctx.stats.warnings)
    # The construction in the cell the binder could not read counts as lexical evidence.
    assert any(finding.kind == Kind.AGENT for finding in findings)


def test_python_that_parses_keeps_import_bound_evidence_without_a_warning(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text(_LANGCHAIN_AGENT)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.errors
    assert any(finding.kind == Kind.AGENT for finding in findings)


# ------------------------------------------- directories named like an SDK
_SDK_APP = (
    "from openai import OpenAI\nfrom langchain.agents import AgentExecutor\n"
    "client = OpenAI()\nexecutor = AgentExecutor(agent=a, tools=[])\n"
)


def _sdk_names_repo(root: Path, layout: dict[str, str | None]) -> None:
    (root / "app.py").write_text(_SDK_APP)
    for rel, content in layout.items():
        target = root / rel
        if content is None:
            target.mkdir(parents=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)


@pytest.mark.parametrize(
    "layout",
    [
        {"openai": None, "agents": None, "langchain": None},
        {"openai/data.json": "{}", "langchain/notes.txt": "x", "agents/model.pyi": "x"},
        {"src/openai": None, "src/langchain": None},
    ],
    ids=["empty-directories", "data-only-directories", "empty-src-directories"],
)
def test_directories_named_like_an_sdk_without_python_do_not_hide_its_imports(
    tmp_path, run_connector, layout
):
    _sdk_names_repo(tmp_path, layout)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("provider.openai" in f.model_providers for f in findings)
    assert any("framework.langchain" in f.frameworks for f in findings)
    assert not ctx.stats.errors and not ctx.stats.incomplete


@pytest.mark.parametrize(
    "layout",
    [
        {"openai/__init__.py": "", "langchain/__init__.py": ""},
        {"openai/client.py": "x = 1\n", "langchain/agents/executor.py": "x = 1\n"},
        {"openai.py": "x = 1\n", "langchain.py": "x = 1\n"},
    ],
    ids=["packages", "namespace-packages-with-modules", "modules"],
)
def test_local_code_named_like_an_sdk_still_is_not_the_sdk(tmp_path, run_connector, layout):
    _sdk_names_repo(tmp_path, layout)
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not any("provider.openai" in f.model_providers for f in findings)
    assert not any("framework.langchain" in f.frameworks for f in findings)
