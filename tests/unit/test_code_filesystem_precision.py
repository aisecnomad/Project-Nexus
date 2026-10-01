"""code.filesystem coverage and precision regressions found in field scans.

Instruction-file aliases, test-path credential shapes, env-name-only coding
agents, CI lockfiles parsed as MCP and oversize recorded fixtures each marked a
scan incomplete or reported evidence the tree does not support. The paired
controls pin the cases that must keep their finding or their coverage gap.
Credentials are assembled at runtime so no key-shaped literal appears here.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shadowscan.models import Kind

OPENAI_LIKE_KEY = "sk-proj-" + "Xk29fLq8Zr1mNvB4" + "tYc7Hs0pWe3Ja6Ud9GiKo5Rb2Ex"

needs_symlinks = pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def scan(run_connector, root: Path, **config):
    findings, ctx = run_connector("code.filesystem", path=str(root), label="repo", use_git=False, **config)
    return findings, ctx.stats


def kinds(findings) -> list[Kind]:
    return [f.kind for f in findings]


def agent_configs(findings) -> list[str]:
    return sorted(f.frameworks[0] for f in findings if f.kind == Kind.AGENT_CONFIG)


# ---------------------------------------------------------------- instruction aliases
@needs_symlinks
@pytest.mark.parametrize("strict", [False, True])
def test_instruction_doc_alias_in_same_project_is_covered(run_connector, tmp_path, strict):
    write(tmp_path, "AGENTS.md", "Repository instructions.\n")
    (tmp_path / "CLAUDE.md").symlink_to("AGENTS.md")
    findings, stats = scan(run_connector, tmp_path, strict_coverage=strict)
    assert not stats.errors and not stats.incomplete
    assert agent_configs(findings) == ["coding-agent.agents-md"]


@needs_symlinks
def test_instruction_doc_alias_into_another_project_stays_a_gap(run_connector, tmp_path):
    write(tmp_path, "AGENTS.md", "Repository instructions.\n")
    write(tmp_path, "pkg/pyproject.toml", "[project]\nname = 'pkg'\n")
    (tmp_path / "pkg" / "CLAUDE.md").symlink_to("../AGENTS.md")
    _, stats = scan(run_connector, tmp_path)
    assert stats.incomplete


@needs_symlinks
def test_instruction_doc_alias_from_a_test_path_stays_a_gap(run_connector, tmp_path):
    write(tmp_path, "AGENTS.md", "Repository instructions.\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "CLAUDE.md").symlink_to("../AGENTS.md")
    _, stats = scan(run_connector, tmp_path)
    assert stats.incomplete


@needs_symlinks
def test_instruction_doc_alias_to_a_directory_stays_a_gap(run_connector, tmp_path):
    write(tmp_path, "docs/AGENTS.md", "Repository instructions.\n")
    (tmp_path / "CLAUDE.md").symlink_to("docs")
    _, stats = scan(run_connector, tmp_path)
    assert stats.incomplete


# ---------------------------------------------------------------- test-path credentials
@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("tests/harness/test_detectors.py", f'KEY = "{OPENAI_LIKE_KEY}"\n'),
        ("tests/cassettes/session.yaml", f"headers:\n  authorization: Bearer {OPENAI_LIKE_KEY}\n"),
        ("tests/.env", f"OPENAI_API_KEY={OPENAI_LIKE_KEY}\n"),
    ],
)
def test_secret_shapes_in_test_paths_are_not_live_secrets(run_connector, tmp_path, rel, text):
    write(tmp_path, rel, text)
    findings, stats = scan(run_connector, tmp_path)
    assert Kind.SECRET not in kinds(findings) and not stats.errors
    assert OPENAI_LIKE_KEY not in json.dumps([f.to_dict() for f in findings])
    # include_tests restores the previous credential weight, still redacted.
    findings, _ = scan(run_connector, tmp_path, include_tests=True)
    assert Kind.SECRET in kinds(findings)
    assert OPENAI_LIKE_KEY not in json.dumps([f.to_dict() for f in findings])


def test_secret_outside_test_paths_is_still_reported(run_connector, tmp_path):
    write(tmp_path, "app/settings.py", f'KEY = "{OPENAI_LIKE_KEY}"\n')
    findings, _ = scan(run_connector, tmp_path)
    assert kinds(findings).count(Kind.SECRET) == 1
    assert OPENAI_LIKE_KEY not in json.dumps([f.to_dict() for f in findings])


# ---------------------------------------------------------------- coding-agent evidence
def test_env_name_alone_is_not_a_configured_coding_agent(run_connector, tmp_path):
    write(tmp_path, "runtime_env.py", 'import os\nos.environ["GOOSE_PROVIDER"] = "openai"\n')
    findings, stats = scan(run_connector, tmp_path)
    assert agent_configs(findings) == [] and not stats.errors


def test_goose_config_file_is_still_a_configured_coding_agent(run_connector, tmp_path):
    write(tmp_path, ".goosehints", "Be concise.\n")
    findings, _ = scan(run_connector, tmp_path)
    assert agent_configs(findings) == ["coding-agent.goose"]


GEMINI_YOLO_WORKFLOW = """\
name: triage
on: [issues]
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          settings: '{"approvalMode": "yolo"}'
"""


def test_workflow_code_and_dependency_signals_still_establish_a_coding_agent(run_connector, tmp_path):
    write(tmp_path, ".github/workflows/triage.yml", GEMINI_YOLO_WORKFLOW)
    findings, _ = scan(run_connector, tmp_path)
    assert agent_configs(findings) == ["coding-agent.gemini-cli"]
    aider = tmp_path / "aider-app"
    write(aider, "requirements.txt", "aider-chat==0.50.0\n")
    findings, _ = scan(run_connector, aider)
    assert agent_configs(findings) == ["coding-agent.aider"]


def test_coding_agent_mentions_in_test_paths_describe_tests_not_deployments(run_connector, tmp_path):
    write(tmp_path, "tests/fixtures/triage.yml", GEMINI_YOLO_WORKFLOW)
    write(tmp_path, "tests/test_detect.py", 'CASE = "npx @google/gemini-cli"\n')
    findings, _ = scan(run_connector, tmp_path)
    assert agent_configs(findings) == []
    findings, _ = scan(run_connector, tmp_path, include_tests=True)
    assert agent_configs(findings) == ["coding-agent.gemini-cli"]


# ---------------------------------------------------------------- MCP parsing
@pytest.mark.parametrize(
    "rel",
    [
        ".github/workflows/ci.lock.yml",
        ".github/workflows/ci.lock.yaml",
        ".github/workflows/matrix.yml",
        "{{cookiecutter.slug}}/mcp-config.json",
    ],
)
def test_ci_lockfiles_workflows_and_templates_are_not_mcp_configs(run_connector, tmp_path, rel):
    write(tmp_path, rel, '# generated\nmcp:\n  note: matrix\nservers:\n  - name: runner\n"mcpServers": {}\n')
    findings, stats = scan(run_connector, tmp_path)
    assert Kind.MCP_SERVER not in kinds(findings) and not stats.errors and not stats.incomplete


def test_real_mcp_config_is_still_parsed(run_connector, tmp_path):
    write(tmp_path, ".mcp.json", '{"mcpServers": {"x": {"command": "npx", "args": ["-y", "pkg"]}}}\n')
    findings, stats = scan(run_connector, tmp_path)
    assert Kind.MCP_SERVER in kinds(findings) and not stats.errors


# ---------------------------------------------------------------- oversize files
OVERSIZE = "x: " + "y" * 400 + "\n"


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize(
    "rel",
    [
        "tests/cassettes/session.yaml",
        "pkg/fixtures/recorded.json",
        "docs/seed-memory/graph.json",
        "recordings/login_cassette.yaml",
        "recordings/login.cassette",
    ],
)
def test_oversize_recorded_fixtures_are_declared_omissions(run_connector, tmp_path, rel, strict):
    write(tmp_path, rel, OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100, strict_coverage=strict)
    assert stats.warnings and not stats.errors and not stats.incomplete


@pytest.mark.parametrize(
    "rel",
    [
        "tests/test_big.py",
        "docs/seed-memory/loader.py",
        "config/settings.yaml",
        "src/agent.py",
    ],
)
def test_oversize_source_and_config_stay_coverage_gaps(run_connector, tmp_path, rel):
    write(tmp_path, rel, OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert stats.warnings and not stats.errors and stats.incomplete
    _, stats = scan(run_connector, tmp_path, max_file_size=100, strict_coverage=True)
    assert stats.errors and stats.incomplete
