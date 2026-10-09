"""code.filesystem coverage and precision regressions found in field scans.

Instruction-file aliases, env-name-only coding agents and CI lockfiles parsed
as MCP each marked a scan incomplete or reported evidence the tree does not
support. Test-path credentials stay findings at the test-code weight, and
oversize recorded fixtures stay coverage gaps. The paired controls pin the
cases that must keep their finding or their coverage gap.
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
def test_credentials_in_test_paths_are_downweighted_not_dropped(run_connector, tmp_path, rel, text):
    # Recorded cassettes capture real traffic, and a key committed under tests/
    # is exposed like any other: it stays a finding, at the test-code weight.
    write(tmp_path, rel, text)
    findings, stats = scan(run_connector, tmp_path)
    secrets = [f for f in findings if f.kind == Kind.SECRET]
    assert len(secrets) == 1 and not stats.errors
    assert "test-code-only" in secrets[0].tags
    assert OPENAI_LIKE_KEY not in json.dumps([f.to_dict() for f in findings])
    included, _ = scan(run_connector, tmp_path, include_tests=True)
    full = [f for f in included if f.kind == Kind.SECRET]
    assert len(full) == 1 and "test-code-only" not in full[0].tags
    assert secrets[0].confidence < full[0].confidence
    assert OPENAI_LIKE_KEY not in json.dumps([f.to_dict() for f in included])


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


@pytest.mark.parametrize(
    "rel",
    [
        "docs/seed-memory/graph.json",
        "recordings/login_cassette.yaml",
        "data/session.yaml",
    ],
)
def test_oversize_recorded_fixtures_stay_coverage_gaps(run_connector, tmp_path, rel):
    # Recorded fixtures outside test paths can hold real credentials; skipping
    # them unread is the operator's decision (oversize_skip_globs), never a
    # silent default.
    write(tmp_path, rel, OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert stats.warnings and not stats.errors and stats.incomplete


@pytest.mark.parametrize(
    "rel", ["tests/cassettes/session.yaml", "pkg/fixtures/recorded.json", "tests/test_big.py"]
)
def test_oversize_test_fixtures_are_disclosed_without_a_gap(run_connector, tmp_path, rel):
    # Test code is discounted evidence that cannot establish a deployment, so an
    # oversize cassette or fixture is a disclosed omission while include_tests
    # is false and nothing reads it for credentials; with include_tests, with
    # credential detection (the default) or under strict_coverage, it is a gap.
    write(tmp_path, rel, OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100, scan_secrets=False)
    assert not stats.errors and not stats.incomplete
    assert [w for w in stats.warnings if rel in w and "skipped oversize test fixture" in w]
    _, stats = scan(run_connector, tmp_path, max_file_size=100, scan_secrets=False, include_tests=True)
    assert stats.warnings and not stats.errors and stats.incomplete
    _, stats = scan(run_connector, tmp_path, max_file_size=100, scan_secrets=False, strict_coverage=True)
    assert stats.errors and stats.incomplete
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert stats.warnings and not stats.errors and stats.incomplete


def test_oversize_test_fixtures_are_counted(run_connector, tmp_path, index):
    from shadowscan.connectors.base import ConnectorContext
    from shadowscan.connectors.code.filesystem import FilesystemConnector

    write(tmp_path, "tests/cassettes/a.yaml", OVERSIZE)
    write(tmp_path, "tests/cassettes/b.yaml", OVERSIZE)
    write(tmp_path, "src/app.py", "from crewai import Agent\n")
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False, "max_file_size": 100, "scan_secrets": False},
        index=index,
    )
    connector = FilesystemConnector(ctx)
    findings = connector.run()
    assert connector.skipped_oversize_test_fixtures == 2
    # The count reaches the report as one summary warning per root.
    assert [w for w in ctx.stats.warnings if "2 oversize test fixture(s) skipped unread" in w]
    assert not ctx.stats.incomplete
    assert [f.frameworks for f in findings if f.resource_type == "project"] == [["framework.crewai"]]


@pytest.mark.parametrize(
    "rel", ["CHANGELOG.md", "CHANGES.md", "HISTORY.txt", "NEWS.txt", "docs/guide.md", "notes.txt"]
)
def test_oversize_documentation_is_disclosed_without_a_gap(run_connector, tmp_path, rel):
    # Prose is matched by file name only (_scan_content never reads its body), so
    # with credential detection off an unread copy loses nothing: a warning, not
    # incomplete coverage. With credential detection on (the default) a change
    # log is read for credentials like any other prose, so it stays a gap.
    write(tmp_path, rel, OVERSIZE)
    write(tmp_path, "app.py", "from crewai import Agent\n")
    findings, stats = scan(run_connector, tmp_path, max_file_size=100, scan_secrets=False)
    assert not stats.errors and not stats.incomplete
    assert [w for w in stats.warnings if rel in w and "max_file_size" in w]
    assert [f.frameworks for f in findings if f.resource_type == "project"] == [["framework.crewai"]]
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert stats.incomplete and not stats.errors


@pytest.mark.parametrize(
    "rel",
    ["history_store.py", "HistoryService.java", "changes.ts", "changelog_parser.go", "CHANGELOG.md", "CHANGES"],
)
def test_oversize_change_log_names_never_hide_read_content(run_connector, tmp_path, rel):
    # A scanned repository chooses its file names: a source file or a change
    # log over max_file_size may hide a key or SDK use, so with credential
    # detection on (the default) it is a recorded gap, never a silent exit 0.
    write(tmp_path, rel, f"import openai\nOPENAI_API_KEY = '{OPENAI_LIKE_KEY}'\n" + "#" * 2000 + "\n")
    findings, stats = scan(run_connector, tmp_path, max_file_size=1000)
    assert not findings
    assert stats.incomplete and not stats.errors
    assert [w for w in stats.warnings if rel in w and "coverage incomplete" in w]


@pytest.mark.parametrize("rel", ["README.md", "docs/setup.txt", "tests/cassettes/login.yaml"])
def test_oversize_documentation_and_fixtures_read_for_credentials_stay_gaps(run_connector, tmp_path, rel):
    # Every read file, prose and fixtures included, is scanned for credentials,
    # so a planted key in an oversize README is found below the limit and is a
    # recorded coverage gap above it: never an unread file and exit 0.
    body = f"Run it:\n\n    export OPENAI_API_KEY={OPENAI_LIKE_KEY}\n"
    write(tmp_path, rel, body)
    findings, stats = scan(run_connector, tmp_path)
    assert Kind.SECRET in kinds(findings) and not stats.incomplete
    write(tmp_path, rel, body + "x" * 2000)
    findings, stats = scan(run_connector, tmp_path, max_file_size=1000)
    assert Kind.SECRET not in kinds(findings)
    assert stats.incomplete and not stats.errors
    assert [w for w in stats.warnings if rel in w and "coverage incomplete" in w]


@pytest.mark.parametrize(
    "rel", [".claude/agents/reviewer.md", "CLAUDE.md", "AGENTS.md", ".cursor/rules/style.mdc"]
)
def test_oversize_agent_documents_stay_coverage_gaps(run_connector, tmp_path, rel):
    # Coding-agent instructions and agent definitions are parsed: unread, they
    # could hide an agent, so they keep the gap whatever their extension.
    write(tmp_path, rel, OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert stats.warnings and not stats.errors and stats.incomplete


@pytest.mark.parametrize(
    "rel", ["gradle.lockfile", "Package.resolved", "deno.lock", "Cartfile.resolved", "bun.lockb"]
)
def test_oversize_lockfiles_are_never_coverage_gaps(run_connector, tmp_path, rel):
    write(tmp_path, rel, OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert not stats.errors and not stats.incomplete


def test_operator_skip_globs_declare_recorded_fixtures_omitted(run_connector, tmp_path):
    write(tmp_path, "tests/cassettes/session.yaml", OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100, oversize_skip_globs=["*/cassettes/*"])
    assert stats.warnings and not stats.errors and not stats.incomplete


@pytest.mark.parametrize(
    "rel",
    [
        "tools/big.py",
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


def test_oversize_file_the_scanner_never_reads_is_ignored_silently(run_connector, tmp_path):
    # Neither source, configuration, a manifest nor a file-name signal: as below
    # the limit, nothing is read and nothing is said (tests/ or not).
    write(tmp_path, "tests/weights/model.bin", OVERSIZE)
    write(tmp_path, "data/model.bin", OVERSIZE)
    _, stats = scan(run_connector, tmp_path, max_file_size=100)
    assert not stats.warnings and not stats.errors and not stats.incomplete


# ---------------------------------------------------------------- model identifiers
def _project(findings):
    return next((f for f in findings if f.resource_type == "project"), None)


def test_model_literal_in_source_names_the_provider_at_medium_weight(run_connector, tmp_path):
    write(
        tmp_path,
        "app.py",
        'MODEL = "claude-3-5-sonnet-20241022"\n\ndef ask(client, prompt):\n    return client(MODEL, prompt)\n',
    )
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and not stats.incomplete
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.anthropic"]
    assert project.metadata["models"] == ["claude-3-5-sonnet-20241022"]
    assert project.confidence <= 0.6 and "model-ids-only" in project.tags
    assert project.metadata["confidence_cap"] == {"reason": "model-ids-only", "maximum": 0.6}
    evidence = [e for e in project.evidence if e.signal == "model:provider.anthropic"]
    assert evidence and evidence[0].weight == pytest.approx(0.5) and evidence[0].location == "app.py:1"


def test_model_literal_in_a_notebook_cell_counts(run_connector, tmp_path):
    notebook = {
        "cells": [
            {"cell_type": "markdown", "source": ["# gpt-4o notes\n"], "metadata": {}},
            {"cell_type": "code", "source": ["model = 'gpt-4o'\n"], "metadata": {}, "outputs": []},
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    write(tmp_path, "experiments/eval.ipynb", json.dumps(notebook))
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and not stats.incomplete
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.openai"]
    assert project.metadata["models"] == ["gpt-4o"]


def test_model_route_in_yaml_attributes_the_route_and_the_vendor(run_connector, tmp_path):
    write(tmp_path, "config/agent.yaml", "llm:\n  model: bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0\n")
    write(tmp_path, "agent.py", "import boto3\n\nclient = boto3.client('bedrock-runtime')\n")
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and not stats.incomplete
    project = _project(findings)
    assert project is not None
    assert {"provider.aws-bedrock", "provider.anthropic"} <= set(project.model_providers)
    assert "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0" in project.metadata["models"]
    assert "model-ids-only" not in project.tags


LOOKALIKE_MODEL_IDS = [
    # Hugging Face families and tooling whose names start like OpenAI ids.
    "gpt-neox-20b",
    "gpt-j-6b",
    "gpt-3-encoder",
    "gpt-tokenizer",
    "gpt-4all",
    "gpt4all",
    "gpt-engineer",
    "gpt-researcher",
    "gpt-pilot",
    "o1-visa",
    "o1-x",
    "o3-build",
    "EleutherAI/gpt-neox-20b",
    "openai/gpt-tokenizer",
    "grok-1-formatter",
    "qwen-agent",
    "qwen-code",
]


def test_model_ids_in_documentation_and_ordinary_strings_count_for_nothing(run_connector, tmp_path):
    write(tmp_path, "README.md", 'model = "claude-3-5-sonnet-20241022"\nmodel: gpt-4o\n')
    write(tmp_path, "notes.txt", "default_model: gemini-1.5-pro\n")
    write(tmp_path, "shop.py", 'a = "amazon.com"\nb = "o1ne"\nc = "tts-config"\nd = "command-line"\n')
    write(
        tmp_path,
        "cached.py",
        '# model = "claude-3-5-sonnet-20241022" (an old default, see the comment)\nx = 1\n',
    )
    write(tmp_path, "lookalikes.py", "".join(f'v{i} = "{v}"\n' for i, v in enumerate(LOOKALIKE_MODEL_IDS)))
    write(tmp_path, "gen.py", 'pipeline("text-generation", model="EleutherAI/gpt-neox-20b")\n')
    write(tmp_path, "package.json", '{"dependencies": {"gpt-tokenizer": "^2.1", "gpt-3-encoder": "^1.1"}}\n')
    findings, stats = scan(run_connector, tmp_path)
    assert findings == [] and not stats.errors and not stats.warnings


def test_lookalike_model_ids_do_not_join_an_established_project(run_connector, tmp_path):
    write(
        tmp_path,
        "package.json",
        '{"dependencies": {"@anthropic-ai/sdk": "^0.30", "gpt-tokenizer": "^2.1"}}\n',
    )
    write(tmp_path, "src/count.js", 'import { encode } from "gpt-tokenizer";\nconst m = "gpt-4o-mini";\n')
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None
    assert project.model_providers == ["provider.anthropic", "provider.openai"]
    assert project.metadata["models"] == ["gpt-4o-mini"]


@pytest.mark.parametrize(
    ("value", "providers"),
    [
        ("gpt-5-codex", ["provider.openai"]),
        ("gpt-oss-120b", ["provider.openai"]),
        ("o3-deep-research", ["provider.openai"]),
        ("o1-2024-12-17", ["provider.openai"]),
        ("grok-code-fast-1", ["provider.xai"]),
        ("qwen2.5-coder-7b-instruct", ["provider.alibaba-dashscope"]),
        ("openrouter/anthropic/claude-3.5-sonnet", ["provider.anthropic", "provider.openrouter"]),
    ],
)
def test_vendor_shaped_model_ids_still_count(run_connector, tmp_path, value, providers):
    write(tmp_path, "app.py", f'MODEL = "{value}"\n')
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None and sorted(project.model_providers) == providers


def test_dotted_properties_keys_name_the_model(run_connector, tmp_path):
    # Spring AI's dotted keys are the .properties idiom.
    write(
        tmp_path, "src/main/resources/application.properties", "spring.ai.openai.chat.options.model=gpt-4o\n"
    )
    write(tmp_path, "pom.xml", "<project><dependencies></dependencies></project>\n")
    write(tmp_path, "src/main/java/App.java", "class App {}\n")
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    notes = [w for w in stats.warnings if "evidence not reported" in w]
    assert len(notes) == 1 and "application.properties" in notes[0]
    assert _project(findings) is None
    write(
        tmp_path,
        "pom.xml",
        "<project><dependencies><dependency><groupId>com.openai</groupId>"
        "<artifactId>openai-java</artifactId></dependency></dependencies></project>\n",
    )
    findings, stats = scan(run_connector, tmp_path)
    project = _project(findings)
    assert project is not None and project.metadata["models"] == ["gpt-4o"]


def test_model_ids_in_a_leaderboard_are_catalog_mentions(run_connector, tmp_path):
    table = "".join(
        f"- model: {model}\n  score: 1\n"
        for model in [
            "gpt-4o",
            "claude-3-5-sonnet-20241022",
            "gemini-1.5-pro",
            "mistral-large-latest",
            "grok-2",
            "deepseek-chat",
            "command-r-plus",
            "gpt-4-turbo",
        ]
    )
    write(tmp_path, "website/_data/leaderboard.yml", table)
    findings, stats = scan(run_connector, tmp_path)
    assert findings == [] and not stats.errors and not stats.incomplete
    # Beside an installed SDK the table is listed as a catalog and only that
    # SDK's models count; a model id in a data file never anchors a project.
    write(tmp_path, "requirements.txt", "openai>=1.0\n")
    findings, stats = scan(run_connector, tmp_path)
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.openai"]
    assert project.metadata["catalog_mentions"]["files"] == ["website/_data/leaderboard.yml"]
    assert "model-ids-only" not in project.tags


def test_model_literal_pass_is_bounded_per_file(run_connector, tmp_path):
    from shadowscan.connectors.code.filesystem import MAX_MODEL_LITERALS_PER_FILE

    literals = "\n".join(
        f'x{n} = "claude-3-5-sonnet-{n:08d}"' for n in range(MAX_MODEL_LITERALS_PER_FILE + 50)
    )
    write(tmp_path, "many.py", literals + "\n")
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and stats.incomplete
    assert [w for w in stats.warnings if "many.py" in w and "model identifiers" in w]
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.anthropic"]
    assert len([e for e in project.evidence if e.signal == "model:provider.anthropic"]) == 3


def test_model_literal_after_the_limit_is_an_incomplete_scan(run_connector, tmp_path):
    from shadowscan.connectors.code.filesystem import MAX_MODEL_LITERALS_PER_FILE

    source = "\n".join(f'x{n} = "ordinary-{n}"' for n in range(MAX_MODEL_LITERALS_PER_FILE))
    write(tmp_path, "app.py", source + '\nmodel = "claude-3-5-sonnet-20241022"\n')
    findings, stats = scan(run_connector, tmp_path)
    assert not findings
    assert stats.incomplete
    assert any("later ones were not matched" in warning for warning in stats.warnings)


def test_exactly_the_model_literal_limit_keeps_complete_coverage(run_connector, tmp_path):
    from shadowscan.connectors.code.filesystem import MAX_MODEL_LITERALS_PER_FILE

    source = "\n".join(f'x{n} = "ordinary-{n}"' for n in range(MAX_MODEL_LITERALS_PER_FILE - 1))
    write(tmp_path, "app.py", source + '\nmodel = "claude-3-5-sonnet-20241022"\n')
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.incomplete
    assert _project(findings).model_providers == ["provider.anthropic"]


@pytest.mark.parametrize("limit_kind", ["assignments", "path-literals", "references"])
def test_catalog_analysis_limits_make_the_scan_incomplete(run_connector, tmp_path, limit_kind):
    from shadowscan.connectors.code.catalogs import (
        MAX_ASSIGNMENT_LINES,
        MAX_PATH_LITERALS,
        MAX_REFERENCES_PER_FILE,
    )

    if limit_kind == "assignments":
        content = "OTHER_VALUE=1\n" * MAX_ASSIGNMENT_LINES + "OPENAI_API_KEY=configured\n"
        write(tmp_path, "etc/settings.cfg", content)
    else:
        content = (
            'load("a.json")\n' * MAX_PATH_LITERALS
            if limit_kind == "path-literals"
            else "".join(f'load("file-{n}.json")\n' for n in range(MAX_REFERENCES_PER_FILE))
        )
        write(tmp_path, "app.py", content + 'load("late.json")\n')
    # Other successfully analyzed files retain their findings.
    write(tmp_path, "requirements.txt", "openai==1.0\n")
    findings, stats = scan(run_connector, tmp_path, scan_secrets=False)
    assert stats.incomplete
    assert any("catalog" in error and "limit exceeded" in error for error in stats.errors)
    assert _project(findings).model_providers == ["provider.openai"]


# ---------------------------------------------------------------- uncorroborated code patterns
def test_lexical_framework_pattern_without_its_library_is_potential(run_connector, tmp_path):
    # Goose: a Rust create_agent( is not LangChain. The crate's own framework is
    # established by its dependency; the LangChain pattern is evidence only.
    write(tmp_path, "Cargo.toml", '[package]\nname = "goose"\n\n[dependencies]\nrig-core = "0.5"\n')
    write(tmp_path, "src/agents.rs", "pub fn build() -> Agent { create_agent(config()) }\n")
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and not stats.incomplete
    project = _project(findings)
    assert project is not None and project.frameworks == ["framework.rig"]
    assert project.metadata["potential_frameworks"] == ["framework.langchain"]
    assert "Spring AI" not in project.title and "LangChain" not in project.title
    evidence = [e for e in project.evidence if e.signal == "code:framework.langchain"]
    assert evidence and evidence[0].weight == pytest.approx(0.6)
    assert evidence[0].attributes["confidence_group"] == "uncorroborated-lexical"


def test_spring_ai_trait_name_in_rust_is_not_spring_ai(run_connector, tmp_path):
    # 0xPlaygrounds/rig: `pub trait ToolCallback` titled a finding "Spring AI".
    write(tmp_path, "Cargo.toml", '[package]\nname = "rig-core"\n\n[dependencies]\nrig-core = "0.5"\n')
    write(
        tmp_path, "src/serve/adapters.rs", "pub trait ToolCallback: Send + Sync {\n    fn call(&self);\n}\n"
    )
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None and "framework.spring-ai" not in project.frameworks
    assert "framework.spring-ai" not in project.metadata.get("potential_frameworks", [])


@pytest.mark.parametrize(
    "rel,text,signature",
    [
        ("Program.cs", "class P { void M() { AgentType.Validate(settings); } }\n", "framework.langchain"),
        ("src/main.rs", "fn main() { handoff(task); }\n", "framework.openai-agents-sdk"),
        ("src/graph.rs", "fn build() { let g = GraphBuilder(); }\n", "framework.aws-strands"),
        ("tool.py", "shell = ShellTool()\nprint(shell)\n", "framework.langchain"),
    ],
)
def test_unbound_code_pattern_alone_establishes_nothing(run_connector, tmp_path, rel, text, signature):
    write(tmp_path, rel, text)
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and not stats.incomplete
    assert all(signature not in f.frameworks for f in findings)
    assert _project(findings) is None
    if rel != "tool.py":  # the Python binder drops the bundled pattern, so there is nothing to note
        notes = [w for w in stats.warnings if "evidence not reported" in w]
        assert len(notes) == 1 and rel in notes[0]


# ---------------------------------------------------------------- OpenAI-compatible call shape
def test_openai_request_shape_follows_the_imported_sdk(run_connector, tmp_path):
    # huggingface/agents-course scripts/translation.py: InferenceClient speaks
    # the OpenAI shape; the shape alone names neither OpenAI nor a second provider.
    write(
        tmp_path,
        "scripts/translation.py",
        "from huggingface_hub import InferenceClient\n\nclient = InferenceClient()\n"
        'reply = client.chat.completions.create(model="x", messages=[])\n',
    )
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.huggingface"]
    write(
        tmp_path,
        "scripts/translation.py",
        'from openai import OpenAI\n\nclient = OpenAI()\nreply = client.chat.completions.create(model="gpt-4o", messages=[])\n',
    )
    findings, stats = scan(run_connector, tmp_path)
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.openai"]


# ---------------------------------------------------------------- mentions in test data
def test_provider_host_in_test_data_alone_yields_a_note_not_a_finding(run_connector, tmp_path):
    # faisalman/ua-parser-js: huggingface.co inside test/data/ua/extension/crawler.json
    # produced a 0.075-confidence provider finding.
    write(tmp_path, "package.json", json.dumps({"name": "ua-parser-js"}))
    write(
        tmp_path,
        "test/data/ua/extension/crawler.json",
        json.dumps([{"ua": "bot", "url": "https://api.anthropic.com/"}]),
    )
    findings, stats = scan(run_connector, tmp_path)
    assert findings == [] and not stats.errors and not stats.incomplete
    notes = [w for w in stats.warnings if "evidence not reported" in w]
    assert len(notes) == 1 and "test/data/ua/extension/crawler.json" in notes[0]
    # The same host in configuration still establishes the provider.
    write(tmp_path, "src/config.json", json.dumps({"endpoint": "https://api.anthropic.com/"}))
    findings, stats = scan(run_connector, tmp_path)
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.anthropic"]
    assert not [w for w in stats.warnings if "evidence not reported" in w]


def test_weak_mention_beside_an_established_provider_is_potential(run_connector, tmp_path):
    # A model-hub link in a comment is a hint written as corroboration only.
    write(
        tmp_path,
        "app.py",
        "from openai import OpenAI\n\n# weights: https://huggingface.co/meta-llama/Llama-3-8b\nclient = OpenAI()\n",
    )
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.openai"]
    assert project.metadata["potential_providers"] == ["provider.huggingface"]
    assert [e.weight for e in project.evidence if e.signal == "domain:provider.huggingface"] == [
        pytest.approx(0.15)
    ]


@pytest.mark.parametrize("host", ["api-inference.huggingface.co", "router.huggingface.co"])
def test_inference_hosts_establish_the_provider(run_connector, tmp_path, host):
    write(tmp_path, "app.py", f'import requests\n\nrequests.post("https://{host}/v1/chat/completions")\n')
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None and project.model_providers == ["provider.huggingface"]
    assert "potential_providers" not in project.metadata


# ---------------------------------------------------------------- CI job images
MCP_SDK_IMAGE = "modelcontextprotocol/python-sdk"


def test_ci_job_image_alone_yields_a_note_not_a_finding(run_connector, tmp_path):
    # pydantic/pydantic .github/workflows/third-party.yml: a job that tests the
    # MCP SDK in its container is not infrastructure provisioning MCP.
    write(
        tmp_path,
        ".github/workflows/third-party.yml",
        f"jobs:\n  mcp:\n    runs-on: ubuntu-latest\n    container:\n      image: {MCP_SDK_IMAGE}\n",
    )
    findings, stats = scan(run_connector, tmp_path)
    assert findings == [] and not stats.errors and not stats.incomplete
    notes = [w for w in stats.warnings if "evidence not reported" in w]
    assert len(notes) == 1 and ".github/workflows/third-party.yml" in notes[0]


@pytest.mark.parametrize("rel", [".gitlab-ci.yml", ".circleci/config.yml", "ci/azure-pipelines.yml"])
def test_ci_job_image_is_a_scaled_mention_beside_real_evidence(run_connector, tmp_path, rel):
    write(tmp_path, rel, f"test:\n  image: {MCP_SDK_IMAGE}\n  script:\n    - pytest\n")
    write(tmp_path, "requirements.txt", "openai>=1.0\n")
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    assert not [f for f in findings if f.kind == Kind.INFRA]
    project = _project(findings)
    assert project is not None and "protocol.mcp" not in project.frameworks
    assert project.metadata["potential_frameworks"] == ["protocol.mcp"]
    [weight] = [e.weight for e in project.evidence if e.signal == "image:protocol.mcp"]
    assert weight < 0.3


def test_ci_job_image_does_not_corroborate_a_lexical_pattern(run_connector, tmp_path):
    # A pipeline image and an unbound Java pattern each establish nothing; two
    # mentions do not add up to the protocol.
    write(
        tmp_path,
        ".github/workflows/t.yml",
        "jobs:\n  t:\n    container:\n      image: ghcr.io/modelcontextprotocol/python-sdk:latest\n",
    )
    write(tmp_path, "pom.xml", "<project><dependencies></dependencies></project>\n")
    write(
        tmp_path, "src/main/java/App.java", "class App { void r() { new MCPClient(); McpClient.sync(t); } }\n"
    )
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    assert not [f for f in findings if f.resource_type == "project" and "protocol.mcp" in f.frameworks]
    assert [w for w in stats.warnings if "evidence not reported" in w]


def test_deployed_image_keeps_full_weight_and_the_infra_finding(run_connector, tmp_path):
    write(tmp_path, "docker-compose.yml", f"services:\n  mcp:\n    image: {MCP_SDK_IMAGE}\n")
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors and not [w for w in stats.warnings if "evidence not reported" in w]
    infra = [f for f in findings if f.kind == Kind.INFRA]
    assert len(infra) == 1 and infra[0].frameworks == ["protocol.mcp"] and infra[0].confidence >= 0.8


# ---------------------------------------------------------------- documentation fences
def test_fenced_example_in_a_readme_is_not_framework_usage(run_connector, tmp_path):
    write(
        tmp_path,
        "README.md",
        "# Demo\n\n```python\nfrom langchain.agents import create_agent\nagent = create_agent(model, tools=[])\n```\n",
    )
    findings, stats = scan(run_connector, tmp_path)
    assert findings == [] and not stats.errors and not stats.warnings


def test_file_names_are_never_model_ids(run_connector, tmp_path):
    # Aider names SonarQube's configuration file in a list of special files.
    write(tmp_path, "requirements.txt", "openai==1.0\n")
    write(
        tmp_path, "app/special.py", 'import openai\nNAMES = ["sonar-project.properties", "gpt-4-notes.md"]\n'
    )
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None and "provider.perplexity" not in project.model_providers
    assert not project.metadata.get("models")


def test_rust_test_modules_are_test_paths(run_connector, tmp_path):
    # Rig keeps provider fixtures in tests.rs modules beside the code they test.
    write(tmp_path, "Cargo.toml", '[package]\nname = "rig-core"\n\n[dependencies]\nrig-core = "0.5"\n')
    write(
        tmp_path,
        "src/providers/openai/wire/tests.rs",
        'const M: &str = "accounts/fireworks/models/llama-3.3-70b";\n',
    )
    write(
        tmp_path, "src/client/voyage_tests.rs", 'const M: &str = "accounts/fireworks/models/llama-3.3-70b";\n'
    )
    findings, stats = scan(run_connector, tmp_path)
    assert not stats.errors
    project = _project(findings)
    assert project is not None and "provider.fireworks" not in project.model_providers


def test_provider_domain_in_crawler_ua_string_is_discounted(tmp_path, run_connector):
    """Regression for the real-world benchmark's only ShadowScan false positive.

    A user-agent parser's crawler fixture quotes provider sites inside UA
    strings; the domain identifies the bot's operator, not provider use.
    The mention is discounted with a visible note and the scan stays
    complete; a genuine API host in code is unaffected.
    """
    fixture = tmp_path / "test" / "data"
    fixture.mkdir(parents=True)
    fixture.joinpath("crawler.json").write_text(
        '[{"ua": "Mozilla/5.0 (compatible; HuggingFace-Bot/1.0; +https://huggingface.co/)"}]\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not findings
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any(
        "crawler user-agent strings" in warning and "huggingface.co" in warning
        for warning in ctx.stats.warnings
    )


def test_provider_domain_outside_ua_strings_still_counts(tmp_path, run_connector):
    (tmp_path / "settings.json").write_text('{"endpoint": "https://api.anthropic.com/v1/messages"}\n')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("provider.anthropic" in {e.signature for e in f.evidence} for f in findings)
    assert not any("user-agent" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("indent", [None, 2])
@pytest.mark.parametrize(
    "user_agent",
    [
        "Mozilla/5.0",
        "Mozilla/5.0 (compatible; SomeBot/1.0; +https://api.anthropic.com/)",
    ],
)
def test_crawler_ua_does_not_hide_separate_provider_endpoint(tmp_path, run_connector, indent, user_agent):
    (tmp_path / "settings.json").write_text(
        json.dumps(
            {"user_agent": user_agent, "endpoint": "https://api.anthropic.com/v1/messages"},
            indent=indent,
        )
        + "\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("provider.anthropic" in {e.signature for e in f.evidence} for f in findings)
    assert not ctx.stats.incomplete
