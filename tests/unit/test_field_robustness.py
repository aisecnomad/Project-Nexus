"""Regressions from the public-repository field review: false incomplete scans.

Ordinary repositories must not come back incomplete because of files that are
not agent configuration: JSONC editor settings, one huge test module, or a
notebook whose saved outputs push it over ``max_file_size``.
"""

from __future__ import annotations

import json
import time

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.semantic_config import is_agent_config_path, structured_code_matches
from shadowscan.connectors.code.source_semantics import (
    MAX_AST_NODES,
    SourceBudgetExceeded,
    bound_source_matches,
)
from shadowscan.models import Kind
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.jsonc import load_json_lenient, strip_json_comments

DEVCONTAINER = """// For format details, see https://aka.ms/devcontainer.json.
{
  "name": "Debian",
  "build": {"dockerfile": "Dockerfile", "context": ".."},
  /* multi-line
     block comment */
  "postStartCommand": "./scripts/bootstrap", // trailing comment
  "customizations": {"vscode": {"extensions": ["ms-python.python",],},},
}
"""
VSCODE_SETTINGS = '{\n    "python.analysis.importFormat": "relative",\n}\n'


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


# ------------------------------------------------------------------ JSONC
@pytest.mark.parametrize(("text", "expected"), [
    ('{"a": 1, // c\n "b": [1,],}', {"a": 1, "b": [1]}),
    ('{"url": "http://x//y", /* c */ "k": "v,}",}', {"url": "http://x//y", "k": "v,}"}),
    ('{"s": "quote \\" // kept", "t": [1, 2, ], }', {"s": 'quote " // kept', "t": [1, 2]}),
    ('[1, /* x */ 2, ]', [1, 2]),
    ('{"k": ",]"}', {"k": ",]"}),
])
def test_lenient_json_strips_comments_and_trailing_commas_outside_strings(text, expected):
    assert load_json_lenient(text) == expected


@pytest.mark.parametrize("text", ['{"a": /* unterminated', "{nope", '{"a": 1,, }'])
def test_lenient_json_still_rejects_invalid_documents(text):
    with pytest.raises(ValueError):
        load_json_lenient(text)


def test_block_comments_keep_line_numbers():
    stripped = strip_json_comments('{\n/* one\ntwo\nthree */\n"a": }')
    with pytest.raises(json.JSONDecodeError) as caught:
        json.loads(stripped)
    assert caught.value.lineno == 5


def test_lenient_json_is_linear_on_large_documents():
    body = "{\n" + "".join(f'  "k{i}": "v // {i}", // c\n' for i in range(50_000)) + '  "end": 0,\n}\n'
    started = time.perf_counter()
    assert load_json_lenient(body)["k7"] == "v // 7"
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize(("rel", "text"), [
    (".devcontainer/devcontainer.json", DEVCONTAINER),
    (".vscode/settings.json", VSCODE_SETTINGS),
    ("tsconfig.json", '{"compilerOptions": {"strict": true, /* why */ },}'),
])
def test_structured_config_accepts_jsonc(index, rel, text):
    errors: list[str] = []
    structured_code_matches(index, rel, text, errors)
    assert errors == []


def test_agent_config_paths_are_recognised():
    assert is_agent_config_path(".claude/settings.json")
    assert is_agent_config_path("svc/.codex/config.toml")
    assert not is_agent_config_path(".vscode/settings.json")
    assert not is_agent_config_path("tests/fixtures/broken.json")


def test_editor_jsonc_files_do_not_make_the_scan_incomplete(tmp_path, index):
    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(DEVCONTAINER)
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "settings.json").write_text(VSCODE_SETTINGS)
    _, ctx = _run(index, tmp_path)
    assert not ctx.stats.incomplete and not ctx.stats.errors and not ctx.stats.warnings


def test_malformed_ordinary_config_warns_but_agent_settings_fail_closed(tmp_path, index):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "invalid.json").write_text('{"deliberately": ')
    _, ctx = _run(index, tmp_path)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any("tests/invalid.json" in w and "structured checks skipped" in w for w in ctx.stats.warnings)

    _, strict = _run(index, tmp_path, strict_coverage=True)
    assert strict.stats.incomplete

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text('{"permissions": ')
    _, ctx = _run(index, tmp_path)
    assert ctx.stats.incomplete
    assert any(".claude/settings.json" in e for e in ctx.stats.errors)


# ---------------------------------------------------------- AST budget
def _huge_module(lines: int) -> str:
    return "from openai import OpenAI\nclient = OpenAI()\n" + "".join(f"value_{i} = [{i}, {i} + 1]\n" for i in range(lines))


def test_structural_budget_is_a_distinct_timeout(index):
    with pytest.raises(SourceBudgetExceeded) as caught:
        bound_source_matches(index, _huge_module(600), "python", [], max_ast_nodes=1_000)
    assert isinstance(caught.value, MatchTimeoutError)
    assert bound_source_matches(index, _huge_module(10), "python", []) != []
    assert MAX_AST_NODES == 50_000


def test_oversized_test_module_warns_and_keeps_lexical_evidence(tmp_path, index):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_everything.py").write_text(_huge_module(600))
    findings, ctx = _run(index, tmp_path, max_ast_nodes=1_000, include_tests=False)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any("import-bound analysis skipped" in w for w in ctx.stats.warnings)
    project = next(f for f in findings if f.resource_type == "project")
    assert "provider.openai" in project.model_providers


def test_oversized_production_module_stays_incomplete_with_its_evidence(tmp_path, index):
    (tmp_path / "service.py").write_text(_huge_module(600))
    findings, ctx = _run(index, tmp_path, max_ast_nodes=1_000)
    assert ctx.stats.incomplete
    assert any("service.py" in e and "lexical evidence retained" in e for e in ctx.stats.errors)
    assert any(f.resource_type == "project" and "provider.openai" in f.model_providers for f in findings)
    _, ctx = _run(index, tmp_path, max_ast_nodes=200_000)
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("value", [999, 2_000_001, "50000", 5.5, True])
def test_max_ast_nodes_is_validated(tmp_path, index, value):
    with pytest.raises(ConnectorError):
        _run(index, tmp_path, max_ast_nodes=value)


# ----------------------------------------------------------- notebooks
def _notebook(code: str, output_bytes: int) -> str:
    return json.dumps({
        "cells": [
            {"cell_type": "markdown", "source": ["# Crew demo\n"]},
            {"cell_type": "code", "source": code.splitlines(keepends=True),
             "outputs": [{"output_type": "display_data", "data": {"image/png": "A" * output_bytes}}]},
        ],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    })


CREW_CODE = (
    "from crewai import Agent, Crew, Task\n"
    "researcher = Agent(role='analyst', goal='g', backstory='b')\n"
    "crew = Crew(agents=[researcher], tasks=[Task(description='d', expected_output='o', agent=researcher)])\n"
    "crew.kickoff()\n"
)


def test_notebook_with_large_outputs_is_analyzed_by_code_cells(tmp_path, index):
    (tmp_path / "demo.ipynb").write_text(_notebook(CREW_CODE, 30_000))
    findings, ctx = _run(index, tmp_path, max_file_size=10_000)
    project = next(f for f in findings if f.resource_type == "project")
    assert "framework.crewai" in project.frameworks and project.kind == Kind.AGENT
    assert not ctx.stats.incomplete
    assert any("code cells analyzed" in w for w in ctx.stats.warnings)


def test_notebook_limits_still_apply(tmp_path, index):
    (tmp_path / "demo.ipynb").write_text(_notebook(CREW_CODE, 30_000))
    findings, ctx = _run(index, tmp_path, max_file_size=10_000, max_notebook_size=20_000)
    assert not any(f.resource_type == "project" for f in findings)
    assert any("demo.ipynb" in w for w in ctx.stats.warnings)
    (tmp_path / "demo.ipynb").write_text(_notebook(CREW_CODE * 40, 10))
    findings, ctx = _run(index, tmp_path, max_file_size=1_000)
    assert any("notebook code cells exceed max_file_size" in w for w in ctx.stats.warnings)
    _, strict = _run(index, tmp_path, max_file_size=1_000, strict_coverage=True)
    assert strict.stats.incomplete


@pytest.mark.parametrize("value", [0, -1, "big", 1.5])
def test_max_notebook_size_is_validated(tmp_path, index, value):
    with pytest.raises(ConnectorError):
        _run(index, tmp_path, max_notebook_size=value)
