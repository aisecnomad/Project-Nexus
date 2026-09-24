"""Regressions for the production-review round: code connectors."""

from __future__ import annotations

import json
import subprocess
import time

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code import filesystem as fs_module
from shadowscan.connectors.code.filesystem import FilesystemConnector, _excerpt, _load_json_lenient
from shadowscan.connectors.code.manifests import parse_manifest
from shadowscan.connectors.code.ownership import MAX_OWNERSHIP_STEPS, OwnershipBudget, codeowners_match
from shadowscan.models import Kind, ScanStats, now_iso


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_secret_excerpt_is_redacted_before_truncation(tmp_path, index):
    key = "pplx-" + "a" * 45
    (tmp_path / "client.py").write_text('headers = {"X-Trace": "' + "p" * 100 + '", "X-Custom-Header": "' + key + '"}\n')
    findings, _ = _run(index, tmp_path)
    secrets = [f for f in findings if f.kind == Kind.SECRET]
    assert len(secrets) == 1
    serialized = json.dumps(secrets[0].to_dict())
    assert "a" * 12 not in serialized and "pplx-" not in serialized


def test_excerpt_helper_redacts_then_truncates():
    line = "x" * 150 + " key=" + "s" * 40
    assert "s" * 8 not in _excerpt([line], 1, "s" * 40)
    assert _excerpt([line], 2) == ""


def test_duplicate_manifest_and_text_observations_count_once(tmp_path, index):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nENV OPENAI_API_KEY=\n")
    findings, _ = _run(index, tmp_path)
    project = next(f for f in findings if f.resource_type == "project")
    env_evidence = [e for e in project.evidence if e.signal == "env:provider.openai"]
    assert len(env_evidence) == 1
    assert project.confidence < 0.85  # a single mention is not a confirmed agent
    (tmp_path / "Dockerfile").unlink()
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-proj-" + "b" * 40 + "\n")
    findings, _ = _run(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert secret.metadata["count"] == 1 and len(secret.evidence) == 1


def test_git_metadata_decoding_is_lenient_and_isolated(tmp_path, index, monkeypatch):
    (tmp_path / ".git").mkdir()
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": True}, index=index)
    ctx.stats = ScanStats(connector="code.filesystem", started_at=now_iso())
    connector = FilesystemConnector(ctx)
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="Jos�|j@example.test|2026-01-01T00:00:00Z", stderr="")

    monkeypatch.setattr(fs_module.subprocess, "run", fake_run)
    assert connector._git_info(tmp_path, ".")["last_author_email"] == "j@example.test"
    assert captured["encoding"] == "utf-8" and captured["errors"] == "replace"

    def failing_run(argv, **kwargs):
        raise ValueError("decode failure")

    monkeypatch.setattr(fs_module.subprocess, "run", failing_run)
    assert connector._git_info(tmp_path, ".") == {}
    assert any("git enrichment failed" in warning for warning in ctx.stats.warnings)


def test_emit_phase_failures_are_isolated_per_finding(tmp_path, index, monkeypatch):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "config.py").write_text("OPENAI_API_KEY = 'sk-proj-" + "c" * 40 + "'\n")

    def boom(self, *args, **kwargs):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(FilesystemConnector, "_secret_finding", boom)
    findings, ctx = _run(index, tmp_path)
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert any("credential analysis incomplete (RuntimeError)" in error for error in ctx.stats.errors)


def test_lenient_json_loader_only_strips_comments_when_needed():
    assert _load_json_lenient('{"a": 1}') == {"a": 1}
    assert _load_json_lenient('{"a": 1, // comment\n "b": [1,],}') == {"a": 1, "b": [1]}
    with pytest.raises(ValueError):
        _load_json_lenient("{nope")


def test_codeowners_large_monorepo_resolves_owners_without_exhausting_the_budget(tmp_path, index):
    rules = ["* @org/everyone"] + [f"/services/service-{i}/ @org/team-{i}" for i in range(2000)]
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("\n".join(rules) + "\n")
    for j in range(120):
        package = tmp_path / "packages" / f"pkg-{j}" / "src" / "agents"
        package.mkdir(parents=True)
        (package / "orchestrator.py").write_text("from crewai import Agent\n")
    started = time.monotonic()
    findings, ctx = _run(index, tmp_path)
    assert time.monotonic() - started < 20
    assert not any("budget exceeded" in error for error in ctx.stats.errors)
    project = next(f for f in findings if f.resource_type == "project")
    assert project.owner == "@org/everyone"


@pytest.mark.parametrize("pattern, path, expected", [
    ("/services/api/", "services/api/main.py", True),
    ("/services/api/", "packages/api/main.py", False),
    ("/**/api/", "packages/api/x.py", True),
    ("*.py", "a/b/c.py", True),
    ("/docs/*.md", "docs/readme.md", True),
    ("/docs/*.md", "src/docs/readme.md", False),
    ("services/*/agents/", "services/x/agents/run.py", True),
])
def test_codeowners_first_selector_short_circuit_preserves_semantics(pattern, path, expected):
    assert codeowners_match(pattern, path) is expected


def test_codeowners_non_matching_anchored_rule_is_nearly_free():
    budget = OwnershipBudget()
    assert not codeowners_match("/services/api/", "packages/api/main.py", budget)
    assert budget.remaining >= MAX_OWNERSHIP_STEPS - 5


def test_manifest_line_index_and_dockerfile_dedupe():
    result = parse_manifest("Dockerfile", "FROM python:3.12\nENV OPENAI_API_KEY=\nENV AA=1 BB=2\n")
    assert result is not None
    env = [(a.value, a.line) for a in result.artifacts if a.kind == "env"]
    assert env == [("OPENAI_API_KEY", 2), ("AA", 3), ("BB", 3)]
    values = "".join(f"APP_SETTING_{i}: value\n" for i in range(4000))
    started = time.monotonic()
    result = parse_manifest("values.yaml", values)
    assert time.monotonic() - started < 5
    assert result is not None and not result.errors
    env = [a for a in result.artifacts if a.kind == "env"]
    assert len(env) == 4000 and env[-1].line == 4000


def test_project_isolation_error_names_the_project(tmp_path, index, monkeypatch):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")

    def boom(self, *args, **kwargs):
        raise RuntimeError("synthetic")
        yield  # pragma: no cover - generator shape

    monkeypatch.setattr(FilesystemConnector, "_emit_project", boom)
    findings, ctx = _run(index, tmp_path)
    assert findings == []
    assert any("project analysis incomplete (RuntimeError)" in error for error in ctx.stats.errors)
