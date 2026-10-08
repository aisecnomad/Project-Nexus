"""Tests for the real-world repository benchmark (corpus validation, checkout copies, scoring)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tools.benchmark import adapters, adapters_repo, realworld
from tools.benchmark.realworld import EVIDENCE_TYPES, STRATA, RepoCase, validate_corpus

SHA = "0" * 40


def _case(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "rw-example",
        "surface": "repo",
        "family": "py-langgraph-app",
        "label": "agent",
        "difficulty": "easy",
        "rationale": "LangGraph agent with tools.",
        "source": {"host": "github", "repo": "owner/name", "sha": SHA, "license": "MIT"},
        "stratum": "app",
        "languages": ["python"],
        "evidence": [{"type": "framework", "family": "langgraph", "paths": ["src/agent.py"]}],
    }
    base.update(overrides)
    return base


def _doc(*cases: dict[str, object]) -> dict[str, object]:
    return {"metadata": {"type": "real-world-pinned"}, "cases": list(cases)}


def test_bundled_corpus_validates_and_is_stratified() -> None:
    doc = json.loads(realworld.DEFAULT_CORPUS.read_text(encoding="utf-8"))
    cases = validate_corpus(doc)
    assert len(cases) >= 50
    labels = {c.label for c in cases}
    assert labels == {"agent", "llm", "none"}
    assert {c.stratum for c in cases} == set(STRATA)
    hosts = {c.source["host"] for c in cases}
    assert hosts == {"github", "gitlab"}
    positives = [c for c in cases if c.label != "none"]
    assert all(c.evidence for c in positives)
    assert all(c.rationale for c in cases)
    languages = {lang for c in cases for lang in c.languages}
    assert {"python", "typescript", "go", "java", "rust", "csharp"} <= languages


def test_validation_rejects_malformed_cases() -> None:
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(source={"host": "github", "repo": "owner/name", "sha": "abc"})))
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(evidence=[{"type": "magic", "paths": ["x"]}])))
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(label="none")))
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(label="llm")))
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(label="agent", evidence=[])))
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(stratum="unknown")))
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(), _case()))
    with pytest.raises(realworld.CorpusError):
        validate_corpus(_doc(_case(evidence=[{"type": "framework", "paths": ["../escape.py"]}])))
    assert validate_corpus(_doc(_case()))[0].evidence_types == {"framework"}
    none_case = _case(
        id="rw-none",
        label="none",
        stratum="plain",
        evidence=[],
        source={"host": "gitlab", "repo": "g/x/y", "sha": SHA},
    )
    assert validate_corpus(_doc(none_case))[0].label == "none"


def test_repo_case_round_trips_through_json() -> None:
    case = RepoCase.from_json(_case())
    assert RepoCase.from_json(case.to_json()) == case
    assert "checkout" not in case.to_json()


def test_tree_copies_a_checkout_without_git_and_keeps_links_as_links(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (checkout / "src").mkdir()
    (checkout / "src" / "agent.py").write_text("from langgraph.graph import StateGraph\n")
    os.symlink("/etc/hostname", checkout / "escape")
    case = RepoCase.from_json(_case())
    case.checkout = str(checkout)
    work = tmp_path / "work"
    work.mkdir()
    root = adapters.Adapter.tree(case, work, "repo")
    assert (root / "src" / "agent.py").read_text() == "from langgraph.graph import StateGraph\n"
    assert not (root / ".git").exists()
    assert (root / "escape").is_symlink()


def test_keyword_baseline_counts_words_and_config_files(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "app.py").write_text("from openai import OpenAI\nclient = OpenAI()\n")
    (checkout / "CLAUDE.md").write_text("Project notes\n")
    (checkout / "binary.bin").write_bytes(b"\0openai\0")
    case = RepoCase.from_json(_case())
    case.checkout = str(checkout)
    work = tmp_path / "work"
    work.mkdir()
    outcome = adapters_repo.KeywordBaseline().run(
        case, work, adapters.ToolEnv(root=tmp_path, python="python")
    )
    assert outcome.status == "ok" and outcome.detected and outcome.agentic
    assert outcome.evidence["provider"] == 3  # "openai" in the import, "OpenAI" twice
    assert outcome.evidence["coding-agent-config"] == 1
    assert "framework" not in outcome.evidence


def test_keyword_baseline_is_quiet_on_plain_code(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "server.go").write_text(
        'package main\nimport "net/http"\nfunc main() { http.ListenAndServe(":80", nil) }\n'
    )
    case = RepoCase.from_json(_case(label="none", stratum="plain", evidence=[]))
    case.checkout = str(checkout)
    work = tmp_path / "work"
    work.mkdir()
    outcome = adapters_repo.KeywordBaseline().run(
        case, work, adapters.ToolEnv(root=tmp_path, python="python")
    )
    assert outcome.status == "ok" and not outcome.detected


def test_shadowscan_evidence_mapping() -> None:
    findings = [
        {
            "kind": "agent",
            "resource_type": "project",
            "frameworks": ["framework.langgraph"],
            "model_providers": ["provider.openai"],
        },
        {"kind": "mcp-server", "resource_type": "mcp-config", "frameworks": ["protocol.mcp"]},
        {"kind": "mcp-server", "resource_type": "mcp-server", "frameworks": ["protocol.mcp"]},
        {
            "kind": "agent-config",
            "resource_type": "coding-agent-config",
            "evidence": [{"location": "skills/x/SKILL.md"}],
        },
        {
            "kind": "agent-config",
            "resource_type": "coding-agent-config",
            "evidence": [{"location": "CLAUDE.md"}],
        },
        {
            "kind": "framework-usage",
            "resource_type": "project",
            "frameworks": ["coding-agent.cursor", "protocol.mcp"],
        },
        {"kind": "workflow"},
        {"kind": "infra"},
        {"kind": "secret"},
        {"kind": "local-model"},
    ]
    counts = adapters.shadowscan_evidence(findings)
    assert counts == {
        "framework": 1,
        "provider": 1,
        "mcp-config": 1,
        "mcp-code": 2,
        "agent-skill": 1,
        "coding-agent-config": 2,
        "lowcode-flow": 1,
        "iac": 1,
        "credential": 1,
        "local-model": 1,
    }
    assert set(counts) <= set(EVIDENCE_TYPES)


def test_evidence_coverage_scores_only_declared_types(tmp_path: Path) -> None:
    cases = [
        RepoCase.from_json(_case(id="rw-a")),
        RepoCase.from_json(
            _case(
                id="rw-b",
                source={"host": "github", "repo": "o/b", "sha": SHA},
                evidence=[{"type": "mcp-config", "paths": [".mcp.json"]}],
            )
        ),
    ]
    rows = [
        {"case": "rw-a", "status": "ok", "detected": True, "evidence": {"framework": 3}},
        {"case": "rw-b", "status": "ok", "detected": True, "evidence": {"framework": 1}},
    ]
    (tmp_path / "tool.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    cov = realworld.evidence_coverage(tmp_path, cases, [("tool", ("framework",))])
    assert set(cov["tool"]) == {"framework"}
    assert cov["tool"]["framework"]["found"] == 1 and cov["tool"]["framework"]["labeled"] == 1
    assert cov["tool"]["framework"]["reported_on_unlabeled"] == 1


def test_adapter_evidence_types_default_to_empty() -> None:
    assert adapters_repo.adapter_evidence_types(adapters.AgentBom()) == ()
    assert "agent-skill" in adapters_repo.adapter_evidence_types(adapters_repo.CiscoSkillScanner())
