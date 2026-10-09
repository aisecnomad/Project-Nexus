"""Tests for the real-world benchmark harness (sampling, annotation ledger, scoring)."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from tools.realbench import adapters, frames, labels, packet, sample, score


def test_awesome_list_links_keep_repositories_and_drop_site_pages() -> None:
    markdown = """
    - [A](https://github.com/Owner/Repo) and [again](https://github.com/owner/repo#readme)
    - [docs](https://github.com/owner/other/blob/main/README.md)
    - [topic](https://github.com/topics/ai) [sponsor](https://github.com/sponsors/someone)
    - [git](https://github.com/x/y.git)
    """
    assert frames.github_links(markdown) == [
        "https://github.com/Owner/Repo",
        "https://github.com/owner/other",
        "https://github.com/x/y",
    ]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://github.com/Owner/Repo/tree/main/x",
            ("github.com/owner/repo", "github.com/owner", "github"),
        ),
        (
            "https://gitlab.com/group/sub/project",
            ("gitlab.com/group/sub/project", "gitlab.com/group", "gitlab"),
        ),
        (
            "https://gitlab.com/group/project/-/tree/main",
            ("gitlab.com/group/project", "gitlab.com/group", "gitlab"),
        ),
        ("https://github.com/onlyowner", None),
        ("https://example.com/a/b", None),
    ],
)
def test_repo_keys_identify_the_repository_and_its_owner(
    url: str, expected: tuple[str, str, str] | None
) -> None:
    assert sample.repo_key(url) == expected


def test_two_stage_draw_is_seeded_and_without_replacement() -> None:
    def cand(frame: str, i: int) -> sample.Candidate:
        return sample.Candidate(f"u{i}", f"github.com/o{i}/r", f"github.com/o{i}", "github", "s", frame)

    pools = [[cand("big", i) for i in range(50)], [cand("small", i) for i in range(50, 53)]]
    first = [c.key for c in sample.two_stage(pools, random.Random("1:s"))]
    second = [c.key for c in sample.two_stage(pools, random.Random("1:s"))]
    assert first == second
    assert len(first) == len(set(first)) == 53
    # The small frame is drawn as often as the big one until it runs out.
    assert sum(k.startswith("github.com/o5") and len(k) == len("github.com/o50/r") for k in first[:10]) >= 1


def test_redaction_removes_credentials_but_keeps_code() -> None:
    assert labels.redact('client = OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz0123")') == (
        'client = OpenAI(api_key="<redacted>")'
    )
    assert labels.redact("from langchain_community.vectorstores import FAISS") == (
        "from langchain_community.vectorstores import FAISS"
    )
    assert len(labels.redact("x" * 300)) == labels.MAX_EXCERPT


def _write_repo(tmp_path: Path) -> Path:
    root = tmp_path / "r001"
    (root / "src").mkdir(parents=True)
    (root / "src" / "agent.py").write_text("import os\nagent = create_react_agent(model,  tools)\n")
    return root


def test_evidence_must_exist_on_or_next_to_the_cited_line(tmp_path: Path) -> None:
    root = _write_repo(tmp_path)
    good = {
        "path": "src/agent.py",
        "line": 2,
        "criterion": "A1",
        "excerpt": "create_react_agent(model, tools)",
    }
    assert labels.check_evidence(root, good) is None
    assert labels.check_evidence(root, {**good, "line": 1}) is None  # adjacent line tolerated
    assert "outside" in str(labels.check_evidence(root, {**good, "line": 9}))
    assert "not found" in str(labels.check_evidence(root, {**good, "excerpt": "Crew(agents=[a])"}))
    assert "bad path" in str(labels.check_evidence(root, {**good, "path": "../secret"}))


def test_validation_rejects_inconsistent_rows(tmp_path: Path) -> None:
    root = _write_repo(tmp_path)
    row = {
        "id": "r001", "label": "llm", "assistant_artifacts": False, "ml_only": False, "subtypes": ["A1"],
        "traits": [], "confidence": "high",
        "evidence": [{"path": "src/agent.py", "line": 2, "criterion": "A1", "excerpt": "create_react_agent"}],
    }  # fmt: skip
    problems = labels.validate_row(row, root)
    assert any("needs a L subtype" in p for p in problems)
    assert any("llm label with an A subtype" in p for p in problems)
    assert labels.validate_row({**row, "label": "agent"}, root) == []


def _ann(i: str, label: str, assistant: bool = False, who: str = "A") -> dict[str, object]:
    return {
        "id": i, "annotator": who, "label": label, "assistant_artifacts": assistant, "ml_only": False,
        "subtypes": ["A1"] if label == "agent" else (["L1"] if label == "llm" else []), "traits": [],
        "evidence": [], "confidence": "high",
    }  # fmt: skip


def test_kappa_and_agreement() -> None:
    assert labels.cohen_kappa(["a", "b", "a", "b"], ["a", "b", "a", "b"]) == pytest.approx(1.0)
    assert labels.cohen_kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"]) == pytest.approx(0.0)
    a = [_ann("r1", "agent"), _ann("r2", "none"), _ann("r3", "llm")]
    b = [_ann("r1", "agent", who="B"), _ann("r2", "llm", who="B"), _ann("r3", "llm", who="B")]
    result = labels.agreement(a, b)
    assert result["label"]["agreement"] == pytest.approx(2 / 3)
    assert labels.disagreements(a, b) == ["r2"]


def test_freeze_requires_adjudication_for_disagreements() -> None:
    a = [_ann("r1", "agent"), _ann("r2", "none")]
    b = [_ann("r1", "agent", who="B"), _ann("r2", "llm", who="B")]
    with pytest.raises(ValueError, match="no adjudication"):
        labels.freeze(a, b, [])
    adjudication = [{**_ann("r2", "llm", who="adjudicator"), "reason": "calls the model in a cron job"}]
    frozen = {r["id"]: r for r in labels.freeze(a, b, adjudication)}
    assert frozen["r2"]["label"] == "llm" and frozen["r2"]["provenance"]["adjudicated"]
    assert frozen["r1"]["label"] == "agent" and not frozen["r1"]["provenance"]["adjudicated"]


def _row(status: str, detected: bool, agentic: bool | None = None) -> dict[str, object]:
    return {"status": status, "detected": detected, "agentic": agentic}


def test_strict_rule_gives_no_verdict_for_incomplete_scans() -> None:
    assert score.verdict(_row("ok", True), "t1") is True
    assert score.verdict(_row("ok", False), "t1") is False
    assert score.verdict(_row("partial", True), "t1") is None
    assert score.verdict(_row("partial", True), "t1", "evidence") is True
    assert score.verdict(_row("partial", False), "t1", "evidence") is None
    assert score.verdict(_row("error", False), "t1") is None
    assert score.verdict(_row("ok", True, agentic=False), "t2") is False


def test_no_verdict_is_a_wrong_answer_unless_completed_only() -> None:
    pairs: list[tuple[bool, bool | None]] = [(True, True), (True, None), (False, None), (False, False)]
    strict = score.confusion(pairs)
    assert (strict["tp"], strict["fn"], strict["fp"], strict["tn"], strict["no_verdict"]) == (1, 1, 1, 1, 2)
    completed = score.confusion(pairs, completed_only=True)
    assert (completed["tp"], completed["fn"], completed["fp"], completed["tn"]) == (1, 0, 0, 1)


def test_assistant_only_repositories_leave_the_primary_population() -> None:
    labs = {
        "r1": {"label": "none", "assistant_artifacts": True},
        "r2": {"label": "none", "assistant_artifacts": False},
        "r3": {"label": "llm", "assistant_artifacts": True},
    }
    pops = score.populations(labs)
    assert pops["primary"](labs["r1"], "t1") is None
    assert pops["footprint"](labs["r1"], "t1") is True
    assert pops["primary"](labs["r3"], "t2") is False
    assert pops["t2_without_assistant_negatives"](labs["r3"], "t2") is None


def test_holm_and_prevalence_adjustment() -> None:
    adjusted = score.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adjusted == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})
    assert score.ppv(0.9, 0.9, 0.5) == pytest.approx(0.9)
    assert score.ppv(0.9, 0.95, 0.01) == pytest.approx(0.009 / (0.009 + 0.0495))


def test_reported_locations_become_repository_relative_paths(tmp_path: Path) -> None:
    repo = tmp_path / "r001"
    assert adapters.relpath(f"{repo}/src/a.py:12", repo) == "src/a.py"
    assert adapters.relpath("file://" + str(repo / "b.ts"), repo) == "b.ts"
    assert adapters.relpath("./c/d.json", repo) == "c/d.json"
    assert adapters.relpath("/etc/passwd", repo) is None
    assert adapters.relpath("../x", repo) is None


def test_manifest_baseline_reads_direct_dependencies(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "web").mkdir(parents=True)
    (repo / "node_modules" / "x").mkdir(parents=True)
    (repo / "requirements.txt").write_text("requests==2.32\nlanggraph>=1.0  # agents\n")
    (repo / "web" / "package.json").write_text(json.dumps({"dependencies": {"ai": "5", "react": "19"}}))
    (repo / "node_modules" / "x" / "package.json").write_text(json.dumps({"dependencies": {"openai": "4"}}))
    out = adapters.ManifestDeps().scan(repo, tmp_path / "work", adapters.ToolEnv(tmp_path, "python3"))
    assert out.detected and out.agentic
    assert out.paths == ["requirements.txt", "web/package.json"]
    assert set(out.kinds) == {"ai", "langgraph"}
    (repo / "requirements.txt").write_text("scikit-learn\n")
    (repo / "web" / "package.json").write_text(json.dumps({"dependencies": {"react": "19"}}))
    out = adapters.ManifestDeps().scan(repo, tmp_path / "work", adapters.ToolEnv(tmp_path, "python3"))
    assert not out.detected and out.agentic is False


def test_packet_manifest_parser_lists_package_json_sections(tmp_path: Path) -> None:
    path = tmp_path / "package.json"
    path.write_text(json.dumps({"dependencies": {"openai": "4"}, "devDependencies": {"vitest": "2"}}))
    assert packet.manifest_dependencies(path) == ["openai (dependencies)", "vitest (devDependencies)"]


def test_prerun_packets_hide_which_annotator_wrote_which(tmp_path: Path) -> None:
    from tools.realbench import adjudicate

    a = [_ann("r1", "agent"), _ann("r2", "none")]
    b = [_ann("r1", "agent", who="B"), _ann("r2", "llm", who="B")]
    repos = {"r1": {"url": "u1", "sha": "s1"}, "r2": {"url": "u2", "sha": "s2"}}
    assert adjudicate.prerun(a, b, repos, tmp_path) == ["r2"]
    text = (tmp_path / "r2.md").read_text()
    assert "Annotation 1" in text and "Annotation 2" in text
    assert "annotator" not in text.lower().replace("annotation", "")
    order = json.loads((tmp_path / "order.json").read_text())
    assert sorted(order["r2"]) == ["A", "B"]


def test_postrun_queue_pools_cited_files_without_tool_names(tmp_path: Path) -> None:
    from tools.realbench import adjudicate

    labs = {
        "r1": {"label": "none", "assistant_artifacts": False, "evidence": []},
        "r2": {"label": "llm", "assistant_artifacts": False, "evidence": []},
    }
    results = {
        "tool-x": {
            "r1": {"status": "ok", "detected": True, "agentic": False, "paths": ["a.py"]},
            "r2": {"status": "ok", "detected": True, "agentic": False, "paths": ["b.py"]},
        },
        "tool-y": {
            "r1": {"status": "partial", "detected": True, "agentic": None, "paths": ["a.py", "c.md"]},
            "r2": {"status": "ok", "detected": True, "agentic": None, "paths": ["b.py"]},
        },
    }
    repos = {"r1": {"url": "u1", "sha": "s1"}, "r2": {"url": "u2", "sha": "s2"}}
    assert adjudicate.postrun(labs, results, repos, tmp_path) == ["r1"]
    text = (tmp_path / "r1.md").read_text()
    assert "- a.py (2)" in text and "- c.md (1)" in text
    assert "tool-x" not in text and "tool-y" not in text


def test_localisation_sample_is_seeded_and_judged_once_per_file() -> None:
    from tools.realbench import adjudicate

    rows = {
        f"r{i}": {"status": "ok", "detected": True, "agentic": None, "paths": [f"f{i}.py"]} for i in range(40)
    }
    results = {"one": rows, "two": rows}
    first = adjudicate.localisation_sample(results)
    assert first == adjudicate.localisation_sample(results)
    keys = [item["key"] for item in first]
    assert len(keys) == len(set(keys))
    assert all(len(item["tools"]) in (1, 2) for item in first)
    decisions = [{"item": item["item"], "verdict": "ai-evidence"} for item in first]
    audit = adjudicate.audit(first, decisions)
    assert audit["one"]["n"] == adjudicate.PER_TOOL and audit["one"]["precision"][0] == 1.0


def test_apply_records_every_changed_label() -> None:
    from tools.realbench import adjudicate

    doc = {
        "labels": [
            {"id": "r1", "label": "none", "assistant_artifacts": False, "subtypes": [], "evidence": []}
        ]
    }
    decision = {
        "id": "r1", "label": "llm", "assistant_artifacts": False, "subtypes": ["L1"], "reason": "calls a model",
        "evidence": [{"path": "a.py", "line": 3, "criterion": "L1", "excerpt": "client.responses.create("}],
    }  # fmt: skip
    out = adjudicate.apply(doc, [decision])["labels"][0]
    assert out["label"] == "llm" and out["postrun"] == {
        "reviewed": True, "changed": True, "from": "none", "from_assistant": False, "reason": "calls a model",
    }  # fmt: skip
    assert out["evidence"][0]["path"] == "a.py"


def test_shadowscan_agentic_follows_the_scanner_metadata() -> None:
    # PROTOCOL.md §13.3: the scanner's own metadata.agentic, not the kind list.
    from tools.realbench.adapters import shadowscan_agentic

    assistant = {
        "kind": "agent-config",
        "metadata": {"agent_type": "coding-assistant-config", "agentic": False},
    }
    server = {"kind": "framework-usage", "metadata": {"agent_type": "mcp-client", "agentic": True}}
    assert shadowscan_agentic([assistant]) is False
    assert shadowscan_agentic([assistant, server]) is True
    assert shadowscan_agentic([{"kind": "agent"}]) is False  # a report without the field claims nothing


def test_rows_keep_the_kind_rule_for_shadowscan_only() -> None:
    from tools.realbench.adapters import Outcome
    from tools.realbench.run import _row

    assert _row("h001", Outcome("ok", agentic=False, agentic_kinds=True), None)["agentic_kinds"] is True
    assert "agentic_kinds" not in _row("h001", Outcome("ok", agentic=True), None)
