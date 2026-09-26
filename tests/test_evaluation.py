"""Verify evaluation counts, corpus boundaries, and offline scanner integration."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from tools.evaluation.benchmark import benchmark
from tools.evaluation.evaluate import (
    DEFAULT_CORPUS,
    CorpusError,
    calibration,
    evaluate,
    load_corpus,
    main,
    summarize,
)


def _corpus(files: dict[str, str], *, present: bool = False, assertions: dict | None = None) -> dict:
    return {
        "schema": 1,
        "metadata": {"name": "test", "type": "synthetic", "provenance": "unit test"},
        "cases": [
            {
                "id": "plain-code",
                "family": "agent",
                "description": "A deliberately plain source file",
                "files": files,
                "target": {"kind": "agent", "signature": "framework.langgraph"},
                "present": present,
                "assertions": assertions or {},
            }
        ],
    }


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_bundled_corpus_has_positive_and_hard_negative_labels():
    meta, cases, digest = load_corpus(DEFAULT_CORPUS)
    assert meta["type"] == "synthetic" and len(digest) == 64
    assert len(cases) >= 25 and {c.family for c in cases} >= {"agent", "mcp-server", "framework-usage"}
    for family in {c.family for c in cases}:
        assert {c.present for c in cases if c.family == family} == {True, False}
    assert {"mcp-empty-json", "mcp-disabled-json", "py-comment-agent", "ts-block-comment-agent"} <= {
        c.id for c in cases
    }


def test_lexer_and_toml_layout_cases_have_distinct_narrow_labels():
    _, cases, _ = load_corpus(DEFAULT_CORPUS)
    by_id = {case.id: case for case in cases}
    for case_id in (
        "py-fstring-interpolated-agent",
        "js-regex-then-agent",
        "mcp-toml-table-active",
        "mcp-toml-dotted-active",
    ):
        assert by_id[case_id].present
    for case_id in ("py-fstring-literal-agent", "jsx-text-agent"):
        assert not by_id[case_id].present
    assert "{StateGraph(dict)}" in by_id["py-fstring-interpolated-agent"].files["agent.py"]
    assert "{{StateGraph(dict)}}" in by_id["py-fstring-literal-agent"].files["agent.py"]
    assert "const graph = new StateGraph()" in by_id["js-regex-then-agent"].files["agent.js"]
    for case_id in ("mcp-toml-table-active", "mcp-toml-dotted-active"):
        assert by_id[case_id].assertions == {"server_count": 1, "server_names": ["active"]}


def test_pinned_public_snapshots_have_verifiable_source_attribution():
    public = DEFAULT_CORPUS.with_name("public_corpus.json")
    meta, cases, _ = load_corpus(public)
    assert meta["type"] == "public-pinned"
    assert len(cases) == 5
    assert len({case.source["commit"] for case in cases}) == 2
    assert {case.present for case in cases} == {True, False}
    assert all(case.source["url"].startswith("https://github.com/") for case in cases)


def test_counts_have_explicit_undefined_denominators():
    rows = [
        {"family": "one", "present": True, "predicted": True},
        {"family": "one", "present": True, "predicted": False},
        {"family": "one", "present": False, "predicted": True},
        {"family": "one", "present": False, "predicted": False},
        {"family": "two", "present": False, "predicted": False},
    ]
    result = summarize(rows)
    assert result["one"] == {
        "cases": 4,
        "positive_cases": 2,
        "negative_cases": 2,
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "specificity": 0.5,
    }
    assert result["two"]["precision"] is None
    assert result["two"]["recall"] is None


def test_calibration_proxies_cover_each_score_once():
    rows = [
        {"score": score, "present": label}
        for score, label in [(0.0, False), (0.5, True), (0.7, False), (0.85, True), (1.0, True)]
    ]
    result = calibration(rows)
    assert [b["count"] for b in result["bins"]] == [1, 1, 1, 2]
    assert result["brier_proxy"] == pytest.approx((0 + 0.25 + 0.49 + 0.0225 + 0) / 5)
    assert result["ece_proxy"] == pytest.approx((0 + 0.5 + 0.7 + 2 * 0.075) / 5)


@pytest.mark.parametrize("bad_name", ["../escape.py", "/absolute.py", "a\\b.py", "x/../escape.py"])
def test_corpus_rejects_escaping_file_paths(tmp_path: Path, bad_name: str):
    with pytest.raises(CorpusError):
        load_corpus(_write(tmp_path / "data.json", _corpus({bad_name: "text"})))


def test_corpus_rejects_duplicate_json_keys(tmp_path: Path):
    path = tmp_path / "data.json"
    path.write_text('{"schema":1,"schema":1,"cases":[]}', encoding="utf-8")
    with pytest.raises(CorpusError, match="unambiguous"):
        load_corpus(path)


def test_corpus_rejects_non_boolean_label_and_invalid_assertions(tmp_path: Path):
    data = _corpus({"plain.py": "pass\n"})
    data["cases"][0]["present"] = 1
    with pytest.raises(CorpusError, match="boolean"):
        load_corpus(_write(tmp_path / "data.json", data))
    data["cases"][0]["present"] = False
    data["cases"][0]["assertions"] = {"server_count": True}
    with pytest.raises(CorpusError, match="server_count"):
        load_corpus(_write(tmp_path / "data.json", data))


def test_public_snapshot_digest_is_verified(tmp_path: Path):
    value = json.loads(DEFAULT_CORPUS.with_name("public_corpus.json").read_text())
    first = value["cases"][0]
    first["files"][first["source"]["path"]] += "extra"
    with pytest.raises(CorpusError, match="digest mismatch"):
        load_corpus(_write(tmp_path / "tampered.json", value))


def test_evaluation_end_to_end_with_isolated_offline_files(tmp_path: Path):
    corpus = _write(
        tmp_path / "data.json",
        _corpus(
            {"plain.py": "def hello():\n    return 1\n"},
            assertions={"max_agent_findings": 0, "server_count": 0},
        ),
    )
    report = evaluate(corpus, repeats=2)
    assert report["passed"] is True
    assert report["metrics"]["all"]["tn"] == 1
    assert report["cases"][0]["assertion_failures"] == []
    assert report["performance"]["scans"] == 2
    assert report["performance"]["files_per_pass"] == 1
    assert report["performance"]["median_scan_ms"] >= 0
    assert report["corpus"]["sha256"]
    assert len(report["implementation"]["scanner_source_sha256"]) == 64
    assert len(report["implementation"]["signature_sha256"]) == 64


def test_structural_assertion_causes_regression_even_when_label_matches(tmp_path: Path):
    corpus = _write(tmp_path / "data.json", _corpus({"plain.py": "pass\n"}, assertions={"server_count": 1}))
    result = evaluate(corpus)
    assert result["metrics"]["all"]["tn"] == 1
    assert result["passed"] is False
    assert "active MCP server count" in result["cases"][0]["assertion_failures"][0]


def test_cli_exits_on_wrong_label_and_writes_private_report(tmp_path: Path):
    corpus = _write(tmp_path / "data.json", _corpus({"plain.py": "pass\n"}, present=True))
    output = tmp_path / "result.json"
    assert main(["--corpus", str(corpus), "--output", str(output)]) == 1
    assert output.exists() and stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text())["metrics"]["all"]["fn"] == 1
    assert main(["--corpus", str(corpus), "--output", str(output)]) == 2  # no silent overwrite


def test_cli_returns_invalid_input_status(tmp_path: Path):
    assert main(["--corpus", str(tmp_path / "missing.json")]) == 2


def test_benchmark_counts_all_files_across_repeat_runs():
    report = benchmark(files=25, runs=2)
    assert report["files"] == 25
    assert report["project_manifests"] == 20
    assert report["finding_count"] >= 1
    assert report["runs"] == 2 and len(report["elapsed_seconds"]) == 2
    assert report["files_per_second_at_median"] > 0


def test_benchmark_rejects_unbounded_work():
    with pytest.raises(ValueError, match="files"):
        benchmark(files=10_001)
    with pytest.raises(ValueError, match="runs"):
        benchmark(runs=11)


def test_breakdowns_score_each_language_and_target_signature():
    from tools.evaluation.evaluate import breakdowns

    rows = [
        {"family": "agent", "present": True, "predicted": True, "files": ["agent.py"], "target": {"signature": "framework.crewai"}},
        {"family": "agent", "present": False, "predicted": True, "files": ["a.ts", "notes.md"], "target": {"signature": "framework.crewai"}},
        {"family": "mcp-server", "present": True, "predicted": False, "files": [".mcp.json"], "target": {"signature": None}},
    ]
    result = breakdowns(rows)
    assert result["language"]["python"]["tp"] == 1
    assert result["language"]["typescript"]["fp"] == 1 and result["language"]["docs"]["fp"] == 1
    assert result["language"]["config"]["fn"] == 1
    assert result["signature"]["framework.crewai"]["precision"] == 0.5
    assert result["signature"]["any"]["recall"] == 0.0


def test_coverage_gate_includes_nested_connector_packages(tmp_path, monkeypatch, capsys):
    import sys as _sys

    from tools import coverage_gate

    def entry(percent):
        return {"summary": {"num_statements": 10, "percent_statements_covered": percent}}

    report = {"files": {
        "shadowscan/connectors/code/filesystem.py": entry(90.0),
        "shadowscan/connectors/cloud/aws/bedrock.py": entry(40.0),
        "shadowscan/connectors/cloud/__init__.py": entry(0.0),
    }}
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report))
    monkeypatch.setattr(_sys, "argv", ["coverage_gate", str(path)])
    assert coverage_gate.main() == 1
    assert "cloud/aws/bedrock.py" in capsys.readouterr().err
