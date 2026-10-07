"""Tests for the head-to-head benchmark harness (generator, renderers, statistics)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from tools.benchmark import adapters, generate, score
from tools.benchmark.common import Case, fill


def test_generation_is_deterministic_and_meets_quotas() -> None:
    first = [c.to_json() for c in generate.generate(seed=3, per_surface=20)]
    second = [c.to_json() for c in generate.generate(seed=3, per_surface=20)]
    assert first == second
    counts = Counter((c["surface"], c["label"]) for c in first)
    for surface in ("repo", "endpoint", "network"):
        assert counts[(surface, "agent")] == 9
        assert counts[(surface, "llm")] == 3
        assert counts[(surface, "none")] == 8


def test_different_seeds_produce_different_corpora() -> None:
    a = [c.to_json() for c in generate.generate(seed=3, per_surface=10)]
    b = [c.to_json() for c in generate.generate(seed=4, per_surface=10)]
    assert a != b


def test_cases_have_inputs_for_their_surface() -> None:
    for case in generate.generate(seed=5, per_surface=30):
        if case.surface == "network":
            assert case.flows and not case.files
            assert all(f["host"] and f["path"].startswith("/") for f in case.flows)
        else:
            assert case.files and not case.flows


def test_unsafe_or_aliasing_paths_are_rejected() -> None:
    with pytest.raises(ValueError):
        generate._check_paths("x", {"../escape.py": ""})
    with pytest.raises(ValueError):
        generate._check_paths("x", {"A.py": "", "a.py": ""})
    with pytest.raises(ValueError):
        generate._check_paths("x", {"pkg": "", "pkg/mod.py": ""})


def test_materialize_writes_every_file(tmp_path: Path) -> None:
    case = next(c for c in generate.generate(seed=6, per_surface=10) if c.surface == "repo")
    generate.materialize(case, tmp_path)
    for rel, text in case.files.items():
        assert (tmp_path / rel).read_text(encoding="utf-8") == text


def test_fill_rejects_unknown_placeholders() -> None:
    assert fill("a @@x@@ b", x="1") == "a 1 b"
    with pytest.raises(KeyError):
        fill("@@missing@@")


def _network_case() -> Case:
    return next(c for c in generate.generate(seed=7, per_surface=10) if c.surface == "network")


def test_squid_lines_match_the_native_field_layout() -> None:
    case = _network_case()
    lines = adapters.squid_lines(case)
    assert len(lines) == len(case.flows)
    fields = lines[0].split()
    assert len(fields) == 10
    assert "/" in fields[3] and fields[3].startswith("TCP_MISS/")
    assert fields[6].startswith(("http://", "https://"))


def test_agentsonar_events_pair_handshake_and_flow_shape() -> None:
    case = _network_case()
    events = adapters.agentsonar_events(case)
    assert len(events) == 2 * len(case.flows)
    assert {e["source"] for e in events[1::2]} == {"streaming"}
    assert all("path" not in json.dumps(e) for e in events)


def test_access_log_records_keep_host_path_and_agent() -> None:
    case = _network_case()
    records = adapters.access_log_records(case)
    assert records[0]["host"] == case.flows[0]["host"]
    assert records[0]["request_uri"] == case.flows[0]["path"]
    assert records[0]["http_user_agent"] == case.flows[0]["user_agent"]


def test_wilson_interval_bounds() -> None:
    p, lo, hi = score.wilson(9, 10)
    assert p == 0.9
    assert lo is not None and hi is not None and 0.55 < lo < 0.6 and 0.98 < hi <= 1.0
    assert score.wilson(0, 0) == (None, None, None)


def test_exact_mcnemar() -> None:
    assert score.mcnemar_exact(0, 0) == 1.0
    assert score.mcnemar_exact(5, 5) == 1.0
    assert score.mcnemar_exact(0, 10) == pytest.approx(2 / 1024)


def test_confusion_treats_errors_as_misses() -> None:
    rows = [
        {"label": "agent", "status": "ok", "detected": True},
        {"label": "llm", "status": "error", "detected": False},
        {"label": "none", "status": "ok", "detected": True},
        {"label": "none", "status": "ok", "detected": False},
    ]
    m = score.confusion(rows)
    assert (m["tp"], m["fn"], m["fp"], m["tn"], m["errors"]) == (1, 1, 1, 1, 1)


def test_unsupported_surface_is_not_applicable(tmp_path: Path) -> None:
    case = _network_case()
    env = adapters.ToolEnv(root=tmp_path, python="python")
    outcome = adapters.ClawHunter().run(case, tmp_path, env)
    assert outcome.status == "n/a"


def test_missing_tool_is_an_error_not_a_negative(tmp_path: Path) -> None:
    case = _network_case()
    env = adapters.ToolEnv(root=tmp_path, python="python")
    outcome = adapters.AgentSonar().run(case, tmp_path, env)
    assert outcome.status == "error"
    assert not outcome.detected


def test_urls_omit_default_ports_like_proxy_logs() -> None:
    flow = {"scheme": "https", "host": "api.openai.com", "port": 443, "path": "/v1/responses"}
    assert adapters._url(flow) == "https://api.openai.com/v1/responses"
    local = {"scheme": "http", "host": "127.0.0.1", "port": 11434, "path": "/api/chat"}
    assert adapters._url(local) == "http://127.0.0.1:11434/api/chat"


def test_last_json_line_skips_log_lines() -> None:
    text = '2026-10-06 [info] catalog_loaded total=106\n{"events": []}\n'
    assert adapters._last_json_line(text) == {"events": []}
    with pytest.raises(ValueError):
        adapters._last_json_line("no json here\n")


def test_mcp_scanner_log_names_the_enumerated_server() -> None:
    line = "ERROR - Unexpected error scanning server 'github' from /h/.cursor/mcp.json: Timeout connecting\n"
    assert adapters._MCP_SCANNER_SERVER.findall(line) == [("github", "/h/.cursor/mcp.json")]


def test_report_renders_tables_and_paired_tests(tmp_path: Path) -> None:
    from tools.benchmark import report

    cases = [c for c in generate.generate(seed=8, per_surface=10) if c.surface == "repo"]
    for tool, hit in (("shadowscan", lambda c: c.positive), ("agent-bom", lambda c: c.label == "agent")):
        rows = [
            {
                "case": c.case_id,
                "surface": c.surface,
                "family": c.family,
                "label": c.label,
                "difficulty": c.difficulty,
                "status": "ok",
                "detected": hit(c),
                "items": int(hit(c)),
                "agentic": None,
                "seconds": 1.0,
                "note": "",
            }
            for c in cases
        ]
        (tmp_path / f"{tool}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    manifest = {
        "cases_run": len(cases),
        "corpus_sha256": "0" * 64,
        "corpus_metadata": {"seed": 8},
        "python": "3.13",
        "platform": "test",
        "runs": [],
    }
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest))
    text = report.render(tmp_path)
    assert "## Surface: repo" in text
    assert "Paired comparison with ShadowScan" in text
    assert "None: every supported case completed" in text
    # One final newline, as pre-commit's end-of-file-fixer leaves the committed REPORT.md.
    assert text.endswith("tool.\n")
