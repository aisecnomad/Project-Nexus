"""Regression tests for the defects found in the v2 code review (each test names the defect it guards)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import tools.benchmark.adapters as adapters_mod
from tools.benchmark.adapters import ToolEnv, _run_group
from tools.benchmark_realworld.adapters import ADAPTERS_V2, AgentDiscoverRepoOnlyV2, _in_scope
from tools.benchmark_realworld.cases import (
    ManifestError,
    RealCase,
    build_cases,
    home_view_label,
    redact,
    validate_manifest,
    verify_checkout,
)
from tools.benchmark_realworld.run import _run_one
from tools.benchmark_realworld.score_v2 import (
    balanced_accuracy,
    bootstrap,
    counts,
    coverage_problems,
    predicted_positive,
    summarize,
)

_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def _row(
    label: str, status: str = "ok", detected: bool = False, surface: str = "repo", case: str = "x"
) -> dict[str, Any]:
    return {
        "case": case,
        "surface": surface,
        "family": "ai-app",
        "label": label,
        "status": status,
        "detected": detected,
        "items": int(detected),
        "agentic": detected,
        "seconds": 0.1,
        "note": "incomplete scan (exit 3)" if status == "error" else "",
    }


# --- defect 1: an error is not a clean negative -------------------------------------


def test_error_on_a_clean_case_is_a_false_alarm_not_a_true_negative() -> None:
    assert predicted_positive(_row("none", status="error")) is True
    assert counts([_row("none", status="error")]) == {"tp": 0, "fp": 1, "fn": 0, "tn": 0}


def test_error_on_a_positive_is_a_miss() -> None:
    assert predicted_positive(_row("agent", status="error")) is False
    assert counts([_row("agent", status="error")]) == {"tp": 0, "fp": 0, "fn": 1, "tn": 0}


def test_a_tool_that_never_runs_cannot_score_perfect_specificity() -> None:
    rows = [_row("none", status="error") for _ in range(20)] + [
        _row("agent", status="error") for _ in range(5)
    ]
    c = counts(rows)
    assert c["tn"] == 0
    assert balanced_accuracy(c) == pytest.approx(0.0)


# --- defect 6: a surface with an undefined balance drops the composite ---------------


def test_composite_is_undefined_when_a_supported_surface_is_undefined() -> None:
    repo = [_row("none"), _row("none")]  # negatives only: balanced accuracy is undefined
    endpoint = [_row("client", detected=True, surface="endpoint"), _row("none", surface="endpoint")]
    summary = summarize({"tool-x": repo + endpoint, "shadowscan": repo + endpoint})
    comp = summary["composite"]["tool-x"]
    assert comp["value"] is None
    assert comp["undefined_on"] == ["repo"]


# --- defect 10: the bootstrap keeps both classes in every resample -------------------


def test_bootstrap_interval_is_defined_for_a_sparse_stratum() -> None:
    rows = [_row("agent", detected=True)] + [_row("none", detected=False) for _ in range(20)]
    low, high = bootstrap(rows, balanced_accuracy, seed=1)
    assert low is not None and high is not None
    assert 0.0 <= low <= high <= 1.0


# --- defect 12: scoring refuses an incomplete or mismatched result set ----------------


def test_coverage_reports_missing_and_extra_rows() -> None:
    doc = {
        "repos": [
            {
                "id": "rw-90-x",
                "repo": "a/b",
                "url": "https://github.com/a/b",
                "dir": "a/b",
                "sha": "a" * 40,
                "license": "MIT",
                "stratum": "ai-app",
                "label": "agent",
                "confidence": "high",
                "labels": {"A": "agent", "B": "agent"},
                "surfaces": ["repo"],
            }
        ]
    }

    def on_repo(*cases: str) -> dict[str, list[dict[str, Any]]]:
        # One row per case for every configuration: n/a where it does not run the repository surface.
        return {
            a.name: [_row("agent", status="ok" if "repo" in a.surfaces else "n/a", case=c) for c in cases]
            for a in ADAPTERS_V2
        }

    full = on_repo("rw-90-x:repo")
    assert coverage_problems(full, doc) == []
    for field, invalid in (
        ("label", "none"),
        ("family", "ordinary"),
        ("surface", "endpoint"),
        ("detected", "false"),
        ("status", "unexpected"),
    ):
        corrupted = on_repo("rw-90-x:repo")
        corrupted["shadowscan"][0][field] = invalid
        assert any(field in p for p in coverage_problems(corrupted, doc))
    missing = dict(full)
    del missing["shadowscan"]
    assert any("shadowscan" in p for p in coverage_problems(missing, doc))
    extra = on_repo("rw-90-x:repo", "rw-99-y:repo")
    assert any("match no manifest case" in p for p in coverage_problems(extra, doc))
    # A repeated case and an n/a row on a surface the configuration runs are both refused.
    repeated = on_repo("rw-90-x:repo")
    repeated["agent-bom"].append(_row("agent", case="rw-90-x:repo"))
    assert any("more than one row" in p for p in coverage_problems(repeated, doc))
    na_on_run = on_repo("rw-90-x:repo")
    na_on_run["shadowscan"][0]["status"] = "n/a"
    assert any("n/a on a surface" in p for p in coverage_problems(na_on_run, doc))


# --- defect 8: the label and the copy agree about symbolic links ---------------------


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_home_label_ignores_a_claude_directory_reached_through_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere" / "claude"
    real.mkdir(parents=True)
    (real / "settings.json").write_text('{"model": "x"}', encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude").symlink_to(real, target_is_directory=True)
    assert home_view_label(home) == "none"


# --- defect 9: a checkout must be clean and the top of its own repository ------------


def _commit_repo(path: Path) -> str:
    path.mkdir(parents=True)
    (path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    git = ["git", "-C", str(path), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run(["git", "-C", str(path), "init", "-q"], check=True)
    subprocess.run([*git, "-c", "commit.gpgsign=false", "add", "-A"], check=True)
    subprocess.run([*git, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"], check=True)
    head = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return head.stdout.strip()


def test_verify_checkout_accepts_a_clean_pinned_repository(tmp_path: Path) -> None:
    sha = _commit_repo(tmp_path / "clean")
    verify_checkout(tmp_path / "clean", sha)  # no error


def test_verify_checkout_rejects_an_untracked_file(tmp_path: Path) -> None:
    sha = _commit_repo(tmp_path / "dirty")
    (tmp_path / "dirty" / ".env").write_text("TOKEN=1\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="not a clean checkout"):
        verify_checkout(tmp_path / "dirty", sha)


def test_verify_checkout_rejects_a_directory_inside_another_repository(tmp_path: Path) -> None:
    outer = tmp_path / "outer"
    _commit_repo(outer)
    inner = outer / "inner"
    inner.mkdir()
    (inner / "x.py").write_text("x = 1\n", encoding="utf-8")
    # Committed in the outer repository, so the inner tree is clean: only the top-level check can refuse it.
    git = ["git", "-C", str(outer), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run([*git, "add", "inner"], check=True)
    subprocess.run([*git, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "inner"], check=True)
    head = subprocess.run(
        ["git", "-C", str(outer), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    with pytest.raises(ManifestError, match="not the top of its own repository"):
        verify_checkout(inner, head.stdout.strip())


# --- defect 13: redaction covers the credential shapes AGENTS.md names ---------------


@pytest.mark.parametrize(
    "text",
    [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
        "Authorization: Bearer abcdefghijklmnop1234",
        "password=hunter2supersecret",
        "glpat-abcdefghijklmnopqrstuvwx",
        "github_pat_11ABCDEFG0123456789_abcdefghij",
        "api_key: 'verylongkeyvalue1'",
    ],
)
def test_redaction_covers_jwt_bearer_password_and_tokens(text: str) -> None:
    assert "[redacted]" in redact(text)


# --- defect 5: v1 build honours surfaces; a repo-only entry has no home case ---------


def test_build_cases_runs_only_the_declared_surfaces(tmp_path: Path) -> None:
    sha = _commit_repo(tmp_path / "owner" / "repo")
    entry = {
        "id": "rw-91-repo",
        "repo": "owner/repo",
        "url": "https://github.com/owner/repo",
        "dir": "owner/repo",
        "sha": sha,
        "license": "MIT",
        "stratum": "ai-app",
        "label": "agent",
        "confidence": "high",
        "labels": {"A": "agent", "B": "agent"},
        "surfaces": ["repo"],
    }
    cases = build_cases({"repos": [entry]} and validate_manifest({"repos": [entry]}), tmp_path)
    assert [c.case_id for c in cases] == ["rw-91-repo:repo"]


# --- defect 2: SafeDep never drops an item whose Scope it does not know --------------


def test_unknown_scope_is_an_unexpected_format_not_a_dropped_item() -> None:
    assert _in_scope([{"Scope": "1", "App": "a"}, {"Scope": "3", "App": "b"}], "1") is None
    assert [i["App"] for i in _in_scope([{"Scope": "1", "App": "a"}, {"Scope": "2", "App": "b"}], "2")] == [
        "b"
    ]


# --- defect 2: a timed-out tool's partial output is never parsed as a result ---------


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="needs Linux /proc")
def test_timeout_returns_no_stdout(tmp_path: Path) -> None:
    code, out, err, _secs = _run_group(
        ["sh", "-c", "echo '{\"complete\": true}'; sleep 60"], env=_ENV, cwd=tmp_path, stdin=None, timeout=2
    )
    assert code == 124
    assert out == ""
    assert "timeout" in err


# --- defect 3 and 4: a failed baseline is an error, and a stale file is never reused -


def _fake_env(tmp_path: Path, tool_dir: str, exe: str) -> ToolEnv:
    bin_dir = tmp_path / "tools" / "venvs" / tool_dir / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / exe).write_text("", encoding="utf-8")
    return ToolEnv(root=tmp_path / "tools", python="python3")


def _tree_case(tmp_path: Path, surface: str) -> RealCase:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    return RealCase(
        case_id=f"rw-92-x:{surface}",
        surface=surface,
        family="ai-app",
        label="none",
        difficulty="high",
        rationale="",
        source_dir=src,
    )


def test_failed_agent_bom_baseline_is_an_error_not_an_empty_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.benchmark.adapters import AgentBom

    env = _fake_env(tmp_path, "agentbom", "agent-bom")
    monkeypatch.setattr(adapters_mod, "_isolated", lambda *a, **k: (1, '{"error": "boom"}', "boom", 0.0))
    AgentBom._baseline = None
    work = tmp_path / "work"
    work.mkdir()
    outcome = _run_one(AgentBom(), _tree_case(tmp_path, "repo"), env, work, tmp_path)
    assert outcome.status == "error"
    assert AgentBom._baseline is None, "a failed baseline must not be cached"


def test_ai_detector_failed_baseline_is_an_error_and_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.benchmark.adapters import AIDetector

    env = _fake_env(tmp_path, "unused", "unused")
    script_dir = tmp_path / "tools" / "third_party" / "shamo0_AI-Detector"
    script_dir.mkdir(parents=True)
    (script_dir / "detect-shadow-ai.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(adapters_mod, "_isolated", lambda *a, **k: (1, "not json", "fail", 0.0))
    AIDetector._baseline = None
    work = tmp_path / "work"
    work.mkdir()
    outcome = _run_one(AIDetector(), _tree_case(tmp_path, "endpoint"), env, work, tmp_path)
    assert outcome.status == "error"
    assert AIDetector._baseline is None


def test_agent_discover_repo_only_v2_has_no_endpoint_surface() -> None:
    assert set(AgentDiscoverRepoOnlyV2().surfaces) == {"repo"}
    assert all(set(a.surfaces) <= {"repo", "endpoint"} for a in ADAPTERS_V2)


def test_cisco_aibom_report_written_before_a_crash_is_not_a_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defect 2: a non-zero exit is an error even when the tool wrote a complete-looking report."""
    from tools.benchmark.adapters import CiscoAIBOM

    env = _fake_env(tmp_path, "aibom", "cisco-aibom")

    def crashing(cmd: list[str], **kwargs: Any) -> tuple[int, str, str, float]:
        out = Path(cmd[cmd.index("--output-file") + 1])
        report = {"aibom_analysis": {"metadata": {"status": "completed"}, "summary": {"total_components": 3}}}
        out.write_text(json.dumps(report), encoding="utf-8")
        return 1, "", "crashed after writing", 0.0

    monkeypatch.setattr(adapters_mod, "_isolated", crashing)
    work = tmp_path / "work"
    work.mkdir()
    outcome = _run_one(CiscoAIBOM(), _tree_case(tmp_path, "repo"), env, work, tmp_path)
    assert outcome.status == "error"
    assert outcome.detected is False


# --- exit status: each rule is the one measured on known cases before the freeze -----


def _checkout_script(tmp_path: Path, name: str, script: str) -> ToolEnv:
    root = tmp_path / "tools"
    (root / "third_party" / name).mkdir(parents=True)
    (root / "third_party" / name / script).write_text("#!/bin/sh\n", encoding="utf-8")
    return ToolEnv(root=root, python="python3")


def test_snyk_non_zero_exit_is_an_error_even_with_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.benchmark.adapters import SnykAgentScan

    env = _fake_env(tmp_path, "snyk", "snyk-agent-scan")
    monkeypatch.setattr(
        adapters_mod, "_isolated", lambda *a, **k: (1, '{"servers": [{"name": "x"}]}', "boom", 0.0)
    )
    work = tmp_path / "work"
    work.mkdir()
    assert _run_one(SnykAgentScan(), _tree_case(tmp_path, "endpoint"), env, work, tmp_path).status == "error"


def test_agent_discover_failed_scan_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.benchmark.adapters import AgentDiscover

    env = _fake_env(tmp_path, "agentdiscover", "agentdiscover")
    monkeypatch.setattr(adapters_mod, "_isolated", lambda *a, **k: (1, "", "scan crashed", 0.0))
    work = tmp_path / "work"
    work.mkdir()
    assert _run_one(AgentDiscover(), _tree_case(tmp_path, "repo"), env, work, tmp_path).status == "error"


def test_claw_hunter_codes_0_1_2_are_results_and_3_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.benchmark.adapters import ClawHunter

    env = _checkout_script(tmp_path, "backslash-security_claw-hunter", "claw-hunter.sh")
    case = _tree_case(tmp_path, "endpoint")
    report = "JSON OUTPUT:\n" + json.dumps(dict.fromkeys(ClawHunter.SIGNALS, False)) + "\n"
    for code in (0, 1, 2):
        monkeypatch.setattr(adapters_mod, "_isolated", lambda *a, _c=code, **k: (_c, report, "", 0.0))
        work = tmp_path / f"work-{code}"
        work.mkdir()
        assert _run_one(ClawHunter(), case, env, work, tmp_path).status == "ok", (
            f"exit {code} is a complete run"
        )
    monkeypatch.setattr(adapters_mod, "_isolated", lambda *a, **k: (3, report, "script error", 0.0))
    work = tmp_path / "work-3"
    work.mkdir()
    assert _run_one(ClawHunter(), case, env, work, tmp_path).status == "error"
    # Exit 0 with a report that lacks the signal fields is unreadable, not a clean result.
    bare = "JSON OUTPUT:\n" + json.dumps({"cli_installed": False}) + "\n"
    monkeypatch.setattr(adapters_mod, "_isolated", lambda *a, **k: (0, bare, "", 0.0))
    work = tmp_path / "work-bare"
    work.mkdir()
    assert _run_one(ClawHunter(), case, env, work, tmp_path).status == "error"


@pytest.mark.parametrize(
    ("code", "stderr", "expected"),
    [(1, "", "ok"), (2, "", "error"), (1, "[ERROR] module failed", "error"), (0, "", "ok")],
)
def test_ai_detector_exit_codes_and_error_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int, stderr: str, expected: str
) -> None:
    """Its contract: 0 clean, 1 found, 2 error. A "[ERROR]" line on stderr marks an incomplete report."""
    from tools.benchmark.adapters import AIDetector

    env = _checkout_script(tmp_path, "shamo0_AI-Detector", "detect-shadow-ai.sh")
    case = _tree_case(tmp_path, "endpoint")

    def fake(*_args: Any, env: dict[str, str], **_kwargs: Any) -> tuple[int, str, str, float]:
        if "-baseline" in env["HOME"]:
            return 0, '{"findings": [], "shadow_ai_detected": false}', "", 0.0  # clean baseline
        found = [{"category": "LLM_CLI", "detail": "x"}] if code == 1 else []
        return code, json.dumps({"findings": found, "shadow_ai_detected": code == 1}), stderr, 0.0

    monkeypatch.setattr(adapters_mod, "_isolated", fake)
    work = tmp_path / f"work-{code}-{bool(stderr)}"
    work.mkdir()
    assert _run_one(AIDetector(), case, env, work, tmp_path).status == expected
