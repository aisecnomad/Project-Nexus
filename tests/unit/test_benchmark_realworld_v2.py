"""Unit tests for benchmark v2: timeout handling, surfaces, adapters and the v2 scoring."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tools.benchmark.adapters import _run_group
from tools.benchmark_realworld.adapters import ADAPTERS, ADAPTERS_V2, ShadowScanDedicatedV2
from tools.benchmark_realworld.cases import ManifestError, build_cases, build_cases_v2, validate_manifest
from tools.benchmark_realworld.score_v2 import (
    balanced_accuracy,
    counts,
    determinism_check,
    mcc,
    render,
    sensitivity_rerun,
    summarize,
)

_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def _entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "rw-90-example",
        "repo": "owner/example",
        "url": "https://github.com/owner/example",
        "dir": "owner/example",
        "sha": "a" * 40,
        "license": "MIT",
        "stratum": "ai-app",
        "label": "agent",
        "confidence": "high",
        "labels": {"A": "agent", "B": "agent"},
        "evidence": ["src/agent.py: tool loop"],
    }
    base.update(overrides)
    return base


def _row(
    label: str,
    detected: bool,
    *,
    status: str = "ok",
    family: str = "ai-app",
    surface: str = "repo",
) -> dict[str, Any]:
    return {
        "case": f"rw-{label}-{int(detected)}:{surface}",
        "surface": surface,
        "family": family,
        "label": label,
        "status": status,
        "detected": detected,
        "items": int(detected),
        "agentic": detected,
        "seconds": 0.1,
        "note": "",
    }


# --- timeouts -----------------------------------------------------------------


def test_run_group_returns_code_and_streams(tmp_path: Path) -> None:
    code, out, err, secs = _run_group(
        ["sh", "-c", "printf hi; printf oops >&2; exit 3"], env=_ENV, cwd=tmp_path, stdin=None, timeout=30
    )
    assert (code, out, err) == (3, "hi", "oops")
    assert secs >= 0


def test_run_group_passes_stdin(tmp_path: Path) -> None:
    code, out, _err, _secs = _run_group(["cat"], env=_ENV, cwd=tmp_path, stdin="abc", timeout=30)
    assert (code, out) == (0, "abc")


def _alive(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    state = stat.rsplit(")", 1)[1].split()[0]  # the field after the command name
    return state != "Z"


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="needs Linux /proc")
def test_timeout_kills_helpers_the_tool_started(tmp_path: Path) -> None:
    pidfile = tmp_path / "helper.pid"
    script = f"sleep 120 & echo $! > {pidfile}; wait"
    code, _out, err, _secs = _run_group(["sh", "-c", script], env=_ENV, cwd=tmp_path, stdin=None, timeout=3)
    assert code == 124, "a timeout is an error code, never a negative"
    assert "timeout" in err
    helper = int(pidfile.read_text(encoding="utf-8"))
    assert not _alive(helper), "the helper outlived its timed-out parent"


# --- adapters -----------------------------------------------------------------


def test_v2_dedicated_configuration_is_endpoint_only() -> None:
    v2 = {a.name: a for a in ADAPTERS_V2}
    v1 = {a.name: a for a in ADAPTERS}
    assert set(v2) == set(v1), "v2 runs the same tools"
    assert isinstance(v2["shadowscan-dedicated"], ShadowScanDedicatedV2)
    assert set(v2["shadowscan-dedicated"].surfaces) == {"endpoint"}
    assert "repo" in v1["shadowscan-dedicated"].surfaces, "v1 behaviour is unchanged"


# --- manifest and surfaces ----------------------------------------------------


def test_endpoint_only_entry_takes_label_n_a() -> None:
    entry = _entry(surfaces=["home"], label="n/a", stratum="dotfiles")
    assert len(validate_manifest({"repos": [entry]})) == 1


@pytest.mark.parametrize(
    "override",
    [
        {"surfaces": ["home"], "label": "agent"},  # endpoint-only entries have no repo label
        {"surfaces": ["network"], "label": "n/a"},  # not a measured surface
        {"surfaces": []},
        {"surfaces": ["repo", "repo"]},
    ],
)
def test_bad_surface_declarations_are_rejected(override: dict[str, object]) -> None:
    with pytest.raises(ManifestError):
        validate_manifest({"repos": [_entry(**override)]})


def test_three_digit_ids_are_accepted_and_four_digits_are_not() -> None:
    assert validate_manifest({"repos": [_entry(id="rw-123-dotfiles", surfaces=["repo"])]})
    with pytest.raises(ManifestError):
        validate_manifest({"repos": [_entry(id="rw-1234-dotfiles")]})


def _git_repo(path: Path) -> str:
    """A committed repository with one AI-client settings file; returns its HEAD commit."""
    (path / ".claude").mkdir(parents=True)
    (path / ".claude" / "settings.json").write_text('{"model": "x"}', encoding="utf-8")
    git = ["git", "-C", str(path), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run(["git", "-C", str(path), "init", "-q"], check=True)
    subprocess.run([*git, "-c", "commit.gpgsign=false", "add", "-A"], check=True)
    subprocess.run([*git, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"], check=True)
    head = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return head.stdout.strip()


def test_build_cases_v2_runs_only_the_declared_surfaces(tmp_path: Path) -> None:
    sha = _git_repo(tmp_path / "owner" / "dots")
    dots = _entry(
        id="rw-120-dots", dir="owner/dots", sha=sha, surfaces=["home"], label="n/a", stratum="dotfiles"
    )
    cases = build_cases_v2(validate_manifest({"repos": [dots]}), tmp_path)
    assert [(c.case_id, c.surface, c.label) for c in cases] == [("rw-120-dots:home", "endpoint", "client")]

    repo_only = _entry(id="rw-121-repo", dir="owner/dots", sha=sha, surfaces=["repo"], label="agent")
    cases = build_cases_v2(validate_manifest({"repos": [repo_only]}), tmp_path)
    assert [(c.case_id, c.surface, c.label) for c in cases] == [("rw-121-repo:repo", "repo", "agent")]


def test_v1_entries_without_surfaces_keep_both_surfaces(tmp_path: Path) -> None:
    sha = _git_repo(tmp_path / "owner" / "dots")
    v1 = _entry(id="rw-122-old", dir="owner/dots", sha=sha, label="agent")
    repos = validate_manifest({"repos": [v1]})
    assert [c.surface for c in build_cases(repos, tmp_path)] == ["repo", "endpoint"]
    assert [c.surface for c in build_cases_v2(repos, tmp_path)] == ["repo", "endpoint"]


# --- metrics ------------------------------------------------------------------


def test_balanced_accuracy_and_mcc_known_values() -> None:
    # 4 positives (3 flagged), 4 negatives (1 flagged): TP 3, FN 1, FP 1, TN 3.
    rows = [_row("agent", i < 3) for i in range(4)] + [_row("none", i < 1) for i in range(4)]
    c = counts(rows)
    assert c == {"tp": 3, "fp": 1, "fn": 1, "tn": 3}
    assert balanced_accuracy(c) == pytest.approx(0.75)
    assert mcc(c) == pytest.approx(0.5)


def test_perfect_and_flag_everything_cases() -> None:
    perfect = counts([_row("agent", True), _row("none", False)])
    assert balanced_accuracy(perfect) == 1.0
    assert mcc(perfect) == pytest.approx(1.0)
    everything = counts([_row("agent", True), _row("none", True)])
    assert balanced_accuracy(everything) == pytest.approx(0.5)
    assert mcc(everything) is None, "a tool that flags everything has undefined MCC"


def test_an_error_is_a_miss_on_a_positive_and_a_false_alarm_on_a_clean_case() -> None:
    rows = [_row("agent", False, status="error"), _row("none", False)]
    assert counts(rows) == {"tp": 0, "fp": 0, "fn": 1, "tn": 1}
    assert counts([_row("none", False, status="error")]) == {"tp": 0, "fp": 1, "fn": 0, "tn": 0}


def test_composite_uses_supported_surfaces_and_estate_uses_chance() -> None:
    repo = [_row("agent", True), _row("agent", False), _row("none", False), _row("none", False)]
    endpoint = [_row("client", True, surface="endpoint"), _row("none", True, surface="endpoint")]
    rows_by_tool = {
        "shadowscan": repo + endpoint,
        "repo-only-tool": [dict(r) for r in repo]
        + [dict(r, surface="endpoint", status="n/a", detected=False) for r in endpoint],
    }
    summary = summarize(rows_by_tool)
    repo_ba = summary["surfaces"]["repo"]["repo-only-tool"]["cell"]["balanced_accuracy"]
    assert repo_ba == pytest.approx(0.75)
    assert summary["composite"]["repo-only-tool"]["value"] == pytest.approx(repo_ba)
    assert summary["composite"]["repo-only-tool"]["surfaces"] == ["repo"]
    assert summary["estate"]["repo-only-tool"] == pytest.approx((repo_ba + 0.5) / 2)
    assert summary["surfaces"]["endpoint"]["shadowscan"]["cell"]["balanced_accuracy"] == pytest.approx(0.5)


def test_render_mentions_each_tool_and_section() -> None:
    rows_by_tool = {
        "shadowscan": [_row("agent", True), _row("none", False)],
        "other": [_row("agent", False), _row("none", True)],
    }
    summary = summarize(rows_by_tool)
    corpus = {
        "repo": {"cases": 2, "labels": {"agent": 1, "none": 1}, "strata": {"ai-app": 2}, "scored": 2},
        "endpoint": {"cases": 0, "labels": {}, "strata": {}, "scored": 0},
    }
    text = render(summary, corpus, {"determinism": None, "sensitivity": None, "labels": None})
    for needle in ("## Composite and estate", "shadowscan", "other", "## Limits"):
        assert needle in text


# --- determinism and sensitivity checks ---------------------------------------


def test_determinism_check_reports_a_disagreeing_repo_case(tmp_path: Path) -> None:
    import json

    base = {"surface": "repo", "family": "ai-app", "label": "agent", "seconds": 0.1, "note": "", "items": 0}
    published = dict(base, case="rw-01:repo", status="ok", detected=True)
    dedicated = dict(base, case="rw-01:repo", status="error", detected=False)
    (tmp_path / "shadowscan.jsonl").write_text(json.dumps(published) + "\n", encoding="utf-8")
    (tmp_path / "shadowscan-dedicated.jsonl").write_text(json.dumps(dedicated) + "\n", encoding="utf-8")
    result = determinism_check(tmp_path)
    assert result is not None
    assert result["repo_cases"] == 1
    assert [d["case"] for d in result["differences"]] == ["rw-01:repo"]


def test_sensitivity_rerun_reports_status_changes(tmp_path: Path) -> None:
    import json

    primary = [dict(_row("agent", False, status="error"), case="rw-01:repo")]
    rerun = dict(_row("agent", True), case="rw-01:repo")
    (tmp_path / "shadowscan.jsonl").write_text(json.dumps(rerun) + "\n", encoding="utf-8")
    result = sensitivity_rerun({"shadowscan": primary}, tmp_path)
    assert result is not None
    assert result["cases_rerun"] == 1
    tool = result["tools"]["shadowscan"]
    assert [f["case"] for f in tool["status_changed"]] == ["rw-01:repo"]
    assert tool["cells"]["repo"]["tp"] == 1
