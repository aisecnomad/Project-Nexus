"""Regression tests for the second review of the v2 benchmark (protocol v2, section 13).

Each test names the finding it guards. The tools are faked at the subprocess boundary, so the
adapters' own parsing and decision rules are what is under test.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

import tools.benchmark.adapters as adapters_mod
import tools.benchmark_realworld.adapters as realworld_adapters
from tools.benchmark.adapters import AgentBom, AIDetector, CiscoAIBOM, ToolEnv
from tools.benchmark_realworld.adapters import SafeDepVet
from tools.benchmark_realworld.build_manifest_v2 import check_citations
from tools.benchmark_realworld.cases import RealCase, home_view_label, redact
from tools.benchmark_realworld.run import _run_one, provenance_conflict, select_only
from tools.benchmark_realworld.score_v2 import (
    bootstrap,
    provenance_problems,
    rerun_plan,
    rerun_problems,
    write_rerun,
)


def _case(tmp_path: Path, surface: str, label: str = "agent") -> RealCase:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    return RealCase(
        case_id=f"rw-01-x:{surface}",
        surface=surface,
        family="ai-app",
        label=label,
        difficulty="n/a",
        rationale="regression test",
        source_dir=src,
    )


def _scratch(tmp_path: Path) -> Path:
    return Path(tempfile.mkdtemp(prefix="scratch-", dir=tmp_path))


def _env(tmp_path: Path, venv: str, exe: str) -> ToolEnv:
    bin_dir = tmp_path / "tools" / "venvs" / venv / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / exe).write_text("", encoding="utf-8")
    return ToolEnv(root=tmp_path / "tools", python="python3")


def _project_doc(
    servers: list[dict[str, Any]], outcome: str = "complete", incomplete: int = 0
) -> dict[str, Any]:
    return {
        "scan_run": {"outcome": outcome, "incomplete_scope_count": incomplete},
        "agents": [
            {"name": "project:repo", "discovery_provenance": {"source": "project"}, "mcp_servers": servers}
        ],
    }


# --- agent-bom: the report's scan_run decides, not the exit code -----------------------------


@pytest.mark.parametrize(
    ("code", "doc", "status", "detected"),
    [
        # A completed scan that exits 1 ("found critical") is a result, not a partial scan.
        (1, _project_doc([{"name": "ai-inventory", "surface": "ai-inventory", "command": ""}]), "ok", True),
        # A CI job named like a command is not AI evidence (the Flask case, clean).
        (1, _project_doc([{"name": "ci", "surface": "other", "command": "github-actions"}]), "ok", False),
        # A project server bound to a model is AI evidence.
        (0, _project_doc([{"name": "m", "surface": "other", "command": "python", "model": "x"}]), "ok", True),
        # A partial scan is an error whatever its exit code.
        (1, _project_doc([{"name": "a", "surface": "ai-inventory"}], outcome="partial"), "error", None),
        (0, _project_doc([{"name": "a", "surface": "ai-inventory"}], outcome="partial"), "error", None),
        (0, _project_doc([{"name": "a", "surface": "ai-inventory"}], incomplete=1), "error", None),
        # Exit 0 with a report that is not an agent-bom report is unreadable, not a clean result.
        (0, {"error": "x"}, "error", None),
        (2, _project_doc([]), "error", None),
    ],
)
def test_agent_bom_result_is_decided_by_its_report_not_its_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    doc: dict[str, Any],
    status: str,
    detected: bool | None,
) -> None:
    monkeypatch.setattr(AgentBom, "_baseline", frozenset())  # no host baseline in this test

    def fake(cmd: list[str], **_kwargs: Any) -> tuple[int, str, str, float]:
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(doc), encoding="utf-8")
        return code, "", "", 0.0

    monkeypatch.setattr(adapters_mod, "_isolated", fake)
    outcome = _run_one(
        AgentBom(),
        _case(tmp_path, "repo"),
        _env(tmp_path, "agentbom", "agent-bom"),
        _scratch(tmp_path),
        tmp_path,
    )
    assert outcome.status == status
    if detected is not None:
        assert outcome.detected is detected


# --- AI-Detector: its JSON must carry findings and agree with its exit code --------------------


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ('{"findings": [], "shadow_ai_detected": false}', "ok"),
        ('{"findings": []}', "error"),  # no flag: unreadable
        ('{"shadow_ai_detected": false}', "error"),  # no findings list: unreadable
        ('{"findings": [], "shadow_ai_detected": true}', "error"),  # flag says found, exit says clean
    ],
)
def test_ai_detector_report_must_carry_findings_and_agree_with_its_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, status: str
) -> None:
    root = tmp_path / "tools"
    script_dir = root / "third_party" / "shamo0_AI-Detector"
    script_dir.mkdir(parents=True)
    (script_dir / "detect-shadow-ai.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    env = ToolEnv(root=root, python="python3")
    monkeypatch.setattr(adapters_mod, "_isolated", lambda *a, **k: (0, body, "", 0.0))
    AIDetector._baseline = None
    try:
        assert (
            _run_one(AIDetector(), _case(tmp_path, "endpoint"), env, _scratch(tmp_path), tmp_path).status
            == status
        )
    finally:
        AIDetector._baseline = None


# --- Cisco AI BOM and SafeDep: a report without its required fields is unreadable -------------


def test_cisco_aibom_report_without_a_total_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = {"aibom_analysis": {"metadata": {"status": "completed"}, "summary": {"component_types": {}}}}

    def fake(cmd: list[str], **_kwargs: Any) -> tuple[int, str, str, float]:
        Path(cmd[cmd.index("--output-file") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return 0, "", "", 0.0

    monkeypatch.setattr(adapters_mod, "_isolated", fake)
    env = _env(tmp_path, "aibom", "cisco-aibom")
    assert (
        _run_one(CiscoAIBOM(), _case(tmp_path, "repo"), env, _scratch(tmp_path), tmp_path).status == "error"
    )


@pytest.mark.parametrize(
    ("report", "status", "detected"),
    [("null", "ok", False), ("{}", "error", None), ('[{"Scope": "2", "App": "x"}]', "ok", True)],
)
def test_safedep_inventory_must_be_a_list_or_null(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report: str, status: str, detected: bool | None
) -> None:
    def fake(cmd: list[str], **_kwargs: Any) -> tuple[int, str, str, float]:
        Path(cmd[cmd.index("--report-json") + 1]).write_text(report, encoding="utf-8")
        return 0, "", "", 0.0

    monkeypatch.setattr(realworld_adapters, "_isolated", fake)
    env = ToolEnv(root=tmp_path / "tools", python="python3")
    (env.root / "bin").mkdir(parents=True)
    (env.root / "bin" / "vet").write_text("", encoding="utf-8")
    outcome = _run_one(SafeDepVet(), _case(tmp_path, "repo"), env, _scratch(tmp_path), tmp_path)
    assert outcome.status == status
    if detected is not None:
        assert outcome.detected is detected


# --- redaction: whole key blocks and unsigned tokens -------------------------------------------


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAabcdef\n-----END RSA PRIVATE KEY-----\n",
            "MIIEpAIBAAKCAQEAabcdef",
        ),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n", "b3BlbnNzaC1rZXktdjEAAAAA"),
        ("id_token=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0"),
    ],
)
def test_redaction_removes_whole_key_blocks_and_unsigned_tokens(text: str, leaked: str) -> None:
    assert leaked not in redact(text)


# --- home label: a directory of symbolic links only is empty, as in the copy --------------------


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_directory_of_only_symbolic_links_is_empty_for_the_home_label(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.md"
    target.write_text("# agent\n", encoding="utf-8")
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "link.md").symlink_to(target)
    assert home_view_label(tmp_path) == "none"


# --- harness: provenance and the sensitivity case list ------------------------------------------


def test_a_run_cannot_keep_summaries_produced_under_other_inputs_or_code() -> None:
    provenance = {"manifest_sha256": "new", "code_sha256": "same"}
    previous = {"manifest_sha256": "old", "code_sha256": "same", "runs": [{"tool": "kept"}]}
    assert provenance_conflict(previous, provenance, {"other"}) is not None
    assert provenance_conflict(previous, provenance, {"kept"}) is None  # nothing would be kept
    assert provenance_conflict({**previous, "manifest_sha256": "new"}, provenance, {"other"}) is None


def _bare_case(tmp_path: Path, case_id: str) -> RealCase:
    return RealCase(
        case_id=case_id,
        surface="repo",
        family="ai-app",
        label="agent",
        difficulty="n/a",
        rationale="regression test",
        source_dir=tmp_path,
    )


def test_only_cases_refuses_an_unknown_id_and_selects_the_listed_cases(tmp_path: Path) -> None:
    cases = [_bare_case(tmp_path, "rw-01-a:repo"), _bare_case(tmp_path, "rw-02-b:repo")]
    listed = tmp_path / "list.txt"
    listed.write_text("rw-01-a:repo\nrw-09-z:repo\n", encoding="utf-8")
    with pytest.raises(ValueError, match="do not exist"):
        select_only(cases, listed)
    listed.write_text("rw-02-b:repo\n", encoding="utf-8")
    assert [c.case_id for c in select_only(cases, listed)] == ["rw-02-b:repo"]


# --- scorer: the rerun plan and the provenance of a run ----------------------------------------


def _rrow(case: str, status: str, note: str) -> dict[str, Any]:
    return {
        "case": case,
        "surface": "repo",
        "family": "ai-app",
        "label": "agent",
        "status": status,
        "detected": False,
        "items": 0,
        "agentic": False,
        "seconds": 0.0,
        "note": note,
    }


def test_rerun_plan_takes_timeouts_and_incomplete_scans_and_nothing_else() -> None:
    rows = {
        "t": [
            _rrow("rw-01-a:repo", "error", "exit 124: timeout after 300s"),
            _rrow("rw-02-b:repo", "error", "exit 1: scan not complete (partial)"),
            _rrow("rw-03-c:repo", "error", "incomplete analysis: status partial"),
            _rrow("rw-04-d:repo", "error", "not installed: /x"),
            _rrow("rw-05-e:repo", "ok", ""),
        ]
    }
    assert rerun_plan(rows) == {"t": ["rw-01-a:repo", "rw-02-b:repo", "rw-03-c:repo"]}


def test_a_rerun_must_use_exactly_the_planned_cases(tmp_path: Path) -> None:
    plan = {"t": ["rw-01-a:repo"], "u": []}
    write_rerun(plan, tmp_path / "rerun")
    assert (tmp_path / "rerun" / "cases-t.txt").read_text(encoding="utf-8") == "rw-01-a:repo\n"
    assert not (tmp_path / "rerun" / "cases-u.txt").exists()
    corpus = tmp_path / "corpus.json"
    corpus.write_text("{}", encoding="utf-8")
    protocol = tmp_path / "PROTOCOL.md"
    protocol.write_text("# protocol\n", encoding="utf-8")
    # No run manifest in the re-run folder: refused before any row is read.
    assert rerun_problems(tmp_path / "rerun", plan, None, corpus, protocol)


def test_provenance_refuses_a_run_under_other_hashes(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.json"
    corpus.write_text("{}", encoding="utf-8")
    protocol = tmp_path / "PROTOCOL.md"
    protocol.write_text("# protocol\n", encoding="utf-8")
    run = {
        "manifest_version": 2,
        "manifest_sha256": "0" * 64,
        "protocol_sha256": "0" * 64,
        "code_sha256": "0" * 64,
    }
    problems = provenance_problems({**run, "runs": []}, {}, corpus, protocol)
    assert any("manifest_sha256" in p for p in problems)
    assert any("no run summary" in p for p in problems)


# --- builder: cited paths must exist inside the checkout; globs are only warned ----------------


def test_citations_must_exist_and_stay_inside_the_checkout(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    literal, bad, globs = check_citations(
        ["src/app.py", "src/gone.py", "/etc/passwd", "../outside.py", "us/*.py"], tmp_path
    )
    assert literal == ["src/app.py", "src/gone.py"]
    assert bad == ["src/gone.py", "/etc/passwd", "../outside.py"]
    assert globs == ["us/*.py"]


def test_bootstrap_resamples_keep_the_observed_number_of_positives() -> None:
    """Stratified: every resample holds the observed positives, so their count never varies.

    An unstratified sampler would draw 0, 1 or 2 positives from one positive in 21 rows, and the
    interval would not collapse to a point."""
    rows = [
        {
            "case": "p",
            "family": "ai-app",
            "label": "agent",
            "status": "ok",
            "detected": True,
            "surface": "repo",
            "note": "",
            "items": 1,
            "agentic": True,
            "seconds": 0.0,
        }
    ]
    rows += [{**rows[0], "case": f"n{i}", "label": "none", "detected": False} for i in range(20)]
    low, high = bootstrap(rows, lambda c: float(c["tp"] + c["fn"]), seed=1)
    assert low == 1.0 and high == 1.0


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        ('{"api_key": "abcdefgh1234", "n": 1}', "abcdefgh1234"),
        ('{"k": {"secret": "abcdefgh"}, "t": "x"}', "abcdefgh"),
        ('{"snippet": "password=hunter2supersecret", "b": 2}', "hunter2supersecret"),
        ('{"s": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIB", "b": 1}', "MIIEpAIB"),
        ('{"evidence": {"heuristic.inline-credential|token": 2}}', None),
    ],
)
def test_redacted_json_is_still_json(text: str, leaked: str | None) -> None:
    """A raw report is written after redaction. Redaction may replace a value, never a key or a colon."""
    out = redact(text)
    json.loads(out)  # raises when the redaction broke the structure
    if leaked is not None:
        assert leaked not in out


# --- merge review: the runner must never process tool-controlled files as root ------------------


def test_realworld_runner_refuses_root_before_reading_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.benchmark_realworld import run

    monkeypatch.setattr(run.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit) as exc:
        run.main(
            [
                "--manifest",
                str(tmp_path / "missing.json"),
                "--checkout-root",
                str(tmp_path / "checkouts"),
                "--tool-root",
                str(tmp_path / "tools"),
                "--results",
                str(tmp_path / "results"),
                "--raw",
                str(tmp_path / "raw"),
                "--scratch",
                str(tmp_path / "scratch"),
            ]
        )
    assert exc.value.code == 2
    assert list(tmp_path.iterdir()) == []


def test_private_result_write_refuses_symlink_target_and_parent(tmp_path: Path) -> None:
    from tools.benchmark_realworld.run import _write_private

    outside = tmp_path / "outside.txt"
    outside.write_text("preserve", encoding="utf-8")
    output = tmp_path / "results"
    output.mkdir()
    (output / "report.json").symlink_to(outside)
    with pytest.raises(ValueError, match="non-regular"):
        _write_private(output / "report.json", "overwrite")
    linked = tmp_path / "linked"
    linked.symlink_to(output, target_is_directory=True)
    with pytest.raises(OSError):
        _write_private(linked / "other.json", "overwrite")
    assert outside.read_text(encoding="utf-8") == "preserve"
    assert not (output / "other.json").exists()


def test_private_result_writes_are_atomic_and_private(tmp_path: Path) -> None:
    import stat

    from tools.benchmark_realworld.run import _write_private

    output = tmp_path / "new" / "report.json"
    _write_private(output, "first")
    _write_private(output, "second")
    assert output.read_text(encoding="utf-8") == "second"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    assert list(output.parent.iterdir()) == [output]


def test_unprivileged_namespace_mapping_is_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.benchmark import adapters

    calls = []

    def fake_group(full: list[str], **kwargs: Any) -> tuple[int, str, str, float]:
        calls.append(full)
        return 0, "", "", 0.0

    monkeypatch.setattr(adapters, "_run_group", fake_group)
    try:
        adapters.set_run_as((), user_namespace=True)
        adapters._isolated(["tool"], env={}, cwd=tmp_path)
        assert calls[0][:4] == ["unshare", "--user", "--map-current-user", "--net"]
        assert "setpriv" not in calls[0]
    finally:
        adapters.set_run_as(())


def test_realworld_nonroot_setup_uses_private_paths_and_preserves_umask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.benchmark import adapters
    from tools.benchmark_realworld import run

    manifest = tmp_path / "corpus.json"
    manifest.write_text('{"version": 2}', encoding="utf-8")
    monkeypatch.setattr(run.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(run.os, "getuid", lambda: 1000)
    monkeypatch.setattr(run, "validate_manifest", lambda doc: [])
    monkeypatch.setattr(run, "build_cases_v2", lambda repos, root: [])
    monkeypatch.setattr(run, "ADAPTERS_V2", ())
    monkeypatch.setattr(run, "checkout_head", lambda root: "a" * 40)
    monkeypatch.setattr(run.os, "umask", lambda mode: pytest.fail("runner must not change the umask"))
    # The test process may itself be root; emulate directories owned by the mocked operator.
    original_fstat = run.os.fstat

    def operator_stat(fd: int) -> Any:
        from types import SimpleNamespace

        info = original_fstat(fd)
        return SimpleNamespace(st_uid=1000, st_mode=info.st_mode)

    monkeypatch.setattr(run.os, "fstat", operator_stat)
    try:
        assert (
            run.main(
                [
                    "--manifest",
                    str(manifest),
                    "--checkout-root",
                    str(tmp_path),
                    "--tool-root",
                    str(tmp_path),
                    "--results",
                    str(tmp_path / "results"),
                    "--raw",
                    str(tmp_path / "raw"),
                    "--scratch",
                    str(tmp_path / "scratch"),
                ]
            )
            == 0
        )
        assert adapters._USER_NAMESPACE is False
        assert json.loads((tmp_path / "results" / "run-manifest.json").read_text())["cases"] == 0
        assert (tmp_path / "scratch").stat().st_mode & 0o777 == 0o700
    finally:
        adapters.set_run_as(())


@pytest.mark.parametrize("uid,euid", [(0, 1000), (1000, 0)])
def test_exit_probe_refuses_root_before_reading_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], uid: int, euid: int
) -> None:
    import importlib.util

    script = Path(__file__).resolve().parents[2] / "tools/benchmark_realworld/v2/exit-probe/exit_probe.py"
    spec = importlib.util.spec_from_file_location("benchmark_exit_probe_test", script)
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    monkeypatch.setattr(probe.os, "getuid", lambda: uid)
    monkeypatch.setattr(probe.os, "geteuid", lambda: euid)
    monkeypatch.setattr(probe.os, "umask", lambda mode: pytest.fail("probe must not change the umask"))
    monkeypatch.setattr(probe, "CORPUS", tmp_path / "missing.json")
    monkeypatch.setattr(probe, "SCRATCH", tmp_path / "scratch")
    assert probe.main() == 2
    assert "refusing root" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []
