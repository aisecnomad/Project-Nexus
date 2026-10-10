"""Regression tests for tools.ai_review.synthesize.

The gate fails closed: every blocked path (blocked label, malformed or
missing artifacts, findings that name files outside the diff, a high-risk
diff with no findings, a critical/high finding) must fail, and the passing
paths must post COMMENT with only valid, deduplicated, redacted content.
These tests run the committed decision code, not a copy of it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.ai_review.schema import parse_finding
from tools.ai_review.synthesize import decide, dedupe, load_findings, render

ROOT = Path(__file__).resolve().parents[1]


def finding(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": "1",
        "agent": "appsec",
        "severity": "high",
        "category": "security",
        "title": "unvalidated redirect target",
        "body": "An attacker controls the redirect. Assume no middleware validates it. CWE-601.",
        "path": "shadowscan/cli.py",
        "line": 12,
        "confidence": "high",
        "cwe": "CWE-601",
    }
    base.update(overrides)
    return base


def write_findings(directory: Path, files: dict[str, object]) -> None:
    directory.mkdir(parents=True)
    for name, data in files.items():
        (directory / name).write_text(json.dumps(data), encoding="utf-8")


class TestParseFinding:
    def test_valid_round_trip(self) -> None:
        parsed = parse_finding(finding())
        assert parsed is not None
        assert parsed.agent == "appsec"
        assert parsed.blocking is True
        assert parsed.identity.startswith("sha256:")

    def test_supplied_fingerprint_wins(self) -> None:
        parsed = parse_finding(finding(fingerprint="codeql:py/xss:123"))
        assert parsed is not None and parsed.identity == "codeql:py/xss:123"

    def test_rejects_bad_schema_version(self) -> None:
        assert parse_finding(finding(schema_version="2")) is None

    def test_rejects_unknown_agent_and_severity(self) -> None:
        assert parse_finding(finding(agent="root")) is None
        assert parse_finding(finding(severity="informational")) is None

    def test_rejects_path_without_line_and_backwards(self) -> None:
        assert parse_finding(finding(line=None)) is None
        assert parse_finding(finding(path=None)) is None

    def test_rejects_traversal_and_absolute_paths(self) -> None:
        assert parse_finding(finding(path="../secret.py")) is None
        assert parse_finding(finding(path="/etc/passwd")) is None
        assert parse_finding(finding(path="shadowscan\\cli.py")) is None

    def test_rejects_overlong_and_multiline_titles(self) -> None:
        assert parse_finding(finding(title="x" * 201)) is None
        assert parse_finding(finding(title="one\ntwo")) is None

    def test_blocking_is_derived_not_trusted(self) -> None:
        parsed = parse_finding(finding(severity="critical", blocking=False))
        assert parsed is not None and parsed.blocking is True

    def test_malformed_cwe_is_dropped_not_fatal(self) -> None:
        parsed = parse_finding(finding(cwe="CWE-; rm -rf /"))
        assert parsed is not None and parsed.cwe is None


class TestDecide:
    def decide_with(self, findings: list[dict[str, object]], **kw: object) -> tuple[str, str, str]:
        parsed = [f for f in (parse_finding(x) for x in findings) if f]
        kwargs = {
            "labels": set(),
            "high_risk": False,
            "invalid_files": 0,
            "diff_files": {"shadowscan/cli.py"},
        }
        kwargs.update(kw)
        return decide(parsed, **kwargs)  # type: ignore[arg-type]

    def test_passes_with_only_low_findings(self) -> None:
        event, conclusion, reason = self.decide_with([finding(severity="low")])
        assert (event, conclusion, reason) == ("COMMENT", "success", "pass")

    def test_critical_or_high_blocks(self) -> None:
        for severity in ("critical", "high"):
            event, conclusion, reason = self.decide_with([finding(severity=severity)])
            assert (event, conclusion, reason) == ("REQUEST_CHANGES", "failure", "blocking_findings")

    def test_blocked_label_wins_over_everything(self) -> None:
        event, conclusion, reason = self.decide_with(
            [finding()], labels={"ai-review: blocked"}, invalid_files=3
        )
        assert (event, conclusion, reason) == ("REQUEST_CHANGES", "failure", "blocked_label")

    def test_malformed_artifacts_fail(self) -> None:
        _, conclusion, reason = self.decide_with([finding(severity="low")], invalid_files=1)
        assert (conclusion, reason) == ("failure", "malformed_findings")

    def test_finding_outside_diff_fails(self) -> None:
        _, conclusion, reason = self.decide_with(
            [finding(severity="low")], diff_files={"other/file.py"}
        )
        assert (conclusion, reason) == ("failure", "stale_findings")

    def test_high_risk_without_findings_fails_closed(self) -> None:
        event, conclusion, reason = self.decide_with([], high_risk=True)
        assert (event, conclusion, reason) == ("COMMENT", "failure", "insufficient_evidence")

    def test_low_risk_without_findings_passes(self) -> None:
        assert self.decide_with([])[2] == "pass"


class TestDedupe:
    def test_scanner_fingerprint_suppresses_agent_copy(self) -> None:
        agent_copy = parse_finding(finding(fingerprint="codeql:py/xss:123"))
        assert agent_copy is not None
        unique, dropped = dedupe([agent_copy], {"codeql:py/xss:123"})
        assert unique == [] and dropped == 1

    def test_duplicates_collapse_and_sort_by_severity(self) -> None:
        low = parse_finding(finding(severity="low", title="b"))
        high = parse_finding(finding(severity="high", title="a"))
        low_again = parse_finding(finding(severity="low", title="b"))
        assert low and high and low_again
        unique, dropped = dedupe([low, high, low_again], set())
        assert dropped == 1
        assert [f.severity for f in unique] == ["high", "low"]


class TestLoadFindings:
    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        try:
            load_findings(tmp_path / "nope")
        except Exception as exc:
            assert "findings directory" in str(exc)
        else:
            raise AssertionError("missing directory must not load")

    def test_invalid_files_count_and_valid_still_load(self, tmp_path: Path) -> None:
        write_findings(
            tmp_path,
            {
                "good.json": [finding()],
                "notjson.json": None,
                "empty.json": [],
                "offschema.json": [{"schema_version": "1"}],
            },
        )
        (tmp_path / "notjson.json").write_text("{not json", encoding="utf-8")
        findings, invalid = load_findings(tmp_path)
        assert len(findings) == 1 and invalid == 3


class TestRender:
    def test_inline_cap_with_summary_overflow(self) -> None:
        parsed = [
            f
            for i in range(60)
            if (f := parse_finding(finding(severity="low", title=f"nit {i:02d}", line=i + 1)))
        ]
        body, comments = render(
            parsed, event="COMMENT", reason="pass", high_risk=False, invalid_files=0, duplicates=0
        )
        assert len(comments) == 50
        assert "nit 50" in body  # the 51st finding is listed in the summary
        for comment in comments:
            assert comment["side"] == "RIGHT"

    def test_rendered_output_is_redacted(self) -> None:
        secret = "ghp_" + "a1" * 20
        parsed = parse_finding(finding(severity="low", body=f"token {secret} in the log"))
        assert parsed is not None
        body, comments = render(
            [parsed], event="COMMENT", reason="pass", high_risk=False, invalid_files=0, duplicates=0
        )
        assert secret not in body
        assert all(secret not in str(comment["body"]) for comment in comments)

    def test_summary_states_not_independent_review(self) -> None:
        body, _ = render(
            [], event="COMMENT", reason="pass", high_risk=False, invalid_files=0, duplicates=0
        )
        assert "not independent human review" in body


class TestMainEndToEnd:
    """Run the committed module the way the workflow does."""

    def run_gate(
        self,
        tmp_path: Path,
        files: dict[str, object] | None,
        env_extra: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object]]:
        out_dir = tmp_path / "out"
        findings_dir = tmp_path / "findings"
        if files is not None:
            write_findings(findings_dir, files)
        diff = tmp_path / "diff.txt"
        diff.write_text("shadowscan/cli.py\n", encoding="utf-8")
        env = {
            **os.environ,
            "AI_REVIEW_OUT_DIR": str(out_dir),
            "AI_REVIEW_FINDINGS_DIR": str(findings_dir),
            "AI_REVIEW_DIFF_FILES": str(diff),
            **(env_extra or {}),
        }
        result = subprocess.run(
            [sys.executable, "-m", "tools.ai_review.synthesize"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        decision = json.loads((out_dir / "decision.json").read_text(encoding="utf-8"))
        return result.returncode, decision

    def test_missing_findings_dir_fails_closed(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(tmp_path, None)
        assert returncode == 1
        assert decision["reason"] == "bypass_unavailable"
        assert decision["conclusion"] == "failure"

    def test_clean_pass_exits_zero(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(tmp_path, {"appsec.json": [finding(severity="low")]})
        assert returncode == 0
        assert decision["conclusion"] == "success"
        assert decision["inline_comments"] == 1

    def test_blocking_finding_fails_gate(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(tmp_path, {"appsec.json": [finding()]})
        assert returncode == 1
        assert decision["event"] == "REQUEST_CHANGES"
        assert decision["reason"] == "blocking_findings"

    def test_blocked_label_fails_gate(self, tmp_path: Path) -> None:
        returncode, decision = self.run_gate(
            tmp_path,
            {"appsec.json": [finding(severity="low")]},
            {"AI_REVIEW_LABELS": "ai-review: blocked"},
        )
        assert returncode == 1 and decision["reason"] == "blocked_label"

    def test_usage_error_without_environment(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "tools.ai_review.synthesize"],
            cwd=ROOT,
            env={k: v for k, v in os.environ.items() if not k.startswith("AI_REVIEW_")},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 2
