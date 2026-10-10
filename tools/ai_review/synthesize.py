"""Orchestrator/synthesizer for the AI Review Gate.

Runs the deterministic half of the multi-agent review: it reads the reviewer
agents' finding artifacts, validates them against the schema, deduplicates
them against scanner evidence and each other, redacts them, and renders the
single consolidated GitHub Review plus the gate decision that the
ai-review-gate workflow posts.

The workflow runs the base-ref copy of this module, never the pull request's.
Every input (finding files, diff list, labels, scanner fingerprints) is
untrusted. The gate fails closed:

- findings directory missing or unreadable  -> failure (bypass_unavailable)
- any finding file that is not valid schema -> failure (malformed_findings)
- a finding that names a file not in the diff -> failure (stale_findings)
- ``ai-review: blocked`` label on the PR     -> failure (blocked_label)
- high-risk diff with zero valid findings    -> failure (insufficient_evidence)
- any critical/high finding                  -> failure (blocking_findings)

Otherwise the gate passes and the review posts as COMMENT. This script
never has merge authority; branch protection and human reviewers decide.

Exit codes: 0 gate passes, 1 gate fails, 2 usage error.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from tools.ai_review.sanitize import redact
from tools.ai_review.schema import BLOCKING_SEVERITIES, MAX_FINDINGS_PER_FILE, Finding, parse_finding

MAX_INLINE_COMMENTS = 50

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

BLOCKED_LABEL = "ai-review: blocked"
HIGH_RISK_LABEL = "ai-review: high-risk"


class GateInputError(Exception):
    """A required input is missing or unusable; never a passing gate."""


def read_input(path: Path, limit: int = 1_000_000) -> str:
    """Read bounded regular inputs without following any symlink component."""
    import stat

    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = path.absolute().parts[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(child, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise GateInputError("input is not a regular file")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise GateInputError("input size limit exceeded")
        return data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateInputError("input unavailable") from exc
    finally:
        os.close(fd)


def _read_diff_files(path: Path) -> set[str]:
    try:
        text = read_input(path)
    except GateInputError as exc:
        raise GateInputError("diff file list unreadable") from exc
    from tools.ai_review.schema import _path

    if any(_path(line) != line for line in text.splitlines()):
        raise GateInputError("diff file list malformed")
    return {line.strip() for line in text.splitlines() if line.strip()}


def _read_scanner_fingerprints(path: Path | None) -> set[str]:
    """Fingerprints of findings a scanner (CodeQL, secret scanning, Dependabot)
    already reported; agent findings carrying one are deduplicated onto it."""
    if path is None:
        return set()
    try:
        data = json.loads(read_input(path))
    except (GateInputError, ValueError) as exc:
        raise GateInputError("scanner fingerprint list unreadable or not JSON") from exc
    if not isinstance(data, list) or any(
        not isinstance(item, str) or not item.strip() or len(item) > 200 for item in data
    ):
        raise GateInputError("scanner fingerprint list must be a JSON list of strings")
    return set(data)


def load_findings(directory: Path) -> tuple[list[Finding], int]:
    """All valid findings under ``directory`` and the count of invalid files.

    A file with no valid findings, invalid JSON, or more than
    MAX_FINDINGS_PER_FILE entries counts as invalid: a reviewer that cannot
    produce the schema produces noise, and the gate fails closed on noise.
    """
    if not directory.is_dir():
        raise GateInputError("findings directory missing or not a directory")
    findings: list[Finding] = []
    invalid_files = 0
    files = sorted(directory.glob("*.json"))
    if not files:
        raise GateInputError("findings directory empty")
    if len(files) > 20:
        raise GateInputError("findings artifact limit exceeded")
    for file in files:
        if file.is_symlink() or not file.is_file():
            invalid_files += 1
            continue
        try:
            data = json.loads(read_input(file))
        except (GateInputError, ValueError):
            invalid_files += 1
            continue
        entries = data if isinstance(data, list) else [data]
        if not entries or len(entries) > MAX_FINDINGS_PER_FILE:
            invalid_files += 1
            continue
        parsed = [finding for finding in (parse_finding(entry) for entry in entries) if finding]
        if len(parsed) != len(entries):
            invalid_files += 1
        findings.extend(parsed)
    return findings, invalid_files


def decide(
    findings: list[Finding],
    *,
    labels: set[str],
    high_risk: bool,
    invalid_files: int,
    diff_files: set[str],
) -> tuple[str, str, str]:
    """The gate verdict as ``(event, conclusion, reason)``.

    ``event`` is the GitHub Review event (COMMENT or REQUEST_CHANGES) and
    ``conclusion`` the check-run conclusion (success or failure). Fail-closed
    ordering: external block first, then integrity failures, then content.
    """
    if BLOCKED_LABEL in labels:
        return "REQUEST_CHANGES", "failure", "blocked_label"
    if invalid_files:
        return "COMMENT", "failure", "malformed_findings"
    stale = sorted(
        {finding.path for finding in findings if finding.path is not None and finding.path not in diff_files}
    )
    if stale:
        return "COMMENT", "failure", "stale_findings"
    if high_risk and not findings:
        return "COMMENT", "failure", "insufficient_evidence"
    if any(finding.severity in BLOCKING_SEVERITIES for finding in findings):
        return "REQUEST_CHANGES", "failure", "blocking_findings"
    return "COMMENT", "success", "pass"


def dedupe(findings: list[Finding], scanner_fingerprints: set[str]) -> tuple[list[Finding], int]:
    """Unique findings by identity; scanner-reported and duplicate ones drop out."""
    seen: set[str] = set(scanner_fingerprints)
    unique: list[Finding] = []
    dropped = 0
    for finding in sorted(findings, key=lambda finding: SEVERITY_RANK[finding.severity]):
        if finding.identity in seen:
            dropped += 1
            continue
        seen.add(finding.identity)
        unique.append(finding)
    unique.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.agent, f.path or "", f.line or 0, f.title))
    return unique, dropped


def _comment_body(finding: Finding) -> str:
    header = f"**[{finding.severity.upper()}] {finding.title}**  — _{finding.agent} reviewer_"
    refs = "  ".join(
        part
        for part in (
            f"`{finding.cwe}`" if finding.cwe else "",
            f"`{finding.owasp}`" if finding.owasp else "",
            f"confidence: {finding.confidence}" if finding.confidence else "",
        )
        if part
    )
    return redact("\n\n".join(part for part in (header, refs, finding.body) if part))


def render(
    findings: list[Finding],
    *,
    event: str,
    reason: str,
    high_risk: bool,
    invalid_files: int,
    duplicates: int,
) -> tuple[str, list[dict[str, object]]]:
    """The consolidated review body and at most MAX_INLINE_COMMENTS comments."""
    inline = [f for f in findings if f.path is not None and f.line is not None]
    summary_only = [f for f in findings if f.path is None]
    overflow = inline[MAX_INLINE_COMMENTS:]
    inline = inline[:MAX_INLINE_COMMENTS]

    counts = {severity: sum(1 for f in findings if f.severity == severity) for severity in SEVERITY_RANK}
    lines = [
        "## AI Review Gate",
        "",
        f"**Decision:** `{event}` — **reason:** `{reason}`"
        + (" — high-risk paths in diff." if high_risk else ""),
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines += [f"| {severity} | {counts[severity]} |" for severity in SEVERITY_RANK]
    lines.append("")
    lines.append(
        f"{len(findings)} unique finding(s)"
        f" ({duplicates} duplicate or scanner-reported dropped, {invalid_files} invalid artifact(s))."
    )
    if reason == "insufficient_evidence":
        lines.append("")
        lines.append(
            "> High-risk paths changed and no reviewer produced a finding. "
            "Defaulting to *insufficient evidence for security acceptance* rather than a silent pass."
        )
    if reason == "malformed_findings":
        lines.append("")
        lines.append(
            "> One or more reviewer artifacts were missing, unreadable or off-schema. "
            "The gate fails closed; re-run the reviewers."
        )
    for finding in summary_only + overflow:
        lines.append("")
        lines.append(_comment_body(finding))
    lines.append("")
    lines.append(
        "_AI-assisted review is advisory evidence for the human gate. "
        "It is not independent human review, and branch protection — not this review — decides the merge._"
    )
    body = redact("\n".join(lines))
    comments: list[dict[str, object]] = [
        {"path": redact(f.path or ""), "line": f.line, "side": "RIGHT", "body": _comment_body(f)}
        for f in inline
    ]
    return body, comments


def main() -> int:
    out_dir = os.environ.get("AI_REVIEW_OUT_DIR")
    findings_dir = os.environ.get("AI_REVIEW_FINDINGS_DIR")
    diff_list = os.environ.get("AI_REVIEW_DIFF_FILES")
    if not out_dir or not findings_dir or not diff_list:
        print(
            "usage: AI_REVIEW_OUT_DIR=.. AI_REVIEW_FINDINGS_DIR=.. AI_REVIEW_DIFF_FILES=.. "
            "python -m tools.ai_review.synthesize",
            file=sys.stderr,
        )
        return 2
    labels = {label.strip() for label in os.environ.get("AI_REVIEW_LABELS", "").split(",") if label.strip()}
    high_risk = os.environ.get("AI_REVIEW_HIGH_RISK", "false").lower() == "true" or HIGH_RISK_LABEL in labels
    scanner_path = os.environ.get("AI_REVIEW_SCANNER_FINGERPRINTS")

    try:
        diff_files = _read_diff_files(Path(diff_list))
        scanner_fingerprints = _read_scanner_fingerprints(Path(scanner_path) if scanner_path else None)
        raw, invalid_files = load_findings(Path(findings_dir))
    except GateInputError as exc:
        # Missing evidence is a failing gate, not a passing one.
        raw, invalid_files, diff_files = [], 0, set()
        event, conclusion, reason = "COMMENT", "failure", "bypass_unavailable"
        if BLOCKED_LABEL in labels:
            event, reason = "REQUEST_CHANGES", "blocked_label"
        print(f"ai-review-gate: {exc} -> {reason}", file=sys.stderr)
    else:
        event, conclusion, reason = decide(
            raw,
            labels=labels,
            high_risk=high_risk,
            invalid_files=invalid_files,
            diff_files=diff_files,
        )

    unique, duplicates = dedupe(raw, scanner_fingerprints if "scanner_fingerprints" in dir() else set())
    if reason == "stale_findings":
        # Stale findings are reported, never posted inline against a file the
        # diff does not contain.
        unique = [f for f in unique if f.path is None]
    body, comments = render(
        unique,
        event=event,
        reason=reason,
        high_risk=high_risk,
        invalid_files=invalid_files,
        duplicates=duplicates,
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "review-body.md").write_text(body + "\n", encoding="utf-8")
    (out / "review-comments.json").write_text(json.dumps(comments, indent=2) + "\n", encoding="utf-8")
    decision = {
        "event": event,
        "conclusion": conclusion,
        "reason": reason,
        "high_risk": high_risk,
        "findings": len(unique),
        "duplicates_dropped": duplicates,
        "invalid_artifacts": invalid_files,
        "inline_comments": len(comments),
    }
    (out / "decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    print(f"ai-review-gate: {json.dumps(decision)}")
    return 0 if conclusion == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
