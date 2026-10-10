"""Bounded GitHub transport and preflight; execute only from the trusted base."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

from tools.ai_review import synthesize
from tools.ai_review.sanitize import redact
from tools.ai_review.schema import AGENTS, _path

MAX_RESPONSE = 8_000_000


class GateError(Exception):
    """A fixed diagnostic, never an API response or untrusted exception."""


class GitHub:
    def __init__(self) -> None:
        self.repo = os.environ["GITHUB_REPOSITORY"]
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", self.repo):
            raise GateError("invalid repository")
        self.token = os.environ["GH_TOKEN"]

    def request(self, endpoint: str, payload: dict[str, Any] | None = None) -> Any:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{self.repo}/{endpoint}",
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        if endpoint.startswith("check-runs/") and payload is not None:
            request.method = "PATCH"

        # Never forward credentials to a redirect destination.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
            ) -> None:
                return None

        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise GateError("API response limit exceeded")
            return json.loads(data)
        except (OSError, ValueError):
            raise GateError("GitHub API unavailable or malformed") from None

    def pages(self, endpoint: str) -> list[Any]:
        result: list[Any] = []
        for page in range(1, 32):
            data = self.request(f"{endpoint}?per_page=100&page={page}")
            if not isinstance(data, list):
                raise GateError("API list malformed")
            result.extend(data)
            if len(data) < 100:
                return result
        raise GateError("API pagination limit exceeded")


def snapshot(api: GitHub, number: int, head: str) -> tuple[list[Any], list[str]]:
    pr = api.request(f"pulls/{number}")
    if pr["head"]["sha"] != head:
        raise GateError("superseded pull request")
    expected_base = os.environ.get("PR_BASE_SHA")
    if expected_base and pr["base"]["sha"] != expected_base:
        raise GateError("superseded base revision")
    files = api.pages(f"pulls/{number}/files")
    if len(files) != pr["changed_files"]:
        raise GateError("incomplete diff")
    paths = [file["filename"] for file in files]
    labels = [label["name"] for label in api.pages(f"issues/{number}/labels")]
    if any(not isinstance(path, str) or _path(path) != path for path in paths):
        raise GateError("diff paths malformed")
    if any(not isinstance(label, str) or "," in label or "\n" in label for label in labels):
        raise GateError("labels malformed")
    current = api.request(f"pulls/{number}")
    if current["head"]["sha"] != head or (expected_base and current["base"]["sha"] != expected_base):
        raise GateError("superseded pull request")
    return files, labels


def high_risk(paths: list[str]) -> bool:
    return any(
        path.startswith((".github/", "tools/", "shadowscan/", "tests/"))
        or path.startswith("requirements")
        or path in {"Dockerfile", "pyproject.toml", "Makefile", "CODEOWNERS", "AGENTS.md"}
        or not path.endswith((".md", ".png", ".svg", ".jpg"))
        for path in paths
    )


def diff_digest(files: list[Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            [
                os.environ.get("PR_BASE_SHA", ""),
                sorted(
                    (file["filename"], file["sha"], file["status"])
                    for file in files
                    if not file["filename"].startswith(".github/ai-review/")
                ),
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def validate_evidence(root: Path, digest: str) -> None:
    manifest = json.loads(synthesize.read_input(root / "manifest.json"))
    roles = set(AGENTS) - {"orchestrator"}
    if manifest != {"schema_version": "1", "diff_digest": digest, "agents": sorted(roles)}:
        raise GateError("evidence manifest malformed or stale")
    for role in roles:
        findings, invalid = synthesize.load_findings(root / "findings" / role)
        if invalid or not findings or any(finding.agent != role for finding in findings):
            raise GateError("specialist evidence malformed or unavailable")
        for file in sorted((root / "findings" / role).glob("*.json")):
            data = json.loads(synthesize.read_input(file))
            for entry in data if isinstance(data, list) else [data]:
                if (
                    isinstance(entry.get("fingerprint"), str)
                    and redact(entry["fingerprint"]) != entry["fingerprint"]
                ):
                    raise GateError("unsafe fingerprint")
                if entry.get("confidence") not in {"high", "medium", "low"} or any(
                    not isinstance(entry.get(field), str)
                    or not entry[field].strip()
                    or len(entry[field]) > 2500
                    for field in ("scenario", "recommendation", "assumptions")
                ):
                    raise GateError("structured review details missing")
    synthesize._read_scanner_fingerprints(root / "scanner-fingerprints.json")


def prepare(api: GitHub, number: int, head: str, root: Path, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    files, labels = snapshot(api, number, head)
    paths = [file["filename"] for file in files]
    (out / "diff.txt").write_text("".join(path + "\n" for path in paths), encoding="utf-8")
    os.environ.update(
        AI_REVIEW_OUT_DIR=str(out),
        AI_REVIEW_FINDINGS_DIR=str(out / "validated"),
        AI_REVIEW_DIFF_FILES=str(out / "diff.txt"),
        AI_REVIEW_SCANNER_FINGERPRINTS=str(root / "scanner-fingerprints.json"),
        AI_REVIEW_LABELS=",".join(labels),
        AI_REVIEW_HIGH_RISK=str(high_risk(paths)).lower(),
    )
    try:
        digest = diff_digest(files)
        validate_evidence(root, digest)
        (out / "validated-digest.txt").write_text(digest, encoding="utf-8")
        target = out / "validated"
        target.mkdir()
        for role in sorted(set(AGENTS) - {"orchestrator"}):
            for index, file in enumerate(sorted((root / "findings" / role).glob("*.json"))):
                data = json.loads(synthesize.read_input(file))
                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    entry["body"] = "\n\n".join(
                        f"{field.title()}: {entry[field]}"
                        for field in ("scenario", "recommendation", "assumptions")
                    )
                    entry.update(
                        {key: redact(value) for key, value in entry.items() if isinstance(value, str)}
                    )
                (target / f"{role}-{index}.json").write_text(json.dumps(entries), encoding="utf-8")
    except (GateError, synthesize.GateInputError, ValueError, OSError):
        # No partial accepted artifacts on an integrity failure.
        if (root / "manifest.json").exists():
            malformed = out / "malformed"
            malformed.mkdir()
            (malformed / "invalid.json").write_text("null", encoding="utf-8")
            os.environ["AI_REVIEW_FINDINGS_DIR"] = str(malformed)
        else:
            os.environ["AI_REVIEW_FINDINGS_DIR"] = str(out / "unavailable")
    return synthesize.main()


def publish(
    api: GitHub,
    number: int,
    head: str,
    out: Path,
    failed: bool,
    check: dict[str, Any] | None = None,
) -> int:
    # Re-evaluate against current labels/diff; never replay a prior decision.
    if failed:
        decision = {"event": "COMMENT", "conclusion": "failure", "reason": "bypass_unavailable"}
        body = (
            "## AI Review Gate\n\nEvidence unavailable. Gate failed closed.\n\nNot independent human review."
        )
        comments: list[Any] = []
    else:
        decision = json.loads(synthesize.read_input(out / "decision.json"))
        body = synthesize.read_input(out / "review-body.md")
        comments = json.loads(synthesize.read_input(out / "review-comments.json"))
    if (
        os.environ.get("AI_REVIEW_PREFLIGHT_RESULT", "success") != "success"
        and decision["conclusion"] == "success"
    ):
        decision.update(conclusion="failure", reason="bypass_unavailable")
        body += "\n\nPreflight did not complete successfully. Gate failed closed."
    files, labels = snapshot(api, number, head)
    if not failed and diff_digest(files) != synthesize.read_input(out / "validated-digest.txt"):
        raise GateError("superseded evidence")
    if synthesize.BLOCKED_LABEL in labels:
        decision.update(event="REQUEST_CHANGES", conclusion="failure", reason="blocked_label")
        body += "\n\nBlocked by maintainer label."
    # File presence alone cannot prove a line is commentable. Preserve all
    # findings in the summary instead of risking a partial review POST (422).
    for comment in comments:
        body += "\n\n" + comment["body"]
    check = check or api.request(
        "check-runs",
        {
            "name": "AI Review Gate",
            "head_sha": head,
            "status": "in_progress",
        },
    )
    try:
        api.request(
            f"pulls/{number}/reviews",
            {
                "commit_id": head,
                "event": decision["event"],
                "body": redact(body),
            },
        )
    except GateError:
        api.request(
            f"check-runs/{check['id']}",
            {
                "status": "completed",
                "conclusion": "failure",
                "output": {"title": "Review publication unavailable", "summary": "Gate failed closed."},
            },
        )
        raise
    api.request(
        f"check-runs/{check['id']}",
        {
            "status": "completed",
            "conclusion": decision["conclusion"],
            "output": {"title": "AI Review Gate", "summary": decision["reason"]},
        },
    )
    return 0 if decision["conclusion"] == "success" else 1


def main() -> int:
    try:
        api = GitHub()
        number = int(os.environ["PR_NUMBER"])
        head = os.environ["PR_HEAD_SHA"]
        if number < 1 or not re.fullmatch(r"[0-9a-f]{40}", head):
            raise GateError("invalid pull request identity")
        out = Path(os.environ["AI_REVIEW_OUT_DIR"])
        root = Path(os.environ["AI_REVIEW_INPUT"])
        mode = sys.argv[1]
        if mode == "preflight":
            return prepare(api, number, head, root, out)
        if mode == "publish":
            # The second stage independently executes the trusted synthesizer.
            check = api.request(
                "check-runs",
                {
                    "name": "AI Review Gate",
                    "head_sha": head,
                    "status": "in_progress",
                },
            )
            try:
                failed = False
                try:
                    prepare(api, number, head, root, out)
                except (GateError, synthesize.GateInputError, OSError, ValueError, KeyError, TypeError):
                    failed = True
                return publish(api, number, head, out, failed, check)
            except (GateError, synthesize.GateInputError, OSError, ValueError, KeyError, TypeError):
                api.request(
                    f"check-runs/{check['id']}",
                    {
                        "status": "completed",
                        "conclusion": "failure",
                        "output": {"title": "AI Review Gate", "summary": "bypass_unavailable"},
                    },
                )
                raise
        raise GateError("invalid mode")
    except (GateError, synthesize.GateInputError, OSError, ValueError, KeyError, TypeError, IndexError):
        print("AI Review Gate: bypass_unavailable; no untrusted diagnostics emitted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
