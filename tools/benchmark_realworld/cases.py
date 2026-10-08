"""Real-world corpus model: manifest validation, checkout identity and home-view labels.

The manifest (``corpus.json``) lists public repositories by checkout directory
and pinned commit. ``verify_checkout`` fails closed when a checkout is not at
its pinned commit, so a result can only describe the commits in the manifest.
Home-view labels are computed from paths (protocol section 6); repo labels come
from the manifest and are fixed by the protocol before any scored run.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.benchmark.common import Case

LABELS = frozenset({"agent", "llm", "none", "ambiguous"})
STRATA = frozenset({"ai-app", "hard-negative", "ordinary"})
CONFIDENCE = frozenset({"high", "medium", "low"})
HOME_POSITIVE = "client"  # home-view label: a user-scope AI client configuration exists

# User-scope AI-client paths (protocol section 6). Project-scope files such as
# ``.mcp.json`` are deliberately absent: clients do not read them from $HOME.
HOME_VIEW_PATHS = (
    ".claude.json",
    ".claude/settings.json",
    ".claude/agents",
    ".cursor/mcp.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".codeium/windsurf/mcp_config.json",
    ".continue/config.json",
    ".continue/config.yaml",
    ".aider.conf.yml",
    ".config/goose/config.yaml",
    ".kiro/settings/mcp.json",
    ".aws/amazonq/mcp.json",
    ".openclaw",
    ".config/Code/User/mcp.json",
)

_SHA = re.compile(r"^[0-9a-f]{40}$")
_ID = re.compile(r"^rw-\d{2}-[a-z0-9][a-z0-9-]*$")
_SECRET = re.compile(
    r"(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AIza[0-9A-Za-z_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "LICENSE-MIT", "LICENSE-APACHE")


class ManifestError(ValueError):
    """The corpus manifest is malformed or a checkout does not match it."""


@dataclass
class RealCase(Case):
    """A repository case. ``surface`` is ``repo`` or ``endpoint`` (root read as $HOME)."""

    source_dir: Path | None = None


def validate_manifest(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the repository entries after checking every field the runner relies on."""
    repos = doc.get("repos")
    if not isinstance(repos, list) or not repos:
        raise ManifestError("manifest needs a non-empty 'repos' list")
    seen: set[str] = set()
    for entry in repos:
        rid = str(entry.get("id", ""))
        if not _ID.match(rid):
            raise ManifestError(f"bad id {rid!r}")
        if rid in seen:
            raise ManifestError(f"duplicate id {rid}")
        seen.add(rid)
        if not _SHA.match(str(entry.get("sha", ""))):
            raise ManifestError(f"{rid}: sha must be a 40-character lowercase hex commit")
        if entry.get("label") not in LABELS:
            raise ManifestError(f"{rid}: label must be one of {sorted(LABELS)}")
        if entry.get("stratum") not in STRATA:
            raise ManifestError(f"{rid}: stratum must be one of {sorted(STRATA)}")
        if entry.get("confidence") not in CONFIDENCE:
            raise ManifestError(f"{rid}: confidence must be one of {sorted(CONFIDENCE)}")
        for key in ("repo", "dir", "url", "license"):
            if not str(entry.get(key, "")).strip():
                raise ManifestError(f"{rid}: missing {key}")
        if ".." in Path(entry["dir"]).parts or Path(entry["dir"]).is_absolute():
            raise ManifestError(f"{rid}: dir must be a relative path under the checkout root")
        labels = entry.get("labels", {})
        if not isinstance(labels, dict) or not {"A", "B"} <= set(labels):
            raise ManifestError(f"{rid}: labels must record labeler A and labeler B")
        if any(v not in LABELS for v in labels.values()):
            raise ManifestError(f"{rid}: every labeler value must be one of {sorted(LABELS)}")
    return list(repos)


def checkout_head(root: Path) -> str:
    """The commit a checkout is at, from git itself (no network)."""
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    head = proc.stdout.strip()
    if proc.returncode != 0 or not _SHA.match(head):
        raise ManifestError(f"{root} is not a git checkout with a readable HEAD")
    return head


def verify_checkout(root: Path, sha: str) -> None:
    """Fail closed unless ``root`` is at the pinned commit."""
    head = checkout_head(root)
    if head != sha:
        raise ManifestError(f"{root} is at {head}, manifest pins {sha}")


def home_view_label(root: Path) -> str:
    """``client`` when a user-scope AI-client path exists and is non-empty, else ``none``."""
    for rel in HOME_VIEW_PATHS:
        path = root / rel
        if path.is_symlink():
            continue
        if path.is_file() and path.stat().st_size > 0:
            return HOME_POSITIVE
        if path.is_dir() and any(path.iterdir()):
            return HOME_POSITIVE
    return "none"


def detect_license(root: Path) -> str:
    """A coarse SPDX-like name from the LICENSE file text; ``unrecognized`` when unsure."""
    for name in _LICENSE_FILES:
        path = root / name
        if path.is_file() and not path.is_symlink():
            text = path.read_text(encoding="utf-8", errors="replace")[:20000]
            if "Permission is hereby granted, free of charge" in text:
                return "MIT"
            if "Apache License" in text and "Version 2.0" in text:
                return "Apache-2.0"
            if "GNU AFFERO GENERAL PUBLIC LICENSE" in text:
                return "AGPL-3.0"
            if "GNU GENERAL PUBLIC LICENSE" in text:
                return "GPL-3.0" if "Version 3" in text else "GPL-2.0"
            if "Redistribution and use in source and binary forms" in text:
                return "BSD"
            if "ISC License" in text:
                return "ISC"
            if "Mozilla Public License Version 2.0" in text:
                return "MPL-2.0"
            return "unrecognized"
    return "none-found"


def redact(text: str) -> str:
    """Replace secret-shaped strings. Applied to every tool output that is written down."""
    return _SECRET.sub("[redacted]", text)


def sanitize_note(text: str, *, paths: tuple[str, ...] = (), limit: int = 200) -> str:
    """Make a tool note safe to commit: hide work paths and secret-shaped strings, then truncate."""
    out = text
    for path in paths:
        if path:
            out = out.replace(path, "<path>")
    return redact(out).replace("\n", " | ")[:limit]


def build_cases(repos: list[dict[str, Any]], checkout_root: Path) -> list[RealCase]:
    """Two cases per repository: the repo surface and the home-view surface."""
    cases: list[RealCase] = []
    for entry in repos:
        root = checkout_root / entry["dir"]
        verify_checkout(root, entry["sha"])
        rationale = "; ".join(entry.get("evidence", []))[:500]
        cases.append(
            RealCase(
                case_id=f"{entry['id']}:repo",
                surface="repo",
                family=entry["stratum"],
                label=entry["label"],
                difficulty=entry["confidence"],
                rationale=rationale,
                source_dir=root,
            )
        )
        cases.append(
            RealCase(
                case_id=f"{entry['id']}:home",
                surface="endpoint",
                family=entry["stratum"],
                label=home_view_label(root),
                difficulty="path-based",
                rationale="home-view: user-scope AI-client paths (protocol section 6)",
                source_dir=root,
            )
        )
    return cases
