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
STRATA = frozenset({"ai-app", "hard-negative", "ordinary", "dotfiles"})  # "dotfiles": v2 endpoint entries
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
_ID = re.compile(r"^rw-\d{2,3}-[a-z0-9][a-z0-9-]*$")
_SECRET = re.compile(
    r"(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?|"  # signed and unsigned JWTs
    r"(?i:bearer)\s+[A-Za-z0-9._~+/=-]{12,}|"
    # A bare keyword and its value. No quote may come between the keyword and its separator: a JSON
    # key such as "token": would then lose its colon, and the raw report would no longer be JSON.
    r"(?i:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['\"]?[^\s,;'\"]{6,}|"
    # A PEM block: its base64 body and line breaks (JSON writes a break as \n), then its END line when
    # present. The body stops at the first other character, so a cut-off block inside JSON stays valid.
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\[nr]|\s|[A-Za-z0-9+/=])*(?:-----END [A-Z ]*PRIVATE KEY-----)?)"
)
# A quoted key and its value, in JSON or a Python dict. Only the value is replaced: the key, the
# colon and both quotes stay, so the text keeps its structure.
_QUOTED_SECRET = re.compile(
    r"""(["'][^"'\\\n]*(?i:password|passwd|secret|token|api[_-]?key)[^"'\\\n]*["']\s*:\s*["'])"""
    r"""[^"'\\\n]{6,}(["'])"""
)
_LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "LICENSE-MIT", "LICENSE-APACHE")


class ManifestError(ValueError):
    """The corpus manifest is malformed or a checkout does not match it."""


@dataclass
class RealCase(Case):
    """A repository case. ``surface`` is ``repo`` or ``endpoint`` (root read as $HOME)."""

    source_dir: Path | None = None


def surfaces_of(entry: dict[str, Any]) -> tuple[str, ...]:
    """The surfaces an entry is run on. An entry without ``surfaces`` is a v1 entry: both."""
    surfaces = tuple(entry.get("surfaces", ("repo", "home")))
    if not surfaces or not set(surfaces) <= {"repo", "home"} or len(set(surfaces)) != len(surfaces):
        raise ManifestError(f"{entry.get('id')}: surfaces must be a non-empty set of 'repo' and 'home'")
    return surfaces


def validate_manifest(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the repository entries after checking every field the runner relies on.

    An entry without the repo surface (v2 endpoint dotfiles) has no repository
    label, so its ``label`` must be ``n/a``; its home-view label is computed.
    """
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
        surfaces = surfaces_of(entry)
        if entry.get("stratum") not in STRATA:
            raise ManifestError(f"{rid}: stratum must be one of {sorted(STRATA)}")
        if entry.get("confidence") not in CONFIDENCE:
            raise ManifestError(f"{rid}: confidence must be one of {sorted(CONFIDENCE)}")
        for key in ("repo", "dir", "url", "license"):
            if not str(entry.get(key, "")).strip():
                raise ManifestError(f"{rid}: missing {key}")
        if ".." in Path(entry["dir"]).parts or Path(entry["dir"]).is_absolute():
            raise ManifestError(f"{rid}: dir must be a relative path under the checkout root")
        if "repo" not in surfaces:
            if entry.get("label") != "n/a":
                raise ManifestError(f"{rid}: an entry without the repo surface has label 'n/a'")
            continue
        if entry.get("label") not in LABELS:
            raise ManifestError(f"{rid}: label must be one of {sorted(LABELS)}")
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
    """Fail closed unless ``root`` is at the pinned commit, is the top of its own repository,
    and has a clean tree. A HEAD match alone would let an untracked or ignored file, a
    modified tracked file, or a plain directory inside another repository be scanned as
    if it were the pinned tree."""
    head = checkout_head(root)
    if head != sha:
        raise ManifestError(f"{root} is at {head}, manifest pins {sha}")
    top = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False
    ).stdout.strip()
    if not top or Path(top).resolve() != root.resolve():
        raise ManifestError(f"{root} is not the top of its own repository")
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--ignored", "--untracked-files=all"],
        capture_output=True,
        text=True,
        check=False,
    )
    if status.returncode != 0 or status.stdout.strip():
        detail = (status.stdout or status.stderr).strip()[:200]
        raise ManifestError(f"{root} is not a clean checkout: {detail}")


def _unlinked(root: Path, rel: str) -> Path | None:
    """The path under ``root``, or None when any component on the way is a symbolic link.

    The copy of a tree drops symbolic links and everything below them, so the home
    label must not see them either.
    """
    current = root
    for part in Path(rel).parts:
        current = current / part
        if current.is_symlink():
            return None
    return current


def home_view_label(root: Path) -> str:
    """``client`` when a user-scope AI-client path exists and is non-empty, else ``none``."""
    for rel in HOME_VIEW_PATHS:
        path = _unlinked(root, rel)
        if path is None:
            continue
        if path.is_file() and path.stat().st_size > 0:
            return HOME_POSITIVE
        # A directory counts through its entries that are not symbolic links, as it does in the copy.
        if path.is_dir() and any(not child.is_symlink() for child in path.iterdir()):
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
    """Replace secret-shaped strings. Applied to every tool output that is written down.

    Quoted values are replaced inside their quotes, so JSON keys and colons stay valid.
    """
    return _SECRET.sub("[redacted]", _QUOTED_SECRET.sub(r"\1[redacted]\2", text))


def sanitize_note(text: str, *, paths: tuple[str, ...] = (), limit: int = 200) -> str:
    """Make a tool note safe to commit: hide work paths and secret-shaped strings, then truncate."""
    out = text
    for path in paths:
        if path:
            out = out.replace(path, "<path>")
    return redact(out).replace("\n", " | ")[:limit]


def build_cases(repos: list[dict[str, Any]], checkout_root: Path) -> list[RealCase]:
    """Cases for each entry on the surfaces it declares (both, for a v1 entry)."""
    return build_cases_v2(repos, checkout_root)


def build_cases_v2(repos: list[dict[str, Any]], checkout_root: Path) -> list[RealCase]:
    """Cases for the v2 manifest: only the surfaces each entry declares.

    The v1 builder always makes both surfaces. A v2 repository entry runs the repo
    surface only, and a v2 dotfiles entry runs the home view only, so no tool is
    run on a surface that the corpus does not give it.
    """
    cases: list[RealCase] = []
    for entry in repos:
        root = checkout_root / entry["dir"]
        verify_checkout(root, entry["sha"])
        surfaces = surfaces_of(entry)
        rationale = "; ".join(entry.get("evidence", []))[:500]
        if "repo" in surfaces:
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
        if "home" in surfaces:
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
