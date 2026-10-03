"""Pre-commit hook: check for common hardcoded secret patterns.

Usage: python tools/check_secrets.py FILE [FILE ...]
       git ls-files -z | xargs -0 python tools/check_secrets.py

Exits 1 when a file contains a string shaped like a known credential, or when
a named file cannot be read, and 2 when no file is named: a pipeline whose file
listing failed must not pass without checking anything. Each report names the file, line and credential
family, the first four characters and the length of the match, never the
value itself. Every supplied file is checked, including tests and corpora.
Reviewed synthetic values and documentation placeholders are approved only
by exact repository path, credential family and SHA-256 in secret_allowlist.json.
Private-key markers also bind the whole file, since a header alone cannot
identify the key body. Invalid or stale approvals fail closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

REPOSITORY_ROOT = Path(__file__).absolute().parent.parent
ALLOWLIST_PATH = Path(__file__).with_name("secret_allowlist.json")

# High-specificity shapes only: each needs a vendor prefix, a fixed structure
# or a key name next to the value, so prose and identifiers do not match. The
# lookbehinds also start every match at the beginning of a token, which keeps
# the scan linear on long runs of token characters.
_END = r"(?![A-Za-z0-9_])"
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI API key", re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{20,}")),
    ("OpenAI project key", re.compile(r"(?<![\w-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}")),
    ("Anthropic API key", re.compile(r"(?<![\w-])sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}")),
    ("AWS access key ID", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])")),
    (
        "AWS secret access key",
        re.compile(
            r"(?i:(?:aws_?)?secret_?access_?key)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
        ),
    ),
    ("GitHub token", re.compile(r"(?<![\w])gh[pousr]_[A-Za-z0-9]{36,251}" + _END)),
    ("GitHub fine-grained token", re.compile(r"(?<![\w])github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}" + _END)),
    ("GitLab token", re.compile(r"(?<![\w-])glpat-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"(?<![A-Za-z0-9])xox[abeoprs]-\d+-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])")),
    ("Hugging Face token", re.compile(r"(?<![\w])hf_[A-Za-z0-9]{34,}" + _END)),
    ("Stripe live key", re.compile(r"(?<![\w])[rs]k_live_[0-9A-Za-z]{20,}" + _END)),
    (
        "JSON Web Token",
        re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    (
        "Azure account or shared access key",
        re.compile(r"(?i:\b(?:Account|SharedAccess)Key)\s*=\s*[A-Za-z0-9+/]{40,}={0,2}"),
    ),
    (
        "password in a URL",
        re.compile(
            r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://"
            r"(?P<user>[^\s/:@'\"<>]+):(?P<password>[^\s/@'\"<>]+)@[^\s/'\"<>]"
        ),
    ),
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Approval:
    path: str
    family: str
    sha256: str
    reason: str
    content_sha256: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return self.path, self.family, self.sha256


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _repository_path(path: str) -> str | None:
    try:
        # Lexical normalization keeps a symlink outside the repository from
        # acquiring an approval belonging to its target.
        return Path(os.path.abspath(path)).relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return None


def _unique_json_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("allowlist contains a duplicate JSON field")
        result[key] = value
    return result


def _load_approvals() -> dict[tuple[str, str, str], str | None]:
    """Validate the manifest and every approval, even for a partial hook run."""
    manifest = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_fields)
    if not isinstance(manifest, dict) or set(manifest) != {"version", "entries"}:
        raise ValueError("allowlist must contain version and entries")
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise ValueError("unsupported allowlist version")
    if not isinstance(manifest["entries"], list):
        raise ValueError("allowlist entries must be a list")
    families = {family for family, _ in PATTERNS}
    approved: dict[tuple[str, str, str], str | None] = {}
    source_digests: dict[str, str] = {}
    source_matches: dict[str, set[tuple[str, str]]] = {}
    for index, entry in enumerate(manifest["entries"], 1):
        label = f"allowlist entry {index}"
        required = {"path", "family", "sha256", "reason"}
        if not isinstance(entry, dict) or not required <= set(entry) <= required | {"content_sha256"}:
            raise ValueError(f"{label}: invalid fields")
        if any(not isinstance(value, str) for value in entry.values()):
            raise ValueError(f"{label}: every field must be text")
        approval = Approval(**entry)
        path = PurePosixPath(approval.path)
        if (
            not approval.path
            or path.is_absolute()
            or path.as_posix() != approval.path
            or any(part in {".", ".."} for part in path.parts)
            or "\\" in approval.path
            or _CONTROL.search(approval.path)
        ):
            raise ValueError(f"{label}: path must be a normalized repository-relative file")
        if approval.family not in families or not approval.reason.strip():
            raise ValueError(f"{label}: unknown family or missing review reason")
        if not _DIGEST.fullmatch(approval.sha256):
            raise ValueError(f"{label}: invalid SHA-256")
        if approval.family == "private key" and approval.content_sha256 is None:
            raise ValueError(f"{label}: private-key markers require a whole-file digest")
        if approval.content_sha256 is not None and not _DIGEST.fullmatch(approval.content_sha256):
            raise ValueError(f"{label}: invalid whole-file SHA-256")
        if approval.key in approved:
            raise ValueError(f"{label}: duplicate approval")
        if approval.path not in source_matches:
            source = REPOSITORY_ROOT / approval.path
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"{label}: approved fixture is missing or is not a regular file")
            contents = source.read_bytes()
            text = contents.decode("utf-8", errors="ignore")
            source_digests[approval.path] = hashlib.sha256(contents).hexdigest()
            source_matches[approval.path] = {(family, digest(value)) for _, family, value in findings(text)}
        if (approval.family, approval.sha256) not in source_matches[approval.path]:
            raise ValueError(f"{label}: stale approval for {display(approval.path)}")
        if approval.content_sha256 is not None and source_digests[approval.path] != approval.content_sha256:
            raise ValueError(f"{label}: fixture contents changed for {display(approval.path)}")
        approved[approval.key] = approval.content_sha256
    return approved


def display(path: str) -> str:
    """The path as reported: control characters are escaped, so a crafted file
    name cannot forge a report line or a workflow log command."""
    return _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", path)


def findings(text: str) -> Iterator[tuple[int, str, str]]:
    """Yield ``(line, family, match)`` for every credential-shaped string in ``text``."""
    for family, pattern in PATTERNS:
        for match in pattern.finditer(text):
            yield text.count("\n", 0, match.start()) + 1, family, match.group()


def main(argv: Sequence[str] | None = None) -> int:
    paths = sys.argv[1:] if argv is None else argv
    if not paths:
        print("check_secrets: no files to check", file=sys.stderr)
        return 2
    try:
        approved = _load_approvals()
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        # JSON parser diagnostics can echo malformed source text. Never print
        # their message or arbitrary manifest values in credential reports.
        detail = str(exc) if type(exc) is ValueError else "cannot read or parse approval manifest"
        print(f"check_secrets: {detail}", file=sys.stderr)
        return 1
    failed = False
    for path in paths:
        # A symbolic link's target is not part of the commit, and a gitlink
        # (submodule) is a directory; neither is file content to scan.
        if os.path.islink(path) or os.path.isdir(path):
            continue
        try:
            contents = Path(path).read_bytes()
            text = contents.decode("utf-8", errors="ignore")
        except OSError as exc:
            print(f"{display(path)}: cannot read: {exc.strerror}", file=sys.stderr)
            failed = True
            continue
        for line, family, value in findings(text):
            key = (_repository_path(path), family, digest(value))
            if key in approved and (
                approved[key] is None or hashlib.sha256(contents).hexdigest() == approved[key]
            ):
                continue
            where = f"{display(path)}:{line}"
            print(f"{where}: possible hardcoded {family}: {value[:4]}... ({len(value)} characters)")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
