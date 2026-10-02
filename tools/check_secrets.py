#!/usr/bin/env python3
"""Pre-commit hook: check for common hardcoded secret patterns.

Usage: python tools/check_secrets.py FILE [FILE ...]
       python tools/check_secrets.py --tracked

Exits 1 when a file contains a string shaped like a known credential, or when
a named file cannot be read. Each report names the file, line and credential
family, the first four characters and the length of the match, never the
value itself. The pre-commit hook and CI pass every tracked text file; the
script itself skips the paths in ``EXCLUDED``, which hold synthetic
credential-shaped strings on purpose, so both run the same check.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterator, Sequence

# Repository-relative paths that hold synthetic credentials on purpose: the
# tests and their fixtures, the signature packs, and the labelled detection
# evaluation corpora (JSON, which cannot carry an allow-list comment).
EXCLUDED = re.compile(r"tests/|shadowscan/signatures/data/|tools/evaluation/[^/]*corpus\.json$")

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

# Documentation placeholders inside an otherwise credential-shaped string.
# Each is long enough that a random credential practically never contains it.
_PLACEHOLDER_MARKERS = ("example", "placeholder", "redacted", "replace", "xxxxxxxx", "00000000")
# URL passwords that name, reference or repeat a value instead of holding one.
_PLACEHOLDER_PASSWORDS = {"password", "passwd", "pass", "pwd", "secret", "token", "changeme"}
_PLACEHOLDER_PASSWORD_WORDS = ("replace", "your", "change")


def _is_placeholder(match: re.Match[str]) -> bool:
    if any(marker in match.group().lower() for marker in _PLACEHOLDER_MARKERS):
        return True
    if "password" not in match.re.groupindex:
        return False
    password = match.group("password")
    lowered = password.lower()
    return (
        password[0] in "$<{%*["
        or lowered == match.group("user").lower()
        or lowered in _PLACEHOLDER_PASSWORDS
        or any(word in lowered for word in _PLACEHOLDER_PASSWORD_WORDS)
    )


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def display(path: str) -> str:
    """The path as reported: control characters are escaped, so a crafted file
    name cannot forge a report line or a workflow log command."""
    return _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", path)


def findings(text: str) -> Iterator[tuple[int, str, str]]:
    """Yield ``(line, family, match)`` for every credential-shaped string in ``text``."""
    for family, pattern in PATTERNS:
        for match in pattern.finditer(text):
            if not _is_placeholder(match):
                yield text.count("\n", 0, match.start()) + 1, family, match.group()


def is_excluded(path: str) -> bool:
    return EXCLUDED.match(os.path.normpath(path).replace(os.sep, "/")) is not None


def main(argv: Sequence[str] | None = None) -> int:
    paths = sys.argv[1:] if argv is None else argv
    failed = False
    for path in paths:
        # A symbolic link's target is not part of the commit, and a gitlink
        # (submodule) is a directory; neither is file content to scan.
        if is_excluded(path) or os.path.islink(path) or os.path.isdir(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except OSError as exc:
            print(f"{display(path)}: cannot read: {exc.strerror}", file=sys.stderr)
            failed = True
            continue
        for line, family, value in findings(text):
            where = f"{display(path)}:{line}"
            print(f"{where}: possible hardcoded {family}: {value[:4]}... ({len(value)} characters)")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
