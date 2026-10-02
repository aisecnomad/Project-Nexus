#!/usr/bin/env python3
"""Pre-commit hook: check for common hardcoded secret patterns.

Usage: python tools/check_secrets.py FILE [FILE ...]
       python tools/check_secrets.py --tracked

Exits 1 when a file contains a string shaped like a known credential. Tests and
fixtures are excluded by the hook configuration and tracked-file mode because
they hold synthetic credential-shaped strings on purpose. This bounded pattern
check is not a complete secret detector.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # OpenAI (legacy user keys)
    re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}"),  # OpenAI project/service/admin keys
    re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"),  # Anthropic
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),  # GitHub PAT
    re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"),  # GitLab PAT
    re.compile(r"xoxb-[0-9]{10,}-[a-zA-Z0-9]+"),  # Slack bot token
]


def _safe_text(text: str) -> str:
    """Escape log controls and mask credentials even in a supplied filename."""
    for pattern in PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return repr(text)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally echoes unknown options; even malformed filenames
        # can contain a credential or a forged workflow log command.
        super().error(_safe_text(message))


def _read(path: Path) -> str:
    # A hook should not follow a committed symlink into the operator's files,
    # or hang forever on a FIFO. Inspect the opened descriptor, not just lstat.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("not a regular file")
        with os.fdopen(descriptor, encoding="utf-8", errors="surrogateescape") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _tracked_paths() -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--",
            "*.py",
            "*.yaml",
            "*.yml",
            ":(exclude)tests/**",
            ":(exclude)shadowscan/signatures/data/**",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    # Git's NUL-delimited output preserves spaces, newlines and non-UTF-8 names.
    return [Path(os.fsdecode(name)) for name in result.stdout.split(b"\0") if name]


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--tracked", action="store_true", help="check tracked Python/YAML files")
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args(argv)
    if args.tracked and args.files:
        parser.error("choose --tracked or explicit filenames")
    if not args.tracked and not args.files:
        parser.error("provide --tracked or at least one filename")
    try:
        paths = _tracked_paths() if args.tracked else args.files
    except (OSError, subprocess.SubprocessError):
        print("cannot enumerate tracked source files", file=sys.stderr)
        return 2
    failed = False
    for path in paths:
        try:
            text = _read(path)
        except OSError:
            # Do not echo exception details, which can contain unsafe filenames.
            print(f"{_safe_text(str(path))}: cannot read a regular source file", file=sys.stderr)
            failed = True
            continue
        for pattern in PATTERNS:
            line = 1
            previous_offset = 0
            for match in pattern.finditer(text):
                # Count each intervening segment once, including consecutive
                # matches on one line, instead of rescanning from the beginning.
                line += text.count("\n", previous_offset, match.start())
                previous_offset = match.start()
                print(f"{_safe_text(str(path))}:{line}: possible hardcoded secret [REDACTED]")
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
