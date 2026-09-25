#!/usr/bin/env python3
"""Pre-commit hook: check for common hardcoded secret patterns.

Usage: python tools/check_secrets.py FILE [FILE ...]

Exits 1 when a file contains a string shaped like a known credential. Tests and
fixtures are excluded by the hook configuration because they hold synthetic
credential-shaped strings on purpose.
"""
import re
import sys

PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),          # OpenAI (legacy user keys)
    re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}"),  # OpenAI project/service/admin keys
    re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"),  # Anthropic
    re.compile(r"AKIA[0-9A-Z]{16}"),              # AWS access key
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),           # GitHub PAT
    re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"),     # GitLab PAT
    re.compile(r"xoxb-[0-9]{10,}-[a-zA-Z0-9]+"),  # Slack bot token
]

fail = False
for path in sys.argv[1:]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
    except OSError:
        continue
    for pattern in PATTERNS:
        for match in pattern.finditer(text):
            print(f"{path}: possible hardcoded secret: {match.group()[:12]}...")
            fail = True

sys.exit(1 if fail else 0)
