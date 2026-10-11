"""Redaction for anything the AI Review Gate posts or logs.

Review findings quote pull-request content, which is untrusted. Before a
finding leaves the runner, every posted string passes through ``redact``,
which removes strings shaped like common credentials and neutralizes GitHub
workflow-command lines. The patterns mirror tools/check_secrets.py closely
enough for posted text; check_secrets.py stays the authoritative gate for
files, because its approvals bind exact paths and digests.
"""

from __future__ import annotations

import re

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![\w-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}"),
    re.compile(r"(?<![\w-])sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    re.compile(r"(?<![\w])gh[pousr]_[A-Za-z0-9]{36,251}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w])github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w-])glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])xox[abeoprs]-\d+-[0-9A-Za-z-]{10,}"),
    re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])"),
    re.compile(r"(?<![\w])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w])[rs]k_live_[0-9A-Za-z]{20,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    re.compile(r"(?i:\b(?:Account|SharedAccess)Key)\s*=\s*[A-Za-z0-9+/]{40,}={0,2}"),
    re.compile(
        r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://"
        r"[^\s/:@'\"<>]+:[^\s/@'\"<>]+@[^\s/'\"<>]"
    ),
)

_REDACTED = "[redacted]"

# A line starting with :: is a workflow command even in a log or a posted
# comment; neutralize it instead of trusting the destination to escape it.
_WORKFLOW_COMMAND = re.compile(r"^::", re.MULTILINE)


def redact(text: str) -> str:
    """``text`` with credential-shaped strings replaced and command lines defused."""
    for pattern in _PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return _WORKFLOW_COMMAND.sub("\\:\\:", text)
