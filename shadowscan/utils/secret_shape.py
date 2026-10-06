"""Value-shape gate for provider credential assignments.

The holdout false positive was an empty ``OPENAI_API_KEY=``. A variable name
is not a secret. Callers must reject empty, placeholder, and interpolation
values before emitting a secret finding.
"""

from __future__ import annotations

import regex

_PLACEHOLDERS = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "your-key-here",
        "your_api_key",
        "todo",
        "test",
        "none",
        "null",
        "undefined",
        "xxx",
        "sk-xxx",
        "replace-me",
    }
)

_PREFIXES = (
    "sk-proj-",
    "sk-ant-",
    "sk-live-",
    "sk-",
    "ghp_",
    "github_pat_",
    "akia",
    "xoxb-",
    "xoxp-",
)

_INTERPOLATION = regex.compile(
    r"^\$(\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)$|^\$\{[A-Za-z_][A-Za-z0-9_]*[:-].*\}$"
)


def is_credential_value(value: str | None, *, min_length: int = 16) -> bool:
    """Return True only when ``value`` looks like a real provider secret.

    Empty assignments, placeholders, and ``${VAR}`` references are not secrets.
    A known prefix or a long high-entropy token is required.
    """
    if value is None:
        return False
    text = value.strip().strip("'\"")
    if not text or text.lower() in _PLACEHOLDERS:
        return False
    if _INTERPOLATION.match(text):
        return False
    if text.lower().startswith("your-") or "example" in text.lower():
        return False
    lowered = text.lower()
    if any(lowered.startswith(prefix) for prefix in _PREFIXES) and len(text) >= 12:
        return True
    if len(text) < min_length:
        return False
    classes = sum(
        [
            any(ch.islower() for ch in text),
            any(ch.isupper() for ch in text),
            any(ch.isdigit() for ch in text),
            any(not ch.isalnum() for ch in text),
        ]
    )
    return classes >= 3
