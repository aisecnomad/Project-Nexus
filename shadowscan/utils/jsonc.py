"""Lenient JSON (JSONC) parsing shared by the code connectors.

VS Code settings, dev container definitions, ``tsconfig.json`` and many MCP
client configurations are JSON with comments and trailing commas. Standard
JSON must not pay for the lenient path, so :func:`load_json_lenient` tries
``json.loads`` first and strips comments only after a syntax error.

Stripping is a single regex pass per stage rather than a Python character
loop: strings are matched first and returned unchanged, so ``//`` or a comma
inside a string value is never rewritten. Block comments keep their newlines
so a later syntax error still points at the original line.
"""

from __future__ import annotations

import json
import re
from typing import Any

# A string literal, a line comment, a block comment, or an unterminated block
# comment. Strings come first so comment markers inside them are preserved.
_COMMENT_TOKENS = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/|/\*', re.DOTALL)
# A string literal, or a comma followed only by whitespace before a closing
# bracket or the end of the document.
_TRAILING_COMMA_TOKENS = re.compile(r'"(?:[^"\\\n]|\\.)*"|,(?=\s*(?:[}\]]|\Z))')


def _strip_comment(match: re.Match[str]) -> str:
    token = match.group(0)
    if token.startswith('"'):
        return token
    if token.startswith("//"):
        return ""  # the terminating newline is not part of the token
    if token == "/*":
        raise ValueError("unterminated JSON comment")
    return " " + "\n" * token.count("\n")


def _strip_trailing_comma(match: re.Match[str]) -> str:
    token = match.group(0)
    return token if token.startswith('"') else ""


def strip_json_comments(text: str) -> str:
    """Remove JSONC comments and trailing commas without rewriting strings."""
    return _TRAILING_COMMA_TOKENS.sub(_strip_trailing_comma, _COMMENT_TOKENS.sub(_strip_comment, text))


def load_json_lenient(text: str) -> Any:
    """Parse JSON, tolerating JSONC comments and trailing commas only when needed."""
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(strip_json_comments(text))
