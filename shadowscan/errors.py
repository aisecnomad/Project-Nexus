"""Exception types whose messages are safe to show to an operator verbatim.

ShadowScan masks most exception text before it reaches a terminal or CI log:
third-party SDK and parser errors routinely echo the credentials, URLs or
source excerpts that caused them. The types below carry a stronger contract so
that the CLI can print them without masking and an operator can still diagnose
a mistyped path, a malformed pack or an unknown option.

Contract for every :class:`SetupError` message:

* it names file paths, option and key names, positions (line and column
  numbers) and fixed diagnostic text only;
* it never contains configuration values, environment variable values,
  credentials or parser source snippets;
* text copied from a third-party exception must be sanitized and bounded
  before it is included, or left out.

Modules raise domain-specific subclasses (configuration, inventory, signature
packs); callers that only need the contract catch :class:`SetupError`.
"""

from __future__ import annotations

import yaml


class SetupError(Exception):
    """A scan cannot start; the message is credential-free and safe to print."""


class SetupPathError(SetupError, FileNotFoundError):
    """A configured inventory or signature path does not exist.

    It remains a :class:`FileNotFoundError` so existing callers that handle
    missing files keep working.
    """


def yaml_error_position(exc: BaseException) -> str:
    """Return `` (line L, column C)`` for a PyYAML error that carries a mark, else ``""``.

    Only the numbers are used. ``str(exc)`` and the marks' own rendering
    include an excerpt of the source line, which may hold a credential.
    """
    if not isinstance(exc, yaml.MarkedYAMLError):
        return ""
    problem = _mark_position(exc.problem_mark)
    context = _mark_position(exc.context_mark)
    if problem is None:
        return f" ({context})" if context else ""
    if context and context != problem:
        # An unterminated construct fails at the end of the stream; the
        # context mark says where it began.
        return f" ({problem}; context started at {context})"
    return f" ({problem})"


def _mark_position(mark: object) -> str | None:
    line = getattr(mark, "line", None)
    column = getattr(mark, "column", None)
    if mark is None or not isinstance(line, int) or not isinstance(column, int):
        return None
    return f"line {line + 1}, column {column + 1}"


__all__ = ["SetupError", "SetupPathError", "yaml_error_position"]
