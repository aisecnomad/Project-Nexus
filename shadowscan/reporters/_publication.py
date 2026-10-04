"""Shared fail-closed normalization at report publication boundaries."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any, cast

from shadowscan.models import ScanResult
from shadowscan.utils.output import terminal_text
from shadowscan.utils.redaction import sanitize

# Every character terminal_text() renders visibly: C0 and C1 controls, bidi
# formatting and line/paragraph separators.
_TERMINAL_CONTROLS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069"
    r"\ufeff\ud800-\udfff\U000e0000-\U000e007f]"
)


def visible_controls(value: str, keep: str = "") -> str:
    """Render terminal controls in a saved report visibly, leaving the ``keep`` characters as data.

    ``cat``-ing a CSV or HTML artifact must not let a repository name, caller
    or diagnostic issue escape sequences. Whitespace a format treats as data
    (tab, newline) is kept by the caller; every other control is shown as
    ``\\uXXXX``, the same rendering the table and Markdown reporters use.
    """
    return _TERMINAL_CONTROLS.sub(
        lambda m: m.group() if m.group() in keep else terminal_text(m.group()), value
    )


def publication_stats(result: ScanResult) -> list[dict[str, Any]]:
    """Return collectively sanitized connector statistics without mutating the result.

    Connectors normally sanitize diagnostics before recording them, but reporters
    are also a public API and may receive results assembled by plugins or direct
    callers. Treat that boundary as independently hostile. Sanitizing all stats
    in one pass also catches a credential copied between otherwise innocuous
    fields.
    """
    stats = sanitize([asdict(item) for item in result.stats])
    # ``sanitize`` preserves ordinary dataclass dictionaries. Sanitizer limit
    # failures propagate so publication fails closed instead of emitting content
    # that was only partially checked.
    return cast(list[dict[str, Any]], stats)


def without_connector_prefix(connector: str, message: str) -> str:
    """Drop a leading ``<connector>: `` from a diagnostic that a report prints under that connector.

    Connectors usually name themselves in their own errors, so a report that
    adds the connector again would print ``code.filesystem: code.filesystem: ...``.
    """
    prefix = f"{connector}: "
    return message[len(prefix) :] if message.startswith(prefix) else message


def related_finding_ids(metadata: dict[str, Any], *, limit: int = 8) -> tuple[str, ...]:
    """Return well-formed related-finding identifiers from untrusted metadata."""
    related = metadata.get("related")
    if not isinstance(related, list):
        return ()
    return tuple(item for item in related[:limit] if isinstance(item, str))
