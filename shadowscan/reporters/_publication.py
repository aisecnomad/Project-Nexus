"""Shared fail-closed normalization at report publication boundaries."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, cast

from shadowscan.models import ScanResult
from shadowscan.utils.redaction import sanitize


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


def related_finding_ids(metadata: dict[str, Any], *, limit: int = 8) -> tuple[str, ...]:
    """Return well-formed related-finding identifiers from untrusted metadata."""
    related = metadata.get("related")
    if not isinstance(related, list):
        return ()
    return tuple(item for item in related[:limit] if isinstance(item, str))
