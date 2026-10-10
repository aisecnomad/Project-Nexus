"""OCSF Detection Finding output for SIEMs and security data lakes.

The document is one JSON object with two members: ``events`` holds one OCSF
1.1.0 Detection Finding event per finding (``class_uid`` 2004, ``category_uid``
2, activity Create, ``type_uid`` 200401), and ``scan`` describes the run
itself: ``status`` (``complete`` or ``incomplete``, from the scan result),
``started_at``/``finished_at``, the summary and the sanitized per-connector
diagnostics. A consumer that drops the envelope and ships ``events`` alone
must read ``scan.status`` first: an incomplete scan is marked there, never
published as an empty, clean-looking event list.

Mapping rules that keep the stream valid for OCSF consumers:

* ``severity_id`` carries the heuristic risk level (info 1, low 2, medium 3,
  high 4, critical 5). It is a discovery score, not CVSS (docs/severity.md).
* ``status_id`` is always 1 (New). ShadowScan records discovery, never a
  triage or verification state.
* Timestamps are epoch milliseconds in ``time``/``*_time`` and ISO 8601 UTC
  with a ``Z`` suffix in the ``*_dt`` twins, which ``metadata.profiles``
  declares as the ``datetime`` profile; an unparseable timestamp is
  omitted, never published as ``null`` or an invalid string.
* A key whose value would be ``null`` is omitted.
* Evidence snippets are capped at 200 characters; evidence attributes and
  finding metadata are not exported (use the JSON report for those).
* ``json.dumps(..., allow_nan=False)``: a NaN or infinite value anywhere in
  the result raises ``ValueError`` before anything is published.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Any

from shadowscan import __version__
from shadowscan.models import Evidence, Finding, RiskLevel, ScanResult
from shadowscan.reporters._publication import publication_stats

_OCSF_VERSION = "1.1.0"
_CATEGORY_UID = 2  # Findings
_CLASS_UID = 2004  # Detection Finding
_ACTIVITY_ID = 1  # Create
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_ID  # 200401
_STATUS_NEW = 1  # the only status ShadowScan asserts; triage states are not invented
_SNIPPET_LIMIT = 200

# OCSF severity_id. The value is ShadowScan's heuristic risk level, not CVSS.
_SEVERITY: dict[RiskLevel, tuple[int, str]] = {
    RiskLevel.INFO: (1, "Informational"),
    RiskLevel.LOW: (2, "Low"),
    RiskLevel.MEDIUM: (3, "Medium"),
    RiskLevel.HIGH: (4, "High"),
    RiskLevel.CRITICAL: (5, "Critical"),
}

# OCSF risk_level_id (0 Info .. 4 Critical) carries the same heuristic level.
_RISK_LEVEL: dict[RiskLevel, tuple[int, str]] = {
    RiskLevel.INFO: (0, "Info"),
    RiskLevel.LOW: (1, "Low"),
    RiskLevel.MEDIUM: (2, "Medium"),
    RiskLevel.HIGH: (3, "High"),
    RiskLevel.CRITICAL: (4, "Critical"),
}


def _compact(mapping: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None: OCSF attributes are optional, never ``null``."""
    return {key: value for key, value in mapping.items() if value is not None}


def _parse_timestamp(value: object) -> datetime | None:
    """An aware UTC datetime, or None for anything that is not ISO 8601."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)  # the engine only records aware UTC timestamps
    return parsed.astimezone(UTC)


def _utc_timestamp(value: object) -> str | None:
    """An ISO 8601 UTC timestamp with a ``Z`` suffix, or None so the caller omits the key."""
    parsed = _parse_timestamp(value)
    return parsed.isoformat().replace("+00:00", "Z") if parsed else None


def _epoch_millis(value: object) -> int | None:
    """OCSF ``timestamp_t`` (milliseconds since the epoch), or None for the key to be omitted."""
    parsed = _parse_timestamp(value)
    return round(parsed.timestamp() * 1000) if parsed else None


def _confidence_score(value: float) -> int | float:
    """A 0-100 integer confidence score.

    A non-finite value is returned unchanged so publication fails closed:
    ``json.dumps(..., allow_nan=False)`` raises ``ValueError`` instead of a
    plugin's NaN silently becoming a confident score.
    """
    if not math.isfinite(value):
        return value
    return round(max(0.0, min(1.0, value)) * 100)


def _metadata() -> dict[str, Any]:
    return {
        "version": _OCSF_VERSION,
        "product": {"name": "ShadowScan", "version": __version__, "vendor_name": "Project Nexus"},
        # The ``*_dt`` twins belong to the datetime profile; a validating
        # consumer rejects or drops them unless the event declares it.
        "profiles": ["datetime"],
    }


def _finding_info(f: Finding) -> dict[str, Any]:
    return _compact(
        {
            "uid": f.id,
            "title": f.title,
            "types": [f.kind.value],
            "data_sources": [f.connector],
            "first_seen_time": _epoch_millis(f.first_seen),
            "first_seen_time_dt": _utc_timestamp(f.first_seen),
            "last_seen_time": _epoch_millis(f.last_seen),
            "last_seen_time_dt": _utc_timestamp(f.last_seen),
        }
    )


def _evidence(e: Evidence) -> dict[str, Any]:
    return {
        "data": _compact(
            {
                "signal": e.signal,
                "description": e.description,
                "location": e.location,
                "snippet": e.snippet[:_SNIPPET_LIMIT] if e.snippet else None,
                "signature": e.signature,
                "weight": e.weight,
            }
        )
    }


def _resources(f: Finding) -> list[dict[str, Any]]:
    data = _compact({"provider": f.provider, "account": f.account})
    return [
        _compact(
            {
                "uid": f.resource,
                "type": f.resource_type or None,
                "region": f.region,
                "owner": {"name": f.owner} if f.owner else None,
                "data": data or None,
            }
        )
    ]


def _unmapped(f: Finding) -> dict[str, Any]:
    factors = [
        {"id": factor.id, "description": factor.description, "weight": factor.weight}
        for factor in f.risk.factors
    ]
    return _compact(
        {
            "surface": f.surface.value,
            "connector": f.connector,
            "kind": f.kind.value,
            "confidence": f.confidence,
            "likelihood": f.likelihood.value,
            "shadow": f.shadow,
            "registry_match": f.registry_match,
            "tags": list(dict.fromkeys(f.tags)) or None,
            "frameworks": f.frameworks or None,
            "model_providers": f.model_providers or None,
            "models": f.models or None,
            "capabilities": f.capabilities or None,
            "permissions": f.permissions or None,
            "risk_factors": factors or None,
            "score_basis": "heuristic-not-cvss",
        }
    )


def _event(f: Finding, time_ms: int | None, time_dt: str | None) -> dict[str, Any]:
    severity_id, severity = _SEVERITY[f.risk.level]
    risk_level_id, risk_level = _RISK_LEVEL[f.risk.level]
    return _compact(
        {
            "activity_id": _ACTIVITY_ID,
            "activity_name": "Create",
            "category_uid": _CATEGORY_UID,
            "category_name": "Findings",
            "class_uid": _CLASS_UID,
            "class_name": "Detection Finding",
            "type_uid": _TYPE_UID,
            "type_name": "Detection Finding: Create",
            "time": time_ms,
            "time_dt": time_dt,
            "severity_id": severity_id,
            "severity": severity,
            "status_id": _STATUS_NEW,
            "status": "New",
            "confidence_score": _confidence_score(f.confidence),
            "message": f.title,
            "metadata": _metadata(),
            "finding_info": _finding_info(f),
            "evidences": [_evidence(e) for e in f.evidence] or None,
            "resources": _resources(f),
            "risk_level_id": risk_level_id,
            "risk_level": risk_level,
            "risk_score": f.risk.score,
            "unmapped": _unmapped(f),
        }
    )


def _connector_diagnostics(result: ScanResult) -> list[dict[str, Any]]:
    """Per-connector run diagnostics, passed through the shared publication boundary.

    Connector statistics are collectively sanitized (fail closed on sanitizer
    limits) before any of them is written into the document.
    """
    return [
        _compact(
            {
                "connector": st.get("connector"),
                "started_at": _utc_timestamp(st.get("started_at")),
                "finished_at": _utc_timestamp(st.get("finished_at")),
                "findings": st.get("findings"),
                "objects_examined": st.get("objects_examined"),
                "errors": st.get("errors"),
                "warnings": st.get("warnings"),
                "skipped": st.get("skipped"),
                "skip_reason": st.get("skip_reason"),
                "cached": st.get("cached"),
                "incomplete": st.get("incomplete"),
            }
        )
        for st in publication_stats(result)
    ]


def _scan(result: ScanResult) -> dict[str, Any]:
    """The run status block. An incomplete scan must be unmistakably marked here."""
    return _compact(
        {
            "status": "complete" if result.complete else "incomplete",
            "complete": result.complete,
            "started_at": _utc_timestamp(result.started_at),
            "finished_at": _utc_timestamp(result.finished_at),
            "summary": result.summary(),
            "connectors": _connector_diagnostics(result),
        }
    )


def render_ocsf(result: ScanResult) -> str:
    """Render a scan result as OCSF Detection Finding events (shape in the module docstring)."""
    for finding in result.findings:
        finding.sanitize()
    # Every event carries the scan's end (or start) as its time: findings are
    # published when the scan concludes. An unparseable timestamp is omitted.
    reference = result.finished_at if _parse_timestamp(result.finished_at) else result.started_at
    time_ms = _epoch_millis(reference)
    time_dt = _utc_timestamp(reference)
    document = {
        "ocsf_version": _OCSF_VERSION,
        "events": [_event(f, time_ms, time_dt) for f in result.findings],
        "scan": _scan(result),
    }
    return json.dumps(document, indent=2, default=str, allow_nan=False)
