"""Conservative collection-scope provenance and report comparison.

A finding disappearing from a report is only evidence of resolution when both
scans completed under the same collection and detection settings. Scope hashes
identify inputs, not their contents: a file changing is what comparisons measure.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.config import PATH_KEYS, ConnectorSpec, ScanConfig
from shadowscan.connectors import _BUILTIN
from shadowscan.signatures import SignatureIndex

_SCHEMA = "shadowscan.collection-scope/v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _scanner_digest() -> str:
    package = Path(__file__).parent
    return hashlib.sha256(_canonical([
        [p.relative_to(package).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()]
        for p in sorted(package.rglob("*.py"))
    ])).hexdigest()


def build_collection_scope(
    config: ScanConfig, index: SignatureIndex, specs: list[ConnectorSpec],
) -> dict[str, Any]:
    """Describe selected static inputs without exposing any configuration values.

    Live provider identity/coverage and third-party implementations are not
    attested here, so those scans cannot automatically resolve earlier findings.
    Credentials, when configured, only participate inside the overall digest;
    changing them conservatively invalidates comparability.
    """
    unavailable = {"schema": _SCHEMA, "comparable": False}
    if not specs:
        return {**unavailable, "reason": "no connectors selected"}
    inputs = []
    for spec in specs:
        if spec.name not in _BUILTIN:
            return {**unavailable, "reason": "third-party connector scope is not attested"}
        offline = isinstance(spec.config.get("input"), str) and bool(spec.config["input"])
        local = spec.name == "code.filesystem" and bool(spec.config.get("path") or spec.config.get("paths"))
        if not offline and not local:
            return {**unavailable, "reason": "live collection scope is not attested"}
        options = dict(spec.config)
        for key in PATH_KEYS:
            val = options.get(key)
            if isinstance(val, str) and val:
                options[key] = str(Path(val).expanduser().resolve())
            elif isinstance(val, list):
                options[key] = [str(Path(v).expanduser().resolve()) if isinstance(v, str) else v for v in val]
        inputs.append({"name": spec.name, "label": spec.label, "config": options})
    try:
        fingerprint = hashlib.sha256(_canonical({
            "inputs": sorted(inputs, key=_canonical),
            "min_confidence": config.min_confidence,
            "signatures": index.fingerprint(),
            "scanner": _scanner_digest(),
            "version": __version__,
        })).hexdigest()
    except (OSError, TypeError, ValueError):
        return {**unavailable, "reason": "collection scope could not be fingerprinted"}
    return {"schema": _SCHEMA, "comparable": True, "fingerprint": fingerprint}


def _complete(report: dict[str, Any]) -> bool:
    summary, stats = report.get("summary"), report.get("stats")
    return (
        isinstance(summary, dict) and summary.get("complete") is True
        and isinstance(stats, list) and bool(stats)
        and all(
            isinstance(s, dict) and isinstance(s.get("connector"), str) and bool(s["connector"])
            and not (s.get("errors") or s.get("skipped") or s.get("incomplete"))
            for s in stats
        )
    )


def _scope_digest(report: dict[str, Any]) -> str | None:
    scope = report.get("collection_scope")
    if not isinstance(scope, dict) or scope.get("schema") != _SCHEMA or scope.get("comparable") is not True:
        return None
    digest = scope.get("fingerprint")
    return digest if isinstance(digest, str) and _DIGEST.fullmatch(digest) else None


def _findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = report.get("findings")
    if not isinstance(records, list):
        raise ValueError("report findings must be an array")
    result = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"]:
            raise ValueError("each finding must have an id")
        risk = record.get("risk")
        if (
            not isinstance(risk, dict) or risk.get("level") not in {"critical", "high", "medium", "low", "info"}
            or not isinstance(risk.get("score"), (int, float))
            or not isinstance(record.get("title"), str) or not isinstance(record.get("resource"), str)
        ):
            raise ValueError("each finding must have valid risk, title and resource fields")
        if record["id"] in result:
            raise ValueError("report has duplicate finding ids")
        result[record["id"]] = record
    return result


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Keep positive observations, but never infer absence from lost coverage."""
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        raise ValueError("reports must be JSON objects")
    b, c = _findings(baseline), _findings(current)
    reasons = []
    for label, report in (("baseline", baseline), ("current", current)):
        if not _complete(report):
            reasons.append(f"{label} scan is incomplete or lacks completion metadata")
    bs, cs = _scope_digest(baseline), _scope_digest(current)
    if not bs or not cs:
        reasons.append("collection scope is unavailable; regenerate legacy reports or use attested static inputs")
    elif bs != cs:
        reasons.append("collection or detection scope differs")
    missing = [b[i] for i in sorted(b.keys() - c.keys())]
    return {
        "comparable": not reasons,
        "reasons": reasons,
        "new": [c[i] for i in sorted(c.keys() - b.keys())],
        "resolved": [] if reasons else missing,
        "unknown": missing if reasons else [],
        "changed": [
            {"before": b[i], "after": c[i]} for i in sorted(b.keys() & c.keys())
            if b[i]["risk"]["level"] != c[i]["risk"]["level"]
        ],
    }
