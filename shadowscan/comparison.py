"""Conservative collection-scope provenance and report comparison.

A finding disappearing from a report is only evidence of resolution when both
scans completed under the same collection and detection settings. Scope hashes
identify inputs, not their contents: a file changing is what comparisons measure.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.config import PATH_KEYS, ConnectorSpec, ScanConfig
from shadowscan.connectors import _BUILTIN
from shadowscan.models import FINDING_IDENTITY_SCHEMA
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.files import read_policy_text
from shadowscan.utils.redaction import sanitize, sensitive_field

_SCHEMA = "shadowscan.collection-scope/v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_EMBEDDED_CREDENTIAL_FINGERPRINT = re.compile(r"credential:sha256:[a-f0-9]{64}")
MAX_REPORT_BYTES = 64 * 1024 * 1024


def load_report(path: str | Path) -> dict[str, Any]:
    """Read an unambiguous, bounded report without following input symlinks."""
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate report field")
            result[key] = value
        return result

    def invalid_number(value: str) -> None:
        raise ValueError("report numbers must be finite")

    try:
        report = json.loads(
            read_policy_text(Path(path), max_bytes=MAX_REPORT_BYTES),
            object_pairs_hook=unique_object, parse_constant=invalid_number,
        )
        if not isinstance(report, dict):
            raise ValueError("report must be a JSON object")
        _findings(report)
        return report
    except RecursionError:
        raise ValueError("report structure exceeds nesting limit") from None


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _has_private_scope_values(value: Any) -> bool:
    """Reject sensitive keys and enumerable credential digests in public hashes.

    Sanitization preserves credential fingerprints intentionally for finding
    identity, so comparing a sanitized config with its source cannot detect
    these potentially low-entropy values on its own.
    """
    remaining = [value]
    seen: set[int] = set()
    while remaining:
        item = remaining.pop()
        if isinstance(item, str) and _EMBEDDED_CREDENTIAL_FINGERPRINT.search(item):
            return True
        if isinstance(item, (Mapping, list, tuple)):
            if id(item) in seen:
                continue
            seen.add(id(item))
        if isinstance(item, Mapping):
            for key, child in item.items():
                if sensitive_field(str(key), child):
                    return True
                remaining.append(child)
        elif isinstance(item, (list, tuple)):
            remaining.extend(item)
    return False


def _scanner_digest() -> str:
    package = Path(__file__).parent
    return hashlib.sha256(_canonical([
        [p.relative_to(package).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()]
        for p in sorted(package.rglob("*.py"))
    ])).hexdigest()


def build_collection_scope(
    config: ScanConfig, index: SignatureIndex, specs: list[ConnectorSpec],
    *, pseudonymization_key_id: str | None = None,
) -> dict[str, Any]:
    """Describe selected static inputs without exposing any configuration values.

    Live provider identity/coverage and third-party implementations are not
    attested here, so those scans cannot automatically resolve earlier findings.
    A public digest of low-entropy credentials or binding labels would permit
    offline guessing. Such configurations have no exported fingerprint and
    cannot automatically resolve findings in a comparison.
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
        # Scope and caller pseudonyms are keyed to each gateway scan unless an
        # operator key keeps them stable. Even a presently unscoped export can
        # change this property as rows change.
        if spec.name == "gateway.logs" and pseudonymization_key_id is None:
            return {**unavailable, "reason": "configuration contains private comparison values"}
        try:
            if sanitize((options, spec.label)) != (options, spec.label) or _has_private_scope_values((options, spec.label)):
                return {**unavailable, "reason": "configuration contains private comparison values"}
        except (RecursionError, TypeError, ValueError):
            return {**unavailable, "reason": "configuration contains private comparison values"}
        inputs.append({"name": spec.name, "label": spec.label, "config": options})
    try:
        fingerprint = hashlib.sha256(_canonical({
            "inputs": sorted(inputs, key=_canonical),
            "min_confidence": config.min_confidence,
            # Pseudonyms from different keys never match, so the key identity
            # is part of the scope whenever gateway pseudonyms are compared.
            **({"pseudonymization_key_id": pseudonymization_key_id}
               if pseudonymization_key_id and any(spec.name == "gateway.logs" for spec in specs) else {}),
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
            or not isinstance(risk.get("score"), (int, float)) or isinstance(risk.get("score"), bool)
            or not 0 <= risk["score"] <= 100
            or not isinstance(record.get("title"), str) or not isinstance(record.get("resource"), str)
        ):
            raise ValueError("each finding must have valid risk, title and resource fields")
        if record["id"] in result:
            raise ValueError("report has duplicate finding ids")
        # Validate new and missing observations as well as shared identities.
        # Malformed records must never be represented as successfully resolved.
        _substantive_state(record)
        result[record["id"]] = record
    return result


def _substantive_state(finding: dict[str, Any]) -> dict[str, Any]:
    """Security state, excluding timestamps, counters, prose and evidence order."""
    state = {key: finding.get(key) for key in ("kind", "resource_type", "owner", "shadow", "registry_match")}
    for key in ("permissions", "capabilities", "frameworks", "model_providers", "models", "tags"):
        values = finding.get(key, [])
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError("finding security attributes must be arrays of strings")
        state[key] = sorted(set(values))
    risk = finding["risk"]
    state["risk.score"] = risk["score"]
    state["risk.level"] = risk["level"]
    factors = risk.get("factors", [])
    if not isinstance(factors, list) or any(not isinstance(factor, dict) for factor in factors):
        raise ValueError("finding risk factors must be an array of objects")
    state["risk.factors"] = sorted({_canonical([factor.get("id"), factor.get("weight")]) for factor in factors})
    return state


def _identity_attested(report: dict[str, Any]) -> bool:
    return report.get("finding_identity_schema") == FINDING_IDENTITY_SCHEMA and all(
        finding.get("identity_schema") == FINDING_IDENTITY_SCHEMA for finding in report["findings"]
    )


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Keep positive observations, but never infer absence from lost coverage."""
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        raise ValueError("reports must be JSON objects")
    b, c = _findings(baseline), _findings(current)
    reasons = []
    for label, report in (("baseline", baseline), ("current", current)):
        if not _complete(report):
            reasons.append(f"{label} scan is incomplete or lacks completion metadata")
        if not _identity_attested(report):
            reasons.append(f"{label} finding identity schema is legacy or unsupported; collect a fresh baseline after upgrade")
    bs, cs = _scope_digest(baseline), _scope_digest(current)
    if not bs or not cs:
        reasons.append("collection scope is unavailable; regenerate legacy reports or use attested static inputs")
    elif bs != cs:
        reasons.append("collection or detection scope differs")
    missing = [b[i] for i in sorted(b.keys() - c.keys())]
    changes = []
    for identifier in sorted(b.keys() & c.keys()):
        before, after = _substantive_state(b[identifier]), _substantive_state(c[identifier])
        fields = sorted(key for key in before if before[key] != after[key])
        if fields:
            changes.append({"before": b[identifier], "after": c[identifier], "changed_fields": fields})
    return {
        "comparable": not reasons,
        "reasons": reasons,
        "new": [c[i] for i in sorted(c.keys() - b.keys())],
        "resolved": [] if reasons else missing,
        "unknown": missing if reasons else [],
        "changed": changes,
    }
