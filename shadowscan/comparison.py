"""Conservative collection-scope provenance and report comparison.

A finding disappearing from a report is only evidence of resolution when both
scans completed under the same collection and detection settings and its ID is
stable across scans. Scope hashes identify inputs, not their contents: a file
changing is what comparisons measure.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.config import PATH_KEYS, ConnectorSpec, ScanConfig
from shadowscan.connectors import _BUILTIN, get_connector_class
from shadowscan.connectors.base import LIVE_SCOPE_SCHEMA
from shadowscan.models import FINDING_IDENTITY_SCHEMA, Finding
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.digest import scanner_source_digest
from shadowscan.utils.files import read_policy_text
from shadowscan.utils.redaction import _sensitive_key, sanitize
from shadowscan.utils.safe_json import JSONIntegrityError, strict_json_loads

_SCHEMA = "shadowscan.collection-scope/v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_EMBEDDED_CREDENTIAL_FINGERPRINT = re.compile(r"credential:(?:hmac-)?sha256:[a-f0-9]{64}")
MAX_REPORT_BYTES = 64 * 1024 * 1024
# Environment variable with the operator's stable identity key; the engine
# reads it. Gateway identities and credential pseudonyms are stable under one key.
IDENTITY_KEY_ENV = "SHADOWSCAN_IDENTITY_KEY"
_GATEWAY_SCOPE = "shadowscan.collection-scope.gateway.v1"


def load_report(path: str | Path) -> dict[str, Any]:
    """Read an unambiguous, bounded report without following input symlinks."""

    try:
        try:
            report = strict_json_loads(read_policy_text(Path(path), max_bytes=MAX_REPORT_BYTES))
        except JSONIntegrityError as exc:
            # Preserve the established public errors without exposing any
            # attacker-controlled field names or values.
            message = "duplicate report field" if "Duplicate" in str(exc) else "report numbers must be finite"
            raise ValueError(message) from None
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
                if _sensitive_key(str(key)):
                    return True
                remaining.append(child)
        elif isinstance(item, (list, tuple)):
            remaining.extend(item)
    return False


def _scanner_digest() -> str:
    return scanner_source_digest()


def _attests_live_scope(name: str) -> bool:
    """Whether a built-in connector declares live scope attestation (False if it cannot be loaded)."""
    try:
        return getattr(get_connector_class(name), "attests_live_scope", False) is True
    except Exception:  # noqa: BLE001 - an unloadable connector attests nothing
        return False


def _live_scope_material(record: Any) -> tuple[dict[str, Any] | None, str]:
    """The fingerprinted part of a live scope record, or the reason it cannot be attested.

    Only the reported principal, the requested options, the partitions and the
    enumerations with their outcomes are hashed. Detail calls, counts and the
    principal's ``verified_by`` note never are: a new agent adds detail calls
    and must not change the scope.
    """
    incomplete = "live collection was not verified or was incomplete"
    if not isinstance(record, Mapping) or record.get("schema") != LIVE_SCOPE_SCHEMA:
        return None, incomplete
    requested, partitions = record.get("requested"), record.get("partitions")
    operations, details = record.get("operations"), record.get("details")
    if (
        record.get("complete") is not True
        or not isinstance(requested, Mapping)
        or not isinstance(partitions, Mapping)
        or not isinstance(operations, list)
        or not isinstance(details, list)
    ):
        return None, incomplete
    enumerations = []
    for entry in [*operations, *details]:
        if not isinstance(entry, Mapping) or entry.get("outcome") != "ok":
            return None, incomplete
    for entry in operations:
        partition = entry.get("partition")
        if (
            not isinstance(entry.get("service"), str)
            or not isinstance(entry.get("operation"), str)
            or not (partition is None or isinstance(partition, str))
        ):
            return None, incomplete
        enumerations.append([entry["service"], entry["operation"], partition, entry["outcome"]])
    if not enumerations:
        # Nothing was listed: there is no coverage to attest.
        return None, incomplete
    # A complete collection whose account, tenant or projects the provider did not confirm.
    principal = record.get("principal")
    if not isinstance(principal, Mapping) or not all(
        isinstance(principal.get(key), str) and principal[key] for key in ("provider", "kind", "id")
    ):
        return None, "live principal could not be verified"
    material = {
        "principal": {key: principal[key] for key in ("provider", "kind", "id")},
        "requested": dict(requested),
        "partitions": dict(partitions),
        "operations": sorted(enumerations, key=_canonical),
    }
    return material, ""


def _live_summary(spec: ConnectorSpec, record: Any) -> dict[str, Any]:
    """The public, unfingerprinted account of what one live connector collected."""
    summary: dict[str, Any] = {"connector": spec.name, "label": spec.label}
    if not isinstance(record, Mapping):
        return {**summary, "complete": False}
    fields = ("principal", "requested", "partitions", "operations", "details", "complete")
    values = {key: record.get(key) for key in fields}
    try:
        if _has_private_scope_values(values) or sanitize(values) != values:
            return {**summary, "complete": False}
    except (RecursionError, TypeError, ValueError):
        return {**summary, "complete": False}
    return {**summary, **values}


def build_collection_scope(
    config: ScanConfig,
    index: SignatureIndex,
    specs: list[ConnectorSpec],
    *,
    identity_key: bytes | None = None,
    live_records: Sequence[Mapping[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Describe the selected inputs and attested live scopes without exposing configuration values.

    ``live_records`` lists, in ``specs`` order, what each live built-in connector
    recorded during collection (``ConnectorContext.scope_record``); the engine
    passes them after collection. A live connector is attested only by its own
    complete record with a verified principal and successful enumerations, and
    every live record is also published under ``live``, outside the fingerprint.
    Without records (before collection), live scopes are not attested. Third-party
    implementations never are, so those scans cannot automatically resolve
    earlier findings.

    A public digest of low-entropy credentials or binding labels would permit
    offline guessing. Such configurations have no exported fingerprint and
    cannot automatically resolve findings in a comparison.

    Gateway inputs are attested only under the operator's stable
    ``identity_key``, which also keys their part of the fingerprint: an HMAC
    under a secret key cannot be tested against guessed labels or bindings,
    and a different key, which changes every gateway ID, changes the scope.
    """
    records = (list(live_records) if live_records is not None else [])[: len(specs)]
    records += [None] * (len(specs) - len(records))
    scope = _collection_scope(config, index, specs, records, identity_key, live_records is not None)
    summaries = [
        _live_summary(spec, record) for spec, record in zip(specs, records, strict=True) if record is not None
    ]
    if summaries:
        scope["live"] = summaries
    return scope


def _collection_scope(
    config: ScanConfig,
    index: SignatureIndex,
    specs: list[ConnectorSpec],
    records: list[Mapping[str, Any] | None],
    identity_key: bytes | None,
    collected: bool,
) -> dict[str, Any]:
    unavailable = {"schema": _SCHEMA, "comparable": False}
    if not specs:
        return {**unavailable, "reason": "no connectors selected"}
    inputs: list[dict[str, Any]] = []
    for spec, record in zip(specs, records, strict=True):
        if spec.name not in _BUILTIN:
            return {**unavailable, "reason": "third-party connector scope is not attested"}
        offline = isinstance(spec.config.get("input"), str) and bool(spec.config["input"])
        local = spec.name == "code.filesystem" and bool(spec.config.get("path") or spec.config.get("paths"))
        if not offline and not local:
            if not collected or (record is None and not _attests_live_scope(spec.name)):
                return {**unavailable, "reason": "live collection scope is not attested"}
            live, reason = _live_scope_material(record)
            if live is None:
                return {**unavailable, "reason": reason}
            live_input = {"name": spec.name, "label": spec.label, "live": live}
            try:
                if sanitize(live_input) != live_input or _has_private_scope_values(live_input):
                    # A value the sanitizer would change is a credential that slipped in.
                    return {**unavailable, "reason": "configuration contains private comparison values"}
            except (RecursionError, TypeError, ValueError):
                return {**unavailable, "reason": "configuration contains private comparison values"}
            inputs.append(live_input)
            continue
        if spec.name == "code.filesystem" and spec.config.get("diff_base"):
            # Which files were read depends on Git state outside the configuration, and
            # unchanged files are not read at all: absence is not evidence of resolution.
            return {**unavailable, "reason": "diff-scoped collection is not a repository inventory"}
        options = dict(spec.config)
        for key in PATH_KEYS:
            val = options.get(key)
            if isinstance(val, str) and val:
                options[key] = str(Path(val).expanduser().resolve())
            elif isinstance(val, list):
                options[key] = [str(Path(v).expanduser().resolve()) if isinstance(v, str) else v for v in val]
        # Gateway IDs and pseudonyms are keyed to each scan unless the operator
        # supplied a stable key; even an unscoped export's configuration can
        # hold guessable labels and bindings, so it never gets a public digest.
        if spec.name == "gateway.logs":
            if identity_key is None:
                return {**unavailable, "reason": f"gateway identities are scan-local; set {IDENTITY_KEY_ENV}"}
            try:
                material = _canonical([_GATEWAY_SCOPE, options, spec.label])
            except (RecursionError, TypeError, ValueError):
                return {**unavailable, "reason": "collection scope could not be fingerprinted"}
            inputs.append({"name": spec.name, "keyed": hmac.digest(identity_key, material, "sha256").hex()})
            continue
        try:
            if sanitize((options, spec.label)) != (options, spec.label) or _has_private_scope_values(
                (options, spec.label)
            ):
                return {**unavailable, "reason": "configuration contains private comparison values"}
        except (RecursionError, TypeError, ValueError):
            return {**unavailable, "reason": "configuration contains private comparison values"}
        inputs.append({"name": spec.name, "label": spec.label, "config": options})
    try:
        scope: dict[str, Any] = {
            "inputs": sorted(inputs, key=_canonical),
            "min_confidence": config.min_confidence,
            "signatures": index.fingerprint(),
            "scanner": _scanner_digest(),
            "version": __version__,
            # Key rotation invalidates comparisons using keyed
            # credential evidence without revealing the secret key.
            "credential_identity_key": (
                hmac.digest(identity_key, b"shadowscan.collection-scope.credential-key.v1", "sha256").hex()
                if identity_key is not None
                else None
            ),
        }
        if config.mcp_registries:
            # Pinned snapshots change tags and scores. The key is added only when configured, so
            # the fingerprints of scans without MCP registries, and their baselines, are unchanged.
            scope["mcp_registries"] = sorted(
                [source.id, source.sha256, source.approved] for source in config.mcp_registries
            )
        fingerprint = hashlib.sha256(_canonical(scope)).hexdigest()
    except (OSError, TypeError, ValueError):
        return {**unavailable, "reason": "collection scope could not be fingerprinted"}
    return {"schema": _SCHEMA, "comparable": True, "fingerprint": fingerprint}


def _complete(report: dict[str, Any]) -> bool:
    summary, stats = report.get("summary"), report.get("stats")
    return (
        isinstance(summary, dict)
        and summary.get("complete") is True
        and isinstance(stats, list)
        and bool(stats)
        and all(
            isinstance(s, dict)
            and isinstance(s.get("connector"), str)
            and bool(s["connector"].strip())
            # Missing or malformed completion fields are not evidence that a
            # connector succeeded. In particular, falsey null/0/"" values must
            # not let truncated or transformed reports resolve prior findings.
            and isinstance(s.get("errors"), list)
            and not s["errors"]
            and s.get("skipped") is False
            and s.get("incomplete") is False
            for s in stats
        )
    )


def _summary_matches_findings(report: dict[str, Any]) -> bool:
    """Whether the summary counts describe the findings array the report actually carries.

    A truncated or filtered array (an emptied ``findings`` in a complete
    report) must not read as resolution. A report without a summary is
    already incomparable through :func:`_complete`.
    """
    summary, findings = report.get("summary"), report["findings"]
    if not isinstance(summary, dict):
        return True
    total = summary.get("total")
    if type(total) is not int or total != len(findings):
        return False
    for key, field in (("by_surface", "surface"), ("by_kind", "kind")):
        if key in summary and summary[key] != dict(Counter(finding.get(field) for finding in findings)):
            return False
    return True


def _connector_coverage(report: dict[str, Any]) -> list[str]:
    """Connectors that completed in a complete report.

    Scan-level ``engine.*`` records are not connectors. In a complete report
    they carry warnings only (an inventory kept in the scanned tree, say), so
    one appearing between scans does not change what was collected.
    """
    return sorted(s["connector"] for s in report["stats"] if not s["connector"].startswith("engine."))


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
            not isinstance(risk, dict)
            or risk.get("level") not in {"critical", "high", "medium", "low", "info"}
            or not isinstance(risk.get("score"), (int, float))
            or isinstance(risk.get("score"), bool)
            or not 0 <= risk["score"] <= 100
            or not isinstance(record.get("title"), str)
            or not isinstance(record.get("resource"), str)
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
    state["risk.factors"] = sorted(
        {_canonical([factor.get("id"), factor.get("weight")]) for factor in factors}
    )
    return state


def _identity_attested(report: dict[str, Any]) -> bool:
    return report.get("finding_identity_schema") == FINDING_IDENTITY_SCHEMA and all(
        finding.get("identity_schema") == FINDING_IDENTITY_SCHEMA for finding in report["findings"]
    )


def _scan_local(record: dict[str, Any]) -> bool:
    """Whether a finding's ID identifies its source only within its own report.

    ``gateway.logs`` declares ``metadata.identity_scope``: ``run`` when its IDs
    derive from a key that is random for each scan, ``keyed`` when they derive
    from the operator's stable key. Any other declared scope, even a malformed
    one, is treated as scan-local: absence of such an ID from another report
    says nothing about the source it describes.
    """
    metadata = record.get("metadata")
    return (
        isinstance(metadata, dict) and "identity_scope" in metadata and metadata["identity_scope"] != "keyed"
    )


def _public_finding(record: dict[str, Any]) -> dict[str, Any]:
    """Apply the normal finding export boundary to imported comparison records.

    JSON reports may come from older versions or external producers. Reusing
    the model's allowlist and cross-field credential sanitization avoids
    reflecting raw secrets (or arbitrary extra columns) through the diff CLI.
    Matching and change detection still use the original observation values.
    """
    try:
        return Finding.from_dict(record).to_dict()
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        raise ValueError("report contains a finding that cannot be safely exported") from None


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Keep positive observations, but never infer absence from lost coverage.

    Unmatched findings with scan-local IDs are neither new, resolved nor
    unknown: they are listed under ``not_comparable`` and the comparison is
    incomplete. A scan-local ID present in both reports is compared as usual.
    """
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        raise ValueError("reports must be JSON objects")
    b, c = _findings(baseline), _findings(current)
    # Validate and sanitize every imported record before publishing anything,
    # including shared records with no substantive change. Schema keys and
    # verified generated identities stay under the model's protection.
    public_b = {identifier: _public_finding(record) for identifier, record in b.items()}
    public_c = {identifier: _public_finding(record) for identifier, record in c.items()}
    reasons = []
    for label, report in (("baseline", baseline), ("current", current)):
        if not _complete(report):
            reasons.append(f"{label} scan is incomplete or lacks completion metadata")
        if not _summary_matches_findings(report):
            reasons.append(f"{label} summary counts do not match its findings (truncated or edited report)")
        if not _identity_attested(report):
            reasons.append(
                f"{label} finding identity schema is legacy or unsupported; "
                "collect a fresh baseline after upgrade"
            )
    if _complete(baseline) and _complete(current):
        if _connector_coverage(baseline) != _connector_coverage(current):
            reasons.append("connector completion coverage differs")
    bs, cs = _scope_digest(baseline), _scope_digest(current)
    if not bs or not cs:
        reasons.append(
            "collection scope is unavailable; regenerate legacy reports or use attested static inputs"
        )
    elif bs != cs:
        reasons.append("collection or detection scope differs")
    local_b = sorted(i for i in b.keys() - c.keys() if _scan_local(b[i]))
    local_c = sorted(i for i in c.keys() - b.keys() if _scan_local(c[i]))
    if local_b or local_c:
        reasons.append(
            f"{len(local_b) + len(local_c)} finding(s) have scan-local identities "
            "(metadata.identity_scope) and cannot be matched across scans; "
            f"set {IDENTITY_KEY_ENV} for both scans to compare gateway callers"
        )
    missing = [public_b[i] for i in sorted(b.keys() - c.keys() - set(local_b))]
    changes = []
    for identifier in sorted(b.keys() & c.keys()):
        before, after = _substantive_state(b[identifier]), _substantive_state(c[identifier])
        fields = sorted(key for key in before if before[key] != after[key])
        if fields:
            changes.append(
                {"before": public_b[identifier], "after": public_c[identifier], "changed_fields": fields}
            )
    return {
        "comparable": not reasons,
        "reasons": reasons,
        "new": [public_c[i] for i in sorted(c.keys() - b.keys() - set(local_c))],
        "resolved": [] if reasons else missing,
        "unknown": missing if reasons else [],
        "changed": changes,
        "not_comparable": {
            "baseline": [public_b[i] for i in local_b],
            "current": [public_c[i] for i in local_c],
        },
    }
