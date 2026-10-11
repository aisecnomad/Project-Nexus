"""Conservative collection-scope provenance and report comparison.

A finding disappearing from a report is only evidence of resolution when both
scans completed under the same collection and detection settings and its ID is
stable across scans. Scope hashes identify inputs, not their contents: a file
changing is what comparisons measure.

Each substantive change is labelled with a drift class (:data:`DRIFT_CLASSES`)
and whether it is adverse: it widens what the finding can do or weakens how it
is governed. A baseline can be pinned by the SHA-256 of its file and expired by
age (:func:`baseline_lifecycle_reasons`); an expired or undatable baseline makes
the comparison incomplete.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.autonomy import _INITIATION_RANK, _OVERSIGHT_RANK, UNDERSTATED_TAG, valid_autonomy
from shadowscan.config import PATH_KEYS, ConnectorSpec, ScanConfig
from shadowscan.connectors import _BUILTIN, get_connector_class
from shadowscan.connectors.base import LIVE_SCOPE_SCHEMA
from shadowscan.models import FINDING_IDENTITY_SCHEMA, Finding
from shadowscan.registries import RECONCILIATION_KEY, RECONCILIATION_STATUSES
from shadowscan.risk import MITIGATING_TAGS
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.digest import scanner_source_digest
from shadowscan.utils.files import read_policy_bytes
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

# What a substantive change is about. ``coverage`` is the comparison itself: an
# incomplete comparison is adverse coverage drift and always exits 3.
DRIFT_CLASSES = ("inventory", "capability", "autonomy", "governance", "coverage")
_AUTONOMY_FIELDS = {
    "metadata.autonomy.floor": None,
    "metadata.autonomy.ceiling": None,
    "metadata.autonomy.oversight": _OVERSIGHT_RANK,
    "metadata.autonomy.initiation": _INITIATION_RANK,
}
_TOOL_HASH = "metadata.tool_definition_sha256"
_RECONCILIATION = "metadata.registry_reconciliation.status"
_CAPABILITY_LISTS = ("permissions", "capabilities", "frameworks", "model_providers", "models")
# Tags that record a governance gap rather than something the finding can do.
_GOVERNANCE_TAGS = frozenset({UNDERSTATED_TAG})
# A baseline written on a host whose clock runs slightly ahead is not from the future.
_CLOCK_SKEW = timedelta(minutes=5)
# About a century: far beyond any review cycle, and well inside what timedelta can represent.
MAX_BASELINE_AGE_DAYS = 36_500


class ReportDigestMismatch(ValueError):
    """A report file's raw bytes do not have the pinned SHA-256 digest."""


def _parse_report(data: bytes) -> dict[str, Any]:
    try:
        try:
            report = strict_json_loads(data.decode("utf-8-sig"))
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


def load_report(path: str | Path) -> dict[str, Any]:
    """Read an unambiguous, bounded report without following input symlinks."""
    return load_report_with_digest(path)[0]


def load_report_with_digest(
    path: str | Path, *, expected_sha256: str | None = None
) -> tuple[dict[str, Any], str]:
    """:func:`load_report` and the SHA-256 of the file's raw bytes, as ``sha256sum`` prints it.

    The digest and the parsed report come from one bounded read, so the file
    cannot change between the check and the parse. With ``expected_sha256`` (64
    lowercase hex characters), a different digest raises
    :class:`ReportDigestMismatch` before the content is parsed.
    """
    data = read_policy_bytes(Path(path), max_bytes=MAX_REPORT_BYTES)
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ReportDigestMismatch("report digest does not match the pinned digest")
    return _parse_report(data), digest


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
    """Security state, excluding timestamps, counters, prose and evidence order.

    Metadata is compared only at fixed paths: the autonomy interval, an MCP
    tool's definition digest and the registry reconciliation status. Each is
    None when absent, so findings without them compare as before; a malformed
    value fails the comparison rather than reading as unchanged.
    """
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
    metadata = finding.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("finding metadata must be an object")
    autonomy = metadata.get("autonomy")
    if "autonomy" in metadata and not valid_autonomy(autonomy):
        raise ValueError("finding autonomy metadata is malformed")
    for field in _AUTONOMY_FIELDS:
        state[field] = autonomy[field.rpartition(".")[2]] if autonomy is not None else None
    tool_hash = metadata.get("tool_definition_sha256")
    if tool_hash is not None and not isinstance(tool_hash, str):
        raise ValueError("finding tool definition digest must be a string")
    state[_TOOL_HASH] = tool_hash
    reconciliation = metadata.get(RECONCILIATION_KEY)
    if RECONCILIATION_KEY in metadata and (
        not isinstance(reconciliation, dict) or reconciliation.get("status") not in RECONCILIATION_STATUSES
    ):
        raise ValueError("finding registry reconciliation metadata is malformed")
    state[_RECONCILIATION] = reconciliation["status"] if reconciliation is not None else None
    return state


def _present(value: Any) -> bool:
    """Whether a scalar says something: None, empty and blank strings do not."""
    return value is not None and not (isinstance(value, str) and not value.strip())


def _direction(field: str, before: Any, after: Any) -> str:
    """``set`` from nothing, ``cleared`` to nothing, ``rose``/``fell`` for autonomy, else ``changed``."""
    if not _present(before):
        return "set"
    if not _present(after):
        return "cleared"
    if field in _AUTONOMY_FIELDS:
        # Levels are ordered by number, oversight and initiation by the autonomy each admits.
        rank = _AUTONOMY_FIELDS[field]
        higher = rank[after] > rank[before] if rank is not None else after > before
        return "rose" if higher else "fell"
    return "changed"


def _adverse(field: str, before: Any, after: Any, direction: str) -> bool:
    """Whether a changed scalar widens what the finding can do or weakens how it is governed."""
    if field in _AUTONOMY_FIELDS:
        # A first classification is not a rise: an unclassified finding was never known to be low.
        return direction == "rose"
    if field == _TOOL_HASH:
        # A changed or lost definition digest; the first one recorded is not a change.
        return direction != "set"
    if field == "owner":
        return direction == "cleared"
    if field == "shadow":
        return after is True
    if field == "registry_match":
        return direction != "set"
    if field == _RECONCILIATION:
        # Newly missing from a complete registry listing, or no longer matched by a record.
        return bool(after == "observed-not-registered" or before == "registered-and-observed")
    # kind and resource_type: the finding is now inventoried as something else.
    return True


_SCALAR_CLASSES = {
    "kind": "inventory",
    "resource_type": "inventory",
    _TOOL_HASH: "capability",
    **dict.fromkeys(_AUTONOMY_FIELDS, "autonomy"),
    "owner": "governance",
    "shadow": "governance",
    "registry_match": "governance",
    _RECONCILIATION: "governance",
}


def _list_parts(field: str, values: list[str]) -> list[tuple[str, set[str]]]:
    """``(drift class, items)`` of a list field; governance tags are split from the other tags."""
    items = set(values)
    if field != "tags":
        return [("capability", items)]
    return [("capability", items - _GOVERNANCE_TAGS), ("governance", items & _GOVERNANCE_TAGS)]


def _widens(field: str, added: set[str], removed: set[str]) -> bool:
    """Whether a list change is adverse: something new, or a lost mitigating tag.

    Anything new the finding can do or reach is adverse, whatever it lost. A
    mitigating tag (:data:`~shadowscan.risk.MITIGATING_TAGS`) records a limit, so
    losing one (``disabled`` on an agent enabled again) is adverse and gaining
    one is not.
    """
    if field != "tags":
        return bool(added)
    return bool(added - MITIGATING_TAGS or removed & MITIGATING_TAGS)


def _drift(
    before: dict[str, Any], after: dict[str, Any], shown_before: dict[str, Any], shown_after: dict[str, Any]
) -> list[dict[str, Any]]:
    """Classify the differences between two substantive states of one finding.

    Directions and adversity come from the observed states; the values shown come
    from the states of the exported records, so nothing the export boundary
    redacts is echoed. ``risk.*`` changes are not classified: ``--fail-on-new``
    gates on risk level rises.
    """
    entries = []
    for field, drift_class in _SCALAR_CLASSES.items():
        if before[field] == after[field]:
            continue
        direction = _direction(field, before[field], after[field])
        entries.append(
            {
                "class": drift_class,
                "field": field,
                "direction": direction,
                "adverse": _adverse(field, before[field], after[field], direction),
                "before": shown_before[field],
                "after": shown_after[field],
            }
        )
    for field in (*_CAPABILITY_LISTS, "tags"):
        parts = zip(
            _list_parts(field, before[field]),
            _list_parts(field, after[field]),
            _list_parts(field, shown_before[field]),
            _list_parts(field, shown_after[field]),
            strict=True,
        )
        for (drift_class, old), (_, new), (_, shown_old), (_, shown_new) in parts:
            added, removed = new - old, old - new
            if not added and not removed:
                continue
            entries.append(
                {
                    "class": drift_class,
                    "field": field,
                    "direction": "replaced" if added and removed else "added" if added else "removed",
                    "adverse": _widens(field, added, removed),
                    "added": sorted(shown_new - shown_old),
                    "removed": sorted(shown_old - shown_new),
                }
            )
    return sorted(entries, key=lambda entry: (DRIFT_CLASSES.index(entry["class"]), entry["field"]))


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


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _started_at(report: dict[str, Any]) -> datetime | None:
    """The report's ``started_at`` as a timezone-aware time; None when missing or unparseable."""
    return _moment(report.get("started_at"))


def _moment(value: Any) -> datetime | None:
    """A report time as a timezone-aware datetime; None when not an offset-aware ISO 8601 string."""
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.utcoffset() is not None else None


def baseline_age_days(baseline: dict[str, Any], *, now: datetime | None = None) -> int | None:
    """Whole days since the baseline scan started (negative if it claims a later time), or None.

    A fleet report starts when its oldest source started, so its age is the age
    of its oldest evidence.
    """
    started = _started_at(baseline)
    if started is None:
        return None
    return ((now or _utcnow()) - started) // timedelta(days=1)


def baseline_lifecycle_reasons(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    max_age_days: int | None,
    now: datetime | None = None,
) -> list[str]:
    """Reasons a baseline cannot serve under an age limit; empty when it can or no limit is set.

    Age is measured from the baseline's ``started_at``. A baseline whose start
    time is missing, unparseable, without a timezone or in the future, or that
    started after the current scan, cannot show that it is recent enough, so each
    of those is a reason as well.
    """
    if max_age_days is None:
        return []
    if type(max_age_days) is not int or not 1 <= max_age_days <= MAX_BASELINE_AGE_DAYS:
        raise ValueError(
            f"maximum baseline age must be a positive number of days, at most {MAX_BASELINE_AGE_DAYS}"
        )
    moment = now or _utcnow()
    started, current_started = _started_at(baseline), _started_at(current)
    if started is None:
        return ["baseline start time is missing or invalid; its age cannot be established"]
    reasons = []
    if started > moment + _CLOCK_SKEW:
        reasons.append("baseline start time is in the future")
    elif moment - started > timedelta(days=max_age_days):
        reasons.append("baseline is older than --max-baseline-age-days")
    if current_started is None:
        reasons.append("current start time is missing or invalid; the baseline cannot be dated against it")
    elif started > current_started:
        reasons.append("baseline started after the current scan")
    return reasons


def _drift_totals(
    new: list[dict[str, Any]],
    resolved: list[dict[str, Any]],
    changes: list[dict[str, Any]],
    reasons: list[str],
) -> tuple[dict[str, int], dict[str, bool]]:
    """Per class, the findings with drift of that class and whether any of it is adverse.

    New and resolved findings are inventory drift; a new one is adverse. Coverage
    counts the reasons the comparison is incomplete, and any reason is adverse.
    """
    counts = dict.fromkeys(DRIFT_CLASSES, 0)
    adverse = dict.fromkeys(DRIFT_CLASSES, False)
    counts["inventory"] = len(new) + len(resolved)
    adverse["inventory"] = bool(new)
    for change in changes:
        for drift_class in {entry["class"] for entry in change["drift"]}:
            counts[drift_class] += 1
        for entry in change["drift"]:
            adverse[entry["class"]] = adverse[entry["class"]] or entry["adverse"]
    counts["coverage"] = len(reasons)
    adverse["coverage"] = bool(reasons)
    return counts, adverse


def compare_reports(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    max_baseline_age_days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Keep positive observations, but never infer absence from lost coverage.

    Unmatched findings with scan-local IDs are neither new, resolved nor
    unknown: they are listed under ``not_comparable`` and the comparison is
    incomplete. A scan-local ID present in both reports is compared as usual.
    Each change lists its ``drift``; ``drift_summary`` and ``adverse`` total
    them per class. With ``max_baseline_age_days``, a baseline that cannot be
    shown to be that recent makes the comparison incomplete.
    """
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        raise ValueError("reports must be JSON objects")
    b, c = _findings(baseline), _findings(current)
    # Validate and sanitize every imported record before publishing anything,
    # including shared records with no substantive change. Schema keys and
    # verified generated identities stay under the model's protection.
    public_b = {identifier: _public_finding(record) for identifier, record in b.items()}
    public_c = {identifier: _public_finding(record) for identifier, record in c.items()}
    moment = now or _utcnow()
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
            "collection scope is unavailable (see each report's collection_scope.reason); regenerate "
            "legacy reports, or use attested static inputs or attested live connectors"
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
    reasons += baseline_lifecycle_reasons(baseline, current, max_age_days=max_baseline_age_days, now=moment)
    missing = [public_b[i] for i in sorted(b.keys() - c.keys() - set(local_b))]
    changes = []
    for identifier in sorted(b.keys() & c.keys()):
        before, after = _substantive_state(b[identifier]), _substantive_state(c[identifier])
        fields = sorted(key for key in before if before[key] != after[key])
        if fields:
            shown = _substantive_state(public_b[identifier]), _substantive_state(public_c[identifier])
            changes.append(
                {
                    "before": public_b[identifier],
                    "after": public_c[identifier],
                    "changed_fields": fields,
                    "drift": _drift(before, after, *shown),
                }
            )
    new = [public_c[i] for i in sorted(c.keys() - b.keys() - set(local_c))]
    resolved = [] if reasons else missing
    drift_summary, adverse = _drift_totals(new, resolved, changes, reasons)
    return {
        "comparable": not reasons,
        "reasons": reasons,
        "new": new,
        "resolved": resolved,
        "unknown": missing if reasons else [],
        "changed": changes,
        "not_comparable": {
            "baseline": [public_b[i] for i in local_b],
            "current": [public_c[i] for i in local_c],
        },
        "drift_summary": drift_summary,
        "adverse": adverse,
        "baseline": {"age_days": baseline_age_days(baseline, now=moment)},
    }
