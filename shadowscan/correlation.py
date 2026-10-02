"""Cross-surface correlation and gateway-to-code attribution.

``correlate`` links findings across surfaces by resource ids and normalised
names.  ``correlate_runtime`` conservatively attributes gateway telemetry to
static framework findings using only operator-configured exact caller/scope
bindings.  Gateway user agents are observations, not attestations: an
``observed`` result means the linked gateway recorded a timestamped request
bearing that framework fingerprint.
"""

from __future__ import annotations

import json
import re
from typing import Any

from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.redaction import REDACTED
from shadowscan.utils.text import parse_timestamp, to_iso

_NAME_KEYS = (
    "agent_name",
    "name",
    "display_name",
    "app_slug",
    "okta_name",
    "developer_name",
    "schema_name",
    "app_id",
    "client_id",
    "msa_app_id",
    "bot_id",
    "principal",
    "caller",
    "repository",
    "project",
    "function_name",
    "agent_id",
)


def _normalise_key(s: Any) -> str | None:
    """Normalise a value for fuzzy cross-surface matching."""
    if s is None:
        return None
    t = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return t if len(t) >= 5 else None


def correlate(findings: list[Finding]) -> None:
    """Link findings across surfaces that describe the same agent / identity / resource.

    Keys: resource ids (ARNs, app/client ids), normalised names and repository labels found in
    metadata. Linked ids are stored in ``metadata['related']`` on both sides.
    """
    keys: dict[str, set[str]] = {}
    for f in findings:
        cand: set[str] = set()
        res = _normalise_key(f.resource)
        if res:
            cand.add(f"res:{res}")
        for k in _NAME_KEYS:
            v = f.metadata.get(k)
            if isinstance(v, str):
                n = _normalise_key(v)
                if n:
                    cand.add(f"name:{n}")
        if f.kind in {Kind.AGENT, Kind.BOT_APP, Kind.SERVICE_IDENTITY, Kind.OAUTH_GRANT, Kind.MCP_SERVER}:
            tail = f.title.split(":", 1)[-1].strip() if ":" in f.title else None
            n = _normalise_key(tail)
            if n and len(n) >= 8:
                cand.add(f"name:{n}")
        for e in f.evidence:
            if e.location and e.location.startswith(("arn:", "projects/", "/subscriptions/", "ocid1.")):
                n = _normalise_key(e.location)
                if n:
                    cand.add(f"res:{n}")
        for k in cand:
            keys.setdefault(k, set()).add(f.id)
    related: dict[str, set[str]] = {}
    for ids in keys.values():
        if 1 < len(ids) <= 25:
            for i in ids:
                related.setdefault(i, set()).update(ids - {i})
    if not related:
        return
    by_id = {f.id: f for f in findings}
    for fid, others in related.items():
        linked_finding = by_id.get(fid)
        if linked_finding:
            links = sorted(
                o
                for o in others
                if by_id.get(o)
                and (
                    by_id[o].connector != linked_finding.connector
                    or by_id[o].surface != linked_finding.surface
                )
            )
            if links:
                linked_finding.metadata["related"] = links


def _usable_code_identity(code: Finding) -> bool:
    """Lossy report identities must never establish an exact workload binding."""
    return (
        isinstance(code.resource, str)
        and bool(code.resource)
        and REDACTED not in code.resource
        and all(
            value is None or (isinstance(value, str) and REDACTED not in value)
            for value in (code.provider, code.account, code.region)
        )
    )


def correlate_runtime(findings: list[Finding]) -> None:
    """Attach runtime_activity metadata without increasing risk or confidence."""
    bound = _trusted_bindings(findings)
    code_identities: dict[str, set[tuple[str | None, str | None, str | None, str]]] = {}
    for code in findings:
        if code.surface == Surface.CODE:
            code_identities.setdefault(code.resource, set()).add(
                (code.provider, code.account, code.region, code.connector)
            )

    for code in findings:
        if code.surface != Surface.CODE:
            continue
        # Repeated calls must replace earlier results, including after cache use.
        code.evidence[:] = [ev for ev in code.evidence if ev.signal != "runtime:gateway-observed"]
        code.metadata.pop("runtime_activity", None)
        if not code.frameworks:
            continue
        usable_identity = _usable_code_identity(code)
        ambiguous = len(code_identities.get(code.resource, set())) > 1
        relevant = [] if ambiguous or not usable_identity else bound.get(code.resource, [])
        matches, missing_timestamps = _framework_matches(code, relevant)
        if matches:
            activity = _observed_activity(code, matches)
        else:
            if not usable_identity:
                reason = "redacted-or-missing-code-identity"
            elif ambiguous:
                reason = "ambiguous-code-resource"
            elif not relevant:
                reason = "no-trusted-workload-binding"
            elif missing_timestamps:
                reason = "missing-event-timestamps"
            else:
                reason = "no-matching-framework-in-linked-telemetry"
            activity = {
                "status": "unknown" if not relevant or missing_timestamps else "unobserved",
                "reason": reason,
                "events": 0,
                "frameworks": [],
                "window": None,
                "last_seen": None,
                "production_observed": False,
                "production_label_verified": False,
                "sources": [],
                "limitations": (
                    "Absence in exported telemetry does not establish that the framework is inactive."
                ),
            }
        code.metadata["runtime_activity"] = activity


def _trusted_bindings(findings: list[Finding]) -> dict[str, list[tuple[Finding, dict[str, Any]]]]:
    """Map each code resource to the gateway observations that name it through a trusted binding."""
    bound: dict[str, list[tuple[Finding, dict[str, Any]]]] = {}
    for gateway in findings:
        if gateway.surface != Surface.GATEWAY:
            continue
        observations = gateway.metadata.get("runtime_observations", [])
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if (
                not isinstance(observation, dict)
                or observation.get("identity_basis") != "configured-exact-caller-and-scope"
                or observation.get("identity_assurance")
                not in ("operator-asserted", "provider-authenticated-field")
            ):
                continue
            resources = observation.get("code_resources", [])
            if isinstance(resources, list):
                for resource in resources:
                    if isinstance(resource, str) and resource and REDACTED not in resource:
                        bound.setdefault(resource, []).append((gateway, observation))
    return bound


def _framework_matches(
    code: Finding,
    relevant: list[tuple[Finding, dict[str, Any]]],
) -> tuple[list[dict[str, Any]], bool]:
    """Return timestamped observations sharing a framework with ``code`` and whether any lacked timestamps."""
    matches: list[dict[str, Any]] = []
    missing_timestamps = False
    for gateway, observation in relevant:
        observed_frameworks = observation.get("frameworks", [])
        if not isinstance(observed_frameworks, list) or any(
            not isinstance(fw, str) for fw in observed_frameworks
        ):
            continue
        frameworks = sorted(set(code.frameworks).intersection(observed_frameworks))
        if not frameworks:
            continue
        first = parse_timestamp(observation.get("first_seen"))
        last = parse_timestamp(observation.get("last_seen"))
        events = observation.get("timestamped_events", 0)
        if not first or not last or last < first or not isinstance(events, int) or events <= 0:
            missing_timestamps = True
            continue
        matches.append(
            {
                "gateway_finding_id": gateway.id,
                "gateway_resource": gateway.resource,
                "source": observation.get("source", gateway.metadata.get("runtime_source", {})),
                "scope": observation.get("scope", {}),
                "frameworks": frameworks,
                "events": events,
                "first_seen": to_iso(first),
                "last_seen": to_iso(last),
                "environment": observation.get("environment"),
                "identity_basis": observation["identity_basis"],
                "identity_assurance": observation.get("identity_assurance", "unspecified"),
                "environment_assurance": observation.get("environment_assurance", "unspecified"),
            }
        )
    return matches, missing_timestamps


def _observed_activity(code: Finding, matches: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize matching observations and record them as zero-weight evidence on ``code``."""
    # Worker completion/configuration order cannot change provenance.
    matches.sort(key=lambda match: json.dumps(match, sort_keys=True))
    first_seen = min(match["first_seen"] for match in matches)
    last_seen = max(match["last_seen"] for match in matches)
    environments = sorted({match["environment"] for match in matches if match["environment"]})
    production_events = sum(
        match["events"] for match in matches if match["environment"] in {"production", "prod"}
    )
    activity = {
        "status": "observed",
        "basis": "gateway-telemetry",
        "events": sum(match["events"] for match in matches),
        "frameworks": sorted({fw for match in matches for fw in match["frameworks"]}),
        "window": {"start": first_seen, "end": last_seen},
        "last_seen": last_seen,
        "environments": environments,
        "production_observed": production_events > 0,
        "production_events": production_events,
        "production_label_verified": False,
        "sources": matches,
        "event_counting": (
            "Source observations; distinct exports may overlap and are not deduplicated into unique requests."
        ),
        "limitations": (
            "Export-window telemetry and spoofable framework fingerprints, not an execution "
            "attestation. Production is an event label, not a verified deployment identity; "
            "generic log identities require an operator assertion."
        ),
    }
    code.add_evidence(
        Evidence(
            signal="runtime:gateway-observed",
            description=(
                f"Linked gateway recorded {activity['events']} timestamped request(s) with matching "
                f"framework fingerprints between {first_seen} and {last_seen}"
            ),
            weight=0.0,
            attributes={
                "gateway_finding_ids": sorted({match["gateway_finding_id"] for match in matches}),
                "frameworks": activity["frameworks"],
            },
        )
    )
    return activity
