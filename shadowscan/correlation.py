"""Conservative attribution of gateway telemetry to static framework findings.

Only operator-configured, exact caller/scope bindings establish code identity.
Gateway user agents are observations, not attestations: an ``observed`` result
means the linked gateway recorded a timestamped request bearing that framework
fingerprint. It does not prove which library executed, agent task completion,
or continuing activity beyond the exported observation window.
"""

from __future__ import annotations

import json
from typing import Any

from shadowscan.models import Evidence, Finding, Surface
from shadowscan.utils.redaction import REDACTED
from shadowscan.utils.text import parse_timestamp, to_iso


def _usable_code_identity(code: Finding) -> bool:
    """Lossy report identities must never establish an exact workload binding."""
    return (
        isinstance(code.resource, str) and bool(code.resource) and REDACTED not in code.resource
        and all(value is None or (isinstance(value, str) and REDACTED not in value)
                for value in (code.provider, code.account, code.region))
    )


def correlate_runtime(findings: list[Finding]) -> None:
    """Attach runtime_activity metadata without increasing risk or confidence."""
    bound: dict[str, list[tuple[Finding, dict[str, Any]]]] = {}
    code_identities: dict[str, set[tuple[str | None, str | None, str | None, str]]] = {}
    for code in findings:
        if code.surface == Surface.CODE:
            code_identities.setdefault(code.resource, set()).add((code.provider, code.account, code.region, code.connector))
    for gateway in findings:
        if gateway.surface != Surface.GATEWAY:
            continue
        observations = gateway.metadata.get("runtime_observations", [])
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if (not isinstance(observation, dict)
                    or observation.get("identity_basis") != "configured-exact-caller-and-scope"
                    or observation.get("identity_assurance") not in ("operator-asserted", "provider-authenticated-field")):
                continue
            resources = observation.get("code_resources", [])
            if isinstance(resources, list):
                for resource in resources:
                    if isinstance(resource, str) and resource and REDACTED not in resource:
                        bound.setdefault(resource, []).append((gateway, observation))

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
        matches = []
        missing_timestamps = False
        for gateway, observation in relevant:
            observed_frameworks = observation.get("frameworks", [])
            if not isinstance(observed_frameworks, list) or any(not isinstance(fw, str) for fw in observed_frameworks):
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
            matches.append({
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
            })
        if matches:
            # Worker completion/configuration order cannot change provenance.
            matches.sort(key=lambda match: json.dumps(match, sort_keys=True))
            first_seen = min(match["first_seen"] for match in matches)
            last_seen = max(match["last_seen"] for match in matches)
            environments = sorted({match["environment"] for match in matches if match["environment"]})
            production_events = sum(match["events"] for match in matches if match["environment"] in {"production", "prod"})
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
                "event_counting": "Source observations; distinct exports may overlap and are not deduplicated into unique requests.",
                "limitations": "Export-window telemetry and spoofable framework fingerprints, not an execution attestation. Production is an event label, not a verified deployment identity; generic log identities require an operator assertion.",
            }
            code.add_evidence(Evidence(
                signal="runtime:gateway-observed",
                description=f"Linked gateway recorded {activity['events']} timestamped request(s) with matching framework fingerprints between {first_seen} and {last_seen}",
                weight=0.0,
                attributes={"gateway_finding_ids": sorted({match["gateway_finding_id"] for match in matches}), "frameworks": activity["frameworks"]},
            ))
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
                "limitations": "Absence in exported telemetry does not establish that the framework is inactive.",
            }
        code.metadata["runtime_activity"] = activity
