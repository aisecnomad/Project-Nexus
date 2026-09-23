"""Conservative attribution of gateway telemetry to static framework findings.

Only operator-configured, exact caller/scope bindings establish code identity.
Gateway user agents are observations, not attestations: an ``observed`` result
means the linked gateway recorded a timestamped request bearing that framework
fingerprint. It does not prove which library executed, agent task completion,
or continuing activity beyond the exported observation window.
"""

from __future__ import annotations

from typing import Any

from shadowscan.models import Evidence, Finding, Surface
from shadowscan.utils.text import parse_timestamp, to_iso


def correlate_runtime(findings: list[Finding]) -> None:
    """Attach runtime_activity metadata without increasing risk or confidence."""
    bound: dict[str, list[tuple[Finding, dict[str, Any]]]] = {}
    code_identities: dict[str, set[tuple[str | None, str | None, str]]] = {}
    for code in findings:
        if code.surface == Surface.CODE:
            code_identities.setdefault(code.resource, set()).add((code.provider, code.account, code.connector))
    for gateway in findings:
        if gateway.surface != Surface.GATEWAY:
            continue
        observations = gateway.metadata.get("runtime_observations", [])
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if (not isinstance(observation, dict)
                    or observation.get("identity_basis") != "configured-exact-caller-and-scope"
                    or observation.get("identity_assurance") == "unverified"):
                continue
            resources = observation.get("code_resources", [])
            if isinstance(resources, list):
                for resource in resources:
                    if isinstance(resource, str):
                        bound.setdefault(resource, []).append((gateway, observation))

    for code in findings:
        if code.surface != Surface.CODE or not code.frameworks:
            continue
        # Repeated calls must replace earlier results, including after cache use.
        code.evidence[:] = [ev for ev in code.evidence if ev.signal != "runtime:gateway-observed"]
        ambiguous = len(code_identities.get(code.resource, set())) > 1
        relevant = [] if ambiguous else bound.get(code.resource, [])
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
                "limitations": "Export-window telemetry and spoofable framework fingerprints, not an execution attestation. Production is an event label, not a verified deployment identity; generic log identities require an operator assertion.",
            }
            code.add_evidence(Evidence(
                signal="runtime:gateway-observed",
                description=f"Linked gateway recorded {activity['events']} timestamped request(s) with matching framework fingerprints between {first_seen} and {last_seen}",
                weight=0.0,
                attributes={"gateway_finding_ids": sorted({match["gateway_finding_id"] for match in matches}), "frameworks": activity["frameworks"]},
            ))
        else:
            activity = {
                "status": "unknown" if not relevant or missing_timestamps else "unobserved",
                "reason": "ambiguous-code-resource" if ambiguous else "no-trusted-workload-binding" if not relevant else "missing-event-timestamps" if missing_timestamps else "no-matching-framework-in-linked-telemetry",
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
