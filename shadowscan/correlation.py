"""Cross-surface correlation and gateway-to-code attribution.

``correlate`` links findings across surfaces by resource ids and normalised
names.  ``correlate_runtime`` conservatively attributes gateway telemetry to
static framework findings using only operator-configured exact caller/scope
bindings.  Gateway user agents are observations, not attestations: an
``observed`` result means the linked gateway recorded a timestamped request
bearing that framework fingerprint. ``correlate_lifecycle`` links endpoint
findings to running-process findings for the same tool on the same device.
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


# --------------------------------------------------------------------------
# Lifecycle corroboration: configured / installed → running

_LIFECYCLE_STATES: dict[tuple[Surface, Kind], str] = {
    (Surface.ENDPOINT, Kind.AGENT_CONFIG): "configured",
    (Surface.ENDPOINT, Kind.MCP_SERVER): "configured",
    (Surface.ENDPOINT, Kind.AI_APP): "installed",
    (Surface.ENDPOINT, Kind.LOCAL_MODEL): "installed",
    (Surface.RUNTIME, Kind.RUNTIME_PROCESS): "running",
}
_LIFECYCLE_ORDER = ("configured", "installed", "running")
_PACKAGE_VERSION = re.compile(r"(?<=.)@[^/@]*$")


def _device_key(value: str | None) -> str | None:
    """A host name compared case-insensitively and without its DNS domain."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text or REDACTED in text:
        return None
    if re.fullmatch(r"[\d.]+|[0-9a-f:]+", text):
        return text
    return text.split(".", 1)[0]


def _package_key(value: object) -> str | None:
    if not isinstance(value, str) or not value or value.startswith("-"):
        return None
    return _PACKAGE_VERSION.sub("", value.strip().lower()) or None


def _lifecycle_keys(f: Finding, device: str) -> set[tuple[str, str]]:
    """What a finding is about on its device: signature ids, and MCP server packages for MCP."""
    keys = {(device, sid) for sid in f.frameworks + f.model_providers if sid != "protocol.mcp"}
    if f.kind == Kind.RUNTIME_PROCESS:
        packages = f.metadata.get("mcp_packages")
        for name in packages if isinstance(packages, dict) else ():
            if (key := _package_key(name)) is not None:
                keys.add((device, f"mcp-package:{key}"))
    elif f.kind == Kind.MCP_SERVER:
        servers = f.metadata.get("servers")
        for server in servers if isinstance(servers, list) else ():
            if not isinstance(server, dict) or server.get("disabled"):
                continue
            for arg in server.get("args") or []:
                if (key := _package_key(arg)) is not None:
                    keys.add((device, f"mcp-package:{key}"))
    return keys


def correlate_lifecycle(findings: list[Finding]) -> None:
    """Link endpoint findings to processes of the same tool on the same device.

    A configured or installed tool with a running process on the same device
    is ``observed-running``. The link is recorded in ``metadata['lifecycle']``
    and as zero-weight evidence: corroboration changes neither confidence nor
    risk. Devices match by host name without its DNS domain; MCP
    configurations match a running MCP server only through the same package.
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        # Repeated calls replace earlier results.
        f.metadata.pop("lifecycle", None)
        f.evidence[:] = [ev for ev in f.evidence if ev.signal != "lifecycle:observed-running"]
        if _LIFECYCLE_STATES.get((f.surface, f.kind)) is None:
            continue
        device = _device_key(f.account)
        if device is None:
            continue
        for key in _lifecycle_keys(f, device):
            groups.setdefault(key, []).append(f)
    linked: dict[str, dict[str, Any]] = {}
    for (_, subject), members in groups.items():
        states = {_LIFECYCLE_STATES[(f.surface, f.kind)] for f in members}
        if "running" not in states or len(states) < 2 or len(members) > 50:
            continue
        running = [f for f in members if f.kind == Kind.RUNTIME_PROCESS]
        for f in members:
            entry = linked.setdefault(
                f.id, {"finding": f, "states": set(), "subjects": set(), "related": set()}
            )
            entry["states"].update(states)
            entry["subjects"].add(subject)
            entry["related"].update(o.id for o in members if o.id != f.id)
            if f.kind != Kind.RUNTIME_PROCESS:
                entry.setdefault("running", set()).update((o.owner or "", o.id) for o in running)
    for entry in linked.values():
        f = entry["finding"]
        lifecycle: dict[str, Any] = {
            "states": [s for s in _LIFECYCLE_ORDER if s in entry["states"]],
            "subjects": sorted(entry["subjects"]),
            "related": sorted(entry["related"])[:20],
        }
        if "running" in entry:
            same_user = sorted({fid for owner, fid in entry["running"] if owner and owner == f.owner})
            lifecycle["same_user"] = bool(same_user)
            f.add_tag("observed-running")
            f.add_evidence(
                Evidence(
                    signal="lifecycle:observed-running",
                    description=(
                        f"{len(entry['running'])} running-process finding(s) for the same tool on this device"
                        + (" and account" if same_user else "")
                    ),
                    weight=0.0,
                )
            )
        f.metadata["lifecycle"] = lifecycle
