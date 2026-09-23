"""Shared logic for identity-provider connectors."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from shadowscan.connectors.common import apply_matches, classify_permissions, domain_matches, name_matches
from shadowscan.models import Evidence, Finding, Kind
from shadowscan.signatures import SignatureIndex

MACHINE_GRANT_TYPES = {"client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:device_code"}


def assess_app(
    index: SignatureIndex,
    finding: Finding,
    *,
    name: str | None,
    publisher: str | None = None,
    description: str | None = None,
    urls: Iterable[str | None] = (),
    scopes: Iterable[str] = (),
    client_id: str | None = None,
    grant_types: Iterable[str] = (),
    auth_method: str | None = None,
) -> None:
    """Apply name / domain / scope / client-id signatures to an OAuth app finding."""
    apply_matches(finding, name_matches(index, name, publisher, description))
    apply_matches(finding, domain_matches(index, *urls), weight_scale=0.8)
    if client_id:
        apply_matches(finding, index.match_client_id(client_id))
    classify_permissions(index, finding, scopes)
    gts = {str(g).lower() for g in grant_types if g}
    if gts & MACHINE_GRANT_TYPES:
        finding.add_tag("machine-identity")
        finding.add_evidence(
            Evidence(
                signal="oauth:grant-type",
                description=f"Non-interactive grant types: {', '.join(sorted(gts & MACHINE_GRANT_TYPES))}",
                weight=0.4,
            )
        )
        if "urn:ietf:params:oauth:grant-type:token-exchange" in gts:
            finding.add_tag("delegation")
            finding.add_capability("delegated-identity")
    if auth_method and auth_method.lower() in {"private_key_jwt", "client_secret_jwt", "client_secret_post", "client_secret_basic"}:
        finding.metadata["token_endpoint_auth_method"] = auth_method


def identity_kind_for(*, user_consented: bool, machine: bool) -> Kind:
    if machine and not user_consented:
        return Kind.SERVICE_IDENTITY
    return Kind.OAUTH_GRANT


def summarize_scopes(scopes: Iterable[str], limit: int = 25) -> list[str]:
    out = sorted({str(s) for s in scopes if s})
    return out[:limit] + ([f"... +{len(out) - limit} more"] if len(out) > limit else [])


def app_identity_summary(rec: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: rec[k] for k in keys if k in rec and rec[k] not in (None, "", [], {})}
