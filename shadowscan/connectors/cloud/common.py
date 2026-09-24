"""Shared helpers for cloud connectors."""

from __future__ import annotations

import json
import re
from typing import Any

from shadowscan.connectors.common import apply_matches, blob_matches, finalize, looks_like_placeholder
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.text import redact

_SECRETISH = re.compile(r"(?i)(?:key|token|secret|password|passwd|credential|apikey|api_key)")


def string_list(value: Any, name: str, *, pattern: str | None = None) -> list[str] | None:
    """Coerce a list-typed connector setting; a bare string is one item, not its characters.

    ``--set regions=us-east-1`` reaches the connector as a string. Iterating it
    as a list silently produced a complete-looking scan of nothing.
    """
    if value is None:
        return None
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
        raise ValueError(f"{name} must be a string or a list of strings")
    cleaned = [item.strip() for item in items if item.strip()]
    if pattern is not None and any(not re.fullmatch(pattern, item) for item in cleaned):
        raise ValueError(f"{name} contains an invalid value")
    return cleaned or None


def cloud_finding(
    connector: str,
    provider: str,
    *,
    kind: Kind,
    title: str,
    resource: str | None,
    resource_type: str,
    account: str | None,
    region: str | None = None,
    owner: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
    surface: Surface = Surface.CLOUD,
) -> Finding:
    if not isinstance(resource, str) or not resource.strip():
        raise ValueError("cloud record is missing a nonempty resource identifier")
    return Finding(
        surface=surface,
        connector=connector,
        kind=kind,
        title=title,
        resource=resource,
        resource_type=resource_type,
        provider=provider,
        account=account,
        region=region,
        owner=owner,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def scan_env(index: SignatureIndex, finding: Finding, env: dict[str, Any] | None, location: str | None = None) -> None:
    """Match environment variable names against signatures and detect credentials in values.

    Values are never stored: only redacted previews of matched secrets.
    """
    if not env:
        return
    matched_names: list[str] = []
    for name, value in env.items():
        matches = index.match_env(str(name))
        if matches:
            matched_names.append(str(name))
            apply_matches(finding, matches, location=location)
        if isinstance(value, str) and value and not looks_like_placeholder(value) and not value.startswith(("${", "{{", "arn:", "projects/")):
            for m in index.match_secrets(value):
                finding.add_tag("plaintext-credential")
                finding.add_evidence(Evidence(signal=f"secret:{m.signature_id}", description=f"Plaintext {m.signal.description or m.signature.name} in environment variable {name}: {redact(m.value)}", location=location, weight=0.6, signature=m.signature_id))
                finding.add_model_provider(m.signature_id) if m.signature.category == "provider" else None
            is_secretish = _SECRETISH.search(str(name)) and len(value) >= 16 and not value.startswith(("http", "/", "@Microsoft.KeyVault", "{", "$"))
            provider_key = next((m for m in matches if m.signature.category == "provider"), None) if matches else None
            if is_secretish and provider_key:
                finding.add_tag("plaintext-credential")
                finding.add_evidence(Evidence(signal=f"secret:{provider_key.signature_id}", description=f"Plaintext value in provider credential variable {name}: {redact(value)}", location=location, weight=0.5, signature=provider_key.signature_id))
            elif is_secretish:
                finding.add_tag("secret-in-env")
    if matched_names:
        finding.metadata["env_matches"] = matched_names[:30]


def scan_blob(index: SignatureIndex, finding: Finding, obj: Any, location: str | None = None, weight_scale: float = 0.8) -> int:
    """Serialise an object and run text signatures over it."""
    text = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    return apply_matches(finding, blob_matches(index, text[:400_000]), location=location, weight_scale=weight_scale)


def scan_iam_actions(index: SignatureIndex, finding: Finding, actions: list[str], location: str | None = None) -> list[str]:
    """Classify IAM actions / roles; returns the LLM-related ones."""
    llm: list[str] = []
    for a in actions:
        for m in index.match_scope(a):
            apply_matches(finding, [m], location=location, weight_scale=0.6)
            if m.signature_id in {"policy.llm-access-scopes", "provider.aws-bedrock", "cloud.aws-bedrock-agents", "cloud.aws-other-ai", "provider.google-vertex-ai", "cloud.gcp-vertex-agent-engine", "provider.azure-openai", "cloud.azure-ai-foundry-agents", "provider.oci-generative-ai", "cloud.oci-generative-ai-agents"}:
                llm.append(a)
    for a in actions:
        if a not in finding.permissions:
            finding.permissions.append(a)
    return sorted(set(llm))


def done(finding: Finding, index: SignatureIndex, kind: Kind) -> Finding:
    finalize(finding, index)
    finding.kind = kind
    return finding


def name_hint(index: SignatureIndex, finding: Finding, *names: str | None) -> None:
    for n in names:
        if n:
            apply_matches(finding, index.match_name(str(n)), weight_scale=0.5)
