"""Shared helpers for cloud connectors."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Hashable, Iterable, Mapping
from typing import Any, TypeVar

from shadowscan.connectors.base import BaseConnector
from shadowscan.connectors.common import apply_matches, blob_matches, finalize, looks_like_placeholder
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match, SignatureIndex
from shadowscan.utils.text import redact

_SECRETISH = re.compile(r"(?i)(?:key|token|secret|password|passwd|credential|apikey|api_key)")
# References and templates name a secret elsewhere; they are not the secret.
_SECRET_REFERENCE_PREFIXES = ("${", "{{", "arn:", "projects/")
_NOT_PLAINTEXT_PREFIXES = ("http", "/", "@Microsoft.KeyVault", "{", "$")
# Scope signatures whose match makes an IAM action or role an LLM/agent grant.
LLM_SCOPE_SIGNATURES = frozenset(
    {
        "policy.llm-access-scopes",
        "provider.aws-bedrock",
        "cloud.aws-bedrock-agents",
        "cloud.aws-other-ai",
        "provider.google-vertex-ai",
        "cloud.gcp-vertex-agent-engine",
        "provider.azure-openai",
        "cloud.azure-ai-foundry-agents",
        "provider.oci-generative-ai",
        "cloud.oci-generative-ai-agents",
    }
)
# Malformed export or provider fields raise these while a record is analysed;
# the record is reported as invalid and the rest of the scan continues.
RECORD_ERRORS = (ValueError, TypeError, KeyError, AttributeError)

K = TypeVar("K", bound=Hashable)


class RecordDispatch:
    """Route exported records to a connector's ``_h_<kind>`` handlers.

    A handler method ``_h_bedrock_agent`` receives records whose ``_kind`` is
    ``bedrock-agent``. ``extra_kinds`` are further kinds that the connector's
    ``analyze`` accepts and handles itself (envelopes, events, related records).
    """

    def __init__(self, connector: BaseConnector, *extra_kinds: str) -> None:
        self.connector = connector
        self.handlers: dict[str, Callable[..., Any]] = {
            name[3:].replace("_", "-"): getattr(connector, name)
            for name in dir(type(connector))
            if name.startswith("_h_")
        }
        self.kinds = self.handlers.keys() | set(extra_kinds)

    def kind(self, rec: Any) -> str | None:
        """Count one record as examined; return its ``_kind``, or warn when unsupported."""
        self.connector.ctx.examined()
        kind = rec.get("_kind") if isinstance(rec, dict) else None
        if not isinstance(kind, str) or kind not in self.kinds:
            self.connector.ctx.warn(
                f"{self.connector.name}: record has missing, invalid, or unsupported _kind"
            )
            return None
        return kind

    def invalid(self, fields: str = "fields for its _kind") -> None:
        """Report a record whose fields do not fit its ``_kind`` (coverage incomplete)."""
        self.connector.ctx.warn(f"{self.connector.name}: record has invalid {fields}")


def aggregate_caller_event(
    callers: dict[K, dict[str, Any]],
    key: K,
    *,
    time: str | None,
    tally: Mapping[str, Hashable] | None = None,
    tally_present: Mapping[str, Hashable] | None = None,
    seed: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Fold one audit-log event into the caller aggregate for ``key`` and return it.

    An aggregate counts ``events``, keeps the ``first`` and ``last`` event
    time, and keeps one counter per name: ``tally`` counts every value, even a
    missing one, while ``tally_present`` counts only nonempty values. ``seed``
    adds provider fields when the caller's first event creates its aggregate.
    """
    tally = tally or {}
    tally_present = tally_present or {}
    agg = callers.get(key)
    if agg is None:
        counters: dict[str, dict[Hashable, int]] = {name: {} for name in (*tally, *tally_present)}
        agg = callers[key] = {"events": 0, "first": None, "last": None, **counters, **(seed or {})}
    agg["events"] += 1
    for name, value in tally.items():
        agg[name][value] = agg[name].get(value, 0) + 1
    for name, value in tally_present.items():
        if value:
            agg[name][value] = agg[name].get(value, 0) + 1
    if time:
        agg["first"] = time if not agg["first"] or time < agg["first"] else agg["first"]
        agg["last"] = time if not agg["last"] or time > agg["last"] else agg["last"]
    return agg


def string_list(value: Any, name: str, *, pattern: str | None = None) -> list[str] | None:
    """Normalize CLI/YAML list settings without iterating a scalar's characters."""
    if value is None:
        return None
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
        raise ValueError(f"{name} must be a string or a list of strings")
    cleaned = list(dict.fromkeys(item.strip() for item in items if item.strip()))
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


def first_tag(tags: Any, *keys: str) -> Any:
    """The first nonempty value among ``keys`` of a tag or label map (``a or b`` semantics)."""
    tags = tags or {}
    value = None
    for key in keys:
        value = tags.get(key)
        if value:
            return value
    return value


def scan_env(
    index: SignatureIndex,
    finding: Finding,
    env: dict[str, Any] | None,
    location: str | None = None,
) -> None:
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
        if isinstance(value, str) and value and not value.startswith(_SECRET_REFERENCE_PREFIXES):
            # Judge each matched credential rather than the surrounding value,
            # so a URL or note containing a marker word cannot hide a real key.
            for m in index.match_secrets(value):
                if looks_like_placeholder(m.value):
                    continue
                finding.add_tag("plaintext-credential")
                finding.add_evidence(
                    Evidence(
                        signal=f"secret:{m.signature_id}",
                        description=(
                            f"Plaintext {m.signal.description or m.signature.name} "
                            f"in environment variable {name}: {redact(m.value)}"
                        ),
                        location=location,
                        weight=0.6,
                        signature=m.signature_id,
                    )
                )
                if m.signature.category == "provider":
                    finding.add_model_provider(m.signature_id)
            is_secretish = (
                _SECRETISH.search(str(name))
                and len(value) >= 16
                and not value.startswith(_NOT_PLAINTEXT_PREFIXES)
                and not looks_like_placeholder(value)
            )
            provider_key = (
                next((m for m in matches if m.signature.category == "provider"), None) if matches else None
            )
            if is_secretish and provider_key:
                finding.add_tag("plaintext-credential")
                finding.add_evidence(
                    Evidence(
                        signal=f"secret:{provider_key.signature_id}",
                        description=(
                            f"Plaintext value in provider credential variable {name}: {redact(value)}"
                        ),
                        location=location,
                        weight=0.5,
                        signature=provider_key.signature_id,
                    )
                )
            elif is_secretish:
                finding.add_tag("secret-in-env")
    if matched_names:
        finding.metadata["env_matches"] = matched_names[:30]


def scan_blob(
    index: SignatureIndex,
    finding: Finding,
    obj: Any,
    location: str | None = None,
    weight_scale: float = 0.8,
) -> int:
    """Serialise an object and run text signatures over it."""
    text = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    matches = blob_matches(index, text[:400_000])
    return apply_matches(finding, matches, location=location, weight_scale=weight_scale)


def scan_iam_actions(
    index: SignatureIndex,
    finding: Finding,
    actions: list[str],
    location: str | None = None,
) -> list[str]:
    """Classify IAM actions / roles; returns the LLM-related ones."""
    llm: list[str] = []
    for a in actions:
        for m in index.match_scope(a):
            apply_matches(finding, [m], location=location, weight_scale=0.6)
            if m.signature_id in LLM_SCOPE_SIGNATURES:
                llm.append(a)
    for a in actions:
        if a not in finding.permissions:
            finding.permissions.append(a)
    return sorted(set(llm))


def credential_name_matches(index: SignatureIndex, name: str, keywords: Iterable[str]) -> list[Match] | None:
    """Signature matches for a stored secret's name, or None when it does not suggest an LLM credential.

    The name is matched as an environment variable (``prod/openai-api-key`` as
    ``PROD_OPENAI_API_KEY``); a provider keyword alone also qualifies it.
    """
    norm = "".join(ch if ch.isalnum() else "_" for ch in name).upper().strip("_")
    matches = index.match_env(norm)
    if not matches and not any(k in name.lower() for k in keywords):
        return None
    return matches


def done(finding: Finding, index: SignatureIndex, kind: Kind) -> Finding:
    finalize(finding, index)
    finding.kind = kind
    return finding


def name_hint(index: SignatureIndex, finding: Finding, *names: str | None) -> None:
    for n in names:
        if n:
            apply_matches(finding, index.match_name(str(n)), weight_scale=0.5)
