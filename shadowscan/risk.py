"""Explainable risk scoring for findings.

The score is an additive model of *what the thing is*, *what it can do*, *what
it can reach* and *how it is governed*, scaled by how sure we are that it is an
agent at all. Every contribution is recorded as a :class:`RiskFactor` so the
report can say *why* something is critical.

Scores map to levels: >=75 critical, >=50 high, >=25 medium, >0 low.

Factors always add up to the reported score: confidence scaling and the 0-100
bounds appear as explicit factors. ``danger_score`` excludes governance
factors (inventory registration and ownership), so triage can rank what an
agent can do separately from whether anyone approved it. A
:class:`RiskPolicy` overrides weights and can base the level on danger alone.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from shadowscan.models import Finding, Kind, Risk, RiskFactor, RiskLevel
from shadowscan.signatures import SignatureIndex

KIND_BASE: dict[Kind, int] = {
    Kind.AGENT: 15,
    Kind.MCP_SERVER: 15,
    Kind.AGENT_CONFIG: 10,
    Kind.WORKFLOW: 10,
    Kind.BOT_APP: 10,
    Kind.OAUTH_GRANT: 10,
    Kind.SERVICE_IDENTITY: 10,
    Kind.IAM_GRANT: 10,
    Kind.GATEWAY_CALLER: 10,
    Kind.CLOUD_RESOURCE: 5,
    Kind.FRAMEWORK_USAGE: 5,
    Kind.SECRET: 30,
    Kind.TOKEN: 5,
    Kind.INFRA: 10,
}

CAPABILITY_WEIGHTS: dict[str, tuple[int, str]] = {
    "code-exec": (15, "can execute code or shell commands"),
    "autonomous": (10, "runs without a human in the loop"),
    "saas-actions": (10, "performs write actions in SaaS / business systems"),
    "data-access": (10, "reads or writes files and databases directly (exfiltration / tampering surface)"),
    "browsing": (5, "has live web access (prompt-injection surface)"),
    "memory": (5, "persists memory / state across sessions"),
    "multi-agent": (5, "orchestrates or delegates to other agents"),
    "delegated-identity": (5, "acts with delegated / on-behalf-of identity"),
    "tool-use": (5, "calls tools / functions"),
    "rag": (3, "retrieves internal documents"),
}

TAG_WEIGHTS: dict[str, tuple[int, str]] = {
    "policy.privileged-scopes": (20, "holds privileged / administrative permissions"),
    "policy.data-access-scopes": (10, "holds broad data-read permissions (mail, files, chat, repos)"),
    "policy.llm-access-scopes": (5, "holds LLM / agent service permissions"),
    "hardcoded-credential": (25, "credential hard-coded in source"),
    "plaintext-credential": (25, "plaintext credential in environment / configuration"),
    "inline-secrets": (15, "secrets inline in MCP configuration"),
    "secret-in-env": (10, "secret-looking values in environment variables"),
    "unmasked-ci-variable": (10, "CI variable holding a provider key is not masked"),
    "ci-credentials": (5, "provider credentials available to CI pipelines"),
    "no-authentication": (15, "no end-user authentication configured"),
    "no-auth-declared": (10, "agent card declares no security scheme"),
    "iam-auth-only": (0, "IAM-only authorisation"),
    "public-ingress": (10, "publicly reachable ingress"),
    "public-network": (5, "public network access enabled"),
    "public-principal": (20, "granted to allUsers / allAuthenticatedUsers"),
    "api-key-auth-enabled": (5, "static API-key authentication enabled"),
    "no-guardrail": (5, "no guardrail configured"),
    "no-content-moderation": (5, "no content moderation configured"),
    "no-invocation-logging": (5, "model invocations are not logged"),
    "no-diagnostic-logging": (5, "no diagnostic / request logging"),
    "tracing-disabled": (3, "tracing disabled"),
    "wildcard-permissions": (15, "wildcard IAM permissions"),
    "all-repositories": (5, "installed on all repositories"),
    "write-access": (5, "write access to source / pull requests"),
    "always-on": (5, "24x7 activity pattern"),
    "scheduled": (5, "runs on a schedule"),
    "event-triggered": (3, "runs on events / webhooks"),
    "long-lived-credentials": (5, "long-lived static credentials (IAM user)"),
    "user-managed-keys": (10, "user-managed service-account keys"),
    "client-secret": (5, "app registration uses client secrets"),
    "unrestricted-api-key": (15, "API key without API restrictions"),
    "anonymous-client": (5, "anonymous OAuth client"),
    "app-only-permissions": (5, "application (app-only) permissions"),
    "self-authorisable": (5, "any user can self-authorise the app"),
    "user-owned-integration": (5, "integration owned by an individual user"),
    "not-directory-approved": (5, "app not approved in the app directory"),
    "no-end-user-attribution": (5, "LLM calls cannot be attributed to an end user"),
    "delegation": (3, "token delegation / actor chain present"),
    "agent-claims": (3, "token carries agent-related claims"),
    "identity:delegated-agent": (10, "token is a delegated agent identity"),
    "identity:service": (5, "token is a service identity"),
    "token-hygiene": (5, "token hygiene issue (lifetime / algorithm)"),
    "meeting-bot": (10, "meeting bot captures conversations"),
    "automation": (5, "automation platform executes actions across SaaS"),
    "agent-platform": (5, "hosted agent platform"),
    "assistant": (3, "general-purpose assistant receives enterprise data"),
    "coding": (5, "acts on source code"),
    "custom-app": (3, "custom (non-store) app"),
    "bot-user": (3, "bot user present in workspace"),
    "managed-secret": (0, "credential kept in a managed secret store"),
    "pending-request": (0, "install requested but not approved"),
    "disabled": (-10, "disabled"),
    "inactive": (-10, "inactive"),
    "suspended": (-10, "suspended"),
    "expired": (-5, "expired"),
    "asks-user": (-3, "asks the user before acting"),
    "test-code-only": (-10, "evidence found only in test or fixture code"),
}

PROVIDER_WEIGHTS: dict[str, tuple[int, str]] = {
    "provider.google-gemini": (5, "uses the consumer Gemini API (API keys outside cloud IAM)"),
    "provider.openrouter": (10, "routes prompts through a third-party model aggregator"),
    "provider.deepseek": (10, "sends data to DeepSeek's hosted API"),
    "provider.openai-compatible": (5, "custom OpenAI-compatible endpoint (unknown host)"),
    "provider.together": (3, "third-party model host"),
    "provider.fireworks": (3, "third-party model host"),
    "provider.groq": (3, "third-party model host"),
    "provider.perplexity": (5, "web-connected answer engine"),
    "provider.huggingface": (3, "third-party inference host"),
    "provider.ollama": (-3, "local / self-hosted inference"),
    "provider.vllm": (-3, "self-hosted inference"),
}



GOVERNANCE_WEIGHTS: dict[str, int] = {"shadow": 25, "registered": -10, "no-owner": 10}
GOVERNANCE_FACTORS = frozenset(GOVERNANCE_WEIGHTS)
RISK_BASES = frozenset({"combined", "danger"})
_WEIGHT_GROUPS = ("kinds", "capabilities", "tags", "providers", "governance")
_KEY_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,99}\Z")


@dataclass(frozen=True, slots=True)
class RiskPolicy:
    """Weights used by :func:`assess`; defaults reproduce the built-in model."""

    kinds: Mapping[Kind, int] = field(default_factory=lambda: dict(KIND_BASE))
    capabilities: Mapping[str, tuple[int, str]] = field(default_factory=lambda: dict(CAPABILITY_WEIGHTS))
    tags: Mapping[str, tuple[int, str]] = field(default_factory=lambda: dict(TAG_WEIGHTS))
    providers: Mapping[str, tuple[int, str]] = field(default_factory=lambda: dict(PROVIDER_WEIGHTS))
    governance: Mapping[str, int] = field(default_factory=lambda: dict(GOVERNANCE_WEIGHTS))
    basis: str = "combined"

    @classmethod
    def from_options(cls, weights: Mapping[str, Any] | None = None, basis: str = "combined") -> RiskPolicy:
        """Validate ``options.risk_weights`` / ``options.risk_basis``; raise ValueError on any problem."""
        if not isinstance(basis, str) or basis not in RISK_BASES:
            raise ValueError("risk_basis must be combined or danger")
        weights = {} if weights is None else weights
        if not isinstance(weights, Mapping):
            raise ValueError("risk_weights must be a mapping")
        unknown = set(weights) - set(_WEIGHT_GROUPS)
        if unknown:
            raise ValueError(f"risk_weights has unknown groups: {', '.join(sorted(map(str, unknown)))}")

        def group(name: str) -> dict[str, int]:
            values = weights.get(name)
            values = {} if values is None else values
            if not isinstance(values, Mapping):
                raise ValueError(f"risk_weights.{name} must be a mapping")
            out: dict[str, int] = {}
            for key, value in values.items():
                if not isinstance(key, str) or not _KEY_RE.match(key):
                    raise ValueError(f"risk_weights.{name} has an invalid key")
                if type(value) is not int or not -100 <= value <= 100:
                    raise ValueError(f"risk_weights.{name}.{key} must be an integer between -100 and 100")
                out[key] = value
            return out

        kinds = dict(KIND_BASE)
        for key, value in group("kinds").items():
            try:
                kinds[Kind(key)] = value
            except ValueError:
                raise ValueError(f"risk_weights.kinds.{key} is not a finding kind") from None
        governance = dict(GOVERNANCE_WEIGHTS)
        for key, value in group("governance").items():
            if key not in GOVERNANCE_WEIGHTS:
                raise ValueError(f"risk_weights.governance.{key} must be one of shadow, registered, no-owner")
            governance[key] = value

        def described(defaults: Mapping[str, tuple[int, str]], overrides: dict[str, int], noun: str) -> dict[str, tuple[int, str]]:
            merged = dict(defaults)
            for key, value in overrides.items():
                merged[key] = (value, defaults[key][1] if key in defaults else f"{noun} {key}")
            return merged

        return cls(
            kinds=kinds,
            capabilities=described(CAPABILITY_WEIGHTS, group("capabilities"), "capability"),
            tags=described(TAG_WEIGHTS, group("tags"), "tag"),
            providers=described(PROVIDER_WEIGHTS, group("providers"), "provider"),
            governance=governance,
            basis=basis,
        )


DEFAULT_POLICY = RiskPolicy()


def _as_int(value: Any, default: int = 0) -> int:
    """Coerce a loosely typed metadata value to an int, or return ``default``.

    Metadata can come from a loaded report, an incremental cache entry or a
    third-party plugin, so scoring must never abort on its shape. Booleans are
    flags rather than counts, and non-finite floats have no integer value.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else default
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _records(value: Any) -> list[dict[str, Any]]:
    """Return the object-shaped entries of a list-like metadata value."""
    if isinstance(value, (list, tuple)):
        return [entry for entry in value if isinstance(entry, dict)]
    return []


def _strings(values: Any) -> list[str]:
    """Return the string items of a list-like field, ignoring any other shape."""
    if isinstance(values, (list, tuple)):
        return [value for value in values if isinstance(value, str)]
    return []


def assess(
    finding: Finding, index: SignatureIndex | None = None, inventory_present: bool = False,
    policy: RiskPolicy | None = None,
) -> Risk:
    """Score one finding, recording every contribution as a :class:`RiskFactor`.

    Scoring is total: a field or metadata value of an unexpected shape (from a
    loaded report, an incremental cache entry or a plugin) contributes nothing
    instead of aborting the scan, and well-formed input scores exactly as
    documented in the module docstring. ``policy`` overrides the built-in
    weights (``options.risk_weights``) and the level basis (``options.risk_basis``).
    """
    policy = policy or DEFAULT_POLICY
    factors: list[RiskFactor] = []
    raw = policy.kinds.get(finding.kind, 5)
    factors.append(RiskFactor("kind", f"{finding.kind.value} finding", raw))
    # Governance factors describe approval and ownership, not capability. Under
    # the "danger" basis they are reported with zero weight.
    governance_scale = 0 if policy.basis == "danger" else 1

    if inventory_present:
        if finding.shadow:
            factors.append(RiskFactor("shadow", "not present in the sanctioned agent inventory", policy.governance["shadow"] * governance_scale))
        elif finding.shadow is False:
            factors.append(RiskFactor("registered", f"registered as {finding.registry_match}", policy.governance["registered"] * governance_scale))
    if not finding.owner:
        factors.append(RiskFactor("no-owner", "no identifiable owner", policy.governance["no-owner"] * governance_scale))

    seen_caps = set()
    for cap in _strings(finding.capabilities):
        if cap in policy.capabilities and cap not in seen_caps:
            seen_caps.add(cap)
            w, d = policy.capabilities[cap]
            factors.append(RiskFactor(f"capability:{cap}", d, w))

    for tag in _strings(finding.tags):
        if tag in policy.tags:
            w, d = policy.tags[tag]
            if w:
                factors.append(RiskFactor(f"tag:{tag}", d, w))

    for pid in _strings(finding.model_providers):
        if pid in policy.providers:
            w, d = policy.providers[pid]
            factors.append(RiskFactor(f"provider:{pid}", d, w))

    if index is not None:
        notes = []
        for sid in _strings(finding.frameworks) + _strings(finding.model_providers):
            sig = index.get(sid)
            if sig and sig.risk_notes:
                notes.extend(sig.risk_notes)
        if notes:
            factors.append(RiskFactor("vendor-notes", "; ".join(dict.fromkeys(notes))[:300], 5))

    metadata: dict[str, Any] = finding.metadata if isinstance(finding.metadata, dict) else {}
    if finding.kind == Kind.SECRET:
        count = _as_int(metadata.get("count", 1), 1)
        if count > 1:
            factors.append(RiskFactor("multiple-secrets", f"{count} credentials in one place", 5))
    if finding.kind == Kind.MCP_SERVER:
        servers = _records(metadata.get("servers"))
        if any(s.get("transport") == "stdio" for s in servers):
            factors.append(RiskFactor("mcp-stdio", "local stdio MCP servers run with the user's full privileges", 5))
        if any(s.get("auto_approve") for s in servers):
            factors.append(RiskFactor("mcp-auto-approve", "MCP tools auto-approved without confirmation", 10))
        if any(s.get("url") and str(s.get("url")).startswith("http://") for s in servers):
            factors.append(RiskFactor("mcp-plain-http", "remote MCP server over plain HTTP", 10))
    if finding.kind == Kind.AGENT_CONFIG:
        definitions = metadata.get("agent_definitions")
        n = len(definitions) if isinstance(definitions, (list, tuple)) else 0
        if n:
            factors.append(RiskFactor("sub-agents", f"{n} sub-agent definition(s)", min(10, 3 * n)))
    if finding.kind == Kind.GATEWAY_CALLER:
        events = _as_int(metadata.get("events"), 0)
        if events >= 10_000:
            factors.append(RiskFactor("volume", f"very high call volume ({events})", 10))
        elif events >= 1_000:
            factors.append(RiskFactor("volume", f"high call volume ({events})", 5))
    if finding.kind in {Kind.OAUTH_GRANT, Kind.BOT_APP}:
        users = _as_int(
            metadata.get("user_count") or metadata.get("consenting_users") or metadata.get("users") or metadata.get("install_count") or 0,
            0,
        )
        if users >= 100:
            factors.append(RiskFactor("blast-radius", f"{users} users / installations", 10))
        elif users >= 10:
            factors.append(RiskFactor("blast-radius", f"{users} users / installations", 5))

    total = sum(f.weight for f in factors)
    danger_total = sum(f.weight for f in factors if f.id not in GOVERNANCE_FACTORS)
    # scale by confidence that this is really an agent / agent enabler
    scale = 0.6 + 0.4 * max(0.0, min(1.0, finding.confidence))
    scaled = int(round(total * scale))
    score = max(0, min(100, scaled))
    if scale < 1.0:
        # Scaling lowers a positive subtotal. A subtotal at or below zero is
        # already floored at 0, so the adjustment must never read as added risk.
        adjustment = min(0, scaled - total)
        factors.append(RiskFactor(
            "confidence-scaling",
            f"score multiplied by {scale:.2f} because confidence is {finding.confidence:.2f}; this only ever lowers risk",
            adjustment,
        ))
    else:
        adjustment = 0
    explained = total + adjustment
    if score != explained:
        # Keep the explanation exact: listed factors always sum to the score.
        factors.append(RiskFactor("bounds", "score floored at 0" if explained < 0 else "score capped at 100", score - explained))
    danger_score = max(0, min(100, int(round(danger_total * scale))))
    return Risk(score=score, level=RiskLevel.from_score(score), factors=factors, danger_score=danger_score)
