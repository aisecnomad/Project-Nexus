"""Helpers shared by connectors to turn signature matches into findings."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from typing import Any

from shadowscan.models import Evidence, Finding, Kind
from shadowscan.signatures import Match, SignatureIndex
from shadowscan.utils.text import redact

TECH_CATEGORIES = {
    "framework",
    "protocol",
    "coding-agent",
    "platform",
    "cloud-service",
    "observability",
    "memory",
    "sandbox",
    "identity-app",
}

_SIGNAL_LABEL = {
    "dependency": "dependency",
    "import": "import",
    "code": "code pattern",
    "file": "config file",
    "env": "environment variable",
    "domain": "endpoint",
    "user_agent": "user agent",
    "image": "container image",
    "iac": "IaC resource",
    "name": "display name",
    "scope": "permission",
    "model": "model id",
    "secret": "credential",
    "client_id": "client id",
}


def describe_match(m: Match) -> str:
    label = _SIGNAL_LABEL.get(m.signal.type, m.signal.type)
    what = m.signal.description or m.signature.name
    return f"{label} matched {what}: {m.value}"


def apply_matches(
    finding: Finding,
    matches: Iterable[Match],
    location: str | None = None,
    snippet: str | None = None,
    max_evidence_per_signature: int = 12,
    weight_scale: float = 1.0,
) -> int:
    """Attach matches to a finding as evidence, tags, frameworks and capabilities.

    Returns the number of *agent indicator* matches, which callers use to
    promote a finding from ``framework-usage`` to ``agent``.
    """
    counts: dict[str, int] = finding.metadata.setdefault("_evidence_counts", {})
    indicators = 0
    for m in matches:
        sig = m.signature
        if sig.id == "identity-app.generic-ai-name":
            finding.add_tag("ai-name-hint")  # a hint, not a technology
        elif sig.category in TECH_CATEGORIES:
            finding.add_framework(sig.id)
        elif sig.category == "provider":
            finding.add_model_provider(sig.id)
        elif sig.category == "policy":
            finding.add_tag(sig.id)
        for cap in m.capabilities():
            finding.add_capability(cap)
        for t in sig.tags:
            finding.add_tag(t)
        if m.agent_indicator:
            indicators += 1
        key = f"{sig.id}|{m.signal.type}"
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > max_evidence_per_signature:
            continue
        value = m.value
        if m.signal.type == "secret":
            value = redact(value)
        loc = location
        if loc and m.line:
            loc = f"{loc}:{m.line}"
        finding.add_evidence(
            Evidence(
                signal=f"{m.signal.type}:{sig.id}",
                description=describe_match(m).replace(m.value, value) if m.value else describe_match(m),
                location=loc,
                snippet=snippet,
                weight=max(0.0, min(1.0, m.weight * weight_scale)),
                signature=sig.id,
                attributes={"category": sig.category, "value": value},
            )
        )
    finding.metadata["agent_indicators"] = finding.metadata.get("agent_indicators", 0) + indicators
    return indicators


def finalize(finding: Finding, index: SignatureIndex | None = None) -> Finding:
    """Recompute confidence, decide kind (agent vs framework-usage), tidy metadata."""
    finding.recompute_confidence()
    counts = finding.metadata.pop("_evidence_counts", None)
    if counts:
        finding.metadata["evidence_counts"] = counts
    indicators = finding.metadata.get("agent_indicators", 0)
    if finding.kind == Kind.FRAMEWORK_USAGE and indicators > 0:
        finding.kind = Kind.AGENT
    if index is not None:
        finding.metadata["technologies"] = [
            {"id": sid, "name": sig.name, "category": sig.category, "vendor": sig.vendor}
            for sid in finding.frameworks + finding.model_providers
            if (sig := index.get(sid)) is not None
        ]
    return finding


def name_matches(index: SignatureIndex, *texts: str | None) -> list[Match]:
    """Run display-name signatures over several strings (name, publisher, description)."""
    out: list[Match] = []
    seen: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in index.match_name(t):
            if m.signature_id in seen:
                continue
            seen.add(m.signature_id)
            out.append(m)
    return out


def scope_matches(index: SignatureIndex, scopes: Iterable[str]) -> list[Match]:
    out: list[Match] = []
    seen: set[tuple[str, str]] = set()
    for s in scopes:
        if not s:
            continue
        for m in index.match_scope(str(s)):
            key = (m.signature_id, m.value.lower())
            if key not in seen:
                seen.add(key)
                out.append(m)
    return out


def domain_matches(index: SignatureIndex, *urls: str | None) -> list[Match]:
    out: list[Match] = []
    seen: set[tuple[str, str]] = set()
    for u in urls:
        if not u:
            continue
        for m in index.match_domains_in_text(str(u)) if ("/" in u or " " in u) else index.match_domain(u):
            key = (m.signature_id, m.value)
            if key not in seen:
                seen.add(key)
                out.append(m)
    return out


def classify_permissions(index: SignatureIndex, finding: Finding, scopes: Iterable[str]) -> None:
    """Record scopes on the finding and tag privileged / data-access / llm-access classes."""
    unordered = isinstance(scopes, (set, frozenset))
    scopes = [str(s) for s in scopes if s]
    if unordered:
        # Sets depend on the process hash seed; keep reports reproducible.
        scopes.sort()
    for s in scopes:
        if s not in finding.permissions:
            finding.permissions.append(s)
    matches = scope_matches(index, scopes)
    apply_matches(finding, matches, weight_scale=0.5)


_PLACEHOLDER = re.compile(r"^(?:x{3,}|\*{3,}|<[^>]+>|\$\{[^}]+\}|your[_-]?[a-z_]*|changeme|redacted|placeholder|todo|null|none)$", re.IGNORECASE)


# Documentation and test fixtures use recognisable fake credentials. Real keys
# are random: they never contain long runs of one character, marker words or
# very low character diversity.
_PLACEHOLDER_MARKER = re.compile(
    r"(?i)(?:example|dummy|fake|placeholder|sample|redacted|changeme|your[_-]?(?:api[_-]?)?(?:key|token|secret)|x{6,}|\*{4,})"
)
_KNOWN_KEY_PREFIX = re.compile(
    r"^(?:sk-(?:ant-(?:api|admin)\d{2}-|proj-|svcacct-|admin-|or-v1-)?|hf_|AIza|xox[abposr]-|gh[pousr]_|github_pat_|gsk_|pplx-|r8_|fw_|nvapi-|AKIA|ASIA)"
)
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*[\"']?(.*?)[\"']?$")
_REPEATED_RUN = re.compile(r"(.)\1{11,}")


def _shannon_entropy(text: str) -> float:
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    candidate = value.strip()
    if _PLACEHOLDER.match(candidate):
        return True
    assignment = _ASSIGNMENT.match(candidate)
    if assignment:  # context-bound patterns capture NAME=value
        candidate = assignment.group(1).strip()
        if not candidate or _PLACEHOLDER.match(candidate):
            return True
    if _PLACEHOLDER_MARKER.search(candidate):
        return True
    body = _KNOWN_KEY_PREFIX.sub("", candidate, count=1)
    if body.lower().startswith(("test-", "test_")):
        body = body[5:]
    if _REPEATED_RUN.search(body):
        return True
    return len(body) >= 16 and _shannon_entropy(body) < 2.5


def merge_metadata(finding: Finding, **kwargs: Any) -> None:
    for k, v in kwargs.items():
        if v not in (None, "", [], {}):
            finding.metadata[k] = v


def blob_matches(index: SignatureIndex, text: str, *, secrets: bool = False) -> list[Match]:
    """Run code / domain / env / model signatures over an arbitrary text blob (e.g. a JSON export).

    Used by low-code, SaaS and cloud connectors to fingerprint definitions
    without duplicating product knowledge.
    """
    out: list[Match] = []
    seen: set[tuple[str, str, str]] = set()
    if not text:
        return out
    for m in [*index.match_code(text, None), *index.match_domains_in_text(text), *index.match_envs_in_text(text)] + (index.match_secrets(text) if secrets else []):
        if m.signature.category == "identity-app" and m.signal.type == "domain":
            continue
        key = (m.signature_id, m.signal.type, m.value[:60])
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
    return out


def model_matches(index: SignatureIndex, *models: str | None) -> list[Match]:
    out: list[Match] = []
    seen: set[str] = set()
    for model in models:
        if not model:
            continue
        for m in index.match_model(str(model)):
            if m.signature_id not in seen:
                seen.add(m.signature_id)
                out.append(m)
    return out
