"""Helpers shared by connectors to turn signature matches into findings.

Placeholder credentials
-----------------------
A credential-looking value is treated as a documentation placeholder, not a
live secret, when :func:`placeholder_reason` finds one of:

* a template marker anywhere in the value (``<...>``, ``${...}``, ``{{...}}``);
* a placeholder word such as REPLACE, REPLACE_ME, YOUR, EXAMPLE, SAMPLE,
  DUMMY, FAKE, TEST, PLACEHOLDER, CHANGEME, INSERT, PASTE, HERE or TODO,
  case-insensitive, delimited by ``_ - .`` or by a case boundary; a fill run
  such as ``xxxx`` counts as a word;
* a low-entropy body: after the provider prefix the value is one or two
  repeated characters, or at least half of its characters continue a run of
  the same or adjacent characters (``0000``, ``1234567890``, ``abcdef``).

Randomly generated keys practically never satisfy these rules (fewer than one
in ten thousand in simulation), and connectors report a placeholder as
low-weight ``example-credential`` evidence rather than dropping it silently,
so a rare misclassification remains visible to analysts.
"""

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
_TEMPLATE_MARKER = re.compile(r"<[^<>\s]+>|\$\{[^{}]*\}|\{\{[^{}]*\}\}")
# Lowercase words that documentation uses where a real key would go.
_PLACEHOLDER_WORDS: tuple[str, ...] = (
    "replaceme", "replace", "placeholder", "changeme", "example", "sample", "dummy", "fake",
    "test", "insert", "paste", "here", "todo", "your", "redacted", "mock", "demo",
)
_FILL_RUN = re.compile(r"(?<![A-Za-z])(?:x{4,}|X{4,})(?![A-Za-z])|[*#?]{4,}")
_ALPHA_RUN = re.compile(r"[A-Za-z]+")
# Vendor prefixes such as sk-ant-api03- or lsv2_pt_ are not part of the body.
_SECRET_PREFIX = re.compile(r"^(?:[A-Za-z0-9]{1,8}[-_]){1,3}")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")
_MIN_ENTROPY_BODY = 8


def _case_delimited(value: str, start: int, end: int) -> bool:
    """True when value[start:end] is its own token by separators or case changes."""
    left = start == 0 or not value[start - 1].isalpha() or (value[start - 1].islower() and value[start].isupper())
    if not left:
        return False
    if end == len(value) or not value[end].isalpha():
        return True
    return (value[end - 1].islower() and value[end].isupper()) or (value[start:end].isupper() and value[end].islower())


def _placeholder_word(value: str) -> bool:
    for run in _ALPHA_RUN.finditer(value):
        word = run.group(0).lower()
        if word in _PLACEHOLDER_WORDS:
            return True
        if len(word) >= 6 and any(word.startswith(w) or word.endswith(w) for w in _PLACEHOLDER_WORDS):
            return True
    lower = value.lower()
    for word in _PLACEHOLDER_WORDS:
        start = lower.find(word)
        while start >= 0:
            if _case_delimited(value, start, start + len(word)):
                return True
            start = lower.find(word, start + 1)
    return False


def _low_entropy_body(value: str) -> bool:
    body = _NON_ALNUM.sub("", _SECRET_PREFIX.sub("", value, count=1))
    if len(body) < _MIN_ENTROPY_BODY:
        return False
    if len(set(body)) <= 2:
        return True
    continued = sum(1 for previous, current in zip(body, body[1:], strict=False) if abs(ord(current) - ord(previous)) <= 1)
    return continued / (len(body) - 1) >= 0.5


def placeholder_reason(value: str) -> str | None:
    """Explain why a credential-looking value is a documentation placeholder, or None.

    The rules are described in the module docstring. The returned reason is a
    short machine-readable label ("template", "placeholder-word",
    "low-entropy") suitable for evidence attributes.
    """
    value = value.strip()
    if not value:
        return None
    if _PLACEHOLDER.match(value) or _TEMPLATE_MARKER.search(value):
        return "template"
    if _FILL_RUN.search(value) or _placeholder_word(value):
        return "placeholder-word"
    if _low_entropy_body(value):
        return "low-entropy"
    return None


def looks_like_placeholder(value: str) -> bool:
    """True when a credential-looking value is a documentation placeholder, not a live secret."""
    return placeholder_reason(value) is not None


def cap_confidence(finding: Finding, maximum: float) -> None:
    """Scale evidence weights so the noisy-OR confidence does not exceed ``maximum``.

    The cap is written into the evidence weights themselves. Any later
    recomputation (engine merging, report import) therefore reproduces the
    capped value instead of restoring a saturated one.
    """
    finding.recompute_confidence()
    if not finding.evidence or finding.confidence <= maximum:
        return
    low, high = 0.0, 1.0
    for _ in range(40):
        mid = (low + high) / 2
        p_none = 1.0
        for ev in finding.evidence:
            p_none *= 1.0 - max(0.0, min(1.0, ev.weight * mid))
        if 1.0 - p_none > maximum:
            high = mid
        else:
            low = mid
    for ev in finding.evidence:
        # Floor rather than round so the stored weights never exceed the bound.
        ev.weight = math.floor(max(0.0, min(1.0, ev.weight * low)) * 10_000) / 10_000
    finding.recompute_confidence()


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
    secret_matches = [m for m in index.match_secrets(text) if not looks_like_placeholder(m.value)] if secrets else []
    for m in [*index.match_code(text, None), *index.match_domains_in_text(text), *index.match_envs_in_text(text), *secret_matches]:
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
