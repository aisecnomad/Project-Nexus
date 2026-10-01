"""Helpers shared by connectors to turn signature matches into findings.

The engine also merges repeated observations of one finding through
:func:`merge_duplicate_metadata`, which knows the metadata keys connectors
emit that combine across observations instead of keeping the first value.

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

When a context-bound pattern captured an assignment (``NAME=value``,
``NAME: value``), only the value is judged, so a variable name such as
``TEST_API_KEY`` never marks a real key as a placeholder; an empty value is a
template.

Randomly generated keys practically never satisfy these rules (fewer than one
in ten thousand in simulation), and connectors report a placeholder as
low-weight ``example-credential`` evidence rather than dropping it silently,
so a rare misclassification remains visible to analysts.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable
from typing import Any

from shadowscan.config import ConfigValidationError, connector_boolean
from shadowscan.connectors.base import ConnectorError, _positive_limit
from shadowscan.models import Evidence, Finding, Kind, Surface
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


def config_boolean(value: Any, name: str) -> bool:
    """Require the native boolean produced by the configuration boundary."""
    if not isinstance(value, bool):
        raise ConnectorError(f"{name} must be a boolean (true or false)")
    try:
        return connector_boolean(value, name)
    except ConfigValidationError:
        raise ConnectorError(f"{name} must be a boolean (true or false)") from None


# Upper bound shared by every connector's ``max_pages`` setting.
MAX_PAGES = 1000


def max_pages_limit(value: Any) -> int:
    """Validate a connector's ``max_pages`` setting: a positive integer, capped at 1000.

    Booleans, fractions and values below 1 raise ConnectorError instead of
    silently becoming a one-page scan. Reaching the bound during collection
    is reported by the connector as incomplete coverage.
    """
    return min(_positive_limit(value, "max_pages"), MAX_PAGES)


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
    capabilities: bool = True,
    signature_capabilities: bool = True,
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
        if capabilities:
            # Static source analysis can retain library-wide features as
            # potential metadata while scoring only the matched code signal.
            for cap in m.capabilities() if signature_capabilities else m.signal.capabilities:
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
    """Finalize connector-verified indicators without reinterpreting evidence text.

    Source provenance, control flow and test exclusion belong to the code
    analyzer. Co-occurring snippets here cannot override that analysis.
    """
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


_PLACEHOLDER = re.compile(
    r"^(?:x{3,}|\*{3,}|<[^>]+>|\$\{[^}]+\}|your[_-]?[a-z_]*"
    r"|changeme|redacted|placeholder|todo|null|none)$",
    re.IGNORECASE,
)
_TEMPLATE_MARKER = re.compile(r"<[^<>\s]+>|\$\{[^{}]*\}|\{\{[^{}]*\}\}")
# Lowercase words that documentation uses where a real key would go.
_PLACEHOLDER_WORDS: tuple[str, ...] = (
    "replaceme",
    "replace",
    "placeholder",
    "changeme",
    "example",
    "sample",
    "dummy",
    "fake",
    "test",
    "insert",
    "paste",
    "here",
    "todo",
    "your",
    "redacted",
    "mock",
    "demo",
)
_FILL_RUN = re.compile(r"(?<![A-Za-z])(?:x{4,}|X{4,})(?![A-Za-z])|[*#?]{4,}")
_ALPHA_RUN = re.compile(r"[A-Za-z]+")
# Vendor prefixes such as sk-ant-api03- or lsv2_pt_ are not part of the body.
_SECRET_PREFIX = re.compile(r"^(?:[A-Za-z0-9]{1,8}[-_]){1,3}")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")
_MIN_ENTROPY_BODY = 8
# Context-bound secret patterns capture ``NAME=value`` / ``NAME: value``; only the value is judged.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*[\"']?(.*?)[\"']?$")


def _case_delimited(value: str, start: int, end: int) -> bool:
    """True when value[start:end] is its own token by separators or case changes."""
    left = (
        start == 0
        or not value[start - 1].isalpha()
        or (value[start - 1].islower() and value[start].isupper())
    )
    if not left:
        return False
    if end == len(value) or not value[end].isalpha():
        return True
    return (value[end - 1].islower() and value[end].isupper()) or (
        value[start:end].isupper() and value[end].islower()
    )


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
    continued = sum(
        1 for previous, current in zip(body, body[1:], strict=False) if abs(ord(current) - ord(previous)) <= 1
    )
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
    assignment = _ASSIGNMENT.match(value)
    if assignment:
        value = assignment.group(1).strip()
        if not value:
            return "template"
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


def blob_matches(index: SignatureIndex, text: str, *, secrets: bool = False) -> list[Match]:
    """Run code / domain / env / model signatures over an arbitrary text blob (e.g. a JSON export).

    Used by low-code, SaaS and cloud connectors to fingerprint definitions
    without duplicating product knowledge.
    """
    out: list[Match] = []
    seen: set[tuple[str, str, str]] = set()
    if not text:
        return out
    secret_matches = (
        [m for m in index.match_secrets(text) if not looks_like_placeholder(m.value)] if secrets else []
    )
    candidates = [
        *index.match_code(text, None),
        *index.match_domains_in_text(text),
        *index.match_envs_in_text(text),
        *secret_matches,
    ]
    for m in candidates:
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


# --------------------------------------------------------------- duplicate findings
# Metrics a gateway-surface caller finding (gateway.logs, and the CloudTrail and
# Vertex AI callers of cloud.aws and cloud.gcp) sums across distinct sources.
_RUNTIME_TOTALS = (
    "events",
    "records",
    "aggregate_records",
    "tool_known",
    "tool_requests",
    "tool_call_responses",
    "tokens_in",
    "tokens_out",
    "cost",
    "errors",
)
_RUNTIME_DISTRIBUTIONS = (
    "models",
    "providers",
    "hosts",
    "user_agents",
    "source_ips",
    "end_users",
    "teams",
    "operations",
    "schemas",
)
_RUNTIME_MERGE_NOTE = "Counts sum records across inputs; overlapping exports can represent the same requests."


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def unique_records(records: list[Any]) -> list[dict[str, Any]]:
    """Deduplicate nested observations while retaining their first provenance."""

    def key_for(value: Any) -> Any:
        if isinstance(value, dict):
            return ("dict", frozenset((key, key_for(item)) for key, item in value.items()))
        if isinstance(value, (list, tuple)):
            return (type(value).__name__, tuple(key_for(item) for item in value))
        if isinstance(value, (set, frozenset)):
            return ("set", frozenset(key_for(item) for item in value))
        # JSON numbers remain equivalent when exporters vary number syntax,
        # but booleans must not collide with Python's equal numeric values.
        if _is_number(value):
            return ("number", value)
        return (type(value).__name__, value)

    unique: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        key = key_for(record)
        if key not in seen:
            seen.add(key)
            unique.append(record)
    return unique


def _runtime_source_snapshot(finding: Finding) -> dict[str, Any]:
    metadata = finding.metadata
    observations = metadata.get("runtime_observations", [])
    digest = hashlib.sha256(json.dumps(observations, sort_keys=True, default=str).encode()).hexdigest()
    return {
        "source": metadata.get("runtime_source", {}),
        "window": {"first_seen": finding.first_seen, "last_seen": finding.last_seen},
        "observation_sha256": digest,
        "metrics": {
            key: metadata[key] for key in (*_RUNTIME_TOTALS, *_RUNTIME_DISTRIBUTIONS) if key in metadata
        },
    }


def _runtime_sources(finding: Finding) -> list[dict[str, Any]]:
    existing = finding.metadata.get("runtime_sources")
    return existing if isinstance(existing, list) else [_runtime_source_snapshot(finding)]


def _merge_runtime_observations(merged: Finding, duplicate: Finding) -> list[dict[str, Any]]:
    """Keep each input's observations alongside the source they were exported from.

    A merged gateway caller may have been exported from several inputs; the
    correlation report must not attribute every event to the first input.
    """
    observations = []
    for finding in (merged, duplicate):
        group = finding.metadata.get("runtime_observations", [])
        if not isinstance(group, list):
            continue
        for observation in group:
            if isinstance(observation, dict):
                entry = dict(observation)
                entry.setdefault("source", finding.metadata.get("runtime_source", {}))
                observations.append(entry)
    return unique_records(observations)


def _merge_runtime_sources(merged: Finding, sources: list[dict[str, Any]]) -> None:
    unique = unique_records(sources)
    merged.metadata["runtime_sources"] = unique
    for key in _RUNTIME_TOTALS:
        values = [source.get("metrics", {}).get(key) for source in unique]
        numbers = [value for value in values if _is_number(value)]
        if numbers:
            total = sum(numbers)
            merged.metadata[key] = round(total, 4) if key == "cost" else total
    for key in _RUNTIME_DISTRIBUTIONS:
        counts: dict[str, int | float] = {}
        for source in unique:
            distribution = source.get("metrics", {}).get(key)
            if isinstance(distribution, dict):
                for name, value in distribution.items():
                    if isinstance(name, str) and _is_number(value):
                        counts[name] = counts.get(name, 0) + value
        if counts:
            merged.metadata[key] = dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
    events = merged.metadata.get("events")
    if isinstance(events, int):
        merged.title = re.sub(r": \d+ requests\b", f": {events} requests", merged.title, count=1)
        identity_signal = "gateway:" + str(merged.metadata.get("caller_kind", ""))
        identity_evidence = [ev for ev in merged.evidence if ev.signal == identity_signal]
        if identity_evidence:
            primary = identity_evidence[0]
            primary.description = re.sub(
                r"^\d+ LLM request\(s\)",
                f"{events} LLM request(s)",
                primary.description,
            )
            merged.evidence = [ev for ev in merged.evidence if ev.signal != identity_signal or ev is primary]
    if len(unique) > 1:
        merged.metadata["runtime_merge_note"] = _RUNTIME_MERGE_NOTE


def merge_duplicate_metadata(merged: Finding, duplicate: Finding) -> None:
    """Fold the metadata of ``duplicate``, another observation of one finding, into ``merged``.

    The engine calls this after combining evidence and before widening the
    observation window, so each finding still carries its own window. The
    first observation's values take precedence, except for keys that combine:

    * ``variable_names`` becomes the sorted union of both lists;
    * ``runtime_observations`` keeps every input's observations, each tagged
      with the ``runtime_source`` it was exported from;
    * gateway-surface findings keep one snapshot per distinct source under
      ``runtime_sources`` and sum request, token and cost metrics over them.

    Gateway IDs include export source identity. Repeated scans of the same
    configured source are idempotent here; observations from distinct exports
    remain separate even if caller and scope match. No cross-source request
    deduplication is inferred from matching timestamps or caller names.
    """
    gateway = merged.surface == duplicate.surface == Surface.GATEWAY
    sources = _runtime_sources(merged) + _runtime_sources(duplicate) if gateway else []
    for key, value in duplicate.metadata.items():
        if key == "variable_names" and isinstance(value, list):
            existing = merged.metadata.get(key, [])
            if isinstance(existing, list):
                merged.metadata[key] = sorted(set(existing) | set(value))
        elif key == "runtime_observations" and isinstance(value, list):
            merged.metadata[key] = _merge_runtime_observations(merged, duplicate)
        else:
            merged.metadata.setdefault(key, value)
    if sources:
        _merge_runtime_sources(merged, sources)
