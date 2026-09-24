"""Helpers shared by connectors to turn signature matches into findings."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

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

_FUNCTION_CALL_BRANCH = re.compile(r"\b(?P<item>[A-Za-z_]\w*)\.type\s*(?:===|==)\s*['\"]function_call['\"]")
_NAMED_TOOL_LOOKUP = re.compile(r"(?:\[\s*|\.get\(\s*)(?P<item>[A-Za-z_]\w*)\.name\s*(?:\]|\))\s*\(")
_FUNCTION_CALL_RESULT = re.compile(r"\b[A-Za-z_]\w*\s*=\s*(?:await\s+)?[A-Za-z_]\w*\(\s*(?P<item>[A-Za-z_]\w*)\.arguments\s*\)")


def _has_responses_tool_loop(finding: Finding) -> bool:
    """Recognise a model call, response branch and named tool dispatch in one file.

    An SDK import, a ``tools=...`` argument or a branch alone does not establish
    an agent. Matching the same loop variable in the branch and tool lookup also
    avoids joining unrelated examples in a large project. Source literals and
    comments are filtered by the code scanner before evidence reaches here.
    """
    if finding.surface != Surface.CODE or finding.resource_type != "project":
        return False

    requests: dict[str, set[int]] = {}
    branches: dict[str, set[str]] = {}
    lookups: dict[str, set[str]] = {}
    direct_results: dict[str, set[str]] = {}
    tools_arguments: dict[str, set[int]] = {}
    for evidence in finding.evidence:
        if not evidence.signal.startswith("code:") or not evidence.location:
            continue
        path, sep, line = evidence.location.rpartition(":")
        if not sep or not line.isdecimal():
            continue
        value = evidence.attributes.get("value")
        if not isinstance(value, str):
            continue
        if evidence.signature == "provider.openai" and "responses.create(" in value:
            requests.setdefault(path, set()).add(int(line))
        elif evidence.signature == "heuristic.function-call-branch":
            match = _FUNCTION_CALL_BRANCH.search(value)
            if match:
                branches.setdefault(path, set()).add(match["item"])
        elif evidence.signature == "heuristic.named-tool-lookup":
            match = _NAMED_TOOL_LOOKUP.search(value)
            if match:
                lookups.setdefault(path, set()).add(match["item"])
        elif evidence.signature == "heuristic.function-call-result":
            match = _FUNCTION_CALL_RESULT.search(value)
            if match:
                direct_results.setdefault(path, set()).add(match["item"])
        elif evidence.signature == "heuristic.tool-use" and re.search(r"\btools\s*=", value):
            tools_arguments.setdefault(path, set()).add(int(line))
    for path, request_lines in requests.items():
        branch_items = branches.get(path, set())
        if branch_items & lookups.get(path, set()):
            return True
        # A direct named handler such as ``answer = lookup(item.arguments)``
        # does not index a registry. Require tools on the nearby model request
        # before treating this generic function call as model-directed dispatch.
        if branch_items & direct_results.get(path, set()) and any(
            0 <= tool_line - request_line <= 20
            for request_line in request_lines
            for tool_line in tools_arguments.get(path, set())
        ):
            return True
    return False

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
    if finding.kind == Kind.FRAMEWORK_USAGE and not indicators and _has_responses_tool_loop(finding):
        indicators = 1
        finding.metadata["agent_indicators"] = 1
        finding.metadata["agent_classification"] = "openai-responses-tool-dispatch"
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


def looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip()))


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
