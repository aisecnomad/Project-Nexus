"""Strict, runtime and CI shared schema for signature packs.

Severity is deliberately not an accepted field: finding severity is derived by
the risk engine. Signatures express evidence strength using ``weight``.

Besides field shapes, the schema pins the closed vocabularies that the matcher
and the risk engine key on. A misspelt ecosystem, language or capability would
otherwise load fine and silently never match (or never score), so each one is
a hard error here.
"""

from __future__ import annotations

import math
import re
from typing import Any

SIGNATURE_STRINGS = {"id", "name", "category", "vendor", "homepage", "description"}
SIGNATURE_LISTS = {"tags", "capabilities", "risk_notes", "references"}
SIGNAL_LISTS = {"languages", "names", "prefixes", "exclude_names", "exclude_prefixes", "patterns", "globs", "values", "capabilities"}
SIGNAL_COMMON = {"type", "weight", "capabilities", "agent_indicator", "description"}
SIGNAL_FIELDS = {
    "dependency": {"ecosystem", "names", "prefixes", "exclude_names", "exclude_prefixes"},
    "import": {"languages", "patterns"},
    "code": {"languages", "patterns"},
    "file": {"globs"},
    "env": {"names", "patterns"},
    "domain": {"values"},
    "user_agent": {"patterns"},
    "image": {"patterns"},
    "iac": {"values"},
    "name": {"patterns"},
    "scope": {"values"},
    "model": {"patterns"},
    "secret": {"patterns"},
    "client_id": {"names", "patterns"},
}

# Dependency ecosystems the manifest parsers emit. ``any`` matches every
# ecosystem; an omitted ecosystem is treated as ``any`` by the matcher.
ECOSYSTEMS = frozenset({"pypi", "npm", "nuget", "maven", "go", "cargo", "rubygems", "composer", "conda", "any"})

# Canonical language names produced by ``matcher.language_for_path``.
LANGUAGES = frozenset({"python", "javascript", "go", "rust", "java", "dotnet", "ruby", "php", "swift", "dart"})

# Capability vocabulary scored by ``shadowscan.risk.CAPABILITY_WEIGHTS``. The
# risk engine keys on these exact strings; anything else would never score.
CAPABILITIES = frozenset({
    "code-exec", "autonomous", "saas-actions", "browsing", "memory", "multi-agent", "delegated-identity", "tool-use", "rag",
    "data-access",
})

# Signature id namespaces (the part before the first dot) and the category each
# one requires. ``cloud.*`` keeps its historical spelling for the cloud-service
# category and ``tool.*`` (tool providers such as web search APIs) shares the
# sandbox category as corroborating infrastructure. Any other namespace is
# reserved for custom packs (for example ``custom.*``) and carries no category
# requirement; the CI validator additionally refuses unknown namespaces in the
# built-in packs.
NAMESPACE_CATEGORIES = {
    "framework": "framework",
    "provider": "provider",
    "protocol": "protocol",
    "coding-agent": "coding-agent",
    "platform": "platform",
    "observability": "observability",
    "memory": "memory",
    "sandbox": "sandbox",
    "tool": "sandbox",
    "identity-app": "identity-app",
    "cloud": "cloud-service",
    "heuristic": "heuristic",
    "policy": "policy",
}

def require_mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ValueError(f"{context}: expected a mapping with string keys")
    return value


def require_list(value: Any, context: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError(f"{context}: expected {'a nonempty' if nonempty else 'a'} list")
    return value


def _string(value: Any, context: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}: expected a nonempty string")


def _unknown(value: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = value.keys() - allowed
    if unknown:
        suffix = "; severity is derived by the risk engine; use weight for confidence" if "severity" in unknown else ""
        raise ValueError(f"{context}: unknown fields {', '.join(sorted(unknown))}{suffix}")


def _string_list(value: Any, context: str) -> list[str]:
    items = require_list(value, context)
    for i, entry in enumerate(items):
        _string(entry, f"{context}[{i}]")
    seen: set[str] = set()
    for entry in items:
        if entry in seen:
            raise ValueError(f"{context}: duplicate value {entry!r}")
        seen.add(entry)
    return items


def _vocabulary(items: list[str], allowed: frozenset[str], context: str, label: str) -> None:
    for entry in items:
        if entry not in allowed:
            raise ValueError(f"{context}: unknown {label} {entry!r}; expected one of {', '.join(sorted(allowed))}")


def matches_empty_string(pattern: str, flags: int = re.MULTILINE) -> bool:
    """Return True when a regex can match without consuming any input.

    Such a pattern fires on every input (or on every line), so it is always a
    data error. Patterns that do not compile return False here; the loader
    reports the compile error itself.
    """
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        return False
    return compiled.search("") is not None


def check_glob(glob: str, context: str) -> None:
    """Reject glob spellings that ``fnmatch`` would silently never match.

    ``fnmatch`` has no brace expansion (``{a,b}`` is matched literally) and
    treats an unmatched ``[`` or a stray ``]`` as a literal character, so each
    of these is a typo that never matches a real path.
    """
    if "{" in glob or "}" in glob:
        raise ValueError(f"{context}: glob {glob!r} uses braces, which fnmatch does not expand")
    i, n = 0, len(glob)
    while i < n:
        char = glob[i]
        if char == "]":
            raise ValueError(f"{context}: glob {glob!r} has an unbalanced ']'")
        if char == "[":
            j = i + 1
            if j < n and glob[j] == "!":
                j += 1
            if j < n and glob[j] == "]":
                j += 1
            while j < n and glob[j] != "]":
                j += 1
            if j >= n:
                raise ValueError(f"{context}: glob {glob!r} has an unbalanced '['")
            i = j
        i += 1


def validate_signature_shape(value: Any, context: str) -> dict[str, Any]:
    """Validate types before construction; never coerce strings/bools to numbers."""
    d = require_mapping(value, context)
    _unknown(d, SIGNATURE_STRINGS | SIGNATURE_LISTS | {"agent_indicator", "signals"}, context)
    for required in ("id", "category", "signals"):
        if required not in d:
            raise ValueError(f"{context}: missing required field {required}")
    for key, item in d.items():
        if key in SIGNATURE_STRINGS:
            if item is None and key in {"vendor", "homepage", "description"}:
                continue
            _string(item, f"{context}.{key}")
        elif key in SIGNATURE_LISTS:
            items = _string_list(item, f"{context}.{key}")
            if key == "capabilities":
                _vocabulary(items, CAPABILITIES, f"{context}.{key}", "capability")
        elif key == "agent_indicator" and type(item) is not bool:
            raise ValueError(f"{context}.{key}: expected a boolean")
    namespace = d["id"].split(".", 1)[0]
    expected = NAMESPACE_CATEGORIES.get(namespace)
    if expected is not None and d["category"] != expected:
        raise ValueError(
            f"{context}: id {d['id']!r} is in the {namespace!r} namespace, which requires category {expected!r}, not {d['category']!r}"
        )
    # Distinct signals of one signature may repeat a value on purpose: the
    # matcher lets them attach different weights or capabilities to the same
    # text, so uniqueness is only enforced inside each signal.
    for i, signal in enumerate(require_list(d["signals"], f"{context}.signals", nonempty=True)):
        validate_signal_shape(signal, f"{context}.signals[{i}]")
    return d


def validate_signal_shape(value: Any, context: str) -> dict[str, Any]:
    d = require_mapping(value, context)
    kind = d.get("type")
    if not isinstance(kind, str) or kind not in SIGNAL_FIELDS:
        raise ValueError(f"{context}: invalid signal type {kind!r}")
    _unknown(d, SIGNAL_COMMON | SIGNAL_FIELDS[kind], context)
    for key, item in d.items():
        if key in SIGNAL_LISTS:
            items = _string_list(item, f"{context}.{key}")
            if key == "languages":
                _vocabulary(items, LANGUAGES, f"{context}.{key}", "language")
            elif key == "capabilities":
                _vocabulary(items, CAPABILITIES, f"{context}.{key}", "capability")
            elif key == "patterns":
                for i, pattern in enumerate(items):
                    if matches_empty_string(pattern):
                        raise ValueError(f"{context}.{key}[{i}]: pattern {pattern!r} matches the empty string")
            elif key == "globs":
                for i, glob in enumerate(items):
                    check_glob(glob, f"{context}.{key}[{i}]")
            elif key == "values" and kind == "domain":
                for i, domain in enumerate(items):
                    if domain.startswith("re:") and matches_empty_string(domain[3:], re.IGNORECASE):
                        raise ValueError(f"{context}.{key}[{i}]: domain regex {domain!r} matches the empty string")
        elif key == "weight":
            # Range first: math.isfinite overflows on arbitrarily large ints.
            if type(item) not in (float, int) or not 0 < item <= 1 or not math.isfinite(item):
                raise ValueError(f"{context}.weight: expected a finite number greater than 0 and at most 1")
        elif key == "agent_indicator":
            if type(item) is not bool:
                raise ValueError(f"{context}.{key}: expected a boolean")
        elif key == "ecosystem":
            if not isinstance(item, str) or item not in ECOSYSTEMS:
                raise ValueError(f"{context}.ecosystem: expected one of {', '.join(sorted(ECOSYSTEMS))}, got {item!r}")
        else:
            _string(item, f"{context}.{key}")
    return d
