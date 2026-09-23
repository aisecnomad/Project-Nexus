"""Strict, runtime and CI shared schema for signature packs.

Severity is deliberately not an accepted field: finding severity is derived by
the risk engine. Signatures express evidence strength using ``weight``.
"""

from __future__ import annotations

import math
from typing import Any

SIGNATURE_STRINGS = {"id", "name", "category", "vendor", "homepage", "description"}
SIGNATURE_LISTS = {"tags", "capabilities", "risk_notes", "references"}
SIGNAL_LISTS = {"languages", "names", "prefixes", "patterns", "globs", "values", "capabilities"}
SIGNAL_COMMON = {"type", "weight", "capabilities", "agent_indicator", "description"}
SIGNAL_FIELDS = {
    "dependency": {"ecosystem", "names", "prefixes"},
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
            for i, entry in enumerate(require_list(item, f"{context}.{key}")):
                _string(entry, f"{context}.{key}[{i}]")
        elif key == "agent_indicator" and type(item) is not bool:
            raise ValueError(f"{context}.{key}: expected a boolean")
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
            for i, entry in enumerate(require_list(item, f"{context}.{key}")):
                _string(entry, f"{context}.{key}[{i}]")
        elif key == "weight":
            if type(item) not in (float, int) or not 0 <= item <= 1 or not math.isfinite(item):
                raise ValueError(f"{context}.weight: expected a finite number between 0 and 1")
        elif key == "agent_indicator":
            if type(item) is not bool:
                raise ValueError(f"{context}.{key}: expected a boolean")
        else:
            _string(item, f"{context}.{key}")
    return d
