"""Recognize detection-rule packs, whose content is data rather than configuration.

A repository that vendors detection content (ShadowScan signature packs,
Semgrep rules, Sigma rules, a gitleaks configuration) lists the environment
variable names, hosts and identifiers it detects. Read as configuration, each
pattern would count as usage of the product it names.

Recognition is deliberately narrow: every document of the file must have one
of these shapes, with no top-level key the format does not define, so a
recognized file cannot also be a manifest or another tool's configuration.
Anything else is scanned as before. Only field names and nesting are read:
patterns are never compiled, and a parse failure means "not a rule pack".
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

import yaml

from shadowscan.signatures.loader import VALID_CATEGORIES
from shadowscan.signatures.schema import SIGNAL_COMMON, SIGNAL_FIELDS, SIGNATURE_LISTS, SIGNATURE_STRINGS
from shadowscan.utils.safe_yaml import (
    YAMLIntegrityError,
    YAMLResourceLimitError,
    strict_bounded_safe_load_all,
)

_SIGNATURE_KEYS = SIGNATURE_STRINGS | SIGNATURE_LISTS | {"agent_indicator", "signals"}
# A Semgrep rule needs a message and at least one way to match.
_SEMGREP_MATCHERS = frozenset(
    {"pattern", "patterns", "pattern-either", "pattern-regex", "match", "taint", "pattern-sources"}
)
# Sigma rule and rule-collection fields (Sigma specification 2.0).
_SIGMA_KEYS = frozenset(
    {
        "title",
        "id",
        "name",
        "related",
        "taxonomy",
        "status",
        "description",
        "license",
        "author",
        "references",
        "date",
        "modified",
        "logsource",
        "detection",
        "fields",
        "falsepositives",
        "level",
        "tags",
        "scope",
        "action",
    }
)
_GITLEAKS_KEYS = frozenset({"title", "extend", "allowlist", "allowlists", "rules"})
_GITLEAKS_RULE_KEYS = frozenset(
    {
        "id",
        "description",
        "regex",
        "secretGroup",
        "entropy",
        "keywords",
        "path",
        "tags",
        "allowlist",
        "allowlists",
        "required",
        "skipReport",
    }
)
# A YAML stream of several documents is parsed again only with a key of a
# format that may span documents (signature packs, Sigma rule collections)
# where the format puts it, so a large manifest bundle is not parsed twice.
_STREAM_HINT = re.compile(r"^(?:[ \t-]*signals:|logsource:)", re.MULTILINE)


def _strings(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _signal(value: Any) -> bool:
    kind = value.get("type") if isinstance(value, dict) else None
    return (
        isinstance(kind, str)
        and kind in SIGNAL_FIELDS
        and value.keys() <= SIGNAL_COMMON | SIGNAL_FIELDS[kind]
    )


def _signature(value: Any) -> bool:
    """Whether ``value`` has the shape the signature loader accepts (field names only)."""
    if not isinstance(value, dict) or not value.keys() <= _SIGNATURE_KEYS:
        return False
    category, signals = value.get("category"), value.get("signals")
    return (
        _strings(value.get("id"))
        and isinstance(category, str)
        and category in VALID_CATEGORIES
        and isinstance(signals, list)
        and bool(signals)
        and all(_signal(signal) for signal in signals)
    )


def _shadowscan(documents: list[Any]) -> bool:
    # The loader's three document forms: a pack, one signature, a signature list.
    signatures: list[Any] = []
    for document in documents:
        if isinstance(document, dict) and "signatures" in document:
            if document.keys() != {"signatures"} or not isinstance(document["signatures"], list):
                return False
            signatures.extend(document["signatures"])
        elif isinstance(document, list):
            signatures.extend(document)
        else:
            signatures.append(document)
    return bool(signatures) and all(_signature(signature) for signature in signatures)


def _semgrep(documents: list[Any]) -> bool:
    if len(documents) != 1 or not isinstance(documents[0], dict) or documents[0].keys() != {"rules"}:
        return False
    rules = documents[0]["rules"]
    return (
        isinstance(rules, list)
        and bool(rules)
        and all(
            isinstance(rule, dict)
            and _strings(rule.get("id"))
            and _strings(rule.get("message"))
            and not _SEMGREP_MATCHERS.isdisjoint(rule)
            for rule in rules
        )
    )


def _sigma(documents: list[Any]) -> bool:
    if not documents or not all(
        isinstance(document, dict) and document and document.keys() <= _SIGMA_KEYS for document in documents
    ):
        return False
    return any(
        isinstance(document.get("logsource"), dict)
        and isinstance(document.get("detection"), dict)
        and "condition" in document["detection"]
        for document in documents
    )


def _gitleaks(documents: list[Any]) -> bool:
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return False
    config = documents[0]
    rules = config.get("rules")
    return (
        config.keys() <= _GITLEAKS_KEYS
        and isinstance(rules, list)
        and bool(rules)
        and all(
            isinstance(rule, dict)
            and rule.keys() <= _GITLEAKS_RULE_KEYS
            and _strings(rule.get("id"))
            and (_strings(rule.get("regex")) or _strings(rule.get("path")))
            for rule in rules
        )
    )


_FORMATS: dict[str, tuple[tuple[str, Callable[[list[Any]], bool]], ...]] = {
    ".yaml": (("shadowscan-signatures", _shadowscan), ("semgrep", _semgrep), ("sigma", _sigma)),
    ".yml": (("shadowscan-signatures", _shadowscan), ("semgrep", _semgrep), ("sigma", _sigma)),
    ".json": (("semgrep", _semgrep),),
    ".toml": (("gitleaks", _gitleaks),),
}


def _stream(text: str) -> list[Any] | None:
    if not _STREAM_HINT.search(text):
        return None
    try:
        return strict_bounded_safe_load_all(text, require_string_keys=False)
    except (YAMLIntegrityError, YAMLResourceLimitError, RecursionError, ValueError, yaml.YAMLError):
        # The configuration pass parses the stream again and reports the problem.
        return None


def detection_rule_format(rel: str, text: str, parsed: Any = None) -> str | None:
    """Return the rule-pack format of the whole file ``rel``, or None.

    ``parsed`` is the file's single parsed document (YAML, JSON or TOML).
    None means it has none: a YAML stream of several documents is then parsed
    here, and any other file is not a rule pack.
    """
    extension = PurePosixPath(rel).suffix.lower()
    formats = _FORMATS.get(extension)
    if formats is None:
        return None
    if parsed is not None:
        documents: list[Any] | None = [parsed]
    else:
        documents = _stream(text) if extension in {".yaml", ".yml"} else None
    if not documents:
        return None
    for name, recognized in formats:
        if recognized(documents):
            return name
    return None
