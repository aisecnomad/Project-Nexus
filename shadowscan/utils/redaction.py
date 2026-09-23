"""Credential-safe evidence and report values.

Sanitize *before* shortening excerpts: once a credential is truncated, its
recognizable structure can be lost. These helpers deliberately do not depend on
signature settings; disabling secret discovery must never disable redaction.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote

REDACTED = "[REDACTED]"
_FINGERPRINT = re.compile(r"^credential:sha256:[a-f0-9]{64}$")
_SENSITIVE_SUFFIXES = (
    "apikey", "accesskey", "secretkey", "accesskeyid", "secretaccesskey",
    "accesstoken", "refreshtoken", "idtoken", "authtoken", "clientsecret",
    "authorization", "proxyauthorization", "password", "passwd", "privatekey",
    "credential", "credentials", "bearertoken", "sessiontoken", "signingkey",
    "secretstring", "secretbinary",
)
_SENSITIVE_NAMES = {"token", "jwt", "secret", "bearer", "passwd", "password", "authorization", "cookie", "setcookie"}
_SECRET_TOKEN = re.compile(
    r"\b(?:sk-(?:proj-|ant-|or-v1-)?[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    r"|xox[baprs]-[A-Za-z0-9-]{8,}|AIza[A-Za-z0-9_-]{16,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|hf_[A-Za-z0-9]{8,})\b"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_PEM = re.compile(r"-----BEGIN (?:[A-Z ]{0,30})PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]{0,30})PRIVATE KEY-----|\Z)", re.DOTALL)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/_.=-]+")
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,20}://[^\s<>\"']+")
# Bounded identifiers keep scanning linear on long lines of non-matching text.
_ASSIGNMENT = re.compile(
    r"(?P<key>(?<![\w-])[A-Za-z_][A-Za-z0-9_.-]{0,100})"
    r"(?P<sep>[\"']\s*:\s*|\s*=\s*|:\s+|:\s*(?=[\"']))"
    r"(?P<value>\[REDACTED\]|\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\}\]\)\"']+)"
)
_QUERY_SEPARATOR = re.compile(r"[&#]")


def _sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in _SENSITIVE_NAMES or normalized.endswith(_SENSITIVE_SUFFIXES)


def credential_id(value: Any) -> str:
    """Stable opaque identity for raw credentials; never retain prefix/suffix."""
    value = str(value)
    if _FINGERPRINT.fullmatch(value):
        return value
    return "credential:sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _redact_value(value: Any) -> Any:
    if value is None or value == "":
        return value
    if isinstance(value, str) and (value == REDACTED or _FINGERPRINT.fullmatch(value)):
        return value
    return REDACTED


def _sanitize_url(match: re.Match[str]) -> str:
    url = match.group(0)
    scheme, rest = url.split("://", 1)
    # Userinfo ends at the authority boundary, not at the first slash alone.
    # An @ in a query value must not be mistaken for a hostname separator.
    authority_end = min((pos for c in "/?#" if (pos := rest.find(c)) >= 0), default=len(rest))
    authority, tail = rest[:authority_end], rest[authority_end:]
    if "@" in authority:
        authority = REDACTED + "@" + authority.rsplit("@", 1)[1]
    url = scheme + "://" + authority + tail

    def query_value(field: str) -> str:
        key, equals, value = field.partition("=")
        if not equals:
            return field
        decoded = unquote(key).lower()
        sensitive = _sensitive_key(decoded) or decoded in {"key", "sig", "signature", "code", "x-amz-signature", "x-goog-signature"}
        return key + equals + (REDACTED if sensitive else value)

    # Consume each field once. A regex that retries an unbounded key after every
    # '?' takes quadratic time on a URL containing many '?' and no '='. Keep '?'
    # within values (it is legal there) so redacting a secret never retains its
    # suffix. Fragment parameters receive the same protection as query fields.
    start = min((pos for c in "?&#" if (pos := url.find(c)) >= 0), default=len(url))
    if start == len(url):
        return url
    parts = [url[:start + 1]]
    cursor = start + 1
    for separator in _QUERY_SEPARATOR.finditer(url, cursor):
        parts.append(query_value(url[cursor:separator.start()]))
        parts.append(separator.group(0))
        cursor = separator.end()
    parts.append(query_value(url[cursor:]))
    return "".join(parts)


def sanitize_text(text: str) -> str:
    """Redact recognizable credentials, assignments, auth headers and URL secrets."""
    if not isinstance(text, str):
        text = str(text)
    text = _PEM.sub(lambda m: REDACTED + "\n" * m.group(0).count("\n"), text)
    text = _URL.sub(_sanitize_url, text)
    text = _JWT.sub(REDACTED, text)
    text = _SECRET_TOKEN.sub(REDACTED, text)
    text = _AUTH.sub(lambda m: m.group(1) + " " + REDACTED, text)

    def assignments(value: str, depth: int = 0) -> str:
        def assignment(m: re.Match[str]) -> str:
            if _FINGERPRINT.fullmatch(m.group(0)):
                return m.group(0)
            raw = m.group("value")
            quote = raw[0] if raw.startswith(('"', "'")) else ""
            bare = raw[1:-1] if quote else raw
            if _sensitive_key(m.group("key")):
                clean = _redact_value(bare)
            elif "=" in bare or ":" in bare:
                # Do not let an ordinary assignment swallow a nested credential,
                # e.g. config = "api_key=opaque-value" in a source-code excerpt.
                clean = assignments(bare, depth + 1) if depth < 8 else REDACTED
            else:
                return m.group(0)
            return m.group("key") + m.group("sep") + quote + clean + quote

        return _ASSIGNMENT.sub(assignment, value)

    return assignments(text)


def sanitize(value: Any) -> Any:
    """Return a sanitized JSON-like copy, preserving nonsecret fields and types.

    Environment variable values are omitted regardless of name. Lists additionally
    recognize argv pairs, so ``["--token", "opaque-value"]`` is safe to retain.
    Known credential values are also removed from other fields in the same object.
    """
    known: set[str] = set()

    def record_has_secret_value(item: Mapping) -> bool:
        name = item.get("name") or item.get("Name") or item.get("key") or item.get("Key")
        return isinstance(name, str) and _sensitive_key(name)

    def remember(child: Any) -> None:
        if isinstance(child, str) and len(child) >= 8:
            if child != REDACTED and not _FINGERPRINT.fullmatch(child):
                known.add(child)

    discovered: set[int] = set()

    def discover(item: Any, depth: int = 0) -> None:
        if depth > 64 or (isinstance(item, (Mapping, list, tuple)) and id(item) in discovered):
            return
        if isinstance(item, (Mapping, list, tuple)):
            discovered.add(id(item))
        if isinstance(item, Mapping):
            if record_has_secret_value(item):
                remember(item.get("value") or item.get("Value"))
            for key, child in item.items():
                if _sensitive_key(str(key)):
                    remember(child)
                if str(key).lower() in {"env", "environment", "environment_variables", "environmentvariables"}:
                    if isinstance(child, Mapping):
                        for env_value in child.values():
                            remember(env_value)
                    elif isinstance(child, list):
                        for entry in child:
                            if isinstance(entry, Mapping):
                                remember(entry.get("value") or entry.get("Value"))
                discover(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            previous = None
            for child in item:
                if isinstance(previous, str) and previous.startswith("-") and _sensitive_key(previous.lstrip("-")):
                    remember(child)
                discover(child, depth + 1)
                previous = child

    discover(value)
    ordered = sorted(known, key=len, reverse=True)

    def text(item: str) -> str:
        for secret in ordered:
            item = item.replace(secret, REDACTED)
        return sanitize_text(item)

    cleaning: set[int] = set()

    def clean(item: Any, depth: int = 0) -> Any:
        if depth > 64:
            return REDACTED
        if isinstance(item, (Mapping, list, tuple)):
            if id(item) in cleaning:
                return REDACTED
            cleaning.add(id(item))
        try:
            return clean_value(item, depth)
        finally:
            if isinstance(item, (Mapping, list, tuple)):
                cleaning.discard(id(item))

    def clean_value(item: Any, depth: int) -> Any:
        if isinstance(item, Mapping):
            mapping_out = {}
            for key, child in item.items():
                name = str(key)
                if _sensitive_key(name) or (record_has_secret_value(item) and name.lower() == "value"):
                    result = _redact_value(child)
                elif name.lower() in {"env", "environment", "environment_variables", "environmentvariables"} and isinstance(child, Mapping):
                    result = {text(str(k)): _redact_value(v) for k, v in child.items()}
                elif name.lower() in {"env", "environment", "environment_variables", "environmentvariables"} and isinstance(child, list):
                    result = [
                        {text(str(k)): (_redact_value(v) if str(k).lower() == "value" else clean(v, depth + 1)) for k, v in entry.items()}
                        if isinstance(entry, Mapping) else _redact_value(entry)
                        for entry in child
                    ]
                else:
                    result = clean(child, depth + 1)
                mapping_out[text(name)] = result
            return mapping_out
        if isinstance(item, (list, tuple)):
            sequence_out = []
            redact_next = False
            for child in item:
                if redact_next:
                    sequence_out.append(_redact_value(child))
                    redact_next = False
                else:
                    sequence_out.append(clean(child, depth + 1))
                    if isinstance(child, str) and child.startswith("-") and "=" not in child:
                        redact_next = _sensitive_key(child.lstrip("-"))
            return tuple(sequence_out) if isinstance(item, tuple) else sequence_out
        if isinstance(item, str):
            return text(item)
        return item

    return clean(value)
