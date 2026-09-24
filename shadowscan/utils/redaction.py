"""Credential-safe evidence and report values.

Sanitize *before* shortening excerpts: once a credential is truncated, its
recognizable structure can be lost. These helpers deliberately do not depend on
signature settings; disabling secret discovery must never disable redaction.
"""

from __future__ import annotations

import hashlib
import io
import re
import token
import tokenize
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
    "secretstring", "secretbinary", "connectionstring", "connstr",
)
_SENSITIVE_NAMES = {"token", "jwt", "secret", "bearer", "passwd", "password", "authorization", "cookie", "setcookie"}
_SECRET_TOKEN = re.compile(
    r"\b(?:sk-(?:proj-|ant-|live-|or-v1-)?[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    r"|glpat-[A-Za-z0-9_-]{8,}"
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
_PYTHON_ASSIGNMENT_KEY = re.compile(
    r"(?<![\w-])(?P<key>[A-Za-z_][A-Za-z0-9_.]{0,100})[ \t]*(?P<separator>:|=(?!=))"
)
_MAX_SANITIZATION_NODES = 100_000
_MAX_SANITIZATION_CHARS = 64 * 1024 * 1024
_MAX_REDACTION_WORK = 128 * 1024 * 1024


class SanitizationLimitError(ValueError):
    """Evidence cannot be safely sanitized within the work/output budget."""


def _redact_python_assignments(text: str) -> str:
    """Redact complete sensitive Python assignment expressions without evaluation.

    Tokenize only sensitive candidates, including ordinary assignments and call
    arguments. String delimiters, escapes, concatenation and continued lines are
    handled lexically. Malformed or unfinished RHS syntax is withheld through
    EOF; the explicit work budget prevents hostile candidates from repeatedly
    tokenizing an unlimited amount of source.
    """
    stream: io.StringIO | None = None
    pieces: list[str] = []
    cursor = 0
    work = 0
    urls = _URL.finditer(text)
    url = next(urls, None)
    for match in _PYTHON_ASSIGNMENT_KEY.finditer(text):
        if match.start() < cursor or not _sensitive_key(match.group("key")):
            continue
        annotated = match.group("separator") == ":"
        assigned_at: int | None = None if annotated else match.end()
        # URL fields use URL boundaries, not Python statement boundaries,
        # and have already been sanitized by the URL pass. Check actual spans:
        # a '#' before a source assignment can also introduce a comment.
        while url is not None and url.end() <= match.start():
            url = next(urls, None)
        if url is not None and url.start() <= match.start():
            continue
        value_start = match.end()
        if not annotated:
            while value_start < len(text) and text[value_start] in " \t":
                value_start += 1
        if stream is None:
            stream = io.StringIO(text)
        stream.seek(match.end())
        offsets = [match.end()]
        end = len(text)
        brackets: list[str] = []
        previous = match.start() - 1
        while previous >= 0 and text[previous] in " \t\r\n":
            previous -= 1
        argument = not annotated and previous >= 0 and text[previous] in "(,"

        def readline() -> str:
            nonlocal work
            assert stream is not None
            line = stream.readline()
            work += len(line)
            if work > _MAX_REDACTION_WORK:
                raise SanitizationLimitError("Python assignment work limit exceeded")
            offsets.append(stream.tell())
            return line

        try:
            for item in tokenize.generate_tokens(readline):
                position = offsets[item.start[0] - 1] + item.start[1]
                if item.type == token.ERRORTOKEN and not item.string.isspace():
                    # Incomplete single-quoted strings generate error tokens,
                    # not TokenError. A semicolon inside one is not a boundary.
                    break
                if item.type == token.OP:
                    if item.string == "=" and assigned_at is None and not brackets:
                        assigned_at = offsets[item.end[0] - 1] + item.end[1]
                    elif item.string in "([{":
                        brackets.append(item.string)
                    elif item.string in ")]}":
                        if not brackets:
                            if argument:
                                end = position
                            break
                        if brackets.pop() != {")": "(", "]": "[", "}": "{"}[item.string]:
                            break
                    elif assigned_at is not None and not brackets and (
                        item.string == ";" or (argument and item.string == ",")
                    ):
                        end = position
                        break
                elif item.type in {token.NEWLINE, token.ENDMARKER}:
                    end = position
                    break
        except (tokenize.TokenError, IndentationError, SyntaxError):
            # Once '=' is seen, incomplete source must not expose any RHS,
            # including credential fragments on subsequent physical lines.
            pass
        if assigned_at is not None:
            raw = text[assigned_at:end]
            bare = raw.strip()
            fingerprint = bare
            if bare.startswith(('"', "'")) and bare.endswith(bare[0]):
                fingerprint = bare[1:-1]
            if _FINGERPRINT.fullmatch(fingerprint):
                continue
            pieces.append(text[cursor:assigned_at])
            if annotated:
                pieces.append(' "' + REDACTED + '"')
            else:
                # Quoted replacements retain expression boundaries inside
                # enclosing calls and text wrappers. Plain diagnostic values
                # keep their established name=[REDACTED] representation.
                simple = bool(re.fullmatch(r"[^\s\"'(){}\[\],;]+", bare)) or bare == REDACTED
                replacement = '"' + REDACTED + '"' if argument or not simple else REDACTED
                pieces.append(text[assigned_at:value_start] + replacement)
            pieces.append("\n" * raw.count("\n"))
            cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


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
    if len(text) > _MAX_SANITIZATION_CHARS:
        raise SanitizationLimitError("text sanitization size limit exceeded")
    text = _PEM.sub(lambda m: REDACTED + "\n" * m.group(0).count("\n"), text)
    text = _URL.sub(_sanitize_url, text)
    text = _redact_python_assignments(text)
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
    _check_sanitization_structure(value)
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
    redaction_work = 0

    def text(item: str) -> str:
        nonlocal redaction_work
        redaction_work += len(item) * (len(ordered) + 1)
        if redaction_work > _MAX_REDACTION_WORK:
            raise SanitizationLimitError("credential replacement work limit exceeded")
        for secret in ordered:
            item = item.replace(secret, REDACTED)
        return sanitize_text(item)

    cleaning: set[int] = set()
    cleaning_steps = 0

    def clean(item: Any, depth: int = 0) -> Any:
        nonlocal cleaning_steps
        cleaning_steps += 1
        if cleaning_steps > _MAX_SANITIZATION_NODES:
            raise SanitizationLimitError("sanitization work limit exceeded")
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


def _check_sanitization_structure(value: Any) -> None:
    """Bound expanded output before copying an alias DAG or running redaction.

    Memoized subtree costs count *every occurrence* in JSON serialization,
    without traversing repeated objects exponentially. Cycles become one
    redaction marker, matching ``sanitize``; excessive depth is an explicit
    incomplete scan, never a silently truncated clean result.
    """
    active: set[int] = set()
    memo: dict[int, tuple[int, int, int]] = {}

    def cost(item: Any) -> tuple[int, int, int]:
        if not isinstance(item, (Mapping, list, tuple)):
            return 1, len(item) if isinstance(item, str) else 0, 1
        identity = id(item)
        if identity in active:
            return 1, len(REDACTED), 1
        if identity in memo:
            return memo[identity]
        if len(active) >= 64:
            raise SanitizationLimitError("sanitization nesting limit exceeded")
        active.add(identity)
        nodes, chars, height = 1, 0, 1
        children = item.items() if isinstance(item, Mapping) else ((None, child) for child in item)
        for key, child in children:
            child_nodes, child_chars, child_height = cost(child)
            nodes += child_nodes + (key is not None)
            chars += child_chars + (len(str(key)) if key is not None else 0)
            height = max(height, child_height + 1)
            if nodes > _MAX_SANITIZATION_NODES or chars > _MAX_SANITIZATION_CHARS:
                raise SanitizationLimitError("sanitization expanded output limit exceeded")
            if height > 64:
                raise SanitizationLimitError("sanitization nesting limit exceeded")
        active.remove(identity)
        memo[identity] = (nodes, chars, height)
        return memo[identity]

    nodes, chars, _ = cost(value)
    if nodes > _MAX_SANITIZATION_NODES or chars > _MAX_SANITIZATION_CHARS:
        raise SanitizationLimitError("sanitization expanded output limit exceeded")
