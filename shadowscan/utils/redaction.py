"""Credential-safe evidence and report values.

Sanitize *before* shortening excerpts: once a credential is truncated, its
recognizable structure can be lost. These helpers deliberately do not depend on
signature settings; disabling secret discovery must never disable redaction.

The passes live in the ``redaction_*`` modules beside this one:
``redaction_rules`` (shared names, limits and value tests),
``redaction_formats`` (token formats and URLs), ``redaction_statements``
(tokenized source assignments), ``redaction_assignments`` (assignments,
mappings and defaults in text), ``redaction_calls``, ``redaction_commands``
and ``redaction_markup``. This module drives them and is their one public
face: every name they define reads through it, and a name replaced here (by a
test's monkeypatch, for example) is replaced in every module that binds it,
exactly as when all of them lived in this one module.

Patch and replace rules through this module, never through a ``redaction_*``
module: a name set on one of those changes only that module, and every other
module that imported the name silently keeps the old object.
"""

from __future__ import annotations

import datetime
import decimal
import re
import sys
import types
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from shadowscan.utils import (
    redaction_assignments,
    redaction_calls,
    redaction_commands,
    redaction_formats,
    redaction_markup,
    redaction_rules,
    redaction_statements,
)
from shadowscan.utils.credential_identity import keyed_credential_digest
from shadowscan.utils.redaction_assignments import (
    _redact_connection_passwords,
    _redact_fallback_defaults,
    _redact_mapping_values,
    _redact_opaque_assignments,
    _redact_plain_assignments,
    _redact_yaml_multiline_values,
)
from shadowscan.utils.redaction_calls import _redact_auth_pairs, _redact_credential_calls
from shadowscan.utils.redaction_commands import (
    _aws_configure_argv_secret_indices,
    _redact_aws_configure,
    _redact_command_credentials,
    _redact_environment_commands,
    _redact_extended_options,
    _redact_opaque_options,
    _redact_user_secrets,
)
from shadowscan.utils.redaction_formats import (
    _ADDED_PEM,
    _PEM,
    _URL,
    _redact_authorization,
    _redact_compact_colons,
    _redact_cookie_headers,
    _redact_jwts,
    _redact_nested_urls,
    _redact_query_text,
    _redact_secret_tokens,
    _sanitize_url,
)
from shadowscan.utils.redaction_markup import (
    _redact_flow_records,
    _redact_markup_credentials,
    _redact_markup_settings,
    _redact_name_value_pairs,
    _redact_record_settings,
    _redact_reversed_records,
)
from shadowscan.utils.redaction_rules import (
    _FINGERPRINT,
    _KEY_NORMALISE,
    _MAX_REDACTION_WORK,
    _MAX_SANITIZATION_CHARS,
    _MAX_SANITIZATION_NODES,
    REDACTED,
    SanitizationLimitError,
    _credential_literal,
    _credential_name,
    _redact_value,
    _sensitive_assignment_key,
    _sensitive_flag,
    _sensitive_key,
    _sensitive_name,
    _setting_level,
    _setting_value_withheld,
)
from shadowscan.utils.redaction_statements import _redact_python_assignments

# Values the sanitizer descends into; sets and frozensets are traversed like lists.
_CONTAINERS = (Mapping, list, tuple, set, frozenset)

# Keys whose mapping or list of name/value records holds environment variables.
_ENVIRONMENT_KEYS = frozenset({"env", "environment", "environment_variables", "environmentvariables"})
# A credential container can include descriptive fields as well as secret
# material. Its descriptor values are not credentials merely because they
# occur next to one (for example {"provider": "openai", "value": "..."}).
_CREDENTIAL_DESCRIPTORS = frozenset(
    {"id", "objectid", "name", "type", "provider", "scope", "scopes", "status"}
)
# Descriptors that are opaque secret material inside a container named for
# credentials ('credentials.id'), but name an identity elsewhere ('api_key.id').
_CREDENTIAL_GROUP_IDS = frozenset({"id", "objectid"})
# An 'auth' block ('{"auth": {"type": "bearer", "value": "..."}}') holds its
# credential under a generic field name; 'auth' alone is too broad a key to
# withhold whole, so only these generic credential fields inside it are.
_AUTH_CONTAINER_KEYS = frozenset({"auth", "authentication", "authn"})
_AUTH_VALUE_KEYS = frozenset({"value", "key", "credential"})


# Leaves that keep their type: JSON's scalars and the standard library's, whose text is
# bounded by their type. Any other leaf (bytes, a set, an exception, a plugin's object)
# reaches a report through ``json.dumps(default=str)`` or ``repr`` as it is, so it is
# turned into text first (see ``_plain``).
_SCALARS = (bool, int, float, datetime.date, datetime.time, datetime.timedelta, decimal.Decimal, uuid.UUID)
_PLAIN_TYPES = (str, Mapping, list, tuple, *_SCALARS)


def _member_order(member: Any) -> tuple[str, str]:
    try:
        return type(member).__name__, repr(member)
    except Exception:  # noqa: BLE001 - an arbitrary object's own repr may raise anything
        return type(member).__name__, ""


def _plain(item: Any) -> Any:
    """``item`` as a value ``sanitize`` can read and copy.

    Text, mappings, lists, tuples and the scalars above are returned as they are. Bytes
    become text (undecodable bytes are replaced), a set a list in a stable order, and
    any other object, an exception included, its ``str`` -- which ``sanitize`` then
    reads like any other text.
    """
    if item is None or isinstance(item, _PLAIN_TYPES):
        return item
    if isinstance(item, (bytes, bytearray, memoryview)):
        if len(item) > _MAX_SANITIZATION_CHARS:
            raise SanitizationLimitError("text sanitization size limit exceeded")
        return bytes(item).decode("utf-8", errors="replace")
    if isinstance(item, (set, frozenset)):
        return sorted(item, key=_member_order)
    try:
        return str(item)
    except Exception:  # noqa: BLE001 - an arbitrary object's own __str__ may raise anything
        return f"<{type(item).__qualname__}>"


def credential_id(value: Any) -> str:
    """Keyed credential pseudonym, stable only within the active private-key scope.

    Legacy public SHA-256 identifiers are rekeyed when passed here. Already
    keyed identifiers remain idempotent so sanitized evidence can be replayed.
    """
    s = str(value)
    if s.startswith("credential:hmac-sha256:") and _FINGERPRINT.fullmatch(s):
        return s
    return "credential:hmac-sha256:" + keyed_credential_digest(s)


def sanitize_text(text: str) -> str:
    """Redact recognizable credentials, assignments, auth headers and URL secrets.

    Context-named values are also withheld: XML elements and attributes,
    name/value records, command-line options, environment commands, basic
    authentication pairs, literals passed to credential-named callees and
    literal fallback defaults of credential names.

    The established passes run first, with the rules and in the order they
    had before the extended passes were added; the extended passes then read
    what they leave. Each pass reads the text the passes before it leave, so
    a rule that withheld more in an early pass would change what the later
    passes see: a value withheld together with the name glued after it
    ('v#password = ...') hides that name from the assignment rules, and the
    credential after the name is no longer withheld. Run last, an added rule
    only adds markers, and whatever the established passes withhold stays
    withheld.
    """
    return _redact_extended(_sanitize_established(text))


def _checked_text(text: str) -> str:
    """``text`` as a string within the sanitization size limit."""
    if not isinstance(text, str):
        # Untyped callers still pass bytes-like values.
        text = str(text)  # type: ignore[unreachable]
    if len(text) > _MAX_SANITIZATION_CHARS:
        raise SanitizationLimitError("text sanitization size limit exceeded")
    return text


def _redact_extended(text: str, *, reread: bool = False) -> str:
    """The rules added to the established passes, on the text those leave (see ``sanitize_text``).

    Settings in markup and name/value records (hierarchical and
    credential-like names), 'dotnet user-secrets set', numbered names and
    YAML values under credential-like names, and opaque values of options
    named for a credential. The options come last: withheld earlier, a value
    glued to a following name ('--key v#openaiKey = ...') would hide that
    name from the others. URLs inside another URL's text are read after all
    of them, and a text they change is then read once more, as the next
    sanitization would read it (``reread``).
    """
    text = _redact_markup_settings(text)
    text = _redact_record_settings(text)
    text = _redact_user_secrets(text)
    text = _redact_connection_passwords(text)
    text = _redact_opaque_assignments(text, extended=True)
    text = _redact_fallback_defaults(text, extended=True)
    text = _redact_reversed_records(text)
    text = _redact_query_text(text)
    text = _redact_extended_options(text)
    # A cookie header comes before the compact names: the rest of its line
    # holds the other cookies, past any ';' the others stop at.
    headers = _redact_cookie_headers(text)
    compact = _redact_compact_colons(headers)
    reshaped = compact != text
    text = _redact_aws_configure(_redact_opaque_options(compact))
    # A bare marker that these passes leave after a sensitive key's colon
    # ('api_key : <opaque>') is read by the established mapping pass as the start
    # of a mapping value; normalize it here so that sanitizing again changes nothing.
    result = _redact_mapping_values(text) if REDACTED in text else text
    if reshaped:
        # A cookie header withheld to the end of its line, or a withheld
        # 'name:value', changes the statement around it for the statement rules:
        # 'get(url, cookie=a; b=v' loses the ';' that ended the argument, and
        # 'api_key:a=1; sid=v' becomes 'api_key:"[REDACTED]"; sid=v', an
        # annotation they read on past the ';'; a bare marker left in an
        # argument ('get(url, cookie=[REDACTED]') is one they quote. What they
        # would change there on the next sanitization is changed now.
        result = _redact_mapping_values(_redact_python_assignments(result))
    # An inner URL's userinfo or query field, withheld only here, changes the
    # URL the established passes read; they read the text once more.
    nested = _redact_nested_urls(result)
    if nested == result or reread:
        return nested
    return _redact_extended(_established_passes(nested), reread=True)


def _sanitize_established(text: str) -> str:
    """The established passes, in their order and with their rules (see ``sanitize_text``).

    Armored PGP private key blocks are withheld next to the PEM keys, before
    any pass reads a name (see ``_withhold_key_blocks``).
    """
    text = _PEM.sub(_withheld_block, _checked_text(text))
    blocks = list(_ADDED_PEM.finditer(text))
    return _withhold_key_blocks(text, blocks) if blocks else _established_passes(text)


def _withheld_block(match: re.Match[str]) -> str:
    """The marker for a private key block, keeping its line breaks so excerpt lines stay aligned."""
    return REDACTED + "\n" * match.group(0).count("\n")


def _withhold_key_blocks(text: str, blocks: list[re.Match[str]]) -> str:
    """The established passes on ``text``, with its armored PGP private key ``blocks`` withheld first.

    A credential name before a block ('private_key: -----BEGIN PGP ...')
    made the established rules withhold its BEGIN line, and the extended
    rule that withholds a block starts at that line: the key's body on the
    lines after it was shown. Withheld before every name pass, as a PEM key
    is, the whole block goes and the name before it stays. A value that
    starts inside a block and runs past its END line ('password: "...' in
    the block, closed on a later line), though, is withheld by the
    established order and was shown once the block went first. So the
    blocks go first only where no line outside them then shows anything the
    established order withholds (see ``_shows_no_more``). Otherwise the
    text every pass leaves in the established order is kept up to the line
    of the first block, and every line from there on is withheld; the
    established passes then read that text once more, as the next
    sanitization would.
    """
    pieces: list[str] = []
    cursor = 0
    for block in blocks:
        pieces.append(text[cursor : block.start()])
        pieces.append(_withheld_block(block))
        cursor = block.end()
    pieces.append(text[cursor:])
    first = _established_passes("".join(pieces))
    kept = _redact_extended(_established_passes(text))
    if _shows_no_more(text, blocks, kept, _redact_extended(first)):
        return first
    lines = kept.split("\n")
    if len(lines) != text.count("\n") + 1:
        return REDACTED + "\n" * text.count("\n")
    start = text.count("\n", 0, blocks[0].start())
    return _established_passes("\n".join([*lines[:start], REDACTED, *[""] * (len(lines) - start - 1)]))


def _shows_no_more(text: str, blocks: list[re.Match[str]], kept: str, shown: str) -> bool:
    """Whether ``shown`` shows nothing that ``kept`` withholds outside the ``blocks`` of ``text``.

    Every pass keeps the lines of a text, so the two are compared line by
    line. The lines inside a block are withheld in ``shown``. Any other line
    must be its line in ``kept`` with at most one more span withheld: the
    text before one of its markers starts ``kept``'s line and the text after
    that marker ends it. The marker of a block is on its first line, so the
    start of its last line, where the rest of the block was, counts as one.
    The blanks and carriage return that end a line are not compared: the
    block's marker keeps only the line feeds of the CRLF breaks inside it,
    and a mapping value withheld in ``kept`` keeps the blanks after it.
    """
    kept_lines, shown_lines = kept.split("\n"), shown.split("\n")
    if not len(kept_lines) == len(shown_lines) == text.count("\n") + 1:
        return False
    inside: set[int] = set()
    ends: set[int] = set()
    line = position = 0
    for block in blocks:
        line += text.count("\n", position, block.start())
        last = line + block.group().count("\n")
        inside.update(range(line + 1, last))
        if last > line:
            ends.add(last)
        line, position = last, block.end()
    return all(
        index in inside
        or _line_shows_no_more(kept_line.rstrip(" \t\r"), shown_line.rstrip(" \t\r"), end=index in ends)
        for index, (kept_line, shown_line) in enumerate(zip(kept_lines, shown_lines, strict=True))
    )


def _line_shows_no_more(kept: str, shown: str, *, end: bool) -> bool:
    """Whether ``shown`` is ``kept`` with at most one more span withheld (see ``_shows_no_more``).

    ``end`` counts the start of ``shown`` as a marker.
    """
    if kept == shown:
        return True
    limit = min(len(kept), len(shown))
    head = _common_length(lambda size: kept[:size] == shown[:size], limit)
    tail = _common_length(lambda size: kept[len(kept) - size :] == shown[len(shown) - size :], limit)
    markers = [(0, 0)] if end else []
    found = shown.find(REDACTED)
    while found >= 0:
        markers.append((found, found + len(REDACTED)))
        found = shown.find(REDACTED, found + len(REDACTED))
    return any(
        before <= head and len(shown) - after <= tail and before + len(shown) - after <= len(kept)
        for before, after in markers
    )


def _common_length(equal: Callable[[int], bool], limit: int) -> int:
    """The largest size up to ``limit`` for which ``equal`` holds, if it holds for every smaller one."""
    low, high = 0, limit
    while low < high:
        middle = (low + high + 1) // 2
        if equal(middle):
            low = middle
        else:
            high = middle - 1
    return low


def _established_passes(text: str) -> str:
    """The established passes that follow the private keys, in their order (see ``_sanitize_established``)."""
    text = _URL.sub(_sanitize_url, text)
    text = _redact_markup_credentials(text)
    text = _redact_flow_records(text, quoted_only=True)
    text = _redact_name_value_pairs(text)
    text = _redact_command_credentials(text)
    text = _redact_environment_commands(text)
    text = _redact_auth_pairs(text)
    text = _redact_credential_calls(text)
    text = _redact_python_assignments(text)
    text = _redact_yaml_multiline_values(text)
    text = _redact_mapping_values(text)
    text = _redact_opaque_assignments(text)
    text = _redact_jwts(text)
    text = _redact_secret_tokens(text)
    text = _redact_authorization(text)
    # Fallback defaults come after plain assignments, which already withhold
    # 'OPENAI_API_KEY=${OPENAI_API_KEY:-v}' whole. Plain assignment redaction
    # can introduce a bracketed marker after a mapping colon (including
    # annotations). Normalize those expressions in this same pass so repeated
    # sanitization does not change the result.
    return _redact_mapping_values(_redact_fallback_defaults(_redact_plain_assignments(text)))


def _opaque_option(option: str) -> bool:
    """An argv option whose last word names a credential ('--key', '--openai-key').

    As on a command line, only a value that looks like an opaque key is one.
    """
    name = option.lstrip("-")
    return not name.lower().startswith(("no-", "no_")) and _credential_name(name, numbered=True)


def _opaque_literal(value: Any) -> bool:
    """A string that looks like an opaque key."""
    return isinstance(value, str) and _credential_literal(value, positional=False)


def _record_has_secret_value(item: Mapping, *, environment: bool = False, extended: bool = False) -> bool:
    """Whether a name/value record's name marks its value as a credential.

    The established rule reads the whole name as a sensitive key. The
    ``extended`` one reads it as a setting (see ``_setting_level``), as the
    text passes read a record: 'OpenAI:Secret' withholds any value, and
    'OpenAIKey' or 'KEY1' a value that looks like an opaque key.
    """
    name = item.get("name") or item.get("Name") or item.get("key") or item.get("Key")
    if not isinstance(name, str):
        return False
    if not extended:
        return _sensitive_assignment_key(name) if environment else _sensitive_name(name)
    level = _setting_level(name, record=not environment)
    return _setting_value_withheld(level, item.get("value") or item.get("Value")) if level else False


def _credential_member(key: str, child: Any, *, group: bool) -> bool:
    """Whether the field ``key`` (lowercase) of a credential container holds credential material.

    A nested record or list does, whatever its name: a provider or name field
    can itself hold a credential record. A scalar does unless it is a
    descriptive label beside the secret ('provider', 'name', 'status'). An
    'id' is one in a container named for credentials ('credentials.id'),
    but names an identity under other credential names ('api_key.id', Azure
    'identity.authorization.objectId'), and a copied short ID must not taint
    otherwise independent caller labels or report identities.
    """
    if isinstance(child, (Mapping, list, tuple)):
        return True
    return key not in _CREDENTIAL_DESCRIPTORS or (group and key in _CREDENTIAL_GROUP_IDS)


class _Sanitizer:
    """One ``sanitize`` pass: the credential values it knows and its work budgets.

    ``discover`` collects the values of sensitive fields, secret-shaped
    records, credential options and (optionally) environment blocks;
    ``order`` ranks them for replacement; ``clean`` copies the input,
    withholding them from every other field as well. The established pass
    uses the established rules and text passes; the ``extended`` one, run
    on the established pass's copy, the rules added since (see ``sanitize``),
    and knows only the values those find.
    """

    def __init__(self, *, redact_short_secrets: bool, env_values_are_secrets: bool, extended: bool) -> None:
        self.redact_short_secrets = redact_short_secrets
        self.env_values_are_secrets = env_values_are_secrets
        self.extended = extended
        self.known: set[str] = set()
        # The same aliased object can occur both outside and inside an environment
        # block. Revisit it under the stricter naming policy, but still bound cycles.
        self.discovered: set[tuple[int, bool]] = set()
        self.ordered: list[str] = []
        self.work = 0
        self.cleaning: set[int] = set()
        self.cleaning_steps = 0

    def charge(self, amount: int) -> None:
        self.work += amount
        if self.work > _MAX_REDACTION_WORK:
            raise SanitizationLimitError("credential replacement work limit exceeded")

    def remember(self, child: Any) -> None:
        child = _plain(child)
        if isinstance(child, str) and child:
            if child != REDACTED and not _FINGERPRINT.fullmatch(child):
                self.known.add(child)
                # Library diagnostics often use repr(), which escapes secret
                # control characters. Remove both spellings in sibling fields.
                escaped = repr(child)[1:-1]
                if escaped != child:
                    self.known.add(escaped)

    def discover(self, item: Any, depth: int = 0, *, environment: bool = False) -> None:
        item = _plain(item)
        identity = (id(item), environment)
        if depth > 64 or (isinstance(item, _CONTAINERS) and identity in self.discovered):
            return
        if isinstance(item, _CONTAINERS):
            self.discovered.add(identity)
        # The extended pass knows only the values the added rules find: the
        # established pass already withheld and removed the others.
        established = not self.extended
        if isinstance(item, Mapping):
            if _record_has_secret_value(item, environment=environment, extended=self.extended):
                self.remember(item.get("value") or item.get("Value"))
            for key, child in item.items():
                name = str(key)
                if established and (_sensitive_key(name) or environment and _sensitive_assignment_key(name)):
                    self.remember(child)
                child_environment = environment or name.lower() in _ENVIRONMENT_KEYS
                if established and self.env_values_are_secrets and child_environment:
                    if isinstance(child, Mapping):
                        for env_value in child.values():
                            self.remember(env_value)
                    elif isinstance(child, list):
                        for entry in child:
                            if isinstance(entry, Mapping):
                                self.remember(entry.get("value") or entry.get("Value"))
                self.discover(child, depth + 1, environment=child_environment)
        elif isinstance(item, (set, frozenset)):
            for child in item:
                self.discover(child, depth + 1, environment=environment)
        elif isinstance(item, (list, tuple)):
            if self.extended:
                for index in _aws_configure_argv_secret_indices(item):
                    self.remember(item[index])
            previous: Any = None
            for child in item:
                # An argv option or value given as bytes is read as its text; the
                # established pass remembers only text otherwise, and a credential
                # after a bytes option was shown in a sibling field.
                option = _plain(previous) if isinstance(previous, (bytes, bytearray)) else previous
                value = _plain(child) if isinstance(child, (bytes, bytearray)) else child
                if isinstance(option, str) and option.startswith("-") and "=" not in option:
                    if (established and _sensitive_flag(option.lstrip("-"))) or (
                        self.extended and _opaque_option(option) and _opaque_literal(value)
                    ):
                        self.remember(child)
                elif established and isinstance(value, str) and value.startswith("-") and "=" in value:
                    # --api-key=VALUE: the value is a credential to remove from
                    # sibling fields, exactly as for a separate argv entry.
                    flag, _, flag_value = value.partition("=")
                    if _sensitive_flag(flag.lstrip("-")):
                        self.remember(flag_value)
                self.discover(child, depth + 1, environment=environment)
                previous = child

    def text_passes(self, text: str) -> str:
        """This pass's text passes: the established ones, or the extended ones on their result.

        Only the established passes check the text's size, as before. The
        extended ones read what the established passes made of a value within
        the limit, which markers can make longer than the limit ('pwd=ab'
        becomes 'pwd=[REDACTED]'), as ``sanitize_text`` does.
        """
        return _redact_extended(text) if self.extended else _sanitize_established(text)

    def order(self) -> None:
        """Rank the known values longest first for replacement."""
        if self.redact_short_secrets:
            # The structural pass can rewrite part of a whole configured secret.
            # Remember that spelling too so its other opaque fragments are removed.
            for value in tuple(self.known):
                self.charge(len(value))
                spelling = self.text_passes(value)
                if spelling and spelling != REDACTED:
                    self.known.add(spelling)
        self.ordered = sorted(self.known, key=len, reverse=True)

    def text(self, item: str) -> str:
        # The extended pass is charged only for removing the values it knows,
        # which the established pass did not know. Its text passes are linear,
        # as in sanitize_text, so a value in which it finds none cannot reach
        # a limit the established pass did not.
        self.charge(len(item) * (len(self.ordered) + (0 if self.extended else 1)))
        if self.redact_short_secrets and self.ordered:
            # Preserve recognizable token/URL structure before a short known
            # secret changes a scheme, hostname, or credential prefix. For
            # example, removing 'hooks' first would hide a Slack webhook URL
            # from the path-secret rules while retaining its capability token.
            self.charge(len(item))
            item = self.text_passes(item)
        for value in self.ordered:
            if self.redact_short_secrets:
                item = self.replace(item, value)
            elif len(value) < 8 and value in item:
                # Default report sanitization withholds the entire field for
                # short secrets; this avoids both expansion and partial leaks.
                return REDACTED
            else:
                # Keep line counts stable: excerpts index sanitized text by the
                # raw line number, and a multi-line secret would shift them.
                item = item.replace(value, REDACTED + "\n" * value.count("\n"))
        return self.text_passes(item)

    def replace(self, item: str, secret: str) -> str:
        """Replace each occurrence of a known ``secret`` in ``item`` within the size limit."""
        self.charge(3 * len(item))
        # A one-character secret must not recursively expand markers
        # inserted by a previous replacement (e.g. a password of 'R').
        # Only protect markers when the secret occurs inside one: a
        # longer real secret may itself contain the literal marker.
        parts = item.split(REDACTED) if secret in REDACTED else [item]
        occurrences = sum(part.count(secret) for part in parts)
        projected_chars = len(item) + occurrences * max(0, len(REDACTED) - len(secret))
        # The extended pass reads the established pass's text, which markers
        # can already have made longer than the limit. A replacement may not
        # grow a text past the limit, nor grow a text already past it.
        limit = max(_MAX_SANITIZATION_CHARS, len(item)) if self.extended else _MAX_SANITIZATION_CHARS
        if projected_chars > limit:
            raise SanitizationLimitError("credential replacement size limit exceeded")
        return REDACTED.join(part.replace(secret, REDACTED) for part in parts)

    def clean(self, item: Any, depth: int = 0) -> Any:
        self.cleaning_steps += 1
        if self.cleaning_steps > _MAX_SANITIZATION_NODES:
            raise SanitizationLimitError("sanitization work limit exceeded")
        if depth > 64:
            return REDACTED
        if isinstance(item, _CONTAINERS):
            if id(item) in self.cleaning:
                return REDACTED
            self.cleaning.add(id(item))
        try:
            return self.clean_value(item, depth)
        finally:
            if isinstance(item, _CONTAINERS):
                self.cleaning.discard(id(item))

    def clean_value(self, item: Any, depth: int) -> Any:
        item = _plain(item)
        if isinstance(item, Mapping):
            return self.clean_mapping(item, depth)
        if isinstance(item, (list, tuple)):
            sequence_out: list[Any] = []
            redact_next = opaque_next = False
            for child in item:
                if redact_next or (opaque_next and _opaque_literal(child)):
                    sequence_out.append(_redact_value(child))
                    redact_next = opaque_next = False
                else:
                    sequence_out.append(self.clean(child, depth + 1))
                    opaque_next = False
                    if isinstance(child, str) and child.startswith("-") and "=" not in child:
                        redact_next = _sensitive_flag(child.lstrip("-"))
                        opaque_next = self.extended and _opaque_option(child)
            return tuple(sequence_out) if isinstance(item, tuple) else sequence_out
        if isinstance(item, (set, frozenset)):
            members = [self.clean(child, depth + 1) for child in item]
            return frozenset(members) if isinstance(item, frozenset) else set(members)
        if isinstance(item, (bytes, bytearray)):
            # Decode tolerantly: json default=str would otherwise print the raw
            # bytes. Untouched content keeps its exact bytes.
            decoded = bytes(item).decode("utf-8", errors="replace")
            cleaned = self.text(decoded)
            if cleaned == decoded:
                return item
            return bytearray(cleaned.encode()) if isinstance(item, bytearray) else cleaned.encode()
        if isinstance(item, str):
            return self.text(item)
        return item

    def clean_mapping(self, item: Mapping, depth: int) -> dict[str, Any]:
        mapping_out: dict[str, Any] = {}
        for key, child in item.items():
            name = str(key)
            result: Any
            if _sensitive_key(name) or (
                name.lower() == "value" and _record_has_secret_value(item, extended=self.extended)
            ):
                result = _redact_value(child)
            elif name.lower() in _AUTH_CONTAINER_KEYS and isinstance(child, Mapping):
                result = {
                    self.text(str(k)): (
                        _redact_value(v)
                        if str(k).lower() in _AUTH_VALUE_KEYS and not isinstance(v, _CONTAINERS)
                        else self.clean(v, depth + 2)
                    )
                    for k, v in child.items()
                }
            elif name.lower() in _ENVIRONMENT_KEYS and isinstance(child, Mapping):
                result = {self.text(str(k)): _redact_value(v) for k, v in child.items()}
            elif name.lower() in _ENVIRONMENT_KEYS and isinstance(child, list):
                result = [self.clean_environment_entry(entry, depth) for entry in child]
            else:
                result = self.clean(child, depth + 1)
            mapping_out[self.text(name)] = result
        return mapping_out

    def clean_environment_entry(self, entry: Any, depth: int) -> Any:
        """One entry of an environment list: a record's value is withheld whatever its name."""
        if not isinstance(entry, Mapping):
            return _redact_value(entry)
        return {
            self.text(str(k)): _redact_value(v) if str(k).lower() == "value" else self.clean(v, depth + 1)
            for k, v in entry.items()
        }


class _NestedSanitizer(_Sanitizer):
    """The last ``sanitize`` pass: the scalar leaves nested in a container ``clean`` withholds whole.

    The value of a sensitive key or of a secret-named record can be a record
    or a list. Its leaves are credential material as well (see
    ``_credential_member``), so a copy in an unrelated field must not survive
    because the credential is nested. Those leaves also hold what the other
    passes read to withhold a credential beside them: an option name
    ('--webhook_secret'), a setting or record name ('PASSWORD_1'), a tag or a
    command word. Removed before those passes, such a leaf hid that context
    and the credential behind it was kept. This pass therefore runs last and
    adds no text rule: ``discover`` reads the input for the leaves, and
    ``clean`` removes them, with the spelling the text passes give them, from
    the copy the extended pass left, where they can only add markers. It is
    charged and bounded as the extended pass, which also reads a copy.
    """

    def __init__(self, *, redact_short_secrets: bool) -> None:
        super().__init__(
            redact_short_secrets=redact_short_secrets, env_values_are_secrets=False, extended=True
        )
        # An aliased object can occur both outside and inside a credential
        # container. Revisit it under the stricter parent, but still bound cycles.
        self.containers: set[tuple[int, bool, bool, bool]] = set()

    def discover(
        self,
        item: Any,
        depth: int = 0,
        *,
        environment: bool = False,
        credential: bool = False,
        credential_group: bool = False,
    ) -> None:
        """Remember the leaves of the credential containers in ``item``.

        ``credential`` marks a container that ``clean`` withholds whole: the
        value of a sensitive key, of a record named for a secret by the
        established or the added rules, or a member of such a container.
        ``credential_group`` marks a container named for credentials.
        """
        item = _plain(item)
        identity = (id(item), environment, credential, credential_group)
        if depth > 64 or (isinstance(item, _CONTAINERS) and identity in self.containers):
            return
        if isinstance(item, _CONTAINERS):
            self.containers.add(identity)
        if isinstance(item, Mapping):
            named_secret = _record_has_secret_value(item, environment=environment) or (
                _record_has_secret_value(item, environment=environment, extended=True)
            )
            for key, child in item.items():
                name = str(key)
                lower_name = name.lower()
                key_sensitive = _sensitive_key(name) or environment and _sensitive_assignment_key(name)
                # 'credentials.id' can itself be opaque secret material;
                # 'api_key.id' names an identity (see _credential_member).
                child_group = credential_group or (
                    key_sensitive
                    and _KEY_NORMALISE.sub("", lower_name).endswith(("credential", "credentials"))
                )
                # A record's value under any casing ('VALUE'), which clean
                # withholds, and the members of a credential container.
                member = (named_secret and lower_name == "value") or (
                    credential and _credential_member(lower_name, child, group=child_group)
                )
                if member:
                    self.remember(child)
                self.discover(
                    child,
                    depth + 1,
                    environment=environment or lower_name in _ENVIRONMENT_KEYS,
                    credential=key_sensitive or member,
                    credential_group=child_group,
                )
        elif isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                if credential:
                    self.remember(child)
                self.discover(
                    child,
                    depth + 1,
                    environment=environment,
                    credential=credential,
                    credential_group=credential_group,
                )

    def order(self) -> None:
        """Rank the known values, and the spellings the text passes give them, longest first.

        The copy this pass reads went through every text pass, which can have
        withheld part of a known value ('prefix sk-proj-... suffix'). Remove
        that spelling too, so the value's other fragments are not kept.
        """
        for value in tuple(self.known):
            self.charge(len(value))
            spelling = _redact_extended(_sanitize_established(value))
            if spelling and spelling != REDACTED:
                self.known.add(spelling)
        self.ordered = sorted(self.known, key=len, reverse=True)

    def text(self, item: str) -> str:
        """``item`` without the known values; no text pass runs again.

        The markers the earlier passes left are not searched: a value found
        only inside one ('ACT') does not occur in the field.
        """
        self.charge(len(item) * len(self.ordered))
        for value in self.ordered:
            if self.redact_short_secrets:
                item = self.replace(item, value)
                continue
            parts = item.split(REDACTED) if value in REDACTED else [item]
            if len(value) < 8 and any(value in part for part in parts):
                return REDACTED
            # Keep line counts stable, as _Sanitizer.text does.
            marker = REDACTED + "\n" * value.count("\n")
            item = REDACTED.join(part.replace(value, marker) for part in parts)
        return item


def sanitize(value: Any, *, redact_short_secrets: bool = False, env_values_are_secrets: bool = True) -> Any:
    """Return a sanitized JSON-like copy, preserving nonsecret fields and types.

    Environment variable values are omitted regardless of name. Lists additionally
    recognize argv pairs, so ``["--token", "opaque-value"]`` is safe to retain.
    Known credential values are also removed from other fields in the same object.
    Short credentials withhold a matching field by default. Diagnostics can opt
    into bounded substring replacement to retain surrounding diagnostic context.

    ``env_values_are_secrets`` controls whether every environment value is also
    treated as a credential to remove from *sibling* fields. That is right for
    tool and agent configuration, where an ``env`` block is where tokens live and
    a source excerpt can repeat them. A provider inventory record's environment
    holds mostly ordinary settings (``STAGE=prod``, ``WORKERS=4``, a region), and
    removing those from sibling fields destroys resource identities. Producers of
    such records pass ``False``; values under sensitive names, secret-record
    shapes and recognizable credential formats are still removed everywhere.

    Two passes run, as in ``sanitize_text``: the established rules copy the
    value, then the rules added since (settings in name/value records,
    opaque values of argv options named for a credential) copy that copy,
    so they only withhold more than the established pass does. The limits
    apply to the established pass as before. The second pass reads text the
    first one produced, which markers can make longer than the size limit,
    so it checks neither that text nor its length; it is charged only for
    removing the values the added rules find from the other fields, and only
    that removal can reach a limit the established pass did not.

    A third pass then removes the leaves nested in a withheld credential
    container from every other field of that copy (see ``_NestedSanitizer``).
    It runs last, so it too only adds markers: a leaf can be an option or
    setting name the first two passes read to withhold the value after it.
    The values the established pass knew are already removed everywhere.
    """
    _check_sanitization_structure(value)
    passes = [
        _Sanitizer(
            redact_short_secrets=redact_short_secrets,
            env_values_are_secrets=env_values_are_secrets,
            extended=extended,
        )
        for extended in (False, True)
    ]
    copy = value
    for sanitizer in passes:
        sanitizer.discover(copy)
        sanitizer.order()
        copy = sanitizer.clean(copy)
    nested = _NestedSanitizer(redact_short_secrets=redact_short_secrets)
    nested.discover(value)
    nested.known -= passes[0].known
    if not nested.known:
        return copy
    nested.order()
    return nested.clean(copy)


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
        # A set is read as a list of its members (see ``_plain``), and a member
        # can itself be a tuple or a set: each member is costed as a list item.
        if not isinstance(item, _CONTAINERS):
            if isinstance(item, (bytes, bytearray, memoryview)):
                return 1, len(item), 1
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


def policy_token() -> tuple[Any, ...]:
    """Identify the redaction rules and limits currently in force.

    State verified clean by one policy is not clean under another. Callers
    that cache a verified-clean digest key it by this value, so a rule set
    replaced at runtime (for example a patched sensitive-name list or a
    lowered limit) is applied on their next pass instead of being skipped.
    The tuple holds the live policy objects, which makes an unchanged policy
    compare by identity; mutable collections are snapshotted by value. Every
    binding in every redaction module counts, including the names one imports
    from another, so a rule replaced in any single module changes the token.
    """
    return tuple(_policy_value(namespace[name]) for namespace, name in _POLICY_BINDINGS)


def _policy_value(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return frozenset(value)
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, dict):
        return tuple(value.items())
    return value


class _RedactionNamespace(types.ModuleType):
    """This module's type: the redaction modules read and written as one namespace.

    A name that one of them binds reads through this module, and writing a
    name here writes it in every module that binds it, so every pass sees the
    replacement, as when they all lived in this module. A name deleted here
    is deleted from each of them, and returns to each when set again. Classes
    are shared objects, so a patched method reaches every pass without this.
    """

    # The modules this one drives. Each name is defined in exactly one of them.
    # (Class attributes: module objects are no rule, and the policy token of a
    # finding is copied with it.)
    _modules: tuple[types.ModuleType, ...] = (
        redaction_rules,
        redaction_formats,
        redaction_statements,
        redaction_assignments,
        redaction_calls,
        redaction_commands,
        redaction_markup,
    )
    # The modules, this one included, that bind each name once all are loaded.
    _binders: dict[str, tuple[types.ModuleType, ...]] = {}

    def __getattr__(self, name: str) -> Any:
        for module in self._binders.get(name, ()):
            namespace = vars(module)
            if name in namespace:
                return namespace[name]
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        for module in self._binders.get(name, (self,)):
            if module is self:
                super().__setattr__(name, value)
            else:
                setattr(module, name, value)

    def __delattr__(self, name: str) -> None:
        binders = [module for module in self._binders.get(name, (self,)) if name in vars(module)]
        if not binders:
            raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")
        for module in binders:
            if module is self:
                super().__delattr__(name)
            else:
                delattr(module, name)


def _is_policy(value: Any) -> bool:
    """Rules, patterns and limits, plus the helpers the redaction modules define."""
    if isinstance(value, (str, int, float, tuple, list, dict, set, frozenset, re.Pattern)):
        return True
    return isinstance(value, types.FunctionType) and value.__module__ in _POLICY_MODULES


def _binding_modules() -> dict[str, tuple[types.ModuleType, ...]]:
    """The modules, this one included, that bind each name."""
    modules = (sys.modules[__name__], *_RedactionNamespace._modules)
    names = {name for module in modules for name in vars(module) if not name.startswith("__")}
    return {name: tuple(module for module in modules if name in vars(module)) for name in names}


_POLICY_MODULES = frozenset({__name__, *(module.__name__ for module in _RedactionNamespace._modules)})
# Every module-level rule, pattern, limit and helper that this module or one
# it drives binds, computed once all are bound: a newly added policy constant
# is covered without registration.
_POLICY_BINDINGS: tuple[tuple[dict[str, Any], str], ...] = tuple(
    (vars(module), name)
    for module in (sys.modules[__name__], *_RedactionNamespace._modules)
    for name, value in sorted(vars(module).items())
    if not name.startswith("__") and _is_policy(value)
)


_RedactionNamespace._binders = _binding_modules()
# From here on, setting or deleting a name on this module writes every module
# that binds it. Patch rules through shadowscan.utils.redaction only: a name
# set on a redaction_* module directly changes that module alone, and the
# other passes keep the object they imported, so a patched rule or limit would
# apply to some passes and silently not to others.
sys.modules[__name__].__class__ = _RedactionNamespace
