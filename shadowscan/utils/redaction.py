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

import hashlib
import re
import sys
import types
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
from shadowscan.utils.redaction_assignments import (
    _redact_added_assignments,
    _redact_compact_colons,
    _redact_fallback_defaults,
    _redact_mapping_values,
    _redact_opaque_assignments,
    _redact_plain_assignments,
    _redact_yaml_multiline_values,
)
from shadowscan.utils.redaction_calls import _redact_auth_pairs, _redact_credential_calls
from shadowscan.utils.redaction_commands import (
    _cli_secret_option,
    _redact_command_credentials,
    _redact_cookie_headers,
    _redact_environment_commands,
    _redact_extended_options,
    _redact_user_secrets,
)
from shadowscan.utils.redaction_formats import (
    _ADDED_PEM,
    _AUTH,
    _JWT,
    _PEM,
    _SECRET_TOKEN,
    _URL,
    _redact_added_formats,
    _sanitize_url,
    _sanitize_url_fields,
)
from shadowscan.utils.redaction_markup import (
    _redact_markup_credentials,
    _redact_markup_settings,
    _redact_name_value_pairs,
    _redact_record_settings,
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
    _sensitive_key,
    _setting_level,
    _setting_value_withheld,
)
from shadowscan.utils.redaction_statements import _redact_python_assignments

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
# Values ``sanitize`` descends into: sets and frozensets are copied as lists
# are (keeping their type), without the argv pairs that order gives a list.
_CONTAINERS = (Mapping, list, tuple, set, frozenset)


def credential_id(value: Any) -> str:
    """Stable opaque identity for raw credentials; never retain prefix/suffix."""
    s = str(value)
    if _FINGERPRINT.fullmatch(s):
        return s
    return "credential:sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def sanitize_text(text: str) -> str:
    """Redact recognizable credentials, assignments, auth headers and URL secrets.

    Context-named values are also withheld: XML elements and attributes,
    name/value records, command-line options, environment commands, basic
    authentication pairs, literals passed to credential-named callees,
    literal fallback defaults of credential names and cookie headers.

    The established passes run first, with the rules and in the order they
    had before the extended passes were added; the extended passes then read
    what they leave. Each pass reads the text the passes before it leave, so
    a rule that withheld more in an early pass would change what the later
    passes see: a value withheld together with the name glued after it
    ('v#password = ...') hides that name from the assignment rules, and the
    credential after the name is no longer withheld. Run last, an added rule
    only adds markers, and whatever the established passes withhold stays
    withheld. Armored PGP private key blocks are the one added rule applied
    first, next to the PEM keys, and only where the result shows nothing the
    established order withholds (see ``_withhold_key_blocks``).
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


def _redact_extended(text: str) -> str:
    """The rules added to the established passes, on the text those leave (see ``sanitize_text``).

    Settings in markup and name/value records (hierarchical and
    credential-like names), 'dotnet user-secrets set', numbered names and
    YAML values under credential-like names, and the options and option
    values only the added rules read (opaque values of options named for a
    credential, short credential names such as '--pat', quoted values that
    never close). The options come after the others: withheld earlier, a
    value glued to a following name ('--key v#openaiKey = ...') would hide
    that name from them. Then come the values that run on past where the
    established rules end one: added query fields, cookie headers, the rest
    of an unquoted value past a glued ';', assignments with escaped quotes
    and 'api-key:value' with no space; and last the added formats (PGP
    private keys, tokens next to non-Latin text, Fireworks AI keys). A marker
    these passes leave after a mapping colon is then quoted, as the
    established passes end, and where a cookie header or a 'name:value' was
    withheld, the statement rules read the text once more, so repeated
    sanitization does not change the result.
    """
    text = _redact_markup_settings(text)
    text = _redact_record_settings(text)
    text = _redact_user_secrets(text)
    text = _redact_opaque_assignments(text, extended=True)
    text = _redact_fallback_defaults(text, extended=True)
    text = _redact_extended_options(text)
    # The added values run on past where the established rules end a value
    # (a query field, a glued ';', a whole header line), so they come after
    # every pass that reads a name. A cookie header comes first: the rest of
    # its line holds the other cookies, past any ';' the others stop at.
    text = _URL.sub(_sanitize_url_fields, text)
    headers = _redact_cookie_headers(text)
    reshaped = headers != text
    text = _redact_python_assignments(headers, glued=True)
    text = _redact_added_assignments(text)
    compact = _redact_compact_colons(text)
    reshaped = reshaped or compact != text
    # Formats need no context, but a token glued to a name hides it, so the
    # formats added since come last of all.
    result = _redact_mapping_values(_redact_added_formats(compact))
    if not reshaped:
        return result
    # A cookie header withheld to the end of its line, or a withheld
    # 'name:value', changes the statement around it for the statement rules:
    # 'get(url, cookie=a; b=v' loses the ';' that ended the argument, and
    # 'api_key:a=1; sid=v' becomes 'api_key:"[REDACTED]"; sid=v', an
    # annotation they read on past the ';'; a bare marker left in an
    # argument ('get(url, cookie=[REDACTED]') is one they quote. What they
    # would change there on the next sanitization is changed now.
    return _redact_mapping_values(_redact_python_assignments(result))


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
    text = _redact_name_value_pairs(text)
    text = _redact_command_credentials(text)
    text = _redact_environment_commands(text)
    text = _redact_auth_pairs(text)
    text = _redact_credential_calls(text)
    text = _redact_python_assignments(text)
    text = _redact_yaml_multiline_values(text)
    text = _redact_mapping_values(text)
    text = _redact_opaque_assignments(text)
    # The text before a token in its run ('x-' of 'x-eyJ...') is kept.
    text = _JWT.sub(r"\g<prefix>" + REDACTED, text)
    text = _SECRET_TOKEN.sub(REDACTED, text)
    # The scheme's whitespace can span lines; keep them so excerpt lines stay aligned.
    text = _AUTH.sub(lambda m: m.group(1) + " " + REDACTED + "\n" * m.group().count("\n"), text)
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


def _decoded(item: bytes | bytearray) -> str:
    """Bytes as text, decoded tolerantly: undecodable bytes become U+FFFD."""
    return bytes(item).decode("utf-8", errors="replace")


def _extended_argv_value(option: str, value: Any) -> bool:
    """Whether the added rules withhold ``value``, the argv element after ``option``."""
    return _cli_secret_option(option) or (_opaque_option(option) and _opaque_literal(value))


def _inline_option_value(item: Any) -> str | None:
    """The credential an argv element passes inline ('--api-key=v', '--pat=v'), if any.

    Option names decide as they do for a separate argv value: a sensitive
    name, a short credential name, or a name whose last word names a
    credential when the value looks like an opaque key.
    """
    if isinstance(item, (bytes, bytearray)):
        item = _decoded(item)
    if not isinstance(item, str) or not item.startswith("-") or "=" not in item:
        return None
    option, _, value = item.partition("=")
    if _sensitive_key(option.lstrip("-")) or _cli_secret_option(option):
        return value
    return value if _opaque_option(option) and _opaque_literal(value) else None


def _argv_bytes_value(option: Any, value: Any) -> bool:
    """Whether ``value``, the argv element after ``option``, is a credential only the input shows.

    The first two passes read an option and its value as text: they withhold
    a bytes value after a text option in place but do not remember it, and do
    not read a bytes option at all. Option names decide as they do there.
    """
    if not isinstance(option, (bytes, bytearray)) and not isinstance(value, (bytes, bytearray)):
        return False
    if isinstance(option, (bytes, bytearray)):
        option = _decoded(option)
    if not isinstance(option, str) or not option.startswith("-") or "=" in option:
        return False
    text = _decoded(value) if isinstance(value, (bytes, bytearray)) else value
    return _sensitive_key(option.lstrip("-")) or _extended_argv_value(option, text)


def _environment_values(block: Any) -> list[Any]:
    """The values of an environment block: a mapping's values, or the values of a list's records."""
    if isinstance(block, Mapping):
        return list(block.values())
    if isinstance(block, list):
        return [entry.get("value") or entry.get("Value") for entry in block if isinstance(entry, Mapping)]
    return []


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
        return _sensitive_assignment_key(name) if environment else _sensitive_key(name)
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
    if isinstance(child, _CONTAINERS):
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
        if isinstance(child, (bytes, bytearray)):
            if not self.extended:
                # Known before the established text passes, a value they did not
                # know before would be removed from a sibling ahead of them and
                # could hide a name they read there; later passes remember it.
                return
            child = _decoded(child)
        if isinstance(child, str) and child:
            if child != REDACTED and not _FINGERPRINT.fullmatch(child):
                self.known.add(child)
                # Library diagnostics often use repr(), which escapes secret
                # control characters. Remove both spellings in sibling fields.
                escaped = repr(child)[1:-1]
                if escaped != child:
                    self.known.add(escaped)

    def discover(self, item: Any, depth: int = 0, *, environment: bool = False) -> None:
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
                    for env_value in _environment_values(child):
                        self.remember(env_value)
                self.discover(child, depth + 1, environment=child_environment)
        elif isinstance(item, (list, tuple)):
            previous = None
            for child in item:
                if isinstance(previous, str) and previous.startswith("-"):
                    if (established and _sensitive_key(previous.lstrip("-"))) or (
                        self.extended and _extended_argv_value(previous, child)
                    ):
                        self.remember(child)
                self.discover(child, depth + 1, environment=environment)
                previous = child
        elif isinstance(item, (set, frozenset)):
            for child in item:
                self.discover(child, depth + 1, environment=environment)

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
                        redact_next = _sensitive_key(child.lstrip("-")) or (
                            self.extended and _cli_secret_option(child)
                        )
                        opaque_next = self.extended and _opaque_option(child)
            return tuple(sequence_out) if isinstance(item, tuple) else sequence_out
        if isinstance(item, (set, frozenset)):
            members = [self.clean(child, depth + 1) for child in item]
            return frozenset(members) if isinstance(item, frozenset) else set(members)
        if isinstance(item, (bytes, bytearray)):
            # json's default=str would otherwise print the raw bytes. Content
            # the text passes leave alone keeps its exact bytes.
            decoded = _decoded(item)
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

    The credential an argv element passes inline ('--api-key=v') is read
    here too: the earlier passes withhold it in place, reading their own
    copy, so only the input still shows v to remove from other fields. So
    are the bytes values the established pass does not remember (see
    ``_Sanitizer.remember``): an argv value after a credential option, or
    after an option given as bytes (see ``_argv_bytes_value``), and, when
    ``env_values_are_secrets``, an environment value.
    """

    def __init__(self, *, redact_short_secrets: bool, env_values_are_secrets: bool = False) -> None:
        super().__init__(
            redact_short_secrets=redact_short_secrets,
            env_values_are_secrets=env_values_are_secrets,
            extended=True,
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
                # Bytes under a sensitive key: the established pass knows only text.
                if member or (key_sensitive and isinstance(child, (bytes, bytearray))):
                    self.remember(child)
                child_environment = environment or lower_name in _ENVIRONMENT_KEYS
                if self.env_values_are_secrets and child_environment:
                    # The established pass remembers the text values alone.
                    for env_value in _environment_values(child):
                        if isinstance(env_value, (bytes, bytearray)):
                            self.remember(env_value)
                self.discover(
                    child,
                    depth + 1,
                    environment=child_environment,
                    credential=key_sensitive or member,
                    credential_group=child_group,
                )
        elif isinstance(item, (list, tuple, set, frozenset)):
            previous: Any = None
            for child in item:
                if credential:
                    self.remember(child)
                elif isinstance(item, (list, tuple)):
                    # '--api-key=v' in an argv list: the earlier passes withhold
                    # it in place, read from their copy; here it is read from
                    # the input, so a copy of v in another field goes as well.
                    inline = _inline_option_value(child)
                    if inline is not None:
                        self.remember(inline)
                    elif _argv_bytes_value(previous, child):
                        self.remember(child)
                previous = child
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
    Sets and frozensets keep their type; bytes are decoded tolerantly, sanitized
    and returned as bytes (content the text passes leave alone keeps its bytes).
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
    nested = _NestedSanitizer(
        redact_short_secrets=redact_short_secrets, env_values_are_secrets=env_values_are_secrets
    )
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
        if not isinstance(item, _CONTAINERS):
            return 1, len(item) if isinstance(item, (str, bytes, bytearray)) else 0, 1
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
