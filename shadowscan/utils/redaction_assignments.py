"""Sensitive values in assignments, mappings and fallback defaults inside text.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. ``name=value`` and ``name: value`` pairs under sensitive names, whole
mapping expressions and indented YAML blocks under sensitive keys, opaque
literals given to names whose last word names a credential, and literal
defaults of credentials read from the environment. After the established
passes, pairs written with escaped quotes (JSON inside a string literal),
unquoted values that hold a ';' and ``name:value`` under header and password
names are read as well.
"""

from __future__ import annotations

import re

from shadowscan.utils.redaction_rules import (
    _CLI_WORD,
    _FINGERPRINT,
    _GLUED_SEMICOLON,
    _KEY_NORMALISE,
    REDACTED,
    SanitizationLimitError,
    _blanks_before,
    _credential_literal,
    _credential_name,
    _interpolated,
    _name_before,
    _redact_value,
    _sensitive_assignment_key,
    _withhold_spans,
)

# A key must be consumed in full: truncating it to a fixed number of characters
# can leave an opaque credential in evidence when the sensitive suffix follows
# that limit. The left boundary includes every character accepted by the key
# lexer (including '.' and '-'), preventing retries at interior key segments.
# Text size and redaction work are bounded separately below. An unquoted
# key's colon stays on its line: a YAML parent ('openai:') must not consume the
# nested sensitive key on the next line as its own value. A quoted key may also
# be assigned with '=' (PowerShell hashtables, TOML quoted keys). An unquoted
# value stops at ']' unless that ']' closes a marker: cut inside the marker, a
# nested sensitive assignment ('Value: a.api_key=[REDACTED]') withheld
# '[REDACTED' again and grew the marker by one ']' on every pass. After such a
# marker it also stops at a query separator: 'sv=1&sig=[REDACTED]&Authorization:'
# must leave the next parameter's name to be read with its own value.
_ASSIGNMENT_KEY = r"(?P<key>(?<![\w.-])[A-Za-z_][A-Za-z0-9_.-]*)"
_ASSIGNMENT = re.compile(
    _ASSIGNMENT_KEY + r"(?P<sep>[\"']\s*:\s*|[\"'][ \t]*=(?!=)[ \t]*|\s*=\s*|:[ \t]+|:[ \t]*(?=[\"']))"
    r"(?P<value>\[REDACTED\]|\"[^\"\r\n]*\"|'[^'\r\n]*'"
    r"|[^\s,;\}\]\)\"']+(?:(?<=\[REDACTED)\][^\s,;\}\]\)\"'&]*)*)"
)
_MAPPING_VALUE = re.compile(
    r"(?<![\w.-])(?:(?P<quote>[\"'])(?P<quoted>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_.-]*))[ \t]*:[ \t]*"
    r"(?P<value>[\"'`\[\{(])"
)
_YAML_MAPPING_LINE = re.compile(
    r"^(?P<prefix>[ \t]*(?:-[ \t]+)*)(?:(?P<quote>[\"'])"
    r"(?P<quoted>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_.-]*))[ \t]*:[ \t]*"
    r"(?P<value>[^\r\n]*)",
    re.MULTILINE,
)
_YAML_CONTINUATION_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n|\Z)")


def _redact_yaml_multiline_values(text: str) -> str:
    """Withhold indented sensitive YAML values before line-based excerpting.

    Literal/folded blocks and continued plain scalars can contain opaque
    credentials with no recognizable token prefix. Consume their indentation
    boundary once, without loading or executing the untrusted source. Preserve
    newline counts for evidence locations and the following peer mapping.
    """
    pieces: list[str] = []
    cursor = 0
    for match in _YAML_MAPPING_LINE.finditer(text):
        key = match.group("quoted") or match.group("plain")
        if match.start() < cursor or not _sensitive_assignment_key(key):
            continue
        value = match.group("value").strip()
        # Quoted and flow-style values are consumed by the mapping lexer.
        if value.startswith(('"', "'", "`", "[", "{", "(")):
            continue
        start = match.start("value")
        end = match.end()
        position = end
        if text.startswith("\r\n", position):
            position += 2
        elif text.startswith(("\n", "\r"), position):
            position += 1
        else:
            continue
        indent = len(match.group("prefix").expandtabs(8))
        has_continuation = False
        while position < len(text):
            line = _YAML_CONTINUATION_LINE.match(text, position)
            assert line is not None
            raw = line.group(0)
            content = raw.rstrip("\r\n")
            whitespace = len(content) - len(content.lstrip(" \t"))
            if content.strip() and len(content[:whitespace].expandtabs(8)) <= indent:
                break
            has_continuation = has_continuation or bool(content.strip())
            end = line.end()
            position = end
        if not has_continuation:
            continue
        pieces.append(text[cursor:start])
        pieces.append('"' + REDACTED + '"' + "\n" * text[start:end].count("\n"))
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


def _mapping_expression_end(text: str, start: int) -> int:
    """Find a mapping value's delimiter without evaluating source code.

    Quoted scalars, escaped/doubled quotes, concatenations and nested containers
    are consumed in full. Malformed expressions are withheld through EOF.
    Values are visited once and nesting is bounded before allocating more work.
    """
    position = start
    brackets: list[str] = []
    while position < len(text):
        char = text[position]
        if char in "\"'`":
            delimiter = char
            if char != "`" and text.startswith(char * 3, position):
                delimiter = char * 3
            position += len(delimiter)
            while position < len(text):
                if text[position] == "\\":
                    position += 2
                elif text.startswith(delimiter, position):
                    # YAML escapes a single quote by doubling it. Consuming
                    # adjacent Python literals here is equally conservative.
                    if delimiter == "'" and text.startswith("''", position):
                        position += 2
                        continue
                    position += len(delimiter)
                    break
                else:
                    position += 1
            else:
                return len(text)
            continue
        if char in "([{":
            if len(brackets) >= 64:
                raise SanitizationLimitError("mapping expression nesting limit exceeded")
            brackets.append(char)
        elif char in ")]}":
            if not brackets:
                return position
            if brackets.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                return len(text)
        elif not brackets and char in ",;\r\n#":
            return position
        position += 1
    return len(text)


def _redact_mapping_values(text: str) -> str:
    """Withhold full sensitive mapping expressions before excerpt shortening."""
    pieces: list[str] = []
    cursor = 0
    for match in _MAPPING_VALUE.finditer(text):
        key = match.group("quoted") or match.group("plain")
        if match.start() < cursor or not _sensitive_assignment_key(key):
            continue
        start = match.start("value")
        end = _mapping_expression_end(text, start)
        raw = text[start:end]
        bare = raw.strip()
        if len(bare) > 1 and bare[0] in "\"'" and bare[-1] == bare[0] and _FINGERPRINT.fullmatch(bare[1:-1]):
            continue
        pieces.append(text[cursor:start])
        trailing_space = raw[len(raw.rstrip(" \t")) :]
        pieces.append('"' + REDACTED + '"' + "\n" * raw.count("\n") + trailing_space)
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# Names whose last word names a credential (openaiKey, OPENAI-KEY, dbPass,
# stripe.secretKey, key) also name sort keys, page tokens and cache keys, so
# only a literal that looks like an opaque key is withheld from them. An
# unquoted value counts after '=' and, in the extended pass, as a YAML value
# after ': ' ('key:v' is a scalar or a URL part); a word-like one is an
# identifier or a type ('key: Ed25519PrivateKey'). Both patterns below start
# at the separator, which is rarer than a name, and the name before it is
# read backwards.
_OPAQUE_VALUE = re.compile(
    r"(?P<separator>:=|=(?![=>~])|:(?![:=]))[ \t]*"
    r"(?:(?P<prefix>[rRbBuUfF]{1,2}|@)?(?P<quote>[\"'`])(?P<quoted>[^\"'`\r\n]{8,})(?P=quote)"
    r"|(?P<bare>[A-Za-z0-9+/_.~-]{8,}={0,2})(?![^\s,;)}\]]))"
)
# An unquoted value made of words is an identifier (key = Ed25519PrivateKey).
# Random keys almost always have a one- or two-letter lowercase run. The
# value is read as runs of one character class, never as a pattern of
# repeated words: '(?:[A-Z][a-z]+|[a-z]{3,}|[A-Z]{2,}|[0-9]+|_)+' split a
# long run of one class every possible way before it failed, so
# 'key: ' + 'a' * 56 + '.' took minutes.
_WORD_RUN = re.compile(r"[A-Z]+|[a-z]+|[0-9_]+|[^A-Za-z0-9_]")


def _wordy(value: str) -> bool:
    """Whether ``value`` is made of words, digits and underscores, as identifiers are.

    A word is capitalized ('Private'), lowercase of three letters or more
    ('key') or uppercase of two or more ('API'). A lowercase run shorter than
    three letters therefore needs the capital before it, which an uppercase
    run can give unless that leaves it one capital ('ABcd' is not a word; 'Ab',
    'ABCd' and 'ABcde' are), and an uppercase run needs two letters unless a
    lowercase run follows it. Reads the value once.
    """
    runs = _WORD_RUN.findall(value)
    for index, run in enumerate(runs):
        if "a" <= run[0] <= "z":
            before = runs[index - 1] if index else ""
            if len(run) < 3 and not ("A" <= before[0:1] <= "Z" and len(before) != 2):
                return False
        elif "A" <= run[0] <= "Z":
            after = runs[index + 1] if index + 1 < len(runs) else ""
            if len(run) < 2 and not "a" <= after[0:1] <= "z":
                return False
        elif not ("0" <= run[0] <= "9" or run[0] == "_"):
            return False
    return bool(runs)


# A sensitive key whose colon ends its line, then a lone word on the next,
# unindented line ('token:\n<value>' in notes and error text). An indented
# line is YAML nesting, which the multiline pass handles.
_NEXT_LINE_VALUE = re.compile(r":[ \t]*\r?\n(?P<value>[^\s\"'#()\[\]{}<>,;]+)[ \t]*(?=\r?\n|\Z)")
_NEXT_LINE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")


def _assigned_name(text: str, separator: int, *, numbered: bool = False) -> str:
    """The name assigned at ``separator``, past a closing quote and a simple type annotation.

    A '?' before the separator is a nullable type ('String? =') or Make's '?='.
    ``numbered`` is passed on to ``_credential_name``.
    """
    end = _blanks_before(text, separator)
    if end > 0 and text[end - 1] in "\"'":
        end -= 1
    elif end > 0 and text[end - 1] == "?":
        end = _blanks_before(text, end - 1)
    name = _name_before(text, end, "_$.-")
    colon = _blanks_before(text, end - len(name))
    typed = colon > 0 and text[colon - 1] == ":" and (colon < 2 or text[colon - 2] != ":")
    if name and typed and not _credential_name(name, numbered=numbered):
        return _name_before(text, _blanks_before(text, colon - 1), "_$.-")  # 'openaiKey: string = "..."'
    return name


def _redact_opaque_assignments(text: str, *, extended: bool = False) -> str:
    """Withhold opaque literals given to credential-like names, and a lone value after 'token:'.

    The ``extended`` pass, which runs after every established pass, also
    reads a name numbered by trailing digits ('KEY1=...') and an unquoted
    YAML value ('openaiKey: ...'); the lone value after 'token:' is the
    established pass's alone.
    """
    spans: list[tuple[int, int]] = []
    for match in _OPAQUE_VALUE.finditer(text):
        name = _assigned_name(text, match.start(), numbered=extended)
        if not _credential_name(name, numbered=extended):
            continue
        group = "quoted" if match.group("quoted") is not None else "bare"
        value = match.group(group)
        if group == "bare" and (
            (
                match.group("separator") == ":"
                and not (extended and text.startswith((" ", "\t"), match.end("separator")))
            )
            or _wordy(value)
        ):
            continue
        if match.group("quote") and _interpolated(match.group("prefix") or "", match.group("quote"), value):
            continue  # interpolated text is assembled elsewhere
        if _credential_literal(value, positional=False):
            spans.append(match.span(group))
    if extended:
        return _withhold_spans(text, spans)
    for match in _NEXT_LINE_VALUE.finditer(text):
        key = _name_before(text, match.start(), "_.-")
        if not _NEXT_LINE_KEY.fullmatch(key) or not _sensitive_assignment_key(key):
            continue
        value = match.group("value")
        if not _CLI_WORD.fullmatch(value) and _credential_literal(value, positional=True):
            spans.append(match.span("value"))
    return _withhold_spans(text, spans)


# A literal default for a credential read from the environment or a
# credential-named field: 'process.env.OPENAI_API_KEY || "v"',
# 'Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY") ?? "v"',
# 'os.getenv("OPENAI_API_KEY") or "v"', 'getenv("X") ?: "v"' and the shell's
# '${OPENAI_API_KEY:-v}'. The pattern starts at the operator; the name before
# it is a name, or the short string literal that ends a call or subscript.
# Every operator starts with a literal, which lets the regex engine skip
# ahead quickly; the word boundary before 'or' is checked after it.
_FALLBACK_DEFAULT = re.compile(
    r"(?:\|\||\?[?:]|or(?<![\w.$]or))[ \t]*(?P<prefix>[rRbBuUfF]{1,2}|@)?(?P<quote>[\"'`])"
    r"(?P<value>[^\"'`\r\n]*)(?P=quote)"
)
_SHELL_DEFAULT = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*):?[-=](?P<value>[^{}\r\n]*)\}")
_FALLBACK_NAME_LITERAL = 256


def _fallback_name(text: str, operator: int) -> str:
    """The name whose value the operator at ``operator`` falls back from."""
    end = _blanks_before(text, operator)
    if end == 0 or text[end - 1] not in ")]":
        return _name_before(text, end, "_$.").rsplit(".", 1)[-1]
    end = _blanks_before(text, end - 1)
    if end == 0 or text[end - 1] not in "\"'":
        return ""
    opening = text.rfind(text[end - 1], max(0, end - 1 - _FALLBACK_NAME_LITERAL), end - 1)
    return text[opening + 1 : end - 1] if opening >= 0 else ""


def _redact_fallback_defaults(text: str, *, extended: bool = False) -> str:
    """Withhold literal defaults given to credential names by fallback operators.

    A lowercase word ('default', 'none') and the values a credential
    literal never is (placeholders, URLs, environment names) stay visible.
    The ``extended`` pass, which runs after every established pass, also
    reads a name numbered by trailing digits ('process.env.KEY1 || "..."').
    """
    spans: list[tuple[int, int]] = []
    for match in _FALLBACK_DEFAULT.finditer(text):
        name = _fallback_name(text, match.start())
        value = match.group("value")
        if not name or _interpolated(match.group("prefix") or "", match.group("quote"), value):
            continue
        sensitive = _sensitive_assignment_key(name)
        if not (sensitive or _credential_name(name, numbered=extended)) or _CLI_WORD.fullmatch(value):
            continue
        if _credential_literal(value, positional=sensitive):
            spans.append(match.span("value"))
    if "${" in text and not extended:
        for match in _SHELL_DEFAULT.finditer(text):
            value = match.group("value")
            if not _sensitive_assignment_key(match.group("name")) or _CLI_WORD.fullmatch(value):
                continue
            if _credential_literal(value, positional=True):
                spans.append(match.span("value"))
    return _withhold_spans(text, spans)


def _redact_plain_assignments(value: str, depth: int = 0) -> str:
    """Withhold values assigned to sensitive names in ``name=value`` and ``name: value`` form.

    A quoted value under an ordinary name is searched again, so it cannot
    carry a nested credential ('config = "api_key=opaque-value"'); nesting
    past eight levels is withheld.
    """

    def assignment(m: re.Match[str]) -> str:
        full: str = m.group(0)
        if _FINGERPRINT.fullmatch(full):
            return full
        raw: str = m.group("value")
        quote = raw[0] if raw.startswith(('"', "'")) else ""
        bare = raw[1:-1] if quote else raw
        key: str = m.group("key")
        sep: str = m.group("sep")
        if _sensitive_assignment_key(key):
            clean: str = _redact_value(bare)
        elif "=" in bare or ":" in bare:
            # Do not let an ordinary assignment swallow a nested credential,
            # e.g. config = "api_key=opaque-value" in a source-code excerpt.
            clean = _redact_plain_assignments(bare, depth + 1) if depth < 8 else REDACTED
        else:
            return full
        return key + sep + quote + clean + quote

    return _ASSIGNMENT.sub(assignment, value)


# Past a ';' glued to an unquoted value (see _GLUED_SEMICOLON) the value runs
# to the next ';' or the end of the line, as far as the mapping rules read a
# value they withhold: withheld only to a blank, the rest of it was withheld
# again by those rules on the next pass, which then found the next glued ';'.
_GLUED_VALUE = _GLUED_SEMICOLON + r"[^;\r\n]*"
# What the established assignment rules leave of two forms they do not read.
# Quotes escaped up to eight levels deep (JSON inside a string literal:
# '\\"api_key\\": \\"v\\"'), where the value closes at the opening
# delimiter's run of backslashes and quote (see _ESCAPED_CLOSER), or runs to
# the end of the line; and the rest of an unquoted value after a ';' glued to
# it, behind the marker that withheld the value's start
# ('db-password=[REDACTED];cd', 'password: "[REDACTED]";cd'). The statement
# rules read most of the '=' forms first. The established passes write that
# marker bare after '=' only for an unquoted value; after ': ' they quote it
# either way.
#
# Each level of escaping doubles a backslash and adds one before a quote, so
# inside a value whose delimiter is k backslashes and a quote, the value's
# own quote is 2k + 1 of them ('\\\"' for k = 1) and a backslash that
# ends the value adds 2k + 2 before the closing delimiter. A run of
# backslashes and that quote closes the value only when the run, read
# whole, is k plus a multiple of 2k + 2: read as the opener's tail, the
# value's own quote ended it early and the rest of the value was shown.
_ESCAPED_CLOSER = r"(?:(?P=run)(?P=run)\\\\)*+(?P=escaped)"
_ADDED_ASSIGNMENT = re.compile(
    _ASSIGNMENT_KEY
    + r"(?P<sep>\\{0,8}[\"']\s*:\s*|[\"'][ \t]*=(?!=)[ \t]*|\s*=\s*|:[ \t]+|:[ \t]*(?=\\{1,8}[\"']))"
    + r"(?P<value>(?P<escaped>(?P<run>\\{1,8})[\"'])"
    + r"(?:[^\\\r\n]++|\\++(?![\"'])|(?!"
    + _ESCAPED_CLOSER
    + r")\\++[\"'])*+"
    + _ESCAPED_CLOSER
    + r"|(?P<unclosed>\\{1,8}[\"'])[^\r\n]*"
    + r"|(?P<glued>\"?\[REDACTED\]\"?(?:"
    + _GLUED_VALUE
    + r")+))"
)


def _redact_added_assignments(text: str) -> str:
    """Withhold sensitive values the established assignment rules leave (see ``_ADDED_ASSIGNMENT``).

    Runs after every established pass, on their output. A value with a glued
    ';' is withheld as one quoted marker, as the statement rules withhold a
    value that is not a simple word.
    """

    def assignment(m: re.Match[str]) -> str:
        full: str = m.group(0)
        if not _sensitive_assignment_key(m.group("key")):
            return full
        sep: str = m.group("sep")
        raw: str = m.group("value")
        glued = m.group("glued")
        if glued is not None:
            if "=" in sep and raw.startswith('"'):
                return full  # a quoted value, then a statement glued to its ';'
            return m.group("key") + sep + '"' + REDACTED + '"'
        opener = m.group("escaped") or m.group("unclosed")
        closer = m.group("escaped") or ""
        bare = raw[len(opener) : len(raw) - len(closer)]
        withheld: str = _redact_value(bare)
        return m.group("key") + sep + opener + withheld + closer

    return _ADDED_ASSIGNMENT.sub(assignment, text)


# 'api-key:value' with no space: an HTTP header written inline, or a password
# field. Limited to these names: a suffix rule would also rewrite identifiers
# such as 'example-credential:provider.openai' or 'arn:...:secret:name'.
_COMPACT_NAMES = frozenset(
    {
        "apikey",
        "xapikey",
        "xgoogapikey",
        "ocpapimsubscriptionkey",
        "xauthtoken",
        "xaccesstoken",
        "xapitoken",
        "authorization",
        "proxyauthorization",
        "password",
        "passwd",
    }
)
_COMPACT_COLON = re.compile(r"(?P<key>(?<![\w.-])[A-Za-z_][A-Za-z0-9_.-]*):(?=[^\s\"'\\])")
# The letters of a JSON string escape that ends the text before a name
# ('\npassword:v', '\r\nX-Api-Key:v', '\u000apassword:v'). The key above
# starts at the escape's letter, since a backslash may precede a name.
_ESCAPE_LETTERS = re.compile(r"[nrtbf]|u[0-9A-Fa-f]{4}")
_COMPACT_VALUE = re.compile(r"\[REDACTED\]|[^\s,;\}\]\)\"']+(?:" + _GLUED_VALUE + r")*")
# Report identifiers written in place of a caller's key (credential_id and the
# gateway connector's keyed fingerprints).
_OPAQUE_IDENTITY = re.compile(r"(?:credential|caller):(?:hmac-)?sha256:[a-f0-9]{64}")


def _redact_compact_colons(text: str) -> str:
    """Withhold 'api-key:value' (no space) after a header or password name.

    Runs after every established pass. The marker is left bare; the mapping
    rules quote it ('password:"[REDACTED]"'), as for 'password: value'.
    """
    pieces: list[str] = []
    cursor = 0
    position = 0
    while match := _COMPACT_COLON.search(text, position):
        position = match.end()
        key = match.group("key")
        name = _KEY_NORMALISE.sub("", key.lower())
        if name not in _COMPACT_NAMES and match.start() and text[match.start() - 1] == "\\":
            escape = _ESCAPE_LETTERS.match(key)
            if escape is not None:
                name = _KEY_NORMALISE.sub("", key[escape.end() :].lower())
        if name not in _COMPACT_NAMES:
            continue
        value = _COMPACT_VALUE.match(text, position)
        if value is None:
            continue
        # Escaped JSON ('\\"api-key:v\\"') leaves the delimiter's backslash behind.
        raw = value.group(0)
        bare = raw.rstrip("\\")
        if (
            not bare
            or _OPAQUE_IDENTITY.fullmatch(bare)
            or _OPAQUE_IDENTITY.fullmatch(key + ":" + bare)
            or _redact_value(bare) == bare
        ):
            position = value.end()
            continue
        pieces.append(text[cursor:position])
        pieces.append(REDACTED + raw[len(bare) :])
        cursor = position = value.end()
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)
