"""Credentials passed to calls: literal key/value pairs and credential-named callees.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. A call that pairs a literal credential key with a value
('os.environ.setdefault("OPENAI_API_KEY", "v")', 'Header("x-api-key", "v")')
loses the value; a callee named for a credential ('AzureKeyCredential("v")',
'setBearerToken("v")') loses its credential literals; and a literal
(user, password) authentication pair loses the password.
"""

from __future__ import annotations

import ast
import heapq
import re
from bisect import bisect_left

from shadowscan.utils.redaction_rules import (
    _CALLEE_WORD,
    _MAX_REDACTION_WORK,
    _MAX_SANITIZATION_NODES,
    REDACTED,
    SanitizationLimitError,
    _blanks_before,
    _credential_literal,
    _interpolated,
    _kept_value,
    _name_before,
    _sensitive_assignment_key,
)

_CALL_START = re.compile(r"(?<![\w.])[A-Za-z_][A-Za-z0-9_.]*[ \t]*\(")
# A method reached through a call result or a chain continued on a new line:
# 'builder().apiKey(', '\n    .apiKey(', 'client?.token('. The leading literal
# '.' lets the regex engine skip ahead quickly.
_CALL_CHAIN = re.compile(r"\.(?<=[\s)\]}?!]\.)[ \t]*[A-Za-z_][A-Za-z0-9_.]*[ \t]*\(")
_CALL_KEYWORD = re.compile(r"\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")
_CALL_INTERPOLATED = re.compile(r"(?i)(?<!\w)(?:[ft]r?|r[ft])$")
_CALL_LITERAL = re.compile(r"(?i)(?:[rub]{0,2})[\"']")
_CALL_PLAIN_KEY = re.compile(r"(?i)[rub]{0,2}(?P<quote>[\"'])(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)")


# Bounds on one call's argument list, outside strings and comments. A call past
# them is only a problem when it pairs a credential key with a value.
_MAX_CALL_DEPTH = 32
_MAX_CALL_STEPS = 8 * 1024
_OPENERS = {")": "(", "]": "[", "}": "{"}


class _CallLexer:
    """Bounded, language-agnostic lexing of call argument lists in one text.

    Every call start is examined, including calls nested in other calls, so the
    same characters can be lexed several times. String ends are memoized per
    opening quote and comment ends come from line and block-comment indexes,
    which keeps that rescanning near linear on ordinary input. The shared work
    budget still bounds adversarial input and fails closed.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.work = 0
        self._strings: dict[int, int] = {}
        self._newlines: list[int] | None = None
        self._block_ends: list[int] | None = None

    def tick(self) -> None:
        self.work += 1
        if self.work > _MAX_REDACTION_WORK:
            raise SanitizationLimitError("credential call work limit exceeded")

    def line_end(self, position: int) -> int:
        """Index just past the line containing ``position``."""
        if self._newlines is None:
            self._newlines = [match.start() for match in re.finditer("\n", self.text)]
        index = bisect_left(self._newlines, position)
        return self._newlines[index] + 1 if index < len(self._newlines) else len(self.text)

    def block_end(self, position: int) -> int:
        """Index just past the ``*/`` closing a block comment opened at ``position``."""
        if self._block_ends is None:
            self._block_ends = [match.start() for match in re.finditer(r"\*/", self.text)]
        index = bisect_left(self._block_ends, position + 2)
        return self._block_ends[index] + 2 if index < len(self._block_ends) else len(self.text)

    def string_end(self, start: int, depth: int = 0) -> int:
        """Consume a string, including nested interpolation, on all supported Pythons."""
        cached = self._strings.get(start)
        if cached is not None:
            return cached
        if depth >= 64:
            raise SanitizationLimitError("credential call nesting limit exceeded")
        text = self.text
        char = text[start]
        delimiter = char * 3 if char != "`" and text.startswith(char * 3, start) else char
        single_line = char != "`" and len(delimiter) == 1
        interpolated = _CALL_INTERPOLATED.search(text, max(0, start - 3), start) is not None
        position = start + len(delimiter)
        braces = 0
        end = len(text)
        while position < len(text):
            self.tick()
            char = text[position]
            if char == "\\":
                position += 2
                continue
            if braces:
                if char in "\"'`":
                    position = self.string_end(position, depth + 1)
                    continue
                if char == "#":
                    position = self.line_end(position)
                    continue
                if char == "{":
                    braces += 1
                    if braces >= 64:
                        raise SanitizationLimitError("credential call nesting limit exceeded")
                elif char == "}":
                    braces -= 1
            elif text.startswith(delimiter, position):
                end = position + len(delimiter)
                break
            elif single_line and char == "\n":
                # An ordinary quote ends at the line: an apostrophe in prose
                # must not swallow the rest of the text as one string.
                end = position
                break
            elif interpolated and text.startswith("{{", position):
                position += 2
                continue
            elif interpolated and char == "{":
                braces = 1
            elif delimiter == "`" and text.startswith("${", position):
                braces = 1
                position += 2
                continue
            position += 1
        self._strings[start] = end
        return end

    def arguments(self, start: int, *, comments: bool) -> tuple[list[tuple[int, int]], str, bool]:
        """Split the argument list whose ``(`` ends just before ``start``.

        Returns the argument spans, a state and whether a comment was skipped.
        ``closed`` found the call's own ``)``. ``open`` reached the end of the
        text or a mismatched bracket; ``nesting`` and ``length`` stopped at a
        bound. Unless closed, the last span runs to the end of the text, so a
        malformed credential value is withheld through EOF. Delimiters inside
        quoted values, nested calls and comments cannot end a value early.
        """
        text = self.text
        spans: list[tuple[int, int]] = []
        position = argument_start = start
        brackets: list[str] = []
        steps = 0
        skipped_comment = False
        state = "open"
        while position < len(text):
            self.tick()
            steps += 1
            if steps > _MAX_CALL_STEPS:
                state = "length"
                break
            char = text[position]
            if char in "\"'`":
                position = self.string_end(position)
                continue
            if comments and (char == "#" or text.startswith(("//", "/*"), position)):
                skipped_comment = True
                block = text.startswith("/*", position)
                position = self.block_end(position) if block else self.line_end(position)
                continue
            if char in "([{":
                if len(brackets) >= _MAX_CALL_DEPTH:
                    state = "nesting"
                    break
                brackets.append(char)
            elif char in ")]}":
                if not brackets:
                    if char == ")":
                        spans.append((argument_start, position))
                        return spans, "closed", skipped_comment
                    break
                if brackets.pop() != _OPENERS[char]:
                    break
            elif char == "," and not brackets:
                spans.append((argument_start, position))
                if len(spans) >= _MAX_SANITIZATION_NODES:
                    raise SanitizationLimitError("credential call argument limit exceeded")
                argument_start = position + 1
            position += 1
        spans.append((argument_start, len(text)))
        return spans, state, skipped_comment


def _call_argument_start(text: str, start: int, end: int) -> int:
    """Skip whitespace, continuation lines and comments before an argument."""
    while start < end:
        if text[start].isspace():
            start += 1
        elif text.startswith(("\\\n", "\\\r\n"), start):
            start += 3 if text.startswith("\\\r\n", start) else 2
        elif text[start] == "#" or text.startswith(("//", "/*"), start):
            block = text.startswith("/*", start)
            following = text.find("*/" if block else "\n", start + 1, end)
            start = end if following < 0 else following + (2 if block else 1)
        else:
            return start
    return start


def _literal_credential_key(expression: str) -> bool:
    """Read only a literal string key; never evaluate an arbitrary expression."""
    expression = expression[_call_argument_start(expression, 0, len(expression)):].strip()
    plain = _CALL_PLAIN_KEY.fullmatch(expression)
    if plain:
        return _sensitive_assignment_key(plain.group("key"))
    if not expression or not (_CALL_LITERAL.match(expression) or expression.startswith("(")):
        return False
    # Literal evaluation is bounded separately from the linear call lexer. Long
    # keys still receive the ordinary sensitive-name check without an AST.
    if len(expression) > 4096:
        return _sensitive_assignment_key(expression.strip("\"'"))
    try:
        value = ast.literal_eval(expression)
    except (ValueError, SyntaxError, RecursionError):
        return False
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="replace")
    return isinstance(value, str) and _sensitive_assignment_key(value)


def _credential_key_argument(text: str, start: int, end: int, bounded: bool) -> bool:
    """Whether the argument ``text[start:end]`` is a literal credential key.

    An unbounded trailing argument (the call never closed) is not copied whole:
    only a plain literal at its start can name a key.
    """
    if bounded or end - start <= 4096:
        return _literal_credential_key(text[start:end])
    head = text[start:start + 4096]
    plain = _CALL_PLAIN_KEY.match(head, _call_argument_start(head, 0, len(head)))
    return plain is not None and _sensitive_assignment_key(plain.group("key"))


def _credential_call_values(
    text: str, spans: list[tuple[int, int]], closed: bool,
) -> tuple[bool, list[tuple[int, int]]]:
    """Whether a call pairs a literal credential key with values, and their spans."""
    sensitive = False
    values: list[tuple[int, int]] = []
    positional = 0
    for number, (start, end) in enumerate(spans):
        bounded = closed or number < len(spans) - 1
        keyword = _CALL_KEYWORD.match(text, _call_argument_start(text, start, end), end)
        if keyword:
            name = keyword.group("name")
            if name in {"key", "name"}:
                sensitive = sensitive or _credential_key_argument(text, keyword.end(), end, bounded)
            elif name in {"default", "value"}:
                values.append((keyword.end(), end))
        else:
            if positional == 0:
                sensitive = sensitive or _credential_key_argument(text, start, end, bounded)
            elif positional == 1:
                values.append((start, end))
            positional += 1
    return sensitive, values


def _redact_credential_calls(text: str) -> str:
    """Withhold values/defaults paired with literal credential keys in calls.

    The credential key, not the callable's spelling, establishes sensitivity:
    aliases of getenv/putenv and mapping methods receive identical protection.
    Only first-position or key/name arguments identify a key. Nonsecret calls
    and read-only lookups remain intact. Keyword order does not affect safety.

    ``#`` and ``//`` start comments only in some languages, and prose uses
    parentheses freely. A call that does not close under the comment reading is
    lexed again with the markers as text, so ``(#123)``, ``(https://...)``,
    ``int(size // 2)`` and ``this.#field`` stay ordinary. A call past the nesting
    or length bound fails closed only when it pairs a credential key with a
    value; otherwise it is left alone.

    Independently, a callee named for a credential (AzureKeyCredential,
    HTTPBasicAuth, setBearerToken) has its credential string literals withheld;
    see ``_credential_literals``. Methods called on a call result or down a
    builder chain ('builder().apiKey(...)') are calls like any other.
    """
    if '"' not in text and "'" not in text and "`" not in text:
        return text
    lexer = _CallLexer(text)
    values: list[tuple[int, int]] = []
    literals: list[tuple[int, int]] = []
    skip_until = 0
    calls = heapq.merge(_CALL_START.finditer(text), _CALL_CHAIN.finditer(text), key=lambda call: call.start())
    for call in calls:
        if call.start() < skip_until:
            continue
        spans, state, skipped_comment = lexer.arguments(call.end(), comments=True)
        if state != "closed" and skipped_comment:
            retry = lexer.arguments(call.end(), comments=False)
            if retry[1] == "closed":
                spans, state, _ = retry
        callee = _qualified_callee(text, call)
        # Prose puts a space before a parenthesis ("Login ('log|n')"); code rarely does.
        level = 0 if callee[-1:].isspace() else _credential_callee(callee)
        if level:
            # Literal credentials do not skip nested calls: a call inside
            # another argument can still pair a credential key with a value.
            literals.extend(_credential_literals(lexer, spans, state == "closed", level))
        sensitive, call_values = _credential_call_values(text, spans, state == "closed")
        if not sensitive:
            continue
        if state in {"nesting", "length"}:
            raise SanitizationLimitError(f"credential call {state} limit exceeded")
        for start, end in sorted(call_values):
            if text[start:end].strip():
                values.append((start, end))
                skip_until = end
    if not values and not literals:
        return text
    pieces: list[str] = []
    cursor = 0
    # Containers first, so a literal inside a withheld value is not repeated.
    for start, end in sorted({*values, *literals}, key=lambda span: (span[0], -span[1])):
        if start < cursor:
            continue
        raw = text[start:end]
        pieces.append(text[cursor:start])
        # Preserve physical line numbers and surrounding call arguments.
        spaces = raw[:len(raw) - len(raw.lstrip(" \t"))]
        pieces.append(spaces + '"' + REDACTED + '"' + "\n" * raw.count("\n"))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


# Credential-named callees. A name ending in a constructor word builds or
# presents a credential (AzureKeyCredential, HTTPBasicAuth, smtp.login): its
# positional string literals are credentials, except the first of several,
# which names a user, account or tenant. Other names with a credential word
# (setBearerToken, WithAPIKey, get_secret) and SDK client constructors
# (openai.NewClient, cohere.Client) only lose literals that look like opaque
# keys, because lookups take a credential's name rather than its value.
_CALLEE_HINT = re.compile(r"(?i)key|token|secret|passw|cred|auth|bearer|client|login")
_CREDENTIAL_CALLEE_WORDS = frozenset({
    "apikey", "auth", "authentication", "bearer", "client", "credential", "credentials", "key", "oauth",
    "passwd", "password", "secret", "token",
})
_CREDENTIAL_CONSTRUCTOR_WORDS = frozenset({
    "auth", "authenticate", "authentication", "credential", "credentials", "login", "passwd", "password",
})
# Verbs that look a credential up or check for one rather than present it
# (get_password, requireAuth, useAuth): only opaque literals are withheld.
_LOOKUP_VERBS = frozenset({
    "check", "count", "del", "delete", "describe", "ensure", "fetch", "find", "get", "has", "is", "list",
    "load", "log", "lookup", "pop", "print", "read", "remove", "require", "requires", "show", "use",
    "validate", "verify",
})
# Factory methods take their receiver's name: Credentials.basic("user", "v"),
# AwsBasicCredentials.create("id", "v") and Ruby's Cohere::Client.new("v").
_CALLEE_FACTORIES = frozenset({"basic", "create", "from", "new", "of"})
# C#'s target-typed 'new(' constructs the type declared before the variable:
# 'AzureKeyCredential credential = new("...")'. A generic type's arguments
# are skipped within 256 characters.
_TARGET_TYPE_CONTEXT = 256
# One whole call argument that is a string literal, optionally named
# (Python/Kotlin 'key=', C#/Swift 'key:'). Python f-string, C# verbatim and
# interpolated prefixes are accepted; interpolated text is never an opaque
# literal.
_CALL_ARGUMENT_LITERAL = re.compile(
    r"(?:(?P<label>[A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:=(?!=)|:(?![:=]))[ \t]*)?"
    r"(?P<prefix>[rRbBuUfF]{1,2}|@\$?|\$@?)?(?P<quote>[\"'`])"
)
# Java's "secret".toCharArray() and similar conversions keep a literal whole.
_LITERAL_CONVERSION = re.compile(r"(?:[ \t]*\.[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\([ \t]*\))*")


def _credential_callee(name: str) -> int:
    """0 for an ordinary callee, 1 for a credential-named one, 2 for a credential constructor."""
    if _CALLEE_HINT.search(name) is None:
        return 0  # the common case, decided without splitting the name into words
    segments = name.split(".")
    method = segments[-1]
    if len(segments) > 1 and method.lower() in _CALLEE_FACTORIES:
        # The nearest receiver named for a credential: auth.preemptive.basic.
        method = next((part for part in reversed(segments[:-1]) if _CALLEE_HINT.search(part)), segments[-2])
    words = [word.lower() for word in _CALLEE_WORD.findall(method) if not word.isdigit()]
    if not words:
        return 0  # 'token.(' or 'auth._(' in prose: no callee name to read
    if words[-1] in _CREDENTIAL_CONSTRUCTOR_WORDS and words[0] not in _LOOKUP_VERBS:
        return 2
    return 1 if not _CREDENTIAL_CALLEE_WORDS.isdisjoint(words) else 0


def _chained_callee(text: str, dot: int) -> str:
    """The empty calls a chained method is reached through: 'given().auth().basic(' gives 'given.auth'."""
    names: list[str] = []
    end = dot
    while len(names) < 4:
        while end > 0 and text[end - 1].isspace():
            end -= 1
        if end < 2 or text[end - 2:end] != "()":
            break
        name = _name_before(text, end - 2, "_$")
        if not name:
            break
        names.append(name)
        end -= 2 + len(name)
        if end < 1 or text[end - 1] != ".":
            break
        end -= 1
    return ".".join(reversed(names))


def _qualified_callee(text: str, call: re.Match[str]) -> str:
    """A call's name, qualified by what it is reached through or constructs.

    'builder().apiKey(' reads as 'builder.apiKey', Rust's and Ruby's
    'AzureKeyCredential::new(' as 'AzureKeyCredential.new', and C#'s
    target-typed 'AzureKeyCredential credential = new(' as
    'AzureKeyCredential.new'. Names are read backwards from the call, so
    each costs only its own length.
    """
    callee = call.group()[:-1]
    start = call.start()
    if callee.startswith("."):
        return _chained_callee(text, start) + callee
    if start >= 2 and text[start - 2:start] == "::":
        receiver = _name_before(text, start - 2, "_")
        return receiver + "." + callee if receiver else callee
    if callee == "new":
        equals = _blanks_before(text, start)
        declared = _declared_type(text, equals - 1) if equals > 0 and text[equals - 1] == "=" else ""
        return declared + "." + callee if declared else callee
    return callee


def _declared_type(text: str, equals: int) -> str:
    """The type in a declaration 'Type name =' whose '=' is at ``equals``, read backwards."""
    if equals > 0 and text[equals - 1] in "=!<>+-*/%&|^?:":
        return ""  # a comparison or a compound assignment
    end = _blanks_before(text, equals)
    name = _name_before(text, end, "_")
    end -= len(name)
    if not name or name[0].isdigit():
        return ""
    if end > 0 and text[end - 1] == "@":
        end -= 1  # a C# verbatim identifier
    gap = _blanks_before(text, end)
    if gap == end:
        return ""  # no blank separates a declared type from the name
    end = gap
    if end > 0 and text[end - 1] == "?":
        end -= 1  # a nullable type
    if end > 0 and text[end - 1] == ">":
        opening = text.rfind("<", max(0, end - _TARGET_TYPE_CONTEXT), end - 1)
        if opening < 0 or text.find("\n", opening, end) >= 0:
            return ""
        end = opening
    return _name_before(text, end, "_.")


def _credential_literals(
    lexer: _CallLexer, spans: list[tuple[int, int]], closed: bool, level: int,
) -> list[tuple[int, int]]:
    """Spans of credential string literals among one credential-named call's arguments.

    A literal that starts a longer expression ("key" + suffix) withholds the
    whole argument. An unterminated literal is withheld to its line end. The
    argument after an unclosed call runs to the end of the text, so there only
    the literal itself is withheld.
    """
    text = lexer.text
    arguments: list[tuple[int, re.Match[str] | None, bool, bool]] = []
    for number, (start, end) in enumerate(spans):
        begin = _call_argument_start(text, start, end)
        if begin >= end:
            continue
        literal = _CALL_ARGUMENT_LITERAL.match(text, begin, end)
        named = bool(literal and literal.group("label")) or _CALL_KEYWORD.match(text, begin, end) is not None
        arguments.append((end, literal, named, closed or number < len(spans) - 1))
    positional_count = sum(1 for _, _, named, _ in arguments if not named)
    found: list[tuple[int, int]] = []
    position = 0
    for end, literal, named, bounded in arguments:
        index = position
        position += not named
        if literal is None:
            continue
        opening = literal.start("quote")
        char = text[opening]
        delimiter = char * 3 if char != "`" and text.startswith(char * 3, opening) else char
        stop = lexer.string_end(opening)
        closing = stop - len(delimiter)
        terminated = closing >= opening + len(delimiter) and text.startswith(delimiter, closing)
        value = text[opening + len(delimiter):closing if terminated else stop]
        if _interpolated(literal.group("prefix") or "", char, value):
            continue  # interpolated text is assembled elsewhere
        positional = level == 2 and not named and not (index == 0 and positional_count > 1)
        if not _credential_literal(value, positional=positional):
            continue
        conversion = _LITERAL_CONVERSION.match(text, stop, end)
        whole = conversion is not None and _call_argument_start(text, conversion.end(), end) >= end
        literal_start = literal.start("prefix") if literal.group("prefix") else opening
        found.append((literal_start, stop if whole or not (bounded and terminated) else end))
    return found


# requests/httpx/Elasticsearch basic authentication tuples: auth=("user", "v").
_AUTH_PAIR_HINT = re.compile(r"(?i)auth[\"']?[ \t]*[:=][ \t]*[\(\[]")
_AUTH_PAIR = re.compile(
    r"(?i)(?<![\w.-])[\"']?[a-z_]*auth[\"']?[ \t]*[:=][ \t]*[\(\[][ \t]*"
    r"(?:[rbu]?\"[^\"\r\n]*\"|[rbu]?'[^'\r\n]*'|[A-Za-z_][\w.]*)[ \t]*,[ \t]*"
    r"[rbu]?(?P<quote>[\"'])(?P<password>[^\"'\r\n]*)(?P=quote)"
)


def _redact_auth_pairs(text: str) -> str:
    """Withhold the password of a literal (user, password) authentication pair."""
    def replace(match: re.Match[str]) -> str:
        if _kept_value(match.group("password")):
            return match.group()
        start = match.start("password") - match.start()
        return match.group()[:start] + REDACTED + match.group()[match.end("password") - match.start():]

    return _AUTH_PAIR.sub(replace, text) if _AUTH_PAIR_HINT.search(text) else text
