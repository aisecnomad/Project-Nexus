"""Credentials passed to calls: literal key/value pairs and credential-named callees.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. A call that pairs a literal credential key with a value
('os.environ.setdefault("OPENAI_API_KEY", "v")', 'Header("x-api-key", "v")')
loses the value; a callee named for a credential ('AzureKeyCredential("v")',
'setBearerToken("v")') loses its credential literals, and a well-known SDK
call ('openai.DefaultConfig("v")') the literal at its credential position;
and a literal (user, password) authentication pair loses the password.
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
    _placeholder,
    _sensitive_assignment_key,
    _setting_level,
    _setting_value_withheld,
)

_CALL_START = re.compile(r"(?<![\w.])[A-Za-z_][A-Za-z0-9_.]*[ \t]*\(")
# Comments or a physical line break may separate a callee from its opening
# parenthesis. Read their ends with the bounded lexer rather than a wildcard
# expression that repeatedly searches the remainder of the text.
_CALL_TRIVIA_START = re.compile(r"(?<![\w.])[A-Za-z_][A-Za-z0-9_.]*[ \t]*(?=/\*|//|#|\r?\n)")
# A method reached through a call result or a chain continued on a new line:
# 'builder().apiKey(', '\n    .apiKey(', 'client?.token('. The leading literal
# '.' lets the regex engine skip ahead quickly.
_CALL_CHAIN = re.compile(r"\.(?<=[\s)\]}?!]\.)[ \t]*[A-Za-z_][A-Za-z0-9_.]*[ \t]*\(")
_CALL_CHAIN_TRIVIA = re.compile(r"\.(?<=[\s)\]}?!]\.)[ \t]*[A-Za-z_][A-Za-z0-9_.]*[ \t]*(?=/\*|//|#|\r?\n)")
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
        # Comment and continuation starts mapped to where the trivia after them ends.
        self._trivia_ends: dict[int, int] = {}
        # Actual Go comments indexed while reading SDK imports. Selector
        # receivers can then be read backwards without searching source again.
        self._go_comments: dict[int, int] = {}

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

    def trivia_end(self, start: int) -> int:
        """Where the trivia from ``start`` to the end of the text ends: ``argument_start(start, len(text))``.

        Each comment and line continuation a skip passes is remembered with where
        that skip ended, and a later skip that reaches it stops there. A word that
        ends a line or precedes a comment is a callee candidate, so in a block of
        comment lines each line's last word skipped every following line again:
        quadratic in the block, which reached the work limit at about 1 MB.
        """
        text = self.text
        position = start
        passed: list[int] = []
        while position < len(text):
            known = self._trivia_ends.get(position)
            if known is not None:
                position = known
                break
            self.tick()
            if text[position].isspace():
                position += 1
                continue
            if text.startswith(("\\\n", "\\\r\n"), position):
                passed.append(position)
                position += 3 if text.startswith("\\\r\n", position) else 2
            elif text.startswith("/*", position):
                passed.append(position)
                position = self.block_end(position)
            elif text[position] == "#" or text.startswith("//", position):
                passed.append(position)
                position = self.line_end(position)
            else:
                break
        for item in passed:
            self._trivia_ends[item] = position
        return position

    def argument_start(self, start: int, end: int) -> int:
        """Skip argument trivia using indexed comment ends and the shared budget."""
        while start < end:
            self.tick()
            if self.text[start].isspace():
                start += 1
            elif self.text.startswith(("\\\n", "\\\r\n"), start):
                start += 3 if self.text.startswith("\\\r\n", start) else 2
            elif self.text.startswith("/*", start):
                start = min(self.block_end(start), end)
            elif self.text[start] == "#" or self.text.startswith("//", start):
                start = min(self.line_end(start), end)
            else:
                break
        return start

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
        csharp_prefix = text[max(0, start - 2) : start]
        verbatim = char == '"' and csharp_prefix.endswith(("@", "@$"))
        single_line = char != "`" and len(delimiter) == 1 and not verbatim
        interpolated = _CALL_INTERPOLATED.search(text, max(0, start - 3), start) is not None or (
            char == '"' and csharp_prefix.endswith(("$", "$@"))
        )
        position = start + len(delimiter)
        braces = 0
        end = len(text)
        while position < len(text):
            self.tick()
            char = text[position]
            if char == "\\" and not verbatim:
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
            elif verbatim and delimiter == '"' and text.startswith('""', position):
                position += 2
                continue
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
    expression = expression[_call_argument_start(expression, 0, len(expression)) :].strip()
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
    head = text[start : start + 4096]
    plain = _CALL_PLAIN_KEY.match(head, _call_argument_start(head, 0, len(head)))
    return plain is not None and _sensitive_assignment_key(plain.group("key"))


def _credential_call_values(
    text: str,
    spans: list[tuple[int, int]],
    closed: bool,
) -> tuple[bool, list[tuple[int, int]]]:
    """Whether a call pairs a literal credential key with values, and their spans."""
    sensitive = False
    values: list[tuple[int, int]] = []
    key_span: tuple[int, int] | None = None
    positional = 0
    for number, (start, end) in enumerate(spans):
        bounded = closed or number < len(spans) - 1
        keyword = _CALL_KEYWORD.match(text, _call_argument_start(text, start, end), end)
        if keyword:
            name = keyword.group("name")
            if name in {"key", "name"}:
                sensitive = sensitive or _credential_key_argument(text, keyword.end(), end, bounded)
                key_span = key_span or (keyword.end(), end)
            elif name in {"default", "value"}:
                values.append((keyword.end(), end))
        else:
            if positional == 0:
                sensitive = sensitive or _credential_key_argument(text, start, end, bounded)
                key_span = key_span or (start, end)
            elif positional == 1:
                values.append((start, end))
            positional += 1
    if sensitive or key_span is None or not values:
        return sensitive, values
    # A setting path whose last word names a credential ('openai.key', 'Azure:Key')
    # withholds only an opaque literal, as the same names do in settings files.
    key = _call_string_literal(text[key_span[0] : key_span[1]])
    if key is None or _setting_level(key) != 1:
        return False, values
    opaque = [
        span for span in values if _setting_value_withheld(1, _call_string_literal(text[span[0] : span[1]]))
    ]
    return bool(opaque), opaque


def _call_string_literal(argument: str) -> str | None:
    """A short plain string literal argument's value; None for anything else."""
    argument = argument[_call_argument_start(argument, 0, len(argument)) :].strip()
    if len(argument) > 4096 or not _CALL_LITERAL.match(argument):
        return None
    try:
        value = ast.literal_eval(argument)
    except (ValueError, SyntaxError, RecursionError):
        return None
    return value if isinstance(value, str) else None


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
    HTTPBasicAuth, setBearerToken) has its credential string literals withheld,
    and a well-known SDK call ('AddAzureOpenAIChatCompletion("gpt-4o",
    endpoint, "v")', 'openai.DefaultConfig("v")') the literal at its credential
    position; see ``_credential_literals`` and ``_SDK_CREDENTIAL_ARGUMENTS``.
    Methods called on a call result or down a builder chain
    ('builder().apiKey(...)') are calls like any other.
    """
    if '"' not in text and "'" not in text and "`" not in text:
        return text
    lexer = _CallLexer(text)
    imported = _go_sdk_credential_bindings(text, lexer)
    values: list[tuple[int, int]] = []
    literals: list[tuple[int, int]] = []
    skip_until = 0
    calls = heapq.merge(
        _CALL_START.finditer(text),
        _CALL_CHAIN.finditer(text),
        _CALL_TRIVIA_START.finditer(text),
        _CALL_CHAIN_TRIVIA.finditer(text),
        _GO_SDK_CALL_START.finditer(text) if imported else (),
        key=lambda call: call.start(),
    )
    # Every word of a comment block before a '(' reaches that '(' as a callee.
    # Its arguments are lexed and judged once; each callee adds what its own
    # name withholds, once per kind of name.
    lexed: dict[int, tuple[list[tuple[int, int]], str]] = {}
    judged: dict[int, tuple[bool, list[tuple[int, int]]]] = {}
    read_literals: set[tuple[int, int, tuple[int, ...]]] = set()
    for call in calls:
        if call.start() < skip_until:
            continue
        argument_start = call.end()
        if not call.group().endswith("("):
            opening = lexer.trivia_end(argument_start)
            if opening >= len(text) or text[opening] != "(":
                continue
            argument_start = opening + 1
        if argument_start not in lexed:
            spans, state, skipped_comment = lexer.arguments(argument_start, comments=True)
            if state != "closed" and skipped_comment:
                retry = lexer.arguments(argument_start, comments=False)
                if retry[1] == "closed":
                    spans, state, _ = retry
            lexed[argument_start] = spans, state
        spans, state = lexed[argument_start]
        callee = _qualified_callee(text, call)
        if imported and callee in _GO_SDK_METHODS:
            receiver = _go_sdk_receiver(text, call.start(), lexer)
            if receiver:
                callee = f"{receiver}.{callee}"
        level = _credential_callee(callee)
        # A lone spaced "Login ('log|n')" occurs in prose. Treat its literal
        # like a lookup's, while qualified SDK logins retain password context.
        if callee.lower() == "login" and argument_start - call.start() > len(callee) + 1:
            level = min(level, 1)
        known = _sdk_credential_positions(callee, imported)
        if level or known:
            if state in {"nesting", "length"}:
                raise SanitizationLimitError(f"credential call {state} limit exceeded")
            # Literal credentials do not skip nested calls: a call inside
            # another argument can still pair a credential key with a value.
            if (argument_start, level, known) not in read_literals:
                read_literals.add((argument_start, level, known))
                literals.extend(_credential_literals(lexer, spans, state == "closed", level, known))
        if argument_start not in judged:
            judged[argument_start] = _credential_call_values(text, spans, state == "closed")
        sensitive, call_values = judged[argument_start]
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
        spaces = raw[: len(raw) - len(raw.lstrip(" \t"))]
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
_CREDENTIAL_CALLEE_WORDS = frozenset(
    {
        "apikey",
        "auth",
        "authentication",
        "bearer",
        "client",
        "credential",
        "credentials",
        "key",
        "oauth",
        "passwd",
        "password",
        "secret",
        "token",
    }
)
_CREDENTIAL_CONSTRUCTOR_WORDS = frozenset(
    {
        "auth",
        "authenticate",
        "authentication",
        "credential",
        "credentials",
        "login",
        "passwd",
        "password",
    }
)
# Verbs that look a credential up or check for one rather than present it
# (get_password, requireAuth, useAuth): only opaque literals are withheld.
_LOOKUP_VERBS = frozenset(
    {
        "check",
        "count",
        "del",
        "delete",
        "describe",
        "ensure",
        "fetch",
        "find",
        "get",
        "has",
        "is",
        "list",
        "load",
        "log",
        "lookup",
        "pop",
        "print",
        "read",
        "remove",
        "require",
        "requires",
        "show",
        "use",
        "validate",
        "verify",
    }
)
# Factory methods take their receiver's name: Credentials.basic("user", "v"),
# AwsBasicCredentials.create("id", "v") and Ruby's Cohere::Client.new("v").
_CALLEE_FACTORIES = frozenset({"basic", "create", "from", "new", "of"})
# Well-known LLM SDK calls that take a credential at a fixed position although
# no word of their name names one. Each lists the zero-based positions where
# its overloads take the key as a string; the first of them that holds a string
# literal among the positional arguments is withheld as a credential
# constructor's is (named arguments such as C#'s 'apiKey: "v"' are left to the
# mapping rules).
# A distinctive name counts wherever it is called from (a builder variable,
# 'services.', a chain); a generic one through its package's own name
# ('openai.DefaultConfig') or a source-bound Go import, including dot imports. The notes
# below say what other overloads pass at those positions. Positions were
# checked against the SDKs' public signatures on 2026-10-01.
_SDK_CREDENTIAL_ARGUMENTS: dict[str, tuple[int, ...]] = {
    # Semantic Kernel for .NET. Azure OpenAI connectors, as IKernelBuilder and
    # IServiceCollection extensions and services: (deploymentName, endpoint,
    # apiKey, ...). The overloads taking a TokenCredential there pass no
    # string; those taking a client second pass a service or model ID third,
    # which is withheld too when it is given positionally.
    "AddAzureOpenAIChatCompletion": (2,),
    "AddAzureOpenAIChatClient": (2,),
    "AddAzureOpenAITextEmbeddingGeneration": (2,),
    "AddAzureOpenAIEmbeddingGenerator": (2,),
    "AddAzureOpenAITextToImage": (2,),
    "AddAzureOpenAIAudioToText": (2,),
    "AddAzureOpenAITextToAudio": (2,),
    "AzureOpenAIChatCompletionService": (2,),
    "AzureOpenAITextEmbeddingGenerationService": (2,),
    # OpenAI connectors: (modelId, apiKey, orgId, ...). The overloads taking a
    # client second pass no string there. Chat completion and chat client also
    # take (modelId, endpoint Uri, apiKey, orgId): an endpoint expression is no
    # literal, so the key third is the first literal candidate. When the key
    # second is a variable, a literal orgId third is withheld instead, which
    # only over-redacts. AddOpenAITextToImage takes (apiKey, orgId, modelId).
    "AddOpenAIChatCompletion": (1, 2),
    "AddOpenAIChatClient": (1, 2),
    "AddOpenAITextEmbeddingGeneration": (1,),
    "AddOpenAIEmbeddingGenerator": (1,),
    "AddOpenAIAudioToText": (1,),
    "AddOpenAITextToAudio": (1,),
    "AddOpenAITextToImage": (0,),
    "OpenAIChatCompletionService": (1, 2),
    "OpenAITextEmbeddingGenerationService": (1,),
    # go-openai (github.com/sashabaranov/go-openai): DefaultConfig(authToken),
    # DefaultAzureConfig(apiKey, baseURL) and NewClient(authToken).
    "openai.DefaultConfig": (0,),
    "openai.DefaultAzureConfig": (0,),
    "openai.NewClient": (0,),
    # openai-java (com.theokanning.openai): new OpenAiService(token[, timeout]).
    "OpenAiService": (0,),
    # Google AI JavaScript SDK (@google/generative-ai): new GoogleGenerativeAI(apiKey).
    "GoogleGenerativeAI": (0,),
}
# Only this imported package grants generic config helpers credential meaning.
# Comments and strings are skipped before reading imports; a similarly named
# method on an unrelated package must not lose its ordinary configuration data.
_GO_SDK_PACKAGE = "github.com/sashabaranov/go-openai"
_GO_SDK_METHODS = ("DefaultConfig", "DefaultAzureConfig", "NewClient")
_GO_IMPORT_START = re.compile(r"/[/*]|[\"'`]|(?<![\w.])import(?!\w)")
_GO_IMPORT_ALIAS = re.compile(r"(?:[^\W\d]|_)\w*|\.")
# A method candidate alone lets the receiver be recovered lexically across
# spaces/comments and through Unicode import aliases, without broadening the
# ordinary cross-language call patterns or treating every generic method as SDK use.
_GO_SDK_CALL_START = re.compile(
    r"(?<!\w)(?:DefaultConfig|DefaultAzureConfig|NewClient)[ \t]*(?:\(|(?=/\*|//|\r?\n))"
)
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


def _go_sdk_credential_bindings(text: str, lexer: _CallLexer) -> dict[str, tuple[int, ...]]:
    """Credential callees bound by Go single or grouped imports in the full source.

    A lightweight lexical pass reads literal imports without executing code or
    resolving files. It shares the call lexer's work budget and string/comment
    indexes. Import aliases are retained conservatively even when a local name
    later shadows them: over-redaction is safer than publishing a credential.
    """
    # Interpreted imports can escape package characters; raw imports discard
    # carriage returns, including ones inside the go-openai substring. Either
    # form still needs the lexical pass. Preserve the original source offsets.
    if "import" not in text or ("go-openai" not in text and "\\" not in text and "\r" not in text):
        return {}
    bindings: dict[str, tuple[int, ...]] = {}
    cursor = 0
    for token in _GO_IMPORT_START.finditer(text):
        if token.start() < cursor:
            continue
        lexer.tick()
        marker = token.group()
        if marker == "//":
            cursor = lexer.line_end(token.start())
            lexer._go_comments[cursor] = token.start()
            continue
        if marker == "/*":
            cursor = lexer.block_end(token.start())
            lexer._go_comments[cursor] = token.start()
            continue
        if marker in "\"'`":
            cursor = lexer.string_end(token.start())
            continue
        position = lexer.argument_start(token.end(), len(text))
        grouped = position < len(text) and text[position] == "("
        position += grouped
        while position < len(text):
            position = lexer.argument_start(position, len(text))
            if position >= len(text) or text[position] == ")":
                cursor = position + (position < len(text))
                break
            if text[position] == ";":
                position += 1
                continue
            alias = "openai"
            named = _GO_IMPORT_ALIAS.match(text, position)
            if named is not None:
                alias = named.group()
                position = lexer.argument_start(named.end(), len(text))
            if position >= len(text) or text[position] not in '"`':
                cursor = position
                break
            end = lexer.string_end(position)
            literal = text[position:end]
            package: str | None = None
            if literal.startswith("`") and literal.endswith("`") and len(literal) > 1:
                # Go raw string values discard CR (https://go.dev/ref/spec#String_literals).
                # Normalize only the value, never the source used for evidence offsets.
                package = literal[1:-1].replace("\r", "")
            elif len(literal) <= 4096:
                try:
                    parsed = ast.literal_eval(literal)
                except (ValueError, SyntaxError, RecursionError):
                    pass
                else:
                    package = parsed if isinstance(parsed, str) else None
            if package == _GO_SDK_PACKAGE and alias != "_":
                for method in _GO_SDK_METHODS:
                    callee = method if alias == "." else f"{alias}.{method}"
                    bindings[callee] = _SDK_CREDENTIAL_ARGUMENTS[f"openai.{method}"]
                if len(bindings) > _MAX_SANITIZATION_NODES:
                    raise SanitizationLimitError("SDK import binding limit exceeded")
            cursor = position = end
            if not grouped:
                break
    return bindings


def _go_sdk_receiver(text: str, start: int, lexer: _CallLexer) -> str:
    """The identifier before a Go selector's dot, skipping real comments and blanks.

    Each traversal consumes the shared work budget. Comments are already
    indexed by the full-source import pass, so a large comment is skipped once
    rather than searched backwards from every method candidate.
    """

    def preceding(position: int) -> int:
        while position > 0:
            lexer.tick()
            comment = lexer._go_comments.get(position)
            if comment is not None:
                position = comment
            elif text[position - 1].isspace():
                position -= 1
            else:
                break
        return position

    dot = preceding(start)
    if dot == 0 or text[dot - 1] != ".":
        return ""
    end = preceding(dot - 1)
    # _name_before supports Unicode letters and digits, as Go identifiers do.
    receiver = _name_before(text, end, "_")
    lexer.work += len(receiver)
    lexer.tick()
    return receiver


def _sdk_credential_positions(
    name: str, imported: dict[str, tuple[int, ...]] | None = None
) -> tuple[int, ...]:
    """Candidate credential positions of a well-known SDK call (see ``_SDK_CREDENTIAL_ARGUMENTS``)."""
    receiver, _, method = name.rpartition(".")
    qualified = receiver.rpartition(".")[2] + "." + method
    if imported:
        bound = imported.get(qualified if receiver else method)
        if bound is not None:
            return bound
    positions = _SDK_CREDENTIAL_ARGUMENTS.get(qualified)
    return _SDK_CREDENTIAL_ARGUMENTS.get(method, ()) if positions is None else positions


def _chained_callee(text: str, dot: int) -> str:
    """The empty calls a chained method is reached through: 'given().auth().basic(' gives 'given.auth'."""
    names: list[str] = []
    end = dot
    while len(names) < 4:
        while end > 0 and text[end - 1].isspace():
            end -= 1
        if end < 2 or text[end - 2 : end] != "()":
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
    callee = call.group().removesuffix("(").rstrip()
    start = call.start()
    if callee.startswith("."):
        return _chained_callee(text, start) + callee
    if start >= 2 and text[start - 2 : start] == "::":
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
    lexer: _CallLexer,
    spans: list[tuple[int, int]],
    closed: bool,
    level: int,
    known: tuple[int, ...] = (),
) -> list[tuple[int, int]]:
    """Spans of credential string literals among one credential-named or well-known SDK call's arguments.

    ``level`` is the callee's ``_credential_callee`` level. ``known`` lists the
    candidate positions of a well-known SDK call's credential argument; the
    literal at the first of them that holds one is withheld as a credential
    constructor's is, whatever the level. At level 0 no other argument is read.

    A literal that starts a longer expression ("key" + suffix) withholds the
    whole argument. Recognized unterminated literals withhold the bounded
    remaining text. A terminated literal in an unclosed call withholds only
    the literal itself rather than consuming an unrelated trailing expression.
    """
    text = lexer.text
    arguments: list[tuple[int, re.Match[str] | None, bool, bool, int]] = []
    for number, (start, end) in enumerate(spans):
        begin = _call_argument_start(text, start, end)
        if begin >= end:
            continue
        literal, named, wrappers = _credential_argument_literal(lexer, begin, end)
        arguments.append((end, literal, named, closed or number < len(spans) - 1, wrappers))
    positional_count = sum(1 for _, _, named, _, _ in arguments if not named)
    indexed: list[tuple[int, int, re.Match[str] | None, bool, bool, int]] = []
    position = 0
    for end, literal, named, bounded, wrappers in arguments:
        indexed.append((position, end, literal, named, bounded, wrappers))
        position += not named
    # An overload with an expression where another takes the key (an endpoint
    # Uri) moves the key to its next candidate position.
    literal_positions = {index for index, _, literal, named, _, _ in indexed if literal and not named}
    target = next((index for index in known if index in literal_positions), None)
    found: list[tuple[int, int]] = []
    for index, end, literal, named, bounded, wrappers in indexed:
        sdk = not named and index == target
        if literal is None or not (level or sdk):
            continue
        opening = literal.start("quote")
        char = text[opening]
        delimiter = char * 3 if char != "`" and text.startswith(char * 3, opening) else char
        stop = lexer.string_end(opening)
        closing = stop - len(delimiter)
        terminated = closing >= opening + len(delimiter) and text.startswith(delimiter, closing)
        value = text[opening + len(delimiter) : closing if terminated else stop]
        prefix = literal.group("prefix") or ""
        multiline = len(delimiter) == 3 or "@" in prefix
        # A C# interpolation prefix can hold a plain literal. Only a real
        # replacement field makes the string a computed value.
        if "$" in prefix and not _csharp_replacement(value):
            prefix = prefix.replace("$", "")
        interpolated = _interpolated(prefix, char, value)
        if interpolated:
            material = _credential_static_material(
                lexer, opening + len(delimiter), closing if terminated else stop, prefix, char
            )
            # Reference fields alone publish no credential. Opaque static
            # material beside them is confidential even when the value is
            # computed at runtime. Never join fragments across a field.
            if not any(_credential_literal(part, positional=False) for part in material.split()):
                continue
        positional = sdk or (level == 2 and not named and not (index == 0 and positional_count > 1))
        # Multiline literals may wrap a credential across physical lines. Do
        # not let those line breaks hide its shape or its constructor context;
        # placeholders are checked before compacting their separate words.
        tested = "".join(value.split()) if multiline else value
        if multiline and not interpolated and _placeholder(value):
            continue
        if not interpolated and not _credential_literal(tested, positional=positional):
            continue
        conversion = _LITERAL_CONVERSION.match(text, stop, end)
        tail = _call_argument_start(text, conversion.end() if conversion else stop, end)
        for _ in range(wrappers):
            if tail >= end or text[tail] != ")":
                break
            tail = _call_argument_start(text, tail + 1, end)
        whole = tail >= end
        literal_start = literal.start("prefix") if literal.group("prefix") else opening
        found.append((literal_start, stop if whole or not (bounded and terminated) else end))
    return found


def _credential_static_material(lexer: _CallLexer, start: int, end: int, prefix: str, quote: str) -> str:
    """Only the static material of an interpolated credential string.

    Balanced replacement fields are skipped without evaluation, including
    quoted strings inside them. Pure variable references remain visible;
    an opaque static key beside one makes the whole literal confidential.
    """
    text = lexer.text
    brace_fields = "f" in prefix.lower() or "$" in prefix
    pieces: list[str] = []
    position = start
    while position < end:
        lexer.tick()
        char = text[position]
        if brace_fields and text.startswith("{{", position):
            pieces.append("{")
            position += 2
            continue
        marker = (brace_fields and char == "{") or (quote == "`" and text.startswith("${", position))
        if not marker:
            pieces.append(char)
            position += 1
            continue
        position += 1 if char == "{" else 2
        depth = 1
        while position < end and depth:
            lexer.tick()
            char = text[position]
            if char in "\"'`":
                position = lexer.string_end(position)
                continue
            depth += (char == "{") - (char == "}")
            position += 1
        # Never join two static fragments into a new opaque token.
        pieces.append(" ")
    return "".join(pieces)


_CALL_ARGUMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*[ \t]*(?:=(?!=)|:(?![:=]))")
_CALL_FALLBACK = re.compile(r"\?\?|\|\||\?:|or\b")
_ENVIRONMENT_CALLEES = frozenset(
    {
        "environment.getenvironmentvariable",
        "system.getenv",
        "os.getenv",
        "os.environ.get",
        "getenv",
    }
)


def _credential_argument_literal(
    lexer: _CallLexer, begin: int, end: int
) -> tuple[re.Match[str] | None, bool, int]:
    """A direct credential literal, including wrappers and environment fallbacks.

    Read no arbitrary nested function: only known environment lookups establish
    a fallback literal here. Their variable names remain visible. The caller's
    credential context decides whether the fallback value should be withheld.
    """
    text = lexer.text
    name = _CALL_ARGUMENT_NAME.match(text, begin, end)
    named = name is not None
    if name:
        begin = lexer.argument_start(name.end(), end)
    wrappers = 0
    while begin < end and text[begin] == "(":
        lexer.tick()
        wrappers += 1
        if wrappers > _MAX_CALL_DEPTH:
            raise SanitizationLimitError("credential call nesting limit exceeded")
        begin = lexer.argument_start(begin + 1, end)
    literal = _CALL_ARGUMENT_LITERAL.match(text, begin, end)
    if literal:
        return literal, named or bool(literal.group("label")), wrappers
    lookup = _CALL_START.match(text, begin, end)
    if lookup is None or lookup.group().removesuffix("(").strip().lower() not in _ENVIRONMENT_CALLEES:
        return None, named, wrappers
    spans, state, _ = lexer.arguments(lookup.end(), comments=True)
    if state != "closed" or not spans or spans[-1][1] >= end:
        return None, named, wrappers
    fallback_start = lexer.argument_start(spans[-1][1] + 1, end)
    fallback = _CALL_FALLBACK.match(text, fallback_start, end)
    if fallback is None:
        return None, named, wrappers
    begin = lexer.argument_start(fallback.end(), end)
    while begin < end and text[begin] == "(":
        lexer.tick()
        wrappers += 1
        if wrappers > _MAX_CALL_DEPTH:
            raise SanitizationLimitError("credential call nesting limit exceeded")
        begin = lexer.argument_start(begin + 1, end)
    return _CALL_ARGUMENT_LITERAL.match(text, begin, end), named, wrappers


def _csharp_replacement(value: str) -> bool:
    """Whether a C# string has an opening replacement brace, rather than '{{'."""
    position = 0
    while position < len(value):
        if value.startswith("{{", position):
            position += 2
        elif value[position] == "{":
            return True
        else:
            position += 1
    return False


# requests/httpx/Elasticsearch basic authentication tuples: auth=("user", "v").
# The password closes at its first quote of its own kind that no backslash
# escapes ('"ab\"cd"' is one string), unless the text before that quote ends
# with an assignment operator, where the quote opens the next value; otherwise
# it closes at its first quote, as before.
_AUTH_PAIR_HINT = re.compile(r"(?i)auth[\"']?[ \t]*[:=][ \t]*[\(\[]")
_AUTH_PAIR = re.compile(
    r"(?i)(?<![\w.-])[\"']?[a-z_]*auth[\"']?[ \t]*[:=][ \t]*[\(\[][ \t]*"
    r"(?:[rbu]?\"[^\"\r\n]*\"|[rbu]?'[^'\r\n]*'|[A-Za-z_][\w.]*)[ \t]*,[ \t]*"
    r"[rbu]?(?P<quote>[\"'])(?P<password>(?:\\[^\r\n]|(?!(?P=quote))[^\\\r\n])*+"
    r"(?<![=:>~])(?<![=:>~][ \t])(?=(?P=quote))|[^\"'\r\n]*)(?P=quote)"
)


def _redact_auth_pairs(text: str) -> str:
    """Withhold the password of a literal (user, password) authentication pair."""

    def replace(match: re.Match[str]) -> str:
        if _kept_value(match.group("password")):
            return match.group()
        start = match.start("password") - match.start()
        return match.group()[:start] + REDACTED + match.group()[match.end("password") - match.start() :]

    return _AUTH_PAIR.sub(replace, text) if _AUTH_PAIR_HINT.search(text) else text
