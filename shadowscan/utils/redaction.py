"""Credential-safe evidence and report values.

Sanitize *before* shortening excerpts: once a credential is truncated, its
recognizable structure can be lost. These helpers deliberately do not depend on
signature settings; disabling secret discovery must never disable redaction.
"""

from __future__ import annotations

import ast
import hashlib
import heapq
import io
import re
import token
import tokenize
import types
from bisect import bisect_left
from collections.abc import Iterator, Mapping
from typing import Any
from urllib.parse import unquote

REDACTED = "[REDACTED]"
_FINGERPRINT = re.compile(r"^credential:sha256:[a-f0-9]{64}$")
_SENSITIVE_SUFFIXES = (
    "apikey", "accesskey", "secretkey", "keystring", "privatekeydata", "accesskeyid", "secretaccesskey",
    "accesstoken", "refreshtoken", "idtoken", "authtoken", "apitoken", "foundrytoken", "githubtoken", "clientsecret",
    "authorization", "proxyauthorization", "password", "passwd", "privatekey",
    "credential", "credentials", "bearertoken", "sessiontoken", "signingkey",
    "secretstring", "secretbinary", "connectionstring", "connstr",
    # Azure storage / Service Bus connection-string members and SAS tokens.
    "accountkey", "sharedaccesskey", "sastoken",
    # Capability URLs: whoever holds a webhook URL can post through it.
    "webhookurl", "webhookuri", "webhookid", "hookurl",
)
_SENSITIVE_NAMES = {"token", "jwt", "secret", "bearer", "passwd", "password", "authorization", "cookie", "setcookie"}
# Keep this backstop aligned with detectable credential formats regardless of
# which signature packs the operator enables for discovery.
_SECRET_TOKEN = re.compile(
    r"\b(?:sk-(?:proj-|ant-|live-|or-v1-|lf-|litellm-|svcacct-|admin-)?[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    r"|glpat-[A-Za-z0-9_-]{8,}"
    r"|xox[baprs]-[A-Za-z0-9-]{8,}|AIza[A-Za-z0-9_-]{16,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|hf_[A-Za-z0-9]{8,}"
    r"|gsk_[A-Za-z0-9]{40,}|pcsk_[A-Za-z0-9_]{20,}|e2b_[a-f0-9]{40}|tgp_v1_[A-Za-z0-9_-]{30,}"
    r"|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}|tvly-(?:dev-|prod-)?[A-Za-z0-9_-]{20,}"
    r"|xai-[A-Za-z0-9]{60,}|pplx-[A-Za-z0-9]{40,}|csk-[A-Za-z0-9]{30,}|nvapi-[A-Za-z0-9_-]{60,}"
    r"|r8_[A-Za-z0-9]{30,}|fc-[a-f0-9]{32}|app-[A-Za-z0-9]{24})\b"
)
# Webhook and bot endpoints whose *path* is the credential. The scheme, host
# and a fixed prefix are kept for context; the remainder of the path is
# withheld. Query parameters (e.g. Power Automate's ``sig``) are handled by the
# ordinary query-field rules.
_PATH_SECRET_RULES: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = (
    (re.compile(r"hooks\.slack(?:-gov)?\.com"), re.compile(r"/(?:services|workflows|triggers|actions|commands)/")),
    (re.compile(r"(?:(?:ptb|canary)\.)?discord(?:app)?\.com"), re.compile(r"/api(?:/v\d+)?/webhooks/")),
    (re.compile(r"(?:[a-z0-9-]+\.)*webhook\.office\.com"), re.compile(r"/webhook(?:b2)?/")),
    (re.compile(r"outlook\.office(?:365)?\.com"), re.compile(r"/webhook(?:b2)?/")),
    (re.compile(r"hooks\.zapier\.com"), re.compile(r"/hooks/")),
    (re.compile(r"hook\.(?:[a-z0-9-]+\.)?(?:make|integromat)\.com"), re.compile(r"/")),
    (re.compile(r"maker\.ifttt\.com"), re.compile(r"/trigger/[^/]+/(?:json/)?with/key/")),
    (re.compile(r"api\.telegram\.org"), re.compile(r"/(?:file/)?bot")),
    # n8n (commonly self-hosted, so any host): /webhook/<id> and /webhook-test/<id>.
    (re.compile(r".+"), re.compile(r"(?:/[^/]+)*?/webhook(?:-test|-waiting)?/")),
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_PEM = re.compile(r"-----BEGIN (?:[A-Z ]{0,30})PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]{0,30})PRIVATE KEY-----|\Z)", re.DOTALL)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic|SSWS)\s+[A-Za-z0-9+/_.=-]+")
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,20}://[^\s<>\"']+")
# A key must be consumed in full: truncating it to a fixed number of characters
# can leave an opaque credential in evidence when the sensitive suffix follows
# that limit. The left boundary includes every character accepted by the key
# lexer (including '.' and '-'), preventing retries at interior key segments.
# Text size and redaction work are bounded separately below.
_ASSIGNMENT = re.compile(
    r"(?P<key>(?<![\w.-])[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<sep>[\"']\s*:\s*|\s*=\s*|:\s+|:\s*(?=[\"']))"
    r"(?P<value>\[REDACTED\]|\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\}\]\)\"']+)"
)
_QUERY_SEPARATOR = re.compile(r"[&#]")
_PYTHON_ASSIGNMENT_KEY = re.compile(
    r"(?<![\w.-])(?P<key>[A-Za-z_][A-Za-z0-9_.]*)[ \t]*(?P<separator>:|=(?!=))"
)
_INDEXED_ASSIGNMENT_KEY = re.compile(
    r"\[[ \t\r\n]*(?P<quote>[\"'`])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,100})"
    r"(?P=quote)"
)
_CALL_START = re.compile(r"(?<![\w.])[A-Za-z_][A-Za-z0-9_.]*[ \t]*\(")
_CALL_KEYWORD = re.compile(r"\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")
_CALL_INTERPOLATED = re.compile(r"(?i)(?<!\w)(?:[ft]r?|r[ft])$")
_CALL_LITERAL = re.compile(r"(?i)(?:[rub]{0,2})[\"']")
_CALL_PLAIN_KEY = re.compile(r"(?i)[rub]{0,2}(?P<quote>[\"'])(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)")
_TARGET_ATTRIBUTE = re.compile(r"\.[A-Za-z_$][A-Za-z0-9_$]*")
_MAPPING_VALUE = re.compile(
    r"(?<![\w.-])(?:(?P<quote>[\"'])(?P<quoted>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_.-]*))[ \t]*:[ \t]*"
    r"(?P<value>[\"'`\[\{(])"
)
_YAML_MAPPING_LINE = re.compile(
    r"^(?P<prefix>[ \t]*(?:-[ \t]+)*)(?:(?P<quote>[\"'])"
    r"(?P<quoted>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_.-]*))[ \t]*:[ \t]*"
    r"(?P<value>[^\r\n]*)", re.MULTILINE,
)
_YAML_CONTINUATION_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n|\Z)")
_MAX_SANITIZATION_NODES = 100_000
_MAX_SANITIZATION_CHARS = 64 * 1024 * 1024
_MAX_REDACTION_WORK = 128 * 1024 * 1024
_KEY_NORMALISE = re.compile(r"[^a-z0-9]")
# Environment-style credential names: an underscore-separated identifier ending
# in KEY/TOKEN/SECRET/... names a credential by convention (AZURE_OPENAI_KEY,
# DATABRICKS_TOKEN, MODAL_TOKEN_SECRET, LITELLM_MASTER_KEY) even though the bare
# suffixes are too broad for arbitrary record fields (S3 object keys, pagination
# tokens, tag "Key" members). Applied to assignments in text excerpts only, where
# over-redaction of a sort key or a page token costs nothing.
_ASSIGNMENT_CREDENTIAL_NAME = re.compile(
    r"(?i)[a-z][a-z0-9]*(?:_[a-z0-9]+)*_(?:key|token|secret|password|passwd|credentials?)"
)


class SanitizationLimitError(ValueError):
    """Evidence cannot be safely sanitized within the work/output budget."""


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
        if match.start() < cursor or not _sensitive_assignment_key(match.group("quoted") or match.group("plain")):
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
        if match.start() < cursor or not _sensitive_assignment_key(match.group("quoted") or match.group("plain")):
            continue
        start = match.start("value")
        end = _mapping_expression_end(text, start)
        raw = text[start:end]
        bare = raw.strip()
        if len(bare) > 1 and bare[0] in "\"'" and bare[-1] == bare[0] and _FINGERPRINT.fullmatch(bare[1:-1]):
            continue
        pieces.append(text[cursor:start])
        trailing_space = raw[len(raw.rstrip(" \t")):]
        pieces.append('"' + REDACTED + '"' + "\n" * raw.count("\n") + trailing_space)
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


def _indexed_assignment_candidates(text: str) -> Iterator[tuple[int, str, str, int]]:
    """Find sensitive literal subscripts without evaluating an assignment target.

    A sensitive parent also protects assignments to its descendants, such as
    config["credentials"]["primary"][0]. Nested target scanning has shared work
    and depth limits so overlapping malformed candidates cannot amplify work.
    """
    work = 0
    for match in _INDEXED_ASSIGNMENT_KEY.finditer(text):
        key = match.group("key")
        if not _sensitive_assignment_key(key):
            continue
        position = match.end()
        brackets: list[str] = ["["]
        quote = ""
        while position < len(text):
            work += 1
            if work > _MAX_REDACTION_WORK:
                raise SanitizationLimitError("indexed assignment work limit exceeded")
            char = text[position]
            if quote:
                if char == "\\":
                    position += 2
                    continue
                if text.startswith(quote, position):
                    position += len(quote)
                    quote = ""
                    continue
            elif text.startswith(("//", "/*"), position) or (char == "#" and brackets):
                block = text.startswith("/*", position)
                end = text.find("*/" if block else "\n", position + (2 if char == "/" else 1))
                if end < 0:
                    break
                following = end + (2 if block else 1)
                work += following - position
                position = following
                continue
            elif text.startswith(("\\\n", "\\\r\n"), position):
                position += 3 if text.startswith("\\\r\n", position) else 2
                continue
            elif brackets:
                if char in "\"'`":
                    quote = char * 3 if char != "`" and text.startswith(char * 3, position) else char
                    position += len(quote)
                    continue
                if char in "([{":
                    if len(brackets) >= 64:
                        raise SanitizationLimitError("indexed assignment nesting limit exceeded")
                    brackets.append(char)
                elif char in ")]}":
                    if brackets.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                        break
            elif char in " \t\r\n":
                pass
            elif char == "[":
                brackets.append(char)
            elif char == ".":
                attribute = _TARGET_ATTRIBUTE.match(text, position)
                if attribute is None:
                    break
                work += attribute.end() - position
                position = attribute.end()
                continue
            else:
                # Comparisons and arrows are not assignments. Compound writes
                # can contain additional credential fragments and need redaction.
                if char == ":":
                    # Python allows annotated assignment to a subscript or its
                    # descendants. The shared RHS parser locates '=' after the
                    # annotation without mistaking an annotation-only read for
                    # a stored credential.
                    yield match.start(), key, ":", position + 1
                    break
                operator = next((op for op in ("&&=", "||=", "??=", "+=", "=",) if text.startswith(op, position)), None)
                if operator and not text.startswith(("==", "=>"), position):
                    yield match.start(), key, "=", position + len(operator)
                break
            position += 1


def _assignment_candidates(text: str) -> Iterator[tuple[int, str, str, int]]:
    plain = ((match.start(), match.group("key"), match.group("separator"), match.end())
             for match in _PYTHON_ASSIGNMENT_KEY.finditer(text))
    return heapq.merge(plain, _indexed_assignment_candidates(text), key=lambda candidate: candidate[0])


def _redact_python_assignments(text: str) -> str:
    """Redact complete sensitive Python assignment expressions without evaluation.

    Tokenize only sensitive candidates, including indexed assignments and call
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
    for start, key, separator, candidate_end in _assignment_candidates(text):
        if start < cursor or not _sensitive_assignment_key(key):
            continue
        annotated = separator == ":"
        assigned_at: int | None = None if annotated else candidate_end
        # URL fields use URL boundaries, not Python statement boundaries,
        # and have already been sanitized by the URL pass. Check actual spans:
        # a '#' before a source assignment can also introduce a comment.
        while url is not None and url.end() <= start:
            url = next(urls, None)
        if url is not None and url.start() <= start:
            continue
        value_start = candidate_end
        if not annotated:
            while value_start < len(text) and text[value_start] in " \t":
                value_start += 1
        if stream is None:
            stream = io.StringIO(text)
        stream.seek(candidate_end)
        offsets = [candidate_end]
        end = len(text)
        brackets: list[str] = []
        previous = start - 1
        while previous >= 0 and text[previous] in " \t\r\n":
            previous -= 1
        argument = not annotated and previous >= 0 and text[previous] in "(,"
        previous_operator = ""

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
                    if item.string == "`" or (item.string in {"/", "//"} and text.startswith(("/*", "//"), position)):
                        # Python's tokenizer is not a JavaScript template/comment
                        # lexer (some Python versions classify backticks as OP).
                        # Withhold the remaining expression conservatively instead
                        # of exposing fragments after its first physical newline.
                        break
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
                    previous_operator = item.string
                elif item.type == token.NEWLINE:
                    following = position + len(item.string)
                    while following < len(text) and text[following] in " \t\r\n":
                        work += 1
                        if work > _MAX_REDACTION_WORK:
                            raise SanitizationLimitError("Python assignment work limit exceeded")
                        following += 1
                    # JavaScript permits binary/member/ternary expressions to
                    # continue across an unescaped newline in either direction.
                    if assigned_at is not None and (
                        previous_operator in {"+", "-", "*", "/", "**", "&", "|", "?", ":", "=", "."}
                        or (following < len(text) and text[following] in "+-*/.?&|")
                    ):
                        continue
                    end = position
                    break
                elif item.type == token.ENDMARKER:
                    end = position
                    break
                elif item.type not in {token.INDENT, token.DEDENT, tokenize.NL, token.COMMENT}:
                    previous_operator = ""
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
                position = self.block_end(position) if text.startswith("/*", position) else self.line_end(position)
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
    """
    if '"' not in text and "'" not in text:
        return text
    lexer = _CallLexer(text)
    pieces: list[str] = []
    cursor = 0
    for call in _CALL_START.finditer(text):
        if call.start() < cursor:
            continue
        spans, state, skipped_comment = lexer.arguments(call.end(), comments=True)
        if state != "closed" and skipped_comment:
            retry = lexer.arguments(call.end(), comments=False)
            if retry[1] == "closed":
                spans, state, _ = retry
        sensitive, values = _credential_call_values(text, spans, state == "closed")
        if not sensitive:
            continue
        if state in {"nesting", "length"}:
            raise SanitizationLimitError(f"credential call {state} limit exceeded")
        for start, end in sorted(values):
            raw = text[start:end]
            if not raw.strip():
                continue
            pieces.append(text[cursor:start])
            # Preserve physical line numbers and surrounding call arguments.
            spaces = raw[:len(raw) - len(raw.lstrip(" \t"))]
            pieces.append(spaces + '"' + REDACTED + '"' + "\n" * raw.count("\n"))
            cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


def _sensitive_key(key: str) -> bool:
    normalized = _KEY_NORMALISE.sub("", key.lower())
    return normalized in _SENSITIVE_NAMES or normalized.endswith(_SENSITIVE_SUFFIXES)


def _sensitive_assignment_key(key: str) -> bool:
    """Sensitive-key test for assignments and mapping entries inside text."""
    return _sensitive_key(key) or _ASSIGNMENT_CREDENTIAL_NAME.fullmatch(key.strip()) is not None


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


def _url_host(authority: str) -> str:
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1:host.find("]")] if "]" in host else host[1:]
    else:
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return host.rstrip(".").lower()


def _redact_path_secret(host: str, path: str) -> str:
    """Withhold the credential-bearing remainder of a known webhook path.

    Idempotent: an already withheld path is returned unchanged.
    """
    if not host or not path:
        return path
    for host_rx, prefix_rx in _PATH_SECRET_RULES:
        if not host_rx.fullmatch(host):
            continue
        prefix = prefix_rx.match(path)
        if prefix and prefix.end() < len(path):
            return path[:prefix.end()] + REDACTED
    return path


def _sanitize_url(match: re.Match[str]) -> str:
    url = match.group(0)
    scheme, rest = url.split("://", 1)
    # Userinfo ends at the authority boundary, not at the first slash alone.
    # An @ in a query value must not be mistaken for a hostname separator.
    authority_end = min((pos for c in "/?#" if (pos := rest.find(c)) >= 0), default=len(rest))
    authority, tail = rest[:authority_end], rest[authority_end:]
    if "@" in authority:
        authority = REDACTED + "@" + authority.rsplit("@", 1)[1]
    path_end = min((pos for c in "?#" if (pos := tail.find(c)) >= 0), default=len(tail))
    tail = _redact_path_secret(_url_host(authority), tail[:path_end]) + tail[path_end:]
    url = scheme + "://" + authority + tail

    def query_value(field: str) -> str:
        key, equals, value = field.partition("=")
        if not equals:
            return field
        decoded = unquote(key).lower()
        sensitive = _sensitive_assignment_key(decoded) or decoded in {"key", "sig", "signature", "code", "x-amz-signature", "x-goog-signature"}
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
    text = _redact_credential_calls(text)
    text = _redact_python_assignments(text)
    text = _redact_yaml_multiline_values(text)
    text = _redact_mapping_values(text)
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
            if _sensitive_assignment_key(m.group("key")):
                clean = _redact_value(bare)
            elif "=" in bare or ":" in bare:
                # Do not let an ordinary assignment swallow a nested credential,
                # e.g. config = "api_key=opaque-value" in a source-code excerpt.
                clean = assignments(bare, depth + 1) if depth < 8 else REDACTED
            else:
                return m.group(0)
            return m.group("key") + m.group("sep") + quote + clean + quote

        return _ASSIGNMENT.sub(assignment, value)

    # Plain assignment redaction can introduce a bracketed marker after a
    # mapping colon (including annotations). Normalize those expressions in
    # this same pass so repeated sanitization does not change the result.
    return _redact_mapping_values(assignments(text))


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
    """
    _check_sanitization_structure(value)
    known: set[str] = set()

    def record_has_secret_value(item: Mapping, *, environment: bool = False) -> bool:
        name = item.get("name") or item.get("Name") or item.get("key") or item.get("Key")
        return isinstance(name, str) and (_sensitive_assignment_key(name) if environment else _sensitive_key(name))

    def remember(child: Any) -> None:
        if isinstance(child, str) and child:
            if child != REDACTED and not _FINGERPRINT.fullmatch(child):
                known.add(child)
                # Library diagnostics often use repr(), which escapes secret
                # control characters. Remove both spellings in sibling fields.
                escaped = repr(child)[1:-1]
                if escaped != child:
                    known.add(escaped)

    # The same aliased object can occur both outside and inside an environment
    # block. Revisit it under the stricter naming policy, but still bound cycles.
    discovered: set[tuple[int, bool]] = set()

    def discover(item: Any, depth: int = 0, *, environment: bool = False) -> None:
        identity = (id(item), environment)
        if depth > 64 or (isinstance(item, (Mapping, list, tuple)) and identity in discovered):
            return
        if isinstance(item, (Mapping, list, tuple)):
            discovered.add(identity)
        if isinstance(item, Mapping):
            if record_has_secret_value(item, environment=environment):
                remember(item.get("value") or item.get("Value"))
            for key, child in item.items():
                if _sensitive_key(str(key)) or environment and _sensitive_assignment_key(str(key)):
                    remember(child)
                child_environment = environment or str(key).lower() in {"env", "environment", "environment_variables", "environmentvariables"}
                if env_values_are_secrets and child_environment:
                    if isinstance(child, Mapping):
                        for env_value in child.values():
                            remember(env_value)
                    elif isinstance(child, list):
                        for entry in child:
                            if isinstance(entry, Mapping):
                                remember(entry.get("value") or entry.get("Value"))
                discover(child, depth + 1, environment=child_environment)
        elif isinstance(item, (list, tuple)):
            previous = None
            for child in item:
                if isinstance(previous, str) and previous.startswith("-") and _sensitive_key(previous.lstrip("-")):
                    remember(child)
                discover(child, depth + 1, environment=environment)
                previous = child

    discover(value)
    redaction_work = 0
    if redact_short_secrets:
        # The structural pass can rewrite part of a whole configured secret.
        # Remember that spelling too so its other opaque fragments are removed.
        for secret in tuple(known):
            redaction_work += len(secret)
            if redaction_work > _MAX_REDACTION_WORK:
                raise SanitizationLimitError("credential replacement work limit exceeded")
            spelling = sanitize_text(secret)
            if spelling and spelling != REDACTED:
                known.add(spelling)
    ordered = sorted(known, key=len, reverse=True)

    def text(item: str) -> str:
        nonlocal redaction_work
        redaction_work += len(item) * (len(ordered) + 1)
        if redaction_work > _MAX_REDACTION_WORK:
            raise SanitizationLimitError("credential replacement work limit exceeded")
        if redact_short_secrets and ordered:
            # Preserve recognizable token/URL structure before a short known
            # secret changes a scheme, hostname, or credential prefix. For
            # example, removing 'hooks' first would hide a Slack webhook URL
            # from the path-secret rules while retaining its capability token.
            redaction_work += len(item)
            if redaction_work > _MAX_REDACTION_WORK:
                raise SanitizationLimitError("credential replacement work limit exceeded")
            item = sanitize_text(item)
        for secret in ordered:
            if redact_short_secrets:
                redaction_work += 3 * len(item)
                if redaction_work > _MAX_REDACTION_WORK:
                    raise SanitizationLimitError("credential replacement work limit exceeded")
                # A one-character secret must not recursively expand markers
                # inserted by a previous replacement (e.g. a password of 'R').
                # Only protect markers when the secret occurs inside one: a
                # longer real secret may itself contain the literal marker.
                parts = item.split(REDACTED) if secret in REDACTED else [item]
                occurrences = sum(part.count(secret) for part in parts)
                projected_chars = len(item) + occurrences * max(0, len(REDACTED) - len(secret))
                if projected_chars > _MAX_SANITIZATION_CHARS:
                    raise SanitizationLimitError("credential replacement size limit exceeded")
                item = REDACTED.join(part.replace(secret, REDACTED) for part in parts)
            else:
                # Default report sanitization withholds the entire field for
                # short secrets; this avoids both expansion and partial leaks.
                if len(secret) < 8 and secret in item:
                    return REDACTED
                # Keep line counts stable: excerpts index sanitized text by the
                # raw line number, and a multi-line secret would shift them.
                item = item.replace(secret, REDACTED + "\n" * secret.count("\n"))
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


def policy_token() -> tuple[Any, ...]:
    """Identify the redaction rules and limits currently in force.

    State verified clean by one policy is not clean under another. Callers
    that cache a verified-clean digest key it by this value, so a rule set
    replaced at runtime (for example a patched sensitive-name list or a
    lowered limit) is applied on their next pass instead of being skipped.
    The tuple holds the live policy objects, which makes an unchanged policy
    compare by identity; mutable collections are snapshotted by value.
    """
    module = globals()
    return tuple(_policy_value(module[name]) for name in _POLICY_NAMES)


def _policy_value(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return frozenset(value)
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, dict):
        return tuple(value.items())
    return value


def _is_policy(value: Any) -> bool:
    """Rules, patterns and limits defined here, plus this module's own helpers."""
    if isinstance(value, (str, int, float, tuple, list, dict, set, frozenset, re.Pattern)):
        return True
    return isinstance(value, types.FunctionType) and value.__module__ == __name__


# Every module-level rule, pattern, limit and helper defined above. Computed
# last so a newly added policy constant is covered without registration.
_POLICY_NAMES = tuple(sorted(name for name, value in globals().items() if not name.startswith("__") and _is_policy(value)))
