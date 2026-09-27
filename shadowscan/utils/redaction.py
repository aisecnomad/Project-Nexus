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
    # Azure API Management and AI services (Ocp-Apim-Subscription-Key).
    "subscriptionkey",
)
_SENSITIVE_NAMES = {"token", "jwt", "secret", "bearer", "passwd", "password", "authorization", "cookie", "setcookie"}
# Keep this backstop aligned with detectable credential formats regardless of
# which signature packs the operator enables for discovery.
_SECRET_TOKEN = re.compile(
    r"\b(?:sk-(?:proj-|ant-|live-|or-v1-|lf-|litellm-|svcacct-|admin-)?[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    # GitLab personal/runner/trigger/deploy/feed/SCIM/CI/mail/OAuth/agent tokens.
    r"|gl(?:pat|rt|ptt|dt|ft|soat|cbt|imt|oas|agent|ffct)-[A-Za-z0-9_-]{8,}|GR1348941[A-Za-z0-9_-]{20,}"
    r"|xox[abeprs]-[A-Za-z0-9-]{8,}|xoxe\.xox[bp]-[A-Za-z0-9-]{8,}|xapp-[A-Za-z0-9-]{8,}"
    # Google API keys, OAuth access/refresh tokens and OAuth client secrets.
    r"|AIza[A-Za-z0-9_-]{16,}|ya29\.[A-Za-z0-9_-]{20,}|1//0[A-Za-z0-9_-]{30,}|GOCSPX-[A-Za-z0-9_-]{20,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|hf_[A-Za-z0-9]{8,}"
    r"|gsk_[A-Za-z0-9]{40,}|pcsk_[A-Za-z0-9_]{20,}|e2b_[a-f0-9]{40}|tgp_v1_[A-Za-z0-9_-]{30,}"
    r"|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}|tvly-(?:dev-|prod-)?[A-Za-z0-9_-]{20,}"
    r"|xai-[A-Za-z0-9]{60,}|pplx-[A-Za-z0-9]{40,}|csk-[A-Za-z0-9]{30,}|nvapi-[A-Za-z0-9_-]{60,}"
    r"|r8_[A-Za-z0-9]{30,}|fc-[a-f0-9]{32}|app-[A-Za-z0-9]{24}|sk_[a-f0-9]{40,}"
    # Package registries, cloud platforms and developer SaaS.
    r"|npm_[A-Za-z0-9]{30,}|pypi-AgE[A-Za-z0-9_-]{40,}|do[opr]_v1_[a-f0-9]{64}"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{24,}"
    r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|dapi[a-f0-9]{32}|shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"
    r"|ATATT3[A-Za-z0-9_=-]{40,}|lin_api_[A-Za-z0-9]{32,}|ntn_[A-Za-z0-9]{40,}"
    r"|PMAK-[a-f0-9]{24}-[a-f0-9]{34}|dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}"
    r"|sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,}|glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}"
    r"|sntry[su]_[A-Za-z0-9+/=_-]{30,}|hv[sbr]\.[A-Za-z0-9_-]{24,}"
    r"|[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b"
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
# Text size and redaction work are bounded separately below. An unquoted
# key's colon stays on its line: a YAML parent ('openai:') must not consume the
# nested sensitive key on the next line as its own value. A quoted key may also
# be assigned with '=' (PowerShell hashtables, TOML quoted keys).
_ASSIGNMENT = re.compile(
    r"(?P<key>(?<![\w.-])[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<sep>[\"']\s*:\s*|[\"'][ \t]*=(?!=)[ \t]*|\s*=\s*|:[ \t]+|:[ \t]*(?=[\"']))"
    r"(?P<value>\[REDACTED\]|\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\}\]\)\"']+)"
)
_QUERY_SEPARATOR = re.compile(r"[&#]")
# R assigns with '<-' and '<<-'; the scan treats them like '='.
_PYTHON_ASSIGNMENT_KEY = re.compile(
    r"(?<![\w.-])(?P<key>[A-Za-z_][A-Za-z0-9_.]*)[ \t]*(?P<separator>:|=(?!=)|<<?-(?!-))"
)
_INDEXED_ASSIGNMENT_KEY = re.compile(
    r"\[[ \t\r\n]*(?P<quote>[\"'`])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,100})"
    r"(?P=quote)"
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


# Brackets a sensitive assignment expression may open before the remaining
# text is withheld. Python 3.12+ tokenizers stop at 200 levels and 3.11 has no
# limit; a lower bound keeps every supported version on the same path.
_MAX_ASSIGNMENT_NESTING = 100
# A candidate's scan first reads at most this many characters of each physical
# line. Most scans stop within a few tokens, and reading a long minified line to
# its end for every candidate on it is quadratic. A scan that stops too close to
# a cut is repeated with a four times larger limit, so no cut changes a result.
_SCAN_LINE_LIMIT = 512
# How far past a token's end the tokenizer may look while classifying it.
_SCAN_LOOKAHEAD = 8
_QUOTE_ERRORS = frozenset({"'", '"'})
# Token classes an annotation-only scan records for the candidates it encloses.
_TOKEN_SPACE, _TOKEN_REAL, _TOKEN_ASSIGN, _TOKEN_CLOSE, _TOKEN_NEWLINE = range(5)
_FSTRING_STARTS = frozenset(
    kind for kind in (getattr(token, "FSTRING_START", None), getattr(token, "TSTRING_START", None)) if kind
)
_FSTRING_ENDS = frozenset(
    kind for kind in (getattr(token, "FSTRING_END", None), getattr(token, "TSTRING_END", None)) if kind
)
_NEWLINE_TOKENS = frozenset({token.NEWLINE, token.NL})
_SPACE_TOKENS = frozenset({token.INDENT, token.DEDENT, token.COMMENT, token.ERRORTOKEN})


class _AnnotationScan:
    """Tokens of one annotation-only scan, reused by the annotations inside it.

    Each ``key:`` candidate is tokenized from its colon to its statement end. An
    annotation that never reaches '=' used to leave the next candidate to
    tokenize the same text again, which is quadratic for a long run of
    unfinished annotations. A later candidate whose colon this scan lexed as an
    operator outside any string is lexed identically by its own scan, offset by
    the bracket depth ``d`` of that colon. Its first *event* at depth ``d``
    decides it: an '=' is its assignment, a closer is its unmatched bracket and
    a newline ends its statement unless only comments preceded it. Without an
    event, how this scan stopped decides. Whatever cannot be read off safely is
    rescanned, so reuse only ever skips a candidate that has no assignment.
    """

    def __init__(self) -> None:
        self.kinds: list[int] = []
        self.depths: list[int] = []
        self.colons: dict[int, int] = {}
        self.rescan: dict[int, bool] = {}
        self.last = 0

    def finish(self, definitive: bool) -> None:
        """Decide every recorded colon once, from the last token backwards."""
        kinds, depths = self.kinds, self.depths
        real = [0]
        for kind in kinds:
            real.append(real[-1] + (kind == _TOKEN_REAL))
        colon_indexes = set(self.colons.values())
        rescan = [False] * len(kinds)
        following: dict[int, int] = {}
        for index in range(len(kinds) - 1, -1, -1):
            kind = kinds[index]
            if kind == _TOKEN_NEWLINE or index in colon_indexes:
                event = following.get(depths[index])
                if event is None:
                    rescan[index] = not definitive
                elif kinds[event] == _TOKEN_ASSIGN:
                    rescan[index] = True
                elif kinds[event] == _TOKEN_CLOSE or real[event] > real[index + 1]:
                    rescan[index] = False
                else:
                    # A blank or comment-only line continues the statement.
                    rescan[index] = rescan[event]
            if kind >= _TOKEN_ASSIGN:
                following[depths[index]] = index
        self.rescan = {offset: rescan[index] for offset, index in self.colons.items()}
        self.kinds, self.depths = [], []


class _AssignmentScanner:
    """Tokenize the sensitive assignment candidates of one text under one budget."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.stream: io.StringIO | None = None
        self.work = 0
        self.annotations: list[_AnnotationScan] = []

    def charge(self, amount: int) -> None:
        self.work += amount
        if self.work > _MAX_REDACTION_WORK:
            raise SanitizationLimitError("Python assignment work limit exceeded")

    def enclosed_without_assignment(self, candidate_end: int) -> bool:
        """Whether an earlier annotation scan shows this annotation assigns nothing."""
        return any(scan.rescan.get(candidate_end) is False for scan in self.annotations)

    def scan(self, start: int, candidate_end: int, annotated: bool) -> tuple[int | None, int, bool]:
        """Locate one candidate's assigned value: (assigned_at, end, argument)."""
        limit = _SCAN_LINE_LIMIT
        while True:
            located = self._scan(start, candidate_end, annotated, limit)
            if located is not None:
                return located
            limit *= 4

    def _scan(
        self, start: int, candidate_end: int, annotated: bool, limit: int,
    ) -> tuple[int | None, int, bool] | None:
        """One scan reading at most ``limit`` characters of each line; None if a cut may matter.

        A cut line ends the input there. Tokens that end well before the cut
        are the ones the whole line yields, so a scan that stops at such a
        token is decided. A stop at end of input, near the cut, at a quote
        whose string may close past it, or at a tokenizer error is not.
        """
        text = self.text
        if self.stream is None:
            self.stream = io.StringIO(text)
        stream = self.stream
        stream.seek(candidate_end)
        offsets = [candidate_end]
        cut = -1
        assigned_at: int | None = None if annotated else candidate_end
        end = len(text)
        brackets: list[str] = []
        argument = False
        if not annotated:
            previous = start - 1
            while previous >= 0 and text[previous] in " \t\r\n":
                previous -= 1
            argument = previous >= 0 and text[previous] in "(,"
        previous_operator = ""
        record = _AnnotationScan() if annotated else None
        definitive = True
        fstrings = 0

        def readline() -> str:
            nonlocal cut
            line = "" if cut >= 0 else stream.readline(limit)
            self.charge(len(line))
            offset = stream.tell()
            if line and line[-1] != "\n" and offset < len(text):
                cut = offset
            offsets.append(offset)
            return line

        stopped: tokenize.TokenInfo | None = None
        try:
            for item in tokenize.generate_tokens(readline):
                stopped = item
                position = offsets[item.start[0] - 1] + item.start[1]
                if item.type == token.ERRORTOKEN and not item.string.isspace():
                    # Incomplete single-quoted strings generate error tokens,
                    # not TokenError. A semicolon inside one is not a boundary.
                    break
                if record is not None:
                    depth = len(brackets)
                    if item.type in _NEWLINE_TOKENS:
                        kind = _TOKEN_NEWLINE
                    elif item.type in _SPACE_TOKENS:
                        kind = _TOKEN_SPACE
                    elif item.type == token.OP and item.string == "=":
                        kind = _TOKEN_ASSIGN
                    elif item.type == token.OP and item.string in ")]}":
                        kind = _TOKEN_CLOSE
                    else:
                        kind = _TOKEN_REAL
                    fstrings += (item.type in _FSTRING_STARTS) - (item.type in _FSTRING_ENDS)
                    if item.type == token.OP and item.string == ":" and not fstrings:
                        record.colons[offsets[item.end[0] - 1] + item.end[1]] = len(record.kinds)
                    record.kinds.append(kind)
                    record.depths.append(depth)
                    record.last = offsets[item.end[0] - 1] + item.end[1]
                if item.type == token.OP:
                    if item.string == "`" or (item.string in {"/", "//"} and text.startswith(("/*", "//"), position)):
                        # Python's tokenizer is not a JavaScript template/comment
                        # lexer (some Python versions classify backticks as OP).
                        # Withhold the remaining expression conservatively instead
                        # of exposing fragments after its first physical newline.
                        break
                    if item.string == "=" and assigned_at is None and not brackets:
                        assigned_at = offsets[item.end[0] - 1] + item.end[1]
                        record = None
                    elif item.string in "([{":
                        if len(brackets) >= _MAX_ASSIGNMENT_NESTING:
                            # Too deep to follow: withhold the rest of the text.
                            if assigned_at is None:
                                assigned_at = candidate_end
                            record = None
                            break
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
                        self.charge(1)
                        following += 1
                    # JavaScript permits binary/member/ternary expressions to
                    # continue across an unescaped newline in either direction.
                    if assigned_at is not None and (
                        previous_operator in {"+", "-", "*", "/", "**", "&", "|", "?", ":", "=", "."}
                        or (following < len(text) and text[following] in "+-*/.?&|")
                    ):
                        continue
                    end = position
                    # A candidate enclosed here whose first line is blank goes
                    # on past this statement end; it needs its own scan.
                    definitive = False
                    break
                elif item.type == token.ENDMARKER:
                    end = position
                    break
                elif item.type not in {token.INDENT, token.DEDENT, tokenize.NL, token.COMMENT}:
                    previous_operator = ""
            else:
                stopped = None
        except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
            # Once '=' is seen, incomplete source must not expose any RHS,
            # including credential fragments on subsequent physical lines.
            # Indentation and nesting errors depend on where a scan started.
            definitive = not isinstance(exc, IndentationError) and "nest" not in str(exc)
            stopped = None
        if cut >= 0 and (
            stopped is None
            or stopped.type == token.ENDMARKER
            or (stopped.type == token.ERRORTOKEN and stopped.string in _QUOTE_ERRORS)
            or offsets[stopped.end[0] - 1] + stopped.end[1] > cut - _SCAN_LOOKAHEAD
        ):
            return None
        if record is not None:
            record.finish(definitive)
            self.annotations = [scan for scan in self.annotations if scan.last > candidate_end][-7:]
            self.annotations.append(record)
        return assigned_at, end, argument


def _redact_python_assignments(text: str) -> str:
    """Redact complete sensitive Python assignment expressions without evaluation.

    Tokenize only sensitive candidates, including indexed assignments and call
    arguments. String delimiters, escapes, concatenation and continued lines are
    handled lexically. Malformed, unfinished or too deeply nested RHS syntax is
    withheld through EOF; the explicit work budget prevents hostile candidates
    from repeatedly tokenizing an unlimited amount of source, and annotations
    enclosed by an earlier annotation-only scan reuse its tokens.
    """
    scanner = _AssignmentScanner(text)
    pieces: list[str] = []
    cursor = 0
    urls = _URL.finditer(text)
    url = next(urls, None)
    for start, key, separator, candidate_end in _assignment_candidates(text):
        if start < cursor or not _sensitive_assignment_key(key):
            continue
        annotated = separator == ":"
        # URL fields use URL boundaries, not Python statement boundaries,
        # and have already been sanitized by the URL pass. Check actual spans:
        # a '#' before a source assignment can also introduce a comment.
        while url is not None and url.end() <= start:
            url = next(urls, None)
        if url is not None and url.start() <= start:
            continue
        if annotated and scanner.enclosed_without_assignment(candidate_end):
            continue
        value_start = candidate_end
        if not annotated:
            while value_start < len(text) and text[value_start] in " \t":
                value_start += 1
        assigned_at, end, argument = scanner.scan(start, candidate_end, annotated)
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

    Independently, a callee named for a credential (AzureKeyCredential,
    HTTPBasicAuth, setBearerToken) has its credential string literals withheld;
    see ``_credential_literals``. Methods called on a call result or down a
    builder chain ('builder().apiKey(...)') are calls like any other.
    """
    if '"' not in text and "'" not in text:
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
        callee = call.group()[:-1]
        if callee.startswith("."):
            callee = _chained_callee(text, call.start()) + callee
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
_CALLEE_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
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
# One whole call argument that is a string literal, optionally named
# (Python/Kotlin 'key=', C#/Swift 'key:'). C# verbatim and interpolated
# prefixes are accepted; interpolated text is never an opaque literal.
_CALL_ARGUMENT_LITERAL = re.compile(
    r"(?:(?P<label>[A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:=(?!=)|:(?![:=]))[ \t]*)?"
    r"(?P<prefix>[rRbBuU]{1,2}|@\$?|\$@?)?(?P<quote>[\"'`])"
)
# Java's "secret".toCharArray() and similar conversions keep a literal whole.
_LITERAL_CONVERSION = re.compile(r"(?:[ \t]*\.[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\([ \t]*\))*")
# Values that name, locate or stand in for a credential instead of being one.
_REFERENCE = re.compile(
    r"\$\{\{[^{}\r\n]*\}\}|\{\{[^{}\r\n]*\}\}|\$\{[A-Za-z_][A-Za-z0-9_.]*\}|\$\([^()\r\n]*\)"
    r"|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|<[A-Za-z][A-Za-z0-9 _.-]*>|#\{[^{}\r\n]*\}"
)
_ALPHANUMERIC = re.compile(r"[A-Za-z0-9]")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_FILE_PATH = re.compile(r"(?:[\w.~-]*[/\\])+[\w.-]+\.[A-Za-z][A-Za-z0-9]{0,5}")
_PLACEHOLDER_WORDS = frozenset({
    "changeme", "dummy", "example", "fake", "insert", "placeholder", "redacted", "replace", "replaceme",
    "sample", "todo", "your",
})
_PLACEHOLDER_FILL = re.compile(r"(?i)x{4,}|\*{4,}|\.{3,}")
# Random keys change character class (digit, lower, upper) often inside one
# long alphanumeric run; names, words and model identifiers rarely do.
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9]{8,}")


def _kept_value(value: str) -> bool:
    """Empty, already withheld, or only variable references and placeholders."""
    value = value.strip()
    return (
        _FINGERPRINT.fullmatch(value) is not None
        or _ALPHANUMERIC.search(_REFERENCE.sub("", value.replace(REDACTED, ""))) is None
    )


def _opaque(value: str) -> bool:
    for run in _OPAQUE_RUN.finditer(value):
        classes = ["d" if char.isdigit() else "u" if char.isupper() else "l" for char in run.group()]
        # An upper-to-lower change starts a capitalized word, not a new class.
        changes = sum(a != b and (a, b) != ("u", "l") for a, b in zip(classes, classes[1:], strict=False))
        if changes >= 3:
            return True
    return False


def _placeholder(value: str) -> bool:
    words = {word.lower() for word in _CALLEE_WORD.findall(value)}
    return not _PLACEHOLDER_WORDS.isdisjoint(words) or _PLACEHOLDER_FILL.search(value) is not None


def _credential_literal(value: str, *, positional: bool) -> bool:
    """Whether a string literal passed to a credential-named callee is a credential."""
    if _kept_value(value) or any(char.isspace() for char in value) or "://" in value:
        return False
    if _ENVIRONMENT_NAME.fullmatch(value) or _FILE_PATH.fullmatch(value) or _placeholder(value):
        return False
    return positional or _opaque(value)


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
        if "$" in (literal.group("prefix") or "") or (char == "`" and "${" in value):
            continue  # interpolated text is assembled elsewhere
        positional = level == 2 and not named and not (index == 0 and positional_count > 1)
        if not _credential_literal(value, positional=positional):
            continue
        conversion = _LITERAL_CONVERSION.match(text, stop, end)
        whole = conversion is not None and _call_argument_start(text, conversion.end(), end) >= end
        literal_start = literal.start("prefix") if literal.group("prefix") else opening
        found.append((literal_start, stop if whole or not (bounded and terminated) else end))
    return found


# Command-line options that take a credential: '--api-key=v', '--token v', an
# argv list '"--password", "v"' or a YAML list item; user:password options
# (curl -u/--user, httpie -a/--auth); and headers written without a space
# after the colon ('-H "X-Api-Key:v"'), which the assignment rules skip.
# The leading literal dash lets the regex engine skip ahead quickly.
_CLI_OPTION = re.compile(r"-(?<![\w./\\\]-]-)-?[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*")
_CLI_BOUNDARY = re.compile(r"[\w./\\\]-]")
_CLI_USER_OPTIONS = frozenset({"a", "u", "U", "auth", "basic-auth", "proxy-user", "user"})
_CLI_HEADER_OPTIONS = frozenset({"H", "header", "headers"})
_CLI_SPACE = re.compile(r"[ \t]*\\\r?\n[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
_CLI_LIST_GAP = re.compile(r"[ \t]*,[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
_CLI_VALUE = re.compile(
    r"\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s\"'`;|&<>(){}\[\],\\]+)"
)
_CLI_METAVAR = re.compile(r"[A-Z]+(?:[_-][A-Z0-9]+)*")
_CLI_VALUE_LIMIT = 4096
_CLI_WORD = re.compile(r"[a-z][a-z_-]*")
_HEADER_VALUE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9-]*):(?:(?:Bearer|Basic|Token|Bot|Digest|SSWS|ApiKey|Api-Key|token)[ \t]+)?"
    r"(?P<secret>\S[^\r\n]*)"
)
# '-p' is a password only after some commands: a registry 'login' (docker,
# podman, helm registry...) and 'sshpass', and the attached '-pVALUE' of MySQL
# clients ('mysql -p db' prompts and names a database). Elsewhere it is often a
# port or a path. The command is read from at most 256 characters before '-p'.
_CLI_COMMAND_CONTEXT = 256
_CLI_CONTINUATION = re.compile(r"\\\r?\n")
_CLI_REGISTRY_LOGIN = re.compile(
    r"(?:^|[\s(/])(?:docker|podman|nerdctl|buildah|skopeo|oras|crane|helm)[ \t](?:.*[ \t])?login(?:[ \t]|$)"
)
_CLI_SSHPASS = re.compile(r"(?:^|[\s(/])sshpass(?:[ \t]+-[A-Za-z]\S*)*[ \t]+$")
_CLI_MYSQL = re.compile(
    r"(?:^|[\s(/])(?:mysql(?:dump|admin|import|show|check|sh)?|mariadb(?:-dump|-admin)?)[ \t]"
)


def _cli_option_mode(option: str) -> str:
    name = option.lstrip("-")
    if name in _CLI_USER_OPTIONS:
        return "user"
    if name in _CLI_HEADER_OPTIONS:
        return "header"
    if not name.lower().startswith(("no-", "no_")) and _sensitive_assignment_key(re.sub(r"[-.]", "_", name)):
        return "secret"
    return ""


def _cli_password_mode(text: str, option: re.Match[str], logins: bool, mysql: bool) -> str:
    """'secret' for a login's '-p', 'attached' for a MySQL client's '-pVALUE', else ''.

    ``logins`` and ``mysql`` say whether the text names those commands at all.
    """
    if not option.group().startswith("-p") or option.group().startswith("--"):
        return ""
    following = text[option.end():option.end() + 1]
    rules: tuple[re.Pattern[str], ...]
    if option.group() == "-p" and following in {" ", "\t", "\\"}:
        mode, rules = "secret", ((_CLI_REGISTRY_LOGIN, _CLI_SSHPASS) if logins else ())
    elif option.group() != "-p" or following.strip():
        mode, rules = "attached", ((_CLI_MYSQL,) if mysql else ())
    else:
        return ""
    if not rules:
        return ""
    head = _CLI_CONTINUATION.sub(" ", text[max(0, option.start() - _CLI_COMMAND_CONTEXT):option.start()])
    command = head[max(head.rfind(separator) for separator in ";&|\n\r") + 1:]
    return mode if any(rule.search(command) for rule in rules) else ""


def _cli_secret_span(mode: str, value: str, start: int, strict: bool) -> tuple[int, int] | None:
    """The part of an option value ``value`` (at ``start``) that is a credential."""
    if value.startswith("-"):
        return None  # the next option, not a value
    if mode == "user":
        user, colon, password = value.partition(":")
        if not colon or "=" in user or not password or password.isdigit() or _kept_value(password):
            return None
        return start + len(user) + 1, start + len(value)
    if mode == "header":
        header = _HEADER_VALUE.fullmatch(value)
        if header is None or not _sensitive_key(header.group("name")) or _kept_value(header.group("secret")):
            return None
        return start + header.start("secret"), start + len(value)
    if _kept_value(value) or _CLI_METAVAR.fullmatch(value):
        return None
    if not strict and _CLI_WORD.fullmatch(value):
        return None  # prose ('--token to authenticate') or an argparse dest name
    return start, start + len(value)


def _cli_value_span(mode: str, text: str, position: int, strict: bool) -> tuple[int, int] | None:
    if text.startswith("-", position):
        return None  # the next option: checked first so chained options are not rescanned
    value = _CLI_VALUE.match(text, position)
    if value is None:
        return None
    group = next(name for name in ("double", "single", "bare") if value.group(name) is not None)
    return _cli_secret_span(mode, value.group(group), value.start(group), strict)


def _redact_command_credentials(text: str) -> str:
    """Withhold credentials passed as command-line option values."""
    if "-" not in text:
        return text
    pieces: list[str] = []
    cursor = 0
    logins = "login" in text or "sshpass" in text
    mysql = "mysql" in text or "mariadb" in text
    for match in _CLI_OPTION.finditer(text):
        mode = _cli_option_mode(match.group()) or (
            _cli_password_mode(text, match, logins, mysql) if logins or mysql else ""
        )
        if not mode:
            continue
        start = match.start()
        # An opening quote belongs to the option unless it closes a preceding word.
        quote = text[start - 1] if start and text[start - 1] in "\"'" else ""
        if quote and start > 1 and _CLI_BOUNDARY.match(text, start - 2):
            quote = ""
        if start - len(quote) < cursor:
            continue
        position = match.end()
        strict = text.startswith("=", position)
        span: tuple[int, int] | None = None
        closing = -1
        if mode == "attached":
            closing = position
            span = _cli_value_span("secret", text, start + 2, True)
        elif quote and strict:
            # '"--api-key=value"' as one argv element.
            limit = text.find("\n", position, position + _CLI_VALUE_LIMIT)
            closing = text.find(quote, position + 1, position + _CLI_VALUE_LIMIT if limit < 0 else limit)
            if closing >= 0:
                span = _cli_secret_span(mode, text[position + 1:closing], position + 1, True)
        elif quote and text.startswith(quote, position):
            # An argv list or a quoted shell word names its value in quotes.
            gap = _CLI_LIST_GAP.match(text, position + 1)
            if gap is None or not text.startswith(("\"", "'"), gap.end()):
                continue
            closing = position
            span = _cli_value_span(mode, text, gap.end(), False)
        if closing < 0:
            # Plain text, or a quote that does not delimit this option.
            if strict:
                span = _cli_value_span(mode, text, position + 1, True)
            else:
                gap = _CLI_SPACE.match(text, position)
                span = None if gap is None else _cli_value_span(mode, text, gap.end(), False)
        if span is None:
            continue
        pieces.append(text[cursor:span[0]])
        pieces.append(REDACTED)
        cursor = span[1]
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# Dockerfile's legacy 'ENV NAME value', csh/Windows 'setenv NAME value' and
# 'setx NAME value', and C's '#define NAME value' set a name without '='.
# 'ENV A=b C=d' is an assignment.
_ENVIRONMENT_COMMAND = re.compile(
    r"(?m)^[ \t]*(?P<command>ENV|[Ee]nv|setenv|setx|#[ \t]*define)[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<gap>[ \t]+(?:\\\r?\n[ \t]*)?)(?P<value>[^\r\n]*)"
)


def _redact_environment_commands(text: str) -> str:
    """Withhold values set by space-separated environment commands."""
    pieces: list[str] = []
    cursor = 0
    for match in _ENVIRONMENT_COMMAND.finditer(text):
        if match.start() < cursor or not _sensitive_assignment_key(match.group("name")):
            continue
        command = match.group("command")
        start = match.start("value")
        raw = match.group("value").rstrip()
        if raw.startswith(("\"", "'")) and raw.find(raw[0], 1) > 0:
            start, raw = start + 1, raw[1:raw.find(raw[0], 1)]
        elif command == "ENV":
            raw = raw.removesuffix("\\").rstrip()  # the legacy form's value is the rest of the line
        else:
            raw = raw.split()[0] if raw.split() else ""
            if command in {"env", "Env"} and _CLI_WORD.fullmatch(raw):
                continue  # prose: 'Env token should be set'
        if _kept_value(raw):
            continue
        pieces.append(text[cursor:start])
        pieces.append(REDACTED)
        cursor = start + len(raw)
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# XML and .NET configuration: a sensitive element (<password>v</password>,
# <apiKey>v</apiKey>) or a key/name attribute naming a credential beside a
# value attribute or element content (<add key="OpenAIApiKey" value="v"/>,
# <entry key="api.key">v</entry>, <setting name="ApiKey"><value>v</value>).
_XML_TAG = re.compile(
    r"<(?P<tag>[A-Za-z_][\w.:-]*)(?P<attributes>(?:[^<>\"']|\"[^\"<>\r\n]*\"|'[^'<>\r\n]*')*)>"
)
_XML_ATTRIBUTE = re.compile(
    r"(?<![\w.:-])(?P<name>[A-Za-z_][\w.:-]*)[ \t\r\n]*=[ \t\r\n]*"
    r"(?:\"(?P<double>[^\"<>\r\n]*)\"|'(?P<single>[^'<>\r\n]*)')"
)
_XML_VALUE_ELEMENT = re.compile(r"[ \t\r\n]*<(?P<tag>[Vv]alue)>")


class _MarkupContent:
    """Where element content that starts at a position ends.

    Content runs to the first '<' that does not open a terminated CDATA
    section. Each '<' is resolved once and CDATA ends come from one forward
    search, so an unterminated CDATA after every sensitive tag, or tags inside
    CDATA, are not searched to the end of the text again for each tag.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.resolved: dict[int, int] = {}
        # No ']]>' starts in [close_from, close_at); close_at is one, or -1 for none.
        self.close_from = len(text) + 1
        self.close_at = -1

    def cdata_close(self, position: int) -> int:
        """The first ']]>' at or after ``position``, or -1."""
        if not (self.close_from <= position and (self.close_at < 0 or position <= self.close_at)):
            self.close_from, self.close_at = position, self.text.find("]]>", position)
        return self.close_at

    def end(self, start: int) -> int:
        text = self.text
        visited: list[int] = []
        position = start
        while True:
            opening = text.find("<", position)
            if opening < 0:
                end = len(text)
                break
            if opening in self.resolved:
                end = self.resolved[opening]
                break
            visited.append(opening)
            if text.startswith("<![CDATA[", opening):
                close = self.cdata_close(opening + 9)
                if close >= 0:
                    position = close + 3
                    continue
            end = opening
            break
        for opening in visited:
            self.resolved[opening] = end
        return end


def _redact_markup_credentials(text: str) -> str:
    """Withhold credentials in XML elements and key/value attribute pairs."""
    if "<" not in text:
        return text
    contents = _MarkupContent(text)
    spans: list[tuple[int, int]] = []
    for tag in _XML_TAG.finditer(text):
        attributes = tag.group("attributes")
        self_closing = attributes.rstrip().endswith("/")
        local = tag.group("tag").rsplit(":", 1)[-1]
        named = False
        values: list[tuple[int, int]] = []
        for attribute in _XML_ATTRIBUTE.finditer(attributes):
            group = "double" if attribute.group("double") is not None else "single"
            name = attribute.group("name").rsplit(":", 1)[-1].lower()
            if name in {"key", "name"} and _sensitive_assignment_key(attribute.group(group)):
                named = True
            elif name == "value":
                offset = tag.start("attributes")
                values.append((offset + attribute.start(group), offset + attribute.end(group)))
        if named and values:
            spans.extend(values)
            continue
        if self_closing or not (named or _sensitive_assignment_key(local)):
            continue
        start = tag.end()
        inner = _XML_VALUE_ELEMENT.match(text, start) if named else None
        closing_tag = tag.group("tag") if inner is None else inner.group("tag")
        if inner is not None:
            start = inner.end()
        end = contents.end(start)
        if text.startswith("</" + closing_tag, end):
            spans.append((start, end))
    pieces: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if start < cursor or _kept_value(text[start:end]):
            continue
        pieces.append(text[cursor:start])
        pieces.append(REDACTED + "\n" * text.count("\n", start, end))
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# Name/value records in YAML, JSON, HCL and JavaScript text: Kubernetes and
# ECS container environments, CloudFormation parameters and similar lists
# pair a credential's name with its value in a sibling field. A name is at
# most 128 characters, so a 'key:key:key:...' chain is not rescanned from
# every word in it.
_RECORD_NAME = re.compile(
    r"(?<![\w.-])(?P<quote>[\"']?)(?:name|key|Name|Key|NAME|KEY)(?P=quote)[ \t]*[:=][ \t]*"
    r"(?P<value_quote>[\"']?)(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})(?![A-Za-z0-9_.:-])(?P=value_quote)"
)
# Found first (a literal alternation scans quickly), then matched in full.
_RECORD_WORD = re.compile(r"name|key|Name|Key|NAME|KEY")
_RECORD_VALUE = re.compile(r"(?<![\w.-])(?P<quote>[\"']?)(?:value|Value|VALUE)(?P=quote)[ \t]*[:=][ \t]*")
_RECORD_INLINE_VALUE = re.compile(r"\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\])]+")
_RECORD_BRACE = re.compile(r"\}")
_RECORD_COMMENT = re.compile(r"[ \t]#")
_RECORD_BLOCK_MARKERS = frozenset({"", "|", ">", "|-", ">-", "|+", ">+"})
_RECORD_LINES = 16


class _RecordIndex:
    """Line facts that the name/value record lookups of one text share.

    A lookup searches the rest of its name's line for a value field, then up
    to 16 following lines for a sibling one. Repeating that search for every
    name is quadratic on one long line of names, so the current line's braces
    and value fields are indexed once and each following line measured once.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.line = (-1, -1)
        self.braces: list[int] = []
        self.fields: list[re.Match[str]] = []
        self.field_starts: list[int] = []
        self.measured: dict[int, tuple[int, int, str]] = {}
        self.siblings: dict[int, re.Match[str] | None] = {}

    def value_field(self, match: re.Match[str]) -> tuple[re.Match[str], int, int] | None:
        """The value field paired with a record name: (field, search end, sibling column or -1)."""
        text = self.text
        line_start, line_end = self.line
        if not line_start <= match.start() <= line_end:
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line_end = len(text) if line_end < 0 else line_end
            self.line = (line_start, line_end)
            self.braces = [brace.start() for brace in _RECORD_BRACE.finditer(text, line_start, line_end)]
            # Value fields cannot overlap, so the first one after a name is
            # what searching from that name would find.
            self.fields = list(_RECORD_VALUE.finditer(text, line_start, line_end))
            self.field_starts = [field.start() for field in self.fields]
        brace = bisect_left(self.braces, match.end())
        stop = self.braces[brace] if brace < len(self.braces) else line_end
        inline = bisect_left(self.field_starts, match.end())
        if inline < len(self.fields) and self.fields[inline].start() < stop:
            return self.fields[inline], stop, -1
        column = match.start() - line_start
        position = line_end + 1
        for _ in range(_RECORD_LINES):
            if position >= len(text):
                return None
            end, indent, lead = self._measure(position)
            if lead and lead != "#":
                if indent < column or (indent == column and lead == "-"):
                    return None
                if indent == column:
                    if position not in self.siblings:
                        self.siblings[position] = _RECORD_VALUE.match(text, position + indent)
                    sibling = self.siblings[position]
                    if sibling is not None:
                        return sibling, end, column
            position = end + 1
        return None

    def _measure(self, position: int) -> tuple[int, int, str]:
        """The end, indentation and first character of the line starting at ``position``."""
        measured = self.measured.get(position)
        if measured is None:
            text = self.text
            end = text.find("\n", position)
            end = len(text) if end < 0 else end
            line = text[position:end].rstrip("\r")
            content = line.lstrip(" \t")
            measured = self.measured[position] = (end, len(line) - len(content), content[:1])
        return measured


def _record_line_value(text: str, start: int, end: int) -> tuple[int, int] | None:
    """A sibling line's value: a quoted scalar, else the text before a comment and trailing blanks.

    Nothing is returned when a carriage return comes first. Blank runs are
    measured once; a lazy pattern with a trailing-blank lookahead is quadratic
    in the length of a blank run inside one value.
    """
    if start < end and text[start] in "\"'":
        closing = text.find(text[start], start + 1, end)
        if closing >= 0 and text.find("\r", start + 1, closing) < 0:
            return start, closing + 1
    stop = end
    while stop > start and text[stop - 1] in " \t":
        stop -= 1
    comment = _RECORD_COMMENT.search(text, start, end)
    if comment is not None and comment.start() < stop:
        stop = comment.start()
        while stop > start and text[stop - 1] in " \t":
            stop -= 1
    return None if text.find("\r", start, stop) >= 0 else (start, stop)


def _block_end(text: str, line_end: int, column: int) -> int:
    """End of the lines after ``line_end`` indented deeper than ``column`` (a block value)."""
    end = line_end
    position = line_end + 1
    while position < len(text):
        following = text.find("\n", position)
        following = len(text) if following < 0 else following
        line = text[position:following].rstrip("\r")
        content = line.lstrip(" \t")
        if content and len(line) - len(content) <= column:
            break
        end = following
        position = following + 1
    return end


def _redact_name_value_pairs(text: str) -> str:
    """Withhold values that sibling name/key fields identify as credentials."""
    pieces: list[str] = []
    cursor = 0
    index: _RecordIndex | None = None
    # Names that share a value field share its value, so it is decided once.
    decided: set[int] = set()
    for word in _RECORD_WORD.finditer(text):
        start = word.start()
        match = _RECORD_NAME.match(text, start - 1) if start and text[start - 1] in "\"'" else None
        match = match or _RECORD_NAME.match(text, start)
        if match is None or match.start() < cursor or not _sensitive_assignment_key(match.group("name")):
            continue
        index = index or _RecordIndex(text)
        located = index.value_field(match)
        if located is None or located[0].start() in decided:
            continue
        field, stop, column = located
        decided.add(field.start())
        if column < 0:
            value = _RECORD_INLINE_VALUE.match(text, field.end(), stop)
            if value is None:
                continue
            start, end = value.span()
        else:
            span = _record_line_value(text, field.end(), stop)
            if span is None or text[span[0]:span[1]].strip() in _RECORD_BLOCK_MARKERS:
                start, end = field.end(), _block_end(text, stop, column)
            else:
                start, end = span
        raw = text[start:end]
        if raw[:1] in {"\"", "'"} and raw.endswith(raw[0]) and len(raw) > 1:
            start, end, raw = start + 1, end - 1, raw[1:-1]
        if start < cursor or _kept_value(raw):
            continue
        pieces.append(text[cursor:start])
        pieces.append(REDACTED + "\n" * raw.count("\n"))
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


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


# Names whose last word names a credential (openaiKey, OPENAI-KEY, dbPass,
# stripe.secretKey, key) also name sort keys, page tokens and cache keys, so
# only a literal that looks like an opaque key is withheld from them. An
# unquoted value counts only after '=': after ':' it is usually a type. Both
# patterns below start at the separator, which is rarer than a name, and the
# name before it is read backwards.
_OPAQUE_VALUE = re.compile(
    r"(?P<separator>:=|=(?![=>~])|:(?![:=]))[ \t]*"
    r"(?:(?:[rRbBuU]{1,2}|@)?(?P<quote>[\"'`])(?P<quoted>[^\"'`\r\n]{8,})(?P=quote)"
    r"|(?P<bare>[A-Za-z0-9+/_.~-]{8,}={0,2})(?![^\s,;)}\]]))"
)
_OPAQUE_NAME = re.compile(r"[A-Za-z_$][\w$-]*(?:\.[A-Za-z_$][\w$-]*)*")
_OPAQUE_NAME_WORDS = frozenset({
    "apikey", "credential", "credentials", "key", "pass", "passwd", "password", "pwd", "secret", "token",
})
# An unquoted value made of words is an identifier (key = Ed25519PrivateKey).
# Random keys almost always have a one- or two-letter lowercase run.
_WORDY = re.compile(r"(?:[A-Z][a-z]+|[a-z]{3,}|[A-Z]{2,}|[0-9]+|_)+")
# A sensitive key whose colon ends its line, then a lone word on the next,
# unindented line ('token:\n<value>' in notes and error text). An indented
# line is YAML nesting, which the multiline pass handles.
_NEXT_LINE_VALUE = re.compile(r":[ \t]*\r?\n(?P<value>[^\s\"'#()\[\]{}<>,;]+)[ \t]*(?=\r?\n|\Z)")
_NEXT_LINE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")


def _name_before(text: str, end: int, characters: str) -> str:
    """The longest run of letters, digits and ``characters`` that ends at ``end``."""
    start = end
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in characters):
        start -= 1
    return text[start:end]


def _blanks_before(text: str, end: int) -> int:
    """Where the spaces and tabs that end at ``end`` start."""
    while end > 0 and text[end - 1] in " \t":
        end -= 1
    return end


def _credential_name(name: str) -> bool:
    """Whether a name's last word names a credential ('monkey' and 'bypass' do not)."""
    if not _OPAQUE_NAME.fullmatch(name):
        return False
    words = _CALLEE_WORD.findall(name.rsplit(".", 1)[-1])
    return bool(words) and words[-1].lower() in _OPAQUE_NAME_WORDS


def _assigned_name(text: str, separator: int) -> str:
    """The name assigned at ``separator``, past a closing quote and a simple type annotation.

    A '?' before the separator is a nullable type ('String? =') or Make's '?='.
    """
    end = _blanks_before(text, separator)
    if end > 0 and text[end - 1] in "\"'":
        end -= 1
    elif end > 0 and text[end - 1] == "?":
        end = _blanks_before(text, end - 1)
    name = _name_before(text, end, "_$.-")
    colon = _blanks_before(text, end - len(name))
    typed = colon > 0 and text[colon - 1] == ":" and (colon < 2 or text[colon - 2] != ":")
    if name and typed and not _credential_name(name):
        return _name_before(text, _blanks_before(text, colon - 1), "_$.-")  # 'openaiKey: string = "..."'
    return name


def _redact_opaque_assignments(text: str) -> str:
    """Withhold opaque literals given to credential-like names, and a lone value after 'token:'."""
    spans: list[tuple[int, int]] = []
    for match in _OPAQUE_VALUE.finditer(text):
        if not _credential_name(_assigned_name(text, match.start())):
            continue
        group = "quoted" if match.group("quoted") is not None else "bare"
        value = match.group(group)
        if group == "bare" and (match.group("separator") == ":" or _WORDY.fullmatch(value)):
            continue
        if match.group("quote") == "`" and "${" in value:
            continue  # interpolated text is assembled elsewhere
        if _credential_literal(value, positional=False):
            spans.append(match.span(group))
    for match in _NEXT_LINE_VALUE.finditer(text):
        key = _name_before(text, match.start(), "_.-")
        if not _NEXT_LINE_KEY.fullmatch(key) or not _sensitive_assignment_key(key):
            continue
        value = match.group("value")
        if not _CLI_WORD.fullmatch(value) and _credential_literal(value, positional=True):
            spans.append(match.span("value"))
    if not spans:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if start >= cursor:
            pieces.append(text[cursor:start])
            pieces.append(REDACTED)
            cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _sensitive_key(key: str) -> bool:
    normalized = _KEY_NORMALISE.sub("", key.lower())
    # This runs for every key of every sanitized record. ``str.endswith`` with
    # a tuple compares the suffixes in C; a Python loop over length-bucketed
    # sets measured about twice as slow per key, so keep the builtin.
    return normalized in _SENSITIVE_NAMES or normalized.endswith(_SENSITIVE_SUFFIXES)


def _sensitive_assignment_key(key: str) -> bool:
    """Sensitive-key test for assignments and mapping entries inside text."""
    return _sensitive_key(key) or _ASSIGNMENT_CREDENTIAL_NAME.fullmatch(key.strip()) is not None


def credential_id(value: Any) -> str:
    """Stable opaque identity for raw credentials; never retain prefix/suffix."""
    s = str(value)
    if _FINGERPRINT.fullmatch(s):
        return s
    return "credential:sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


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
    """Redact recognizable credentials, assignments, auth headers and URL secrets.

    Context-named values are also withheld: XML elements and attributes,
    name/value records, command-line options, environment commands, basic
    authentication pairs and literals passed to credential-named callees.
    """
    if not isinstance(text, str):
        text = str(text)  # type: ignore[unreachable]  # untyped callers still pass bytes-like values
    if len(text) > _MAX_SANITIZATION_CHARS:
        raise SanitizationLimitError("text sanitization size limit exceeded")
    text = _PEM.sub(lambda m: REDACTED + "\n" * m.group(0).count("\n"), text)
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
    text = _JWT.sub(REDACTED, text)
    text = _SECRET_TOKEN.sub(REDACTED, text)
    # The scheme's whitespace can span lines; keep them so excerpt lines stay aligned.
    text = _AUTH.sub(lambda m: m.group(1) + " " + REDACTED + "\n" * m.group().count("\n"), text)

    def assignments(value: str, depth: int = 0) -> str:
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
                clean = assignments(bare, depth + 1) if depth < 8 else REDACTED
            else:
                return full
            return key + sep + quote + clean + quote

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
