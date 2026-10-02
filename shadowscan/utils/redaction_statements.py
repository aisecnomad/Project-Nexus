"""Complete sensitive assignment statements in source code.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. Candidates are sensitive names before ':', '=' or R's '<-', and
sensitive literal subscripts ('config["password"] ='). Each candidate's
right-hand side is found with Python's tokenizer, which also lexes the
strings, brackets and continued lines of JavaScript, R and similar languages
closely enough to find where the expression ends. Nothing is evaluated.
"""

from __future__ import annotations

import heapq
import io
import re
import token
import tokenize
from bisect import bisect_right
from collections.abc import Iterator

from shadowscan.utils.redaction_formats import _URL
from shadowscan.utils.redaction_rules import (
    _FINGERPRINT,
    _MAX_REDACTION_WORK,
    REDACTED,
    SanitizationLimitError,
    _sensitive_assignment_key,
)

# R assigns with '<-' and '<<-', Go with ':=' and several languages with '||=', '+=' and
# '.='; the scan treats them like '='. '=>' (hash rocket, arrow), '==' and '=~' contain an
# '=' that assigns nothing: they are read whole, and left to the assignment rules.
_PYTHON_ASSIGNMENT_KEY = re.compile(
    r"(?<![\w.-])(?P<key>[A-Za-z_][A-Za-z0-9_.]*)[ \t]*"
    r"(?P<separator>:=|:|\|\|=|&&=|\?\?=|[-+.]=|=(?![=>~])|<<?-(?!-))"
)
_INDEXED_ASSIGNMENT_KEY = re.compile(
    r"\[[ \t\r\n]*(?P<quote>[\"'`])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,100})"
    r"(?P=quote)"
)
_TARGET_ATTRIBUTE = re.compile(r"\.[A-Za-z_$][A-Za-z0-9_$]*")


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
            elif char == "." and not text.startswith(".=", position):
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
                operator = next(
                    (
                        op
                        for op in (
                            "&&=",
                            "||=",
                            "??=",
                            "+=",
                            "-=",
                            ".=",
                            "<<-",
                            "<-",
                            "=",
                        )
                        if text.startswith(op, position)
                    ),
                    None,
                )
                if operator and not text.startswith(("==", "=>", "=~"), position):
                    yield match.start(), key, "=", position + len(operator)
                break
            position += 1


def _assignment_candidates(text: str) -> Iterator[tuple[int, str, str, int]]:
    plain = (
        (match.start(), match.group("key"), match.group("separator"), match.end())
        for match in _PYTHON_ASSIGNMENT_KEY.finditer(text)
    )
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
# The tokenizer reads at most this many characters of a run of spaces, tabs and
# form feeds; the rest of the run is skipped and positions are mapped back to
# the text. Python 3.11's pure-Python tokenizer rescans a run once per character
# when a character it cannot tokenize ('$', '?', a control character, a lone
# quote) ends it, so one long run made a scan quadratic. Blanks only separate
# tokens or sit inside a string or comment, so the shortened line yields the
# same tokens, and every Python version reads it. Indentation the tokenizer
# measures, in one linear pass, is kept whole. At least _SCAN_LOOKAHEAD, so no
# token is nearer a cut in the shortened line than in the text.
_MAX_TOKENIZED_BLANKS = 8
_LONG_BLANK_RUN = re.compile(rf"[ \t\f]{{{_MAX_TOKENIZED_BLANKS + 1},}}")
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
# A ';' glued into an unquoted value: not followed by whitespace, the end of
# the text or another ``name=`` pair (see redaction_assignments._VALUE_SEMICOLON).
_GLUED_SEMICOLON = re.compile(r";(?!\s|\Z|[A-Za-z_][A-Za-z0-9_.-]*\s*=)")
# Operators after which an assigned expression continues on the next line.
_CONTINUING_OPERATORS = frozenset({"+", "-", "*", "/", "**", "&", "|", "?", ":", "=", "."})


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
        # Open f-strings: a colon inside one is a format specifier.
        self.fstrings = 0

    def add(self, item: tokenize.TokenInfo, depth: int, end: int) -> None:
        """Record a token at bracket ``depth`` that ends at text offset ``end``."""
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
        self.fstrings += (item.type in _FSTRING_STARTS) - (item.type in _FSTRING_ENDS)
        if item.type == token.OP and item.string == ":" and not self.fstrings:
            self.colons[end] = len(self.kinds)
        self.kinds.append(kind)
        self.depths.append(depth)
        self.last = end

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


class _LineReader:
    """The physical lines one scan reads, each to at most ``limit`` characters.

    A line cut at the limit ends the input there: ``cut`` is its offset.
    ``offsets`` holds the text offset of each line the tokenizer numbers.
    Long blank runs are shortened (see ``_MAX_TOKENIZED_BLANKS``): ``shifts``
    maps a shortened line's columns back, and ``offset`` gives the text offset
    of any tokenizer position. The scan sets ``statement_start`` while the
    next line starts a statement, whose leading blanks are its indentation.
    """

    def __init__(self, scanner: _AssignmentScanner, start: int, limit: int) -> None:
        if scanner.stream is None:
            scanner.stream = io.StringIO(scanner.text)
        self.scanner = scanner
        self.stream = scanner.stream
        self.stream.seek(start)
        self.length = len(scanner.text)
        self.limit = limit
        self.offsets = [start]
        # Per shortened line: the columns that end a kept part of a run, and
        # the characters removed from the line up to each of them.
        self.shifts: dict[int, tuple[list[int], list[int]]] = {}
        self.statement_start = True
        self.cut = -1

    def readline(self) -> str:
        line = "" if self.cut >= 0 else self.stream.readline(self.limit)
        self.scanner.charge(len(line))
        offset = self.stream.tell()
        if line and line[-1] != "\n" and offset < self.length:
            self.cut = offset
        self.offsets.append(offset)
        return self._shorten(line, len(self.offsets) - 1)

    def _shorten(self, line: str, row: int) -> str:
        """``line`` with each long blank run cut to its first characters, except measured indentation."""
        pieces: list[str] = []
        ends: list[int] = []
        removed: list[int] = []
        cursor = dropped = 0
        for run in _LONG_BLANK_RUN.finditer(line):
            if run.start() == 0 and self.statement_start:
                continue
            kept = run.start() + _MAX_TOKENIZED_BLANKS
            pieces.append(line[cursor:kept])
            ends.append(kept - dropped)
            dropped += run.end() - kept
            removed.append(dropped)
            cursor = run.end()
        if not pieces:
            return line
        self.shifts[row] = (ends, removed)
        pieces.append(line[cursor:])
        return "".join(pieces)

    def offset(self, row: int, column: int) -> int:
        """The text offset of the tokenizer's ``row`` and ``column``."""
        shift = self.shifts.get(row)
        if shift is not None:
            index = bisect_right(shift[0], column)
            column += shift[1][index - 1] if index else 0
        return self.offsets[row - 1] + column

    def end(self, item: tokenize.TokenInfo) -> int:
        """The text offset just past ``item``."""
        return self.offset(*item.end)

    def undecided(self, stopped: tokenize.TokenInfo | None) -> bool:
        """Whether a scan that stopped at ``stopped`` (None: at an error) may depend on the cut.

        Tokens that end well before the cut are the ones the whole line
        yields, so a scan that stops at such a token is decided. A stop at end
        of input, near the cut, at a quote whose string may close past it, or
        at a tokenizer error is not.
        """
        return self.cut >= 0 and (
            stopped is None
            or stopped.type == token.ENDMARKER
            or (stopped.type == token.ERRORTOKEN and stopped.string in _QUOTE_ERRORS)
            or self.end(stopped) > self.cut - _SCAN_LOOKAHEAD
        )


def _opens_argument(text: str, start: int) -> bool:
    """Whether the candidate at ``start`` follows '(' or ',', as a call argument does."""
    previous = start - 1
    while previous >= 0 and text[previous] in " \t\r\n":
        previous -= 1
    return previous >= 0 and text[previous] in "(,"


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

    def _continues(self, following: int, previous_operator: str, assigned: bool) -> bool:
        """Whether an assigned expression goes on past the newline that ends at ``following``.

        JavaScript permits binary/member/ternary expressions to continue
        across an unescaped newline in either direction.
        """
        text = self.text
        while following < len(text) and text[following] in " \t\r\n":
            self.charge(1)
            following += 1
        return assigned and (
            previous_operator in _CONTINUING_OPERATORS
            or (following < len(text) and text[following] in "+-*/.?&|")
        )

    def _scan(
        self,
        start: int,
        candidate_end: int,
        annotated: bool,
        limit: int,
    ) -> tuple[int | None, int, bool] | None:
        """One scan reading at most ``limit`` characters of each line; None if a cut may matter.

        A cut line ends the input there; see ``_LineReader.undecided``.
        """
        text = self.text
        lines = _LineReader(self, candidate_end, limit)
        assigned_at: int | None = None if annotated else candidate_end
        end = len(text)
        brackets: list[str] = []
        argument = not annotated and _opens_argument(text, start)
        previous_operator = ""
        record = _AnnotationScan() if annotated else None
        definitive = True
        stopped: tokenize.TokenInfo | None = None
        quoted = False
        try:
            for item in tokenize.generate_tokens(lines.readline):
                stopped = item
                quoted = quoted or '"' in item.string or "'" in item.string
                # The tokenizer yields every token of a line before it reads
                # the next. That line starts a statement, whose leading blanks
                # are measured indentation, only after a newline outside brackets.
                lines.statement_start = item.type in _NEWLINE_TOKENS and not brackets
                position = lines.offset(*item.start)
                if item.type == token.ERRORTOKEN and not item.string.isspace():
                    # Incomplete single-quoted strings generate error tokens,
                    # not TokenError. A semicolon inside one is not a boundary.
                    break
                if record is not None:
                    record.add(item, len(brackets), lines.end(item))
                if item.type == token.OP:
                    if item.string == "`" or (
                        item.string in {"/", "//"} and text.startswith(("/*", "//"), position)
                    ):
                        # Python's tokenizer is not a JavaScript template/comment
                        # lexer (some Python versions classify backticks as OP).
                        # Withhold the remaining expression conservatively instead
                        # of exposing fragments after its first physical newline.
                        break
                    if item.string == "=" and assigned_at is None and not brackets:
                        assigned_at = lines.end(item)
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
                    elif (
                        assigned_at is not None
                        and not brackets
                        and (item.string == ";" or (argument and item.string == ","))
                    ):
                        # An unquoted value (.env style) may itself contain a
                        # ';' that is not followed by whitespace or ``name=``.
                        if item.string == ";" and not quoted and _GLUED_SEMICOLON.match(text, position):
                            previous_operator = item.string
                            continue
                        end = position
                        break
                    previous_operator = item.string
                elif item.type == token.NEWLINE:
                    assigned = assigned_at is not None
                    if self._continues(position + len(item.string), previous_operator, assigned):
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
        except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeError) as exc:
            # Once '=' is seen, incomplete source must not expose any RHS,
            # including credential fragments on subsequent physical lines.
            # Indentation and nesting errors depend on where a scan started,
            # and so may the codec errors Python 3.12+ tokenizers raise for a
            # lone surrogate or a non-ASCII character after a lone '\r'.
            definitive = not isinstance(exc, (IndentationError, UnicodeError)) and "nest" not in str(exc)
            stopped = None
        if lines.undecided(stopped):
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
