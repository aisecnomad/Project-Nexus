"""Lexical ranges that cannot establish executable agent code.

Offsets refer to the original source. Signature patterns still see literal
arguments and module specifiers when they start at executable syntax (for
example ``from "@langchain/langgraph"``), but a match *starting* inside a
comment or a string cannot by itself establish framework use.
"""

from __future__ import annotations

import io
import re
import tokenize
from bisect import bisect_right
from dataclasses import dataclass

from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

_RUBY_BLOCK_END = re.compile(r"(?m)^=end(?:\s|$)")

_FSTRING_PREFIX = re.compile(r"(?i)^([rubf]{1,3})(\"\"\"|'''|\"|')")
_STRING_PREFIX = re.compile(r"(?i)[rubf]{0,3}(\"\"\"|'''|\"|')")
_MAX_FSTRING_DEPTH = 24

# A slash is a regular-expression delimiter only where an expression can start.
# In particular, after an identifier, literal, or closing expression delimiter
# it is division. This is deliberately a lexical approximation, not a JS parser.
_REGEX_PREFIX_WORDS = frozenset(
    {
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }
)
_CONTROL_HEADS = frozenset({"catch", "for", "if", "switch", "while", "with"})
# Keywords in a module, generator or async function but ordinary names in a script:
# without a parse, a `/` after one of them cannot be classified.
_AMBIGUOUS_REGEX_WORDS = frozenset({"await", "yield"})
_MAX_REGEX_LENGTH = 8192
# Extensions whose source is TypeScript (a postfix "!" asserts non-null), and plain JavaScript extensions
# in which React code keeps JSX anyway.
_TYPESCRIPT_DIALECTS = frozenset({".ts", ".tsx", ".mts", ".cts"})
_JSX_RETRY_DIALECTS = frozenset({".js", ".mjs", ".cjs"})
# Qt Linguist translations (<TS>) and Tiled tilesets (<tileset>) are XML documents named .ts or .tsx; no
# TypeScript starts that way, and a file that also has module syntax is not treated as one.
_XML_DOCUMENT = re.compile(
    r"\ufeff?\s*(?:<\?xml[^>]*\?>\s*)?(?:<!DOCTYPE\s+(?:TS|tileset)[^>]*>\s*)?<(?:TS|tileset)[\s>]"
)
_MODULE_SYNTAX = re.compile(r"^[ \t]*(?:import|export)\b|\brequire\s*\(", re.MULTILINE)
# Real regular expression literals can be long: generated Unicode tables such as emoji-regex's run to
# tens of kilobytes on one line. The scan is linear, never leaves its line and is not repeated once it
# fails (the rest of the line is skipped), so this bound only decides when a literal that has not
# closed is too long to trust.
_MAX_REGEX_LITERAL_LENGTH = 262_144
# ECMAScript line terminators: LF, CR, LINE SEPARATOR and PARAGRAPH SEPARATOR (CRLF counts once).
_JS_LINE_TERMINATORS = "\n\r\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}"
_JS_LINE_BREAK = re.compile(f"[{_JS_LINE_TERMINATORS}]")
# What can open a string, a template or a comment when the body of a regular expression is read as code.
_REGEX_BODY_OPENER = re.compile("[\"'`/]")
_NON_SPACE = re.compile(r"\S")


def _js_line_end(text: str, pos: int) -> int:
    """Return the offset of the first line terminator at or after ``pos``, or the end of ``text``."""
    match = _JS_LINE_BREAK.search(text, pos)
    return len(text) if match is None else match.start()


def _skip_trivia(text: str, pos: int) -> int:
    """Return the first offset at or after ``pos`` that is neither whitespace nor inside a comment.

    This only looks ahead. An unterminated block comment returns -1: the lexer
    reports it when its own walk reaches the comment.
    """
    size = len(text)
    while pos < size:
        if text[pos].isspace():
            pos += 1
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            if end < 0:
                return -1
            pos = end + 2
        elif text.startswith("//", pos):
            pos = _js_line_end(text, pos + 2)
        else:
            break
    return pos


def _property_name_start(text: str, pos: int) -> int:
    """Return the offset of the name after a property-access dot that ends at ``pos``, or -1."""
    if pos < len(text) and (text[pos].isalpha() or text[pos] in "_$"):
        return pos
    pos = _skip_trivia(text, pos)
    if pos >= 0 and text.startswith("#", pos):  # private name: `this.#of`
        pos += 1
    if 0 <= pos < len(text) and (text[pos].isalpha() or text[pos] in "_$"):
        return pos
    return -1


def _javascript_regex_end(text: str, start: int, budget: _LookaheadBudget | None = None) -> int | None:
    """Find the end of a regex literal, honoring escapes and character classes.

    A missing delimiter or an oversized literal is ambiguous; the caller masks
    the remainder of that line and reports incomplete lexical analysis. A caller
    that tries a candidate it will not consume passes ``budget``, which is charged
    the length scanned, so that thousands of candidates cannot each rescan a line.
    """
    pos = start + 1
    in_class = False
    end = None
    limit = min(len(text), start + _MAX_REGEX_LITERAL_LENGTH)
    while pos < limit and text[pos] not in _JS_LINE_TERMINATORS:
        char = text[pos]
        if char == "\\":
            if pos + 1 >= limit or text[pos + 1] in _JS_LINE_TERMINATORS:
                break
            pos += 2
            continue
        if char == "[" and not in_class:
            in_class = True
        elif char == "]" and in_class:
            in_class = False
        elif char == "/" and not in_class:
            pos += 1
            # Flags are identifiers in the lexical grammar. A later syntax
            # check can reject duplicates or unsupported flag names.
            while pos < len(text) and (text[pos].isalnum() or text[pos] in "_$"):
                pos += 1
            end = pos
            break
        pos += 1
    if budget is not None:
        budget.spend(pos - start)
    return end


_MAX_TYPE_ARGUMENTS_LENGTH = 1024
# Deciding whether a "<" opens a JSX element looks ahead over a bounded window. Each look-ahead is
# cheap, but a file of thousands of "<A>(" would repeat a window of thousands of characters for every
# one of them. The look-ahead of one walk is therefore charged to an allowance made of a fixed floor
# plus a multiple of the input length: far more than real components spend (a small fraction of a
# character per character), and little enough that hostile input ends within a second or so.
_LOOKAHEAD_FLOOR = 65_536
_LOOKAHEAD_PER_CHARACTER = 4


class _LookaheadBudget:
    """The look-ahead allowance of one lexical walk; exhausting it raises ``MatchTimeoutError``.

    The connector reports that as an incomplete scan of the file, like the other bounded analyses.
    The per-file time budget is checked at the same points.
    """

    __slots__ = ("remaining",)

    def __init__(self, size: int) -> None:
        self.remaining = _LOOKAHEAD_FLOOR + _LOOKAHEAD_PER_CHARACTER * size

    def spend(self, count: int) -> None:
        self.remaining -= count
        if self.remaining < 0:
            raise MatchTimeoutError("JavaScript lexical analysis look-ahead budget exceeded")
        pattern_timeout()


def _type_arguments_end(text: str, start: int, budget: _LookaheadBudget) -> int | None:
    """Return the offset after a balanced TypeScript type-argument list at ``text[start] == "<"``.

    Handles nested lists, quoted literal types and `=>` in function types.
    Anything unbalanced within the bound is not a type-argument list.
    """
    depth = 0
    pos = start
    limit = min(len(text), start + _MAX_TYPE_ARGUMENTS_LENGTH)
    end = None
    while pos < limit:
        char = text[pos]
        if char in "\"'`":
            closing = text.find(char, pos + 1, limit)
            if closing < 0:
                pos = limit
                break
            pos = closing + 1
            continue
        if char == "<":
            depth += 1
        elif char == ">" and text[pos - 1] != "=":
            depth -= 1
            if depth == 0:
                end = pos + 1
                break
        pos += 1
    budget.spend(pos - start)
    return end


def _parenthesized_end(text: str, start: int, budget: _LookaheadBudget) -> int | None:
    """Return the offset after the balanced parenthesized group at ``text[start] == "("``."""
    depth = 0
    pos = start
    limit = min(len(text), start + _MAX_REGEX_LENGTH)
    end = None
    while pos < limit:
        char = text[pos]
        if char in "\"'`":
            closing = text.find(char, pos + 1, limit)
            if closing < 0:
                pos = limit
                break
            pos = closing + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                end = pos + 1
                break
        pos += 1
    budget.spend(pos - start)
    return end


def _jsx_open_tag(text: str, start: int, budget: _LookaheadBudget) -> tuple[str, int] | None:
    """Return the JSX tag name and the offset where its attributes begin.

    TSX allows explicit type arguments on an element (`<Select<Option> ...>`,
    `<Form<{ email: string }>>`); they are skipped so that the type argument
    is not mistaken for a nested opening tag.
    """
    if text.startswith("<>", start):
        return "", start + 1
    pos = start + 1
    if pos >= len(text) or not (text[pos].isascii() and text[pos].isalpha()):
        return None
    pos += 1
    while pos < min(len(text), start + 129) and (
        (text[pos].isascii() and text[pos].isalnum()) or text[pos] in "_.$:-"
    ):
        pos += 1
    name = text[start + 1 : pos]
    if pos < len(text) and text[pos] == "<":
        after = _type_arguments_end(text, pos, budget)
        if after is None or after == len(text) or text[after] not in " \t\r\n/>":
            return None
        return name, after
    if pos == len(text) or text[pos] not in " \t\r\n/>":
        return None
    # A bare `<T>(...) => ...` in TSX is a generic arrow function, with no
    # JSX closing tag. Leave its body visible to the scanner. Element text
    # that merely starts with a parenthesis (`<Text>({n})</Text>`) is JSX.
    if name[0].isupper():
        if text.startswith(">(", pos):
            group_end = _parenthesized_end(text, pos + 1, budget)
            if group_end is None or text[group_end : group_end + 64].lstrip().startswith(("=>", ":")):
                return None
        # Constrained and defaulted TSX generic arrows can look like JSX
        # opening tags: `<T extends object>(x: T) => x` and `<T = X>(...)`.
        suffix = text[pos : min(len(text), pos + 64)].lstrip()
        constraint = suffix.startswith("extends") and (
            len(suffix) == 7 or suffix[7].isspace() or suffix[7] in "<{"
        )
        if constraint or suffix.startswith("="):
            end = text.find(">(", pos, min(len(text), pos + 1024))
            if end >= 0 and "=>" in text[end + 2 : min(len(text), end + 258)]:
                return None
    return name, pos


def noncode_ranges(
    text: str,
    language: str | None,
    dialect: str | None = None,
    *,
    jsx: bool = False,
) -> tuple[list[tuple[int, int]], bool]:
    """Return sorted ignored half-open spans and whether lexing was incomplete."""
    if language == "python":
        return _python_ranges(text)
    if language == "javascript":
        typescript = dialect in _TYPESCRIPT_DIALECTS
        if typescript and _XML_DOCUMENT.match(text) and not _MODULE_SYNTAX.search(text):
            return [(0, len(text))], False  # a Qt Linguist translation: data that happens to be named .ts
        spans, incomplete = _javascript_ranges(text, jsx=jsx, typescript=typescript)
        if incomplete and not jsx and dialect in _JSX_RETRY_DIALECTS:
            # React projects keep JSX in .js files, and a JSX closing tag read as code is a division
            # followed by an unterminated regular expression. Valid JavaScript has no "<" where an
            # expression starts, so the JSX walk is only used when it reads the whole file cleanly.
            retried, retried_incomplete = _javascript_ranges(text, jsx=True, typescript=typescript)
            if not retried_incomplete:
                return retried, False
        return spans, incomplete
    if language in {"go", "rust", "java", "dotnet", "ruby", "php", "swift", "dart"}:
        return _other_source_ranges(text, language, dialect)
    return [], False


def _python_ranges(text: str) -> tuple[list[tuple[int, int]], bool]:
    # Python's file reader treats a standalone CR as a newline, whereas
    # StringIO.readline does not. Normalize only those CRs, preserving every
    # offset so ignored spans still refer to the original source.
    lex_text = re.sub(r"\r(?!\n)", "\n", text) if "\r" in text else text
    # tokenize.readline advances at '\n' only. str.splitlines() also treats
    # Unicode separators inside a quoted value as line breaks and would shift
    # later ignored spans away from their original source positions.
    offsets = [0, *(match.end() for match in re.finditer("\n", lex_text))]
    if offsets[-1] != len(lex_text):
        offsets.append(len(lex_text))

    spans: list[tuple[int, int]] = []
    ambiguous = False
    resume_line: int | None = 0  # zero-based line at which the tokenizer (re)starts
    reader = io.StringIO(lex_text)
    while resume_line is not None:
        reader.seek(offsets[min(resume_line, len(offsets) - 1)])
        ambiguous, resume_line = _python_ranges_from(lex_text, offsets, resume_line, spans, reader)
    return sorted(spans), ambiguous


_UNTERMINATED_ONE_LINE_STRING = "unterminated string literal"


def _python_ranges_from(
    text: str,
    offsets: list[int],
    first_line: int,
    spans: list[tuple[int, int]],
    reader: io.StringIO,
) -> tuple[bool, int | None]:
    """Tokenize from ``first_line``; return (ambiguous, line to resume at or None)."""

    def offset(position: tuple[int, int]) -> int:
        line, column = position
        line += first_line
        return min(len(text), offsets[min(line - 1, len(offsets) - 1)] + column)

    fstring_starts: list[int] = []
    fstring_start_type = getattr(tokenize, "FSTRING_START", None)
    fstring_end_type = getattr(tokenize, "FSTRING_END", None)
    fstring_parts = {
        getattr(tokenize, name)
        for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END")
        if hasattr(tokenize, name)
    }
    try:
        for token in tokenize.generate_tokens(reader.readline):
            if token.type == tokenize.STRING:
                prefix = _FSTRING_PREFIX.match(token.string)
                if prefix is not None and "f" in prefix.group(1).lower():
                    inner, incomplete = _legacy_fstring_ranges(token.string, offset(token.start))
                    if incomplete:
                        spans.append((offset(token.start), offset(token.end)))
                        return True, None
                    spans.extend(inner)
                else:
                    spans.append((offset(token.start), offset(token.end)))
            elif token.type == tokenize.COMMENT or token.type in fstring_parts:
                spans.append((offset(token.start), offset(token.end)))
                if token.type == fstring_start_type:
                    fstring_starts.append(offset(token.start))
                elif token.type == fstring_end_type and fstring_starts:
                    fstring_starts.pop()
            elif token.type == tokenize.ERRORTOKEN and token.string in {'"', "'"}:
                # Unclosed one-line literal (Python 3.11): do not scan its prose
                # as code; the tokenizer itself continues on the next line.
                start = offset(token.start)
                end = text.find("\n", start)
                spans.append((start, len(text) if end < 0 else end))
    except (tokenize.TokenError, IndentationError) as exc:
        if fstring_starts:
            start = fstring_starts[0]
            spans[:] = [*(span for span in spans if span[1] <= start), (start, len(text))]
            return True, None
        message = str(exc.args[0]) if exc.args else ""
        position = exc.args[1] if isinstance(exc, tokenize.TokenError) else (exc.lineno or 1, exc.offset or 0)
        if isinstance(exc, tokenize.TokenError) and message.startswith(_UNTERMINATED_ONE_LINE_STRING):
            # Python 3.12+ aborts on an unclosed one-line literal where 3.11
            # emitted an ERRORTOKEN and carried on. Mask that line (the
            # reported column is one past the opening quote) and resume on the
            # next line so the remainder keeps the same coverage as 3.11.
            start = max(offset((position[0], 0)), offset(position) - 1)
            end = text.find("\n", start)
            if end < 0:
                spans.append((start, len(text)))
                return False, None
            spans.append((start, end))
            return False, first_line + position[0]
        if isinstance(exc, tokenize.TokenError) and "multi-line statement" in message:
            # An unclosed bracket: every token through EOF has been read, and its
            # literals masked, so nothing is left to mask. Python 3.11 reports
            # this error past the last line; 3.12+ reports the start of the last
            # line, which would mask code the tokenizer already read.
            return False, None
        start = offset(position)
        if start < len(text):  # an error reported at EOF itself masks nothing
            spans.append((start, len(text)))
        # An unterminated multi-line literal is masked through EOF: nothing after
        # its opening can be executable Python. Any other tokenizer error
        # (Python 3.12+ raises for mid-file lexical errors that 3.11 tolerated)
        # masks the remainder ambiguously and must mark the file incomplete.
        return not (isinstance(exc, tokenize.TokenError) and "EOF" in message), None
    if fstring_starts:
        start = fstring_starts[0]
        spans[:] = [*(span for span in spans if span[1] <= start), (start, len(text))]
        return True, None
    return False, None


def _legacy_fstring_ranges(token: str, base: int, depth: int = 0) -> tuple[list[tuple[int, int]], bool]:
    """Find executable replacements in a Python 3.11 f-string STRING token.

    Python 3.12+ tokenizes f-string text and expressions independently. Python
    3.11 returns one STRING token, so mask literal text and recursively inspect
    replacement expressions, including nested format fields and f-strings.
    Ambiguous or deeply nested input is masked entirely and marked incomplete.
    """
    if depth > _MAX_FSTRING_DEPTH:
        return [(base, base + len(token))], True
    match = _FSTRING_PREFIX.match(token)
    if match is None or "f" not in match.group(1).lower():
        return [(base, base + len(token))], False
    quote = match.group(2)
    body_start, body_end = match.end(), len(token) - len(quote)
    if body_end < body_start or not token.endswith(quote):
        return [(base, base + len(token))], True
    spans: list[tuple[int, int]] = [(base, base + body_start)]

    def mask(start: int, end: int) -> None:
        if end > start:
            spans.append((base + start, base + end))

    def quoted(start: int) -> tuple[int, bool, bool] | None:
        # A replacement field may itself contain a nested f-string. A prefix
        # must start at a token boundary; ordinary identifiers are not strings.
        prefix = _STRING_PREFIX.match(token, start)
        if prefix is None or (start > body_start and (token[start - 1].isalnum() or token[start - 1] == "_")):
            return None
        delimiter = prefix.group(1)
        i = prefix.end()
        while i < body_end:
            if token[i] == "\\":
                i += 2
            elif token.startswith(delimiter, i):
                return i + len(delimiter), "f" in token[start : prefix.start(1)].lower(), True
            else:
                i += 1
        return body_end, False, False

    def expression(start: int, depth: int) -> int | None:
        if depth > _MAX_FSTRING_DEPTH:
            return None
        brackets: list[str] = []
        i = start
        while i < body_end:
            string = quoted(i)
            if string is not None:
                stop, nested_f, closed = string
                if not closed:
                    return None
                if nested_f:
                    nested, incomplete = _legacy_fstring_ranges(token[i:stop], base + i, depth + 1)
                    if incomplete:
                        return None
                    spans.extend(nested)
                else:
                    mask(i, stop)
                i = stop
                continue
            char = token[i]
            if char in "([{":
                brackets.append({"(": ")", "[": "]", "{": "}"}[char])
            elif char in ")]}":
                if brackets and char == brackets[-1]:
                    brackets.pop()
                elif char == "}" and not brackets:
                    return i + 1
                else:
                    return None
            elif not brackets and char == ":":
                return literal(i, depth + 1, terminates=True)
            elif not brackets and char == "!" and i + 1 < body_end and token[i + 1] != "=":
                if token[i + 1] not in "rsa":
                    return None
                mask(i, i + 2)
                i += 1
            i += 1
        return None

    def literal(start: int, depth: int, *, terminates: bool) -> int | None:
        if depth > _MAX_FSTRING_DEPTH:
            return None
        i = start
        segment = start
        while i < body_end:
            if token[i] == "\\":
                # Backslash does not escape a replacement-field brace.
                i += 1 if i + 1 < body_end and token[i + 1] in "{}" else 2
            elif token.startswith("{{", i) or token.startswith("}}", i):
                i += 2
            elif token[i] == "{":
                mask(segment, i + 1)
                replacement_end = expression(i + 1, depth + 1)
                if replacement_end is None:
                    return None
                i = replacement_end
                segment = i
            elif token[i] == "}" and terminates:
                mask(segment, i + 1)
                return i + 1
            elif token[i] == "}":
                return None
            else:
                i += 1
        mask(segment, body_end)
        return None if terminates else body_end

    if literal(body_start, depth, terminates=False) is None:
        return [(base, base + len(token))], True
    mask(body_end, len(token))
    return sorted(spans), False


def _follows_operand_on_same_line(text: str, pos: int) -> bool:
    """Whether the token before ``text[pos]`` on its line ends with a name, ")" or "]".

    A TypeScript non-null assertion follows such an operand. After "}" the walk cannot tell a block
    from an object literal, so `} !/'/.test(s)` stays what it was: a regular expression is possible,
    and the ambiguity checks that already guard a slash after "}" decide.
    """
    before = pos - 1
    while before >= 0 and text[before] in " \t":
        before -= 1
    return before >= 0 and (text[before].isalnum() or text[before] in "_$)]")


def _javascript_ranges(
    text: str, *, jsx: bool = False, typescript: bool = False
) -> tuple[list[tuple[int, int]], bool]:
    return _JavaScriptLexer(text, jsx, typescript).run()


class _JavaScriptLexer:
    """One lexical walk over JavaScript or TypeScript source for ``_javascript_ranges``.

    ``run`` dispatches on the innermost mode; each mode method consumes input
    until the mode stack changes and returns the next index. A construct left
    open at the end of the input masks the remainder and marks the walk
    incomplete.
    """

    __slots__ = (
        "budget",
        "can_start_regex",
        "control_parens",
        "control_pending",
        "incomplete",
        "jsx",
        "modes",
        "open_jsx_tags",
        "pending_jsx_tags",
        "size",
        "spans",
        "text",
        "typescript",
    )

    def __init__(self, text: str, jsx: bool, typescript: bool = False) -> None:
        self.text = text
        self.size = len(text)
        self.jsx = jsx
        self.typescript = typescript
        self.budget = _LookaheadBudget(self.size)
        self.spans: list[tuple[int, int]] = []
        # Template text is inert; ${...} expressions are scanned as executable code.
        # The stack also allows nested template literals in interpolation bodies.
        # JSX modes carry the offset where their inert text began.
        self.modes: list[tuple[str, int]] = [("code", 0)]
        self.pending_jsx_tags: list[str] = []
        self.open_jsx_tags: list[str] = []
        # One lexical expression context for each active code/interpolation body.
        # Template text has no expression context of its own.
        self.can_start_regex = [True]
        self.control_pending = [False]
        self.control_parens: list[list[bool]] = [[]]
        self.incomplete = False

    def run(self) -> tuple[list[tuple[int, int]], bool]:
        modes = self.modes
        i = 0
        while i < self.size:
            mode, depth = modes[-1]
            if mode == "template":
                i = self._template(i)
            elif mode == "jsx_text":
                i = self._jsx_text(i, depth)
            elif mode == "jsx_tag":
                i = self._jsx_tag(i, depth)
            else:
                i = self._code(i, mode, depth)
        return self.spans, self.incomplete or len(modes) != 1

    def _unterminated(self, start: int) -> int:
        """Mask from ``start`` to the end of an input whose construct never closes."""
        self.spans.append((start, self.size))
        self.incomplete = True
        return self.size

    def _enter_expression(self, mode: str) -> None:
        self.modes.append((mode, 1))
        self.can_start_regex.append(True)
        self.control_pending.append(False)
        self.control_parens.append([])

    def _leave_expression(self, i: int, mode: str) -> None:
        """Close the interpolation or JSX expression whose final ``}`` is at ``i``."""
        self.spans.append((i, i + 1))
        self.modes.pop()
        self.can_start_regex.pop()
        self.control_pending.pop()
        self.control_parens.pop()
        if mode == "jsx_expression":
            self.modes[-1] = (self.modes[-1][0], i + 1)

    def _flag_slash_after_brace(self, i: int) -> None:
        """Mark the walk incomplete when the slash after the ``}`` at ``i`` could hide code.

        After a block a slash starts a regular expression and after an object literal it divides.
        Without a parse the two cannot be told apart, and this walk reads a division. That is harmless
        unless the text up to the next slash is a valid regular expression holding a quote, a backtick
        or a slash: read as code, `}` newline `/'/.test(x); code()` opens a "string" that masks the
        rest of the line, and `[//]` opens a comment. Anything else reads the same either way, or is
        exposed rather than hidden, so JSX text such as `{a}/{b}` in a `.js` file is not flagged.
        """
        text = self.text
        following = _NON_SPACE.search(text, i + 1)
        if following is None or following.group() != "/":
            return  # the usual case; only a slash can start a comment or a regular expression
        slash = _skip_trivia(text, following.start())
        if 0 <= slash < self.size and text[slash] == "/":
            end = _javascript_regex_end(text, slash, self.budget)
            if end is not None and _REGEX_BODY_OPENER.search(
                text, slash + 1, text.rfind("/", slash + 1, end)
            ):
                self.incomplete = True

    def _template(self, i: int) -> int:
        """Mask template text from ``i`` through the next ``${`` or the closing backtick."""
        text, size = self.text, self.size
        start = i
        while i < size:
            if text[i] == "\\":
                i += 2
            elif text.startswith("${", i):
                self.spans.append((start, i + 2))
                self._enter_expression("interpolation")
                return i + 2
            elif text[i] == "`":
                self.spans.append((start, i + 1))
                self.modes.pop()
                return i + 1
            else:
                i += 1
        return self._unterminated(start)

    def _jsx_text(self, i: int, start: int) -> int:
        """Walk JSX text that began at ``start`` to a closing tag, an expression or a child tag."""
        text, size, spans, modes = self.text, self.size, self.spans, self.modes
        while i < size:
            if text.startswith("</", i):
                end = text.find(">", i + 2, min(size, i + _MAX_REGEX_LENGTH))
                if end < 0:
                    return self._unterminated(start)
                spans.append((start, i))
                spans.append((i, end + 1))
                if not self.open_jsx_tags or text[i + 2 : end].strip() != self.open_jsx_tags.pop():
                    self.incomplete = True
                modes.pop()
                i = end + 1
                if modes[-1][0] in {"jsx_tag", "jsx_text"}:
                    modes[-1] = (modes[-1][0], i)
                return i
            if text[i] == "{":
                spans.append((start, i + 1))
                self._enter_expression("jsx_expression")
                return i + 1
            opened = _jsx_open_tag(text, i, self.budget) if text[i] == "<" else None
            if opened is not None:
                spans.append((start, i))
                modes.append(("jsx_tag", i))
                self.pending_jsx_tags.append(opened[0])
                return opened[1]
            i += 1
            if i == size:
                return self._unterminated(start)
        return i

    def _jsx_tag(self, i: int, start: int) -> int:
        """Walk a JSX tag that began at ``start`` to an attribute expression or its closing ``>``."""
        text, size, spans, modes = self.text, self.size, self.spans, self.modes
        # Whether the last significant character was ``/``. Each walk starts
        # after the tag name, its type arguments or an attribute expression's
        # ``}``, none of which ends in ``/``. Comments do not count, so
        # ``<div /* note */>`` is not self-closing.
        slash = False
        while i < size:
            # Comments may separate attributes; their text is never an
            # attribute string or expression.
            if text.startswith("//", i):
                end = _js_line_end(text, i + 2)
                if end >= size:
                    return self._unterminated(start)
                i = end
                continue
            if text.startswith("/*", i):
                end = text.find("*/", i + 2)
                if end < 0:
                    return self._unterminated(start)
                i = end + 2
                continue
            if text[i] in {'"', "'"}:
                # A JSX attribute string has no escapes: `title="\"` is complete, and it may span lines.
                end = text.find(text[i], i + 1)
                if end < 0:
                    return self._unterminated(start)
                i = end + 1
                slash = False
                continue
            if text[i] == "{":
                spans.append((start, i + 1))
                self._enter_expression("jsx_expression")
                return i + 1
            if text[i] == ">":
                spans.append((start, i + 1))
                name = self.pending_jsx_tags.pop()
                self_closing = slash
                i += 1
                modes.pop()
                if self_closing:
                    if modes[-1][0] == "jsx_text":
                        modes[-1] = ("jsx_text", i)
                else:
                    self.open_jsx_tags.append(name)
                    modes.append(("jsx_text", i))
                return i
            if not text[i].isspace():
                slash = text[i] == "/"
            i += 1
            if i == size:
                return self._unterminated(start)
        return i

    def _string(self, start: int) -> int:
        """Mask a quoted string; an unclosed one ends at its line break."""
        text, size = self.text, self.size
        quote = text[start]
        i = start + 1
        while i < size and text[i] != quote and text[i] not in "\r\n":
            if text[i] == "\\":
                # A backslash continues the string over a line break; CRLF is one break.
                i += 3 if text.startswith("\r\n", i + 1) else 2
            else:
                i += 1
        if i < size and text[i] == quote:
            i += 1
        self.spans.append((start, i))
        return i

    def _regex(self, start: int) -> int:
        """Mask a regular-expression literal; an ambiguous one masks the rest of its line."""
        regex_end = _javascript_regex_end(self.text, start)
        if regex_end is None:
            end = _js_line_end(self.text, start)
            self.spans.append((start, end))
            self.incomplete = True
            return end
        self.spans.append((start, regex_end))
        return regex_end

    def _code(self, i: int, mode: str, depth: int) -> int:
        """Walk code or an expression body, tracking where a regular expression can start."""
        text, size, jsx, spans, modes = self.text, self.size, self.jsx, self.spans, self.modes
        can_start_regex, control_pending, control_parens = (
            self.can_start_regex,
            self.control_pending,
            self.control_parens,
        )
        member_at = -1  # offset of the name after the latest single `.` or `?.`
        while i < size:
            if text.startswith("//", i):
                end = _js_line_end(text, i + 2)
                spans.append((i, end))
                i = end
            elif text.startswith("/*", i):
                end = text.find("*/", i + 2)
                if end < 0:
                    return self._unterminated(i)
                spans.append((i, end + 2))
                i = end + 2
            elif text[i] in {'"', "'"}:
                i = self._string(i)
                can_start_regex[-1] = False
                control_pending[-1] = False
            elif text[i] == "/" and can_start_regex[-1]:
                i = self._regex(i)
                can_start_regex[-1] = False
                control_pending[-1] = False
            elif text[i] == "/":
                i += 2 if text.startswith("/=", i) else 1
                can_start_regex[-1] = True
                control_pending[-1] = False
            elif text[i] == "`":
                spans.append((i, i + 1))
                modes.append(("template", 0))
                can_start_regex[-1] = False
                control_pending[-1] = False
                return i + 1
            elif mode in {"interpolation", "jsx_expression"} and text[i] == "{":
                modes[-1] = (mode, depth + 1)
                can_start_regex[-1] = True
                return i + 1
            elif mode in {"interpolation", "jsx_expression"} and text[i] == "}":
                if depth == 1:
                    self._leave_expression(i, mode)
                else:
                    modes[-1] = (mode, depth - 1)
                    can_start_regex[-1] = False
                    self._flag_slash_after_brace(i)
                return i + 1
            elif (
                jsx
                and text[i] == "<"
                and can_start_regex[-1]
                and (opened := _jsx_open_tag(text, i, self.budget)) is not None
            ):
                self.pending_jsx_tags.append(opened[0])
                modes.append(("jsx_tag", i))
                can_start_regex[-1] = False
                control_pending[-1] = False
                return opened[1]
            elif text[i].isalpha() or text[i] in "_$":
                start = i
                i += 1
                while i < size and (text[i].isalnum() or text[i] in "_$"):
                    i += 1
                word = text[start:i]
                if start == member_at:
                    # A property name is an operand whatever it is called, so
                    # `o.of / 1` and `o.for(x) / 2` divide.
                    can_start_regex[-1] = False
                    control_pending[-1] = False
                else:
                    # `of` is a keyword only after an operand (`for (x of /re/)`);
                    # where an operand is expected it is an ordinary name.
                    can_start_regex[-1] = word in _REGEX_PREFIX_WORDS and (
                        word != "of" or not can_start_regex[-1]
                    )
                    control_pending[-1] = word in _CONTROL_HEADS
                    if word in _AMBIGUOUS_REGEX_WORDS:
                        following = _skip_trivia(text, i)
                        if 0 <= following < size and text[following] == "/":
                            self.incomplete = True
            elif text[i].isdigit():
                i += 1
                while i < size and (text[i].isalnum() or text[i] in "._"):
                    i += 1
                can_start_regex[-1] = False
                control_pending[-1] = False
            elif text[i] == "(":
                control_parens[-1].append(control_pending[-1])
                control_pending[-1] = False
                can_start_regex[-1] = True
                i += 1
            elif text[i] == ")":
                can_start_regex[-1] = control_parens[-1].pop() if control_parens[-1] else False
                control_pending[-1] = False
                i += 1
            elif text[i] in "[,{":
                can_start_regex[-1] = True
                control_pending[-1] = False
                i += 1
            elif text[i] in "]}":
                can_start_regex[-1] = False
                control_pending[-1] = False
                if text[i] == "}":
                    self._flag_slash_after_brace(i)
                i += 1
            elif text[i] in "+-" and i + 1 < size and text[i + 1] == text[i]:
                # ++/-- in an expression are postfix; in expression-start position
                # they are prefix operators.
                control_pending[-1] = False
                i += 2
            elif (
                text[i] == "!"
                and self.typescript
                and not can_start_regex[-1]
                and not text.startswith("!=", i)
                and _follows_operand_on_same_line(text, i)
            ):
                # A TypeScript non-null assertion (`idle! / step`) ends an operand, so the slash
                # after it divides. It must follow its operand on the same line, and not a "}".
                control_pending[-1] = False
                i += 1
            elif text[i] in ";:=!?%~^&|*<>+-":
                can_start_regex[-1] = True
                control_pending[-1] = False
                i += 1
            elif text[i] == ".":
                control_pending[-1] = False
                can_start_regex[-1] = False
                i += 1
                if i < size and (text[i].isalpha() or text[i] in "_$"):
                    member_at = i  # the usual `a.b`
                elif text.startswith("..", i):
                    # Spread: an expression, possibly a regular expression, follows.
                    can_start_regex[-1] = True
                    i += 2
                else:
                    member_at = _property_name_start(text, i)
            else:
                if not text[i].isspace():
                    control_pending[-1] = False
                i += 1
        return i


@dataclass
class _Literal:
    start: int
    close: str
    escaped: bool = True
    verbatim: bool = False
    interpolation: str = ""
    multiline: bool = False


@dataclass
class _Expression:
    close: str
    depth: int = 1


# Where a ``//`` or ``#`` comment ends. One search per comment finds its end: a pattern that scanned
# ahead for a terminator and then looked for an earlier escape would rescan the rest of the file for
# every comment that an escape ends early.
_COMMENT_END_LF = re.compile("\n")
_COMMENT_END_CR = re.compile("[\n\r]")
# C# new-line characters also include NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR.
_COMMENT_END_UNICODE = re.compile("[\n\r\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}]")
# javac translates Unicode escapes before it lexes (JLS 3.3): a backslash preceded by an even number of
# backslashes, one or more "u" and four hex digits. A run of backslashes is matched only from its start
# and possessively, so the search is linear however long the run.
_JAVA_UNICODE_ESCAPE = re.compile(r"(?<!\\)(\\++)u++([0-9A-Fa-f]{4})")
# A PHP line comment also ends at a closing tag: `// note ?> html <?php code();` leaves PHP mode.
_COMMENT_END_PHP = re.compile(r"[\n\r]|\?>")
_RUST_RAW = re.compile(r'(?:br|rb|r)(#{0,255})"')
# An F# character literal: one character, a simple escape, or a unicode/trigraph escape.
_FSHARP_CHAR = re.compile(
    r"'(?:[^\\'\r\n]|\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}|\d{3}|[^\r\n]))'"
)
# A Swift raw string opens with 1-255 "#" and a quote. Possessive, so that a long run of "#" costs one
# bounded pass at each position in C instead of 255 steps of Python (13 s for a megabyte of "#").
_SWIFT_RAW_OPEN = re.compile(r'#{1,255}+(?=")')
_RUBY_HEREDOC = re.compile(r"<<[-~]?(['\"]?)([A-Za-z_]\w*)\1")
_PHP_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1")
_GO_IMPORT_BLOCK = re.compile(r"import\s*\(")
_MAX_GO_IMPORT_PREFIX = 4096
_RUBY_PERCENT_PAIRS = {"{": "}", "[": "]", "(": ")", "<": ">"}
# Languages whose string literals can carry a prefix (see ``_literal_prefix``).
_PREFIXED_LITERALS = frozenset({"dotnet", "dart", "rust", "swift"})


def _comment_end_pattern(language: str, dialect: str | None) -> re.Pattern[str]:
    """Return the pattern that finds where a ``//`` or ``#`` comment in ``language`` ends.

    Go, Rust and Ruby compilers treat a bare CR as white space; the others end the
    comment there, and C# also at NEL and the Unicode line and paragraph separators.
    """
    if language in {"go", "rust", "ruby"}:
        return _COMMENT_END_LF
    if language == "dotnet":
        return _COMMENT_END_UNICODE
    if language == "php":
        return _COMMENT_END_PHP
    # Java's escaped line breaks (`// note \u000a import x;`) are translated before lexing
    # (_translated_java_ranges), so the comment then ends at a real one.
    return _COMMENT_END_CR


def _ruby_percent_delimiter(text: str, start: int) -> bool:
    if start + 2 >= len(text) or not text.startswith(("%q", "%Q"), start):
        return False
    delimiter = text[start + 2]
    # Ruby's percent strings need an immediately following non-alphanumeric
    # delimiter. Do not interpret an adjacent identifier/modulo as a string.
    if start and (text[start - 1].isalnum() or text[start - 1] in "_$.)]}"):
        return False
    return delimiter.isascii() and not delimiter.isalnum() and not delimiter.isspace() and delimiter != "\\"


def _ruby_percent_string_end(text: str, start: int) -> tuple[int, bool]:
    """Return end and certainty for delimited %q/%Q Ruby strings.

    %q is inert even when it contains interpolation syntax. %Q can contain
    executable interpolation; mask through EOF and mark incomplete instead of
    claiming a code finding or a complete scan without parsing that expression.
    """
    opener = text[start + 2]
    closer = _RUBY_PERCENT_PAIRS.get(opener, opener)
    depth = 1
    i = start + 3
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text.startswith("#{", i) and text[start + 1] == "Q":
            return len(text), False
        if opener != closer and text[i] == opener:
            depth += 1
        elif text[i] == closer:
            depth -= 1
            if depth == 0:
                return i + 1, True
        i += 1
    return len(text), False


def _other_source_ranges(text: str, language: str, dialect: str | None) -> tuple[list[tuple[int, int]], bool]:
    """Mask inert text in source with a bounded lexical walk, preserving offsets.

    This is a lexical filter, not a language parser. Interpolation expressions
    remain executable, and an unterminated comment/literal marks the source
    incomplete. Go imports are special: their signatures start at the opening
    quote of the import path, so those quoted paths stay visible to matching.
    """
    if language == "java" and dialect == ".java" and "\\u" in text:
        translation = _java_unicode_translation(text)
        if translation is not None:
            return _translated_java_ranges(text, *translation)
    return _SourceLexer(text, language, dialect).run()


def _java_unicode_translation(text: str) -> tuple[str, list[int], list[int]] | None:
    """Translate Java Unicode escapes as javac does before it lexes; None when there are none.

    Returns the translated text, the offset in ``text`` of each translated
    character followed by ``len(text)``, and the translated offsets of the
    characters that escapes produced. A character an escape produces does not
    start another escape (``\\u005cu0041`` is a backslash, then ``u0041``).
    """
    pieces: list[str] = []
    origin: list[int] = []
    produced: list[int] = []
    previous = 0
    for match in _JAVA_UNICODE_ESCAPE.finditer(text):
        if not len(match[1]) % 2:
            continue  # the backslash before "u" is escaped by the one before it
        start = match.end(1) - 1
        pieces.append(text[previous:start])
        origin.extend(range(previous, start))
        produced.append(len(origin))
        pieces.append(chr(int(match[2], 16)))
        origin.append(start)
        previous = match.end()
    if not produced:
        return None
    pieces.append(text[previous:])
    origin.extend(range(previous, len(text) + 1))
    return "".join(pieces), origin, produced


def _translated_java_ranges(
    text: str, translated: str, origin: list[int], produced: list[int]
) -> tuple[list[tuple[int, int]], bool]:
    """Lex the translated source, as javac reads it, and map its spans back onto ``text``.

    ``\\u002a/`` closes a block comment, ``\\u0022`` a string and ``\\u000a`` a line
    comment: read as written, each would mask the code after it. Matchers still
    read ``text`` as written, so an escape that spells a printable ASCII
    character in code (``\\u0069mport``) hides that code from them: the lexical
    analysis is incomplete. Escapes inside literals and comments, of blanks and
    of other characters (``caf\\u00e9``) need nothing.
    """
    lexer = _SourceLexer(translated, "java", ".java")
    spans, incomplete = lexer.run()
    starts = [start for start, _ in spans]
    for position in produced:
        character = translated[position]
        if character.isascii() and not character.isspace():
            index = bisect_right(starts, position) - 1
            if index < 0 or position >= spans[index][1]:
                incomplete = True
                break
    return [(origin[start], origin[end]) for start, end in spans], incomplete


def _block_comment_end(text: str, start: int, opener: str, closer: str, *, nested: bool) -> tuple[int, bool]:
    """Return the end of the block comment opened at ``start`` and whether it closed."""
    depth = 1
    j = start + len(opener)
    size = len(text)
    while j < size and depth:
        if nested and text.startswith(opener, j):
            depth += 1
            j += len(opener)
        elif text.startswith(closer, j):
            depth -= 1
            j += len(closer)
        else:
            j += 1
    return j, not depth


def _literal_prefix(text: str, i: int, language: str) -> str:
    """Return the string prefix (C# ``$@``, Dart ``r``, Rust ``b``, Swift ``#``) at ``i``, if any."""
    if language == "dotnet":
        for candidate in ("$@", "@$", "@", "$"):
            if text.startswith(candidate + '"', i):
                return candidate
    elif language == "dart" and text.startswith(("r'", 'r"'), i):
        return "r"
    elif language == "rust" and text.startswith(('b"', "b'"), i):
        return "b"
    elif language == "swift" and text[i] == "#":
        raw = _SWIFT_RAW_OPEN.match(text, i)
        if raw is not None:
            return raw.group()
    return ""


def _open_literal(
    text: str,
    i: int,
    q: int,
    prefix: str,
    language: str,
    dialect: str | None,
) -> tuple[_Literal, int]:
    """Return the literal opened by ``prefix`` at ``i`` and the quote at ``q``, and the index after it."""
    quote = text[q]
    # C# raw string literals open with three quotes and no "@": `@"""x"" y"` is a verbatim string whose
    # text starts with an escaped quote.
    verbatim_dotnet = language == "dotnet" and "@" in prefix
    triple = (
        quote == '"'
        and language in {"java", "dotnet", "swift", "dart", "ruby"}
        and text.startswith('"""', q)
        and not verbatim_dotnet
    )
    if quote == "'" and language in {"dart", "ruby"} and text.startswith("'''", q):
        triple = True
    opener = quote * (3 if triple else 1)
    close = opener + (prefix if language == "swift" and prefix.startswith("#") else "")
    interpolation = ""
    if (language == "dart" and prefix != "r") or dialect in {".kt", ".kts"}:
        interpolation = "${"
    elif language == "swift":
        interpolation = "\\" + prefix + "(" if prefix.startswith("#") else "\\("
    elif language == "dotnet" and "$" in prefix:
        interpolation = "{"
    elif language == "ruby" and quote == '"':
        interpolation = "#{"
    literal = _Literal(
        i,
        close,
        escaped=quote != "`"
        and not (prefix == "r" or "@" in prefix or prefix.startswith("#") or triple and language == "dotnet"),
        verbatim="@" in prefix,
        interpolation=interpolation,
        multiline=triple or quote == "`" or "@" in prefix or _spans_lines(quote, language, dialect),
    )
    return literal, q + len(opener)


def _spans_lines(quote: str, language: str, dialect: str | None) -> bool:
    """Whether an ordinary (single-quote or double-quote) literal of ``language`` may contain a line break.

    Rust and PHP strings and F# strings run on across lines. Java, C#, Swift, Dart, Kotlin and Go
    interpreted strings do not, so a line break there still ends the walk as ambiguous. Ruby strings
    can span lines too, but the walk cannot yet tell its quote characters from those of a regular
    expression literal, `$'` or `?'`, so a Ruby literal that runs past a line break stays ambiguous.
    """
    if language == "rust":
        return quote == '"'
    if language == "php":
        return quote in {'"', "'"}
    return language == "dotnet" and dialect == ".fs" and quote == '"'


class _SourceLexer:
    """One bounded lexical walk for ``_other_source_ranges``.

    ``run`` dispatches on the innermost mode; each mode method consumes input
    until the mode stack changes and returns the next index. ``stopped`` is
    set when an unterminated comment or literal masks the rest of the source.
    """

    __slots__ = (
        "comment_end",
        "dialect",
        "go_import_block",
        "heredocs",
        "incomplete",
        "language",
        "line_checked_through",
        "line_start",
        "modes",
        "php_code",
        "size",
        "spans",
        "stopped",
        "text",
    )

    def __init__(self, text: str, language: str, dialect: str | None) -> None:
        self.text = text
        self.size = len(text)
        self.language = language
        self.dialect = dialect
        self.comment_end = _comment_end_pattern(language, dialect)
        self.spans: list[tuple[int, int]] = []
        self.modes: list[_Literal | _Expression] = []
        self.incomplete = False
        self.stopped = False
        self.go_import_block = False
        self.heredocs: list[str] = []
        self.line_start = 0
        self.line_checked_through = 0
        # A PHP source file can be an HTML-only template. Enter code mode only at
        # an opening tag, including the short echo form (<?=).
        self.php_code = language != "php"

    def run(self) -> tuple[list[tuple[int, int]], bool]:
        modes = self.modes
        i = 0
        while i < self.size:
            mode = modes[-1] if modes else None
            if self.language == "php" and not self.php_code:
                i = self._php_template(i)
            elif isinstance(mode, _Literal):
                i = self._literal(i, mode)
            else:
                i = self._code(i, mode)
            if self.stopped:
                return self.spans, True
        if modes or self.heredocs:
            self.incomplete = True
            for mode in modes:
                if isinstance(mode, _Literal):
                    self.spans.append((mode.start, self.size))
        return sorted(self.spans), self.incomplete

    def _mask(self, start: int, end: int, closed: bool) -> int:
        """Mask an inert construct; one that never closes stops the walk."""
        self.spans.append((start, end))
        if closed:
            return end
        self.stopped = True
        return self.size

    def _line_before(self, index: int) -> str | None:
        # Check only source not visited by the preceding Go quote. Repeated
        # quotes on a very long line must not repeatedly scan/copy its prefix.
        newline = self.text.rfind("\n", self.line_checked_through, index)
        if newline >= 0:
            self.line_start = newline + 1
        self.line_checked_through = index
        if index - self.line_start > _MAX_GO_IMPORT_PREFIX:
            prefix = self.text[self.line_start : self.line_start + _MAX_GO_IMPORT_PREFIX]
            if prefix.isspace() or re.match(r"\s*import\b", prefix):
                self.incomplete = True  # Too long to classify as a Go import safely.
            return None
        return self.text[self.line_start : index]

    def _line_comment_end(self, start: int) -> int:
        """Return where the ``//`` or ``#`` comment at ``start`` ends: at its language's first line break."""
        match = self.comment_end.search(self.text, start)
        return self.size if match is None else match.start()

    def _php_template(self, i: int) -> int:
        """Mask template text up to and including the next PHP opening tag."""
        opening = self.text.find("<?", i)
        if opening < 0:
            self.spans.append((i, self.size))
            return self.size
        self.spans.append((i, opening + 2))
        self.php_code = True
        return opening + 2

    def _literal(self, i: int, mode: _Literal) -> int:
        """Walk literal text to its close or to the start of an interpolation expression."""
        text, size = self.text, self.size
        while i < size:
            if mode.interpolation and text.startswith(mode.interpolation, i):
                # In C# escaped braces are text, not interpolation delimiters.
                if mode.interpolation == "{" and text.startswith("{{", i):
                    i += 2
                    continue
                end = i + len(mode.interpolation)
                self.spans.append((mode.start, end))
                self.modes.append(_Expression(")" if mode.interpolation.endswith("(") else "}"))
                return end
            if mode.verbatim and text.startswith('""', i) and mode.close == '"':
                i += 2
            elif mode.escaped and text[i] == "\\":
                i = min(size, i + 2)
            elif text.startswith(mode.close, i):
                end = i + len(mode.close)
                self.spans.append((mode.start, end))
                self.modes.pop()
                return end
            elif not mode.multiline and text[i] in "\r\n":
                self.spans.append((mode.start, i))
                self.modes.pop()
                self.incomplete = True
                return i
            else:
                i += 1
        return i

    def _heredoc_line(self, i: int) -> int:
        """Mask one here-document line starting at ``i``; the pending marker's line closes it."""
        text, size, language, heredocs = self.text, self.size, self.language, self.heredocs
        marker = heredocs[0]
        end = text.find("\n", i)
        end = size if end < 0 else end
        line = text[i:end]
        if (language == "ruby" and line.strip() == marker) or (
            language == "php" and re.fullmatch(r"\s*" + re.escape(marker) + r"[;,)]?\s*", line)
        ):
            heredocs.pop(0)
        elif (language == "ruby" and "#{" in line) or (language == "php" and ("${" in line or "{$" in line)):
            # Interpolation inside a here-document needs language parsing.
            # Preserve the conservative mask and report incomplete analysis.
            self.incomplete = True
        self.spans.append((i, end))
        if end < size:
            return end + 1
        self.incomplete |= bool(heredocs)
        return end

    def _quote(self, i: int, q: int, prefix: str) -> tuple[int, bool]:
        """Handle the quote at ``q``; return the next index and whether a literal opened."""
        text, size, language = self.text, self.size, self.language
        quote = text[q]
        if quote == "`" and language != "go":
            return i + 1, False
        if quote == "'" and language == "dotnet" and self.dialect == ".fs":
            # F# writes a type variable as 'T and may prime an identifier (type', x'): neither is a
            # character literal, which holds one character or an escape and closes on the same line.
            if q > 0 and (text[q - 1].isalnum() or text[q - 1] in "_'"):
                return i + 1, False
            if _FSHARP_CHAR.match(text, q) is None:
                return i + 1, False
        if quote == "'" and language == "rust":
            # A lifetime ('a or 'static) is code. Rust character literals
            # contain exactly one character or an escaped character.
            char = q + 1
            char += 2 if char < size and text[char] == "\\" else 1
            if char >= size or text[char] != "'":
                return i + 1, False
        if quote == '"' and language == "go":
            before = self._line_before(i)
            if before is not None and (
                re.fullmatch(r"\s*import\s+(?:[\w.]+\s+)?", before)
                or (self.go_import_block and re.fullmatch(r"\s*(?:[\w.]+\s*)?", before))
            ):
                i = q + 1
                while i < size and text[i] != '"' and text[i] not in "\r\n":
                    i += 2 if text[i] == "\\" else 1
                i += i < size and text[i] == '"'
                return i, False
        literal, end = _open_literal(text, i, q, prefix, language, self.dialect)
        self.modes.append(literal)
        return end, True

    def _code(self, i: int, mode: _Expression | None) -> int:
        """Walk code or an interpolation expression until a literal opens, it closes or PHP code ends."""
        text, size, language, dialect = self.text, self.size, self.language, self.dialect
        spans, heredocs = self.spans, self.heredocs
        while i < size:
            if mode is not None:
                if text[i] == mode.close:
                    mode.depth -= 1
                    if not mode.depth:
                        spans.append((i, i + 1))
                        self.modes.pop()
                        literal = self.modes[-1]
                        assert isinstance(literal, _Literal)
                        literal.start = i + 1
                        return i + 1
                    i += 1
                    continue
                if text[i] == ("(" if mode.close == ")" else "{"):
                    mode.depth += 1
                    i += 1
                    continue

            if heredocs and (i == 0 or text[i - 1] == "\n"):
                i = self._heredoc_line(i)
                continue

            if language == "php" and text.startswith("?>", i):
                spans.append((i, i + 2))
                self.php_code = False
                return i + 2

            if (
                language == "ruby"
                and (i == 0 or text[i - 1] == "\n")
                and text.startswith("=begin", i)
                and (i + 6 == size or text[i + 6].isspace())
            ):
                # Search from a position instead of slicing: a file of many short
                # blocks would otherwise copy the remainder for each one (quadratic).
                end_marker = _RUBY_BLOCK_END.search(text, i + 6)
                if end_marker is None:
                    return self._mask(i, size, False)
                i = self._mask(i, end_marker.end(), True)
                continue

            if language == "ruby" and text.startswith("<<", i):
                heredoc = _RUBY_HEREDOC.match(text, i)
                if heredoc:
                    heredocs.append(heredoc.group(2))
                    i = heredoc.end()
                    continue

            if language == "ruby" and _ruby_percent_delimiter(text, i):
                i = self._mask(i, *_ruby_percent_string_end(text, i))
                continue

            if language == "php" and text.startswith("<<<", i):
                heredoc = _PHP_HEREDOC.match(text, i)
                if heredoc:
                    heredocs.append(heredoc.group(2))
                    i = heredoc.end()
                    continue

            if (
                language == "go"
                and text.startswith("import", i)
                and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))
            ):
                match = _GO_IMPORT_BLOCK.match(text, i)
                if match:
                    self.go_import_block = True
                    i = match.end()
                    continue
            if language == "go" and self.go_import_block and text[i] == ")":
                self.go_import_block = False

            if dialect == ".fs" and text.startswith("(*", i):
                i = self._mask(i, *_block_comment_end(text, i, "(*", "*)", nested=True))
                continue

            if (language != "ruby" and text.startswith("//", i)) or (
                language in {"ruby", "php"}
                and text[i] == "#"
                # PHP 8 opens an attribute with "#[": code, and its strings can span lines.
                and not (language == "php" and text.startswith("#[", i))
            ):
                end = self._line_comment_end(i)
                spans.append((i, end))
                i = end
                continue
            if language != "ruby" and text.startswith("/*", i):
                nested = language in {"rust", "swift", "dart"} or dialect in {".kt", ".kts", ".scala"}
                i = self._mask(i, *_block_comment_end(text, i, "/*", "*/", nested=nested))
                continue

            if language == "rust" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                raw = _RUST_RAW.match(text, i)
                if raw:
                    close = '"' + raw.group(1)
                    end = text.find(close, raw.end())
                    if end < 0:
                        return self._mask(i, size, False)
                    i = self._mask(i, end + len(close), True)
                    continue

            prefix = _literal_prefix(text, i, language) if language in _PREFIXED_LITERALS else ""
            q = i + len(prefix)
            if q < size and text[q] in {'"', "'", "`"}:
                i, opened = self._quote(i, q, prefix)
                if opened:
                    return i
                continue
            i += 1
        return i
