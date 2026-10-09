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
# JavaScript dialects whose sources may hold JSX: React projects commonly keep
# components in `.js` files. The lexer only reads a `<` as a JSX tag where an
# expression starts, where plain JavaScript has no `<` operator, so this does
# not change how other sources read. TypeScript's `.ts`, `.mts` and `.cts`
# instead allow `<T>value` type assertions there and never hold JSX.
JSX_DIALECTS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".tsx"})
# TypeScript has a postfix non-null assertion (`a[b]! / n`); JavaScript does not.
TYPESCRIPT_DIALECTS = frozenset({".ts", ".tsx", ".mts", ".cts"})
# Words after which `!` starts an operand: a keyword, not a value.
_NON_OPERAND_WORDS = frozenset(
    {
        "as", "await", "case", "default", "delete", "do", "else", "export", "extends", "in", "instanceof",
        "keyof", "new", "of", "return", "satisfies", "throw", "typeof", "void", "yield",
    }
)  # fmt: skip


def _js_line_end(text: str, pos: int) -> int:
    """Return the offset of the first line terminator at or after ``pos``, or the end of ``text``."""
    match = _JS_LINE_BREAK.search(text, pos)
    return len(text) if match is None else match.start()


def _on_line_of_previous_token(text: str, pos: int) -> bool:
    """Whether no line terminator separates ``pos`` from the non-blank character before it."""
    pos -= 1
    while pos >= 0 and text[pos] in " \t\v\f\N{NO-BREAK SPACE}\N{ZERO WIDTH NO-BREAK SPACE}":
        pos -= 1
    return pos >= 0 and text[pos] not in _JS_LINE_TERMINATORS


def _operand_before(text: str, pos: int) -> bool:
    """Whether the token before ``pos`` (on its line) ends an operand: a name, a literal, `)` or `]`.

    A keyword, a closing brace and a comment are not, so the `!` after them is a prefix.
    """
    pos -= 1
    while pos >= 0 and text[pos] in " \t\v\f\N{NO-BREAK SPACE}\N{ZERO WIDTH NO-BREAK SPACE}":
        pos -= 1
    if pos < 0:
        return False
    char = text[pos]
    if char in ")]\"'`":
        return True
    if not (char.isalnum() or char in "_$"):
        return False
    start = pos
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "_$"):
        start -= 1
    return text[start : pos + 1] not in _NON_OPERAND_WORDS


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


def _jsx_open_tag(
    text: str, start: int, budget: _LookaheadBudget, *, expression: bool = True
) -> tuple[str, int] | None:
    """Return the JSX tag name and the offset where its attributes begin.

    TSX allows explicit type arguments on an element (`<Select<Option> ...>`,
    `<Form<{ email: string }>>`); they are skipped so that the type argument
    is not mistaken for a nested opening tag. ``expression`` is False for a
    ``<`` in JSX text, where it always opens a child element.
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
    if expression:
        # Where an expression starts, TypeScript reads `<T =` and `<T extends X`
        # (X not `=`, `>` or `/`) in a .tsx file as type parameters, never as
        # JSX: a generic arrow function, or a call signature in a type literal
        # (`{ <V extends string>(props: P): R }`).
        suffix = text[pos : min(len(text), pos + 64)].lstrip()
        if suffix.startswith("="):
            return None
        if name == "const" and re.match(r"\s+[A-Za-z_$][\w$]*\s*(?:extends\b|=|,|>)", text[pos : pos + 128]):
            # A const type parameter: `<const T extends object>(x: T) => x`.
            return None
        if (
            suffix.startswith("extends")
            and (len(suffix) == 7 or suffix[7].isspace() or suffix[7] in "<{")
            and not suffix[7:].lstrip().startswith(("=", ">", "/"))
        ):
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
        return _javascript_ranges(text, jsx=jsx, typescript=dialect in TYPESCRIPT_DIALECTS)
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
            opened = _jsx_open_tag(text, i, self.budget, expression=False) if text[i] == "<" else None
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
                self.typescript
                and text[i] == "!"
                and not can_start_regex[-1]
                and not text.startswith("!=", i)
                and _on_line_of_previous_token(text, i)
                and _operand_before(text, i)
            ):
                # After an operand on the same line, `!` is TypeScript's postfix
                # non-null assertion, so `a[b]! / n` divides. (JavaScript has no
                # binary `!`; after a line break ASI makes it a prefix `!`, as
                # after a keyword, a closing brace or a comment.)
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
    # A line break inside it makes the walk incomplete: a multi-line quoted
    # string whose quote did not open where an expression starts may be a
    # stray quote of a construct the lexer does not parse (see _expression_start).
    guarded: bool = False
    # Ruby percent literals with paired delimiters nest: %w[a [b] c] closes at the last `]`.
    opener: str = ""
    depth: int = 1


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
# A Swift raw string opens with 1-255 "#" and a quote. Possessive, so that a long run of "#" costs one
# bounded pass at each position in C instead of 255 steps of Python (13 s for a megabyte of "#").
_SWIFT_RAW_OPEN = re.compile(r'#{1,255}+(?=")')
_RUBY_HEREDOC = re.compile(r"<<[-~]?(['\"]?)([A-Za-z_]\w*)\1")
_PHP_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1")
# Where interpolated code starts in a here-document: PHP's `{$expr}` (the `$`
# begins the expression) and `${expr}`, Ruby's `#{expr}`.
_HEREDOC_INTERPOLATION = {"php": re.compile(r"\{(?=\$)|\$\{"), "ruby": re.compile(r"#\{")}
# PHP double-quoted and backtick strings interpolate `{$expr}` and `${expr}` (see _SourceLexer._literal).
_PHP_INTERPOLATION = "php"
# Characters before a quote where an expression starts (an operator or an opening bracket).
_EXPRESSION_START_CHARS = frozenset("([{,=:;!&|^~+-*%<>")
# A C# string prefix: `$`s (interpolation braces) and `@` (verbatim). Possessive, so a long run of `$` is
# one bounded pass in C.
_DOTNET_STRING_PREFIX = re.compile(r'(?:\$++@?|@\$?)(?=")')
# Rust, PHP and Ruby quoted strings may span lines; elsewhere a line break ends an unclosed literal.
_MULTILINE_QUOTED = frozenset({"rust", "php", "ruby"})
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


# Percent literal types whose text interpolates `#{...}`; %q, %w, %i and %s are literal text.
_RUBY_PERCENT_TYPES = frozenset("qQwWiIrsx")
_RUBY_PERCENT_INTERPOLATING = frozenset("QWIrx")
# Keywords after which a `/` or `%` starts a literal rather than an operator.
_RUBY_OPERAND_KEYWORDS = frozenset(
    [
        "and",
        "begin",
        "case",
        "do",
        "else",
        "elsif",
        "if",
        "in",
        "not",
        "or",
        "print",
        "puts",
        "raise",
        "return",
        "then",
        "unless",
        "until",
        "when",
        "while",
        "yield",
    ]
)
_RUBY_IDENTIFIER_END = re.compile(r"[A-Za-z0-9_]*[?!]?\Z")


def _ruby_operand_start(text: str, start: int) -> bool:
    """Whether a `/` or `%` at ``start`` begins a literal, by Ruby's own rule.

    It does after an operator, an opening bracket, a line break or a keyword
    such as ``when``, and after a command name set off by white space when the
    next character is not white space (``line.split /,/``). After a value (a name
    without that space, a number, a closing bracket) it divides. A symbol
    (``:/``), a method name (``.%``, ``def /``) and a global (``$/``) are code.
    """
    if start and text[start - 1] in ":.$":
        return False
    j = start - 1
    while j >= 0 and start - j <= 4096 and text[j] in " \t":
        j -= 1
    if j < 0 or text[j] in "\r\n":
        return True
    char = text[j]
    if char in _EXPRESSION_START_CHARS or (
        char == "?" and not (j and (text[j - 1].isalnum() or text[j - 1] == "_"))
    ):
        return True
    if not (char.isalnum() or char in "_?!"):
        return False
    word = _RUBY_IDENTIFIER_END.search(text, max(0, j - 63), j + 1)
    name = word.group() if word is not None else ""
    before = text[j - len(name)] if j >= len(name) else ""
    if (before and before in "@$") or (before == ":" and text[j - len(name) - 1 : j - len(name)] != ":"):
        return False  # an instance or global variable, or a symbol, is a value
    if name in _RUBY_OPERAND_KEYWORDS and before != ".":
        return True
    if not name or name[0].isdigit() or name == "def":
        return False
    following = text[start + 1] if start + 1 < len(text) else ""
    return j < start - 1 and following not in " \t\r\n="


def _ruby_percent_literal(text: str, start: int) -> tuple[str, str, str, int] | None:
    """(opener, closer, interpolation, text start) of a percent literal at ``start``, or None."""
    kind = text[start + 1] if start + 1 < len(text) else ""
    if kind in _RUBY_PERCENT_TYPES:
        at = start + 2
        # A typed literal needs a delimiter right after its letter; after a value it is modulo (`x%w`).
        if start and (text[start - 1].isalnum() or text[start - 1] in "_$.)]}"):
            return None
    else:
        at = start + 1
        kind = "Q"
        if not _ruby_operand_start(text, start):
            return None
    if at >= len(text):
        return None
    opener = text[at]
    if not opener.isascii() or opener.isalnum() or opener.isspace() or opener in "\\=":
        return None
    closer = _RUBY_PERCENT_PAIRS.get(opener, opener)
    interpolation = "#{" if kind in _RUBY_PERCENT_INTERPOLATING else ""
    return (opener if opener != closer else ""), closer, interpolation, at + 1


def _ruby_character_end(text: str, start: int) -> int | None:
    """End of a character literal (``?a``, ``?"``, ``?\\n``) at ``start``; None for a ternary or method."""
    size = len(text)
    if start + 1 >= size or text[start + 1].isspace():
        return None
    if start and (text[start - 1].isalnum() or text[start - 1] in "_)]}\"'`$@"):
        return None
    end = start + 2
    if text[start + 1] == "\\":
        escape = _RUBY_CHARACTER_ESCAPE.match(text, start + 2)
        end = escape.end() if escape else min(size, start + 3)
    if end < size and (text[end].isalnum() or text[end] == "_"):
        return None
    return end


_RUBY_CHARACTER_ESCAPE = re.compile(
    r"u\{[0-9A-Fa-f ]{1,40}\}|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|(?:[CM]-\\?|c\\?)+.|.", re.S
)
_RUBY_SINGLETON = re.compile(r"\bclass[ \t]*\Z")
_RUBY_DATA_SECTION = re.compile(r"__END__(?:\r?\n|\Z)")


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


def _php_heredoc_close(marker: str, line: str) -> int | None:
    """Return the offset just past ``marker`` when ``line`` closes a PHP here-document, else None.

    Since PHP 7.3 the closing marker may be indented and be followed by any
    character that cannot continue an identifier, such as `);` or `, $next`.
    """
    stripped = line.lstrip(" \t")
    if not stripped.startswith(marker):
        return None
    after = len(line) - len(stripped) + len(marker)
    if after < len(line) and (line[after].isalnum() or line[after] == "_" or ord(line[after]) >= 0x80):
        return None
    return after


def _interpolation_end(text: str, start: int, end: int, language: str) -> int | None:
    """Return the offset of the ``}`` closing an interpolation whose body starts at ``start``, or None.

    The body is read by counting braces outside quotes. None, which makes the
    walk incomplete, also stands for a body this cannot read: a comment, a
    regular expression, a character or percent literal, or a nested Ruby
    interpolation can each hold a brace or a quote that is not code.
    """
    depth = 1
    i = start
    while i < end:
        char = text[i]
        if char in "\"'":
            close = i + 1
            while close < end and text[close] != char:
                if language == "ruby" and char == '"' and text.startswith("#{", close):
                    return None
                close += 2 if text[close] == "\\" else 1
            if close >= end:
                return None
            i = close + 1
            continue
        if char == "#" or (language == "php" and text.startswith(("//", "/*"), i)):
            return None
        if language == "ruby" and (
            (char == "/" and i + 1 < end and not text[i + 1].isspace())
            or (char == "?" and i + 1 < end and not text[i + 1].isspace())
            or (char == "%" and i + 1 < end and not text[i + 1].isspace())
        ):
            return None
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if not depth:
                return i
        i += 1
    return None


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
        # Only from the start of a run of `$`: a match tried at every `$` of a
        # long run rescans the rest of it each time.
        if text[i] in "$@" and not (text[i] == "$" and i and text[i - 1] == "$"):
            prefix = _DOTNET_STRING_PREFIX.match(text, i)
            if prefix is not None:
                return prefix.group()
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
    if language == "dotnet" and "@" not in prefix and text.startswith('"""', q):
        # A C# 11 raw string opens with three or more quotes and closes with as
        # many; it has no escapes. Its `$`s give the braces that open an
        # interpolation (`$$"""{ "a": {{x}} }"""` holds one); fewer are text.
        # F# triple-quoted strings always use three. A verbatim `@"""` is not
        # raw: it opens a string whose text starts with an escaped quote.
        quotes = 3
        while dialect != ".fs" and q + quotes < len(text) and text[q + quotes] == '"':
            quotes += 1
        raw = _Literal(i, '"' * quotes, escaped=False, interpolation="{" * len(prefix), multiline=True)
        return raw, q + quotes
    triple = quote == '"' and language in {"java", "swift", "dart", "ruby"} and text.startswith('"""', q)
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
    elif language == "ruby" and quote in '"`':
        interpolation = "#{"
    elif language == "php" and quote in '"`':
        interpolation = _PHP_INTERPOLATION
    literal = _Literal(
        i,
        close,
        escaped=quote != "`" and not (prefix == "r" or "@" in prefix or prefix.startswith("#")),
        verbatim="@" in prefix,
        interpolation=interpolation,
        multiline=triple or quote == "`" or "@" in prefix or language in _MULTILINE_QUOTED,
    )
    return literal, q + len(opener)


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
        # Pending here-documents in order: each marker and whether its text interpolates code.
        self.heredocs: list[tuple[str, bool]] = []
        self.line_start = 0
        self.line_checked_through = 0
        # A PHP source file can be an HTML-only template. Enter code mode only at
        # an opening tag, including the short echo form (<?=).
        self.php_code = language != "php"

    def run(self) -> tuple[list[tuple[int, int]], bool]:
        modes = self.modes
        i = 0
        steps = 0
        while i < self.size:
            steps += 1
            if not steps & 0xFFF:
                pattern_timeout()  # the per-file time budget, as the JavaScript lexer checks it
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
            if mode.interpolation == _PHP_INTERPOLATION:
                # `{$expr}`: the `{` is text and the expression starts at `$`; `${expr}`.
                opener = 1 if text.startswith("{$", i) else 2 if text.startswith("${", i) else 0
                if opener:
                    end = i + opener
                    self.spans.append((mode.start, end))
                    self.modes.append(_Expression("}"))
                    return end
            elif mode.interpolation and text.startswith(mode.interpolation, i):
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
            elif mode.opener and text[i] == mode.opener:
                mode.depth += 1
                i += 1
            elif mode.depth > 1 and text.startswith(mode.close, i):
                mode.depth -= 1
                i += 1
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
                if mode.guarded and text[i] in "\r\n":
                    mode.guarded = False
                    self.incomplete = True
                i += 1
        return i

    def _heredoc_line(self, i: int) -> int:
        """Mask one here-document line starting at ``i``; the pending marker's line closes it."""
        text, size, language, heredocs = self.text, self.size, self.language, self.heredocs
        marker, interpolates = heredocs[0]
        end = text.find("\n", i)
        end = size if end < 0 else end
        line = text[i:end]
        closing = _php_heredoc_close(marker, line) if language == "php" else None
        if closing is not None:
            # Code can continue after a PHP closing marker on the same line.
            heredocs.pop(0)
            self.spans.append((i, i + closing))
            return i + closing
        if language == "ruby" and line.strip() == marker:
            heredocs.pop(0)
            self.spans.append((i, end))
        elif interpolates:
            self._mask_interpolated(i, end)
        else:
            self.spans.append((i, end))
        if end < size:
            return end + 1
        self.incomplete |= bool(heredocs)
        return end

    def _mask_interpolated(self, start: int, end: int) -> None:
        """Mask here-document text in ``[start, end)``, leaving interpolated expressions visible as code.

        An expression that does not close on its line needs language parsing:
        the rest of the line stays masked and the walk is incomplete.
        """
        text = self.text
        opener = _HEREDOC_INTERPOLATION[self.language]
        masked_from = search_from = start
        while (found := opener.search(text, search_from, end)) is not None:
            at = found.start()
            if text[at] in "$#":
                # `\${` and `\#{` are escaped text (PHP's `{$` cannot be escaped).
                before = at - 1
                while before >= start and text[before] == "\\":
                    before -= 1
                if (at - 1 - before) % 2:
                    search_from = found.end()
                    continue
            close = (
                self._ruby_interpolation_close(found.end(), end)
                if self.language == "ruby"
                else _interpolation_end(text, found.end(), end, self.language)
            )
            if close is None:
                self.incomplete = True
                break
            self.spans.append((masked_from, found.end()))
            masked_from = search_from = close
        self.spans.append((masked_from, end))

    def _ruby_interpolation_close(self, start: int, end: int) -> int | None:
        """Offset of the ``}`` closing the Ruby interpolation whose body starts at ``start``, or None.

        The body is lexed as code by a walk bounded to ``end`` (the line), so
        strings, regular expressions and nested interpolations inside it are
        read as they are elsewhere. A body that does not close by ``end``, or
        that opens a here-document, needs parsing: None.
        """
        walk = _SourceLexer(self.text, self.language, self.dialect)
        walk.size = end
        walk.modes = [_Literal(start, "\0", escaped=False, multiline=True), _Expression("}")]
        i = start
        while i < end and len(walk.modes) > 1 and not walk.stopped:
            mode = walk.modes[-1]
            i = walk._literal(i, mode) if isinstance(mode, _Literal) else walk._code(i, mode)
        if len(walk.modes) != 1 or walk.stopped or walk.heredocs or walk.incomplete:
            return None
        self.spans.extend(span for span in walk.spans if span[1] < i)  # literals inside the expression
        return i - 1

    def _quote(self, i: int, q: int, prefix: str) -> tuple[int, bool]:
        """Handle the quote at ``q``; return the next index and whether a literal opened."""
        text, size, language = self.text, self.size, self.language
        quote = text[q]
        if quote == "`" and (
            language not in {"go", "php", "ruby"} or (language == "ruby" and i and text[i - 1] in ":.")
        ):
            return i + 1, False  # Ruby's :` and .` name the command method
        if quote == "'" and language == "rust":
            # A lifetime ('a or 'static) is code. Rust character literals
            # contain exactly one character or an escape: `'\n'`, `'\x7f'` or
            # `'\u{201C}'`.
            char = q + 1
            if char < size and text[char] == "\\":
                if text.startswith("u{", char + 1):
                    close = text.find("}", char + 3, char + 12)
                    char = close + 1 if close >= 0 else char + 2
                else:
                    char += 4 if text.startswith("x", char + 1) else 2
            else:
                char += 1
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
        if (
            language in _MULTILINE_QUOTED
            and quote in "\"'`"
            and end == q + 1
            and not self._expression_start(i)
        ):
            literal.guarded = True
        self.modes.append(literal)
        return end, True

    def _expression_start(self, i: int) -> bool:
        """Whether a literal starting at ``i`` opens where an expression starts.

        The previous token is an operator or an opening bracket, or a word set
        off by white space (``return``, a Ruby or PHP command call such as
        ``puts`` or ``echo``), or a Ruby line break. A quote right after
        ``$``, ``?``, ``/``, a closing bracket or another literal is not: Ruby's
        ``$'`` and ``?'``, a quote in a regular expression or a ``%w[]`` word.
        """
        text = self.text
        j = i - 1
        while j >= 0 and i - j <= 4096 and text[j] in " \t\r\n":
            j -= 1
        if j < 0:
            return True
        spaced = j < i - 1
        if self.language == "ruby" and "\n" in text[j + 1 : i]:
            return True
        char = text[j]
        if char in _EXPRESSION_START_CHARS or (self.language == "php" and char in ".@"):
            return True
        if char == "?":
            return spaced
        return spaced and (char.isalnum() or char == "_")

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
                # `items<<value` appends: a bare marker opens a here-document only
                # after white space or an operator.
                if (
                    heredoc
                    and heredoc.group(0)[2] not in "-~'\""
                    and i
                    and (
                        text[i - 1].isalnum()
                        or text[i - 1] in "_)]}"
                        or _RUBY_SINGLETON.search(text, max(0, i - 16), i)
                    )
                ):
                    heredoc = None  # `class << self` opens a singleton class
                if heredoc:
                    # A single-quoted marker (`<<~'SQL'`) makes the text literal.
                    heredocs.append((heredoc.group(2), heredoc.group(1) != "'"))
                    i = heredoc.end()
                    continue

            if language == "ruby":
                char = text[i]
                if char == "$" and i + 1 < size and not (text[i + 1].isalnum() or text[i + 1] in "_{"):
                    i += 2  # a punctuation global: $" $' $/ $; $~
                    continue
                if char == "?" and (end := _ruby_character_end(text, i)) is not None:
                    spans.append((i, end))
                    i = end
                    continue
                if char == "_" and (i == 0 or text[i - 1] == "\n") and _RUBY_DATA_SECTION.match(text, i):
                    return self._mask(i, size, True)  # the rest of the file is data
                if char == "%" and (percent := _ruby_percent_literal(text, i)) is not None:
                    opener, closer, interpolation, body = percent
                    self.modes.append(
                        _Literal(i, closer, interpolation=interpolation, multiline=True, opener=opener)
                    )
                    return body
                if char == "/" and _ruby_operand_start(text, i):
                    self.modes.append(_Literal(i, "/", interpolation="#{", multiline=True))
                    return i + 1

            if language == "php" and text.startswith("<<<", i):
                heredoc = _PHP_HEREDOC.match(text, i)
                if heredoc:
                    # A single-quoted marker opens a nowdoc, whose text is literal.
                    heredocs.append((heredoc.group(2), heredoc.group(1) != "'"))
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
                language in {"ruby", "php"} and text[i] == "#"
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
