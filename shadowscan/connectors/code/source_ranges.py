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
from dataclasses import dataclass

_RUBY_BLOCK_END = re.compile(r"(?m)^=end(?:\s|$)")

_FSTRING_PREFIX = re.compile(r"(?i)^([rubf]{1,3})(\"\"\"|'''|\"|')")
_STRING_PREFIX = re.compile(r"(?i)[rubf]{0,3}(\"\"\"|'''|\"|')")
_MAX_FSTRING_DEPTH = 24

# A slash is a regular-expression delimiter only where an expression can start.
# In particular, after an identifier, literal, or closing expression delimiter
# it is division. This is deliberately a lexical approximation, not a JS parser.
_REGEX_PREFIX_WORDS = frozenset({
    "await", "case", "delete", "do", "else", "in", "instanceof", "new", "of",
    "return", "throw", "typeof", "void", "yield",
})
_CONTROL_HEADS = frozenset({"catch", "for", "if", "switch", "while", "with"})
_MAX_REGEX_LENGTH = 8192


def _javascript_regex_end(text: str, start: int) -> int | None:
    """Find the end of a regex literal, honoring escapes and character classes.

    A missing delimiter or an oversized literal is ambiguous; the caller masks
    the remainder of that line and reports incomplete lexical analysis.
    """
    pos = start + 1
    in_class = False
    limit = min(len(text), start + _MAX_REGEX_LENGTH)
    while pos < limit and text[pos] not in "\r\n":
        char = text[pos]
        if char == "\\":
            if pos + 1 >= limit or text[pos + 1] in "\r\n":
                return None
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
            return pos
        pos += 1
    return None


def _jsx_open_name(text: str, start: int) -> str | None:
    """Recognize a JSX opening tag without confusing `<T,>` generics with JSX."""
    if text.startswith("<>", start):
        return ""
    pos = start + 1
    if pos >= len(text) or not (text[pos].isascii() and text[pos].isalpha()):
        return None
    pos += 1
    while pos < min(len(text), start + 129) and (
        (text[pos].isascii() and text[pos].isalnum()) or text[pos] in "_.$:-"
    ):
        pos += 1
    if pos == len(text) or text[pos] not in " \t\r\n/>":
        return None
    name = text[start + 1:pos]
    # A bare `<T>(...)` in TSX is commonly a generic arrow function, with
    # no JSX closing tag. Leave its body visible to the scanner.
    if name[0].isupper():
        if text.startswith(">(", pos):
            return None
        # Constrained and defaulted TSX generic arrows can look like JSX
        # opening tags: `<T extends object>(x: T) => x` and `<T = X>(...)`.
        suffix = text[pos:min(len(text), pos + 64)].lstrip()
        constraint = suffix.startswith("extends") and (
            len(suffix) == 7 or suffix[7].isspace() or suffix[7] in "<{"
        )
        if constraint or suffix.startswith("="):
            end = text.find(">(", pos, min(len(text), pos + 1024))
            if end >= 0 and "=>" in text[end + 2:min(len(text), end + 258)]:
                return None
    return name


def noncode_ranges(
    text: str, language: str | None, dialect: str | None = None, *, jsx: bool = False,
) -> tuple[list[tuple[int, int]], bool]:
    """Return sorted ignored half-open spans and whether lexing was incomplete."""
    if language == "python":
        return _python_ranges(text)
    if language == "javascript":
        return _javascript_ranges(text, jsx=jsx)
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
    text: str, offsets: list[int], first_line: int, spans: list[tuple[int, int]], reader: io.StringIO,
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
        getattr(tokenize, name) for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END")
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
        start = offset(position)
        if start < len(text):  # an error reported at EOF itself masks nothing
            spans.append((start, len(text)))
        # An unterminated multi-line literal/statement is masked through EOF:
        # nothing after that opening can be executable Python. Any other
        # tokenizer error (Python 3.12+ raises for mid-file lexical errors that
        # 3.11 tolerated) masks the remainder ambiguously and must mark the
        # file incomplete.
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
                return i + len(delimiter), "f" in token[start:prefix.start(1)].lower(), True
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


def _javascript_ranges(text: str, *, jsx: bool = False) -> tuple[list[tuple[int, int]], bool]:
    spans: list[tuple[int, int]] = []
    # Template text is inert; ${...} expressions are scanned as executable code.
    # The stack also allows nested template literals in interpolation bodies.
    modes: list[tuple[str, int]] = [("code", 0)]
    pending_jsx_tags: list[str] = []
    open_jsx_tags: list[str] = []
    # One lexical expression context for each active code/interpolation body.
    # Template text has no expression context of its own.
    can_start_regex = [True]
    control_pending = [False]
    control_parens: list[list[bool]] = [[]]
    incomplete = False
    i = 0
    size = len(text)
    while i < size:
        mode, depth = modes[-1]
        if mode == "template":
            start = i
            while i < size:
                if text[i] == "\\":
                    i += 2
                elif text.startswith("${", i):
                    spans.append((start, i + 2))
                    i += 2
                    modes.append(("interpolation", 1))
                    can_start_regex.append(True)
                    control_pending.append(False)
                    control_parens.append([])
                    break
                elif text[i] == "`":
                    spans.append((start, i + 1))
                    i += 1
                    modes.pop()
                    break
                else:
                    i += 1
            else:
                spans.append((start, size))
                return spans, True
            continue

        if mode == "jsx_text":
            if text.startswith("</", i):
                end = text.find(">", i + 2, min(size, i + _MAX_REGEX_LENGTH))
                if end < 0:
                    spans.append((depth, size))
                    return spans, True
                spans.append((depth, i))
                spans.append((i, end + 1))
                if not open_jsx_tags or text[i + 2:end].strip() != open_jsx_tags.pop():
                    incomplete = True
                modes.pop()
                i = end + 1
                if modes[-1][0] in {"jsx_tag", "jsx_text"}:
                    modes[-1] = (modes[-1][0], i)
                continue
            if text[i] == "{":
                spans.append((depth, i + 1))
                i += 1
                modes.append(("jsx_expression", 1))
                can_start_regex.append(True)
                control_pending.append(False)
                control_parens.append([])
                continue
            name = _jsx_open_name(text, i) if text[i] == "<" else None
            if name is not None:
                spans.append((depth, i))
                modes.append(("jsx_tag", i))
                pending_jsx_tags.append(name)
                i += 1
                continue
            i += 1
            if i == size:
                spans.append((depth, size))
                return spans, True
            continue

        if mode == "jsx_tag":
            if text[i] in {'"', "'"}:
                quote = text[i]
                i += 1
                while i < size and text[i] != quote:
                    i += 2 if text[i] == "\\" else 1
                if i >= size:
                    spans.append((depth, size))
                    return spans, True
                i += 1
                continue
            if text[i] == "{":
                spans.append((depth, i + 1))
                i += 1
                modes.append(("jsx_expression", 1))
                can_start_regex.append(True)
                control_pending.append(False)
                control_parens.append([])
                continue
            if text[i] == ">":
                spans.append((depth, i + 1))
                name = pending_jsx_tags.pop()
                self_closing = text[depth:i].rstrip().endswith("/")
                i += 1
                modes.pop()
                if self_closing:
                    if modes[-1][0] == "jsx_text":
                        modes[-1] = ("jsx_text", i)
                else:
                    open_jsx_tags.append(name)
                    modes.append(("jsx_text", i))
                continue
            i += 1
            if i == size:
                spans.append((depth, size))
                return spans, True
            continue

        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            spans.append((i, size if end < 0 else end))
            i = size if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                spans.append((i, size))
                return spans, True
            spans.append((i, end + 2))
            i = end + 2
        elif text[i] in {'"', "'"}:
            quote = text[i]
            start = i
            i += 1
            while i < size and text[i] != quote and text[i] not in "\r\n":
                i += 2 if text[i] == "\\" else 1
            if i < size and text[i] == quote:
                i += 1
            spans.append((start, i))
            can_start_regex[-1] = False
            control_pending[-1] = False
        elif text[i] == "/" and can_start_regex[-1]:
            regex_end = _javascript_regex_end(text, i)
            if regex_end is None:
                end = text.find("\n", i)
                end = size if end < 0 else end
                spans.append((i, end))
                i = end
                incomplete = True
            else:
                spans.append((i, regex_end))
                i = regex_end
            can_start_regex[-1] = False
            control_pending[-1] = False
        elif text[i] == "/":
            i += 2 if text.startswith("/=", i) else 1
            can_start_regex[-1] = True
            control_pending[-1] = False
        elif text[i] == "`":
            spans.append((i, i + 1))
            i += 1
            modes.append(("template", 0))
            can_start_regex[-1] = False
            control_pending[-1] = False
        elif mode in {"interpolation", "jsx_expression"} and text[i] == "{":
            modes[-1] = (mode, depth + 1)
            i += 1
            can_start_regex[-1] = True
        elif mode in {"interpolation", "jsx_expression"} and text[i] == "}":
            if depth == 1:
                spans.append((i, i + 1))
                modes.pop()
                can_start_regex.pop()
                control_pending.pop()
                control_parens.pop()
                if mode == "jsx_expression":
                    modes[-1] = (modes[-1][0], i + 1)
            else:
                modes[-1] = (mode, depth - 1)
                can_start_regex[-1] = False
            i += 1
        elif jsx and text[i] == "<" and can_start_regex[-1] and (
            name := _jsx_open_name(text, i)
        ) is not None:
            pending_jsx_tags.append(name)
            modes.append(("jsx_tag", i))
            can_start_regex[-1] = False
            control_pending[-1] = False
            i += 1
        elif text[i].isalpha() or text[i] in "_$":
            start = i
            i += 1
            while i < size and (text[i].isalnum() or text[i] in "_$"):
                i += 1
            word = text[start:i]
            can_start_regex[-1] = word in _REGEX_PREFIX_WORDS
            control_pending[-1] = word in _CONTROL_HEADS
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
            i += 1
        elif text[i] in "+-" and i + 1 < size and text[i + 1] == text[i]:
            # ++/-- in an expression are postfix; in expression-start position
            # they are prefix operators.
            control_pending[-1] = False
            i += 2
        elif text[i] in ";:=!?%~^&|*<>+-":
            can_start_regex[-1] = True
            control_pending[-1] = False
            i += 1
        elif text[i] == ".":
            can_start_regex[-1] = False
            control_pending[-1] = False
            i += 1
        else:
            if not text[i].isspace():
                control_pending[-1] = False
            i += 1
    return spans, incomplete or len(modes) != 1


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


_RUST_RAW = re.compile(r'(?:br|rb|r)(#{0,255})"')
_RUBY_HEREDOC = re.compile(r"<<[-~]?(['\"]?)([A-Za-z_]\w*)\1")
_PHP_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1")
_GO_IMPORT_BLOCK = re.compile(r"import\s*\(")
_MAX_GO_IMPORT_PREFIX = 4096
_RUBY_PERCENT_PAIRS = {"{": "}", "[": "]", "(": ")", "<": ">"}


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
    spans: list[tuple[int, int]] = []
    modes: list[_Literal | _Expression] = []
    i = 0
    size = len(text)
    incomplete = False
    go_import_block = False
    heredocs: list[str] = []
    line_start = 0
    line_checked_through = 0
    # A PHP source file can be an HTML-only template. Enter code mode only at
    # an opening tag, including the short echo form (<?=).
    php_code = language != "php"

    def line_before(index: int) -> str | None:
        nonlocal line_start, line_checked_through, incomplete
        # Check only source not visited by the preceding Go quote. Repeated
        # quotes on a very long line must not repeatedly scan/copy its prefix.
        newline = text.rfind("\n", line_checked_through, index)
        if newline >= 0:
            line_start = newline + 1
        line_checked_through = index
        if index - line_start > _MAX_GO_IMPORT_PREFIX:
            prefix = text[line_start:line_start + _MAX_GO_IMPORT_PREFIX]
            if prefix.isspace() or re.match(r"\s*import\b", prefix):
                incomplete = True  # Too long to classify as a Go import safely.
            return None
        return text[line_start:index]

    while i < size:
        mode = modes[-1] if modes else None
        if language == "php" and not php_code:
            opening = text.find("<?", i)
            if opening < 0:
                spans.append((i, size))
                break
            spans.append((i, opening + 2))
            i = opening + 2
            php_code = True
            continue
        if isinstance(mode, _Literal):
            if mode.interpolation and text.startswith(mode.interpolation, i):
                # In C# escaped braces are text, not interpolation delimiters.
                if mode.interpolation == "{" and text.startswith("{{", i):
                    i += 2
                    continue
                end = i + len(mode.interpolation)
                spans.append((mode.start, end))
                modes.append(_Expression(")" if mode.interpolation.endswith("(") else "}"))
                i = end
            elif mode.verbatim and text.startswith('""', i) and mode.close == '"':
                i += 2
            elif mode.escaped and text[i] == "\\":
                i = min(size, i + 2)
            elif text.startswith(mode.close, i):
                end = i + len(mode.close)
                spans.append((mode.start, end))
                modes.pop()
                i = end
            elif not mode.multiline and text[i] in "\r\n":
                spans.append((mode.start, i))
                modes.pop()
                incomplete = True
            else:
                i += 1
            continue

        if isinstance(mode, _Expression):
            if text[i] == mode.close:
                mode.depth -= 1
                if not mode.depth:
                    spans.append((i, i + 1))
                    modes.pop()
                    assert isinstance(modes[-1], _Literal)
                    modes[-1].start = i + 1
                i += 1
                continue
            if text[i] == ("(" if mode.close == ")" else "{"):
                mode.depth += 1
                i += 1
                continue

        if heredocs and (i == 0 or text[i - 1] == "\n"):
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
                incomplete = True
            spans.append((i, end))
            i = end
            if i < size:
                i += 1
            else:
                incomplete |= bool(heredocs)
            continue

        if language == "php" and text.startswith("?>", i):
            spans.append((i, i + 2))
            i += 2
            php_code = False
            continue

        if language == "ruby" and (i == 0 or text[i - 1] == "\n") and text.startswith("=begin", i) and (i + 6 == size or text[i + 6].isspace()):
            # Search from a position instead of slicing: a file of many short
            # blocks would otherwise copy the remainder for each one (quadratic).
            end_marker = _RUBY_BLOCK_END.search(text, i + 6)
            if end_marker is None:
                spans.append((i, size))
                return spans, True
            end = end_marker.end()
            spans.append((i, end))
            i = end
            continue

        if language == "ruby" and text.startswith("<<", i):
            heredoc = _RUBY_HEREDOC.match(text, i)
            if heredoc:
                heredocs.append(heredoc.group(2))
                i = heredoc.end()
                continue

        if language == "ruby" and _ruby_percent_delimiter(text, i):
            end, certain = _ruby_percent_string_end(text, i)
            spans.append((i, end))
            if not certain:
                return spans, True
            i = end
            continue

        if language == "php" and text.startswith("<<<", i):
            heredoc = _PHP_HEREDOC.match(text, i)
            if heredoc:
                heredocs.append(heredoc.group(2))
                i = heredoc.end()
                continue

        if language == "go" and text.startswith("import", i) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            match = _GO_IMPORT_BLOCK.match(text, i)
            if match:
                go_import_block = True
                i = match.end()
                continue
        if language == "go" and go_import_block and text[i] == ")":
            go_import_block = False

        if dialect == ".fs" and text.startswith("(*", i):
            depth = 1
            j = i + 2
            while j < size and depth:
                if text.startswith("(*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*)", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            spans.append((i, j))
            if depth:
                return spans, True
            i = j
            continue

        if (language != "ruby" and text.startswith("//", i)) or (language in {"ruby", "php"} and text[i] == "#"):
            end = text.find("\n", i)
            end = size if end < 0 else end
            spans.append((i, end))
            i = end
            continue
        if language != "ruby" and text.startswith("/*", i):
            depth = 1
            j = i + 2
            nested = language in {"rust", "swift", "dart"} or dialect in {".kt", ".kts", ".scala"}
            while j < size and depth:
                if nested and text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            spans.append((i, j))
            if depth:
                return spans, True
            i = j
            continue

        if language == "rust" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            raw = _RUST_RAW.match(text, i)
            if raw:
                close = '"' + raw.group(1)
                end = text.find(close, raw.end())
                if end < 0:
                    spans.append((i, size))
                    return spans, True
                spans.append((i, end + len(close)))
                i = end + len(close)
                continue

        prefix = ""
        if language == "dotnet":
            for candidate in ("$@", "@$", "@", "$"):
                if text.startswith(candidate + '"', i):
                    prefix = candidate
                    break
        elif language == "dart" and text.startswith(("r'", 'r"'), i):
            prefix = "r"
        elif language == "rust" and text.startswith(('b"', "b'"), i):
            prefix = "b"
        elif language == "swift" and text[i] == "#":
            j = i
            while j < size and text[j] == "#" and j - i < 255:
                j += 1
            if j < size and text[j] == '"':
                prefix = text[i:j]

        q = i + len(prefix)
        if q < size and text[q] in {'"', "'", "`"}:
            quote = text[q]
            if quote == "`" and language != "go":
                i += 1
                continue
            if quote == "'" and language == "rust":
                # A lifetime ('a or 'static) is code. Rust character literals
                # contain exactly one character or an escaped character.
                char = q + 1
                char += 2 if char < size and text[char] == "\\" else 1
                if char >= size or text[char] != "'":
                    i += 1
                    continue
            if quote == '"' and language == "go":
                before = line_before(i)
                if before is not None and (re.fullmatch(r"\s*import\s+(?:[\w.]+\s+)?", before) or (
                    go_import_block and re.fullmatch(r"\s*(?:[\w.]+\s*)?", before)
                )):
                    i = q + 1
                    while i < size and text[i] != '"' and text[i] not in "\r\n":
                        i += 2 if text[i] == "\\" else 1
                    i += i < size and text[i] == '"'
                    continue
            triple = quote == '"' and language in {"java", "dotnet", "swift", "dart", "ruby"} and text.startswith('"""', q)
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
            modes.append(_Literal(i, close, escaped=quote != "`" and not (prefix == "r" or "@" in prefix or prefix.startswith("#") or triple and language == "dotnet"),
                                  verbatim="@" in prefix, interpolation=interpolation,
                                  multiline=triple or quote == "`" or "@" in prefix))
            i = q + len(opener)
            continue
        i += 1

    if modes or heredocs:
        incomplete = True
        for mode in modes:
            if isinstance(mode, _Literal):
                spans.append((mode.start, size))
    return sorted(spans), incomplete
