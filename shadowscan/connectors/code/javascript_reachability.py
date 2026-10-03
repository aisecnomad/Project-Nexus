"""Exclude only JavaScript branches proved dead by a literal condition.

This is a bounded lexical check, not a JavaScript control-flow analysis. It
understands ``if``/``else`` and ``while`` with boolean, null, numeric or plain
string conditions, optional parentheses and boolean negation. Dynamic guards,
escaped strings, logical operators, ambiguous ASI bodies and malformed shapes
remain possible. Source is never executed and returned ranges preserve offsets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import regex

from shadowscan.signatures.matcher import pattern_timeout

MAX_TOKENS = 50_000
MAX_NESTING = 128
_TOKEN = re.compile(
    r"[A-Za-z_$][\w$]*|0[xX][0-9a-fA-F]+n?|0[bB][01]+n?|0[oO][0-7]+n?|"
    r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?n?|\S"
)
_NUMBER = re.compile(
    r"(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|"
    r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)(?:n)?\Z"
)


class JavascriptReachabilityLimit(Exception):
    """The literal-branch check exceeded its structural budget."""


@dataclass(frozen=True)
class _Token:
    value: str
    start: int
    end: int
    literal: bool = False


def _tokens(text: str, masked: str, ignored: list[tuple[int, int]]) -> list[_Token]:
    result: list[_Token] = []
    spans = iter(ignored)
    span = next(spans, None)
    offset = 0
    while offset < len(masked):
        if len(result) >= MAX_TOKENS:
            raise JavascriptReachabilityLimit("source binding JavaScript token limit exceeded")
        if not len(result) % 256:
            pattern_timeout()
        if span is not None and offset == span[0]:
            value = text[span[0] : span[1]]
            if not value.startswith(("//", "/*")):
                # Keep opaque literals as tokens. Otherwise an unknown regex or
                # template condition would disappear and resemble a known one.
                result.append(_Token(value, *span, literal=True))
            offset = span[1]
            span = next(spans, None)
        elif masked[offset].isspace():
            offset += 1
        else:
            match = _TOKEN.match(masked, offset)
            assert match is not None  # every non-whitespace character matches \S
            result.append(_Token(match.group(), offset, match.end()))
            offset = match.end()
    return result


class _Branches:
    def __init__(self, text: str, tokens: list[_Token]) -> None:
        self.text = text
        self.tokens = tokens
        self.pairs: dict[int, int] = {}
        self.ends: dict[int, int | None] = {}
        stack: list[int] = []
        for position, token in enumerate(tokens):
            if not position % 256:
                pattern_timeout()
            if token.literal:
                continue
            if token.value in {"(", "[", "{"}:
                stack.append(position)
            elif token.value in {")", "]", "}"}:
                if not stack or tokens[stack[-1]].value != {")": "(", "]": "[", "}": "{"}[token.value]:
                    self.pairs.clear()
                    return
                self.pairs[stack.pop()] = position
        if stack:
            self.pairs.clear()

    def is_token(self, position: int, value: str) -> bool:
        return (
            position < len(self.tokens)
            and not self.tokens[position].literal
            and self.tokens[position].value == value
        )

    def truth(self, start: int, end: int) -> bool | None:
        negate = False
        while start < end:
            if self.is_token(start, "!"):
                negate = not negate
                start += 1
            elif self.is_token(start, "(") and self.pairs.get(start) == end - 1:
                start, end = start + 1, end - 1
            else:
                break
        # A numeric unary sign preserves truthiness; other operations are unknown.
        if end - start == 2 and self.tokens[start].value in {"+", "-"}:
            operand = self.tokens[start + 1]
            if operand.literal or not _NUMBER.fullmatch(operand.value):
                return None
            if self.tokens[start].value == "+" and operand.value.endswith("n"):
                return None
            start += 1
        if end - start != 1:
            return None
        token = self.tokens[start]
        value = token.value
        if token.literal:
            if len(value) < 2 or value[0] not in {"'", '"'} or value[-1] != value[0] or "\\" in value:
                return None
            truth = bool(value[1:-1])
        elif value in {"true", "false", "null"}:
            truth = value == "true"
        elif _NUMBER.fullmatch(value):
            number = value.removesuffix("n")
            if number.lower().startswith(("0x", "0b", "0o")):
                truth = any(character not in "0" for character in number[2:])
            elif value.endswith("n") and number.isdecimal():
                truth = any(character != "0" for character in number)
            elif value.endswith("n") or len(number) > 512:
                return None
            else:
                # JavaScript decimal Number literals use binary64 too: small
                # exponents can underflow to zero, unlike mathematical integers.
                truth = bool(float(number))
        else:
            # undefined, NaN and Infinity are identifiers, possibly shadowed.
            return None
        return truth != negate

    def guard(self, position: int) -> tuple[int, int] | None:
        opening = position + 1
        if not self.is_token(opening, "(") or opening not in self.pairs:
            return None
        closing = self.pairs[opening]
        return opening, closing

    def statement_end(self, position: int, depth: int = 0) -> int | None:
        if depth >= MAX_NESTING:
            raise JavascriptReachabilityLimit("source binding JavaScript statement nesting limit exceeded")
        if position in self.ends:
            return self.ends[position]
        result = self._statement_end(position, depth)
        self.ends[position] = result
        return result

    def _statement_end(self, position: int, depth: int) -> int | None:
        if position >= len(self.tokens):
            return None
        if self.is_token(position, "{"):
            closing = self.pairs.get(position)
            return closing + 1 if closing is not None else None
        if self.is_token(position, "do"):
            end = self.statement_end(position + 1, depth + 1)
            guard = self.guard(end) if end is not None and self.is_token(end, "while") else None
            if guard is None:
                return None
            finish = guard[1] + 1
            return finish + int(self.is_token(finish, ";"))
        if self.is_token(position + 1, ":"):
            # A labeled statement may own a nested if's else. Without parsing
            # labels, never let that alternative be mistaken for the outer if.
            return None
        if self.tokens[position].value in {"if", "while", "for", "with"}:
            guard = self.guard(position)
            if guard is None:
                return None
            end = self.statement_end(guard[1] + 1, depth + 1)
            if end is not None and self.is_token(position, "if") and self.is_token(end, "else"):
                end = self.statement_end(end + 1, depth + 1)
            return end
        # An explicit semicolon, block end or EOF bounds an unbraced body. At a
        # top-level newline, ASI could have ended it: do not swallow the next
        # live statement. Balanced call/object text can itself span many lines.
        cursor = position
        previous = self.tokens[position].start
        while cursor < len(self.tokens):
            token = self.tokens[cursor]
            if self.is_token(cursor, "}"):
                return cursor if cursor > position else None
            if any(character in "\n\r\u2028\u2029" for character in self.text[previous : token.start]):
                return None
            if self.is_token(cursor, ";"):
                return cursor + 1
            if token.value in {"else", "do", "switch", "try", "function", "class"} and not token.literal:
                return None
            if cursor in self.pairs:
                cursor = self.pairs[cursor]
                token = self.tokens[cursor]
            previous = token.end
            cursor += 1
        return len(self.tokens)

    def dead_ranges(self) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        tails: set[int] = set()
        ambiguous_do = False
        for position, token in enumerate(self.tokens):
            if not position % 256:
                pattern_timeout()
            if token.literal or token.value != "do":
                continue
            if position and self.tokens[position - 1].value == ".":
                continue
            end = self.statement_end(position + 1)
            if end is not None and self.is_token(end, "while") and self.guard(end) is not None:
                tails.add(end)
            else:
                # An ASI-dependent or unsupported do body may end at a later
                # while. Do not misread that tail as a new loop around live code.
                ambiguous_do = True
        for position, token in enumerate(self.tokens):
            if not position % 256:
                pattern_timeout()
            if token.literal or token.value not in {"if", "while"}:
                continue
            if token.value == "while" and (position in tails or ambiguous_do):
                continue
            # Member calls named if/while cannot establish a control statement.
            if position and self.tokens[position - 1].value == ".":
                continue
            guard = self.guard(position)
            if guard is None:
                continue
            truth = self.truth(guard[0] + 1, guard[1])
            if truth is None:
                continue
            body = guard[1] + 1
            end = self.statement_end(body)
            if end is None:
                continue
            if not truth:
                ranges.append((self.tokens[body].start, self.tokens[end - 1].end))
            elif token.value == "if" and self.is_token(end, "else"):
                alternative = self.statement_end(end + 1)
                if alternative is not None:
                    ranges.append((self.tokens[end + 1].start, self.tokens[alternative - 1].end))
        # Nested dead statements can overlap; coalesce before masking.
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged


def javascript_dead_ranges(text: str, masked: str, ignored: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Return literal-dead statement ranges, or none for unsupported guards."""
    if not regex.search(r"\b(?:if|while)\b", masked, timeout=pattern_timeout(), concurrent=False):
        return []
    # A file containing only dynamic guards cannot yield a literal-dead branch
    # at any size. Prove that before spending the structural token budget. Put
    # back only a quote marker at each ordinary string's start so plain-string
    # guards remain candidates without exposing fake guards in literal text.
    pieces: list[str] = []
    previous = 0
    for start, _ in ignored:
        if text[start : start + 1] in {"'", '"'}:
            pieces.extend((masked[previous:start], "'"))
            previous = start + 1
    pieces.append(masked[previous:])
    probe = "".join(pieces)
    if not regex.search(
        r"(?<![\w$.])(?:if|while)\s*\(\s*[!()+\-\s]*(?:(?:true|false|null)\b|[0-9]|\.[0-9]|')",
        probe,
        timeout=pattern_timeout(),
        concurrent=False,
    ):
        return []
    return _Branches(text, _tokens(text, masked, ignored)).dead_ranges()
