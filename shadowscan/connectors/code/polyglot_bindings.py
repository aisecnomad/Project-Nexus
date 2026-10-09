"""Bounded lexical structures for narrow Go and C# import proofs.

This is not a compiler or type checker. Literal/comment ranges come from the
source lexer; unsupported or uncertain bindings never prove an agent. Token,
nesting and call budgets share the scanner's per-input execution deadline.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass

from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

MAX_TOKENS = 50_000
MAX_DEPTH = 128
MAX_CALLS = 512
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|`[^`]*`|[A-Za-z_@][\w@]*|:=|=>|::|[^\s]')
IDENTIFIER = re.compile(r"[A-Za-z_]\w*\Z")


@dataclass
class SourceTokens:
    text: str
    words: list[str]
    starts: list[int]
    pairs: dict[int, int]
    reverse: dict[int, int]
    newlines: list[int]

    def line(self, position: int) -> int:
        return bisect_right(self.newlines, self.starts[position]) + 1

    def args(self, opening: int) -> list[tuple[int, int]]:
        """Top-level comma-separated spans in a paired delimiter."""
        end = self.pairs.get(opening, opening)
        result: list[tuple[int, int]] = []
        start = cursor = opening + 1
        while cursor < end:
            if self.words[cursor] == ",":
                result.append((start, cursor))
                start = cursor + 1
            cursor = self.pairs.get(cursor, cursor) + 1
        if start < end:
            result.append((start, end))
        return result

    def path(self, start: int) -> tuple[str, int]:
        words = self.words
        if start >= len(words) or not IDENTIFIER.fullmatch(words[start]):
            return "", start
        end = start + 1
        while end + 1 < len(words) and words[end] == "." and IDENTIFIER.fullmatch(words[end + 1]):
            end += 2
        return "".join(words[start:end]), end


def source_tokens(text: str, ignored: list[tuple[int, int]], language: str) -> SourceTokens:
    """Preserve offsets; Go import literals are executable import syntax."""
    pieces: list[str] = []
    last = 0
    for start, end in ignored:
        pieces.extend((text[last:start], re.sub(r"[^\n]", " ", text[start:end])))
        last = end
    pieces.append(text[last:])
    masked = "".join(pieces)
    words: list[str] = []
    starts: list[int] = []
    pairs: dict[int, int] = {}
    stack: list[tuple[str, int]] = []
    closing = {")": "(", "]": "[", "}": "{"}
    for token in _TOKEN.finditer(masked):
        if len(words) >= MAX_TOKENS:
            raise MatchTimeoutError(f"{language} import proof token budget exceeded")
        if not len(words) % 256:
            pattern_timeout()
        word = token.group()
        position = len(words)
        words.append(word)
        starts.append(token.start())
        if word in {"(", "[", "{"}:
            stack.append((word, position))
            if len(stack) > MAX_DEPTH:
                raise MatchTimeoutError(f"{language} import proof nesting budget exceeded")
        elif word in closing:
            if not stack or stack[-1][0] != closing[word]:
                # Unknown structure cannot establish import/receiver proof.
                return SourceTokens(text, [], [], {}, {}, [])
            _, opening = stack.pop()
            pairs[opening] = position
    if stack:
        return SourceTokens(text, [], [], {}, {}, [])
    return SourceTokens(
        text,
        words,
        starts,
        pairs,
        {end: start for start, end in pairs.items()},
        [i for i, char in enumerate(text) if char == "\n"],
    )
