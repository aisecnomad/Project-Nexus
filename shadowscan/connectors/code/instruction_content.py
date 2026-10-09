"""Static checks on agent instruction files: hidden content, fetched code, invisible text.

Coding agents execute skills, instruction files, rules and hook configuration
as operator guidance. Three shapes make such a file a review item on their
own, independent of any product signature: text the agent reads but a human
viewing the rendered file does not (HTML comments and invisible or
bidirectional control characters), and shell lines that download code and run
it in one step. Checks are bounded regexes over text; nothing is executed and
no excerpt leaves this module beyond the rule name, line and byte counts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_TEXT_BYTES = 512 * 1024
MAX_HITS_PER_RULE = 3

# Rendered Markdown hides HTML comments; a comment holding sentences is content
# addressed to the agent alone. Short markers (a TODO, a linter directive) are not.
MAX_COMMENT_BYTES = 4000
MIN_COMMENT_WORDS = 6
_WORD = re.compile(r"[A-Za-z]{2,}")
# A network fetch piped straight into an interpreter, or process substitution of one.
_FETCH_PIPE = re.compile(
    r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|fi)?sh\b"
    r"|\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby|pwsh|powershell)\b"
    r"|\b(?:ba)?sh\s+<\(\s*(?:curl|wget)\b"
)
# An inline encoded blob decoded and handed to an interpreter in one pipeline.
_DECODE_PIPE = re.compile(
    r"\bbase64\s+(?:-d|-D|--decode)\b[^\n]{0,300}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"
    r"|\bbase64\s+(?:-d|-D|--decode)\b[^\n]{0,300}\|\s*(?:sudo\s+)?(?:python3?|node|perl)\b"
)
# Zero-width, bidirectional and Unicode tag characters: present in the bytes,
# absent from the rendered page.
_INVISIBLE = re.compile("[​-‏  ‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")


@dataclass(frozen=True)
class ContentHit:
    rule: str
    tag: str
    weight: float
    line: int
    detail: str


RULE_TAGS: dict[str, str] = {
    "hidden-comment-content": "hidden-instructions",
    "fetch-and-execute": "remote-code-fetch",
    "decode-and-execute": "remote-code-fetch",
    "invisible-characters": "invisible-text",
}


def _html_comments(text: str) -> list[tuple[int, str]]:
    """(offset, body) of each closed HTML comment, found with linear string scans rather than a regex."""
    out: list[tuple[int, str]] = []
    position = 0
    while True:
        start = text.find("<!--", position)
        if start < 0:
            return out
        end = text.find("-->", start + 4, start + 4 + MAX_COMMENT_BYTES)
        if end < 0:
            position = start + 4
            continue
        out.append((start, text[start + 4 : end]))
        position = end + 3


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def inspect_instruction_text(text: str) -> list[ContentHit]:
    """Return the rule hits for one instruction file, at most MAX_HITS_PER_RULE each."""
    if len(text) > MAX_TEXT_BYTES:
        text = text[:MAX_TEXT_BYTES]
    hits: list[ContentHit] = []
    counts: dict[str, int] = {}

    def add(rule: str, weight: float, offset: int, detail: str) -> None:
        if counts.get(rule, 0) >= MAX_HITS_PER_RULE:
            return
        counts[rule] = counts.get(rule, 0) + 1
        hits.append(ContentHit(rule, RULE_TAGS[rule], weight, _line_of(text, offset), detail))

    for start, body in _html_comments(text):
        words = len(_WORD.findall(body))
        if words >= MIN_COMMENT_WORDS:
            add("hidden-comment-content", 0.8, start, f"HTML comment holding {words} words")
    for m in _FETCH_PIPE.finditer(text):
        add("fetch-and-execute", 0.85, m.start(), "network fetch piped into an interpreter")
    for m in _DECODE_PIPE.finditer(text):
        add("decode-and-execute", 0.85, m.start(), "decoded data piped into an interpreter")
    invisible = _INVISIBLE.findall(text)
    if invisible:
        first = _INVISIBLE.search(text)
        assert first is not None
        add("invisible-characters", 0.7, first.start(), f"{len(invisible)} invisible or control character(s)")
    return hits
