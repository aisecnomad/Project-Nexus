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
_INVISIBLE = re.compile(
    "[\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
# A zero-width joiner between two pictographs builds one emoji (a profession,
# a skin tone, a flag variant); it hides nothing. Python's ``re`` has no
# Extended_Pictographic class, so the blocks that hold emoji stand in for it.
_JOINER = "\u200d"
_PICTOGRAPH = re.compile(
    "[\u00a9\u00ae\u203c\u2049\u2122\u2139\u2194-\u21aa\u231a-\u23ff\u24c2\u25aa-\u27bf"
    "\u2934\u2935\u2b05-\u2b55\u3030\u303d\u3297\u3299\U0001f000-\U0001faff]"
)


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


def _html_comments(text: str) -> list[tuple[int, str, bool]]:
    """(offset, body, closed) of each HTML comment, found with linear string scans rather than a regex.

    A comment runs to the first ``-->`` after it, however long, and one that
    is never closed hides the rest of the file. Each scan resumes where the
    previous comment ended, so the whole pass stays linear.
    """
    out: list[tuple[int, str, bool]] = []
    position = 0
    while True:
        start = text.find("<!--", position)
        if start < 0:
            return out
        end = text.find("-->", start + 4)
        if end < 0:
            out.append((start, text[start + 4 :], False))
            return out
        out.append((start, text[start + 4 : end], True))
        position = end + 3


def _emoji_joiner(text: str, offset: int) -> bool:
    """Whether the character at ``offset`` is a zero-width joiner inside an emoji sequence."""
    if text[offset] != _JOINER or offset == 0 or offset + 1 >= len(text):
        return False
    before = offset - 1
    if text[before] == "\ufe0f" and before > 0:  # emoji presentation selector
        before -= 1
    return bool(_PICTOGRAPH.match(text, before) and _PICTOGRAPH.match(text, offset + 1))


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

    for start, body, closed in _html_comments(text):
        words = len(_WORD.findall(body))
        if words >= MIN_COMMENT_WORDS:
            detail = (
                f"HTML comment holding {words} words"
                if closed
                else f"unterminated HTML comment holding {words} words"
            )
            add("hidden-comment-content", 0.8, start, detail)
    for m in _FETCH_PIPE.finditer(text):
        add("fetch-and-execute", 0.85, m.start(), "network fetch piped into an interpreter")
    for m in _DECODE_PIPE.finditer(text):
        add("decode-and-execute", 0.85, m.start(), "decoded data piped into an interpreter")
    invisible = [m.start() for m in _INVISIBLE.finditer(text) if not _emoji_joiner(text, m.start())]
    if invisible:
        add("invisible-characters", 0.7, invisible[0], f"{len(invisible)} invisible or control character(s)")
    return hits
