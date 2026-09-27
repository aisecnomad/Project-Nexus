"""Credentials named by XML elements, key/value attributes and name/value records.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. A setting's name decides whether its value is withheld: see
``redaction_rules._setting_level``.
"""

from __future__ import annotations

import re
from bisect import bisect_left

from shadowscan.utils.redaction_rules import REDACTED, _kept_value, _setting_level, _setting_value_withheld

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


def _markup_content(
    text: str, contents: _MarkupContent, tag: re.Match[str], inner_value: bool,
) -> tuple[int, int] | None:
    """The content of the element ``tag`` opens (of its <value> child when ``inner_value``).

    None unless the element closes right after that content.
    """
    start = tag.end()
    inner = _XML_VALUE_ELEMENT.match(text, start) if inner_value else None
    closing_tag = tag.group("tag") if inner is None else inner.group("tag")
    if inner is not None:
        start = inner.end()
    end = contents.end(start)
    return (start, end) if text.startswith("</" + closing_tag, end) else None


def _redact_markup_credentials(text: str) -> str:
    """Withhold credentials in XML elements and key/value attribute pairs.

    Key/name attributes and element names are read as settings (see
    ``_setting_level``): a sensitive one withholds any value, one whose last
    word names a credential only an opaque literal.
    """
    if "<" not in text:
        return text
    contents = _MarkupContent(text)
    spans: list[tuple[int, int]] = []
    for tag in _XML_TAG.finditer(text):
        attributes = tag.group("attributes")
        named = 0  # the strongest level of a key/name attribute
        values: list[tuple[int, int]] = []
        for attribute in _XML_ATTRIBUTE.finditer(attributes):
            group = "double" if attribute.group("double") is not None else "single"
            name = attribute.group("name").rsplit(":", 1)[-1].lower()
            if name in {"key", "name"}:
                named = max(named, _setting_level(attribute.group(group)))
            elif name == "value":
                offset = tag.start("attributes")
                values.append((offset + attribute.start(group), offset + attribute.end(group)))
        if named and values:
            spans.extend(span for span in values if _setting_value_withheld(named, text[span[0]:span[1]]))
            if named == 2:
                continue
        if attributes.rstrip().endswith("/"):
            continue  # a self-closing element has no content
        if named and not values:
            content = _markup_content(text, contents, tag, inner_value=True)
            if content is not None and _setting_value_withheld(named, text[content[0]:content[1]]):
                spans.append(content)
            if named == 2:
                continue
        # A weakly named key attribute leaves the element's own name to decide.
        level = _setting_level(tag.group("tag").rsplit(":", 1)[-1])
        if level:
            content = _markup_content(text, contents, tag, inner_value=False)
            if content is not None and _setting_value_withheld(level, text[content[0]:content[1]]):
                spans.append(content)
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
# An unquoted value stops at ']' unless that ']' closes a marker an earlier
# pass (or an earlier sanitization) left in it: stopping inside the marker
# would withhold '[REDACTED' again and grow it by one ']' on every pass.
_RECORD_INLINE_VALUE = re.compile(
    r"\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\])]+(?:(?<=\[REDACTED)\][^\s,;}\])]*)*"
)
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


def _record_scalar(raw: str) -> str:
    """A record value without surrounding blanks or a block scalar indicator ('|', '>-')."""
    value = raw.strip()
    head, newline, rest = value.partition("\n")
    return rest.strip() if newline and head.strip() in _RECORD_BLOCK_MARKERS else value


def _redact_name_value_pairs(text: str) -> str:
    """Withhold values that sibling name/key fields identify as credentials.

    Names are read as settings (see ``_setting_level``): a sensitive one
    withholds any value, one whose last word names a credential only an opaque
    literal.
    """
    pieces: list[str] = []
    cursor = 0
    index: _RecordIndex | None = None
    # Names that share a value field share its value, so it is decided once
    # per level: a weak name deciding it first leaves a sensitive one to withhold it.
    decided: dict[int, int] = {}
    for word in _RECORD_WORD.finditer(text):
        start = word.start()
        match = _RECORD_NAME.match(text, start - 1) if start and text[start - 1] in "\"'" else None
        match = match or _RECORD_NAME.match(text, start)
        if match is None or match.start() < cursor:
            continue
        level = _setting_level(match.group("name"))
        if not level:
            continue
        index = index or _RecordIndex(text)
        located = index.value_field(match)
        if located is None or decided.get(located[0].start(), 0) >= level:
            continue
        field, stop, column = located
        decided[field.start()] = level
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
        if start < cursor or _kept_value(raw) or not _setting_value_withheld(level, _record_scalar(raw)):
            continue
        pieces.append(text[cursor:start])
        pieces.append(REDACTED + "\n" * raw.count("\n"))
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)
