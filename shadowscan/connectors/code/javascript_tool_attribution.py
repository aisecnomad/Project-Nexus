"""Connect literal JavaScript tool registrations to their local execution sites.

Only supplied import-bound agent/MCP constructors and stable module-level
definitions supply proof. Unknown collections, aliases, spreads and shadowed
names remain opaque. This is static registration evidence, never execution
attestation. Token and nesting limits share the source binder's bounded lexer.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass

import regex

from shadowscan.connectors.code.javascript_reachability import (
    JavascriptReachabilityLimit,
    _Branches,
    _Token,
    _tokens,
    javascript_dead_ranges,
)
from shadowscan.connectors.code.tool_attribution import ToolRegions
from shadowscan.signatures.matcher import pattern_timeout

_NAME = re.compile(r"[A-Za-z_$][\w$]*\Z")
MAX_SELECTED_DEFINITIONS = 512
MAX_TOOL_NESTING = 128


@dataclass(frozen=True)
class _Definition:
    name: str
    value: tuple[int, int]
    declaration: tuple[int, int]
    function: bool = False


class _Tools:
    def __init__(self, text: str, masked: str, tokens: list[_Token]) -> None:
        self.text = text
        self.masked = masked
        self.tokens = tokens
        self.pairs = _Branches(text, tokens).pairs
        self.positions = {token.start: index for index, token in enumerate(tokens)}
        self.ends = [token.end for token in tokens]
        self.definitions: dict[str, _Definition] = {}
        self.duplicates: set[str] = set()
        self.stability: dict[str, bool] = {}
        self.bodies: set[tuple[int, int]] = set()
        self.selected: set[str] = set()
        self.depth = 0
        self.collection_references: set[int] = set()
        self.entry_references: set[int] = set()
        self._definitions()

    def is_token(self, position: int, value: str) -> bool:
        return (
            position < len(self.tokens)
            and not self.tokens[position].literal
            and self.tokens[position].value == value
        )

    def name(self, position: int) -> str | None:
        if position >= len(self.tokens) or self.tokens[position].literal:
            return None
        value = self.tokens[position].value
        return value if _NAME.fullmatch(value) else None

    def parts(self, start: int, end: int) -> list[tuple[int, int]] | None:
        result: list[tuple[int, int]] = []
        cursor, previous = start, start
        while cursor < end:
            if not cursor % 256:
                pattern_timeout()
            if self.is_token(cursor, ","):
                result.append((previous, cursor))
                previous = cursor + 1
            elif self.tokens[cursor].value in {"(", "[", "{"} and not self.tokens[cursor].literal:
                closing = self.pairs.get(cursor)
                if closing is None or closing >= end:
                    return None
                cursor = closing
            cursor += 1
        if previous < end:
            result.append((previous, end))
        return result

    def fields(self, start: int, end: int) -> dict[str, tuple[int, int]] | None:
        if not self.is_token(start, "{") or self.pairs.get(start) != end - 1:
            return None
        fields: dict[str, tuple[int, int]] = {}
        for first, last in self.parts(start + 1, end - 1) or []:
            key = self.name(first)
            if key is None or key in fields:
                return None
            if self.is_token(first + 1, ":"):
                fields[key] = (first + 2, last)
            elif last - first == 1:
                fields[key] = (first, last)
            elif key == "execute" and self.is_token(first + 1, "("):
                fields[key] = (first, last)  # supported ordinary method shorthand
            else:
                return None
        return fields

    def call(self, start: int, end: int) -> tuple[int, int] | None:
        cursor = start + int(self.is_token(start, "new"))
        if self.name(cursor) is None:
            return None
        cursor += 1
        while self.is_token(cursor, ".") and self.name(cursor + 1) is not None:
            cursor += 2
        if self.is_token(cursor, "<"):
            # The binder already bounds generic arguments to a simple form.
            # Unsupported nested call/type syntax cannot supply registration.
            while cursor < end and not self.is_token(cursor, "("):
                if self.tokens[cursor].value in {";", "{", "}"}:
                    return None
                cursor += 1
        if self.is_token(cursor, "(") and self.pairs.get(cursor) == end - 1:
            return cursor, end - 1
        return None

    def callback(self, start: int, end: int) -> tuple[int, int] | None:
        cursor = start + int(self.is_token(start, "async"))
        if self.is_token(cursor, "function"):
            cursor += 1
            if self.name(cursor) is not None:
                cursor += 1
            if not self.is_token(cursor, "(") or cursor not in self.pairs:
                return None
            cursor = self.pairs[cursor] + 1
            if self.is_token(cursor, "{") and self.pairs.get(cursor) == end - 1:
                return cursor + 1, end - 1
            return None
        if self.is_token(cursor, "execute") and self.is_token(cursor + 1, "("):
            cursor = self.pairs.get(cursor + 1, end) + 1
            if self.is_token(cursor, "{") and self.pairs.get(cursor) == end - 1:
                return cursor + 1, end - 1
            return None
        if self.is_token(cursor, "(") and cursor in self.pairs:
            cursor = self.pairs[cursor] + 1
        elif self.name(cursor) is not None:
            cursor += 1
        else:
            return None
        if not self.is_token(cursor, "=") or not self.is_token(cursor + 1, ">"):
            return None
        cursor += 2
        if self.is_token(cursor, "{"):
            return (cursor + 1, end - 1) if self.pairs.get(cursor) == end - 1 else None
        return (cursor, end) if cursor < end else None

    def _definitions(self) -> None:
        depth = 0
        for position, token in enumerate(self.tokens):
            if not position % 256:
                pattern_timeout()
            if token.literal:
                continue
            if token.value == "{":
                depth += 1
            elif token.value == "}":
                depth -= 1
            if depth or token.value not in {"const", "function"}:
                continue
            name = self.name(position + 1)
            if name is None:
                continue
            if name in self.definitions:
                self.duplicates.add(name)
                continue
            if token.value == "function":
                opening = position + 2
                closing = self.pairs.get(opening)
                body = closing + 1 if closing is not None else len(self.tokens)
                finish = self.pairs.get(body)
                if self.is_token(opening, "(") and self.is_token(body, "{") and finish is not None:
                    self.definitions[name] = _Definition(
                        name, (body + 1, finish), (position + 1, position + 2), function=True
                    )
                continue
            cursor = position + 2
            if self.is_token(cursor, ":"):
                while cursor < len(self.tokens) and self.tokens[cursor].value not in {"=", ";", "{"}:
                    cursor += 1
            if not self.is_token(cursor, "="):
                continue
            start = cursor + 1
            cursor = start
            while cursor < len(self.tokens) and not self.is_token(cursor, ";"):
                if cursor in self.pairs:
                    cursor = self.pairs[cursor]
                elif self.tokens[cursor].value in {"}", "const", "let", "var", "export"}:
                    break
                cursor += 1
            if self.is_token(cursor, ";"):
                self.definitions[name] = _Definition(name, (start, cursor), (position + 1, position + 2))

    def stable(
        self,
        definition: _Definition,
        *,
        server: bool = False,
        collection: bool = False,
        descriptor: bool = False,
    ) -> bool:
        if definition.name in self.duplicates:
            return False
        key = definition.name + (
            ":server" if server else ":collection" if collection else ":descriptor" if descriptor else ""
        )
        if key in self.stability:
            return self.stability[key]
        first, last = definition.declaration
        start, end = self.tokens[first].start, self.tokens[last - 1].end
        allowed = self.collection_references if collection else self.entry_references
        if (collection or descriptor) and any(
            not token.literal
            and token.value == definition.name
            and token.start != start
            and token.start not in allowed
            for token in self.tokens
        ):
            self.stability[key] = False
            return False  # const protects the binding, not escaped mutable contents
        rest = self.masked[:start] + " " * (end - start) + self.masked[end:]
        name = re.escape(definition.name)
        patterns = [
            rf"\b(?:const|let|var|class|function)\s+{name}\b",
            rf"(?<![\w$.]){name}\s*(?:=(?!=|>)|\+=|-=|\*=|/=|\+\+|--|\[)",
            rf"\bfunction\b[^(){{}};]*\([^)]*\b{name}\b[^)]*\)",
            rf"\([^()]*\b{name}\b[^()]*\)\s*(?::[^=;{{}}]+)?=>",
            rf"(?<![\w$.]){name}\s*=>",
            rf"(?<![\w$.]){name}\s*\.\s*[\w$]+\s*(?:=(?!=)|\+=|-=|\*=|/=|\+\+|--)",
            rf"\b(?:const|let|var)\s*\{{[^}}]*\b{name}\b",
            rf"\bdelete\s+{name}\s*(?:\.|\[)",
            rf"\b(?:Object\s*\.\s*(?:assign|defineProperty|defineProperties|setPrototypeOf)|"
            rf"Reflect\s*\.\s*(?:set|deleteProperty|defineProperty|setPrototypeOf))\s*\(\s*{name}\b",
            rf"\b(?:const|let|var)\s+[\w$]+\s*=\s*{name}\b",
            rf"\bcatch\s*\(\s*{name}\b",
            rf"(?:^|[;{{}}\n])\s*(?:async\s+)?[\w$]+\s*\([^)]*\b{name}\b[^)]*\)\s*(?::[^{{}};]+)?\{{",
        ]
        if not server:
            patterns.append(rf"(?<![\w$.]){name}\s*\.\s*[\w$]+\s*\(")
        result = not any(
            regex.search(pattern, rest, timeout=pattern_timeout(), concurrent=False) for pattern in patterns
        )
        self.stability[key] = result
        return result

    def resolve(self, start: int, end: int, before: int, *, collection: bool = False) -> _Definition | None:
        if end - start != 1:
            return None
        definition = self.definitions.get(self.tokens[start].value)
        return (
            definition
            if definition is not None
            and self.tokens[definition.value[0]].start < before
            and self.stable(definition, collection=collection)
            else None
        )

    def select_callback(self, start: int, end: int, before: int) -> None:
        body = self.callback(start, end)
        if body is not None:
            self.body(*body)
            return
        definition = self.resolve(start, end, before)
        if definition is None or definition.name in self.selected:
            return
        if len(self.selected) >= MAX_SELECTED_DEFINITIONS:
            raise JavascriptReachabilityLimit("source binding JavaScript tool definition limit exceeded")
        self.selected.add(definition.name)
        if definition.function:
            self.body(*definition.value)
        else:
            body = self.callback(*definition.value)
            if body is not None:
                self.body(*body)

    def body(self, start: int, end: int) -> None:
        if self.depth >= MAX_TOOL_NESTING:
            raise JavascriptReachabilityLimit("source binding JavaScript tool nesting limit exceeded")
        self.depth += 1
        try:
            self._body(start, end)
        finally:
            self.depth -= 1

    def _body(self, start: int, end: int) -> None:
        cursor = start
        while cursor < end:
            if not cursor % 256:
                pattern_timeout()
            # An unused nested function or arrow is not the registered callback.
            if self.is_token(cursor, "function"):
                opening = cursor + 1
                if self.name(opening) is not None:
                    opening += 1
                closing = self.pairs.get(opening)
                body = closing + 1 if closing is not None else end
                finish = self.pairs.get(body)
                if finish is not None:
                    cursor = finish + 1
                    continue
            if self.is_token(cursor, "=") and self.is_token(cursor + 1, ">"):
                first = cursor + 2
                if first in self.pairs and self.is_token(first, "{"):
                    cursor = self.pairs[first] + 1
                else:
                    cursor = first
                    while cursor < end and self.tokens[cursor].value not in {",", ";"}:
                        cursor = self.pairs.get(cursor, cursor) + 1
                continue
            if self.name(cursor) is not None and (cursor == start or not self.is_token(cursor - 1, ".")):
                opening = cursor + 1
                while self.is_token(opening, ".") and self.name(opening + 1) is not None:
                    opening += 2
                closing = self.pairs.get(opening)
                if self.is_token(opening, "(") and closing is not None:
                    if self.is_token(closing + 1, "{") and self.tokens[cursor].value not in {
                        "if",
                        "while",
                        "for",
                        "switch",
                        "catch",
                        "with",
                    }:
                        cursor = self.pairs.get(closing + 1, closing) + 1
                        continue  # an object/class method body is not invoked
                    self.bodies.add((self.tokens[cursor].start, self.tokens[opening].end))
                    if opening == cursor + 1:
                        self.select_callback(cursor, cursor + 1, self.tokens[cursor].start)
            cursor += 1

    def entry(self, start: int, end: int, before: int) -> None:
        definition = self.resolve(start, end, before)
        if definition is not None:
            if definition.function:
                self.select_callback(start, end, before)
                return
            if self.callback(*definition.value) is None and not self.stable(definition, descriptor=True):
                return
            start, end = definition.value
        callback = self.callback(start, end)
        if callback is not None:
            self.body(*callback)
            return
        call = self.call(start, end)
        if call is not None:
            self.bodies.add((self.tokens[start].start, self.tokens[call[0]].end))
            parts = self.parts(call[0] + 1, call[1])
            fields = self.fields(*parts[0]) if parts and len(parts) == 1 else None
        else:
            fields = self.fields(start, end)
        if fields and "execute" in fields:
            self.select_callback(*fields["execute"], before)

    def constructor_fields(self, span: tuple[int, int]) -> dict[str, tuple[int, int]] | None:
        start = self.positions.get(span[0])
        if start is None:
            return None
        end = bisect_right(self.ends, span[1])
        call = self.call(start, end)
        parts = self.parts(call[0] + 1, call[1]) if call is not None else None
        return self.fields(*parts[0]) if parts and len(parts) == 1 else None

    def constructor_entries(self, span: tuple[int, int]) -> list[tuple[int, int]]:
        fields = self.constructor_fields(span)
        if not fields or "tools" not in fields:
            return []
        first, last = fields["tools"]
        definition = self.resolve(first, last, span[0], collection=True)
        if definition is not None and not definition.function:
            first, last = definition.value
        if self.is_token(first, "[") and self.pairs.get(first) == last - 1:
            entries = self.parts(first + 1, last - 1)
        else:
            tools = self.fields(first, last)
            entries = list(tools.values()) if tools else None
        if entries is None or any(self.is_token(a, ".") for a, _ in entries):
            return []
        return entries

    def constructor(self, span: tuple[int, int]) -> None:
        for first, last in self.constructor_entries(span):
            if first < last:
                self.entry(first, last, span[0])

    def mcp(self, spans: list[tuple[int, int]]) -> None:
        servers: dict[str, _Definition] = {}
        for span in spans:
            for definition in self.definitions.values():
                first, last = definition.value
                # The source binder starts at the imported class, after new.
                call_start = first + int(self.is_token(first, "new"))
                if (
                    call_start < last
                    and self.tokens[call_start].start == span[0]
                    and self.tokens[last - 1].end == span[1]
                    and self.stable(definition, server=True)
                ):
                    servers[definition.name] = definition
        for position, token in enumerate(self.tokens):
            if not position % 256:
                pattern_timeout()
            server = servers.get(token.value) if not token.literal else None
            if server is None or not self.is_token(position + 1, "."):
                continue
            if not (self.is_token(position + 2, "registerTool") or self.is_token(position + 2, "tool")):
                continue
            opening = position + 3
            closing = self.pairs.get(opening)
            if closing is None or token.start <= self.tokens[server.value[1] - 1].end:
                continue
            parts = self.parts(opening + 1, closing)
            if parts is None or len(parts) < 2 or parts[0][1] - parts[0][0] != 1:
                continue
            name = self.tokens[parts[0][0]]
            if not (name.literal and name.value[:1] in {"'", '"'} and "\\" not in name.value):
                continue
            if any(self.is_token(first, ".") for first, _ in parts):
                continue
            self.select_callback(*parts[-1], token.start)


def javascript_tool_regions(
    text: str,
    ignored: list[tuple[int, int]],
    constructor_spans: list[tuple[int, int]],
    mcp_constructor_spans: list[tuple[int, int]],
) -> ToolRegions:
    """Resolve narrowly registered tool entries and MCP callbacks in this file."""
    if not constructor_spans and not mcp_constructor_spans:
        return ToolRegions()
    pieces: list[str] = []
    previous = 0
    for start, end in ignored:
        pieces.extend((text[previous:start], re.sub(r"[^\r\n]", " ", text[start:end])))
        previous = end
    pieces.append(text[previous:])
    masked = "".join(pieces)
    dead = javascript_dead_ranges(text, masked, ignored)
    starts = [start for start, _ in dead]
    tokens = []
    for token in _tokens(text, masked, ignored):
        branch = bisect_right(starts, token.start) - 1
        if branch < 0 or token.start >= dead[branch][1]:
            tokens.append(token)
    tools = _Tools(text, masked, tokens)
    for span in constructor_spans:
        fields = tools.constructor_fields(span)
        if fields and "tools" in fields:
            first, last = fields["tools"]
            if last - first == 1:
                tools.collection_references.add(tokens[first].start)
    for span in constructor_spans:
        for first, last in tools.constructor_entries(span):
            if last - first == 1:
                tools.entry_references.add(tokens[first].start)
    for span in constructor_spans:
        tools.constructor(span)
    tools.mcp(mcp_constructor_spans)
    return ToolRegions(tuple(sorted(tools.bodies)))
