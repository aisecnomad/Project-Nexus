"""Bounded recognition of a direct JavaScript Responses dispatch.

This deliberately accepts a small, complete top-level program: imports, a
constant SDK client, an awaited Responses request with simple options, and a
guarded dispatch over that response's output. It establishes a single dispatch,
not an iterative agent loop or execution at runtime. Extra statements, nested
scopes, mutations, templates and dynamic options cannot supply proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

MAX_TOKENS = 50_000
_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+(?:\.[0-9]+)?|===|==|[{}()\[\].,:;=]")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_CONSTRUCTORS = frozenset({"default", "OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI"})
_RESERVED = frozenset({
    "await", "break", "case", "catch", "class", "const", "continue", "debugger", "default",
    "delete", "do", "else", "enum", "export", "extends", "false", "finally", "for", "function",
    "if", "implements", "import", "in", "instanceof", "interface", "let", "new", "null",
    "package", "private", "protected", "public", "return", "static", "super", "switch", "this",
    "throw", "true", "try", "typeof", "var", "void", "while", "with", "yield", "undefined",
})


@dataclass(frozen=True)
class _Token:
    value: str
    line: int
    literal: bool = False


def _tokens(text: str, ignored: list[tuple[int, int]]) -> list[_Token] | None:
    """Retain complete ordinary strings, discard comments, reject other literals."""
    result: list[_Token] = []
    spans = iter(ignored)
    span = next(spans, None)
    offset, line = 0, 1
    while offset < len(text):
        if len(result) >= MAX_TOKENS:
            raise MatchTimeoutError("JavaScript Responses dispatch token limit exceeded")
        if offset % 256 == 0:
            pattern_timeout()
        if span is not None and offset == span[0]:
            value = text[span[0]:span[1]]
            if value.startswith("//") or value.startswith("/*") and value.endswith("*/"):
                pass
            elif (len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]
                  and "\\" not in value and "\n" not in value and "\r" not in value):
                result.append(_Token(value[1:-1], line, literal=True))
            else:
                return None
            line += value.count("\n")
            offset = span[1]
            span = next(spans, None)
            continue
        character = text[offset]
        if character in " \t\r\n":
            line += character == "\n"
            offset += 1
            continue
        match = _TOKEN.match(text, offset)
        if match is None:
            return None
        result.append(_Token(match.group(), line))
        offset = match.end()
    return result


class _Unsupported(ValueError):
    pass


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.position = 0

    def peek(self, value: str) -> bool:
        return (self.position < len(self.tokens) and not self.tokens[self.position].literal
                and self.tokens[self.position].value == value)

    def take(self, value: str) -> None:
        if not self.peek(value):
            raise _Unsupported
        self.position += 1

    def token(self) -> _Token:
        if self.position >= len(self.tokens):
            raise _Unsupported
        result = self.tokens[self.position]
        self.position += 1
        return result

    def identifier(self) -> str:
        token = self.token()
        if token.literal or not _IDENTIFIER.fullmatch(token.value) or token.value in _RESERVED:
            raise _Unsupported
        return token.value

    def literal(self) -> str:
        token = self.token()
        if not token.literal:
            raise _Unsupported
        return token.value

    def imports(self) -> tuple[set[str], set[str]]:
        names: set[str] = set()
        constructors: set[str] = set()
        while self.peek("import"):
            self.take("import")
            exports: list[tuple[str, str]] = []
            if not self.peek("{"):
                exports.append(("default", self.identifier()))
                if self.peek(","):
                    self.take(",")
                else:
                    self.take("from")
                    module = self.literal()
                    self.take(";")
                    symbol, name = exports[0]
                    if name in names:
                        raise _Unsupported
                    names.add(name)
                    if module == "openai":
                        constructors.add(name)
                    continue
            self.take("{")
            while not self.peek("}"):
                symbol = self.identifier()
                name = symbol
                if self.peek("as"):
                    self.take("as")
                    name = self.identifier()
                exports.append((symbol, name))
                if not self.peek(","):
                    break
                self.take(",")
            self.take("}")
            self.take("from")
            module = self.literal()
            self.take(";")
            for symbol, name in exports:
                if name in names:
                    raise _Unsupported
                names.add(name)
                if module == "openai" and symbol in _CONSTRUCTORS:
                    constructors.add(name)
        return names, constructors

    def options(self) -> dict[str, _Token]:
        """Simple scalar/name options exclude executable or computed expressions."""
        result: dict[str, _Token] = {}
        self.take("{")
        while not self.peek("}"):
            key = self.identifier()
            if key in result:
                raise _Unsupported
            self.take(":")
            value = self.token()
            if not (value.literal or _IDENTIFIER.fullmatch(value.value)
                    or re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value.value)):
                raise _Unsupported
            if not value.literal and value.value in _RESERVED - {"true", "false", "null", "undefined"}:
                raise _Unsupported
            result[key] = value
            if not self.peek(","):
                break
            self.take(",")
        self.take("}")
        return result

    def declaration(self) -> str:
        self.take("const")
        name = self.identifier()
        self.take("=")
        return name

    def recognize(self, constructor_lines: set[int]) -> int:
        imported, constructors = self.imports()
        client = self.declaration()
        self.take("new")
        constructor = self.token()
        if constructor.literal or constructor.value not in constructors or constructor.line not in constructor_lines:
            raise _Unsupported
        self.take("(")
        if self.peek("{"):
            self.options()
        self.take(")")
        self.take(";")

        response = self.declaration()
        self.take("await")
        request_line = self.tokens[self.position].line if self.position < len(self.tokens) else 0
        for value in (client, ".", "responses", ".", "create", "("):
            self.take(value)
        options = self.options()
        tools = options.get("tools")
        if tools is None or tools.literal or not _IDENTIFIER.fullmatch(tools.value) or tools.value in _RESERVED:
            raise _Unsupported
        self.take(")")
        self.take(";")

        for value in ("for", "(", "const"):
            self.take(value)
        item = self.identifier()
        for value in ("of", response, ".", "output", ")", "{", "if", "(", item, ".", "type"):
            self.take(value)
        self.take("===" if self.peek("===") else "==")
        if self.literal() != "function_call":
            raise _Unsupported
        self.take(")")
        self.take("{")
        result = self.declaration() if self.peek("const") else None
        if self.peek("await"):
            self.take("await")
        registry = self.identifier()
        for value in ("[", item, ".", "name", "]", "(", item, ".", "arguments", ")", ";", "}", "}"):
            self.take(value)
        if self.position != len(self.tokens):
            raise _Unsupported
        # Reject invalid redeclarations and names whose meanings would be
        # shadowed by the client, response, item or optional result binding.
        locals_ = [client, response, item, *([result] if result else [])]
        if len(set(locals_)) != len(locals_) or set(locals_) & (imported | {registry, tools.value}):
            raise _Unsupported
        return request_line


def javascript_responses_dispatch_lines(
    text: str, ignored: list[tuple[int, int]], constructor_lines: set[int],
) -> list[int]:
    """Return a request line only for the supported, import-bound direct flow.

    ``ignored`` comes from ``noncode_ranges``. ``constructor_lines`` contains
    only OpenAI SDK constructor calls resolved by the caller's import analysis.
    The complete source must match the supported grammar; no file-wide keyword
    co-occurrence can establish dispatch evidence.
    """
    if not constructor_lines:
        return []
    tokens = _tokens(text, ignored)
    if tokens is None:
        return []
    try:
        return [_Parser(tokens).recognize(constructor_lines)]
    except _Unsupported:
        return []
