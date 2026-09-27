"""Conservative recognition of inline Vercel SDK tool execution options.

Source strings/comments are already masked by the JavaScript lexer. Only a
complete inline options object with an enabled, nonempty tool map and an
explicit execution callback establishes model-selected dispatch. Dynamic
objects, unknown option spreads, duplicate properties and unknown tool choices
remain SDK usage evidence. A tool map spread invalidates earlier definitions;
explicit callbacks after it remain observable. No JavaScript is executed.
"""

from __future__ import annotations

import re

from shadowscan.signatures.matcher import pattern_timeout

_NAME = r"[A-Za-z_$][\w$]*"
_KEY = re.compile(rf"\s*({_NAME})\s*:")
_FUNCTION = re.compile(rf"\s*(?:async\s+)?function(?:\s+{_NAME})?\s*\([^()]*\)\s*")
_ARROW = re.compile(rf"\s*(?:async\b\s*)?(?:\([^()]*\)|{_NAME})\s*=>")
_METHOD = re.compile(r"\s*(?:async\s+)?execute\s*\([^()]*\)\s*\{")
_PAIRS = {"(": ")", "[": "]", "{": "}"}


def _parts(raw: str, masked: str) -> list[tuple[str, str]] | None:
    """Split on commas outside all bracket pairs, rejecting unbalanced input."""
    stack: list[str] = []
    result: list[tuple[str, str]] = []
    start = 0
    for offset, char in enumerate(masked):
        if offset % 256 == 0:
            pattern_timeout()
        if char in _PAIRS:
            stack.append(_PAIRS[char])
        elif char in _PAIRS.values():
            if not stack or stack.pop() != char:
                return None
        elif char == "," and not stack:
            result.append((raw[start:offset], masked[start:offset]))
            start = offset + 1
    if stack:
        return None
    if raw[start:].strip():
        result.append((raw[start:], masked[start:]))
    return result


def _unwrap(raw: str, masked: str, opening: str) -> tuple[str, str] | None:
    start = len(masked) - len(masked.lstrip())
    end = len(masked.rstrip())
    if start >= end or masked[start] != opening or masked[end - 1] != _PAIRS[opening]:
        return None
    inner = raw[start + 1:end - 1], masked[start + 1:end - 1]
    return inner if _parts(*inner) is not None else None


def _object(raw: str, masked: str, *, tool_map: bool = False) -> dict[str, tuple[str, str]] | None:
    inner = _unwrap(raw, masked, "{")
    if inner is None:
        return None
    fields: dict[str, tuple[str, str]] = {}
    for source, code in _parts(*inner) or []:
        if tool_map and re.fullmatch(rf"\s*\.\.\.\s*{_NAME}(?:\s*\.\s*{_NAME})*\s*", code):
            # The spread may override every preceding callback. Later explicit
            # properties override the spread and can supply dispatch evidence.
            fields.clear()
            continue
        match = _KEY.match(code)
        if match:
            key = match[1]
            value = source[match.end():], code[match.end():]
        elif _METHOD.match(code):
            key, value = "execute", (source, code)
        elif re.fullmatch(rf"\s*{_NAME}\s*", code):
            key, value = code.strip(), (source, code)
        else:
            # Quoted/computed keys, spreads and getters cannot
            # establish a stable execution policy through this narrow parser.
            return None
        if key in fields:
            return None
        fields[key] = value
    return fields


def _literal(raw: str) -> str | None:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] in {"'", '"'} and raw[-1] == raw[0] and "\\" not in raw[1:-1]:
        return raw[1:-1]
    return None


def _execution_callback(raw: str, masked: str) -> bool:
    """Recognize the entire callback value, not a function-valued prefix.

    A function expression followed by (), a member access or a binary operator
    can produce a noncallable value. A block arrow also ends at its closing brace.
    """
    function = _FUNCTION.match(masked)
    method = _METHOD.match(masked)
    if function is not None:
        start = function.end()
        return _unwrap(raw[start:], masked[start:], "{") is not None
    if method is not None:
        start = method.end() - 1
        return _unwrap(raw[start:], masked[start:], "{") is not None
    arrow = _ARROW.match(masked)
    if not arrow:
        return False
    body, code = raw[arrow.end():], masked[arrow.end():]
    if code.lstrip().startswith("{"):
        return _unwrap(body, code, "{") is not None
    # The remainder belongs to the arrow's expression body. A literal was
    # masked by the lexer and is also a valid expression body.
    return bool(code.strip()) or _literal(body) is not None


def has_executable_vercel_tools(arguments: str, masked: str, tool_factories: tuple[str, ...]) -> bool:
    """Whether a resolved generateText/streamText call can dispatch a tool."""
    inner = _unwrap(arguments, masked, "(")
    if inner is None:
        return False
    options = _object(*inner)
    if options is None or "tools" not in options:
        return False
    choice = options.get("toolChoice")
    if choice is not None and _literal(choice[0]) not in {"auto", "required"}:
        return False
    if "activeTools" in options and "experimental_activeTools" in options:
        return False
    active = options.get("activeTools", options.get("experimental_activeTools"))
    active_names: set[str] | None = None
    if active is not None:
        array = _unwrap(*active, "[")
        if array is None:
            return False
        values = [_literal(raw) for raw, _ in _parts(*array) or []]
        if not values or any(value is None for value in values):
            return False
        active_names = {value for value in values if value is not None}
    tools = _object(*options["tools"], tool_map=True)
    if not tools:
        return False
    for name, (raw, code) in tools.items():
        if active_names is not None and name not in active_names:
            continue
        definition = _object(raw, code)
        if definition is None:
            wrapper = re.match(rf"\s*({_NAME}(?:\s*\.\s*{_NAME})*)\s*", code)
            if wrapper is None or re.sub(r"\s", "", wrapper[1]) not in tool_factories:
                continue
            inner = _unwrap(raw[wrapper.end():], code[wrapper.end():], "(")
            definition = _object(*inner) if inner is not None else None
        if not definition or "execute" not in definition:
            continue
        if _execution_callback(*definition["execute"]):
            return True
    return False
