"""Conservative recognition of inline Vercel SDK tool execution options.

Source strings/comments are already masked by the JavaScript lexer. Only a
complete inline options object with an enabled, nonempty tool map and an
explicit execution callback establishes model-selected dispatch. Dynamic
objects, unknown option spreads, duplicate properties and unknown tool choices
remain SDK usage evidence. A tool map spread invalidates earlier definitions;
explicit callbacks after it remain observable. No JavaScript is executed.

A multi-step tool loop is the other agent shape: a stop condition past the
first step (``stopWhen``, or ``maxSteps`` before AI SDK 5) returns tool
results to the model until it stops calling tools. Its tools are usually
imported definitions, so only their presence and explicit disabling are read.
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
# Option values that leave an option at its default.
_UNSET = frozenset({"undefined", "null"})
# stepCountIs(1) (isStepCount in AI SDK 7) is the default: no step after a tool call.
_ONE_STEP = re.compile(rf"\s*(?:{_NAME}\s*\.\s*)?(?:stepCountIs|isStepCount)\s*\(\s*1\s*\)\s*")


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
    inner = raw[start + 1 : end - 1], masked[start + 1 : end - 1]
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
            value = source[match.end() :], code[match.end() :]
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
    body, code = raw[arrow.end() :], masked[arrow.end() :]
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
            inner = _unwrap(raw[wrapper.end() :], code[wrapper.end() :], "(")
            definition = _object(*inner) if inner is not None else None
        if not definition or "execute" not in definition:
            continue
        if _execution_callback(*definition["execute"]):
            return True
    return False


def _options(raw: str, masked: str) -> dict[str, tuple[str, str]] | None:
    """Return the plain and shorthand properties of an inline options object.

    Unlike ``_object``, members that cannot be the options read here (methods
    such as ``onFinish() {}``, quoted or computed keys) are skipped rather than
    rejected. A spread may override every earlier property and a repeated key
    is ambiguous, as in ``_object``.
    """
    inner = _unwrap(raw, masked, "{")
    if inner is None:
        return None
    fields: dict[str, tuple[str, str]] = {}
    for source, code in _parts(*inner) or []:
        if code.lstrip().startswith("..."):
            fields.clear()
            continue
        match = _KEY.match(code)
        if match:
            key, value = match[1], (source[match.end() :], code[match.end() :])
        elif re.fullmatch(rf"\s*{_NAME}\s*", code):
            key, value = code.strip(), (source, code)
        else:
            continue
        if key in fields:
            return None
        fields[key] = value
    return fields


def _set(options: dict[str, tuple[str, str]], key: str) -> str | None:
    """Return the masked value of an option that is present and not explicitly unset."""
    value = options.get(key)
    if value is None or value[1].strip() in _UNSET:
        return None
    return value[1]


def _continues_after_tools(options: dict[str, tuple[str, str]]) -> bool:
    """Whether a stop condition lets generation continue after a tool step."""
    stop = _set(options, "stopWhen")
    if stop is not None:
        # The default stops after the first step. A larger step count,
        # hasToolCall(...) or any other condition runs further steps.
        return _ONE_STEP.fullmatch(stop) is None
    steps = _set(options, "maxSteps")
    if steps is not None:
        # Compare the digits as text: a numeral can exceed what int() parses.
        count = re.fullmatch(r"\s*([0-9]+)\s*", steps)
        return count is None or count[1].lstrip("0") not in {"", "1"}
    return False


def has_vercel_tool_loop(arguments: str, masked: str) -> bool:
    """Whether a resolved generateText/streamText call runs a multi-step tool loop.

    The tool set may be any nonempty value, including imported tools whose
    execution callbacks live elsewhere. Explicitly disabled selection
    (``toolChoice: 'none'`` or an empty ``activeTools`` list) is not a loop;
    a dynamic choice or tool list may enable tools and still counts.
    """
    inner = _unwrap(arguments, masked, "(")
    options = _options(*inner) if inner is not None else None
    if options is None or not _continues_after_tools(options):
        return False
    tools = _set(options, "tools")
    if tools is None or re.fullmatch(r"\s*\{\s*\}\s*", tools):
        return False
    choice = options.get("toolChoice")
    if choice is not None and _literal(choice[0]) == "none":
        return False
    for key in ("activeTools", "experimental_activeTools"):
        active = options.get(key)
        array = _unwrap(*active, "[") if active is not None else None
        if array is not None and not _parts(*array):
            return False
    return True
