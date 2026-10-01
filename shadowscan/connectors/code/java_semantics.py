"""Bounded proof for Spring ChatClient fields registering annotated tools.

This is deliberately not a Java type checker. Only an explicitly imported
ChatClient field and an unshadowed ``client.prompt(...).tools(...).call()``
chain count. External tool fields remain candidates until project evidence
resolves their exact class to imported @Tool methods. Scanned classes are
never loaded or executed.
"""

from __future__ import annotations

import re
from bisect import bisect_right

from shadowscan.signatures import Match, SignatureIndex
from shadowscan.signatures.loader import Signal
from shadowscan.signatures.matcher import MatchTimeoutError

_TOKEN = re.compile(r"[A-Za-z_$][\w$]*|->|[^\s]")
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*\Z")
_MAX_TOKENS = 50_000
_MAX_CLASSES = 128
_MAX_FIELDS = 32
_CLASS_WORDS = {"class", "interface", "record", "enum"}


def _structure(words: list[str]) -> tuple[dict[int, int], list[int]]:
    """Pair delimiters and retain brace depth in one bounded pass."""
    stack: list[tuple[str, int]] = []
    pairs: dict[int, int] = {}
    depths: list[int] = []
    depth = 0
    closing = {")": "(", "]": "[", "}": "{"}
    for i, word in enumerate(words):
        depths.append(depth)
        if word in {"(", "[", "{"}:
            stack.append((word, i))
            depth += word == "{"
        elif word in closing:
            if not stack or stack[-1][0] != closing[word]:
                return {}, []
            _, start = stack.pop()
            pairs[start] = i
            depth -= word == "}"
    return (pairs, depths) if not stack else ({}, [])


def _has_tool_method(
    words: list[str], pairs: dict[int, int], depths: list[int], start: int, end: int
) -> bool:
    for i in range(start + 1, end - 2):
        if depths[i] != 1 or words[i : i + 2] != ["@", "Tool"]:
            continue
        cursor = i + 2
        if words[cursor] == "(":
            cursor = pairs.get(cursor, end) + 1
        # A method declaration, rather than an annotated field or helper in
        # another class, must immediately follow the annotation.
        for token in range(cursor, min(cursor + 16, end)):
            if words[token] in {";", "=", "{"}:
                break
            if words[token] == "(":
                close = pairs.get(token, end)
                if close + 1 < end and words[close + 1] == "{":
                    return True
                break
    return False


def _chain_tool(words: list[str], pairs: dict[int, int], cursor: int, end: int) -> int | None:
    """Accept bounded request configuration and return the registered token."""
    if words[cursor : cursor + 3] != [".", "prompt", "("]:
        return None
    close = pairs.get(cursor + 2, end)
    if close - cursor > 32:
        return None
    cursor = close + 1
    for _ in range(4):
        if cursor + 3 >= end or words[cursor] != "." or words[cursor + 1] not in {"user", "system"}:
            break
        if words[cursor + 2] != "(":
            return None
        close = pairs.get(cursor + 2, end)
        if close - cursor > 128:
            return None
        cursor = close + 1
    if words[cursor : cursor + 3] != [".", "tools", "("]:
        return None
    tool = cursor + 3
    if not _IDENTIFIER.fullmatch(words[tool]) or words[tool + 1] != ")":
        return None
    cursor += 5
    for _ in range(4):
        if words[cursor : cursor + 3] != [".", "advisors", "("]:
            break
        close = pairs.get(cursor + 2, end)
        if close - cursor > 128:
            return None
        cursor = close + 1
    if words[cursor : cursor + 4] not in ([".", "call", "(", ")"], [".", "stream", "(", ")"]):
        return None
    return tool


def _has_import(name: str, module: str, imports: set[str], words: list[str]) -> bool:
    return (
        module in imports
        and not any(item.endswith("." + name) and item != module for item in imports)
        and not any(words[i] in _CLASS_WORDS and words[i + 1] == name for i in range(len(words) - 1))
    )


def _shadowed(words: list[str], name: str, start: int, end: int) -> bool:
    return any(
        words[j] == name
        and (
            (_IDENTIFIER.fullmatch(words[j - 1]) and words[j - 1] != "return")
            or words[j - 1] in {"]", ">", ","}
            or words[j - 3 : j] == [".", ".", "."]
            or words[j + 1] in {"->", "="}
        )
        for j in range(start, end)
    )


def spring_tool_registration_matches(
    index: SignatureIndex, text: str, ignored: list[tuple[int, int]]
) -> list[Match]:
    """Return annotated class declarations and typed tool-registration evidence."""
    signature = index.signatures.get("framework.spring-ai")
    if signature is None or ("ChatClient" not in text and "Tool" not in text):
        return []
    parts: list[str] = []
    last = 0
    for start, end in ignored:
        parts.extend((text[last:start], re.sub(r"[^\n]", " ", text[start:end])))
        last = end
    parts.append(text[last:])
    masked = "".join(parts)
    tokens: list[re.Match[str]] = []
    for token in _TOKEN.finditer(masked):
        if len(tokens) >= _MAX_TOKENS:
            raise MatchTimeoutError("Java tool registration token budget exceeded")
        tokens.append(token)
    words = [token.group() for token in tokens]
    pairs, depths = _structure(words)
    if not depths:
        return []
    imports: set[str] = set()
    package = ""
    for i, word in enumerate(words):
        if word in {"import", "package"} and depths[i] == 0:
            # Fixed-size import window; wildcard imports never establish types.
            stop = next((j for j in range(i + 1, min(i + 32, len(words))) if words[j] == ";"), i)
            value = "".join(words[i + 1 : stop])
            if word == "import":
                imports.add(value)
            else:
                package = value
    imported_client = _has_import(
        "ChatClient", "org.springframework.ai.chat.client.ChatClient", imports, words
    )
    imported_tool = _has_import("Tool", "org.springframework.ai.tool.annotation.Tool", imports, words)
    if not imported_client and not imported_tool:
        return []
    newlines = [i for i, char in enumerate(text) if char == "\n"]
    result: list[Match] = []
    classes = 0
    for i, word in enumerate(words):
        if word != "class" or depths[i] != 0:
            continue
        classes += 1
        if classes > _MAX_CLASSES:
            raise MatchTimeoutError("Java tool registration class budget exceeded")
        class_start = next((j for j in range(i + 1, min(i + 32, len(words))) if words[j] == "{"), None)
        if class_start is None or class_start not in pairs:
            continue
        if "<" in words[i + 1 : class_start]:
            continue  # generic type parameters may shadow the imported type
        end = pairs[class_start]
        qualified_class = ".".join(filter(None, (package, words[i + 1])))
        local_tools = imported_tool and _has_tool_method(words, pairs, depths, class_start, end)
        if local_tools:
            result.append(
                Match(
                    signature,
                    Signal(type="code", weight=0.9),
                    "Spring @Tool method declaration",
                    0.9,
                    line=bisect_right(newlines, tokens[i].start()) + 1,
                    extra={
                        "verified_agent": False,
                        "source_capabilities": [],
                        "java_tool_type": qualified_class,
                    },
                )
            )
        if not imported_client:
            continue
        # Method bodies are the depth-one braces after a method parameter
        # list. Skip nested type bodies and anonymous constructor bodies.
        nested: list[tuple[int, int]] = []
        nested_names: set[str] = set()
        for j in range(class_start + 1, end):
            if words[j] in _CLASS_WORDS and words[j - 1] != ".":
                nested_names.add(words[j + 1])
                if len(nested) >= _MAX_CLASSES:
                    raise MatchTimeoutError("Java nested type budget exceeded")
                opening = next((k for k in range(j + 1, min(j + 128, end)) if words[k] == "{"), None)
                if opening is not None and opening in pairs:
                    nested.append((j, pairs[opening]))
        reverse_pairs = {close: opening for opening, close in pairs.items()}
        lambda_names: set[str] = set()
        for j in range(class_start + 1, end):
            if words[j] == "->":
                if words[j - 1] == ")":
                    lambda_names.update(
                        word
                        for word in words[reverse_pairs[j - 1] + 1 : j - 1]
                        if _IDENTIFIER.fullmatch(word)
                    )
                else:
                    lambda_names.add(words[j - 1])
        methods: list[tuple[int, int, int]] = []
        for j in range(class_start + 1, end):
            if words[j] != "{" or depths[j] != 1 or words[j - 1] != ")":
                continue
            arguments = reverse_pairs[j - 1]
            if arguments < 2 or words[arguments - 2] == "new":
                continue
            if any(a <= j <= b for a, b in nested):
                continue
            methods.append((j, pairs[j], arguments + 1))
        method_starts = [start for start, _, _ in methods]
        typed_fields = {
            words[j + 1]: words[j]
            for j in range(class_start + 1, end - 2)
            if depths[j] == 1
            and _IDENTIFIER.fullmatch(words[j])
            and _IDENTIFIER.fullmatch(words[j + 1])
            and words[j + 2] == ";"
        }
        if len(typed_fields) > _MAX_FIELDS:
            raise MatchTimeoutError("Java tool registration field budget exceeded")
        null_fields = {
            words[k] for k in range(class_start + 1, end - 2) if words[k + 1 : k + 3] == ["=", "null"]
        }
        shadows: dict[tuple[int, str], bool] = {}
        fields = [
            j + 1
            for j in range(class_start + 1, end - 2)
            if depths[j] == 1
            and words[j] == "ChatClient"
            and _IDENTIFIER.fullmatch(words[j + 1])
            and words[j + 2] == ";"
        ]
        if len(fields) > _MAX_FIELDS:
            raise MatchTimeoutError("Java tool registration field budget exceeded")
        for field in fields:
            name = words[field]
            if name in lambda_names:
                continue
            occurrences = [j for j in range(class_start + 1, end) if words[j] == name]
            # Conservatively discard the field proof if a parameter, local
            # variable or lambda can shadow it. Explicit `this.field` remains
            # deferred as well, avoiding a partial scope-resolution model.
            if any(
                j != field
                and (
                    (_IDENTIFIER.fullmatch(words[j - 1]) and words[j - 1] != "return") or words[j + 1] == "->"
                )
                for j in occurrences
            ):
                continue
            for j in occurrences:
                if depths[j] != 2 or j == field or (words[j - 1] == "." and words[j - 2] != "this"):
                    continue
                method_index = bisect_right(method_starts, j) - 1
                if method_index < 0 or j >= methods[method_index][1]:
                    continue
                _, method_end, arguments = methods[method_index]
                receiver_key = (method_index, name)
                if receiver_key not in shadows:
                    shadows[receiver_key] = _shadowed(words, name, arguments, method_end)
                if shadows[receiver_key]:
                    continue
                tool = _chain_tool(words, pairs, j + 1, end)
                if tool is None:
                    continue
                tool_name = words[tool]
                verified = tool_name == "this" and local_tools
                tool_type = ""
                if tool_name != "this" and tool_name in typed_fields:
                    type_name = typed_fields[tool_name]
                    if type_name in nested_names or tool_name in null_fields or tool_name in lambda_names:
                        continue
                    imported_types = {item for item in imports if item.endswith("." + type_name)}
                    if len(imported_types) > 1:
                        continue
                    tool_type = next(iter(imported_types), ".".join(filter(None, (package, type_name))))
                    _, method_end, arguments = methods[method_index]
                    key = (method_index, tool_name)
                    if key not in shadows:
                        shadows[key] = _shadowed(words, tool_name, arguments, method_end)
                    if shadows[key]:
                        continue
                if not verified and not tool_type:
                    continue
                result.append(
                    Match(
                        signature,
                        Signal(type="code", weight=0.9),
                        "ChatClient.prompt().tools(typed tool).call()",
                        0.9,
                        line=bisect_right(newlines, tokens[j].start()) + 1,
                        extra={
                            "verified_agent": verified,
                            "source_capabilities": ["tool-use"] if verified else [],
                            "java_tool_registration_type": tool_type,
                        },
                    )
                )
    return result
