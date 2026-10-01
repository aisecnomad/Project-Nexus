"""Bounded proof for Spring ChatClient fields registering this class's tools.

This is deliberately not a Java type checker. Only an explicitly imported
ChatClient field in a non-nested class, a local @Tool method, and an unshadowed
``client.prompt(...).tools(this).call()`` chain count. Other receivers remain
lexical framework evidence. Scanned classes are never loaded or executed.
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


def _chain_end(words: list[str], pairs: dict[int, int], cursor: int, end: int) -> int | None:
    """Accept only prompt, optional user/system arguments, this-tools, call."""
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
        if close - cursor > 32:
            return None
        cursor = close + 1
    if words[cursor : cursor + 5] != [".", "tools", "(", "this", ")"]:
        return None
    cursor += 5
    if words[cursor : cursor + 4] not in ([".", "call", "(", ")"], [".", "stream", "(", ")"]):
        return None
    return cursor + 4


def spring_tool_registration_matches(
    index: SignatureIndex, text: str, ignored: list[tuple[int, int]]
) -> list[Match]:
    """Return evidence of same-class Spring tool registration on a typed field."""
    signature = index.signatures.get("framework.spring-ai")
    if signature is None or "ChatClient" not in text or "Tool" not in text or "tools" not in text:
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
    for i, word in enumerate(words):
        if word == "import" and depths[i] == 0:
            # Fixed-size import window; wildcard imports never establish types.
            stop = next((j for j in range(i + 1, min(i + 32, len(words))) if words[j] == ";"), i)
            imports.add("".join(words[i + 1 : stop]))
    for name, module in (
        ("ChatClient", "org.springframework.ai.chat.client.ChatClient"),
        ("Tool", "org.springframework.ai.tool.annotation.Tool"),
    ):
        if module not in imports or any(item.endswith("." + name) and item != module for item in imports):
            return []
        if any(words[i] in _CLASS_WORDS and words[i + 1] == name for i in range(len(words) - 1)):
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
        # Nested/anonymous classes change what `this` denotes. Defer them to
        # a future full JVM binder, even if the outer class contains tools.
        if any(words[j] in _CLASS_WORDS and words[j - 1] != "." for j in range(class_start + 1, end)):
            continue
        if not _has_tool_method(words, pairs, depths, class_start, end):
            continue
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
                if _chain_end(words, pairs, j + 1, end) is None:
                    continue
                result.append(
                    Match(
                        signature,
                        Signal(type="code", weight=0.9, agent_indicator=True, capabilities=["tool-use"]),
                        "ChatClient.prompt().tools(this).call()",
                        0.9,
                        line=bisect_right(newlines, tokens[j].start()) + 1,
                        extra={"verified_agent": True, "source_capabilities": ["tool-use"]},
                    )
                )
    return result
