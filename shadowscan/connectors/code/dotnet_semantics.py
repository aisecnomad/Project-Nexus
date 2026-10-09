"""Conservative Microsoft.Extensions.AI tool-loop proof for C# source.

Import/namespace aliases, typed parameters, local assignments and block scopes
bind the client, options and actual AIFunction objects. A tool definition alone
is supporting framework evidence. Only a function-invoking client receiving
known nonempty tools through a response call establishes an agent here. Dynamic
factories, fields and cross-file flows remain candidates, not proof; the
lexical UseFunctionInvocation signal covers them with corroboration.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass

from shadowscan.connectors.code.polyglot_bindings import (
    IDENTIFIER,
    MAX_CALLS,
    SourceTokens,
    source_tokens,
)
from shadowscan.signatures import Match, SignatureIndex
from shadowscan.signatures.loader import Signal
from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

_NAMESPACE = "Microsoft.Extensions.AI"
_TYPES = {
    "AIFunction",
    "AITool",
    "AIFunctionFactory",
    "ChatOptions",
    "ChatToolMode",
    "IChatClient",
    "FunctionInvokingChatClient",
    "ChatClientBuilder",
}
_RESPONSES = {"GetResponseAsync", "GetStreamingResponseAsync"}


@dataclass
class _Value:
    kind: str
    tools: bool = False
    automatic: bool = True
    collection: _Value | None = None


class _Proof:
    def __init__(self, source: SourceTokens):
        self.source = source
        self.words = source.words
        self.imports: dict[str, str] = {}
        self.import_tokens: set[int] = set()
        self.scopes: list[dict[str, _Value | None]] = [{}]
        self.calls = 0
        self._imports()
        self.dead, self.uncertain = self.control_ranges()
        self.dead_starts = [start for start, _ in self.dead]
        self.uncertain_starts = [start for start, _ in self.uncertain]

    @staticmethod
    def merged(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if result and start <= result[-1][1]:
                result[-1] = (result[-1][0], max(end, result[-1][1]))
            else:
                result.append((start, end))
        return result

    @staticmethod
    def inside(position: int, starts: list[int], ranges: list[tuple[int, int]]) -> bool:
        candidate = bisect_right(starts, position) - 1
        return candidate >= 0 and position < ranges[candidate][1]

    def control_ranges(self) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
        """Mark literal-false bodies and writes in unbraced control suites."""
        words, source = self.words, self.source
        dead: list[tuple[int, int]] = []
        uncertain: list[tuple[int, int]] = []
        for i, word in enumerate(words):
            if word not in {"if", "while", "for", "foreach", "else", "do"}:
                continue
            pattern_timeout()
            if word in {"else", "do"}:
                body, impossible = i + 1, False
            elif words[i + 1 : i + 2] == ["("] and i + 1 in source.pairs:
                close = source.pairs[i + 1]
                body = close + 1
                impossible = word in {"if", "while"} and words[i + 2 : close] in (["false"], ["0"])
            else:
                continue
            if body >= len(words):
                continue
            if words[body] == "{" and body in source.pairs:
                end = source.pairs[body] + 1
            else:
                cursor = body
                for _ in range(512):
                    if cursor >= len(words) or words[cursor] in {";", "}"}:
                        break
                    cursor = source.pairs.get(cursor, cursor) + 1
                else:
                    raise MatchTimeoutError("C# control statement proof budget exceeded")
                end = cursor + 1
                uncertain.append((body, end))
            if impossible:
                dead.append((body, end))
        return self.merged(dead), self.merged(uncertain)

    def _imports(self) -> None:
        words = self.words
        aliases: dict[str, str] = {}
        namespace = False
        declared = {
            words[i + 1]
            for i, word in enumerate(words[:-1])
            if word in {"class", "struct", "interface", "record", "enum"}
        }
        for i, word in enumerate(words):
            if word != "using":
                continue
            stop = next((j for j in range(i + 1, min(i + 32, len(words))) if words[j] == ";"), i)
            declaration = words[i + 1 : stop]
            if declaration == ["Microsoft", ".", "Extensions", ".", "AI"]:
                namespace = True
                self.import_tokens.update(range(i, stop + 1))
            elif len(declaration) > 2 and declaration[1] == "=":
                self.import_tokens.update(range(i, stop + 1))
                alias, target = declaration[0], "".join(declaration[2:])
                aliases[alias] = target if alias not in aliases else ""
        if namespace:
            self.imports.update({name: f"{_NAMESPACE}.{name}" for name in _TYPES - declared})
        for alias, target in aliases.items():
            self.imports.pop(alias, None)
            if target == _NAMESPACE or target.startswith(_NAMESPACE + "."):
                self.imports[alias] = target
        for name in declared:
            self.imports.pop(name, None)

    def lookup(self, name: str) -> _Value | None:
        return next((scope[name] for scope in reversed(self.scopes) if name in scope), None)

    def owner_scope(self, name: str) -> int:
        return next((i for i in reversed(range(len(self.scopes))) if name in self.scopes[i]), -1)

    def type_name(self, start: int) -> tuple[str, int]:
        path, end = self.source.path(start)
        root, _, tail = path.partition(".")
        if any(root in scope for scope in self.scopes):
            return "", end
        resolved = self.imports.get(root, root)
        if tail:
            resolved += "." + tail
        prefix = _NAMESPACE + "."
        result = resolved.removeprefix(prefix) if resolved.startswith(prefix) else ""
        return (result if result in _TYPES or result == "AIFunctionFactory.Create" else ""), end

    def expr(self, start: int, end: int, depth: int = 0) -> _Value | None:
        pattern_timeout()
        if depth > 24:
            raise MatchTimeoutError("C# import proof expression nesting budget exceeded")
        if start >= end:
            return None
        words, source = self.words, self.source
        if end - start == 1:
            return self.lookup(words[start])
        if words[start] == "(" and source.pairs.get(start) == end - 1:
            return self.expr(start + 1, end - 1, depth + 1)
        if words[start] == "[" and source.pairs.get(start) == end - 1:
            values = [self.expr(a, b, depth + 1) for a, b in source.args(start)]
            return _Value("tools", any(value is not None and value.kind == "tool" for value in values))
        if words[start] == "new":
            value = self.construct(start + 1, end, depth + 1)
            name, cursor = self.type_name(start + 1)
            if name in {"FunctionInvokingChatClient", "ChatClientBuilder"} and cursor in source.pairs:
                return self.chain(value, source.pairs[cursor] + 1, end)
            return value
        name, cursor = self.type_name(start)
        if name == "AIFunctionFactory.Create" and cursor < end and words[cursor] == "(":
            arguments = source.args(cursor)
            if arguments and words[arguments[0][0] : arguments[0][1]] != ["null"]:
                return _Value("tool")
        # The standard IChatClient.AsBuilder().UseFunctionInvocation().Build()
        # chain creates the same automatic loop as the explicit constructor.
        return self.chain(self.lookup(words[start]), start + 1, end)

    def chain(self, value: _Value | None, cursor: int, end: int) -> _Value | None:
        words, source = self.words, self.source
        if cursor == end:
            return value
        invoked = value is not None and value.kind == "invoker"
        builder = value is not None and value.kind == "builder"
        while value is not None and cursor + 2 < end and words[cursor] == ".":
            method, opening = words[cursor + 1], cursor + 2
            if words[opening] != "(" or opening not in source.pairs:
                return None
            if method == "AsBuilder" and value.kind in {"chat", "invoker"}:
                builder = True
            elif method == "UseFunctionInvocation" and builder:
                invoked = True
            elif method == "Build" and builder and invoked:
                value = _Value("invoker")
            else:
                return None
            cursor = source.pairs[opening] + 1
        return value if cursor == end and invoked and value is not None and value.kind == "invoker" else None

    def construct(self, start: int, end: int, depth: int) -> _Value | None:
        words, source = self.words, self.source
        name, cursor = self.type_name(start)
        if name in {"FunctionInvokingChatClient", "ChatClientBuilder"} and words[cursor : cursor + 1] == [
            "("
        ]:
            arguments = source.args(cursor)
            if not arguments or words[arguments[0][0] : arguments[0][1]] == ["null"]:
                return None
            return _Value("invoker" if name == "FunctionInvokingChatClient" else "builder")
        if name == "ChatOptions":
            if words[cursor : cursor + 1] == ["("]:
                cursor = source.pairs.get(cursor, cursor) + 1
            if words[cursor : cursor + 1] != ["{"]:
                return _Value("options")
            value = _Value("options")
            for a, b in source.args(cursor):
                if words[a : a + 2] == ["Tools", "="]:
                    tools = self.expr(a + 2, b, depth + 1)
                    value.collection = tools if tools is not None and tools.kind == "tools" else None
                elif words[a : a + 2] == ["ToolMode", "="]:
                    value.automatic = self.automatic_mode(a + 2, b)
            return value
        # Literal collections must contain actual AIFunctions, not tool schemas
        # or an unresolved field. Empty/null/disabled collections prove nothing.
        if words[start : start + 2] == ["[", "]"]:
            cursor = start + 2
        elif name in {"AIFunction", "AITool"} and words[cursor : cursor + 2] == ["[", "]"]:
            cursor += 2
        elif words[start : start + 2] == ["List", "<"]:
            element, after = self.type_name(start + 2)
            if element not in {"AIFunction", "AITool"} or words[after : after + 1] != [">"]:
                return None
            cursor = after + 1
            if words[cursor : cursor + 1] == ["("]:
                cursor = source.pairs.get(cursor, cursor) + 1
        else:
            return None
        if words[cursor : cursor + 1] != ["{"]:
            return None
        items = [self.expr(a, b, depth + 1) for a, b in source.args(cursor)]
        return _Value("tools", any(item is not None and item.kind == "tool" for item in items))

    def automatic_mode(self, start: int, end: int) -> bool:
        if self.words[start:end] == ["null"]:
            return True
        path, cursor = self.source.path(start)
        root, _, tail = path.partition(".")
        if any(root in scope for scope in self.scopes):
            return False
        resolved = self.imports.get(root, root)
        if tail:
            resolved += "." + tail
        return cursor == end and resolved in {
            f"{_NAMESPACE}.ChatToolMode.Auto",
            f"{_NAMESPACE}.ChatToolMode.RequireAny",
        }

    def parameters(self, opening: int) -> dict[str, _Value | None]:
        words, source = self.words, self.source
        if not opening or words[opening - 1] != ")":
            return {}
        parameters = source.reverse.get(opening - 1)
        if parameters is None:
            return {}
        result: dict[str, _Value | None] = {}
        for a, b in source.args(parameters):
            name, cursor = self.type_name(a)
            if cursor >= b or not IDENTIFIER.fullmatch(words[cursor]):
                continue
            kind = {
                "AIFunction": "tool",
                "IChatClient": "chat",
                "FunctionInvokingChatClient": "invoker",
            }.get(name)
            result[words[cursor]] = _Value(kind) if kind else None
        return result

    def assignment(self, position: int) -> None:
        words, source = self.words, self.source
        if not position or not IDENTIFIER.fullmatch(words[position - 1]):
            return
        end = cursor = position + 1
        while cursor < len(words) and words[cursor] not in {";", ",", "}"}:
            end = source.pairs.get(cursor, cursor) + 1
            cursor = end
        value = self.expr(position + 1, end)
        conditional = self.inside(position, self.uncertain_starts, self.uncertain)
        target = words[position - 1]
        if position >= 3 and words[position - 2] == ".":
            owner = self.owner_scope(words[position - 3])
            receiver = self.lookup(words[position - 3])
            if receiver is not None and receiver.kind == "options":
                if target == "Tools":
                    receiver.collection = (
                        value
                        if not conditional
                        and owner == len(self.scopes) - 1
                        and value is not None
                        and value.kind == "tools"
                        else None
                    )
                elif target == "ToolMode":
                    receiver.automatic = (
                        not conditional
                        and owner == len(self.scopes) - 1
                        and self.automatic_mode(position + 1, end)
                    )
            return
        # A declaration shadows its enclosing local; a plain assignment writes
        # that local. Nested/conditional writes cannot prove the final binding,
        # so invalidate the enclosing proof rather than discarding the write
        # when this block closes or promoting one possible branch outcome.
        preceding = words[position - 2] if position >= 2 else ""
        declared = bool(IDENTIFIER.fullmatch(preceding)) and preceding not in {
            "return",
            "await",
            "else",
            "do",
        }
        declared = declared or preceding in {">", "]"}
        owner = self.owner_scope(target)
        if declared or owner < 0 or owner == len(self.scopes) - 1:
            self.scopes[-1][target] = None if conditional else value
        else:
            self.scopes[owner][target] = None

    def dispatch(self, position: int) -> bool:
        words, source = self.words, self.source
        if position < 2 or words[position - 1] != "." or words[position + 1 : position + 2] != ["("]:
            return False
        # Options.Tools can name the exact collection whose mutation matters;
        # other member paths must not borrow an unrelated local's provenance.
        if position >= 3 and words[position - 3] == ".":
            owner = self.lookup(words[position - 4]) if position >= 4 else None
            receiver = (
                owner.collection
                if owner is not None and owner.kind == "options" and words[position - 2] == "Tools"
                else None
            )
        else:
            receiver = self.lookup(words[position - 2])
        if receiver is None:
            return False
        if words[position] in {"Clear", "Remove", "RemoveAt"} and receiver.kind == "tools":
            receiver.tools = False
            return False
        if receiver.kind != "invoker" or words[position] not in _RESPONSES:
            return False
        self.calls += 1
        if self.calls > MAX_CALLS:
            raise MatchTimeoutError("C# import proof call budget exceeded")
        args = source.args(position + 1)
        if len(args) < 2:
            return False
        a, b = args[1]
        if words[a : a + 2] == ["options", ":"]:
            a += 2
        options = self.expr(a, b)
        return (
            options is not None
            and options.kind == "options"
            and options.collection is not None
            and options.collection.tools
            and options.automatic
        )


def microsoft_tool_loop_matches(
    index: SignatureIndex, text: str, ignored: list[tuple[int, int]]
) -> list[Match]:
    signature = index.signatures.get("framework.microsoft-extensions-ai")
    if signature is None or not any(method in text for method in _RESPONSES):
        return []
    proof = _Proof(source_tokens(text, ignored, "C#"))
    result: list[Match] = []
    for i, word in enumerate(proof.words):
        if not i % 256:
            pattern_timeout()
        if i in proof.import_tokens:
            continue
        if proof.inside(i, proof.dead_starts, proof.dead):
            continue
        if word == "{":
            proof.scopes.append(proof.parameters(i))
        elif word == "}":
            if len(proof.scopes) > 1:
                proof.scopes.pop()
        elif word == "=":
            proof.assignment(i)
        elif word in _RESPONSES or word in {"Clear", "Remove", "RemoveAt"}:
            if proof.dispatch(i):
                result.append(
                    Match(
                        signature,
                        Signal(type="code", weight=0.9, agent_indicator=True, capabilities=["tool-use"]),
                        f"{_NAMESPACE}.FunctionInvokingChatClient:{word}(tools)",
                        0.9,
                        line=proof.source.line(i),
                        extra={"verified_agent": True, "source_capabilities": ["tool-use"]},
                    )
                )
    return result
