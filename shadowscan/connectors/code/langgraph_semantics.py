"""Bounded static recognition of a connected, model-directed LangGraph tool cycle.

StateGraph alone is a general workflow builder. This recognizer requires an
import-bound builder and ToolNode sharing nonempty tools with a bound chat
model, a node that returns its model response to state, tool-call-conditioned
routing, and a tool-to-model feedback edge. Unsupported dynamic shapes provide
no agent evidence. It never imports or executes scanned source.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum, auto

from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

MAX_FLOW_STEPS = 100_000
MAX_SEQUENCE_ITEMS = 4096
MAX_SEQUENCE_ALLOCATIONS = 16_384
_UNKNOWN = object()


class _Mark(Enum):
    STATE = auto()
    MESSAGES = auto()
    LAST = auto()
    CALLS = auto()
    TOOL = auto()


@dataclass(frozen=True)
class _Symbol:
    module: str
    name: str


@dataclass(frozen=True)
class _ChatModel:
    symbol: _Symbol


@dataclass(eq=False)
class _Sequence:
    items: list[object]
    invalid: bool = False


@dataclass(frozen=True)
class _Model:
    tools: _Sequence


@dataclass(frozen=True)
class _ToolNode:
    tools: _Sequence


@dataclass(frozen=True)
class _Response:
    tools: _Sequence


@dataclass(eq=False)
class _Function:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    closure: dict[str, object]


@dataclass(eq=False)
class _Graph:
    line: int
    nodes: dict[str, object] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)
    routes: list[tuple[str, object, dict[str, str]]] = field(default_factory=list)
    entry: str | None = None
    compiled: bool = False
    invalid: bool = False


def _label(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, _Symbol) and value.module.startswith("langgraph.graph"):
        return {"START": "__start__", "END": "__end__"}.get(value.name.split(".")[-1])
    return None


class _Analysis:
    def __init__(self, bound_calls: list[tuple[ast.Call, str, str]]) -> None:
        self.bound = {id(node): (module, symbol) for node, module, symbol in bound_calls}
        self.steps = 0
        self.sequence_allocations = 0
        self.lines: set[int] = set()

    def tick(self, count: int = 1) -> None:
        self.steps += count
        if self.steps > MAX_FLOW_STEPS:
            raise MatchTimeoutError("LangGraph analysis budget exceeded")
        if self.steps % 256 < count:
            pattern_timeout()

    def reserve_sequence(self, count: int, current: int) -> None:
        # Check before any append/extend: tiny source can otherwise double an
        # aliased sequence repeatedly and allocate exponential memory.
        if (current + count > MAX_SEQUENCE_ITEMS
                or self.sequence_allocations + count > MAX_SEQUENCE_ALLOCATIONS):
            raise MatchTimeoutError("LangGraph sequence allocation budget exceeded")
        self.sequence_allocations += count
        self.tick(count)

    def walk(self, node: ast.AST):
        pending = [node]
        while pending:
            self.tick()
            item = pending.pop()
            yield item
            if item is node or not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                pending.extend(ast.iter_child_nodes(item))

    def invalidate(self, value: object) -> None:
        if isinstance(value, (_Sequence, _Graph)):
            value.invalid = True

    def store(self, target: ast.AST, value: object, env: dict[str, object]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.store(item, _UNKNOWN, env)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            root = target.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                self.invalidate(env.get(root.id))
                env[root.id] = _UNKNOWN

    def expr(self, node: ast.AST | None, env: dict[str, object], presence: bool | None) -> object:
        self.tick()
        if isinstance(node, ast.Name):
            return env.get(node.id, _UNKNOWN)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Await):
            return self.expr(node.value, env, presence)
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value, env, presence)
            if isinstance(base, _Symbol):
                return _Symbol(base.module, ".".join(filter(None, (base.name, node.attr))))
            if base is _Mark.LAST and node.attr == "tool_calls":
                return _Mark.CALLS
        if isinstance(node, ast.Subscript):
            base = self.expr(node.value, env, presence)
            key = self.expr(node.slice, env, presence)
            if base is _Mark.STATE and key == "messages":
                return _Mark.MESSAGES
            if base is _Mark.MESSAGES and key == -1:
                return _Mark.LAST
        if isinstance(node, ast.UnaryOp):
            value = self.expr(node.operand, env, presence)
            if isinstance(node.op, ast.USub) and isinstance(value, int):
                return -value
            truth = self.truth(value, presence)
            if isinstance(node.op, ast.Not) and truth is not None:
                return not truth
        if isinstance(node, (ast.List, ast.Tuple)):
            flattened: list[object] = []
            messages_input = False
            for item in node.elts:
                value = self.expr(item.value if isinstance(item, ast.Starred) else item, env, presence)
                if isinstance(item, ast.Starred):
                    if value is _Mark.MESSAGES:
                        messages_input = True
                        continue
                    if not isinstance(value, _Sequence) or value.invalid:
                        return _UNKNOWN
                    self.reserve_sequence(len(value.items), len(flattened))
                    flattened.extend(value.items)
                else:
                    self.reserve_sequence(1, len(flattened))
                    flattened.append(value)
            return _Mark.MESSAGES if messages_input else _Sequence(flattened)
        if isinstance(node, ast.Dict):
            result: dict[str, object] = {}
            for key, value in zip(node.keys, node.values, strict=True):
                name = _label(self.expr(key, env, presence))
                if name is None or name in result:
                    return _UNKNOWN
                result[name] = self.expr(value, env, presence)
            return result
        if isinstance(node, ast.Call):
            return self.call(node, env, presence)
        return _UNKNOWN

    @staticmethod
    def truth(value: object, presence: bool | None) -> bool | None:
        if value is _Mark.CALLS:
            return presence
        if isinstance(value, (bool, int, str)) or value is None:
            return bool(value)
        return None

    @staticmethod
    def valid_tools(value: object) -> bool:
        return (isinstance(value, _Sequence) and bool(value.items) and not value.invalid
                and all(isinstance(item, (_Symbol, _Function)) or item is _Mark.TOOL
                        for item in value.items))

    @staticmethod
    def enabled_choice(kwargs: dict[str, object]) -> bool:
        # Recognize the default (omitted/None), automatic selection, or required
        # tool use. Dynamic settings and other provider-specific choices remain
        # unsupported; in particular they must not silently stand in for auto.
        value = kwargs.get("tool_choice")
        return value is None or isinstance(value, str) and value in {"auto", "required"}

    def call(self, node: ast.Call, env: dict[str, object], presence: bool | None) -> object:
        if any(keyword.arg is None for keyword in node.keywords):
            # Unpacking can replace tools, tool_choice, or state-field options.
            # Even a literal mapping is outside this deliberately small parser.
            if isinstance(node.func, ast.Attribute):
                self.invalidate(self.expr(node.func.value, env, presence))
            return _UNKNOWN
        function = self.expr(node.func, env, presence)
        args = [self.expr(arg, env, presence) for arg in node.args]
        kwargs = {arg.arg: self.expr(arg.value, env, presence) for arg in node.keywords if arg.arg}
        binding = self.bound.get(id(node))
        first = args[0] if args else kwargs.get("tools", _UNKNOWN)
        if isinstance(function, _Symbol) and binding == (function.module, function.name):
            full = f"{function.module}.{function.name}"
            if full in {"langgraph.graph.StateGraph", "langgraph.graph.state.StateGraph"}:
                return _Graph(node.lineno)
            if full in {"langgraph.prebuilt.ToolNode", "langgraph.prebuilt.tool_node.ToolNode"}:
                if (isinstance(first, _Sequence) and self.valid_tools(first)
                        and kwargs.get("messages_key", "messages") == "messages"):
                    return _ToolNode(first)
            if (function.module.startswith(("langchain_community.tools.", "langchain.tools."))
                    or function.module in {"langchain_community.tools", "langchain.tools"}) and function.name[:1].isupper():
                return _Mark.TOOL
            # Retain only imported chat-model constructors, never arbitrary
            # user objects exposing methods named bind_tools or invoke.
            if function.module.startswith("langchain") and function.name.split(".")[-1] in {
                "ChatOpenAI", "AzureChatOpenAI", "ChatAnthropic", "ChatGoogleGenerativeAI",
                "ChatVertexAI", "ChatBedrock", "ChatBedrockConverse", "ChatOllama", "ChatGroq", "ChatMistralAI",
            }:
                return _ChatModel(function)
        if isinstance(node.func, ast.Attribute):
            owner = self.expr(node.func.value, env, presence)
            method = node.func.attr
            if (method == "bind_tools" and isinstance(owner, _ChatModel) and binding is not None
                    and binding == (owner.symbol.module, f"{owner.symbol.name}.bind_tools")
                    and isinstance(first, _Sequence) and self.valid_tools(first)
                    and self.enabled_choice(kwargs)):
                return _Model(first)
            if isinstance(owner, _Model) and method in {"invoke", "ainvoke"}:
                if (first is _Mark.MESSAGES and not owner.tools.invalid
                        and self.enabled_choice(kwargs) and "tools" not in kwargs):
                    return _Response(owner.tools)
            if isinstance(owner, _Graph):
                if kwargs and method != "compile":
                    owner.invalid = True
                    return _UNKNOWN
                return self.graph_call(owner, method, args)
            self.invalidate(owner)
        return _UNKNOWN

    def graph_call(self, graph: _Graph, method: str, args: list[object]) -> object:
        if method == "compile":
            graph.compiled = True
            return graph
        labels = [_label(arg) for arg in args]
        if method == "add_node" and len(args) == 2 and labels[0] is not None:
            if labels[0] in graph.nodes:
                graph.invalid = True
            graph.nodes[labels[0]] = args[1]
        elif method == "set_entry_point" and len(args) == 1 and labels[0] is not None:
            graph.entry = labels[0]
        elif method == "add_edge" and len(args) == 2 and labels[0] is not None and labels[1] is not None:
            graph.edges.add((labels[0], labels[1]))
            if labels[0] == "__start__":
                graph.entry = labels[1]
        elif method == "add_conditional_edges" and len(args) in {2, 3} and labels[0] is not None:
            mapping = args[2] if len(args) == 3 else {"tools": "tools", "__end__": "__end__"}
            if isinstance(mapping, dict):
                routes = {str(key): _label(value) for key, value in mapping.items()}
                graph.routes.append((labels[0], args[1], {key: value for key, value in routes.items() if value is not None}))
            else:
                graph.invalid = True
        else:
            graph.invalid = True
        return graph

    def kill_unknown(self, node: ast.AST, env: dict[str, object]) -> None:
        for item in self.walk(node):
            if isinstance(item, ast.Name):
                self.invalidate(env.get(item.id))
                if isinstance(item.ctx, (ast.Store, ast.Del)):
                    env[item.id] = _UNKNOWN

    def run(self, body: list[ast.stmt], env: dict[str, object], presence: bool | None = None) -> tuple[bool, object]:
        for statement in body:
            self.tick()
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                for alias in statement.names:
                    if isinstance(statement, ast.Import):
                        env[alias.asname or alias.name.split(".")[0]] = _Symbol(alias.name if alias.asname else alias.name.split(".")[0], "")
                    else:
                        env[alias.asname or alias.name] = (_Symbol(statement.module or "", alias.name)
                                                         if not statement.level and alias.name != "*" else _UNKNOWN)
                        if alias.name == "*":
                            env.update(dict.fromkeys(env, _UNKNOWN))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                env[statement.name] = _Function(statement, env)
            elif isinstance(statement, ast.ClassDef):
                env[statement.name] = _UNKNOWN
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = self.expr(statement.value, env, presence)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    self.store(target, value, env)
            elif isinstance(statement, ast.Expr):
                self.expr(statement.value, env, presence)
            elif isinstance(statement, ast.Return):
                return True, self.expr(statement.value, env, presence)
            elif isinstance(statement, (ast.Raise, ast.Break, ast.Continue)):
                return True, _UNKNOWN
            elif isinstance(statement, ast.If):
                truth = self.truth(self.expr(statement.test, env, presence), presence)
                if truth is not None:
                    returned, value = self.run(statement.body if truth else statement.orelse, env, presence)
                    if returned:
                        return True, value
                    continue
                # Shared mutable builders under uncertain control flow cannot
                # establish which graph will actually be assembled.
                self.kill_unknown_graphs(statement, env)
                left, right = env.copy(), env.copy()
                lreturn, lvalue = self.run(statement.body, left, presence)
                rreturn, rvalue = self.run(statement.orelse, right, presence)
                if lreturn or rreturn:
                    return True, lvalue if lreturn and rreturn and lvalue == rvalue else _UNKNOWN
                env.update({name: left.get(name, _UNKNOWN) if left.get(name, _UNKNOWN) == right.get(name, _UNKNOWN)
                            else _UNKNOWN for name in left.keys() | right.keys()})
            elif not isinstance(statement, ast.Pass):
                self.kill_unknown(statement, env)
        return False, _UNKNOWN

    def kill_unknown_graphs(self, node: ast.AST, env: dict[str, object]) -> None:
        for item in self.walk(node):
            if isinstance(item, ast.Name) and isinstance(env.get(item.id), (_Graph, _Sequence)):
                self.invalidate(env[item.id])

    def function_env(self, function: _Function, state: bool = False) -> dict[str, object]:
        env = function.closure.copy()
        for item in self.walk(function.node):
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                env[item.id] = _UNKNOWN
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and item is not function.node:
                env[item.name] = _UNKNOWN
            elif isinstance(item, (ast.Import, ast.ImportFrom)):
                for alias in item.names:
                    env[alias.asname or alias.name.split(".")[0]] = _UNKNOWN
        arguments = function.node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        for arg in [*positional, *arguments.kwonlyargs, *([arguments.vararg] if arguments.vararg else []),
                    *([arguments.kwarg] if arguments.kwarg else [])]:
            env[arg.arg] = _UNKNOWN
        if state and positional:
            env[positional[0].arg] = _Mark.STATE
        return env

    def route(self, callback: object, presence: bool) -> str | None:
        if isinstance(callback, _Symbol):
            if (callback.module in {"langgraph.prebuilt", "langgraph.prebuilt.tool_node"}
                    and callback.name == "tools_condition"):
                return "tools" if presence else "__end__"
        if isinstance(callback, _Function) and not callback.node.decorator_list:
            _, value = self.run(callback.node.body, self.function_env(callback, state=True), presence)
            return _label(value)
        return None

    def model_tools(self, callback: object) -> _Sequence | None:
        if isinstance(callback, _Function) and not callback.node.decorator_list:
            _, value = self.run(callback.node.body, self.function_env(callback, state=True))
            if isinstance(value, dict):
                messages = value.get("messages")
                if isinstance(messages, _Sequence) and len(messages.items) == 1:
                    response = messages.items[0]
                    if isinstance(response, _Response) and not response.tools.invalid:
                        return response.tools
        return None

    def verified(self, graph: _Graph) -> bool:
        if graph.invalid or not graph.compiled:
            return False
        for start, callback, mapping in graph.routes:
            self.tick()
            target = mapping.get(self.route(callback, True) or "")
            stop = mapping.get(self.route(callback, False) or "")
            tool = graph.nodes.get(target or "")
            if (graph.entry == start and isinstance(tool, _ToolNode) and not tool.tools.invalid
                    and stop == "__end__" and (target, start) in graph.edges
                    and self.model_tools(graph.nodes.get(start)) is tool.tools):
                return True
        return False

    def scope(self, body: list[ast.stmt], env: dict[str, object]) -> None:
        self.run(body, env)
        for value in list(env.values()):
            if isinstance(value, _Graph) and self.verified(value):
                self.lines.add(value.line)
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function = env.get(statement.name)
                if isinstance(function, _Function) and function.node is statement and not statement.decorator_list:
                    self.scope(statement.body, self.function_env(function))


def langgraph_agent_lines(tree: ast.AST, bound_calls: list[tuple[ast.Call, str, str]]) -> set[int]:
    """Return StateGraph construction lines with static tool-cycle evidence.

    ``tree`` and calls must come from the caller's bounded import resolver,
    after local-module exclusions. This pass has its own operation/time budget;
    exhaustion raises MatchTimeoutError so the scan remains explicitly partial.
    """
    analysis = _Analysis(bound_calls)
    if isinstance(tree, ast.Module):
        analysis.scope(tree.body, {})
    return analysis.lines
