"""Bounded, conservative recognition of Python OpenAI chat tool loops.

This is source evidence, never execution. A supported loop must request tools
through a resolved OpenAI client, iterate that response's tool calls, dispatch
to a declared tool name or a callable selected by the returned function name,
and append the dispatch result and matching call ID to the same message history.
Merely declaring schemas or transforming arguments does not qualify. Recognition
stays within direct statements in one loop and its
tool-call iteration; interprocedural flows, Responses API and other languages
remain supporting evidence until they have their own reviewed recognizers.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator

from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

MAX_FLOW_STEPS = 100_000


class _Budget:
    def __init__(self) -> None:
        self.steps = 0

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_FLOW_STEPS:
            raise MatchTimeoutError("provider tool-loop analysis budget exceeded")
        if self.steps % 256 == 0:
            pattern_timeout()

    def walk(self, node: ast.AST, *, nested_scopes: bool = False) -> Iterator[ast.AST]:
        pending = [node]
        while pending:
            item = pending.pop()
            self.tick()
            yield item
            if not nested_scopes and isinstance(item, (
                ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
            )):
                continue
            pending.extend(ast.iter_child_nodes(item))


def _unwrap(node: ast.AST) -> ast.AST:
    return node.value if isinstance(node, ast.Await) else node


def _root(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _value(node: ast.AST, values: dict[str, str]) -> str | None:
    node = _unwrap(node)
    if isinstance(node, ast.Name):
        return values.get(node.id)
    if isinstance(node, ast.Attribute):
        base = node.value
        if node.attr == "message" and isinstance(base, ast.Subscript):
            if (isinstance(base.slice, ast.Constant) and type(base.slice.value) is int
                    and base.slice.value == 0 and isinstance(base.value, ast.Attribute)
                    and base.value.attr == "choices" and _value(base.value.value, values) == "response"):
                return "message"
        parent = _value(base, values)
        if node.attr == "tool_calls" and parent == "message":
            return "calls"
        if node.attr == "function" and parent == "tool":
            return "function"
        if node.attr == "arguments" and parent == "function":
            return "arguments"
        if node.attr == "name" and parent == "function":
            return "function-name"
        if node.attr == "id" and parent == "tool":
            return "tool-id"
    if isinstance(node, ast.Subscript) and _value(node.slice, values) == "function-name":
        return "dispatcher"
    return None


def _depends(node: ast.AST, values: dict[str, str], kind: str, budget: _Budget) -> bool:
    return any(_value(part, values) == kind for part in budget.walk(node))


def _assignment(statement: ast.stmt) -> tuple[list[ast.expr], ast.expr | None]:
    if isinstance(statement, ast.Assign):
        return statement.targets, statement.value
    if isinstance(statement, ast.AnnAssign):
        return [statement.target], statement.value
    return [], None


def _invalidate(statement: ast.AST, values: dict[str, str], budget: _Budget) -> None:
    # Unknown branches/reassignments destroy proof instead of assuming that
    # related-looking names still refer to the selected response/tool/result.
    for item in budget.walk(statement):
        if isinstance(item, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(item.ctx, (ast.Store, ast.Del)):
            if root := _root(item):
                values.pop(root, None)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            values.pop(item.name, None)


def _assign(
    statement: ast.stmt, values: dict[str, str], budget: _Budget, *,
    dispatch: bool, declared_tools: set[str],
) -> None:
    targets, expression = _assignment(statement)
    kind = _value(expression, values) if expression is not None else None
    call = _unwrap(expression) if expression is not None else None
    if isinstance(call, ast.Call):
        name = call.func.id if isinstance(call.func, ast.Name) else call.func.attr if isinstance(call.func, ast.Attribute) else ""
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        if any(_depends(argument, values, "arguments", budget) for argument in arguments):
            target_is_tool = (
                isinstance(call.func, ast.Name) and call.func.id in declared_tools
                or _value(call.func, values) == "dispatcher"
            )
            if dispatch and target_is_tool:
                kind = "result"
            elif name in {"loads", "str", "bytes", "dict"}:
                kind = "arguments"
        elif any(_depends(argument, values, "result", budget) for argument in arguments) and name in {"dumps", "str", "repr"}:
            kind = "result"
    _invalidate(statement, values, budget)
    for target in targets:
        if kind and isinstance(target, ast.Name):
            values[target.id] = kind


def _feedback(statement: ast.stmt, history: str, values: dict[str, str], budget: _Budget) -> bool:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "append"
            and isinstance(call.func.value, ast.Name) and call.func.value.id == history
            and len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.Dict)):
        return False
    payload = call.args[0]
    if any(not isinstance(key, ast.Constant) or not isinstance(key.value, str) for key in payload.keys):
        return False
    pairs = {key.value: value for key, value in zip(payload.keys, payload.values, strict=True) if isinstance(key, ast.Constant)}
    if len(pairs) != len(payload.keys):
        return False
    role = pairs.get("role")
    return (
        isinstance(role, ast.Constant) and role.value == "tool"
        and "tool_call_id" in pairs and _value(pairs["tool_call_id"], values) == "tool-id"
        and "content" in pairs and _depends(pairs["content"], values, "result", budget)
    )


def _history_rebound(loop: ast.For | ast.While, history: str, budget: _Budget) -> bool:
    for node in budget.walk(loop):
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)) and _root(node) == history:
            return True
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == history
                and node.func.attr not in {"append", "extend"}):
            return True
    return False


def _declared_tools(expression: ast.expr, budget: _Budget) -> set[str]:
    """Read literal schemas only; unknown/dynamic schemas prove no tool names."""
    def fields(node: ast.AST) -> dict[str, ast.expr]:
        if not isinstance(node, ast.Dict):
            return {}
        result = {}
        for key, value in zip(node.keys, node.values, strict=True):
            budget.tick()
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str) or key.value in result:
                return {}
            result[key.value] = value
        return result

    names = set()
    if isinstance(expression, (ast.List, ast.Tuple)):
        for item in expression.elts:
            budget.tick()
            schema = fields(item)
            tool_type = schema.get("type")
            if isinstance(tool_type, ast.Constant) and tool_type.value == "function" and "function" in schema:
                name = fields(schema["function"]).get("name")
                if isinstance(name, ast.Constant) and isinstance(name.value, str) and name.value.isidentifier():
                    names.add(name.value)
    return names


def _request_loop(
    loop: ast.For | ast.While, statement_index: int, response: str, history: str,
    budget: _Budget, declared_tools: set[str],
) -> bool:
    values = {response: "response"}
    if _history_rebound(loop, history, budget):
        return False
    for statement in loop.body[statement_index + 1:]:
        budget.tick()
        if isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
            break
        if (isinstance(statement, ast.For) and isinstance(statement.target, ast.Name)
                and _value(statement.iter, values) == "calls"):
            local = values.copy()
            local[statement.target.id] = "tool"
            for action in statement.body:
                budget.tick()
                if isinstance(action, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
                    break
                if _feedback(action, history, local, budget):
                    return True
                _assign(action, local, budget, dispatch=True, declared_tools=declared_tools)
        _assign(statement, values, budget, dispatch=False, declared_tools=declared_tools)
    return False


def openai_tool_loop_lines(tree: ast.AST, request_calls: set[int]) -> list[int]:
    """Return request lines with the supported request/dispatch/feedback flow.

    ``request_calls`` contains only AST calls whose import-bound provenance is
    an OpenAI chat-completion client. This function cannot establish provenance
    from method spelling alone.
    """
    if not request_calls:
        return []
    budget = _Budget()
    lines: set[int] = set()
    for loop in budget.walk(tree, nested_scopes=True):
        if not isinstance(loop, (ast.For, ast.While)):
            continue
        if isinstance(loop, ast.While) and isinstance(loop.test, ast.Constant) and not loop.test.value:
            continue
        if isinstance(loop, ast.For) and isinstance(loop.iter, (ast.List, ast.Tuple)) and not loop.iter.elts:
            continue
        for number, statement in enumerate(loop.body):
            budget.tick()
            targets, expression = _assignment(statement)
            call = _unwrap(expression) if expression is not None else None
            if not (len(targets) == 1 and isinstance(targets[0], ast.Name)
                    and isinstance(call, ast.Call) and id(call) in request_calls):
                continue
            options = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
            history, tools = options.get("messages"), options.get("tools")
            if not isinstance(history, ast.Name) or tools is None:
                continue
            if isinstance(tools, ast.Constant) or isinstance(tools, (ast.List, ast.Tuple, ast.Dict)) and not (tools.keys if isinstance(tools, ast.Dict) else tools.elts):
                continue
            if _request_loop(loop, number, targets[0].id, history.id, budget, _declared_tools(tools, budget)):
                lines.add(call.lineno)
    return sorted(lines)
