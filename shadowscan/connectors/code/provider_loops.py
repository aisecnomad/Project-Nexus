"""Bounded, conservative recognition of Python provider tool loops.

This is source evidence, never execution. A supported loop must request tools
through a resolved OpenAI chat-completion or Anthropic messages client, iterate
that response's tool calls (``message.tool_calls``) or content blocks
(``response.content``), dispatch to a declared tool name, a callable selected
by the returned tool name, or a process/code execution sink fed with the
model's arguments, and append the dispatch result and matching call ID to the
same message history (an OpenAI ``role: tool`` message or an Anthropic
``tool_result`` block, directly or through a collected results list). Merely
declaring schemas or transforming arguments does not qualify. Recognition
stays within direct statements of one loop, its tool-call iteration and the
``if`` branches inside them; interprocedural flows, the Responses API and
other languages remain supporting evidence until they have their own reviewed
recognizers.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator

from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

MAX_FLOW_STEPS = 100_000

# Calls that execute whatever the model selected: its tool input reaches a
# shell, a process or an interpreter. Names resolve through the module's imports.
EXECUTION_SINKS = frozenset({
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
    "subprocess.check_call", "os.system", "os.popen", "builtins.exec", "builtins.eval",
})


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
        if node.attr == "content" and parent == "response":
            return "calls"  # Anthropic content blocks carry the tool_use selections
        if node.attr == "function" and parent == "tool":
            return "function"
        if node.attr == "arguments" and parent == "function":
            return "arguments"
        if node.attr == "input" and parent == "tool":
            return "arguments"  # Anthropic tool_use block input
        if node.attr == "name" and parent in {"function", "tool"}:
            return "function-name"
        if node.attr == "id" and parent == "tool":
            return "tool-id"
    if isinstance(node, ast.Subscript) and _value(node.slice, values) == "function-name":
        return "dispatcher"
    return None


def _depends(node: ast.AST, values: dict[str, str], kind: str, budget: _Budget) -> bool:
    return any(_value(part, values) == kind for part in budget.walk(node))


def _assignment(statement: ast.AST) -> tuple[list[ast.expr], ast.expr | None]:
    if isinstance(statement, ast.Assign):
        return statement.targets, statement.value
    if isinstance(statement, ast.AnnAssign):
        return [statement.target], statement.value
    return [], None


def _pairs(node: ast.AST) -> dict[str, ast.expr] | None:
    """Constant string keys of a dict literal; None for any other shape."""
    if not isinstance(node, ast.Dict):
        return None
    pairs: dict[str, ast.expr] = {}
    for key, value in zip(node.keys, node.values, strict=True):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str) or key.value in pairs:
            return None
        pairs[key.value] = value
    return pairs


def _imports(tree: ast.AST, budget: _Budget) -> dict[str, str]:
    """Map local names to the dotted module or attribute they import."""
    names: dict[str, str] = {}
    for node in budget.walk(tree, nested_scopes=True):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".", 1)[0]] = alias.name if alias.asname else alias.name.split(".", 1)[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _execution_sink(func: ast.expr, imports: dict[str, str]) -> bool:
    if isinstance(func, ast.Name):
        target = imports.get(func.id, f"builtins.{func.id}" if func.id in {"exec", "eval"} else "")
        return target in EXECUTION_SINKS
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{imports.get(func.value.id, '')}.{func.attr}" in EXECUTION_SINKS
    return False


def _schema_variables(tree: ast.AST, budget: _Budget) -> dict[str, ast.expr]:
    """Names bound exactly once, to a literal list or tuple: a reusable tool schema."""
    literals: dict[str, ast.expr] = {}
    bindings: dict[str, int] = {}

    def bound(name: str) -> None:
        bindings[name] = bindings.get(name, 0) + 1

    for node in budget.walk(tree, nested_scopes=True):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound(node.name)
        elif isinstance(node, ast.arg):
            bound(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound(alias.asname or alias.name.split(".", 1)[0])
        targets, value = _assignment(node)
        if len(targets) == 1 and isinstance(targets[0], ast.Name) and isinstance(value, (ast.List, ast.Tuple)):
            literals[targets[0].id] = value
    return {name: value for name, value in literals.items() if bindings.get(name) == 1}


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
    dispatch: bool, declared_tools: set[str], imports: dict[str, str],
) -> None:
    targets, expression = _assignment(statement)
    kind = _value(expression, values) if expression is not None else None
    call = _unwrap(expression) if expression is not None else None
    while isinstance(call, ast.Attribute):
        call = call.value  # ``subprocess.run(...).stdout`` is still the sink's result
    if isinstance(call, ast.Call):
        name = call.func.id if isinstance(call.func, ast.Name) else call.func.attr if isinstance(call.func, ast.Attribute) else ""
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        if any(_depends(argument, values, "arguments", budget) for argument in arguments):
            target_is_tool = (
                isinstance(call.func, ast.Name) and call.func.id in declared_tools
                or _value(call.func, values) == "dispatcher"
                or _execution_sink(call.func, imports)
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


def _history_call(statement: ast.stmt, history: str) -> tuple[str, ast.expr] | None:
    """``history.append(x)`` / ``history.extend(x)`` with exactly one positional argument."""
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return None
    call = statement.value
    if (isinstance(call.func, ast.Attribute) and call.func.attr in {"append", "extend"}
            and isinstance(call.func.value, ast.Name) and call.func.value.id == history
            and len(call.args) == 1 and not call.keywords):
        return call.func.attr, call.args[0]
    return None


def _tool_message(pairs: dict[str, ast.expr], values: dict[str, str], budget: _Budget) -> bool:
    """OpenAI feedback: ``{"role": "tool", "tool_call_id": <selected call>, "content": <its result>}``."""
    role = pairs.get("role")
    return (
        isinstance(role, ast.Constant) and role.value == "tool"
        and "tool_call_id" in pairs and _value(pairs["tool_call_id"], values) == "tool-id"
        and "content" in pairs and _depends(pairs["content"], values, "result", budget)
    )


def _tool_result_block(pairs: dict[str, ast.expr], values: dict[str, str], budget: _Budget) -> bool:
    """Anthropic feedback block: ``{"type": "tool_result", "tool_use_id": <block>, "content": <result>}``."""
    block_type = pairs.get("type")
    return (
        isinstance(block_type, ast.Constant) and block_type.value == "tool_result"
        and "tool_use_id" in pairs and _value(pairs["tool_use_id"], values) == "tool-id"
        and "content" in pairs and _depends(pairs["content"], values, "result", budget)
    )


def _feedback(statement: ast.stmt, history: str, values: dict[str, str], budget: _Budget) -> bool:
    """The dispatch result, bound to the selected call ID, re-enters the request history."""
    appended = _history_call(statement, history)
    if appended is None:
        return False
    method, payload = appended
    if isinstance(payload, ast.Name):
        return values.get(payload.id) == "results"  # collected tool results, see _collected
    if method != "append":
        return False
    pairs = _pairs(payload)
    if pairs is None:
        return False
    if _tool_message(pairs, values, budget):
        return True
    role, content = pairs.get("role"), pairs.get("content")
    if not (isinstance(role, ast.Constant) and role.value == "user") or content is None:
        return False
    if isinstance(content, ast.Name):
        return values.get(content.id) == "results"
    if isinstance(content, (ast.List, ast.Tuple)):
        for item in content.elts:
            budget.tick()
            block = _pairs(item)
            if block is not None and _tool_result_block(block, values, budget):
                return True
    return False


def _collected(statement: ast.stmt, history: str, values: dict[str, str], budget: _Budget) -> str | None:
    """``results.append(<feedback for the selected call>)``: the list is fed back after the iteration."""
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return None
    call = statement.value
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "append"
            and isinstance(call.func.value, ast.Name) and call.func.value.id != history
            and len(call.args) == 1 and not call.keywords):
        return None
    pairs = _pairs(call.args[0])
    if pairs is not None and (_tool_message(pairs, values, budget) or _tool_result_block(pairs, values, budget)):
        return call.func.value.id
    return None


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
    names = set()
    if isinstance(expression, (ast.List, ast.Tuple)):
        for item in expression.elts:
            budget.tick()
            schema = _pairs(item) or {}
            tool_type = schema.get("type")
            name: ast.expr | None = None
            if isinstance(tool_type, ast.Constant) and tool_type.value == "function" and "function" in schema:
                name = (_pairs(schema["function"]) or {}).get("name")  # OpenAI function tool
            elif "input_schema" in schema:
                name = schema.get("name")  # Anthropic tool
            if isinstance(name, ast.Constant) and isinstance(name.value, str) and name.value.isidentifier():
                names.add(name.value)
    return names


def _tool_iteration(
    body: list[ast.stmt], local: dict[str, str], history: str, budget: _Budget,
    declared_tools: set[str], imports: dict[str, str], collected: set[str],
) -> bool:
    for action in body:
        budget.tick()
        if isinstance(action, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
            return False
        if isinstance(action, ast.If):
            # Branch-local proof: nothing bound inside a branch is trusted after it.
            if any(_tool_iteration(branch, local.copy(), history, budget, declared_tools, imports, collected)
                   for branch in (action.body, action.orelse)):
                return True
        elif _feedback(action, history, local, budget):
            return True
        elif (results := _collected(action, history, local, budget)) is not None:
            collected.add(results)
        _assign(action, local, budget, dispatch=True, declared_tools=declared_tools, imports=imports)
    return False


def _statements(
    statements: list[ast.stmt], values: dict[str, str], history: str, budget: _Budget,
    declared_tools: set[str], imports: dict[str, str],
) -> bool:
    for statement in statements:
        budget.tick()
        if isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
            return False
        if isinstance(statement, ast.If):
            if any(_statements(branch, values.copy(), history, budget, declared_tools, imports)
                   for branch in (statement.body, statement.orelse)):
                return True
        elif (isinstance(statement, ast.For) and isinstance(statement.target, ast.Name)
                and _value(statement.iter, values) == "calls"):
            local = values.copy()
            local[statement.target.id] = "tool"
            collected: set[str] = set()
            if _tool_iteration(statement.body, local, history, budget, declared_tools, imports, collected):
                return True
            _assign(statement, values, budget, dispatch=False, declared_tools=declared_tools, imports=imports)
            for name in collected:
                values[name] = "results"
            continue
        elif _feedback(statement, history, values, budget):
            return True
        _assign(statement, values, budget, dispatch=False, declared_tools=declared_tools, imports=imports)
    return False


def _request_loop(
    loop: ast.For | ast.While, statement_index: int, response: str, history: str,
    budget: _Budget, declared_tools: set[str], imports: dict[str, str],
) -> bool:
    values = {response: "response"}
    if _history_rebound(loop, history, budget):
        return False
    return _statements(loop.body[statement_index + 1:], values, history, budget, declared_tools, imports)


def provider_tool_loop_lines(tree: ast.AST, request_calls: set[int]) -> list[int]:
    """Return request lines with the supported request/dispatch/feedback flow.

    ``request_calls`` contains only AST calls whose import-bound provenance is
    an OpenAI chat-completion or Anthropic messages client. This function
    cannot establish provenance from method spelling alone.
    """
    if not request_calls:
        return []
    budget = _Budget()
    imports = _imports(tree, budget)
    schemas = _schema_variables(tree, budget)
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
            if isinstance(tools, ast.Name):
                tools = schemas.get(tools.id, tools)  # unresolved names prove no tool names
            if isinstance(tools, ast.Constant) or isinstance(tools, (ast.List, ast.Tuple, ast.Dict)) and not (tools.keys if isinstance(tools, ast.Dict) else tools.elts):
                continue
            if _request_loop(loop, number, targets[0].id, history.id, budget, _declared_tools(tools, budget), imports):
                lines.add(call.lineno)
    return sorted(lines)
