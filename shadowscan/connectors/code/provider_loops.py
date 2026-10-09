"""Bounded, conservative recognition of Python provider tool loops.

This is source evidence, never execution. A supported loop must request tools
through a resolved OpenAI chat-completion or Anthropic messages client, iterate
that response's tool calls (``message.tool_calls``) or content blocks
(``response.content``), dispatch to a declared tool name, a callable selected
by the returned tool name, or a process/code execution sink fed with the
model's arguments, and append the dispatch result and matching call ID to the
same message history (an OpenAI ``role: tool`` message or an Anthropic
``tool_result`` block, directly or through a collected results list). Merely
declaring schemas or transforming arguments does not qualify. The request may be
a plain call, a raw-response call whose ``.parse()`` result is used, a
streaming call whose ``get_final_message()`` / ``get_final_completion()``
result is used, or a call to a module function that returns such a request
with the history passed through a parameter. Recognition otherwise stays within
direct statements of one loop, its tool-call iteration and the ``if``
branches inside them; other interprocedural flows, the Responses API and
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
EXECUTION_SINKS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "os.system",
        "os.popen",
        "builtins.exec",
        "builtins.eval",
    }
)


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
            if not nested_scopes and isinstance(
                item,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
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
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "parse"
        and not node.args
        and not node.keywords
        and _value(node.func.value, values) == "raw-response"
    ):
        return "response"  # raw_response.parse() is the provider message
    if isinstance(node, ast.Name):
        return values.get(node.id)
    if isinstance(node, ast.Attribute):
        base = node.value
        if node.attr == "message" and isinstance(base, ast.Subscript):
            if (
                isinstance(base.slice, ast.Constant)
                and type(base.slice.value) is int
                and base.slice.value == 0
                and isinstance(base.value, ast.Attribute)
                and base.value.attr == "choices"
                and _value(base.value.value, values) == "response"
            ):
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
    if isinstance(node, ast.Subscript):
        if _value(node.slice, values) == "function-name":
            return "dispatcher"
        if (
            isinstance(node.slice, ast.Constant)
            and type(node.slice.value) is int
            and _value(node.value, values) == "calls"
        ):
            return "tool"  # message.tool_calls[0] is one selected call
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and len(node.args) == 1
        and not node.keywords
        and _value(node.args[0], values) == "function-name"
    ):
        return "dispatcher"  # registry.get(call.function.name)
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
    """Map imports that cannot be shadowed to their dotted targets.

    The provider request binder already rejects shadowed SDK clients. Sink
    provenance must be at least as strict: an imported ``subprocess`` can be
    replaced by a local dry-run object before the apparent dispatch.
    """
    names: dict[str, str] = {}
    bindings: dict[str, int] = {}

    def bound(name: str) -> None:
        bindings[name] = bindings.get(name, 0) + 1

    for node in budget.walk(tree, nested_scopes=True):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                bound(local)
                names[local] = alias.name if alias.asname else local
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                bound(local)
                if node.module and not node.level:
                    names[local] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound(node.id)
        elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if root := _root(node):
                bound(root)  # imported namespace or member was mutated
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound(node.name)
        elif isinstance(node, ast.arg):
            bound(node.arg)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            bound(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound(node.rest)
    for name, count in bindings.items():
        if count != 1:
            names.pop(name, None)
        if name in {"exec", "eval"} and name not in names:
            names[name] = ""  # a local binding shadows the builtin sink
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
        if (
            len(targets) == 1
            and isinstance(targets[0], ast.Name)
            and isinstance(value, (ast.List, ast.Tuple))
        ):
            literals[targets[0].id] = value
    return {name: value for name, value in literals.items() if bindings.get(name) == 1}


def _invalidate(statement: ast.AST, values: dict[str, str], budget: _Budget) -> None:
    # Unknown branches/reassignments destroy proof instead of assuming that
    # related-looking names still refer to the selected response/tool/result.
    for item in budget.walk(statement):
        if isinstance(item, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(
            item.ctx, (ast.Store, ast.Del)
        ):
            if root := _root(item):
                values.pop(root, None)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            values.pop(item.name, None)
        elif isinstance(item, ast.alias):
            values.pop(item.asname or item.name.split(".", 1)[0], None)  # `import cached as call`
        elif isinstance(item, ast.ExceptHandler) and item.name:
            values.pop(item.name, None)  # `except Exception as call:`


def _selected_tool(
    call: ast.Call, values: dict[str, str], declared_tools: set[str], imports: dict[str, str]
) -> bool:
    """The call runs a declared tool, the callable the model named, or an execution sink."""
    return (
        isinstance(call.func, ast.Name)
        and call.func.id in declared_tools
        or _value(call.func, values) == "dispatcher"
        or _execution_sink(call.func, imports)
    )


def _assign(
    statement: ast.stmt,
    values: dict[str, str],
    budget: _Budget,
    *,
    dispatch: bool,
    declared_tools: set[str],
    imports: dict[str, str],
    dispatch_calls: set[int] | None = None,
) -> None:
    targets, expression = _assignment(statement)
    kind = _value(expression, values) if expression is not None else None
    call = _unwrap(expression) if expression is not None else None
    while isinstance(call, ast.Attribute):
        call = call.value  # ``subprocess.run(...).stdout`` is still the sink's result
    if isinstance(call, ast.Call):
        name = (
            call.func.id
            if isinstance(call.func, ast.Name)
            else call.func.attr
            if isinstance(call.func, ast.Attribute)
            else ""
        )
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        if any(_depends(argument, values, "arguments", budget) for argument in arguments):
            if dispatch and _selected_tool(call, values, declared_tools, imports):
                kind = "result"
                if dispatch_calls is not None:
                    dispatch_calls.add(id(call))
            elif name in {"loads", "str", "bytes", "dict"}:
                kind = "arguments"
        elif any(_depends(argument, values, "result", budget) for argument in arguments) and name in {
            "dumps",
            "str",
            "repr",
        }:
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
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr in {"append", "extend"}
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == history
        and len(call.args) == 1
        and not call.keywords
    ):
        return call.func.attr, call.args[0]
    return None


def _tool_message(pairs: dict[str, ast.expr], values: dict[str, str], budget: _Budget) -> bool:
    """OpenAI feedback: ``{"role": "tool", "tool_call_id": <selected call>, "content": <its result>}``."""
    role = pairs.get("role")
    return (
        isinstance(role, ast.Constant)
        and role.value == "tool"
        and "tool_call_id" in pairs
        and _value(pairs["tool_call_id"], values) == "tool-id"
        and "content" in pairs
        and _depends(pairs["content"], values, "result", budget)
    )


def _tool_result_block(pairs: dict[str, ast.expr], values: dict[str, str], budget: _Budget) -> bool:
    """Anthropic feedback block: ``{"type": "tool_result", "tool_use_id": <block>, "content": <result>}``."""
    block_type = pairs.get("type")
    return (
        isinstance(block_type, ast.Constant)
        and block_type.value == "tool_result"
        and "tool_use_id" in pairs
        and _value(pairs["tool_use_id"], values) == "tool-id"
        and "content" in pairs
        and _depends(pairs["content"], values, "result", budget)
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
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "append"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id != history
        and len(call.args) == 1
        and not call.keywords
    ):
        return None
    pairs = _pairs(call.args[0])
    if pairs is not None and (
        _tool_message(pairs, values, budget) or _tool_result_block(pairs, values, budget)
    ):
        return call.func.value.id
    return None


def _history_rebound(loop: ast.For | ast.While, history: str, budget: _Budget) -> bool:
    for node in budget.walk(loop):
        if (
            isinstance(node, (ast.Name, ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and _root(node) == history
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == history
            and node.func.attr not in {"append", "extend"}
        ):
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
    body: list[ast.stmt],
    local: dict[str, str],
    history: str,
    budget: _Budget,
    declared_tools: set[str],
    imports: dict[str, str],
    collected: set[str],
    dispatch_calls: set[int],
) -> bool:
    for number, action in enumerate(body):
        budget.tick()
        if isinstance(action, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
            return False
        if isinstance(action, ast.If):
            if isinstance(action.test, ast.Constant):
                # A literal guard has exactly one reachable branch. Keep the
                # following statements on that same path so a guaranteed
                # break/return cannot turn later feedback into loop evidence.
                selected = action.body if bool(action.test.value) else action.orelse
                return _tool_iteration(
                    [*selected, *body[number + 1 :]],
                    local,
                    history,
                    budget,
                    declared_tools,
                    imports,
                    collected,
                    dispatch_calls,
                )
            # Branch-local proof: nothing bound inside a branch is trusted after it.
            for branch in (action.body, action.orelse):
                branch_calls = set(dispatch_calls)
                branch_collected: set[str] = set()
                proved = _tool_iteration(
                    branch,
                    local.copy(),
                    history,
                    budget,
                    declared_tools,
                    imports,
                    branch_collected,
                    branch_calls,
                )
                if proved or branch_collected:
                    dispatch_calls.update(branch_calls)
                    collected.update(branch_collected)
                if proved:
                    return True
        elif _feedback(action, history, local, budget):
            return True
        elif (results := _collected(action, history, local, budget)) is not None:
            collected.add(results)
        _assign(
            action,
            local,
            budget,
            dispatch=True,
            declared_tools=declared_tools,
            imports=imports,
            dispatch_calls=dispatch_calls,
        )
    return False


def _statements(
    statements: list[ast.stmt],
    values: dict[str, str],
    history: str,
    budget: _Budget,
    declared_tools: set[str],
    imports: dict[str, str],
    dispatch_calls: set[int],
) -> bool:
    for number, statement in enumerate(statements):
        budget.tick()
        if isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
            return False
        if isinstance(statement, ast.If):
            if isinstance(statement.test, ast.Constant):
                selected = statement.body if bool(statement.test.value) else statement.orelse
                return _statements(
                    [*selected, *statements[number + 1 :]],
                    values,
                    history,
                    budget,
                    declared_tools,
                    imports,
                    dispatch_calls,
                )
            for branch in (statement.body, statement.orelse):
                branch_calls = set(dispatch_calls)
                if _statements(branch, values.copy(), history, budget, declared_tools, imports, branch_calls):
                    dispatch_calls.update(branch_calls)
                    return True
        elif (
            isinstance(statement, ast.For)
            and isinstance(statement.target, ast.Name)
            and _value(statement.iter, values) == "calls"
        ):
            local = values.copy()
            local[statement.target.id] = "tool"
            collected: set[str] = set()
            selected_calls = set(dispatch_calls)
            if _tool_iteration(
                statement.body, local, history, budget, declared_tools, imports, collected, selected_calls
            ):
                dispatch_calls.update(selected_calls)
                return True
            _assign(statement, values, budget, dispatch=False, declared_tools=declared_tools, imports=imports)
            for name in collected:
                values[name] = "results"
            if collected:
                dispatch_calls.update(selected_calls)
            continue
        elif _feedback(statement, history, values, budget):
            return True
        _assign(statement, values, budget, dispatch=False, declared_tools=declared_tools, imports=imports)
    return False


def _request_loop(
    loop: ast.For | ast.While,
    following: list[ast.stmt],
    response: str,
    kind: str,
    history: str,
    budget: _Budget,
    declared_tools: set[str],
    imports: dict[str, str],
    dispatch_calls: set[int],
) -> bool:
    values = {response: kind}
    if _history_rebound(loop, history, budget):
        return False
    return _statements(following, values, history, budget, declared_tools, imports, dispatch_calls)


_RAW_METHOD = "with_raw_response"
_FINAL_MESSAGE = frozenset({"get_final_message", "get_final_completion"})


def _request_helpers(
    tree: ast.AST, request_calls: set[int], budget: _Budget
) -> dict[str, tuple[int | None, str, ast.expr, bool]]:
    """Functions defined once whose body returns a bound request.

    ``def call(messages): return client.messages.create(..., messages=messages, tools=TOOLS)``
    maps to (positional index, parameter name, tools expression, raw).
    """
    defined: dict[str, int] = {}
    helpers: dict[str, tuple[int | None, str, ast.expr, bool]] = {}
    for node in budget.walk(tree, nested_scopes=True):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        defined[node.name] = defined.get(node.name, 0) + 1
        returned = [
            statement.value
            for statement in node.body
            if isinstance(statement, ast.Return) and statement.value is not None
        ]
        if len(returned) != 1:
            continue
        call = _unwrap(returned[0])
        if not isinstance(call, ast.Call) or id(call) not in request_calls:
            continue
        options = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        history, tools = options.get("messages"), options.get("tools")
        parameters = [argument.arg for argument in (*node.args.posonlyargs, *node.args.args)]
        if (
            isinstance(history, ast.Name)
            and tools is not None
            and (history.id in parameters or history.id in {a.arg for a in node.args.kwonlyargs})
        ):
            position = parameters.index(history.id) if history.id in parameters else None
            helpers[node.name] = (position, history.id, tools, _RAW_METHOD in ast.unparse(call.func))
    return {name: helper for name, helper in helpers.items() if defined[name] == 1}


def _loop_request(
    statement: ast.stmt,
    request_calls: set[int],
    helpers: dict[str, tuple[int | None, str, ast.expr, bool]],
) -> tuple[ast.Call, str, str, ast.expr | None, ast.expr | None, list[ast.stmt]] | None:
    """(request call, response name, kind, history, tools, statements following in the same block)."""
    if isinstance(statement, (ast.With, ast.AsyncWith)) and len(statement.items) == 1:
        item = statement.items[0]
        opened = _unwrap(item.context_expr)
        if not (
            isinstance(opened, ast.Call)
            and id(opened) in request_calls
            and isinstance(item.optional_vars, ast.Name)
        ):
            return None
        stream = item.optional_vars.id
        for number, inner in enumerate(statement.body):
            targets, expression = _assignment(inner)
            final = _unwrap(expression) if expression is not None else None
            if (
                len(targets) == 1
                and isinstance(targets[0], ast.Name)
                and isinstance(final, ast.Call)
                and isinstance(final.func, ast.Attribute)
                and final.func.attr in _FINAL_MESSAGE
                and isinstance(final.func.value, ast.Name)
                and final.func.value.id == stream
            ):
                options = {keyword.arg: keyword.value for keyword in opened.keywords if keyword.arg}
                return (
                    opened,
                    targets[0].id,
                    "response",
                    options.get("messages"),
                    options.get("tools"),
                    statement.body[number + 1 :],
                )
        return None
    targets, expression = _assignment(statement)
    call = _unwrap(expression) if expression is not None else None
    if not (len(targets) == 1 and isinstance(targets[0], ast.Name) and isinstance(call, ast.Call)):
        return None
    if id(call) in request_calls:
        options = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        kind = "raw-response" if _RAW_METHOD in ast.unparse(call.func) else "response"
        return call, targets[0].id, kind, options.get("messages"), options.get("tools"), []
    if isinstance(call.func, ast.Name) and call.func.id in helpers:
        position, parameter, tools, raw = helpers[call.func.id]
        history: ast.expr | None = next(
            (keyword.value for keyword in call.keywords if keyword.arg == parameter), None
        )
        if history is None and position is not None and position < len(call.args):
            history = call.args[position]
        return call, targets[0].id, "raw-response" if raw else "response", history, tools, []
    return None


def provider_tool_loop_lines(
    tree: ast.AST, request_calls: set[int], *, dispatch_calls: set[int] | None = None
) -> list[int]:
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
    helpers = _request_helpers(tree, request_calls, budget)
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
            request = _loop_request(statement, request_calls, helpers)
            if request is None:
                continue
            call, response, kind, history, tools, inner = request
            if not isinstance(history, ast.Name) or tools is None:
                continue
            if isinstance(tools, ast.Name):
                tools = schemas.get(tools.id, tools)  # unresolved names prove no tool names
            if isinstance(tools, ast.Constant) or (
                isinstance(tools, (ast.List, ast.Tuple, ast.Dict))
                and not (tools.keys if isinstance(tools, ast.Dict) else tools.elts)
            ):
                continue
            following = [*inner, *loop.body[number + 1 :]]
            selected_calls: set[int] = set()
            if _request_loop(
                loop,
                following,
                response,
                kind,
                history.id,
                budget,
                _declared_tools(tools, budget),
                imports,
                selected_calls,
            ):
                lines.add(call.lineno)
                if dispatch_calls is not None:
                    dispatch_calls.update(selected_calls)
    return sorted(lines)


def _dispatches(
    statements: list[ast.stmt],
    values: dict[str, str],
    budget: _Budget,
    declared_tools: set[str],
    imports: dict[str, str],
    dispatch_calls: set[int],
    mentions: list[frozenset[str]] | None = None,
) -> bool:
    """Some reachable path through ``statements`` runs a tool the model selected.

    ``mentions`` holds the names each statement uses. A statement that uses
    none of the tracked names can neither dispatch the selection nor rebind
    it, so it is skipped without analysis unless it ends the path (a jump or a
    literal guard); the walk ends when no name is left.
    """
    for number, statement in enumerate(statements):
        if not values:
            return False
        if (
            mentions is not None
            and mentions[number].isdisjoint(values)
            and not isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise))
            and not (isinstance(statement, ast.If) and isinstance(statement.test, ast.Constant))
        ):
            continue  # a jump or a literal guard still ends the path
        budget.tick()
        if isinstance(statement, (ast.Expr, ast.Return)) and statement.value is not None:
            call = _unwrap(statement.value)
            if (
                isinstance(call, ast.Call)
                and any(
                    _depends(argument, values, "arguments", budget)
                    for argument in [*call.args, *(keyword.value for keyword in call.keywords)]
                )
                and _selected_tool(call, values, declared_tools, imports)
            ):
                dispatch_calls.add(id(call))
                return True  # a bare or returned dispatch runs the tool all the same
        if isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
            return False
        if isinstance(statement, ast.If) and isinstance(statement.test, ast.Constant):
            selected = statement.body if bool(statement.test.value) else statement.orelse
            following = [*selected, *statements[number + 1 :]]
            return _dispatches(following, values, budget, declared_tools, imports, dispatch_calls)
        branches: list[tuple[list[ast.stmt], dict[str, str]]] = []
        if isinstance(statement, ast.If):
            branches = [(statement.body, values.copy()), (statement.orelse, values.copy())]
        elif isinstance(statement, ast.Try):
            branches = [(statement.body, values.copy())]
        elif (
            isinstance(statement, (ast.For, ast.AsyncFor))
            and isinstance(statement.target, ast.Name)
            and _value(statement.iter, values) == "calls"
        ):
            local = values.copy()
            local[statement.target.id] = "tool"
            branches = [(statement.body, local)]
        if branches:
            for branch, local in branches:
                found: set[int] = set()
                if _dispatches(branch, local, budget, declared_tools, imports, found):
                    dispatch_calls.update(found)
                    return True
            _invalidate(statement, values, budget)  # nothing bound inside a branch is trusted after it
            continue
        found = set()
        _assign(
            statement,
            values,
            budget,
            dispatch=True,
            declared_tools=declared_tools,
            imports=imports,
            dispatch_calls=found,
        )
        if found:
            dispatch_calls.update(found)
            return True
    return False


def _reachable_blocks(tree: ast.AST, budget: _Budget) -> Iterator[list[ast.stmt]]:
    """Statement lists that can run: literal-false guards and empty literal loops are skipped."""
    pending: list[list[ast.stmt]] = [tree.body] if isinstance(tree, ast.Module) else []
    while pending:
        block = pending.pop()
        yield block
        for statement in block:
            budget.tick()
            if isinstance(statement, (ast.If, ast.While)) and isinstance(statement.test, ast.Constant):
                pending.append(statement.body if bool(statement.test.value) else statement.orelse)
            elif isinstance(statement, (ast.For, ast.AsyncFor)) and (
                isinstance(statement.iter, (ast.List, ast.Tuple)) and not statement.iter.elts
            ):
                pending.append(statement.orelse)
            else:
                for field in ("body", "orelse", "finalbody"):
                    inner = getattr(statement, field, None)
                    if isinstance(inner, list) and inner and isinstance(inner[0], ast.stmt):
                        pending.append(inner)
                for part in getattr(statement, "handlers", None) or getattr(statement, "cases", None) or []:
                    pending.append(part.body)
            if isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
                break  # what follows in this block never runs


def provider_tool_dispatch_lines(
    tree: ast.AST, request_calls: set[int], *, dispatch_calls: set[int] | None = None
) -> list[int]:
    """Return request lines whose selected tool call is executed, with or without feedback.

    This is rubric A2's minimum: the program sends tool definitions to an
    import-bound OpenAI chat-completion or Anthropic messages request and runs
    a call the model selected from its response, in the statements that follow
    the request in the same block. The target must be a tool the literal schema
    declares, the callable looked up by the returned tool name, or an execution
    sink fed with the model's arguments. Unlike ``provider_tool_loop_lines`` it
    proves neither repetition nor feedback, so it does not imply autonomy.
    """
    if not request_calls:
        return []
    budget = _Budget()
    if not any(
        isinstance(node, ast.Call)
        and id(node) in request_calls
        and any(keyword.arg == "tools" for keyword in node.keywords)
        for node in budget.walk(tree, nested_scopes=True)
    ):
        return []  # nothing offers tools: skip the whole-module analyses below
    imports = _imports(tree, budget)
    schemas = _schema_variables(tree, budget)
    helpers = _request_helpers(tree, request_calls, budget)
    lines: set[int] = set()

    def names(statement: ast.stmt) -> frozenset[str]:
        found = set()
        for node in budget.walk(statement, nested_scopes=True):
            if isinstance(node, ast.Name):
                found.add(node.id)
            elif isinstance(node, ast.alias):
                found.add(node.asname or node.name.split(".", 1)[0])
            elif isinstance(node, ast.ExceptHandler) and node.name:
                found.add(node.name)
        return frozenset(found)

    for block in _reachable_blocks(tree, budget):
        block_names: list[frozenset[str]] | None = None
        for number, statement in enumerate(block):
            budget.tick()
            if isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
                break
            request = _loop_request(statement, request_calls, helpers)
            if request is None:
                continue
            call, response, kind, _, tools, inner = request
            if tools is None:
                continue
            if isinstance(tools, ast.Name):
                tools = schemas.get(tools.id, tools)
            if isinstance(tools, ast.Constant) or (
                isinstance(tools, (ast.List, ast.Tuple, ast.Dict))
                and not (tools.keys if isinstance(tools, ast.Dict) else tools.elts)
            ):
                continue
            if block_names is None:
                block_names = [names(item) for item in block]  # once per block: linear, not per request
            selected: set[int] = set()
            if _dispatches(
                [*inner, *block[number + 1 :]],
                {response: kind},
                budget,
                _declared_tools(tools, budget),
                imports,
                selected,
                [*(names(item) for item in inner), *block_names[number + 1 :]],
            ):
                lines.add(call.lineno)
                if dispatch_calls is not None:
                    dispatch_calls.update(selected)
    return sorted(lines)
