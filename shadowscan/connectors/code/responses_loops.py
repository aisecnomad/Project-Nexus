"""Conservative source recognition of OpenAI Responses selected actions.

Only import-bound SDK calls can be supplied by the caller. Loop recognition
requires a repeating request, selection of a returned function call, dispatch
using its name/arguments, and ordered feedback to the same request input. The
separate single-action recognizer requires linked selection and dispatch in a
direct scope, and does not imply repetition or ordered model feedback.
This is static evidence and deliberately does not resolve helper functions or
dynamic control flow outside the supported direct loop structure.
"""

from __future__ import annotations

import ast

from shadowscan.connectors.code.provider_loops import _Budget as _ImportBudget
from shadowscan.connectors.code.provider_loops import _execution_sink, _imports
from shadowscan.signatures.matcher import MatchTimeoutError, pattern_timeout

MAX_FLOW_STEPS = 100_000
MAX_PATHS = 64


class _Budget:
    def __init__(self) -> None:
        self.steps = 0

    def tick(self, count: int = 1) -> None:
        self.steps += count
        if self.steps > MAX_FLOW_STEPS:
            raise MatchTimeoutError("Responses tool-loop analysis budget exceeded")
        if self.steps % 256 < count:
            pattern_timeout()


def _member(node: ast.AST | None, owner: str, name: str) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == name
            and isinstance(node.value, ast.Name) and node.value.id == owner)


def _assigned(statement: ast.stmt) -> tuple[str, ast.expr] | None:
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
        return statement.targets[0].id, statement.value
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.value is not None:
        return statement.target.id, statement.value
    return None


def _call(value: ast.expr) -> ast.Call | None:
    if isinstance(value, ast.Await):
        value = value.value
    return value if isinstance(value, ast.Call) else None


def _depends(node: ast.AST, item: str, attr: str, budget: _Budget) -> bool:
    for child in ast.walk(node):
        budget.tick()
        if _member(child, item, attr):
            return True
    return False


def _fields(value: ast.AST) -> dict[str, ast.expr]:
    if not isinstance(value, ast.Dict):
        return {}
    result: dict[str, ast.expr] = {}
    for key, field in zip(value.keys, value.values, strict=True):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str) or key.value in result:
            return {}
        result[key.value] = field
    return result


def _output(value: ast.AST, item: str, results: set[str], budget: _Budget) -> bool:
    fields = _fields(value)
    kind, call_id, content = fields.get("type"), fields.get("call_id"), fields.get("output")
    return (isinstance(kind, ast.Constant) and kind.value == "function_call_output"
            and _member(call_id, item, "call_id") and content is not None
            and any(isinstance(child, ast.Name) and child.id in results
                    for child in _walk(content, budget)))


def _walk(node: ast.AST, budget: _Budget):
    for child in ast.walk(node):
        budget.tick()
        yield child


def _type_guard(test: ast.AST, item: str) -> bool | None:
    """Evaluate a simple type guard for an item known to be a function call."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return None
    left, right = test.left, test.comparators[0]
    if _member(right, item, "type"):
        left, right = right, left
    if not (_member(left, item, "type") and isinstance(right, ast.Constant)
            and isinstance(right.value, str)):
        return None
    if isinstance(test.ops[0], ast.Eq):
        return right.value == "function_call"
    if isinstance(test.ops[0], ast.NotEq):
        return right.value != "function_call"
    return None


def _condition(test: ast.AST, item: str) -> tuple[str, bool] | bool | None:
    if isinstance(test, ast.Constant):
        return bool(test.value)
    known = _type_guard(test, item)
    if known is not None:
        return known
    if isinstance(test, ast.Name):
        return test.id, True
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and isinstance(test.operand, ast.Name):
        return test.operand.id, False
    # For unsupported predicates, keep either branch but never treat the
    # condition itself as evidence of dispatch or feedback.
    return None


def _paths(
    statements: list[ast.stmt], item: str, budget: _Budget, depth: int = 0,
    initial_facts: dict[str, bool] | None = None,
    finished: list[tuple[list[ast.stmt], dict[str, bool]]] | None = None,
):
    """Generate source-ordered reachable paths and correlate simple predicates.

    Paths ending in ``break``/``continue``/``return``/``raise`` are dropped.
    When ``finished`` is given, a path ending in ``return <value>`` is added
    to it, with the return statement last: its value runs before the path ends.
    """
    if depth > 64:
        raise MatchTimeoutError("Responses tool-loop branch-depth limit exceeded")
    paths: list[tuple[list[ast.stmt], dict[str, bool]]] = [([], dict(initial_facts or {}))]
    for statement in statements:
        budget.tick(len(paths))
        candidates: list[tuple[list[ast.stmt], dict[str, bool]]] = []
        for nodes, facts in paths:
            if isinstance(statement, ast.If):
                condition = _condition(statement.test, item)
                for truth, branch in ((True, statement.body), (False, statement.orelse)):
                    if isinstance(condition, bool) and truth != condition:
                        continue
                    branch_facts = facts.copy()
                    if isinstance(condition, tuple):
                        name, positive = condition
                        required = positive if truth else not positive
                        if name in facts and facts[name] != required:
                            continue
                        branch_facts[name] = required
                    branch_finished: list[tuple[list[ast.stmt], dict[str, bool]]] | None = (
                        [] if finished is not None else None
                    )
                    for branch_nodes, branch_conditions in _paths(
                        branch, item, budget, depth + 1, initial_facts=branch_facts, finished=branch_finished,
                    ):
                        candidates.append((nodes + branch_nodes, branch_conditions))
                    if finished is not None and branch_finished:
                        finished.extend((nodes + ended, ended_facts) for ended, ended_facts in branch_finished)
            elif isinstance(statement, (ast.Break, ast.Continue, ast.Return, ast.Raise)):
                if finished is not None and isinstance(statement, ast.Return) and statement.value is not None:
                    finished.append(([*nodes, statement], facts))
                continue
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With,
                                        ast.AsyncWith, ast.Match, ast.FunctionDef, ast.AsyncFunctionDef,
                                        ast.ClassDef)):
                # Nested scopes and unmodeled control flow cannot supply proof.
                candidates.append((nodes, facts))
            else:
                assignment = _assigned(statement)
                updated = facts.copy()
                if assignment:
                    updated.pop(assignment[0], None)
                candidates.append(([*nodes, statement], updated))
        if len(candidates) > MAX_PATHS:
            raise MatchTimeoutError("Responses tool-loop path limit exceeded")
        paths = candidates
        if not paths:
            break
    return paths


def _schema_names(tree: ast.AST, tools: ast.expr, budget: _Budget) -> set[str]:
    if isinstance(tools, ast.Name) and isinstance(tree, ast.Module):
        matches = [assigned[1] for stmt in tree.body if (assigned := _assigned(stmt))
                   and assigned[0] == tools.id]
        if len(matches) != 1:
            return set()
        tools = matches[0]
    if not isinstance(tools, (ast.List, ast.Tuple)):
        return set()
    names = set()
    for entry in tools.elts:
        budget.tick()
        fields = _fields(entry)
        kind, name = fields.get("type"), fields.get("name")
        if (isinstance(kind, ast.Constant) and kind.value == "function"
                and isinstance(name, ast.Constant) and isinstance(name.value, str)
                and name.value.isidentifier()):
            names.add(name.value)
    return names


def _sink_call(value: ast.expr) -> ast.Call | None:
    """Like ``_call`` but also unwraps trailing attribute access.

    ``subprocess.run(...).stdout`` and ``.decode()``-style chains are still the
    sink's own result; the model-selected arguments already reached the sink.
    """
    if isinstance(value, ast.Await):
        value = value.value
    while isinstance(value, ast.Attribute):
        value = value.value
    return value if isinstance(value, ast.Call) else None


def _is_declared_dispatch(func: ast.expr, item: str, handlers: set[str], static: set[str]) -> bool:
    """A callable bound to the tool-call dispatch table, keyed by ``item``'s name.

    Recognizes both the two-step handler lookup (``handler = FUNCTIONS[item.name]``
    then ``handler(...)``, already resolved into ``handlers``/``static``) and the
    equally common inline form, ``FUNCTIONS[item.name](...)``.
    """
    if isinstance(func, ast.Name):
        return func.id in handlers or func.id in static
    if isinstance(func, ast.Subscript):
        return _member(func.slice, item, "name")
    return False


def _has_feedback(
    path: list[ast.stmt], item: str, history: str, static: set[str],
    response_linked: bool, budget: _Budget, imports: dict[str, str],
) -> bool:
    handlers: set[str] = set()
    results: set[str] = set()
    outputs: set[str] = set()
    raw_call = response_linked
    static = static.copy()
    for statement in path:
        budget.tick()
        # Selection provenance ends if the current call or one of its fields
        # is overwritten before dispatch/feedback. A cached object with the
        # same attribute names is not evidence of model-selected execution.
        for node in _walk(statement, budget):
            if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                target: ast.AST = node
                while isinstance(target, (ast.Attribute, ast.Subscript)):
                    target = target.value
                if isinstance(target, ast.Name) and target.id == item:
                    return False
        assignment = _assigned(statement)
        if assignment:
            name, expression = assignment
            # A later assignment invalidates an earlier dispatch/result/output.
            handlers.discard(name)
            results.discard(name)
            outputs.discard(name)
            static.discard(name)
            call = _call(expression)
            # A dispatch call's own result may still be wrapped in an
            # attribute access (``subprocess.run(...).stdout``); recover the
            # underlying call for the sink/dispatch-table checks below while
            # still using ``call`` (never a wrapped one) for the ``.get()``
            # handler-lookup form, which is never itself called immediately.
            dispatch = call if call is not None else _sink_call(expression)
            if (isinstance(expression, ast.Subscript) and _member(expression.slice, item, "name")
                    or call is not None and isinstance(call.func, ast.Attribute) and call.func.attr == "get"
                    and any(_member(arg, item, "name") for arg in call.args)):
                handlers.add(name)
            elif (dispatch is not None
                  and (_is_declared_dispatch(dispatch.func, item, handlers, static)
                       or _execution_sink(dispatch.func, imports))
                  and any(_depends(arg, item, "arguments", budget) for arg in
                          [*dispatch.args, *(keyword.value for keyword in dispatch.keywords)])):
                results.add(name)
            elif _output(expression, item, results, budget):
                outputs.add(name)
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            continue
        call = statement.value
        if not (_member(call.func, history, "append") or _member(call.func, history, "extend")):
            continue
        if _member(call.func, history, "append") and len(call.args) == 1 and not call.keywords:
            if isinstance(call.args[0], ast.Name) and call.args[0].id == item:
                raw_call = True
            if ((isinstance(call.args[0], ast.Name) and call.args[0].id in outputs)
                    or _output(call.args[0], item, results, budget)) and raw_call:
                return True
        if _member(call.func, history, "extend") and len(call.args) == 1 and not call.keywords:
            sequence = call.args[0]
            if isinstance(sequence, (ast.List, ast.Tuple)):
                # extend preserves sequence order: an output before its call
                # does not establish valid conversation feedback.
                for part in sequence.elts:
                    if isinstance(part, ast.Name) and part.id == item:
                        raw_call = True
                    if raw_call and (isinstance(part, ast.Name) and part.id in outputs
                                     or _output(part, item, results, budget)):
                        return True
    return False


def _can_repeat(loop: ast.For | ast.AsyncFor | ast.While) -> bool:
    if isinstance(loop, ast.While):
        return not (isinstance(loop.test, ast.Constant) and not loop.test.value)
    source = loop.iter
    if isinstance(source, (ast.List, ast.Tuple, ast.Set)):
        return len(source.elts) > 1
    if (isinstance(source, ast.Call) and isinstance(source.func, ast.Name) and source.func.id == "range"
            and not source.keywords and 1 <= len(source.args) <= 3
            and all(isinstance(arg, ast.Constant) and type(arg.value) is int for arg in source.args)):
        try:
            values = [arg.value for arg in source.args if isinstance(arg, ast.Constant)
                      and type(arg.value) is int]
            return len(range(*values)) > 1
        except (OverflowError, ValueError):
            return True
    return True


def _history_rebound(loop: ast.AST, history: str, budget: _Budget) -> bool:
    for node in _walk(loop, budget):
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            target: ast.AST = node
            while isinstance(target, (ast.Attribute, ast.Subscript)):
                target = target.value
            if isinstance(target, ast.Name) and target.id == history:
                return True
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == history
                and node.func.attr not in {"append", "extend"}):
            return True
    return False


def _filter_list(value: ast.expr, response: str, budget: _Budget) -> bool:
    if not isinstance(value, ast.ListComp) or len(value.generators) != 1:
        return False
    generator = value.generators[0]
    budget.tick()
    return (isinstance(generator.target, ast.Name) and _member(generator.iter, response, "output")
            and isinstance(value.elt, ast.Name) and value.elt.id == generator.target.id
            and any(_type_guard(condition, generator.target.id) is True for condition in generator.ifs)
            and all(_condition(condition, generator.target.id) is not False for condition in generator.ifs))


def _continuations(
    statements: list[ast.stmt], facts: dict[str, bool], budget: _Budget, depth: int = 0,
) -> list[tuple[dict[str, bool], bool]]:
    """Keep only paths on which feedback can reach the next model request."""
    if depth > 64:
        raise MatchTimeoutError("Responses continuation branch-depth limit exceeded")
    paths = [(facts, False)]  # True means continue explicitly starts next turn.
    for statement in statements:
        budget.tick(len(paths))
        if isinstance(statement, ast.If):
            known = _condition(statement.test, "")
            alternatives: list[tuple[dict[str, bool], bool]] = []
            for current_facts, done in paths:
                if done:
                    alternatives.append((current_facts, done))
                    continue
                for truth, branch in ((True, statement.body), (False, statement.orelse)):
                    if isinstance(known, bool) and known != truth:
                        continue
                    next_facts = current_facts.copy()
                    if isinstance(known, tuple):
                        name, positive = known
                        required = positive if truth else not positive
                        if name in next_facts and next_facts[name] != required:
                            continue
                        next_facts[name] = required
                    alternatives.extend(_continuations(branch, next_facts, budget, depth + 1))
            paths = alternatives
        elif isinstance(statement, (ast.Return, ast.Break, ast.Raise)):
            paths = [path for path in paths if path[1]]
        elif isinstance(statement, ast.Continue):
            paths = [(current_facts, True) for current_facts, _ in paths]
        elif (assignment := _assigned(statement)) is not None:
            paths = [({key: value for key, value in current_facts.items() if key != assignment[0]}, done)
                     for current_facts, done in paths]
        if len(paths) > MAX_PATHS:
            raise MatchTimeoutError("Responses continuation path limit exceeded")
    return paths


def responses_tool_loop_lines(tree: ast.AST, request_calls: set[int]) -> list[int]:
    """Return lines for linked, import-verified Responses calls in repeatable loops."""
    if not request_calls:
        return []
    budget = _Budget()
    # A separate, one-off budget: this mirrors provider_loops.py's own
    # unconditional import resolution, bounded independently of the
    # loop-shape walk below.
    imports = _imports(tree, _ImportBudget())
    functions = {node.name for node in getattr(tree, "body", [])
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    found: set[int] = set()
    for loop in _walk(tree, budget):
        if not isinstance(loop, (ast.For, ast.AsyncFor, ast.While)) or not _can_repeat(loop):
            continue
        body = loop.body
        for position, statement in enumerate(body):
            budget.tick()
            assignment = _assigned(statement)
            if not assignment:
                continue
            response, expression = assignment
            request = _call(expression)
            if request is None or id(request) not in request_calls:
                continue
            options = {keyword.arg: keyword.value for keyword in request.keywords if keyword.arg}
            history, tools = options.get("input"), options.get("tools")
            if not isinstance(history, ast.Name) or tools is None:
                continue
            if not any(not continued for _, continued in _continuations(body[:position], {}, budget)):
                continue
            if isinstance(tools, ast.Constant) and not tools.value:
                continue
            if isinstance(tools, (ast.List, ast.Tuple, ast.Dict)) and not (
                tools.keys if isinstance(tools, ast.Dict) else tools.elts
            ):
                continue
            if _history_rebound(loop, history.id, budget):
                continue
            static = functions & _schema_names(tree, tools, budget)
            selected: set[str] = set()
            response_linked = False
            for selection_position, selection in enumerate(body[position + 1:], position + 1):
                budget.tick()
                if (isinstance(selection, ast.Expr) and isinstance(selection.value, ast.Call)
                        and _member(selection.value.func, history.id, "extend")
                        and len(selection.value.args) == 1 and not selection.value.keywords
                        and _member(selection.value.args[0], response, "output")):
                    response_linked = True
                bound = _assigned(selection)
                if bound:
                    selected.discard(bound[0])
                    if bound[0] == response:
                        break
                    if _filter_list(bound[1], response, budget):
                        selected.add(bound[0])
                if not isinstance(selection, (ast.For, ast.AsyncFor)) or not isinstance(selection.target, ast.Name):
                    continue
                item = selection.target.id
                direct = _member(selection.iter, response, "output")
                filtered = isinstance(selection.iter, ast.Name) and selection.iter.id in selected
                if not (direct or filtered):
                    continue
                if direct and not any(_type_guard(node.test, item) is not None
                                      for node in _walk(selection, budget) if isinstance(node, ast.If)):
                    continue
                # Carry reachable branch facts through the request and the
                # selection. Statements after break/continue cannot prove a
                # loop, nor can mutually exclusive branches supply its parts.
                prefixes = _continuations(body[:selection_position], {}, budget)
                if any(_has_feedback(path, item, history.id, static, response_linked, budget, imports)
                       and _continuations(body[selection_position + 1:], facts, budget)
                       for prefix_facts, continued in prefixes if not continued
                       for path, facts in _paths(selection.body, item, budget, initial_facts=prefix_facts)):
                    found.add(request.lineno)
                    break
    return sorted(found)


def _single_dispatch(path: list[ast.stmt], item: str, budget: _Budget) -> bool:
    """Prove selected-name dispatch, or argument dispatch with linked output.

    A single selected action is weaker than an iterative feedback loop. In
    particular, this does not confer autonomous/repeated-execution capability.
    """
    results: set[str] = set()
    for statement in path:
        for node in _walk(statement, budget):
            if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                target: ast.AST = node
                while isinstance(target, (ast.Attribute, ast.Subscript)):
                    target = target.value
                if isinstance(target, ast.Name) and target.id == item:
                    return False
        assignment = _assigned(statement)
        name: str | None = None
        expression: ast.expr | None = None
        if assignment:
            name, expression = assignment
            results.discard(name)
        elif isinstance(statement, (ast.Expr, ast.Return)) and statement.value is not None:
            # A registry dispatch need not keep its result: a bare call or a
            # returned call selects and runs the model's tool all the same.
            expression = statement.value
        call = _call(expression) if expression is not None else None
        if call is not None and any(
            _depends(arg, item, "arguments", budget)
            for arg in [*call.args, *(keyword.value for keyword in call.keywords)]
        ):
            if isinstance(call.func, ast.Subscript) and _member(call.func.slice, item, "name"):
                return True
            if (isinstance(call.func, ast.Call) and isinstance(call.func.func, ast.Attribute)
                    and call.func.func.attr == "get" and len(call.func.args) == 1
                    and not call.func.keywords and _member(call.func.args[0], item, "name")):
                return True
            if isinstance(call.func, ast.Name) and name is not None:
                # A fixed local handler needs result/call-id linkage too;
                # logging or printing selected arguments is insufficient.
                results.add(name)
                continue
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            call = statement.value
            if (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                    and call.func.attr == "append" and len(call.args) == 1 and not call.keywords
                    and _output(call.args[0], item, results, budget)):
                return True
    return False


def _dispatch_paths(
    body: list[ast.stmt], item: str, budget: _Budget, facts: dict[str, bool],
) -> list[tuple[list[ast.stmt], dict[str, bool]]]:
    """Reachable paths through one selection, including those returning a dispatch."""
    finished: list[tuple[list[ast.stmt], dict[str, bool]]] = []
    live = _paths(body, item, budget, initial_facts=facts, finished=finished)
    return [*live, *finished]


def responses_dispatch_lines(tree: ast.AST, request_calls: set[int]) -> list[int]:
    """Recognize one selected action in an import-bound, direct-scope flow.

    Support a request immediately followed by its response-output iteration
    (optionally through a function-call list filter). Keep this distinct from
    repeating requests: they must meet the stronger feedback-loop contract.
    Adjacent statements, identity-preserving filters and path analysis avoid
    joining unrelated functions, cached responses, dead branches or handlers.
    """
    if not request_calls:
        return []
    budget = _Budget()
    found: set[int] = set()
    for scope in _walk(tree, budget):
        if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = scope.body
        for position, statement in enumerate(body):
            assignment = _assigned(statement)
            if not assignment:
                continue
            response, expression = assignment
            request = _call(expression)
            if request is None or id(request) not in request_calls:
                continue
            options = {keyword.arg: keyword.value for keyword in request.keywords if keyword.arg}
            tools = options.get("tools")
            if tools is None or isinstance(tools, ast.Constant) and not tools.value:
                continue
            if isinstance(tools, (ast.List, ast.Tuple, ast.Dict)) and not (
                tools.keys if isinstance(tools, ast.Dict) else tools.elts
            ):
                continue
            cursor = position + 1
            selected: str | None = None
            if cursor < len(body) and (bound := _assigned(body[cursor])):
                if bound[0] != response and _filter_list(bound[1], response, budget):
                    selected = bound[0]
                    cursor += 1
            if cursor >= len(body):
                continue
            selection = body[cursor]
            if not isinstance(selection, (ast.For, ast.AsyncFor)) or not isinstance(selection.target, ast.Name):
                continue
            item = selection.target.id
            direct = _member(selection.iter, response, "output")
            filtered = selected is not None and isinstance(selection.iter, ast.Name) and selection.iter.id == selected
            if not (direct or filtered) or item in (response, selected):
                continue
            if direct and not any(_type_guard(node.test, item) is not None
                                  for node in _walk(selection, budget) if isinstance(node, ast.If)):
                continue
            # Reachability of the request is the expensive step: it runs only
            # for requests already followed by a selection over their output,
            # so long modules with many plain requests stay within budget.
            prefixes = _continuations(body[:position], {}, budget)
            if not prefixes:
                continue
            if any(_single_dispatch(path, item, budget)
                   for facts, continued in prefixes if not continued
                   for path, _ in _dispatch_paths(selection.body, item, budget, facts)):
                found.add(request.lineno)
    return sorted(found)
