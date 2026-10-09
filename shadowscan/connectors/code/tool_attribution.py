"""Narrow connections between Python agent registrations and local tool bodies.

This is a static registration check, not an execution attestation or general
call-graph analysis. Only unambiguous same-scope function names and literal
tool collections qualify. Imported, aliased or dynamically assembled tools
remain opaque; their configured tool-use evidence is retained by the binder.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Collection, Iterable
from dataclasses import dataclass

from shadowscan.connectors.code.provider_tools import python_provider_tool_literals
from shadowscan.signatures.matcher import pattern_timeout
from shadowscan.utils.text import python_source_lines

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_FUNCTIONS, ast.ClassDef, ast.Lambda)
# Builtins that reach a module's functions by name ('globals()[name](...)').
_DYNAMIC_LOOKUPS = frozenset({"eval", "exec", "globals"})
_Walk = tuple[tuple[tuple[int, int], ...], tuple[tuple[int, int], ...], tuple[ast.AST, ...]]


@dataclass(frozen=True)
class ToolRegions:
    """Source regions attributable to a registered local tool, including its helpers."""

    bodies: tuple[tuple[int, int], ...] = ()
    declarations: tuple[tuple[int, int], ...] = ()


def python_tool_regions(
    text: str,
    tree: ast.AST,
    constructors: list[tuple[ast.Call, int | None]],
    registrations: list[tuple[ast.Call | None, int, bool]],
    dispatch_calls: set[int],
    *,
    each: dict[int, ToolRegions] | None = None,
    escapes: list[tuple[int, int]] | None = None,
    duplicates: Collection[ast.Call] = (),
) -> ToolRegions:
    """Resolve literal registrations and uniquely named local helper calls.

    The caller supplies only import-bound constructors and registrations.
    Rebinding, wildcard imports, foreign scopes and unresolved tool collections
    establish no local body. AST traversal shares the source matching deadline.
    With ``each``, every constructor's own regions are also stored under
    ``id(call)``; literal collections still resolve against all constructors.
    Each function body is read once however many constructors reach it.

    ``escapes`` receives the regions of every local function that code other
    than a resolved tools entry or a direct call can obtain, with whatever it
    calls: a function passed to another call ('bind_tools([lookup])'),
    stored, returned or placed in a computed collection, a method or lambda
    (callable wherever its object goes), or a function a local decorator
    receives. ``globals()``, ``eval`` or ``exec`` reach any function, and
    make it the whole text. ``duplicates`` are constructions whose literal
    tools lists repeat a constructor's in the same scope; their entries are
    resolved registrations too.
    """
    if not constructors and not registrations and not dispatch_calls:
        return ToolRegions()
    scopes: dict[int, int] = {}
    stores: Counter[tuple[int, str]] = Counter()
    definitions: dict[tuple[int, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
    objects: dict[tuple[int, str], ast.Call] = {}
    wildcards: set[int] = set()
    imported: set[tuple[int, str]] = set()
    redirects: dict[int, set[str]] = {}
    globals_: dict[int, set[str]] = {}
    parents: dict[int, int | None] = {id(tree): None}
    owners: dict[int, ast.AST] = {id(tree): tree}
    evaluation_scopes: dict[int, int] = {}
    live: set[int] = set()
    nodes: list[ast.AST] = []
    outcomes: dict[int, frozenset[str]] = {}
    control_steps = 0

    def control_checkpoint() -> None:
        nonlocal control_steps
        control_steps += 1
        if control_steps % 256 == 0:
            pattern_timeout()

    def block_outcomes(statements: list[ast.stmt]) -> set[str]:
        result = {"next"}
        for statement in statements:
            control_checkpoint()
            if "next" not in result:
                break
            result.remove("next")
            result.update(statement_outcomes(statement))
        return result

    def statement_outcomes(statement: ast.stmt) -> frozenset[str]:
        if id(statement) in outcomes:
            return outcomes[id(statement)]
        result: set[str] = {"next"}
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            result = {type(statement).__name__.lower()}
        elif isinstance(statement, ast.If):
            if isinstance(statement.test, ast.Constant):
                result = block_outcomes(statement.body if statement.test.value else statement.orelse)
            else:
                result = block_outcomes(statement.body) | block_outcomes(statement.orelse)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            result = block_outcomes(statement.body)
            if "raise" in result:
                result.add("next")  # A context manager can suppress an exception.
        elif isinstance(statement, ast.Try):
            result = block_outcomes(statement.body)
            if "next" in result:
                result.remove("next")
                result.update(block_outcomes(statement.orelse))
            # Implicit exceptions can enter any handler, even when the body
            # has a return. Do not assume exception types or handler selection.
            for handler in statement.handlers:
                result.update(block_outcomes(handler.body))
            final = block_outcomes(statement.finalbody)
            result = (result if "next" in final else set()) | (final - {"next"})
        outcomes[id(statement)] = frozenset(result)
        return outcomes[id(statement)]

    def unreachable_children(node: ast.AST) -> set[int]:
        unreachable: set[int] = set()
        for _, value in ast.iter_fields(node):
            if (
                not isinstance(value, list)
                or not value
                or not all(isinstance(part, ast.stmt) for part in value)
            ):
                continue
            continuing = True
            for statement in value:
                control_checkpoint()
                if not continuing:
                    unreachable.add(id(statement))
                else:
                    continuing = "next" in statement_outcomes(statement)
        return unreachable

    pending = [(tree, id(tree), True)]
    while pending:
        node, scope, active = pending.pop()
        scope = evaluation_scopes.get(id(node), scope)
        if len(nodes) % 256 == 0:
            pattern_timeout()
        nodes.append(node)
        scopes[id(node)] = scope
        if active:
            live.add(id(node))
        if isinstance(node, _FUNCTIONS):
            stores[scope, node.name] += 1
            if active:
                definitions[scope, node.name] = node
        elif isinstance(node, ast.ClassDef):
            stores[scope, node.name] += 1
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            stores[scope, node.id] += 1
        elif isinstance(node, ast.arg):
            stores[scope, node.arg] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    wildcards.add(scope)
                stores[scope, alias.asname or alias.name.split(".", 1)[0]] += 1
                imported.add((scope, alias.asname or alias.name.split(".", 1)[0]))
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            stores[scope, node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            stores[scope, node.rest] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            redirects.setdefault(scope, set()).update(node.names)
            if isinstance(node, ast.Global):
                globals_.setdefault(scope, set()).update(node.names)
        if (
            active
            and isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            if isinstance(node.value, ast.Call):
                objects[scope, node.targets[0].id] = node.value
        elif active and isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Call):
                objects[scope, node.target.id] = node.value
        child_scope = id(node) if isinstance(node, _SCOPES) else scope
        if isinstance(node, _SCOPES):
            parent_scope = scope
            while isinstance(owners[parent_scope], ast.ClassDef):
                parent_scope = parents[parent_scope] or id(tree)
            parents[child_scope] = parent_scope
            owners[child_scope] = node
        if isinstance(node, (*_FUNCTIONS, ast.Lambda)):
            # Parameter bindings belong to the new scope; their defaults and
            # annotations are evaluated when the function object is created.
            expressions: list[ast.AST] = [*node.args.defaults, *filter(None, node.args.kw_defaults)]
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            arguments.extend(arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None)
            expressions.extend(arg.annotation for arg in arguments if arg.annotation is not None)
            if isinstance(node, _FUNCTIONS):
                expressions.extend(node.decorator_list)
                if node.returns is not None:
                    expressions.append(node.returns)
            evaluation_scopes.update((id(expression), scope) for expression in expressions)
        unreachable = unreachable_children(node)
        for child in ast.iter_child_nodes(node):
            child_active = active and id(child) not in unreachable
            if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
                dead = node.orelse if node.test.value else node.body
                child_active = child_active and child not in dead
            elif isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and not node.test.value:
                child_active = child_active and child not in node.body
            pending.append((child, child_scope, child_active))

    # A global/nonlocal write can replace an outer helper through a separate
    # function call. Without executing that call, every same-spelled binding
    # must remain opaque. Read-only declarations do not invalidate a helper.
    uncertain = {name for scope, names in redirects.items() for name in names if stores[scope, name]}

    def binding_scope(name: str, scope: int) -> int | None:
        if name in uncertain:
            return None
        current: int | None = scope
        while current is not None:
            if current in wildcards:
                return None
            if name in globals_.get(current, ()) and current != id(tree):
                current = id(tree)
                continue
            if stores[current, name]:
                return current if stores[current, name] == 1 else None
            current = parents.get(current)
        return None

    lines = python_source_lines(text)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def offset(line: int, column: int) -> int:
        # Python AST columns count UTF-8 bytes; matcher offsets count characters.
        return offsets[line - 1] + len(lines[line - 1].encode()[:column].decode())

    def span(node: ast.AST) -> tuple[int, int]:
        return (
            offset(node.lineno, node.col_offset),  # type: ignore[attr-defined]
            offset(node.end_lineno, node.end_col_offset),  # type: ignore[attr-defined]
        )

    def callee_span(node: ast.AST) -> tuple[int, int] | None:
        """Keep invoked names without enclosing deferred callback bodies."""
        if isinstance(node, ast.Name):
            return span(node)
        if isinstance(node, ast.Attribute):
            root: ast.AST = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                return span(node)
            end = span(node)[1]
            return end - len(node.attr), end
        if isinstance(node, ast.Subscript):
            return callee_span(node.value)
        return None

    def record_callee(node: ast.AST, regions: list[tuple[int, int]]) -> None:
        if (region := callee_span(node)) is not None:
            regions.append(region)

    literals = python_provider_tool_literals(
        tree,
        {id(call) for call, _ in constructors},
        {id(call): position for call, position in constructors if position is not None},
    )

    def local_callable(value: ast.AST, scope: int) -> ast.AST | None:
        """The lambda, or the uniquely bound local function, that ``value`` denotes."""
        if isinstance(value, ast.Lambda):
            return value
        if isinstance(value, ast.Name) and (resolved := binding_scope(value.id, scope)) is not None:
            return definitions.get((resolved, value.id))
        return None

    walks: dict[int, _Walk] = {}

    def walk(function: ast.AST) -> _Walk:
        """A function's invoked callees, its decorators and the local functions it calls.

        Each body is read once per file: constructors sharing a tools
        collection, or tools sharing helpers, reuse what was read.
        """
        if (known := walks.get(id(function))) is not None:
            return known
        bodies: list[tuple[int, int]] = []
        declarations: list[tuple[int, int]] = []
        callees: list[ast.AST] = []
        if isinstance(function, _FUNCTIONS):
            declarations.extend(
                (max(0, span(decorator)[0] - 1), span(decorator)[1]) for decorator in function.decorator_list
            )
            body: list[ast.AST] = list(function.body)
        else:
            assert isinstance(function, ast.Lambda)
            body = [function.body]
        while body:
            node = body.pop()
            pattern_timeout()
            if id(node) not in live:
                continue
            if isinstance(node, (*_FUNCTIONS, ast.Lambda)):
                # Creating a deferred function still evaluates its defaults
                # and decorators. Its uncalled body remains contextual.
                body.extend(node.args.defaults)
                body.extend(default for default in node.args.kw_defaults if default is not None)
                if isinstance(node, _FUNCTIONS):
                    body.extend(node.decorator_list)
                    for decorator in node.decorator_list:
                        if isinstance(decorator, (ast.Name, ast.Lambda)) and (
                            chosen := local_callable(decorator, scopes[id(decorator)])
                        ):
                            callees.append(chosen)
                continue
            if isinstance(node, ast.ClassDef):
                # A class body runs immediately; its methods are deferred and
                # are handled by the function-object rule above.
                body.extend(node.body)
                body.extend(node.bases)
                body.extend(keyword.value for keyword in node.keywords)
                body.extend(node.decorator_list)
                continue
            if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
                body.extend(node.body if node.test.value else node.orelse)
                continue
            if isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and not node.test.value:
                body.extend(node.orelse)
                continue
            if isinstance(node, ast.Call):
                # Keep only the invoked expression. A deferred lambda inside
                # its arguments is not established as an executed callback.
                record_callee(node.func, bodies)
                if isinstance(node.func, (ast.Name, ast.Lambda)) and (
                    chosen := local_callable(node.func, scopes[id(node)])
                ):
                    callees.append(chosen)
            body.extend(ast.iter_child_nodes(node))
        walks[id(function)] = (tuple(bodies), tuple(declarations), tuple(callees))
        return walks[id(function)]

    def reach(
        functions: Iterable[ast.AST], bodies: set[tuple[int, int]], declarations: set[tuple[int, int]]
    ) -> None:
        """Add what ``functions`` and the local functions they call reach."""
        queue = list(functions)
        visited: set[int] = set()
        while queue:
            function = queue.pop()
            if id(function) in visited:
                continue
            visited.add(id(function))
            own_bodies, own_declarations, callees = walk(function)
            bodies.update(own_bodies)
            declarations.update(own_declarations)
            queue.extend(callees)

    # Tools entries that a resolved registration accounts for; any other
    # reference to a local function lets other code obtain it (``escapes``).
    entries: set[int] = set()

    def resolve(
        requested: list[tuple[ast.Call, int | None]],
        registered: list[tuple[ast.Call | None, int, bool]],
        dispatched: set[int],
    ) -> ToolRegions:
        selected: dict[int, ast.AST] = {}
        configured_objects: list[tuple[int, int]] = []

        def select(value: ast.AST | None, scope: int) -> None:
            if isinstance(value, ast.Call):
                record_callee(value.func, configured_objects)
            elif value is not None and (function := local_callable(value, scope)) is not None:
                selected[id(function)] = function
            elif isinstance(value, ast.Name) and (resolved := binding_scope(value.id, scope)) is not None:
                if (created := objects.get((resolved, value.id))) is not None:
                    record_callee(created.func, configured_objects)

        for call, position in requested:
            keywords = [keyword.arg for keyword in call.keywords]
            if None in keywords or len(set(keywords)) != len(keywords):
                continue
            scope = scopes.get(id(call), id(tree))
            value: ast.AST | None = next(
                (keyword.value for keyword in call.keywords if keyword.arg == "tools"), None
            )
            if value is None and position is not None and len(call.args) > position:
                if not any(isinstance(argument, ast.Starred) for argument in call.args[: position + 1]):
                    value = call.args[position]
            if isinstance(value, ast.Name):
                value = literals.get(id(call), {}).get(value.id)
            values = (
                value.elts
                if isinstance(value, (ast.List, ast.Tuple, ast.Set))
                else value.values
                if isinstance(value, ast.Dict) and all(key is not None for key in value.keys)
                else ()
            )
            for entry in values:
                entries.add(id(entry))
                select(entry, scope)
        # Whole-file scans run only for paths that need them, so resolving
        # one constructor costs its own registrations and reachable bodies.
        decorator_lines = {line for _, line, decorated in registered if decorated}
        if decorator_lines:
            for node in nodes:
                if (
                    isinstance(node, _FUNCTIONS)
                    and id(node) in live
                    and any(decorator.lineno in decorator_lines for decorator in node.decorator_list)
                ):
                    selected[id(node)] = node
        for registration, _, decorated in registered:
            if registration is not None and not decorated and registration.args:
                select(registration.args[0], scopes.get(id(registration), id(tree)))

        # Follow direct calls into unambiguous lexical function bindings. Aliases,
        # attributes and imported implementations remain contextual observations.
        if dispatched:
            for node in nodes:
                if isinstance(node, ast.Call) and id(node) in dispatched and id(node) in live:
                    record_callee(node.func, configured_objects)
                    if isinstance(node.func, ast.Name):
                        select(node.func, scopes[id(node)])
        bodies = set(configured_objects)
        declarations: set[tuple[int, int]] = set()
        reach(selected.values(), bodies, declarations)
        return ToolRegions(tuple(sorted(bodies)), tuple(sorted(declarations)))

    def escaped_regions() -> list[tuple[int, int]]:
        """What local functions reach when code other than a resolved registration obtains them."""
        stored = {name for _, name in stores}

        def foreign(expression: ast.AST, scope: int) -> bool:
            """Whether an expression's root name is imported or a builtin, not local code."""
            while isinstance(expression, (ast.Call, ast.Attribute, ast.Subscript)):
                expression = expression.func if isinstance(expression, ast.Call) else expression.value
            if not isinstance(expression, ast.Name):
                return False
            if (resolved := binding_scope(expression.id, scope)) is not None:
                return (resolved, expression.id) in imported
            return not wildcards and expression.id not in stored

        called = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
        called.update(
            id(decorator)
            for node in nodes
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef))
            for decorator in node.decorator_list
        )
        roots: list[ast.AST] = []
        for node in nodes:
            control_checkpoint()
            if id(node) not in live:
                continue
            scope = scopes[id(node)]
            if isinstance(node, ast.Lambda):
                if id(node) not in entries and id(node) not in called:
                    roots.append(node)
            elif isinstance(node, _FUNCTIONS):
                # A method runs wherever its object goes; a local decorator
                # receives the function itself.
                if isinstance(owners[scope], ast.ClassDef) or not all(
                    foreign(decorator, scopes[id(decorator)]) for decorator in node.decorator_list
                ):
                    roots.append(node)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id in _DYNAMIC_LOOKUPS and foreign(node, scope):
                    return [(0, len(text))]
                if id(node) not in called and id(node) not in entries:
                    if (function := local_callable(node, scope)) is not None:
                        roots.append(function)
        bodies: set[tuple[int, int]] = set()
        declarations: set[tuple[int, int]] = set()
        reach(roots, bodies, declarations)
        return sorted(bodies | declarations)

    if each is not None:
        # Resolve every constructor alone against the tables built once
        # above: separate identities must not repeat this whole-file pass.
        for call, position in constructors:
            each[id(call)] = resolve([(call, position)], [], set())
    regions = resolve(constructors, registrations, dispatch_calls)
    if escapes is not None:
        for call in duplicates:
            tools = next((keyword.value for keyword in call.keywords if keyword.arg == "tools"), None)
            if isinstance(tools, (ast.List, ast.Tuple)):
                entries.update(id(entry) for entry in tools.elts)
        escapes.extend(escaped_regions())
    return regions
