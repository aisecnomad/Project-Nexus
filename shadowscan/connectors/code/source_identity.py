"""Bounded identities for unique named Python source constructions.

This pass consumes import-proved call spans. It does not discover agents or
claim that a source construction represents one deployed runtime instance.
"""

from __future__ import annotations

import ast
from collections import Counter

from shadowscan.connectors.code.tool_attribution import ToolRegions, python_tool_regions

DEFAULT_MAX_AST_NODES = 50_000
MAX_BINDING_LENGTH = 256

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_CONTROL = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)


def named_construction_spans(
    text: str,
    *,
    max_ast_nodes: int | None = None,
    verified_spans: set[tuple[int, int]] | None = None,
    tool_regions: dict[tuple[int, int], ToolRegions] | None = None,
) -> dict[tuple[int, int], str]:
    """Return stable scoped names of direct, unique, straight-line assignments.

    Reassignment, repeated scope definitions, control-flow assignments,
    global/nonlocal writes, attributes and unbound expressions are excluded.
    The same AST-node budget as source binding applies; an unsupported or
    over-budget input yields no identities rather than guessing from lines.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return {}
    budget = max_ast_nodes or DEFAULT_MAX_AST_NODES
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    total = 0
    for line in lines:
        offsets.append(total)
        total += len(line)

    writes: Counter[tuple[tuple[str, ...], str]] = Counter()
    definitions: Counter[tuple[str, ...]] = Counter()
    external: set[tuple[tuple[str, ...], str]] = set()
    wildcards: set[tuple[str, ...]] = set()
    candidates: list[tuple[tuple[str, ...], str, ast.Call]] = []
    pending: list[tuple[ast.AST, tuple[str, ...], bool]] = [(tree, (), False)]
    count = 0
    while pending:
        node, scope, blocked = pending.pop()
        count += 1
        if count > budget:
            return {}
        if isinstance(node, _SCOPES):
            writes[(scope, node.name)] += 1
            scope = (*scope, node.name)
            definitions[scope] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            external.update((scope, name) for name in node.names)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    wildcards.add(scope)
                else:
                    name = alias.asname or (
                        alias.name.split(".", 1)[0] if isinstance(node, ast.Import) else alias.name
                    )
                    writes[(scope, name)] += 1
        elif (
            isinstance(node, ast.ExceptHandler)
            and node.name
            or isinstance(node, (ast.MatchAs, ast.MatchStar))
            and node.name
        ):
            writes[(scope, node.name)] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            writes[(scope, node.rest)] += 1
        elif isinstance(node, ast.arg):
            writes[(scope, node.arg)] += 1
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            writes[(scope, node.id)] += 1
        call: ast.AST | None = None
        target: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            call, target = node.value, node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            call, target = node.value, node.target
        if not blocked and isinstance(call, ast.Call) and isinstance(target, ast.Name):
            candidates.append((scope, target.id, call))
        # TryStar is available from Python 3.11, the minimum supported version.
        blocked = blocked or isinstance(node, (*_CONTROL, ast.TryStar))
        pending.extend((child, scope, blocked) for child in ast.iter_child_nodes(node))

    eligible: list[tuple[tuple[str, ...], str, ast.Call]] = []
    coordinates: dict[int, set[int]] = {}
    for scope, name, call in candidates:
        key = (scope, name)
        binding = ".".join((*scope, name))
        if (
            writes[key] != 1
            or key in external
            or scope in wildcards
            or len(binding) > MAX_BINDING_LENGTH
            or any(definitions[scope[:number]] != 1 for number in range(1, len(scope) + 1))
        ):
            continue
        if call.end_lineno is None or call.end_col_offset is None:
            continue
        eligible.append((scope, binding, call))
        coordinates.setdefault(call.lineno, set()).add(call.col_offset)
        coordinates.setdefault(call.end_lineno, set()).add(call.end_col_offset)
    positions: dict[tuple[int, int], int] = {}
    for line_number, columns in coordinates.items():
        # Encode each line once and decode disjoint slices: many calls on a
        # long non-ASCII line must not repeatedly decode the entire prefix.
        encoded = lines[line_number - 1].encode("utf-8")
        previous = 0
        chars = offsets[line_number - 1]
        for column in sorted(columns):
            chars += len(encoded[previous:column].decode("utf-8"))
            positions[(line_number, column)] = chars
            previous = column
    found: dict[tuple[int, int], str] = {}
    shared_regions: dict[tuple[tuple[str, ...], str, tuple[str, ...]], ToolRegions] = {}
    for scope, binding, call in eligible:
        assert call.end_lineno is not None and call.end_col_offset is not None
        span = (
            positions[(call.lineno, call.col_offset)],
            positions[(call.end_lineno, call.end_col_offset)],
        )
        found[span] = binding
        if tool_regions is not None and verified_spans is not None and span in verified_spans:
            # Only the keyword tools argument qualifies here. Positional
            # factories need their resolved SDK symbol, unavailable in this
            # identity pass, and remain project-level context.
            tools = next((keyword.value for keyword in call.keywords if keyword.arg == "tools"), None)
            empty = (
                isinstance(tools, (ast.List, ast.Tuple, ast.Set))
                and not tools.elts
                or isinstance(tools, ast.Dict)
                and not tools.keys
            )
            # Missing/empty tool registrations have no local bodies. Avoid a
            # complete AST/tool pass for every such construction in a large
            # file while preserving its independent inventory identity.
            if tools is None or empty:
                tool_regions[span] = ToolRegions()
                continue
            keywords = [keyword.arg for keyword in call.keywords]
            if (
                isinstance(tools, (ast.List, ast.Tuple))
                and all(isinstance(entry, ast.Name) for entry in tools.elts)
                and None not in keywords
                and len(set(keywords)) == len(keywords)
            ):
                # Literal names resolve against the same unique lexical scope.
                # The tool pass rejects rebinding and wildcard imports globally,
                # so identical registrations in that scope share its result.
                # Unpacked/duplicate keywords keep the resolver's opaque path.
                region_key = (
                    scope,
                    type(tools).__name__,
                    tuple(entry.id for entry in tools.elts if isinstance(entry, ast.Name)),
                )
                if region_key not in shared_regions:
                    shared_regions[region_key] = python_tool_regions(text, tree, [(call, None)], [], set())
                tool_regions[span] = shared_regions[region_key]
            else:
                tool_regions[span] = python_tool_regions(text, tree, [(call, None)], [], set())
    return found
