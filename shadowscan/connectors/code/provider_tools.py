"""Literal tool configuration on import-bound provider requests.

Passing an empty collection or a dynamic value is not evidence of offering
tools. This pass reads bounded Python AST arguments and complete inline
JavaScript option objects. Python also permits a preceding, single literal
declaration in the same scope, with no aliases, mutations or shadowing. It
does not execute source; separately connected tool dispatch can still prove an
observed capability.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field

from shadowscan.connectors.code.source_capabilities import (
    _javascript_collection,
    _python_collection,
    _python_entry,
)
from shadowscan.connectors.code.vercel_tools import _literal, _object, _parts, _unwrap
from shadowscan.signatures.matcher import pattern_timeout

_TOOL_OPTIONS = ("tools", "functions", "function_declarations", "functionDeclarations")
_CHOICE_OPTIONS = ("tool_choice", "toolChoice", "function_call")
_ENABLED_CHOICES = frozenset({"auto", "required", "any"})
_ENABLED_TYPES = frozenset({"auto", "any", "tool", "function"})
_DECLARATIONS = ("function_declarations", "functionDeclarations")
_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


@dataclass
class ProviderLiteralCache:
    """AST classifications shared by calls within one parsed source file."""

    objects: dict[int, dict[str, ast.AST] | None] = field(default_factory=dict)
    tools: dict[int, bool] = field(default_factory=dict)


def python_provider_tool_literals(
    tree: ast.AST, requests: set[int], positional_tools: Mapping[int, int] | None = None
) -> dict[int, dict[str, ast.AST]]:
    """Index safe literal declarations once, without general variable data flow.

    Only direct declarations in a lexical scope qualify. A name must be bound
    once across the file, and every use must be a same-scope tool option on a
    known provider request after that declaration. Rejecting other uses also
    rejects mutable aliases, captured references, method calls and indexed
    writes. Same-name declarations in separate scopes are conservatively
    ambiguous rather than inferred to identify different runtime objects.
    """
    if not requests:
        return {}
    stores: Counter[str] = Counter()
    literals: dict[str, tuple[int, ast.AST, tuple[int, int]]] = {}
    loads: dict[str, list[tuple[int, ast.Name, ast.AST | None, ast.AST | None]]] = {}
    requested: dict[int, tuple[int, ast.Call]] = {}
    stack: list[tuple[ast.AST, ast.AST | None, ast.AST | None, int]] = [(tree, None, None, id(tree))]
    visited = 0
    while stack:
        node, parent, grandparent, scope = stack.pop()
        visited += 1
        if visited % 256 == 0:
            pattern_timeout()
        if isinstance(node, _SCOPES):
            scope = id(node)
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                stores[node.id] += 1
            elif isinstance(node.ctx, ast.Load):
                loads.setdefault(node.id, []).append((scope, node, parent, grandparent))
        elif isinstance(node, ast.arg):
            stores[node.arg] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stores[node.name] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    return {}  # an unresolved import may overwrite any declaration
                stores[alias.asname or alias.name.split(".", 1)[0]] += 1
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name is not None:
            stores[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest is not None:
            stores[node.rest] += 1
        if isinstance(node, ast.Call) and id(node) in requests:
            requested[id(node)] = scope, node
        target: ast.AST | None = None
        value: ast.AST | None = None
        if isinstance(parent, _SCOPES):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign):
                target, value = node.target, node.value
        if isinstance(target, ast.Name) and isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            literals[target.id] = (
                scope,
                value,
                (
                    value.end_lineno or value.lineno,
                    value.end_col_offset or 0,
                ),
            )
        stack.extend((child, node, parent, scope) for child in ast.iter_child_nodes(node))

    def tool_request(used: ast.Name, parent: ast.AST | None, grandparent: ast.AST | None) -> ast.Call | None:
        if (
            isinstance(parent, ast.keyword)
            and parent.arg in (*_TOOL_OPTIONS, "toolConfig")
            and isinstance(grandparent, ast.Call)
            and id(grandparent) in requests
        ):
            return grandparent
        if isinstance(parent, ast.Call) and id(parent) in requests and positional_tools:
            position = positional_tools.get(id(parent))
            if position is not None and len(parent.args) > position and parent.args[position] is used:
                return parent
        return None

    result: dict[int, dict[str, ast.AST]] = {}
    for name, (scope, value, declared) in literals.items():
        uses = loads.get(name, [])
        if stores[name] != 1 or any(
            used_scope != scope
            or (used.lineno, used.col_offset) <= declared
            or tool_request(used, parent, call) is None
            for used_scope, used, parent, call in uses
        ):
            continue
        for _, used, parent, outer in uses:
            call = tool_request(used, parent, outer)
            if call is not None:
                result.setdefault(id(call), {})[name] = value
    return result


def _python_object(
    value: ast.AST | None, cache: ProviderLiteralCache | None = None
) -> dict[str, ast.AST] | None:
    if not isinstance(value, ast.Dict):
        return None
    if cache is not None and id(value) in cache.objects:
        return cache.objects[id(value)]
    fields: dict[str, ast.AST] = {}
    valid = True
    for number, (key, item) in enumerate(zip(value.keys, value.values, strict=True)):
        if number % 256 == 0:
            pattern_timeout()
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str) or key.value in fields:
            valid = False
            break
        fields[key.value] = item
    result = fields if valid else None
    if cache is not None:
        cache.objects[id(value)] = result
    return result


def _python_literal(value: ast.AST | None) -> str | None:
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def _python_choice(value: ast.AST, cache: ProviderLiteralCache | None = None) -> bool:
    literal = _python_literal(value)
    if literal is not None:
        return literal in _ENABLED_CHOICES
    fields = _python_object(value, cache)
    if fields is None:
        return False
    kind = _python_literal(fields.get("type"))
    return kind in _ENABLED_TYPES or "type" not in fields and bool(_python_literal(fields.get("name")))


def _python_choices(values: dict[str, ast.AST], cache: ProviderLiteralCache | None = None) -> bool:
    return all(name not in values or _python_choice(values[name], cache) for name in _CHOICE_OPTIONS)


def _python_tools(value: ast.AST | None, cache: ProviderLiteralCache | None = None) -> bool:
    if value is None:
        return False
    if cache is not None and id(value) in cache.tools:
        return cache.tools[id(value)]
    result = _python_tools_value(value, cache)
    if cache is not None:
        cache.tools[id(value)] = result
    return result


def _python_tools_value(value: ast.AST, cache: ProviderLiteralCache | None) -> bool:
    pattern_timeout()
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        result = _python_collection(value)
        pattern_timeout()
        return result
    for number, item in enumerate(value.elts):
        if number % 256 == 0:
            pattern_timeout()
        fields = _python_object(item, cache)
        if fields is not None and any(name in fields for name in _DECLARATIONS):
            if any(_python_collection(fields.get(name)) for name in _DECLARATIONS):
                return True
        elif _python_entry(item):
            return True
    return False


def _javascript_choice(raw: str, masked: str) -> bool:
    literal = _literal(raw)
    if literal is not None:
        return literal in _ENABLED_CHOICES
    fields = _object(raw, masked)
    if fields is None:
        return False
    kind = _literal(fields["type"][0]) if "type" in fields else None
    return (
        kind in _ENABLED_TYPES
        or "type" not in fields
        and "name" in fields
        and bool(_literal(fields["name"][0]))
    )


def _javascript_choices(values: dict[str, tuple[str, str]]) -> bool:
    return all(name not in values or _javascript_choice(*values[name]) for name in _CHOICE_OPTIONS)


def _javascript_tools(raw: str, masked: str) -> bool:
    array = _unwrap(raw, masked, "[")
    if array is None:
        return _javascript_collection(raw, masked)
    for source, code in _parts(*array) or []:
        fields = _object(source, code)
        if fields is not None and any(name in fields for name in _DECLARATIONS):
            if any(name in fields and _javascript_collection(*fields[name]) for name in _DECLARATIONS):
                return True
        elif _javascript_collection(f"[{source}]", f"[{code}]"):
            return True
    return False


def provider_tools_disabled(node: ast.Call) -> bool:
    """Whether a supported literal selection disables dispatch on this request.

    Unknown selections cannot prove configured tools, but do not erase
    independently connected execution evidence from the loop recognizer.
    """
    for keyword in node.keywords:
        if keyword.arg not in _CHOICE_OPTIONS:
            continue
        if _python_literal(keyword.value) == "none":
            return True
        choice = _python_object(keyword.value)
        if choice is not None and _python_literal(choice.get("type")) == "none":
            return True
    return False


def has_provider_tools(
    *,
    node: ast.Call | None,
    arguments: str,
    masked: str,
    python_literals: Mapping[str, ast.AST] | None = None,
    python_cache: ProviderLiteralCache | None = None,
) -> bool:
    """Recognize enabled nonempty literal tools, preserving dynamic SDK usage."""
    if node is not None:
        values: dict[str, ast.AST] = {}
        for keyword in node.keywords:
            # Expanded options and repeated fields can conflict with the
            # apparent choice/tool definitions; retain only SDK usage.
            if keyword.arg is None or keyword.arg in values:
                return False
            value: ast.AST = keyword.value
            if (
                isinstance(value, ast.Name)
                and keyword.arg in (*_TOOL_OPTIONS, "toolConfig")
                and python_literals is not None
            ):
                value = python_literals.get(value.id, value)
            values[keyword.arg] = value
        if not _python_choices(values, python_cache):
            return False
        config = _python_object(values.get("toolConfig"), python_cache)
        if "toolConfig" in values and (config is None or not _python_choices(config, python_cache)):
            return False
        if any(_python_tools(values.get(name), python_cache) for name in _TOOL_OPTIONS):
            return True
        return bool(
            config is not None
            and any(_python_tools(config.get(name), python_cache) for name in _TOOL_OPTIONS)
        )

    inner = _unwrap(arguments, masked, "(")
    options = _object(*inner) if inner is not None else None
    if options is None or not _javascript_choices(options):
        return False
    js_config = _object(*options["toolConfig"]) if "toolConfig" in options else None
    if "toolConfig" in options and (js_config is None or not _javascript_choices(js_config)):
        return False
    if any(name in options and _javascript_tools(*options[name]) for name in _TOOL_OPTIONS):
        return True
    return bool(
        js_config is not None
        and any(name in js_config and _javascript_tools(*js_config[name]) for name in _TOOL_OPTIONS)
    )
