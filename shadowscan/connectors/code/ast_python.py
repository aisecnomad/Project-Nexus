"""Python AST confirmation for import and code signature matches.

Lexical ignore-spans already hide comments and strings. AST confirmation
additionally requires that an import/code regex hit correspond to a real
Import/ImportFrom or a Call/Attribute/Name on that line. When the file does
not parse, matches are kept and marked incomplete so the scan cannot look
empty.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

_MAX_NODES = 50_000
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(slots=True)
class PythonUnits:
    parse_ok: bool
    incomplete: bool = False
    error: str | None = None
    import_modules: dict[int, set[str]] = field(default_factory=dict)
    import_lines: set[int] = field(default_factory=set)
    names_by_line: dict[int, set[str]] = field(default_factory=dict)
    calls_by_line: dict[int, set[str]] = field(default_factory=dict)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def parse_python_units(source: str) -> PythonUnits:
    if not source or not source.strip():
        return PythonUnits(parse_ok=True)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return PythonUnits(parse_ok=False, incomplete=True, error=type(exc).__name__)

    units = PythonUnits(parse_ok=True)
    count = 0
    for node in ast.walk(tree):
        count += 1
        if count > _MAX_NODES:
            units.incomplete = True
            break
        line = getattr(node, "lineno", None)
        if not isinstance(line, int) or line < 1:
            continue
        if isinstance(node, ast.Import):
            units.import_lines.add(line)
            names = units.import_modules.setdefault(line, set())
            for alias in node.names:
                if alias.name:
                    names.add(alias.name.split(".", 1)[0])
                    names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            units.import_lines.add(line)
            names = units.import_modules.setdefault(line, set())
            if node.module:
                names.add(node.module.split(".", 1)[0])
                names.add(node.module)
            for alias in node.names:
                if alias.name and alias.name != "*":
                    names.add(alias.name)
        elif isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            if dotted:
                bucket = units.calls_by_line.setdefault(line, set())
                bucket.add(dotted)
                bucket.add(dotted.split(".")[-1])
        elif isinstance(node, ast.Attribute):
            units.names_by_line.setdefault(line, set()).add(node.attr)
        elif isinstance(node, ast.Name):
            units.names_by_line.setdefault(line, set()).add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                dotted = _dotted(dec)
                if dotted:
                    dec_line = getattr(dec, "lineno", line)
                    units.calls_by_line.setdefault(dec_line, set()).add(dotted.split(".")[-1])
                    units.names_by_line.setdefault(dec_line, set()).add(dotted.split(".")[-1])
    return units


def _idents(value: str) -> set[str]:
    return set(_IDENT.findall(value or ""))


def match_confirmed(match: Any, units: PythonUnits) -> bool:
    if not units.parse_ok:
        return True
    signal_type = getattr(getattr(match, "signal", None), "type", None)
    line = getattr(match, "line", None) or 0
    value = str(getattr(match, "value", "") or "")
    idents = _idents(value)
    if signal_type == "import":
        if line in units.import_lines:
            return True
        return any(abs(existing - line) <= 1 for existing in units.import_lines)
    if signal_type == "code":
        nearby_calls: set[str] = set()
        nearby_names: set[str] = set()
        for offset in (-1, 0, 1):
            nearby_calls |= units.calls_by_line.get(line + offset, set())
            nearby_names |= units.names_by_line.get(line + offset, set())
        if idents & nearby_calls:
            return True
        if value.lstrip().startswith("@") and idents & nearby_names:
            return True
        if idents & nearby_names and not value.rstrip().endswith("("):
            return True
        return False
    return True


def filter_python_matches(source: str, matches: list[Any]) -> tuple[list[Any], PythonUnits]:
    units = parse_python_units(source)
    if not units.parse_ok:
        for match in matches:
            extra = getattr(match, "extra", None)
            if isinstance(extra, dict):
                extra["python_ast"] = "unavailable"
        return list(matches), units
    kept: list[Any] = []
    for match in matches:
        signal_type = getattr(getattr(match, "signal", None), "type", None)
        if signal_type not in {"import", "code"}:
            kept.append(match)
            continue
        if match_confirmed(match, units):
            extra = getattr(match, "extra", None)
            if isinstance(extra, dict):
                extra["python_ast"] = "confirmed"
            kept.append(match)
    return kept, units
