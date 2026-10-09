"""Resolve a narrow class of Python re-exports from already-read source.

Only flat, project-root modules containing unconditional ``from`` imports and
an optional docstring qualify. No module is imported and no path is opened.
Packages, relative/star imports, assignments and other executable statements
remain unresolved. The caller retains its ordinary per-file evidence.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Callable
from pathlib import PurePosixPath

ImportResolver = Callable[[str, str], tuple[str, str] | None]
MAX_SHIM_BYTES = 65_536
MAX_SHIMS = 4096
MAX_EXPORTS = 256
MAX_CHAIN = 16
MAX_PENDING_FILES = 4096
MAX_PENDING_BYTES = 16 * 1024 * 1024
# ``\s`` includes newlines: at every line anchor it would rescan the entire
# remaining blank-file suffix. Python indentation has only these characters.
_FROM = re.compile(r"(?m)^[ \t\f]*from[ \t\f]+([A-Za-z_]\w*)[ \t\f]+import[ \t\f(]")


class ReexportLimitError(RuntimeError):
    """A candidate needs source or resolution work beyond the fixed budget."""


def project_path(project: str, relative: str) -> PurePosixPath:
    path = PurePosixPath(relative)
    return path if project == "." else path.relative_to(project)


def has_local_import(text: str, is_local: Callable[[str], bool]) -> bool:
    """Cheap conservative prefilter; AST binding still checks the actual import."""
    return any(is_local(match.group(1)) for match in _FROM.finditer(text))


def _may_be_import_only(text: str) -> bool:
    """Whether some statement and every other may be a ``from`` import, after an optional docstring.

    Tokens are read lazily, so an ordinary module stops at its first other
    statement. Source that does not tokenize would not parse as a shim either.
    """
    first = start = True
    imports = False
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type in {tokenize.NL, tokenize.COMMENT}:
                continue
            if token.type == tokenize.ENDMARKER:
                break
            if token.type == tokenize.NEWLINE or token.exact_type == tokenize.SEMI:
                start = True
            elif start:
                is_from = token.type == tokenize.NAME and token.string == "from"
                if not (is_from or (first and token.type == tokenize.STRING)):
                    return False
                imports = imports or is_from
                first = start = False
    except (tokenize.TokenError, SyntaxError, ValueError):
        return False
    return imports


class PythonReexports:
    """An import-only module graph, scoped to one scan's manifest projects."""

    def __init__(self) -> None:
        self.modules: dict[tuple[str, str], dict[str, tuple[str, str]]] = {}
        self.packages: set[tuple[str, str]] = set()
        self.limited: set[tuple[str, str]] = set()
        self.full = False

    def note_path(self, project: str, relative: str) -> None:
        path = project_path(project, relative)
        if len(path.parts) > 1:
            # A module/package collision is ambiguous for this deliberately
            # flat resolver, even if a package path is only a data directory.
            self.packages.add((project, path.parts[0]))

    def add(self, project: str, relative: str, text: str) -> None:
        path = project_path(project, relative)
        if len(path.parts) != 1 or path.suffix != ".py" or not path.stem.isidentifier():
            return
        key = (project, path.stem)
        if len(text.encode("utf-8")) > MAX_SHIM_BYTES:
            # Only a module that may be import-only could be a shim; any other
            # large module stays unresolved, like every other non-shim.
            if _may_be_import_only(text):
                self.limited.add(key)
            return
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return
        exports: dict[str, tuple[str, str]] = {}
        for position, statement in enumerate(tree.body):
            if (
                position == 0
                and isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            if not isinstance(statement, ast.ImportFrom) or statement.level or not statement.module:
                return
            for alias in statement.names:
                name = alias.asname or alias.name
                if alias.name == "*" or name in exports:
                    return
                exports[name] = (statement.module, alias.name)
        if not exports:
            return
        if len(exports) > MAX_EXPORTS:
            # Counted once the whole module is known to be import-only: names
            # an ordinary module imports before its code are not exports.
            self.limited.add(key)
            return
        if len(self.modules) >= MAX_SHIMS:
            self.full = True
            return
        self.modules[key] = exports

    def resolver(self, project: str, is_local: Callable[[str], bool]) -> ImportResolver:
        def resolve(module: str, symbol: str) -> tuple[str, str] | None:
            if not is_local(module):
                return None
            seen: set[str] = set()
            for _ in range(MAX_CHAIN):
                # Dotted modules require package import semantics; unsupported.
                if "." in module or module in seen or (project, module) in self.packages:
                    return None
                seen.add(module)
                key = (project, module)
                if self.full or key in self.limited:
                    raise ReexportLimitError("Python re-export source budget exceeded")
                exported = self.modules.get(key, {}).get(symbol)
                if exported is None:
                    return None
                module, symbol = exported
                if not is_local(module):
                    return module, symbol
            raise ReexportLimitError("Python re-export chain budget exceeded")

        return resolve
