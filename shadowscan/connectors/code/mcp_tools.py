"""What an MCP server can do, read from the tools it registers.

An MCP server's risk is the set of tools it exposes to whichever model
connects: ``write_file`` and ``git_commit`` change data, ``fetch`` reaches
the web, ``run_command`` executes code. Vendor-neutral idioms elsewhere in
the server's source (a ``thought:`` schema field, a ``while`` loop) say
nothing about that, so capabilities of an MCP tool server come from here.

Python extraction uses its AST; JavaScript/TypeScript registration starts
must lie outside comments and strings. Both passes are bounded, including
string enums referenced by ``Tool(name=Enum.MEMBER)``. Names are mapped to
capabilities by vocabulary;
the mapping is deliberately conservative and every implied capability is
reported with the tool names behind it.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_right

from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.signatures.matcher import pattern_timeout

MAX_TOOLS_PER_FILE = 100
MAX_MCP_AST_NODES = 50_000
_NAME = r"([A-Za-z][A-Za-z0-9_.-]{0,63})"
_VALID_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")

_REGISTRATIONS = (
    # TypeScript/JavaScript SDK: server.registerTool("name", ...), server.tool("name", ...)
    re.compile(r"\.(?:registerTool|tool)\(\s*[\"'`]" + _NAME + r"[\"'`]"),
    # Tool schema objects in a list_tools handler: { name: "x", description: ... }
    re.compile(
        r"\bname\s*:\s*[\"'`]" + _NAME + r"[\"'`]\s*,\s*(?:title\s*:\s*[^\n]{0,200}\n\s*)?description\s*:"
    ),
)

_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")

_VOCABULARY: dict[str, frozenset[str]] = {
    "code-exec": frozenset(
        {
            "exec",
            "execute",
            "shell",
            "bash",
            "command",
            "commands",
            "cmd",
            "eval",
            "terminal",
            "script",
            "powershell",
            "subprocess",
            "interpreter",
        }
    ),
    "data-access": frozenset(
        {
            "file",
            "files",
            "directory",
            "directories",
            "dir",
            "dirs",
            "folder",
            "folders",
            "path",
            "paths",
            "sql",
            "query",
            "database",
            "db",
            "table",
            "tables",
            "record",
            "records",
            "git",
            "repo",
            "repository",
        }
    ),
    "browsing": frozenset(
        {
            "fetch",
            "browse",
            "browser",
            "navigate",
            "url",
            "urls",
            "http",
            "https",
            "web",
            "scrape",
            "crawl",
            "screenshot",
            "website",
        }
    ),
    "memory": frozenset(
        {
            "memory",
            "memories",
            "remember",
            "recall",
            "entity",
            "entities",
            "observations",
            "relations",
            "knowledge",
        }
    ),
    "saas-actions": frozenset(
        {
            "send",
            "email",
            "mail",
            "slack",
            "tweet",
            "issue",
            "issues",
            "ticket",
            "tickets",
            "publish",
            "deploy",
            "payment",
            "transfer",
        }
    ),
}
_RUNNABLE = frozenset({"code", "script", "command", "python", "shell", "program"})


class MCPToolLimitError(ValueError):
    """Tool analysis omitted content; partial names do not establish coverage."""

    def __init__(self, reason: str, names: list[str] | None = None):
        super().__init__(reason)
        self.names = names or []


class _Names:
    def __init__(self) -> None:
        self.names: dict[str, None] = {}

    def add(self, name: object) -> None:
        if not isinstance(name, str) or not _VALID_NAME.fullmatch(name) or name in self.names:
            return
        if len(self.names) >= MAX_TOOLS_PER_FILE:
            raise MCPToolLimitError("MCP tool-name limit exceeded", list(self.names))
        self.names[name] = None


def _literal_name(node: ast.AST | None, enums: dict[tuple[str, str], str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return enums.get((node.value.id, node.attr))
    return None


def _mcp_python_bindings(nodes: list[ast.AST]) -> tuple[dict[str, str], set[str]]:
    """Conservatively identify unmutated MCP imports and constructed receivers.

    This is a narrow source context check, not runtime import verification.
    Rebinding anywhere in the file removes the proof, including in nested
    scopes, rather than assigning SDK provenance to a shadowed receiver.
    """
    imports: dict[str, str] = {}
    counts: dict[str, int] = {}
    star_import = False

    def bound(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                bound(local)
                if alias.name.split(".")[0] in {"mcp", "fastmcp"}:
                    imports[local] = alias.name if alias.asname else local
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    star_import = True
                    continue
                local = alias.asname or alias.name
                bound(local)
                if node.module and not node.level and node.module.split(".")[0] in {"mcp", "fastmcp"}:
                    imports[local] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound(node.name)
        elif isinstance(node, ast.arg):
            bound(node.arg)
        elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                bound(root.id)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            bound(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound(node.rest)
    imports = (
        {} if star_import else {name: target for name, target in imports.items() if counts.get(name) == 1}
    )
    servers: set[str] = set()
    for node in nodes:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and isinstance(value, ast.Call) and counts.get(target.id) == 1:
            resolved = _import_target(value.func, imports)
            if resolved and resolved.split(".")[-1] in {"FastMCP", "MCPServer", "Server"}:
                servers.add(target.id)
    return imports, servers


def _import_target(node: ast.AST, imports: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return imports.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _import_target(node.value, imports)
        return f"{base}.{node.attr}" if base else None
    return None


def _python_tool_names(tree: ast.AST, max_ast_nodes: int, require_mcp_binding: bool) -> list[str]:
    """Read actual decorators and tool-schema calls, never documentary text."""
    nodes: list[ast.AST] = []
    for count, node in enumerate(ast.walk(tree), start=1):
        if count > max_ast_nodes:
            raise MCPToolLimitError("MCP syntax-tree node limit exceeded")
        if count % 256 == 0:
            pattern_timeout()
        nodes.append(node)
    imports, servers = _mcp_python_bindings(nodes) if require_mcp_binding else ({}, set())
    enums: dict[tuple[str, str], str] = {}
    for node in nodes:
        if isinstance(node, ast.ClassDef) and any(
            isinstance(base, ast.Name) and base.id in {"Enum", "StrEnum"} for base in node.bases
        ):
            for statement in node.body:
                if (
                    isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)
                    and isinstance(statement.value, ast.Constant)
                    and isinstance(statement.value.value, str)
                ):
                    enums[node.name, statement.targets[0].id] = statement.value.value
    names = _Names()
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if not isinstance(target, ast.Attribute) or target.attr != "tool":
                    continue
                if require_mcp_binding and not (
                    isinstance(target.value, ast.Name) and target.value.id in servers
                ):
                    continue
                name: str | None = node.name
                if isinstance(decorator, ast.Call):
                    options = {keyword.arg: keyword.value for keyword in decorator.keywords}
                    if None in options:
                        continue  # dynamic keywords may replace the default name
                    if "name" in options:
                        name = _literal_name(options["name"], enums)
                    elif decorator.args:
                        name = _literal_name(decorator.args[0], enums)
                names.add(name)
        if isinstance(node, ast.Call):
            target = node.func
            if not (
                isinstance(target, ast.Name)
                and target.id == "Tool"
                or isinstance(target, ast.Attribute)
                and target.attr == "Tool"
            ):
                continue
            if require_mcp_binding and not (_import_target(target, imports) or "").endswith(".Tool"):
                continue
            options = {keyword.arg: keyword.value for keyword in node.keywords}
            if None not in options:
                names.add(_literal_name(options.get("name"), enums))
    return list(names.names)


def mcp_tool_names(
    text: str,
    language: str | None = None,
    *,
    ignored: list[tuple[int, int]] | None = None,
    ignore_spans: list[tuple[int, int]] | None = None,
    max_ast_nodes: int | None = None,
    require_mcp_binding: bool = False,
) -> list[str]:
    """Return supported source registrations; omitted analysis raises explicitly."""
    if ignore_spans is not None:
        if ignored is not None:
            raise ValueError("MCP source ranges were supplied twice")
        ignored = ignore_spans
    if language in {None, "python"}:
        try:
            tree = ast.parse(text)
        except (RecursionError, MemoryError) as exc:
            raise MCPToolLimitError("MCP syntax-tree parsing limit exceeded") from exc
        except (SyntaxError, ValueError):
            if language == "python":
                return []  # invalid source cannot establish registrations
        else:
            return _python_tool_names(
                tree, MAX_MCP_AST_NODES if max_ast_nodes is None else max_ast_nodes, require_mcp_binding
            )
    if language not in {None, "javascript"}:
        return []
    if ignored is None:
        ignored, ambiguous = noncode_ranges(text, "javascript")
        if ambiguous:
            raise MCPToolLimitError("MCP source lexing was incomplete")
    starts = [start for start, _ in ignored]
    ends = [end for _, end in ignored]
    names = _Names()
    for pattern in _REGISTRATIONS:
        for match in pattern.finditer(text):
            preceding = bisect_right(starts, match.start()) - 1
            if preceding >= 0 and match.start() < ends[preceding]:
                continue
            names.add(match.group(1))
    return list(names.names)


def _tokens(name: str) -> set[str]:
    return {word.lower() for part in re.split(r"[_.\-\s]+", name) for word in _WORDS.findall(part)}


def mcp_tool_capabilities(name: str) -> set[str]:
    """Capabilities a tool name implies, by vocabulary."""
    tokens = _tokens(name)
    implied = {capability for capability, words in _VOCABULARY.items() if tokens & words}
    if "run" in tokens and tokens & _RUNNABLE:
        implied.add("code-exec")
    return implied
