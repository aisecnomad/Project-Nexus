"""What an MCP server can do, read from the tools it registers.

An MCP server's risk is the set of tools it exposes to whichever model
connects: ``write_file`` and ``git_commit`` change data, ``fetch`` reaches
the web, ``run_command`` executes code. Vendor-neutral idioms elsewhere in
the server's source (a ``thought:`` schema field, a ``while`` loop) say
nothing about that, so capabilities of an MCP tool server come from here.

Extraction is lexical and bounded: literal tool names in common Python and
TypeScript SDK registration forms, including string enums referenced by
``Tool(name=Enum.MEMBER)``. Names are mapped to capabilities by vocabulary;
the mapping is deliberately conservative and every implied capability is
reported with the tool names behind it.
"""

from __future__ import annotations

import re

MAX_TOOLS_PER_FILE = 100
_NAME = r"([A-Za-z][A-Za-z0-9_.-]{0,63})"

_REGISTRATIONS = (
    # TypeScript/JavaScript SDK: server.registerTool("name", ...), server.tool("name", ...)
    re.compile(r"\.(?:registerTool|tool)\(\s*[\"'`]" + _NAME + r"[\"'`]"),
    # Tool schema objects in a list_tools handler: { name: "x", description: ... }
    re.compile(r"\bname\s*:\s*[\"'`]" + _NAME + r"[\"'`]\s*,\s*(?:title\s*:\s*[^\n]{0,200}\n\s*)?description\s*:"),
    # Python: types.Tool(name="x", ...)
    re.compile(r"\bTool\(\s*name\s*=\s*[\"']" + _NAME + r"[\"']"),
    # Python decorators with an explicit name: @mcp.tool(name="x")
    re.compile(r"@\w+\.tool\(\s*name\s*=\s*[\"']" + _NAME + r"[\"']"),
)
# Python decorators naming the tool after the function: @mcp.tool() / @server.tool
_DECORATED = re.compile(r"@\w+\.tool(?:\(\s*\))?[ \t]*\r?\n(?:[ \t]*@[^\n]{0,200}\n){0,3}[ \t]*(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w{0,63})\s*\(")
_ENUM_CLASS = re.compile(r"^class[ \t]+(\w+)\((?:str,[ \t]*)?(?:Str)?Enum\):[ \t]*\r?\n((?:[ \t]+[^\n]*\n|[ \t]*\r?\n){1,200})", re.MULTILINE)
_ENUM_TOOL_NAME = re.compile(r"\bTool\(\s*name\s*=\s*(\w+)\.")
_ENUM_MEMBER = re.compile(r"^[ \t]+[A-Z][A-Z0-9_]*[ \t]*=[ \t]*[\"']([a-z][a-z0-9_.-]{0,63})[\"']", re.MULTILINE)

_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")

_VOCABULARY: dict[str, frozenset[str]] = {
    "code-exec": frozenset({
        "exec", "execute", "shell", "bash", "command", "commands", "cmd", "eval", "terminal", "script",
        "powershell", "subprocess", "interpreter",
    }),
    "data-access": frozenset({
        "file", "files", "directory", "directories", "dir", "dirs", "folder", "folders", "path", "paths",
        "sql", "query", "database", "db", "table", "tables", "record", "records", "git", "repo", "repository",
    }),
    "browsing": frozenset({"fetch", "browse", "browser", "navigate", "url", "urls", "http", "https", "web", "scrape", "crawl", "screenshot", "website"}),
    "memory": frozenset({"memory", "memories", "remember", "recall", "entity", "entities", "observations", "relations", "knowledge"}),
    "saas-actions": frozenset({"send", "email", "mail", "slack", "tweet", "issue", "issues", "ticket", "tickets", "publish", "deploy", "payment", "transfer"}),
}
_RUNNABLE = frozenset({"code", "script", "command", "python", "shell", "program"})


def mcp_tool_names(text: str) -> list[str]:
    """Literal tool names registered in one source file, in first-seen order."""
    names: dict[str, None] = {}

    def add(name: str) -> bool:
        names.setdefault(name, None)
        return len(names) >= MAX_TOOLS_PER_FILE

    for pattern in (*_REGISTRATIONS, _DECORATED):
        for match in pattern.finditer(text):
            if add(match.group(1)):
                return list(names)
    # One pass collects the enums used as tool names; searching the whole
    # text once per enum class was quadratic in files with many enums.
    referenced = set(_ENUM_TOOL_NAME.findall(text))
    for enum in _ENUM_CLASS.finditer(text):
        if enum.group(1) in referenced:
            for member in _ENUM_MEMBER.finditer(enum.group(2)):
                if add(member.group(1)):
                    return list(names)
    return list(names)


def _tokens(name: str) -> set[str]:
    return {word.lower() for part in re.split(r"[_.\-\s]+", name) for word in _WORDS.findall(part)}


def mcp_tool_capabilities(name: str) -> set[str]:
    """Capabilities a tool name implies, by vocabulary."""
    tokens = _tokens(name)
    implied = {capability for capability, words in _VOCABULARY.items() if tokens & words}
    if "run" in tokens and tokens & _RUNNABLE:
        implied.add("code-exec")
    return implied
