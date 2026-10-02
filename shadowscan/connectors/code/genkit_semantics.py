"""Conservative configured-agent and automatic tool-loop evidence for Genkit.

Only calls on an import-bound, stable Genkit instance reach these checks.
Initialization, ordinary flows and standalone tool declarations do not define
an agent. A generate call establishes an automatic loop only with a callback
registered on that same instance and without disabled or uncertain dispatch.
"""

from __future__ import annotations

import re

from shadowscan.connectors.code.vercel_tools import _execution_callback, _literal, _object, _parts, _unwrap

_AGENT_METHODS = frozenset({"Genkit.defineAgent", "Genkit.definePromptAgent", "Genkit.defineCustomAgent"})
_GENERATION_METHODS = frozenset({"Genkit.generate", "Genkit.generateStream"})


def genkit_tool_registration(arguments: str, masked: str) -> str | None:
    """Return the declared name of a complete tool definition with a callable handler."""
    inner = _unwrap(arguments, masked, "(")
    parts = _parts(*inner) if inner is not None else None
    if parts is None or len(parts) != 2:
        return None
    options = _object(*parts[0])
    if not options or "name" not in options or not _execution_callback(*parts[1]):
        return None
    name = _literal(options["name"][0])
    return name if name else None


def genkit_call_capabilities(
    method: str,
    arguments: str,
    masked: str,
    registered_tools: tuple[str, ...],
    *,
    constructed: bool,
) -> tuple[bool, set[str]]:
    """Return explicit agent presence and configured capabilities of this call."""
    if not constructed or method not in _AGENT_METHODS | _GENERATION_METHODS:
        return False, set()
    inner = _unwrap(arguments, masked, "(")
    options = _object(*inner) if inner is not None else None
    agent = method in _AGENT_METHODS
    if not options:
        return agent, set()
    # Returning tool requests delegates execution to the caller. Unknown
    # options cannot establish the SDK's automatic execution loop.
    if "returnToolRequests" in options and options["returnToolRequests"][1].strip() != "false":
        return agent, set()
    if "toolChoice" in options and _literal(options["toolChoice"][0]) not in {"auto", "required"}:
        return agent, set()
    if "tools" not in options:
        return agent, set()
    tools = _unwrap(*options["tools"], "[")
    if tools is None:
        return agent, set()
    enabled = any(
        (
            "variable:" + code.strip() in registered_tools
            if re.fullmatch(r"\s*[A-Za-z_$][\w$]*\s*", code)
            else "name:" + str(_literal(raw)) in registered_tools
        )
        for raw, code in _parts(*tools) or []
    )
    return agent or enabled, {"tool-use"} if enabled else set()
