"""Capabilities configured on supported import-bound agent constructors.

An SDK's available features are not workload capabilities. These checks read
only bounded AST expressions or complete inline JavaScript option objects;
they never evaluate source or guess the contents of a dynamic collection.
Results are local to one call, so disabling one agent cannot erase another
agent's independently observed capabilities in the same project.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any

from shadowscan.connectors.code.vercel_tools import _object, _parts, _unwrap

# Other frameworks retain their existing signal semantics until their option
# contracts have dedicated tests. In particular, concrete browser/code tools
# must not lose capabilities merely because they have no ``tools`` argument.
CONFIGURED_FRAMEWORKS = frozenset(
    {
        "framework.openai-agents-sdk",
        "framework.crewai",
        "framework.pydantic-ai",
        "framework.langgraph",
        "framework.langchain",
        "framework.genkit",
    }
)


@dataclass(frozen=True)
class CallCapabilities:
    """Attach call-specific capabilities without changing reusable signatures."""

    signature: str
    verified: bool
    configured: set[str]
    span: tuple[int, int]

    def metadata(self, indicator: bool, capabilities: list[str], *, option: bool = False) -> dict[str, Any]:
        metadata: dict[str, Any] = {"verified_agent": indicator}
        if self.signature in CONFIGURED_FRAMEWORKS:
            observed = set(capabilities)
            if self.verified or option:
                observed.difference_update({"tool-use", "multi-agent", "memory"})
                observed.update(self.configured)
            metadata["source_capabilities"] = sorted(observed)
            metadata["configured_call_span"] = self.span
        return metadata


_COLLECTION_OPTIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "framework.openai-agents-sdk": {"tool-use": ("tools",), "multi-agent": ("handoffs",)},
    "framework.crewai": {"tool-use": ("tools",), "multi-agent": ("agents",)},
    "framework.pydantic-ai": {"tool-use": ("tools", "toolsets")},
    "framework.langgraph": {"tool-use": ("tools",), "multi-agent": ("agents",)},
    "framework.langchain": {"tool-use": ("tools",)},
}
_INACTIVE_JS = frozenset({"", "null", "undefined", "false", "true", "0"})

_CONSTRUCTORS = {
    "framework.openai-agents-sdk": frozenset({"Agent"}),
    "framework.crewai": frozenset({"Agent", "Crew"}),
    "framework.pydantic-ai": frozenset({"Agent"}),
    "framework.langgraph": frozenset(
        {"create_react_agent", "createReactAgent", "create_supervisor", "create_swarm", "StateGraph"}
    ),
}


def _configured_constructor(signature: str, symbol: str) -> bool:
    if signature == "framework.langchain":
        return bool(
            re.fullmatch(
                r"(?:AgentExecutor|initialize_agent|create_\w*agent|createReactAgent|createToolCallingAgent)",
                symbol,
            )
        )
    return symbol in _CONSTRUCTORS.get(signature, ())


def _python_entry(value: ast.AST) -> bool:
    return isinstance(value, (ast.Name, ast.Attribute, ast.Call)) or (
        isinstance(value, ast.Dict) and bool(value.keys) and all(key is not None for key in value.keys)
    )


def _python_collection(value: ast.AST | None) -> bool:
    """Recognize explicit collection entries; empty and dynamic values stay unknown."""
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return any(_python_entry(item) for item in value.elts)
    if isinstance(value, ast.Dict) and all(key is not None for key in value.keys):
        return any(_python_entry(item) for item in value.values)
    return False


def _javascript_collection(raw: str, masked: str) -> bool:
    array = _unwrap(raw, masked, "[")
    if array is not None:
        # A spread has unknown contents; an explicit entry alongside it can
        # still establish configuration because an array spread cannot replace it.
        return any(
            code.strip() not in _INACTIVE_JS
            and not code.lstrip().startswith("...")
            and (
                bool(_object(source, code))
                if code.lstrip().startswith("{")
                else bool(re.match(r"\s*[A-Za-z_$]", code))
            )
            for source, code in _parts(*array) or []
        )
    fields = _object(raw, masked)
    return fields is not None and any(
        code.strip() not in _INACTIVE_JS and bool(re.match(r"\s*(?:[A-Za-z_$]|\{)", code))
        for _, code in fields.values()
    )


def configured_capabilities(
    signature: str,
    symbol: str,
    *,
    node: ast.Call | None,
    arguments: str,
    masked: str,
    verified_graph: bool = False,
) -> set[str]:
    """Return capabilities supported by literal options of a known SDK call."""
    if signature not in CONFIGURED_FRAMEWORKS or not _configured_constructor(signature, symbol):
        return set()
    result = {"tool-use"} if verified_graph else set()
    if node is not None:
        # **options may supply or conflict with any option. It cannot establish
        # additional configuration without resolving a separate data flow.
        if any(keyword.arg is None for keyword in node.keywords):
            return result
        values = {keyword.arg: keyword.value for keyword in node.keywords}
        # The documented positional tool argument of these Python factories.
        position = (
            0
            if signature == "framework.langchain" and symbol == "initialize_agent"
            else 1
            if signature in {"framework.langchain", "framework.langgraph"}
            and symbol in {"create_agent", "create_react_agent", "create_tool_calling_agent"}
            else None
        )
        if "tools" not in values and position is not None and len(node.args) > position:
            values["tools"] = node.args[position]
        for capability, names in _COLLECTION_OPTIONS[signature].items():
            if signature == "framework.crewai" and (
                capability == "multi-agent"
                and symbol != "Crew"
                or capability == "tool-use"
                and symbol != "Agent"
            ):
                continue
            if any(_python_collection(values.get(name)) for name in names):
                result.add(capability)
        if signature == "framework.crewai" and symbol == "Agent":
            delegation = values.get("allow_delegation")
            if isinstance(delegation, ast.Constant) and delegation.value is True:
                result.add("multi-agent")
        if signature == "framework.langgraph" and any(
            isinstance(values.get(name), (ast.Call, ast.Name, ast.Attribute))
            for name in ("checkpointer", "store")
        ):
            result.add("memory")
        return result

    inner = _unwrap(arguments, masked, "(")
    options = _object(*inner) if inner is not None else None
    if options is None:
        return result
    for capability, names in _COLLECTION_OPTIONS[signature].items():
        if any(name in options and _javascript_collection(*options[name]) for name in names):
            result.add(capability)
    if signature == "framework.langgraph" and any(
        name in options
        and options[name][1].strip() not in _INACTIVE_JS
        and bool(re.match(r"\s*[A-Za-z_$]", options[name][1]))
        for name in ("checkpointer", "store")
    ):
        result.add("memory")
    return result
