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
from collections.abc import Mapping
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
        "framework.google-adk",
        "framework.aws-strands",
        "framework.autogen",
        "framework.llamaindex",
        "framework.semantic-kernel",
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
                if self.signature == "framework.llamaindex":
                    observed.discard("rag")  # an agent/tool retriever need not retrieve documents
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
    "framework.google-adk": frozenset({"Agent", "LlmAgent", "SequentialAgent", "ParallelAgent", "LoopAgent"}),
    "framework.aws-strands": frozenset({"Agent", "Swarm"}),
    "framework.autogen": frozenset(
        {
            "AssistantAgent",
            "ConversableAgent",
            "UserProxyAgent",
            "RoundRobinGroupChat",
            "SelectorGroupChat",
            "MagenticOneGroupChat",
            "Swarm",
        }
    ),
    "framework.llamaindex": frozenset(
        {
            "FunctionAgent",
            "ReActAgent",
            "FunctionCallingAgent",
            "OpenAIAgent",
            "CodeActAgent",
            "AgentWorkflow",
        }
    ),
    "framework.semantic-kernel": frozenset({"ChatCompletionAgent"}),
}


def _configured_constructor(signature: str, symbol: str) -> bool:
    if signature == "framework.llamaindex" and symbol.endswith(".from_tools"):
        symbol = symbol.removesuffix(".from_tools")
    if signature == "framework.langchain":
        return bool(
            re.fullmatch(
                r"(?:AgentExecutor|initialize_agent|create_\w*agent|createReactAgent|createToolCallingAgent)",
                symbol,
            )
        )
    return symbol in _CONSTRUCTORS.get(signature, ())


def python_tool_argument_position(signature: str, symbol: str) -> int | None:
    """Return the documented positional tools argument for supported factories."""
    if signature == "framework.langchain" and symbol == "initialize_agent":
        return 0
    if signature in {"framework.langchain", "framework.langgraph"} and symbol in {
        "create_agent",
        "create_react_agent",
        "create_tool_calling_agent",
    }:
        return 1
    return None


def _python_entry(value: ast.AST, *, string_entry: bool = False) -> bool:
    return (
        isinstance(value, (ast.Name, ast.Attribute, ast.Call))
        or (isinstance(value, ast.Dict) and bool(value.keys) and all(key is not None for key in value.keys))
        or (
            string_entry
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and bool(value.value.strip())
        )
    )


def _python_collection(value: ast.AST | None, *, minimum: int = 1, string_entries: bool = False) -> bool:
    """Recognize explicit collection entries; empty and dynamic values stay unknown."""
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return sum(_python_entry(item, string_entry=string_entries) for item in value.elts) >= minimum
    if isinstance(value, ast.Dict) and all(key is not None for key in value.keys):
        return sum(_python_entry(item) for item in value.values) >= minimum
    return False


def _collection_options(signature: str, symbol: str) -> dict[str, tuple[str, ...]]:
    """Known constructor option names, never options from an unrelated runner/model."""
    if signature == "framework.google-adk":
        return {
            "multi-agent": ("sub_agents", "subAgents"),
            **({"tool-use": ("tools",)} if symbol in {"Agent", "LlmAgent"} else {}),
        }
    if signature == "framework.aws-strands":
        return {"tool-use": ("tools",)} if symbol == "Agent" else {"multi-agent": ("nodes",)}
    if signature == "framework.autogen":
        if symbol == "AssistantAgent":
            return {"tool-use": ("tools",), "multi-agent": ("handoffs",)}
        if symbol in {"ConversableAgent", "UserProxyAgent"}:
            return {}
        return {"multi-agent": ("participants",)}
    if signature == "framework.llamaindex":
        return {"multi-agent": ("agents",)} if symbol == "AgentWorkflow" else {"tool-use": ("tools",)}
    if signature == "framework.semantic-kernel":
        return {"tool-use": ("plugins",)}
    return _COLLECTION_OPTIONS[signature]


def _positional_collection(signature: str, symbol: str) -> tuple[str, int] | None:
    position = python_tool_argument_position(signature, symbol)
    if position is not None:
        return "tools", position
    if signature == "framework.aws-strands":
        return ("tools", 2) if symbol == "Agent" else ("nodes", 0)
    if signature == "framework.llamaindex":
        if symbol.endswith(".from_tools"):
            return "tools", 0
        if symbol == "AgentWorkflow":
            return "agents", 0
        if symbol == "FunctionAgent":
            return "tools", 3
    if signature == "framework.autogen" and symbol in {
        "RoundRobinGroupChat",
        "SelectorGroupChat",
        "MagenticOneGroupChat",
        "Swarm",
    }:
        return "participants", 0
    return None


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
    python_literals: Mapping[str, ast.AST] | None = None,
) -> set[str]:
    """Return capabilities supported by literal options of a known SDK call."""
    if signature not in CONFIGURED_FRAMEWORKS or not _configured_constructor(signature, symbol):
        return set()
    result = {"tool-use"} if verified_graph else set()
    collections = _collection_options(signature, symbol)
    if node is not None:
        # **options may supply or conflict with any option. It cannot establish
        # additional configuration without resolving a separate data flow.
        if any(keyword.arg is None for keyword in node.keywords):
            return result
        values = {keyword.arg: keyword.value for keyword in node.keywords}
        if len(values) != len(node.keywords):
            return result  # repeated options do not form a valid runtime call
        # The documented positional tool argument of these Python factories.
        positional = _positional_collection(signature, symbol)
        if positional is not None:
            name, position = positional
            if (
                name not in values
                and len(node.args) > position
                and not any(isinstance(argument, ast.Starred) for argument in node.args[: position + 1])
            ):
                values[name] = node.args[position]
        for capability, names in collections.items():
            if signature == "framework.crewai" and (
                capability == "multi-agent"
                and symbol != "Crew"
                or capability == "tool-use"
                and symbol != "Agent"
            ):
                continue
            if signature == "framework.semantic-kernel" and {
                "function_choice_behavior",
                "arguments",
            }.intersection(values):
                # An explicit behavior may disable invocation, or be overridden
                # by KernelArguments. Do not guess an opaque behavior's contract.
                continue
            candidates: list[tuple[str, ast.AST | None]] = [(name, values.get(name)) for name in names]
            if python_literals:
                candidates = [
                    (name, python_literals.get(value.id) if isinstance(value, ast.Name) else value)
                    for name, value in candidates
                ]
            if any(
                _python_collection(
                    value,
                    # Strands accepts tool names and file paths as strings.
                    # String handoff targets or participant names are not
                    # proof of another AI agent, and other SDKs need objects.
                    string_entries=signature == "framework.aws-strands"
                    and capability == "tool-use"
                    and name == "tools",
                    minimum=2
                    if capability == "multi-agent"
                    and name in {"participants", "agents", "nodes"}
                    and signature in {"framework.autogen", "framework.llamaindex", "framework.aws-strands"}
                    else 1,
                )
                for name, value in candidates
            ):
                result.add(capability)
        if signature == "framework.autogen" and symbol in {
            "AssistantAgent",
            "ConversableAgent",
            "UserProxyAgent",
        }:
            execution = values.get("code_execution_config")
            # Legacy AG2/AutoGen explicitly enables execution with {}, while
            # False disables it. An unknown expression establishes neither.
            if isinstance(execution, ast.Dict) and all(key is not None for key in execution.keys):
                result.add("code-exec")
            mode = values.get("human_input_mode")
            if isinstance(mode, ast.Constant) and mode.value == "NEVER":
                # Autonomy: approval-bypass evidence (the agent never asks a person for input).
                result.add("autonomous")
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
    for capability, names in collections.items():
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
