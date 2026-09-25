"""Structural evidence for agent manifests and low-code configuration.

These are discovery checks, not substitutes for a vendor's versioned schema
validator. Descriptive strings are never evaluated as source code. A filename
only selects a parser; it does not establish an agent or a deployment.
"""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import chain
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from shadowscan.signatures.matcher import Match, SignatureIndex
from shadowscan.utils.safe_yaml import bounded_safe_load, bounded_safe_load_all


@dataclass(slots=True)
class AgentManifestResult:
    data: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)
    valid: bool = False


def agent_manifest_kind(rel: str) -> str | None:
    path = PurePosixPath(rel)
    name = path.name.lower()
    if name in {"agent-card.json", "agent_card.json"} or name == "agent.json" and ".well-known" in path.parts:
        return "a2a"
    if name.startswith("declarativeagent") and path.suffix.lower() == ".json":
        return "m365"
    if name == "langgraph.json":
        return "langgraph"
    if name in {"agents.yaml", "agents.yml"} and "config" in path.parts:
        return "crewai"
    return None


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _choice(value: Any, values: set[str]) -> bool:
    return isinstance(value, str) and value in values


def _http_url(value: Any) -> bool:
    if not _nonempty(value) or any(char.isspace() for char in value):
        return False
    try:
        url = urlsplit(value)
        return url.scheme in {"https", "http"} and bool(url.hostname) and not url.username and not url.password
    except ValueError:
        return False


def _service_endpoint(value: Any, transport: Any = None) -> bool:
    if _http_url(value):
        return True
    if not _nonempty(value) or not isinstance(transport, str) or transport.upper() != "GRPC":
        return False
    try:
        address = urlsplit("//" + value)
        return bool(address.hostname) and address.port is not None and not (
            address.path or address.query or address.fragment or address.username or address.password
        ) and not any(char.isspace() for char in value)
    except ValueError:
        return False


def _list_of_objects(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def parse_agent_manifest(rel: str, text: str, kind: str) -> AgentManifestResult:
    """Validate substantive declarations without executing or importing them.

    LangGraph: graph entry points. A2A: identity, HTTP/gRPC endpoint, capabilities and
    named skills (0.x URL and 1.x interfaces supported). Microsoft 365: named,
    versioned instructions. CrewAI: role, goal and backstory for every agent.
    Unknown optional fields are retained for forward-compatible discovery.
    """
    result = AgentManifestResult()
    try:
        data = bounded_safe_load(text) if PurePosixPath(rel).suffix.lower() in {".yaml", ".yml"} else json.loads(text)
    except (ValueError, RecursionError, yaml.YAMLError):
        result.errors.append("invalid agent manifest syntax")
        return result
    if not isinstance(data, dict):
        result.errors.append("agent manifest must be an object")
        return result
    result.data = data
    errors = result.errors
    if kind == "langgraph":
        graphs = data.get("graphs")
        if not isinstance(graphs, dict) or not graphs:
            errors.append("LangGraph manifest requires a nonempty graphs object")
        elif any(not _nonempty(name) or not _graph_entrypoint(entry) for name, entry in graphs.items()):
            errors.append("LangGraph graph entries require a name and module-or-path:symbol entry point")
        if "dependencies" in data and (
            not isinstance(data["dependencies"], list) or not all(_nonempty(dep) for dep in data["dependencies"])
        ):
            errors.append("LangGraph dependencies must be an array of nonempty strings")
        if "env" in data and not isinstance(data["env"], (str, dict)):
            errors.append("LangGraph env must be a file path or object")
    elif kind == "a2a":
        for key in ("name", "version"):
            if not _nonempty(data.get(key)):
                errors.append(f"A2A card requires a nonempty {key}")
        interfaces = data.get("supportedInterfaces", data.get("supported_interfaces", data.get("additionalInterfaces", [])))
        if not _list_of_objects(interfaces):
            errors.append("A2A interfaces must be an array of objects")
            interfaces = []
        if not _service_endpoint(data.get("url"), data.get("preferredTransport")) and not any(
            _service_endpoint(item.get("url"), item.get("protocolBinding", item.get("protocol_binding", item.get("transport"))))
            for item in _objects(interfaces)
        ):
            errors.append("A2A card requires an HTTP(S) or declared gRPC service endpoint")
        if not isinstance(data.get("capabilities"), dict):
            errors.append("A2A card requires a capabilities object")
        skills = data.get("skills")
        if not _list_of_objects(skills) or not skills or any(
            not _nonempty(skill.get("id")) or not _nonempty(skill.get("name")) for skill in skills
        ):
            errors.append("A2A card requires nonempty skills with string id and name")
        for key in ("defaultInputModes", "defaultOutputModes"):
            if key in data and (not isinstance(data[key], list) or not all(_nonempty(mode) for mode in data[key])):
                errors.append(f"A2A {key} must be an array of strings")
    elif kind == "m365":
        for key in ("name", "version", "description", "instructions"):
            if not _nonempty(data.get(key)):
                errors.append(f"M365 agent manifest requires a nonempty {key}")
        for key in ("capabilities", "actions", "conversation_starters"):
            if key in data and not _list_of_objects(data[key]):
                errors.append(f"M365 {key} must be an array of objects")
    elif kind == "crewai":
        if not data or any(
            not _nonempty(name) or not isinstance(agent, dict)
            or not all(_nonempty(agent.get(key)) for key in ("role", "goal", "backstory"))
            for name, agent in data.items()
        ):
            errors.append("CrewAI definitions require named agents with role, goal and backstory")
    else:
        errors.append("unsupported agent manifest kind")
    result.valid = not errors
    return result


def _graph_entrypoint(value: Any) -> bool:
    # Import paths, Python file paths and JavaScript file paths are valid. This
    # checks declarations only: a scan must never import the referenced module.
    if isinstance(value, dict):
        value = value.get("path")
    if not _nonempty(value) or ":" not in value or any(char.isspace() for char in value):
        return False
    module, symbol = value.rsplit(":", 1)
    return bool(re.fullmatch(r"[A-Za-z0-9_./@$-]+", module)) and bool(re.fullmatch(r"[A-Za-z_$][\w.$]*", symbol))


def _objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, list):
        yield from (item for item in value if isinstance(item, dict))


def _projected_signals(data: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """Project operational schema fields; never traverse arbitrary metadata."""
    # n8n exports place executable node types directly below nodes[]. Neither
    # a description mentioning a node type nor a disabled node is evidence.
    for node in _objects(data.get("nodes")):
        node_type = node.get("type")
        if "disabled" in node and node["disabled"] is not False:
            continue
        if isinstance(node_type, str) and node_type.startswith(("@n8n/n8n-nodes-langchain.", "n8n-nodes-base.")):
            yield "platform.n8n", json.dumps({"type": node_type})
        node_data = node.get("data")
        if not isinstance(node_data, dict):
            continue
        if _choice(node_data.get("category"), {"Agents", "Multi Agents", "Sequential Agents", "Agentflow"}) and _nonempty(node_data.get("name")):
            yield "platform.flowise", json.dumps({"category": node_data["category"], "name": node_data["name"]})
        if node_data.get("type") == "Agent" and isinstance(node_data.get("node"), dict):
            yield "platform.langflow", json.dumps({"type": "Agent", "display_name": "Agent"})
    # Langflow wraps its graph in a data object; only enter that known graph
    # shape, not descriptions, samples, or arbitrary nested dictionaries.
    graph = data.get("data")
    if isinstance(graph, dict) and isinstance(graph.get("nodes"), list) and isinstance(graph.get("edges"), list):
        for node in _objects(graph["nodes"]):
            node_data = node.get("data")
            if isinstance(node_data, dict) and node_data.get("type") == "Agent" and isinstance(node_data.get("node"), dict):
                yield "platform.langflow", json.dumps({"type": "Agent", "display_name": "Agent"})
    # Dify's top-level app identity plus an actual model/workflow declaration.
    app = data.get("app")
    if data.get("kind") == "app" and isinstance(app, dict) and _choice(app.get("mode"), {"agent-chat", "advanced-chat", "workflow", "completion", "chat"}):
        model = data.get("model_config")
        workflow = data.get("workflow")
        model_spec = model.get("model") if isinstance(model, dict) else None
        graph_spec = workflow.get("graph") if isinstance(workflow, dict) else None
        has_model = isinstance(model_spec, dict) and _nonempty(model_spec.get("provider")) and _nonempty(model_spec.get("name"))
        has_nodes = isinstance(graph_spec, dict) and any(
            isinstance(node.get("data"), dict) and _choice(node["data"].get("type"), {"agent", "llm", "tool"})
            for node in _objects(graph_spec.get("nodes"))
        )
        if has_model or has_nodes:
            has_agent_nodes = isinstance(graph_spec, dict) and any(
                isinstance(node.get("data"), dict) and node["data"].get("type") == "agent"
                for node in _objects(graph_spec.get("nodes"))
            )
            declaration = "kind: app\nmode: " + app["mode"]
            if app["mode"] == "agent-chat" or has_agent_nodes:
                declaration += "\nagent_mode:\n  enabled: true"
            yield "platform.dify", declaration
    # Make blueprint modules are under flow[] (routes have nested flow[]).
    pending = list(_objects(data.get("flow")))
    visited = 0
    while pending and visited < 10000:
        step = pending.pop()
        visited += 1
        module = step.get("module")
        if _nonempty(module):
            yield "platform.make", json.dumps({"module": module})
        for route in _objects(step.get("routes")):
            pending.extend(_objects(route.get("flow")))
    if pending:
        raise ValueError("structured workflow exceeds the 10000 step inspection limit")
    # Recipes must include an executable step, not a prose provider mention.
    for step in _objects(data.get("code", data.get("steps"))):
        if _nonempty(step.get("provider")) and _nonempty(step.get("name", step.get("operation"))):
            yield "platform.workato", json.dumps({"provider": step["provider"]})
    if _choice(data.get("kind"), {"AdaptiveDialog", "GptComponentMetadata", "OnRecognizedIntent", "CustomTopic", "TaskDialog", "ConversationalTopic"}) and (
        isinstance(data.get("beginDialog"), dict) or isinstance(data.get("actions"), list)
    ):
        yield "platform.copilot-studio", "kind: " + data["kind"]
    # Gateways: structural configuration, without promoting arbitrary prompts.
    models = data.get("model_list")
    if isinstance(models, list) and any(_nonempty(model.get("model_name")) and isinstance(model.get("litellm_params"), dict) and _nonempty(model["litellm_params"].get("model")) for model in _objects(models)):
        yield "platform.litellm", "model_list:\n"
    for plugin in _objects(data.get("plugins")):
        if _nonempty(plugin.get("name")) and isinstance(plugin.get("config"), dict):
            yield "platform.kong-ai-gateway", "name: " + plugin["name"]
    # Azure/Power Platform workflow actions have operational inputs. Select
    # only known connection fields, never prompt text or descriptions.
    definition = data.get("definition")
    if not isinstance(definition, dict):
        properties = data.get("properties")
        definition = properties.get("definition") if isinstance(properties, dict) else None
    if isinstance(definition, dict) and isinstance(definition.get("actions"), dict):
        for action in definition["actions"].values():
            if not isinstance(action, dict) or not isinstance(action.get("inputs"), dict):
                continue
            inputs = action["inputs"]
            host = inputs.get("host") if isinstance(inputs.get("host"), dict) else {}
            connection = inputs.get("serviceProviderConfiguration")
            projection: dict[str, Any] = {
                "host": {key: host[key] for key in ("apiId", "operationId", "connectionName") if isinstance(host.get(key), str)},
                "serviceProviderConfiguration": {
                    key: connection[key] for key in ("serviceProviderId", "operationId", "connectionName")
                    if isinstance(connection, dict) and isinstance(connection.get(key), str)
                },
            }
            if action.get("type") == "Agent":
                projection.update({"type": "Agent", "inputs": {}})
            yield "cloud.azure-logic-apps-ai", json.dumps(projection)
            yield "platform.power-platform-ai", json.dumps(projection)
    for query in _objects(data.get("queries")):
        if _choice(query.get("type"), {"AIAgentQuery", "RetoolAIQuery", "AgentQuery"}):
            yield "platform.retool", json.dumps({"type": query["type"]})


def _coding_agent_signals(rel: str, data: dict[str, Any]) -> Iterator[tuple[str, str]]:
    path = PurePosixPath(rel)
    if ".claude" in path.parts and path.name in {"settings.json", "settings.local.json"}:
        permissions = data.get("permissions")
        if isinstance(permissions, dict):
            if permissions.get("defaultMode") == "bypassPermissions":
                yield "coding-agent.claude-code", json.dumps({"defaultMode": "bypassPermissions"})
            allow = permissions.get("allow")
            if isinstance(allow, list) and "Bash(*)" in allow:
                yield "coding-agent.claude-code", json.dumps({"permissions": {"allow": ["Bash(*)"]}})
    if ".codex" in path.parts and path.name == "config.toml":
        active = data.copy()
        profiles, profile = data.get("profiles"), data.get("profile")
        if isinstance(profiles, dict) and isinstance(profile, str) and isinstance(profiles.get(profile), dict):
            active.update(profiles[profile])
        for key, expected in (("approval_policy", "never"), ("sandbox_mode", "danger-full-access")):
            if active.get(key) == expected:
                yield "coding-agent.openai-codex", key + ' = "' + expected + '"'
    if ".gemini" in path.parts and path.name == "settings.json" and data.get("approvalMode") == "yolo":
        yield "coding-agent.gemini-cli", json.dumps({"approvalMode": "yolo"})


def structured_code_matches(
    index: SignatureIndex, rel: str, text: str, errors: list[str] | None = None,
) -> list[Match]:
    """Match recognized operational config shapes, preserving signature policy.

    Dependency/container/IaC declarations are handled by manifests.py. Agent
    cards and MCP configs have their own validators. Unknown configuration
    formats deliberately do not fall back to scanning arbitrary prose as code.
    """
    issues = errors if errors is not None else []
    extension = PurePosixPath(rel).suffix.lower()
    try:
        if extension in {".yaml", ".yml"}:
            documents = bounded_safe_load_all(text)
        elif extension == ".json":
            documents = [json.loads(text)]
        elif extension == ".toml":
            documents = [tomllib.loads(text)]
        elif extension in {".xml", ".props", ".targets", ".csproj", ".fsproj", ".vbproj"}:
            # ElementTree never resolves external entities. XML examples in
            # descriptions/CDATA do not become active Salesforce metadata.
            root = ET.fromstring(text)
            tag = root.tag.rsplit("}", 1)[-1]
            if tag in {"GenAiPlanner", "GenAiPlugin", "GenAiFunction", "GenAiPromptTemplate", "BotDefinition", "BotVersion"} and len(root):
                return _matches(index, "platform.salesforce-agentforce", "<" + tag + ">")
            return []
        else:
            return []
    except (ValueError, RecursionError, yaml.YAMLError, ET.ParseError):
        issues.append("invalid structured configuration syntax")
        return []
    matches: list[Match] = []
    seen: set[tuple[str, str]] = set()
    for data in documents:
        if not isinstance(data, dict):
            continue
        for signature, projection in chain(_projected_signals(data), _coding_agent_signals(rel, data)):
            if (signature, projection) in seen:
                continue
            seen.add((signature, projection))
            matches.extend(_matches(index, signature, projection))
    return matches


def _matches(index: SignatureIndex, signature: str, projection: str) -> list[Match]:
    matches = [
        match for match in index.match_code(projection, None)
        # n8n model nodes (lmChatOpenAi, lmChatAnthropic...) also name the
        # provider that receives the workflow's data.
        if match.signature_id == signature or (signature == "platform.n8n" and match.signature.category == "provider")
    ]
    for match in matches:
        # Projection offsets are not source line numbers. Do not claim an
        # unrelated source line is the evidence location.
        match.line = None
        match.extra["structured_config"] = True
        if signature == "platform.n8n":
            node_type = json.loads(projection).get("type", "")
            match.extra["verified_agent"] = match.signature_id == signature and node_type in {
                "@n8n/n8n-nodes-langchain.agent", "@n8n/n8n-nodes-langchain.agentTool",
                "@n8n/n8n-nodes-langchain.openAiAssistant",
            }
        elif signature == "platform.dify":
            match.extra["verified_agent"] = "agent_mode:\n  enabled: true" in projection
    return matches
