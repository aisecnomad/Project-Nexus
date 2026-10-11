"""Google Agent Registry and Gemini Enterprise catalogs for ``cloud.gcp``.

Agent Registry (``agentregistry.googleapis.com``) lists agents, MCP servers and endpoints (and,
in ``v1alpha``, skills and publishers) per project and location. It has no approval workflow, so
its records are ``registered``. Gemini Enterprise (Discovery Engine ``v1alpha`` assistant agents)
lists the agents an app offers with an administrator-controlled state, but only those the caller
created or can see: its listing is caller-scoped and never complete.

Both become registry record findings (:mod:`shadowscan.registries`). This module normalizes
their items when they are collected and, once every record of an analysis pass has been read,
computes what those findings carry: exact bindings to observed reasoning engines and Dialogflow
agents, binding coverage, listing completeness and catalog presence.

Items are reduced to an allow-list when they are collected, so a record dump replays exactly what
live analysis saw and never holds an agent card, the userinfo or query of an interface URL, an
icon, a starter prompt or an authorization value. Analysis reduces replayed records the same way.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, TypeGuard
from urllib.parse import urlsplit

from shadowscan.models import Finding
from shadowscan.registries import MAX_BINDINGS, RECORD_KEY, RECORD_SCHEMA
from shadowscan.utils.safe_json import strict_json_loads

AR_REGISTRY = "google-agent-registry"
GE_REGISTRY = "gemini-enterprise"
AR_VERSIONS = ("v1", "v1alpha")
# Agent Registry collections listed per location, and the record kind of their items.
AR_COLLECTIONS = {
    "agents": "agent-registry-agent",
    "mcpServers": "agent-registry-mcp-server",
    "endpoints": "agent-registry-endpoint",
}
AR_ALPHA_COLLECTIONS = {"skills": "agent-registry-skill", "publishers": "agent-registry-publisher"}
GE_AGENT_KIND = "gemini-enterprise-agent"
PUBLISHER_KIND = "agent-registry-publisher"
COVERAGE_KIND = "registry-coverage"
PROJECT_NUMBER_KIND = "project-number"
# Kinds that analysis reads without emitting a finding of their own.
EXTRA_KINDS = (COVERAGE_KIND, PROJECT_NUMBER_KIND, PUBLISHER_KIND)
# Kinds that become registry record findings, with their registry and descriptor type.
RECORD_KINDS = {
    "agent-registry-agent": (AR_REGISTRY, "agent"),
    "agent-registry-mcp-server": (AR_REGISTRY, "mcp"),
    "agent-registry-endpoint": (AR_REGISTRY, "custom"),
    "agent-registry-skill": (AR_REGISTRY, "agent-skills"),
    GE_AGENT_KIND: (GE_REGISTRY, "agent"),
}
_KIND_COLLECTION = {kind: name for name, kind in {**AR_COLLECTIONS, **AR_ALPHA_COLLECTIONS}.items()}
# Observed listings a binding's coverage is read from: catalog and collection per record kind.
VERTEX_CATALOG = "vertex-ai"
DIALOGFLOW_CATALOG = "dialogflow-cx"
OBSERVED_LISTINGS = {
    "reasoning-engine": (VERTEX_CATALOG, "reasoningEngines"),
    "dialogflow-agent": (DIALOGFLOW_CATALOG, "agents"),
}
_COVERAGE_COLLECTIONS = {
    AR_REGISTRY: frozenset({"locations", *AR_COLLECTIONS, *AR_ALPHA_COLLECTIONS}),
    GE_REGISTRY: frozenset({"engines", "assistants", "agents"}),
    VERTEX_CATALOG: frozenset({"reasoningEngines"}),
    DIALOGFLOW_CATALOG: frozenset({"agents"}),
}
_COVERAGE_FIELDS = frozenset(
    {
        "_kind",
        "_project",
        "_location",
        "catalog",
        "collection",
        "api_version",
        "complete",
        "listing_scope",
        "locations",
        "parent",
    }
)
# Agent Registry collections whose items are records: a location is listed completely only
# when every one of them is.
_AR_RECORD_COLLECTIONS = {"v1": tuple(AR_COLLECTIONS), "v1alpha": (*AR_COLLECTIONS, "skills")}
_AR_ATTRIBUTE = "agentregistry.googleapis.com/system/"
_GE_DEFINITIONS = {
    "adkAgentDefinition": "adk",
    "a2aAgentDefinition": "a2a",
    "dialogflowAgentDefinition": "dialogflow",
    "managedAgentDefinition": "managed",
}
_GE_REASONS = ("rejection", "suspension", "deploymentFailure", "creationFailure")
# Gemini Enterprise agent states. An administrator enables an agent for the app's users.
_GE_STATUS = {
    "ENABLED": "approved",
    "CONFIGURED": "draft",
    "CREATING": "draft",
    "DEPLOYING": "draft",
    "DISABLED": "blocked",
    "SUSPENDED": "blocked",
}
_SKILL_STATUS = {
    "STATE_ACTIVE": "registered",
    "STATE_CREATING": "draft",
    "STATE_DRAFT": "draft",
    "STATE_DISABLED": "blocked",
    "STATE_DEPRECATED": "deprecated",
    "STATE_DECOMMISSIONED": "deprecated",
    "STATE_DELETING": "deprecated",
}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
MAX_CARD_BYTES = 64 * 1024
_MAX_URL = 2048
_MAX_LIST = 50
_MAX_HINTS = 10

_SEGMENT = re.compile(r"[^/\s?#]+")
PROJECT = re.compile(r"[A-Za-z0-9._:-]+")
_NUMBER = re.compile(r"[0-9]+")
LOCATION = re.compile(r"[a-z][a-z0-9-]*")
COLLECTION_ID = re.compile(r"[a-z0-9][a-z0-9_-]*")
_RESOURCE = re.compile(
    r"projects/(?P<project>[A-Za-z0-9._:-]+)/locations/(?P<location>[a-z][a-z0-9-]*)"
    r"/(?P<collection>[A-Za-z]+)/(?P<id>[^/\s?#]+)"
)
_REGISTRY_NAME = re.compile(
    r"(?://agentregistry\.googleapis\.com/)?projects/([A-Za-z0-9._:-]+)/locations/([a-z][a-z0-9-]*)"
)
_RUNTIME_REFERENCE = re.compile(
    r"//(?:[a-z0-9-]+-)?(?P<service>aiplatform|dialogflow)\.googleapis\.com/(?P<resource>projects/.+)"
)
# Any reference on a Vertex AI or Dialogflow host, in whatever form (scheme, version segment).
_RUNTIME_HOST = re.compile(r"(?:https?:)?//(?:[a-z0-9-]+-)?(?:aiplatform|dialogflow)\.googleapis\.com/", re.I)
# Discovery Engine names that become authenticated request paths.
ENGINE_NAME = re.compile(
    r"projects/(?P<project>[A-Za-z0-9._:-]+)/locations/(?P<location>global|us|eu)"
    r"/collections/(?P<collection>[a-z0-9][a-z0-9_-]*)/engines/[A-Za-z0-9_-]+"
)
_ASSISTANT_SUFFIX = re.compile(r"/assistants/[A-Za-z0-9_-]+")
_CARD_TEXT = {"name": 200, "version": 64, "protocol_version": 32, "preferred_transport": 32, "provider": 200}
_CARD_COUNTS = ("security_requirements", "signatures")
_TOOL_HINTS = {"read_only": "readOnlyHint", "destructive": "destructiveHint", "open_world": "openWorldHint"}


def _text(value: Any, limit: int = 200) -> str | None:
    """A bounded nonempty string, or None for anything else."""
    if not isinstance(value, str) or not value:
        return None
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _dig(value: Any, *path: str) -> Any:
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _dicts(value: Any, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)][:limit] if isinstance(value, list) else []


def _texts(value: Any, limit: int = 128) -> list[str]:
    items = value if isinstance(value, list) else []
    return [text for item in items[:_MAX_LIST] if (text := _text(item, limit))]


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _count(value: Any) -> int:
    return value if type(value) is int and value >= 0 else 0


def _safe_segment(value: str) -> bool:
    return value not in {".", ".."}


def is_number(value: str) -> bool:
    return bool(_NUMBER.fullmatch(value))


def valid_project(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and bool(PROJECT.fullmatch(value)) and _safe_segment(value)


def valid_location(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and bool(LOCATION.fullmatch(value))


def normalize_url(value: Any) -> str | None:
    """The exact join form of a URL: lowercase scheme and host, no default port, userinfo, query, fragment."""
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_URL:
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port is not None and port != _DEFAULT_PORTS[scheme] else ""
    return f"{scheme}://{host}{suffix}{parts.path}"


def urls(*values: Any) -> list[str]:
    """Distinct URLs in join form; values that are not usable URLs are dropped."""
    found = [url for value in values if (url := normalize_url(value))]
    return list(dict.fromkeys(found))[:_MAX_LIST]


def _scheme_type(value: Any) -> str:
    """An A2A security scheme's type: 0.3 cards name it in ``type``, 1.0 by a ``*SecurityScheme`` key."""
    if isinstance(value, dict):
        if isinstance(value.get("type"), str):
            return str(value["type"])[:32]
        keys = [key for key in value if isinstance(key, str) and key.endswith("SecurityScheme")]
        if len(keys) == 1:
            return keys[0][: -len("SecurityScheme")][:32]
    return "unknown"


def summarize_card(card: Any) -> dict[str, Any] | None:
    """An A2A agent card reduced to what discovery needs: scheme names only, URLs in join form."""
    if not isinstance(card, dict):
        return None
    schemes = card.get("securitySchemes")
    scheme_map = schemes if isinstance(schemes, dict) else {}
    names = sorted(str(name)[:64] for name in scheme_map)[:20]
    # A2A 0.2 cards declared ``authentication: {schemes: [...]}`` instead.
    names += sorted(_texts(_dig(card, "authentication", "schemes"), 64))[:20]
    extensions = _dig(card, "capabilities", "extensions")
    return clean_card(
        {
            "name": card.get("name"),
            "url": card.get("url"),
            "additional_urls": [item.get("url") for item in _dicts(card.get("additionalInterfaces"), 10)],
            "version": card.get("version"),
            "protocol_version": card.get("protocolVersion"),
            "preferred_transport": card.get("preferredTransport"),
            "skills": [skill.get("id") or skill.get("name") for skill in _dicts(card.get("skills"))],
            "capabilities": {
                "streaming": _dig(card, "capabilities", "streaming"),
                "push_notifications": _dig(card, "capabilities", "pushNotifications"),
                "extensions": len(extensions) if isinstance(extensions, list) else 0,
            },
            "security_schemes": names,
            "security_scheme_types": sorted({_scheme_type(value) for value in scheme_map.values()}),
            "security_requirements": len(card["security"]) if isinstance(card.get("security"), list) else 0,
            "signatures": len(card["signatures"]) if isinstance(card.get("signatures"), list) else 0,
            "provider": _dig(card, "provider", "organization"),
        }
    )


def clean_card(summary: Any) -> dict[str, Any] | None:
    """Keep only the fields and value types of a card summary (a replayed one may hold anything)."""
    if not isinstance(summary, dict):
        return None
    capabilities = summary.get("capabilities")
    return {
        **{key: _text(summary.get(key), limit) for key, limit in _CARD_TEXT.items()},
        "url": normalize_url(summary.get("url")),
        "additional_urls": urls(*(summary.get("additional_urls") or []))[:10]
        if isinstance(summary.get("additional_urls"), list)
        else [],
        "skills": _texts(summary.get("skills")),
        "capabilities": {
            "streaming": _flag(_dig(capabilities, "streaming")),
            "push_notifications": _flag(_dig(capabilities, "push_notifications")),
            "extensions": _count(_dig(capabilities, "extensions")),
        },
        "security_schemes": _texts(summary.get("security_schemes"), 64)[:20],
        "security_scheme_types": _texts(summary.get("security_scheme_types"), 32)[:10],
        **{key: _count(summary.get(key)) for key in _CARD_COUNTS},
    }


def clean_tools(tools: Any) -> list[dict[str, Any]]:
    """MCP tool summaries with a bounded name and boolean hints only (a replayed one may hold anything)."""
    return [
        {"name": _text(tool.get("name"), 128), **{key: _flag(tool.get(key)) for key in _TOOL_HINTS}}
        for tool in _dicts(tools, 100)
    ]


def clean_texts(values: Any, limit: int = 128) -> list[str]:
    """Bounded nonempty strings from a list; anything else is dropped."""
    return _texts(values, limit)


def card_urls(card: dict[str, Any] | None) -> list[str]:
    if card is None:
        return []
    return [url for url in [card.get("url"), *card.get("additional_urls", [])] if isinstance(url, str)]


def parse_json_card(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Summarize a JSON agent card string; the status says why there is no summary."""
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, "invalid"
    if len(value.encode("utf-8", "surrogatepass")) > MAX_CARD_BYTES:
        return None, "too-large"
    try:
        card = strict_json_loads(value)
    except (ValueError, RecursionError):
        return None, "invalid"
    summary = summarize_card(card)
    return (summary, "parsed") if summary is not None else (None, "invalid")


def _attribute(attributes: Any, name: str, key: str) -> str | None:
    return _text(_dig(attributes, _AR_ATTRIBUTE + name, key), 512)


def _common(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "displayName": _text(item.get("displayName")),
        "description": _text(item.get("description"), 1000),
        "createTime": _text(item.get("createTime"), 64),
        "updateTime": _text(item.get("updateTime"), 64),
    }


def _present(out: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in out.items() if value is not None}


def normalize_ar_item(collection: str, item: dict[str, Any]) -> dict[str, Any]:
    """One Agent Registry item reduced to its allow-listed fields (raw cards and URLs never kept)."""
    out = _common(item)
    if collection == "publishers":
        out.update(
            verifiedPrefix=_text(item.get("verifiedPrefix"), 128),
            publisherTier=_text(item.get("publisherTier"), 64),
        )
        return _present(out)
    attributes = item.get("attributes")
    out.update(
        framework=_attribute(attributes, "Framework", "framework"),
        runtime_identity=_attribute(attributes, "RuntimeIdentity", "principal"),
        runtime_reference=_attribute(attributes, "RuntimeReference", "uri"),
    )
    interfaces = [face.get("url") for face in _dicts(item.get("interfaces"))]
    if collection == "agents":
        out.update(
            agentId=_text(item.get("agentId"), 256),
            version=_text(item.get("version"), 64),
            hosting_location=_text(item.get("location"), 64),
            skills=[skill.get("id") or skill.get("name") for skill in _dicts(item.get("skills"))],
            protocols=[
                {
                    "type": _text(protocol.get("type"), 64),
                    "protocol_version": _text(protocol.get("protocolVersion"), 32),
                    "urls": urls(*(face.get("url") for face in _dicts(protocol.get("interfaces")))),
                }
                for protocol in _dicts(item.get("protocols"), 10)
            ],
            agent_card=summarize_card(_dig(item, "card", "content")),
        )
        out["skills"] = _texts(out["skills"])
    elif collection == "mcpServers":
        out.update(
            mcpServerId=_text(item.get("mcpServerId"), 256),
            urls=urls(*interfaces),
            tools=[
                {
                    "name": _text(tool.get("name"), 128),
                    **{key: _flag(_dig(tool, "annotations", hint)) for key, hint in _TOOL_HINTS.items()},
                }
                for tool in _dicts(item.get("tools"), 100)
            ],
        )
    elif collection == "endpoints":
        out.update(endpointId=_text(item.get("endpointId"), 256), urls=urls(*interfaces))
    else:  # skills
        out.update(
            state=_text(item.get("state"), 64),
            targetState=_text(item.get("targetState"), 64),
            type=_text(item.get("type"), 64),
            publisher=_text(item.get("publisher"), 512),
            license=_text(_dig(item, "frontmatter", "license"), 128),
        )
    return _present(out)


def normalize_ge_agent(item: dict[str, Any]) -> dict[str, Any]:
    """One Gemini Enterprise agent without its icon, prompts, card text or authorization values."""
    out = _common(item)
    definitions = [label for key, label in _GE_DEFINITIONS.items() if item.get(key) is not None]
    card, card_status = parse_json_card(_dig(item, "a2aAgentDefinition", "jsonAgentCard"))
    tools = _dig(item, "authorizationConfig", "toolAuthorizations")
    out.update(
        state=_text(item.get("state"), 64),
        languageCode=_text(item.get("languageCode"), 32),
        reasons=[reason for reason in _GE_REASONS if item.get(f"{reason}Reason")],
        sharing_scope=_text(_dig(item, "sharingConfig", "scope"), 64),
        definition=definitions[0] if len(definitions) == 1 else ("multiple" if definitions else None),
        reasoning_engine=_text(
            _dig(item, "adkAgentDefinition", "provisionedReasoningEngine", "reasoningEngine"), 512
        ),
        dialogflow_agent=_text(_dig(item, "dialogflowAgentDefinition", "dialogflowAgent"), 512),
        agent_card=card,
        agent_card_status=card_status,
        marketplace=_dig(item, "a2aAgentDefinition", "cloudMarketplaceConfig") is not None,
        # Whether the app passes user tokens to the agent and how many tool grants: never the values.
        # (Named so that export redaction, which withholds any 'authorization' field, keeps it.)
        auth_config={
            "agent_auth_required": bool(_dig(item, "authorizationConfig", "agentAuthorization")),
            "tool_auth_grants": len(tools) if isinstance(tools, list) else 0,
        },
        observability={
            "enabled": _flag(_dig(item, "observabilityConfig", "observabilityEnabled")),
            "sensitive_logging": _flag(_dig(item, "observabilityConfig", "sensitiveLoggingEnabled")),
        },
    )
    return _present(out)


def ge_status(state: Any, reasons: Iterable[Any]) -> str:
    """Map a Gemini Enterprise agent state onto the record status vocabulary."""
    if state == "PRIVATE":
        # A rejected agent returns to PRIVATE with a rejection reason; otherwise it is unpublished.
        return "rejected" if "rejection" in reasons else "draft"
    return _GE_STATUS.get(state, "unknown") if isinstance(state, str) else "unknown"


def skill_status(state: Any) -> str:
    return _SKILL_STATUS.get(state, "unknown") if isinstance(state, str) else "unknown"


def engine_scope(name: Any) -> tuple[str, str, str] | None:
    """(project segment, location, collection) of a Discovery Engine engine name, or None."""
    match = ENGINE_NAME.fullmatch(name) if isinstance(name, str) else None
    if match is None or not _safe_segment(match["project"]):
        return None
    return match["project"], match["location"], match["collection"]


def is_assistant_of(name: Any, engine: str) -> bool:
    return (
        isinstance(name, str)
        and name.startswith(engine)
        and bool(_ASSISTANT_SUFFIX.fullmatch(name[len(engine) :]))
    )


def is_ge_app(engine: dict[str, Any]) -> bool:
    """Whether an engine is a Gemini Enterprise (Agentspace) app that can hold assistant agents."""
    return engine.get("appType") == "APP_TYPE_INTRANET" or engine.get("solutionType") in {
        "SOLUTION_TYPE_CHAT",
        "SOLUTION_TYPE_GENERATIVE_CHAT",
    }


# ------------------------------------------------------------------ analysis


@dataclass(frozen=True, slots=True)
class Reference:
    """An exact reference to an observable resource (a ``reasoning-engine`` or ``dialogflow-agent``)."""

    kind: str
    literal: str
    project: str
    location: str
    rid: str


def _resource(name: Any) -> tuple[str, str, str, str] | None:
    match = _RESOURCE.fullmatch(name) if isinstance(name, str) else None
    if match is None or not _safe_segment(match["project"]) or not _safe_segment(match["id"]):
        return None
    return match["project"], match["location"], match["collection"], match["id"]


def observed_reference(kind: str, name: Any) -> Reference | None:
    """The reference a ``reasoning-engine`` or ``dialogflow-agent`` resource name makes."""
    parts = _resource(name)
    if parts is None or kind not in OBSERVED_LISTINGS or parts[2] != OBSERVED_LISTINGS[kind][1]:
        return None
    return Reference(kind, str(name), parts[0], parts[1], parts[3])


def runtime_reference(uri: Any) -> Reference | None:
    """An Agent Registry ``RuntimeReference`` URI naming a reasoning engine or Dialogflow agent."""
    match = _RUNTIME_REFERENCE.fullmatch(uri) if isinstance(uri, str) else None
    if match is None:
        return None
    kind = "reasoning-engine" if match["service"] == "aiplatform" else "dialogflow-agent"
    return observed_reference(kind, match["resource"])


def unrecognized_reference(uri: Any) -> bool:
    """Whether a ``RuntimeReference`` names a Vertex AI or Dialogflow host in a form this scan cannot read.

    Such a reference (an ``https:`` URL, a version segment, a trailing slash) may register a
    reasoning engine or Dialogflow agent that would otherwise look unregistered. A plain resource
    name of a collection this scan does not observe (a Vertex AI endpoint) is read: it names no
    engine.
    """
    if not isinstance(uri, str) or not _RUNTIME_HOST.match(uri):
        return False
    match = _RUNTIME_REFERENCE.fullmatch(uri)
    return match is None or _resource(match["resource"]) is None


class ProjectNumbers:
    """Project number to project id, from this scan's own listings; a conflicting number maps to nothing."""

    def __init__(self) -> None:
        self._ids: dict[str, str | None] = {}
        self._numbers: dict[str, str] = {}

    def add(self, project: str, number: str) -> bool:
        """Record one project's number; False (and neither mapping kept) when either is already taken."""
        previous = self._numbers.setdefault(project, number)
        consistent = previous == number and self._ids.get(number, project) == project
        if consistent:
            self._ids[number] = project
        else:
            self._ids[number] = self._ids[previous] = None
        return consistent

    def project_id(self, segment: str) -> str | None:
        """The project id a resource name's project segment stands for; None when it is unknown."""
        return self._ids.get(segment) if is_number(segment) else segment

    def names(self, project: str, segment: str) -> bool | None:
        """Whether a name's project segment stands for ``project``; None when this scan cannot tell."""
        owner = self.project_id(segment)
        if owner is not None:
            return owner == project
        number = self._numbers.get(project)
        # An unknown number is another project's when this project's own number is known.
        return False if number is not None and self._ids.get(number) == project else None


@dataclass(frozen=True, slots=True)
class Coverage:
    """One validated ``registry-coverage`` record."""

    project: str
    location: str | None
    catalog: str
    collection: str
    api_version: str
    complete: bool
    locations: tuple[str, ...] = ()


def parse_coverage(rec: dict[str, Any]) -> Coverage:
    """Validate a ``registry-coverage`` record; ValueError when it does not fit the contract.

    Every record names one listing: a catalog and collection in one project and location. The
    Agent Registry ``locations`` listing is project-wide (``_location`` null) and names the
    locations it found. A caller-scoped listing is never complete.
    """
    catalog, collection, location = rec.get("catalog"), rec.get("collection"), rec.get("_location")
    if not rec.keys() <= _COVERAGE_FIELDS or catalog not in _COVERAGE_COLLECTIONS:
        raise ValueError("registry coverage record")
    project_wide = catalog == AR_REGISTRY and collection == "locations"
    locations = rec.get("locations")
    listed = (
        isinstance(locations, list) and all(valid_location(item) for item in locations)
        if project_wide
        else locations is None
    )
    if (
        collection not in _COVERAGE_COLLECTIONS[catalog]
        or not valid_project(rec.get("_project"))
        or not (location is None if project_wide else valid_location(location))
        or not listed
        or not isinstance(rec.get("api_version"), str)
        or type(rec.get("complete")) is not bool
        or rec.get("listing_scope") not in {"project", "caller"}
        or not isinstance(rec.get("parent", ""), str)
    ):
        raise ValueError("registry coverage record")
    return Coverage(
        project=rec["_project"],
        location=location,
        catalog=catalog,
        collection=collection,
        api_version=rec["api_version"],
        complete=rec["complete"] and rec["listing_scope"] == "project",
        locations=tuple(str(item) for item in locations or ()),
    )


@dataclass
class RecordEntry:
    """What a registry record finding needs from its record to be completed after analysis.

    ``registry_project`` is the project segment of the registry's own name (a number or an id)
    and ``registry_suffix`` the rest of that name: the registry id is both, with the number
    replaced by the project id when this scan knows it. ``references`` that name another
    project's resource move to ``cross_project`` when the catalogs are finished: a record binds
    only resources of the project it was listed in. ``unrecognized_reference`` marks a runtime
    reference to Vertex AI or Dialogflow that this scan cannot read.
    """

    kind: str
    registry: str
    descriptor_type: str
    name: str
    project: str
    location: str
    status: str
    approval_mode: str
    registry_project: str
    registry_suffix: str
    references: list[Reference] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    identity: str | None = None
    associated_registry: str | None = None
    updated_at: str | None = None
    publisher: str | None = None
    cross_project: list[Reference] = field(default_factory=list)
    unrecognized_reference: bool = False


def _typed(rec: dict[str, Any], key: str, kind: type) -> Any:
    value = rec.get(key)
    if value is not None and not isinstance(value, kind):
        raise ValueError(key)
    return value


# String fields of registry records and the length collection bounds each to.
_STRING_LIMITS = {
    "displayName": 200,
    "description": 1000,
    "createTime": 64,
    "updateTime": 64,
    "framework": 512,
    "runtime_reference": 512,
    "runtime_identity": 512,
    "state": 64,
    "publisher": 512,
    "sharing_scope": 64,
    "reasoning_engine": 512,
    "dialogflow_agent": 512,
    "agentId": 256,
    "version": 64,
    "hosting_location": 64,
    "mcpServerId": 256,
    "endpointId": 256,
    "type": 64,
    "targetState": 64,
    "license": 128,
    "languageCode": 32,
}
_STRING_FIELDS = (*_STRING_LIMITS, "definition", "_agent_registry", "agent_card_status")
_LIST_FIELDS = ("urls", "protocols", "skills", "tools", "reasons")
_DICT_FIELDS = ("agent_card", "auth_config", "observability")


def bound_strings(rec: dict[str, Any]) -> dict[str, Any]:
    """A registry record with its strings bounded as collection bounds them (a replayed one may not be)."""
    bounded = {
        key: _text(rec[key], limit) for key, limit in _STRING_LIMITS.items() if isinstance(rec.get(key), str)
    }
    return {**rec, **bounded}


def record_entry(kind: str, rec: dict[str, Any]) -> RecordEntry:
    """Validate a registry record of ``kind`` and extract its join keys; ValueError when malformed."""
    registry, descriptor = RECORD_KINDS[kind]
    name, project, location = rec.get("name"), rec.get("_project"), rec.get("_location")
    if not isinstance(name, str) or not valid_project(project) or not valid_location(location):
        raise ValueError("record scope")
    for keys, kind_type in ((_STRING_FIELDS, str), (_LIST_FIELDS, list), (_DICT_FIELDS, dict)):
        for key in keys:
            _typed(rec, key, kind_type)
    found = card_urls(clean_card(rec.get("agent_card")))
    if registry == AR_REGISTRY:
        return _registry_entry(kind, rec, name, project, location, found)
    engine, assistant = rec.get("_engine"), rec.get("_assistant")
    scope = engine_scope(engine)
    prefix = f"{assistant}/agents/"
    if (
        scope is None
        or scope[1] != location
        or not (is_number(scope[0]) or scope[0] == project)
        or not is_assistant_of(assistant, str(engine))
        or not name.startswith(prefix)
        or not _SEGMENT.fullmatch(name[len(prefix) :])
        or not _safe_segment(name[len(prefix) :])
    ):
        raise ValueError("gemini enterprise agent name")
    references = []
    for key in ("reasoning_engine", "dialogflow_agent"):
        if rec.get(key) is not None:
            reference = observed_reference(key.replace("_", "-"), rec[key])
            if reference is None:
                raise ValueError(key)
            references.append(reference)
    return RecordEntry(
        kind=kind,
        registry=registry,
        descriptor_type="a2a" if rec.get("definition") == "a2a" else descriptor,
        name=name,
        project=project,
        location=location,
        status=ge_status(rec.get("state"), rec.get("reasons") or []),
        approval_mode="manual",
        registry_project=scope[0],
        registry_suffix=str(engine)[len(f"projects/{scope[0]}") :],
        references=references,
        urls=found,
        associated_registry=rec.get("_agent_registry"),
        updated_at=_text(rec.get("updateTime"), 64),
    )


def _registry_entry(
    kind: str, rec: dict[str, Any], name: str, project: str, location: str, found: list[str]
) -> RecordEntry:
    parts = _resource(name)
    version = rec.get("_api_version")
    if (
        parts is None
        or parts[2] != _KIND_COLLECTION[kind]
        or parts[1] != location
        or not (is_number(parts[0]) or parts[0] == project)
        or not isinstance(version, str)
        or version not in AR_VERSIONS
        or (kind == "agent-registry-skill" and version != "v1alpha")
    ):
        raise ValueError("agent registry record name")
    for protocol in rec.get("protocols") or []:
        if not isinstance(protocol, dict) or not isinstance(protocol.get("urls") or [], list):
            raise ValueError("protocols")
        found += protocol.get("urls") or []
    raw_reference = rec.get("runtime_reference")
    reference = runtime_reference(raw_reference)
    identity = rec.get("runtime_identity")
    return RecordEntry(
        kind=kind,
        registry=AR_REGISTRY,
        descriptor_type=RECORD_KINDS[kind][1],
        name=name,
        project=project,
        location=location,
        status=skill_status(rec.get("state")) if kind == "agent-registry-skill" else "registered",
        # Agent Registry has no approval workflow: listing an agent is not approving it.
        approval_mode="none",
        registry_project=parts[0],
        registry_suffix=f"/locations/{location}",
        references=[reference] if reference else [],
        urls=urls(*found, *(rec.get("urls") or [])),
        identity=identity.removeprefix("principal://") if identity else None,
        updated_at=_text(rec.get("updateTime"), 64),
        publisher=_text(rec.get("publisher"), 512) if kind == "agent-registry-skill" else None,
        unrecognized_reference=reference is None and unrecognized_reference(raw_reference),
    )


@dataclass(frozen=True, slots=True)
class _Observed:
    resource: str
    account: str | None
    region: str | None


class RegistryCatalogs:
    """Coverage, project numbers, observed resources and deferred record findings of one analysis pass.

    :meth:`finish` completes each deferred finding's ``registry_record`` and ``catalog_presence``
    from everything the pass read, so the result does not depend on record order. A record the
    pass could not read taints the catalogs: it may be the agent, binding or incomplete listing
    that a completeness claim would overlook, so no binding is then in scope, no listing is
    complete and nothing is reported absent. So does a record or publisher whose name carries the
    number of a project other than the one it was listed in (counted in :attr:`foreign` and
    dropped): it would claim that other project's registry identity.

    :attr:`failed_listings` counts coverage records of listings that did not complete,
    :attr:`failed_lookups` the project-number records of lookups that did, and :attr:`unrecognized`
    the Agent Registry records whose runtime reference names Vertex AI or Dialogflow in a form
    this scan cannot read.
    """

    def __init__(self) -> None:
        self.numbers = ProjectNumbers()
        self._coverage: dict[tuple[str, str, str | None, str], list[Coverage]] = {}
        self._observed: list[tuple[Reference, _Observed]] = []
        self._identities: dict[str, list[str]] = {}
        self._observed_urls: dict[str, list[str]] = {}
        # (project listed in, publisher name) -> (display name, tier): a skill names only a
        # publisher of its own project. Each listed publisher keeps its name's project segment.
        self._publishers: dict[tuple[str, str], tuple[str, str | None]] = {}
        self._listed_publishers: list[tuple[str, str, str, tuple[str, str | None]]] = []
        self._deferred: list[tuple[Finding, RecordEntry]] = []
        # Projects with an Agent Registry record whose runtime references this scan cannot resolve
        # to a resource of that project.
        self._unresolved_projects: set[str] = set()
        self.tainted = False
        self.foreign = 0
        self.failed_listings = 0
        self.failed_lookups = 0
        self.unrecognized = 0

    # ------------------------------------------------------------ intake
    def taint(self) -> None:
        self.tainted = True

    def add(self, kind: str, rec: dict[str, Any]) -> None:
        """Read a coverage, project-number or publisher record; ValueError when it is malformed."""
        if kind == COVERAGE_KIND:
            item = parse_coverage(rec)
            key = (item.catalog, item.project, item.location, item.collection)
            self._coverage.setdefault(key, []).append(item)
            # A listing that failed (not one that is only caller-scoped).
            self.failed_listings += rec["complete"] is False
        elif kind == PROJECT_NUMBER_KIND:
            project, number = rec.get("_project"), rec.get("project_number")
            if not valid_project(project) or not (
                number is None or (isinstance(number, str) and is_number(number))
            ):
                raise ValueError("project number")
            if number is None:
                # The lookup failed when collected (and was warned then); the export records that.
                self.failed_lookups += 1
            elif not self.numbers.add(str(project), number):
                raise ValueError("conflicting project number")
        else:
            # Publishers only name the publisher of a skill; they are not records themselves, but
            # like records they speak only for the project and location they were listed in.
            name, project = rec.get("name"), rec.get("_project")
            parts = _resource(name) if isinstance(name, str) and len(name) <= 512 else None
            if (
                parts is None
                or parts[2] != "publishers"
                or parts[1] != rec.get("_location")
                or not valid_project(project)
                or not (is_number(parts[0]) or parts[0] == project)
            ):
                raise ValueError("publisher")
            for field_name in ("displayName", "publisherTier", "verifiedPrefix"):
                _typed(rec, field_name, str)
            display = _text(rec.get("displayName")) or parts[3]
            publisher = (display, _text(rec.get("publisherTier"), 64))
            self._listed_publishers.append((str(name), project, parts[0], publisher))

    def observe(self, kind: str, rec: dict[str, Any], finding: Finding) -> None:
        """Index an observed finding that registry records may bind to or hint at."""
        if kind == "cloud-run-service":
            url = normalize_url(finding.metadata.get("uri"))
            if url:
                self._observed_urls.setdefault(url, []).append(finding.resource)
            return
        reference = observed_reference(kind, finding.resource)
        if reference is None:
            return
        self._observed.append((reference, _Observed(finding.resource, finding.account, finding.region)))
        identity = _dig(rec, "spec", "effectiveIdentity")
        if isinstance(identity, str) and identity:
            self._identities.setdefault(identity, []).append(finding.resource)

    def defer(self, finding: Finding, entry: RecordEntry) -> None:
        self._deferred.append((finding, entry))

    # ------------------------------------------------------------ coverage
    def _listed(self, catalog: str, project: str, location: str | None, collection: str) -> bool | None:
        """True after a complete listing, False after an incomplete one, None when none ran."""
        items = self._coverage.get((catalog, project, location, collection))
        if not items:
            return None
        return all(item.complete for item in items) and not self.tainted

    def _ar_location_complete(self, project: str, location: str) -> bool:
        versions = {
            item.api_version
            for collection in _COVERAGE_COLLECTIONS[AR_REGISTRY]
            for item in self._coverage.get((AR_REGISTRY, project, location, collection), [])
        }
        if len(versions) != 1:
            return False
        required = _AR_RECORD_COLLECTIONS.get(versions.pop(), ())
        return bool(required) and all(
            self._listed(AR_REGISTRY, project, location, collection) is True for collection in required
        )

    def ar_project_complete(self, project: str) -> bool:
        """Whether every Agent Registry location of ``project`` was enumerated and listed completely,
        and every record there names its runtime resources in a form this scan can resolve."""
        listings = self._coverage.get((AR_REGISTRY, project, None, "locations"), [])
        if len(listings) != 1 or self._listed(AR_REGISTRY, project, None, "locations") is not True:
            return False
        if project in self._unresolved_projects:
            return False
        return all(self._ar_location_complete(project, location) for location in listings[0].locations)

    def _resolved(self, entry: RecordEntry) -> bool:
        return all(self.numbers.project_id(reference.project) is not None for reference in entry.references)

    # ------------------------------------------------------------ results
    def finish(self) -> list[Finding]:
        """Complete every deferred record finding; return them in the order they were read."""
        kept = [
            (finding, entry)
            for finding, entry in self._deferred
            if self.numbers.names(entry.project, entry.registry_project) is not False
        ]
        publishers = [
            item for item in self._listed_publishers if self.numbers.names(item[1], item[2]) is not False
        ]
        self.foreign = len(self._deferred) - len(kept) + len(self._listed_publishers) - len(publishers)
        if self.foreign:
            self.taint()
        self._deferred = kept
        self._publishers = {(project, name): publisher for name, project, _, publisher in publishers}
        canonical: dict[tuple[str, str, str, str], _Observed] = {}
        literal: dict[str, _Observed] = {}
        for reference, item in self._observed:
            literal.setdefault(item.resource, item)
            project = self.numbers.project_id(reference.project)
            if project is None and item.account:
                # A listing returns the resources of the project it was asked for: an unmapped
                # number in an observed name stands for the collected project.
                project = item.account
            if project:
                canonical.setdefault((reference.kind, project, reference.location, reference.rid), item)
        for _, entry in self._deferred:
            own = [reference for reference in entry.references if self._owns(entry, reference, literal)]
            entry.cross_project = [reference for reference in entry.references if reference not in own]
            entry.references = own
        # An Agent Registry whose records name runtimes of another project, or name them in a form
        # or by a number this scan cannot resolve, is never a complete listing of its own project.
        self._unresolved_projects = {
            entry.project
            for _, entry in self._deferred
            if entry.registry == AR_REGISTRY
            and (entry.cross_project or entry.unrecognized_reference or not self._resolved(entry))
        }
        self.unrecognized = sum(entry.unrecognized_reference for _, entry in self._deferred)
        for finding, entry in self._deferred:
            self._apply(finding, entry, canonical, literal)
        self._presence()
        return [finding for finding, _ in self._deferred]

    def _owns(self, entry: RecordEntry, reference: Reference, literal: dict[str, _Observed]) -> bool:
        """Whether a reference names a resource of the project the record was listed in.

        When this scan knows neither project's number, an observed resource of that exact name
        belongs to the project whose listing returned it.
        """
        owns = self.numbers.names(entry.project, reference.project)
        if owns is None:
            observed = literal.get(reference.literal)
            return observed is None or observed.account == entry.project
        return owns

    def _observed_item(
        self,
        reference: Reference,
        canonical: dict[tuple[str, str, str, str], _Observed],
        literal: dict[str, _Observed],
    ) -> _Observed | None:
        project = self.numbers.project_id(reference.project)
        found = literal.get(reference.literal)
        if found is None and project is not None:
            found = canonical.get((reference.kind, project, reference.location, reference.rid))
        return found

    def _binding(
        self,
        entry: RecordEntry,
        reference: Reference,
        canonical: dict[tuple[str, str, str, str], _Observed],
        literal: dict[str, _Observed],
    ) -> dict[str, Any]:
        project = self.numbers.project_id(reference.project)
        catalog, collection = OBSERVED_LISTINGS[reference.kind]
        observed = self._observed_item(reference, canonical, literal)
        listed: bool | None = False
        if project is not None:
            listed = self._listed(catalog, project, reference.location, collection)
        coverage = {True: "in-scope", False: "unknown", None: "out-of-scope"}[listed]
        # The account is always the record's own project, the only one whose resources it binds.
        # When not observed, the binding names the referenced resource as the record gave it.
        return {
            "resource": observed.resource if observed else reference.literal,
            "provider": "gcp",
            "account": entry.project,
            "region": observed.region if observed else reference.location,
            "coverage": coverage,
        }

    def _apply(
        self,
        finding: Finding,
        entry: RecordEntry,
        canonical: dict[tuple[str, str, str, str], _Observed],
        literal: dict[str, _Observed],
    ) -> None:
        project = self.numbers.project_id(entry.registry_project)
        bindings = [self._binding(entry, reference, canonical, literal) for reference in entry.references]
        record: dict[str, Any] = {
            "schema": RECORD_SCHEMA,
            "registry": entry.registry,
            "registry_id": f"projects/{project or entry.registry_project}{entry.registry_suffix}",
            "record_id": entry.name,
            "status": entry.status,
            "descriptor_type": entry.descriptor_type,
            "bindings": bindings[:MAX_BINDINGS],
            "approval_mode": entry.approval_mode,
        }
        if entry.updated_at:
            record["updated_at"] = entry.updated_at
        if entry.publisher:
            # Only a publisher listed in the skill's own project names it, as with bindings.
            fallback = (entry.publisher.rsplit("/", 1)[-1], None)
            display, tier = self._publishers.get((entry.project, entry.publisher), fallback)
            record["publisher"] = display
            finding.metadata["publisher_tier"] = tier
        if entry.registry == AR_REGISTRY:
            # A registry whose project this scan cannot resolve is never complete.
            complete = project == entry.project and self.ar_project_complete(entry.project)
            record.update(listing_scope="registry", listing_complete=complete)
        else:
            # Gemini Enterprise lists only the agents the caller created or can see.
            record.update(listing_scope="caller", listing_complete=False)
        finding.metadata[RECORD_KEY] = record
        bound = {binding["resource"] for binding in bindings}
        # Another project's resource: named by the record, but neither bound nor approved.
        hints: list[dict[str, str]] = []
        for reference in entry.cross_project:
            observed = self._observed_item(reference, canonical, literal)
            resource = observed.resource if observed else reference.literal
            hints.append({"key": "cross-project-reference", "resource": resource})
        hints += [
            {"key": "runtime-identity", "resource": resource}
            for resource in self._identities.get(entry.identity or "", [])
            if resource not in bound
        ]
        hints += [
            {"key": "endpoint-url", "resource": resource}
            for url in entry.urls
            for resource in self._observed_urls.get(url, [])
        ]
        if hints:
            finding.metadata["registry_join_hints"] = hints[:_MAX_HINTS]

    def _join_keys(self, entry: RecordEntry) -> set[tuple[str, ...]]:
        keys: set[tuple[str, ...]] = {("url", url) for url in entry.urls}
        for reference in entry.references:
            project = self.numbers.project_id(reference.project)
            if project is None:
                keys.add(("literal", reference.literal))
            else:
                keys.add((reference.kind, project, reference.location, reference.rid))
        return keys

    def _presence(self) -> None:
        """``catalog_presence`` on Agent Registry agents and Gemini Enterprise agents."""
        agents = [
            (finding, entry, self._join_keys(entry))
            for finding, entry in self._deferred
            if entry.kind in {"agent-registry-agent", GE_AGENT_KIND}
        ]
        in_registry: set[tuple[str, ...]] = set()
        in_catalog: set[tuple[str, ...]] = set()
        for _, entry, keys in agents:
            (in_registry if entry.registry == AR_REGISTRY else in_catalog).update(keys)
        for finding, entry, keys in agents:
            if entry.registry == AR_REGISTRY:
                presence = {
                    "agent_registry": "present",
                    # Gemini Enterprise listings are caller-scoped: absence from them proves nothing.
                    "gemini_enterprise": "present" if keys & in_catalog else "unknown",
                }
            else:
                found = "present" if keys & in_registry else None
                absent = keys and not self.tainted and self._registry_scope_complete(entry)
                presence = {
                    "agent_registry": found or ("absent" if absent else "unknown"),
                    "gemini_enterprise": "present",
                }
            finding.metadata["catalog_presence"] = presence

    def _registry_scope_complete(self, entry: RecordEntry) -> bool:
        """Whether the Agent Registry an agent should appear in was listed completely and comparably.

        The scope is the engine's associated registry when it names one, otherwise every Agent
        Registry location of the agent's project. An agent reference or registry record that this
        scan cannot resolve to a project id makes the comparison impossible.
        """
        if not self._resolved(entry) or self._unresolved_projects:
            return False
        if entry.associated_registry:
            match = _REGISTRY_NAME.fullmatch(entry.associated_registry)
            project = self.numbers.project_id(match[1]) if match else None
            return match is not None and project is not None and self._ar_location_complete(project, match[2])
        return self.ar_project_complete(entry.project)
