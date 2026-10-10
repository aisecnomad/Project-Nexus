"""AWS Agent Registry and AgentCore registry shapes for ``cloud.aws`` (pure helpers, no configuration).

Two SDK namespaces hold agent registries:

* ``agent-registry-control`` (registry type ``aws-agent-registry``), plus the ``agent-registry``
  data plane, which lists only the approved records of a registry the caller may discover; and
* ``bedrock-agentcore-control`` (registry type ``aws-agentcore-registry``).

Record descriptors are untrusted inline documents of up to 100 KiB that can embed URLs and
credential-provider settings. Collection parses them strictly and keeps only a bounded summary
(:func:`descriptor_summary`): the raw ``data``/``inlineContent`` and OAuth ``customParameters``
are never exported, and no descriptor URL becomes a finding resource.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from shadowscan.models import Kind
from shadowscan.utils.redaction import sanitize_text
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.text import truncate

_PARTITION = r"arn:aws(?:-[a-z]+)*"
_REGISTRY_ID = r"[A-Za-z0-9]{12,16}"
# An exact agent-registry registry ARN, the form ``registry_arns`` accepts.
REGISTRY_ARN_PATTERN = rf"{_PARTITION}:agent-registry:[a-z0-9-]+:[0-9]{{12}}:registry/{_REGISTRY_ID}"
# The deployed AgentCore objects a record's provenance can name, in the form their findings use.
_AGENTCORE_SOURCE = re.compile(
    rf"{_PARTITION}:bedrock-agentcore:(?P<region>[a-z0-9-]+):(?P<account>[0-9]{{12}}):"
    r"(?P<type>runtime|gateway)/[A-Za-z0-9_-]+"
)
_SOURCE_TYPES = {"runtime": "AWS::BedrockAgentCore::Runtime", "gateway": "AWS::BedrockAgentCore::Gateway"}
# The only provenance relation the SDK models define: the registry detected the record from the source.
# The models keep provenance a list so that other relations can follow; those bind nothing.
DETECTED_FROM = "DETECTED_FROM"

# Vendor record statuses; CREATING, UPDATING and the failed states are not a review outcome.
STATUSES = {
    "APPROVED": "approved",
    "PENDING_APPROVAL": "pending",
    "DRAFT": "draft",
    "REJECTED": "rejected",
    "DEPRECATED": "deprecated",
}
# agent-registry ``recordType`` and AgentCore ``descriptorType`` values.
DESCRIPTOR_TYPES = {
    "MCP": "mcp",
    "GATEWAY": "mcp",
    "AGENT": "agent",
    "A2A": "a2a",
    "CUSTOM": "custom",
    "SKILL": "agent-skills",
    "AGENT_SKILLS": "agent-skills",
}
KINDS = {
    "mcp": Kind.MCP_SERVER,
    "agent": Kind.AGENT,
    "a2a": Kind.AGENT,
    "agent-skills": Kind.AGENT_CONFIG,
    "custom": Kind.CLOUD_RESOURCE,
}
# Coverage of a provenance binding, as the registry record contract spells it.
COVERAGE = ("in-scope", "out-of-scope", "unknown")

# Inline descriptors are at most 102,400 characters in both SDK models.
MAX_DESCRIPTOR_CHARS = 102_400
MAX_PROVENANCE = 8
_MAX_ITEMS = 50
_MAX_INTERFACES = 10
_MAX_TEXT = 300


@dataclass(frozen=True, slots=True)
class RegistryApi:
    """One registry namespace: its SDK client, record kinds and vendor field names.

    ``label`` names the namespace's records ("<label> record") and ``product`` its registries
    ("<product> registry").
    """

    service: str
    label: str
    product: str
    registry_type: str
    registry_kind: str
    record_kind: str
    type_field: str
    arn_service: str

    def is_registry_arn(self, value: Any) -> bool:
        """Whether ``value`` is an exact registry ARN of this namespace."""
        pattern = rf"{_PARTITION}:{self.arn_service}:[a-z0-9-]+:[0-9]{{12}}:registry/{_REGISTRY_ID}"
        return isinstance(value, str) and re.fullmatch(pattern, value) is not None

    def owns(self, registry_arn: Any, record_arn: Any) -> bool:
        """Whether the registry ARN belongs to this namespace and the record ARN lies directly under it."""
        return (
            self.is_registry_arn(registry_arn)
            and isinstance(record_arn, str)
            and re.fullmatch(re.escape(registry_arn) + r"/record/[A-Za-z0-9]{12}", record_arn) is not None
        )


AGENT_REGISTRY = RegistryApi(
    service="agent-registry-control",
    label="Agent Registry",
    product="Agent Registry",
    registry_type="aws-agent-registry",
    registry_kind="agent-registry",
    record_kind="agent-registry-record",
    type_field="recordType",
    arn_service="agent-registry",
)
AGENTCORE_REGISTRY = RegistryApi(
    service="bedrock-agentcore-control",
    label="AgentCore registry",
    product="AgentCore",
    registry_type="aws-agentcore-registry",
    registry_kind="agentcore-registry",
    record_kind="agentcore-registry-record",
    type_field="descriptorType",
    arn_service="bedrock-agentcore",
)
# Records of another account's registry, read through the agent-registry data plane.
DISCOVERABLE_RECORD_KIND = "agent-registry-discoverable-record"


def text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    """A provider string, credentials redacted and bounded; anything else is absent."""
    return truncate(sanitize_text(value), limit) if isinstance(value, str) and value else None


def mapping(value: Any) -> dict[str, Any]:
    """A provider object, or an empty one when the field is absent or of another type."""
    return value if isinstance(value, dict) else {}


def sequence(value: Any) -> list[Any]:
    """A provider array, or an empty one when the field is absent or of another type."""
    return value if isinstance(value, list) else []


def approval_mode(api: RegistryApi, configuration: Any) -> str:
    """``auto``, ``manual`` or ``unknown`` from a registry's ``approvalConfiguration``.

    An automatic setting wins whatever else the configuration holds: a true AgentCore
    ``autoApproval``, or any agent-registry ``autoApprovalRules`` value (``APPROVE_ALL``
    approves every record, and a rule this release does not know may approve some of them
    without a person). A true value of an unexpected type counts as automatic too. ``manual``
    needs a configuration this release reads in full: the setting absent, false or empty and
    nothing beside it. Anything else is ``unknown``: no configuration (registry details denied
    or not returned), or one of another shape or with a setting this release does not know
    (:func:`approval_unrecognized`).
    """
    if not isinstance(configuration, dict):
        return "unknown"
    field = "autoApproval" if api is AGENTCORE_REGISTRY else "autoApprovalRules"
    value = configuration.get(field)
    if value:
        return "auto"
    # Falsy from here on: only the documented "off" values of the documented type read as manual.
    off = value is False if api is AGENTCORE_REGISTRY else isinstance(value, list)
    if (value is None or off) and configuration.keys() <= {field}:
        return "manual"  # no automatic approval is configured
    return "unknown"


def approval_unrecognized(api: RegistryApi, configuration: Any) -> bool:
    """Whether a returned approval configuration is one this release cannot read (mode ``unknown``)."""
    return configuration is not None and approval_mode(api, configuration) == "unknown"


def provenance(items: Any, coverage: Callable[[str], str]) -> list[dict[str, Any]]:
    """Bounded provenance entries; ``coverage`` gives a source ARN's binding coverage.

    Raises ``ValueError`` for a malformed list (the record is skipped as malformed).
    """
    if items is None:
        return []
    if not isinstance(items, list) or len(items) > MAX_PROVENANCE:
        raise ValueError("invalid registry record provenance")
    entries = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("sourceId"), str):
            raise ValueError("invalid registry record provenance")
        details = mapping(item.get("sourceDetails"))
        runtime = mapping(details.get("agentcoreRuntime"))
        gateway = mapping(details.get("agentcoreGateway"))
        identity = mapping(runtime.get("workloadIdentityDetails") or gateway.get("workloadIdentityDetails"))
        entry = {
            "relation": item.get("relation"),
            "sourceId": item["sourceId"],
            "sourceType": item.get("sourceType"),
            "serverProtocol": mapping(runtime.get("protocolConfiguration")).get("serverProtocol"),
            "gatewayProtocol": gateway.get("protocolType"),
            "workloadIdentityArn": identity.get("workloadIdentityArn"),
            # Authorizer settings are left out: they name token issuers and allowed clients.
            "_coverage": coverage(item["sourceId"]),
        }
        entries.append({key: value for key, value in entry.items() if value is not None})
    return entries


def source_coverage(source_id: str, account: str | None, collected_regions: set[str]) -> str:
    """``in-scope`` for an AgentCore runtime or gateway of ``account`` in a region collected cleanly."""
    match = _AGENTCORE_SOURCE.fullmatch(source_id)
    if match and account is not None and match["account"] == account and match["region"] in collected_regions:
        return "in-scope"
    return "out-of-scope"


def binding(entry: Any) -> dict[str, Any] | None:
    """The registry-record binding for one exported provenance entry, or None.

    The resource is the source ARN exactly as the runtime or gateway finding carries it, so
    reconciliation matches it without normalization. Only a ``DETECTED_FROM`` entry naming an
    AgentCore runtime or gateway ARN whose ``sourceType`` agrees (or is absent) binds; any other
    relation or source binds nothing. Whether the record's provenance may bind at all is the
    caller's decision (:func:`provenance_binds`).
    """
    if (
        not isinstance(entry, dict)
        or entry.get("relation") != DETECTED_FROM
        or not isinstance(entry.get("sourceId"), str)
    ):
        return None
    match = _AGENTCORE_SOURCE.fullmatch(entry["sourceId"])
    declared = entry.get("sourceType")
    if match is None or (declared is not None and declared != _SOURCE_TYPES[match["type"]]):
        return None
    coverage = entry.get("_coverage")
    return {
        "resource": entry["sourceId"],
        "provider": "aws",
        "account": match["account"],
        "region": match["region"],
        "coverage": coverage if coverage in COVERAGE else "unknown",
    }


def provenance_binds(record: dict[str, Any]) -> bool:
    """Whether a record's provenance can bind: only lineage the registry recorded by auto-detection.

    ``CreateRegistryRecord`` and ``UpdateRegistryRecord`` accept provenance from the caller, so
    on a record created through the API it is the publisher's assertion and binds nothing.
    """
    return record.get("createdByAutoDetection") is True


def unrecognized_relation(entry: Any) -> bool:
    """Whether a provenance entry carries a relation other than ``DETECTED_FROM``, or none."""
    return not isinstance(entry, dict) or entry.get("relation") != DETECTED_FROM


# ----------------------------------------------------------------- descriptors
class DescriptorError(ValueError):
    """An inline descriptor that is not a bounded, strictly valid JSON document of the expected shape."""


def _document(value: Any, *, expect: type | tuple[type, ...] = dict) -> Any:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_DESCRIPTOR_CHARS:
        raise DescriptorError("descriptor is not a bounded string")
    try:
        parsed = strict_json_loads(value)
    except (ValueError, RecursionError):
        raise DescriptorError("descriptor is not valid JSON") from None
    if not isinstance(parsed, expect):
        raise DescriptorError("descriptor has an unexpected shape")
    return parsed


def _get(value: Any, *path: str) -> Any:
    for key in path:
        value = mapping(value).get(key)
    return value


def _strings(values: Any, limit: int = _MAX_ITEMS) -> list[str]:
    return [shown for item in sequence(values)[:limit] if (shown := text(item)) is not None]


def _keys(value: Any) -> list[str]:
    return sorted(str(key) for key in mapping(value))[:_MAX_ITEMS]


def _package(package: dict[str, Any]) -> str:
    """``<registry type>:<identifier>@<version>`` of an MCP server package entry."""
    parts = (
        package.get("registryType") or package.get("registry_name"),
        package.get("identifier") or package.get("name"),
    )
    version = package.get("version")
    shown = ":".join(part for part in parts if isinstance(part, str))
    return shown + (f"@{version}" if isinstance(version, str) else "")


def mcp_summary(server: Any, tools: Any) -> dict[str, Any]:
    """Name, version, remote URLs, package identifiers and tool names of an MCP descriptor."""
    summary: dict[str, Any] = {}
    if isinstance(server, dict):
        remotes = sequence(server.get("remotes"))
        packages = [package for package in sequence(server.get("packages")) if isinstance(package, dict)]
        summary["name"] = text(server.get("name"))
        summary["version"] = text(server.get("version"))
        summary["remotes"] = _strings([mapping(remote).get("url") for remote in remotes])
        summary["packages"] = _strings([_package(package) for package in packages])
    if tools is not None:
        listed = sequence(tools.get("tools") if isinstance(tools, dict) else tools)
        summary["tools"] = _strings([mapping(tool).get("name") for tool in listed], limit=100)
    return {key: value for key, value in summary.items() if value not in (None, [])}


def _interfaces(card: dict[str, Any]) -> list[dict[str, Any]]:
    """An A2A card's interfaces: ``supportedInterfaces`` (1.0) or ``additionalInterfaces`` (0.3)."""
    listed = card.get("supportedInterfaces")
    if listed is None:
        listed = card.get("additionalInterfaces")
    interfaces = []
    for item in sequence(listed)[:_MAX_INTERFACES]:
        interface = mapping(item)
        shown = {
            "url": text(interface.get("url")),
            "protocol_binding": text(interface.get("protocolBinding") or interface.get("transport"), 64),
            "protocol_version": text(interface.get("protocolVersion"), 64),
        }
        if shown["url"] is not None:
            interfaces.append({key: value for key, value in shown.items() if value is not None})
    return interfaces


def a2a_summary(card: dict[str, Any]) -> dict[str, Any]:
    """The A2A card fields the filesystem scanner records for a card file, bounded and sanitized.

    A 1.0 card names its endpoints and protocol versions only in ``supportedInterfaces``; the
    top-level ``url`` and ``protocolVersion`` of a 0.3 card win, and otherwise the first
    (preferred) interface supplies them.
    """
    schemes = card.get("securitySchemes")
    skills = [mapping(skill) for skill in sequence(card.get("skills"))]
    interfaces = _interfaces(card)
    preferred = interfaces[0] if interfaces else {}
    return {
        "name": text(card.get("name")),
        "url": text(card.get("url")) or preferred.get("url"),
        "version": text(card.get("version")),
        "protocol_version": text(card.get("protocolVersion"), 64) or preferred.get("protocol_version"),
        "interfaces": interfaces,
        "skills": _strings([skill.get("name") or skill.get("id") for skill in skills]),
        "capabilities": _keys(card.get("capabilities")),
        "security_schemes": _keys(schemes),
        "auth_declared": bool(
            schemes or card.get("authentication") or card.get("security") or card.get("securityRequirements")
        ),
    }


def _credentials(configurations: Any) -> list[dict[str, Any]]:
    """Credential providers without OAuth ``customParameters``, which can carry secrets."""
    out: list[dict[str, Any]] = []
    for item in sequence(configurations)[:4]:
        provider = mapping(mapping(item).get("credentialProvider"))
        oauth, iam = provider.get("oauthCredentialProvider"), provider.get("iamCredentialProvider")
        if isinstance(oauth, dict):
            out.append(
                {
                    "type": "OAUTH",
                    "providerArn": text(oauth.get("providerArn")),
                    "grantType": text(oauth.get("grantType")),
                    "scopes": _strings(oauth.get("scopes"), limit=20),
                }
            )
        elif isinstance(iam, dict):
            out.append(
                {
                    "type": "IAM",
                    "roleArn": text(iam.get("roleArn")),
                    "service": text(iam.get("service")),
                    "region": text(iam.get("region")),
                }
            )
    return out


def _source(name: str, origin: Any) -> dict[str, Any] | None:
    """Where a descriptor is synchronized from (``fromUrl``), with its credential providers."""
    if not isinstance(origin, dict):
        return None
    return {
        "descriptor": name,
        "url": text(origin.get("url")),
        # Not named 'credentials': the sanitizer would treat every value below it as a secret.
        "credential_providers": _credentials(origin.get("credentialProviderConfigurations")),
    }


@dataclass(frozen=True, slots=True)
class _Layout:
    """Where one namespace keeps its descriptor documents, relative to ``descriptors``."""

    server: tuple[str, ...]
    tools: tuple[str, ...]
    card: tuple[str, ...]
    content: str
    versions: dict[str, tuple[str, ...]]
    sources: dict[str, tuple[str, ...]]


_LAYOUTS = {
    AGENT_REGISTRY.arn_service: _Layout(
        server=("mcpServer",),
        tools=("mcpServer", "additionalData", "tools"),
        card=("a2aAgentCard",),
        content="data",
        versions={
            "mcpServer": ("mcpServer", "dataSchemaVersion"),
            "mcpServer.tools": ("mcpServer", "additionalData", "tools", "dataSchemaVersion"),
            "a2aAgentCard": ("a2aAgentCard", "dataSchemaVersion"),
            "agentSkillsDefinition": ("agentSkillsDefinition", "dataSchemaVersion"),
        },
        sources={
            "mcpServer": ("mcpServer", "source", "fromUrl"),
            "a2aAgentCard": ("a2aAgentCard", "source", "fromUrl"),
            "agentSkillsDefinition.skillMd": (
                "agentSkillsDefinition",
                "additionalData",
                "skillMd",
                "source",
                "fromUrl",
            ),
            "http": ("http", "source", "fromUrl"),
            "agui": ("agui", "source", "fromUrl"),
        },
    ),
    AGENTCORE_REGISTRY.arn_service: _Layout(
        server=("mcp", "server"),
        tools=("mcp", "tools"),
        card=("a2a", "agentCard"),
        content="inlineContent",
        versions={
            "mcp.server": ("mcp", "server", "schemaVersion"),
            "mcp.tools": ("mcp", "tools", "protocolVersion"),
            "a2a.agentCard": ("a2a", "agentCard", "schemaVersion"),
            "agentSkills.skillDefinition": ("agentSkills", "skillDefinition", "schemaVersion"),
        },
        # AgentCore records name their source outside ``descriptors``.
        sources={},
    ),
}


def descriptor_summary(
    api: RegistryApi, descriptors: Any, synchronization: Any = None
) -> tuple[dict[str, Any], str]:
    """A bounded summary of a record's descriptors and whether they parsed.

    Returns ``(summary, parse)`` where ``parse`` is ``ok``, ``absent`` (no descriptor) or
    ``invalid`` (a document that is oversized, not strict JSON or of the wrong shape; the
    summary then holds what the other documents gave). Opaque documents (custom data, skill
    markdown and definitions) are recorded only as present. ``synchronization`` is an
    AgentCore record's ``synchronizationConfiguration``.
    """
    if not isinstance(descriptors, dict) or not descriptors:
        return {}, "absent"
    layout = _LAYOUTS[api.arn_service]
    invalid = False

    def document(path: tuple[str, ...], expect: type | tuple[type, ...] = dict) -> Any:
        nonlocal invalid
        try:
            return _document(_get(descriptors, *path, layout.content), expect=expect)
        except DescriptorError:
            invalid = True
            return None

    summary: dict[str, Any] = {
        "types": sorted(str(key) for key, value in descriptors.items() if isinstance(value, dict))
    }
    mcp = mcp_summary(document(layout.server), document(layout.tools, (dict, list)))
    if mcp:
        summary["mcp"] = mcp
    card = document(layout.card)
    if card is not None:
        summary["a2a"] = a2a_summary(card)
    versions = {name: text(_get(descriptors, *path), 64) for name, path in layout.versions.items()}
    if any(versions.values()):
        summary["schema_versions"] = {name: value for name, value in versions.items() if value}
    origins = {name: _get(descriptors, *path) for name, path in layout.sources.items()}
    if api is AGENTCORE_REGISTRY:
        origins["synchronization"] = _get(synchronization, "fromUrl")
    sources = [source for name, origin in origins.items() if (source := _source(name, origin)) is not None]
    if sources:
        summary["sources"] = sources
    return summary, "invalid" if invalid else "ok"
