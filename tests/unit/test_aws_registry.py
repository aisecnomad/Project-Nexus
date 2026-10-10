"""cloud.aws registry collection: AWS Agent Registry and AgentCore registry records, without credentials.

Provider responses are synthetic and follow the installed botocore models; they were not
validated against a live account.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock
from unittest.mock import Mock

import pytest
import yaml

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud import aws as aws_module
from shadowscan.connectors.cloud.aws import DEFAULT_SERVICES, KNOWN_SERVICES, AwsConnector
from shadowscan.connectors.cloud.aws_registry import (
    AGENT_REGISTRY,
    AGENTCORE_REGISTRY,
    approval_mode,
    binding,
    descriptor_summary,
    provenance,
    source_coverage,
)
from shadowscan.engine import Engine
from shadowscan.models import Kind, ScanResult, ScanStats
from shadowscan.registries import RECONCILIATION_KEY, RECORD_KEY, parse_registry_record

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
REGION = "us-east-1"
WHEN = datetime(2026, 9, 1, tzinfo=UTC)
REGISTRY_ID = "abcd1234abcd"
REGISTRY_ARN = f"arn:aws:agent-registry:{REGION}:{ACCOUNT}:registry/{REGISTRY_ID}"
CORE_REGISTRY_ID = "efgh5678efgh"
CORE_REGISTRY_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:registry/{CORE_REGISTRY_ID}"
FOREIGN_REGISTRY_ARN = f"arn:aws:agent-registry:{REGION}:{OTHER_ACCOUNT}:registry/wxyz9876wxyz"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/support_agent-AbCdE12345"
GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/tools-gateway-pq1rs2tu3v"
CUSTOM_PARAMETER = "audience-value-that-must-not-leave-collection"
# tools/canaries/run.py parses denials in exactly this form.
CANARY_DENIED = re.compile(
    r"cloud\.aws: [a-z_]+ collection failed \(access denied \((AccessDenied|AccessDeniedException|UnauthorizedOperation)\)\)"
)
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cloud" / "aws_registry_records.jsonl"


class SDKError(Exception):
    """A botocore ClientError-shaped failure whose message must never reach a diagnostic."""

    def __init__(self, code: str) -> None:
        super().__init__(f"{code}: sensitive-provider-message arn:aws:iam::{ACCOUNT}:role/secret-context")
        self.response = {"Error": {"Code": code, "Message": "sensitive-provider-message"}}


class EndpointConnectionError(Exception):
    """Named like botocore's error for a region where the service has no endpoint."""


# Every list key the registry and AgentCore collectors read: an empty page for any listing.
EMPTY_PAGE = {
    key: []
    for key in (
        "registries",
        "registryRecords",
        "agentRuntimes",
        "items",
        "memories",
        "browserSummaries",
        "codeInterpreterSummaries",
        "workloadIdentities",
    )
}


class FakePaginator:
    """Pages for one listing request; an exception in the list is raised when its page is reached."""

    def __init__(self, client: FakeClient, op: str) -> None:
        self.client, self.op = client, op

    def paginate(self, **kwargs: Any) -> Any:
        listings = self.client.listings
        self.client.calls.append((self.op, kwargs))
        for page in listings.get((self.op, kwargs.get("registryId")), listings.get(self.op, [EMPTY_PAGE])):
            if isinstance(page, Exception):
                raise page
            yield page


class FakeClient:
    """A registry SDK client: pages by operation or ``(operation, registryId)``, details by id."""

    def __init__(
        self,
        listings: dict[Any, list[Any]] | None = None,
        registries: dict[str, Any] | None = None,
        records: dict[str, Any] | None = None,
        batches: list[Any] | None = None,
    ) -> None:
        self.listings = listings or {}
        self.registries = registries or {}
        self.records = records or {}
        self.batches = list(batches or [])
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get_paginator(self, op: str) -> FakePaginator:
        return FakePaginator(self, op)

    @staticmethod
    def _answer(table: dict[str, Any], key: str) -> Any:
        value = table[key]
        if isinstance(value, Exception):
            raise value
        return value

    def get_registry(self, *, registryId: str) -> Any:
        self.calls.append(("get_registry", {"registryId": registryId}))
        return self._answer(self.registries, registryId)

    def get_registry_record(self, *, registryId: str, recordId: str) -> Any:
        self.calls.append(("get_registry_record", {"registryId": registryId, "recordId": recordId}))
        return self._answer(self.records, recordId)

    def batch_get_discoverable_registry_record(self, *, entries: list[dict[str, Any]]) -> Any:
        self.calls.append(("batch_get_discoverable_registry_record", {"entries": entries}))
        answer = self.batches.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def registry_summary(registry_id: str = REGISTRY_ID, arn: str = REGISTRY_ARN, **extra: Any) -> dict[str, Any]:
    return {
        "name": "platform-agents",
        "description": "Agents of the platform team",
        "registryId": registry_id,
        "registryArn": arn,
        "discoveryConfiguration": {"authorizerType": "AWS_IAM"},
        "status": "READY",
        "createdAt": WHEN,
        "updatedAt": WHEN,
        **extra,
    }


def registry_detail(rules: Any = (), **extra: Any) -> dict[str, Any]:
    return {
        **registry_summary(),
        "approvalConfiguration": {"autoApprovalRules": list(rules)},
        "ResponseMetadata": {"RequestId": "r"},
        **extra,
    }


def record_summary(
    record_id: str = "rec000000001",
    *,
    status: str = "APPROVED",
    record_type: str = "AGENT",
    source: str | None = RUNTIME_ARN,
    registry_arn: str = REGISTRY_ARN,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "registryArn": registry_arn,
        "recordArn": f"{registry_arn}/record/{record_id}",
        "recordId": record_id,
        "name": f"agent-{record_id}",
        "description": "Answers support tickets",
        "recordType": record_type,
        "recordVersion": "1.0.0",
        "status": status,
        "createdAt": WHEN,
        "updatedAt": WHEN,
        "createdByAutoDetection": True,
        "createdBy": ACCOUNT,
    }
    if source is not None:
        source_type = "Gateway" if ":gateway/" in source else "Runtime"
        summary["provenanceSummaryList"] = [
            {
                "relation": "DETECTED_FROM",
                "sourceId": source,
                "sourceType": f"AWS::BedrockAgentCore::{source_type}",
            }
        ]
    return summary


def card(**extra: Any) -> str:
    return json.dumps(
        {
            "name": "Support agent",
            "url": "https://support.agents.example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "0.3.0",
            "skills": [{"id": "triage", "name": "Triage"}],
            "capabilities": {"streaming": True},
            "securitySchemes": {"sigv4": {"type": "apiKey"}},
            **extra,
        }
    )


def record_detail(record_id: str = "rec000000001", **extra: Any) -> dict[str, Any]:
    summary = record_summary(record_id)
    provenance_list = summary.pop("provenanceSummaryList")
    return {
        **summary,
        "displayName": "Support agent",
        "descriptors": {
            "a2aAgentCard": {
                "data": card(),
                "dataSchemaVersion": "0.3.0",
                "source": {
                    "fromUrl": {
                        "url": "https://support.agents.example.com/.well-known/agent-card.json",
                        "credentialProviderConfigurations": [
                            {
                                "credentialProviderType": "OAUTH",
                                "credentialProvider": {
                                    "oauthCredentialProvider": {
                                        "providerArn": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:token-vault/default/oauth2credentialprovider/support",
                                        "grantType": "CLIENT_CREDENTIALS",
                                        "scopes": ["agent.read"],
                                        "customParameters": {"audience": CUSTOM_PARAMETER},
                                    }
                                },
                            }
                        ],
                    }
                },
            }
        },
        "provenance": [
            {
                **provenance_list[0],
                "sourceDetails": {
                    "agentcoreRuntime": {
                        "protocolConfiguration": {"serverProtocol": "A2A"},
                        "authorizerConfiguration": {
                            "customJWTAuthorizer": {"discoveryUrl": "https://issuer.example.com/.well-known"}
                        },
                    }
                },
            }
        ],
        "ResponseMetadata": {"RequestId": "r"},
        **extra,
    }


def context(index: Any, **config: Any) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-10-10T00:00:00+00:00")
    return ctx


def connector(
    index: Any,
    clients: dict[str, Any],
    *,
    services: tuple[str, ...] = ("registry", "agentcore"),
    **config: Any,
) -> AwsConnector:
    instance = AwsConnector(
        context(index, account_id=ACCOUNT, services=list(services), regions=[REGION], **config)
    )
    instance.check_requirements = Mock()  # type: ignore[method-assign]
    instance._session_ = Mock()  # type: ignore[method-assign]
    instance._client = lambda service, region=None: clients[service]  # type: ignore[method-assign]
    return instance


def agent_registry_client(**overrides: Any) -> FakeClient:
    listings: dict[Any, Any] = {
        "list_registries": [{"registries": [registry_summary()]}],
        "list_registry_records": [{"registryRecords": [record_summary()]}],
    }
    listings.update(overrides.pop("listings", {}))
    return FakeClient(
        listings=listings,
        registries=overrides.pop("registries", {REGISTRY_ID: registry_detail()}),
        records=overrides.pop("records", {"rec000000001": record_detail()}),
        **overrides,
    )


def collect(instance: AwsConnector) -> list[dict[str, Any]]:
    return [record for record in instance.collect() if record["_kind"] != "account"]


def of_kind(records: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [record for record in records if record["_kind"] == kind]


def analyze(instance: AwsConnector, records: list[dict[str, Any]]) -> list[Any]:
    account = {"_kind": "account", "account": ACCOUNT, "regions": [REGION]}
    return list(instance.analyze([account, *records]))


def warnings(instance: AwsConnector) -> list[str]:
    assert instance.ctx.stats is not None
    return instance.ctx.stats.warnings


# ------------------------------------------------------------------ configuration
def test_default_services_exclude_registry_and_make_no_registry_call(index):
    assert "registry" in KNOWN_SERVICES and "registry" not in DEFAULT_SERVICES
    assert KNOWN_SERVICES.difference(DEFAULT_SERVICES) == {"registry"}
    default = AwsConnector(context(index))
    assert default.services == set(DEFAULT_SERVICES)
    opted_in = AwsConnector(context(index, services=["registry"]))
    assert opted_in.services == {"registry"}
    # Without services, every other collector runs and the registry collectors never do.
    instance = AwsConnector(context(index, account_id=ACCOUNT, regions=[REGION]))
    instance._session_ = Mock()  # type: ignore[method-assign]
    collectors = [name for name in dir(AwsConnector) if name.startswith("_collect_")]
    for name in collectors:
        setattr(instance, name, Mock(return_value=iter([])))
    list(instance.collect())
    called = {name for name in collectors if getattr(instance, name).called}
    assert {"_collect_registries", "_collect_registry_arns"}.isdisjoint(called)
    assert {"_collect_agentcore", "_collect_bedrock", "_collect_iam", "_collect_cloudtrail"} <= called


@pytest.mark.parametrize(
    "value",
    [
        "arn:aws:agent-registry:us-east-1:12345678901:registry/abcd1234abcd",
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:registry/abcd1234abcd",
        f"{REGISTRY_ARN}/record/rec000000001",
        "arn:aws:agent-registry:us-east-1:123456789012:registry/abcd*",
        ["ok", 1],
    ],
)
def test_registry_arns_accept_only_exact_agent_registry_arns(index, value):
    with pytest.raises(ConnectorError, match="registry_arns"):
        AwsConnector(context(index, services=["registry"], registry_arns=value))


def test_registry_arns_need_the_registry_service(index):
    with pytest.raises(ConnectorError, match="registry_arns needs 'registry' in services"):
        AwsConnector(context(index, registry_arns=[FOREIGN_REGISTRY_ARN]))
    assert AwsConnector(
        context(index, services="registry", registry_arns=FOREIGN_REGISTRY_ARN)
    ).registry_arns == [FOREIGN_REGISTRY_ARN]
    assert AwsConnector(context(index, services=["registry"])).registry_arns == []


def test_registry_arns_from_a_list_are_kept_in_order(index):
    other = "arn:aws-us-gov:agent-registry:us-gov-west-1:210987654321:registry/abcdabcdabcdabcd"
    configured = AwsConnector(
        context(
            index, services=["registry"], registry_arns=[FOREIGN_REGISTRY_ARN, other, FOREIGN_REGISTRY_ARN]
        )
    )
    assert configured.registry_arns == [FOREIGN_REGISTRY_ARN, other]


# ------------------------------------------------------------------ approval mode
@pytest.mark.parametrize(
    "api,configuration,expected",
    [
        (AGENT_REGISTRY, {"autoApprovalRules": ["APPROVE_ALL"]}, "auto"),
        (AGENT_REGISTRY, {"autoApprovalRules": ["APPROVE_FUTURE_RULE"]}, "auto"),
        (AGENT_REGISTRY, {"autoApprovalRules": []}, "manual"),
        (AGENT_REGISTRY, {}, "manual"),
        (AGENT_REGISTRY, {"autoApprovalRules": "APPROVE_ALL"}, "unknown"),
        (AGENT_REGISTRY, {"autoApprovalRules": [], "futureSetting": 1}, "unknown"),
        (AGENT_REGISTRY, None, "unknown"),
        (AGENTCORE_REGISTRY, {"autoApproval": True}, "auto"),
        (AGENTCORE_REGISTRY, {"autoApproval": False}, "manual"),
        (AGENTCORE_REGISTRY, {}, "manual"),
        (AGENTCORE_REGISTRY, {"autoApproval": "true"}, "unknown"),
        (AGENTCORE_REGISTRY, {"futureSetting": 1}, "unknown"),
        (AGENTCORE_REGISTRY, ["autoApproval"], "unknown"),
    ],
)
def test_approval_mode_reads_each_namespace_configuration(api, configuration, expected):
    assert approval_mode(api, configuration) == expected


# ------------------------------------------------------------------ collection
def test_registry_records_are_collected_sanitized_and_bound_to_their_runtime(index):
    client = agent_registry_client()
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    records = collect(instance)
    assert not warnings(instance)
    [registry] = of_kind(records, "agent-registry")
    assert registry["approvalConfiguration"] == {"autoApprovalRules": []}
    assert registry["authorizerType"] == "AWS_IAM"
    [record] = of_kind(records, "agent-registry-record")
    assert record["_listing_complete"] is True and record["_detail"] == "observed"
    assert record["provenance"] == [
        {
            "relation": "DETECTED_FROM",
            "sourceId": RUNTIME_ARN,
            "sourceType": "AWS::BedrockAgentCore::Runtime",
            "serverProtocol": "A2A",
            "_coverage": "in-scope",
        }
    ]
    summary = record["_descriptor_summary"]
    assert summary["a2a"]["skills"] == ["Triage"] and summary["a2a"]["auth_declared"] is True
    [source] = summary["sources"]
    assert source["credential_providers"] == [
        {
            "type": "OAUTH",
            "providerArn": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:token-vault/default/oauth2credentialprovider/support",
            "grantType": "CLIENT_CREDENTIALS",
            "scopes": ["agent.read"],
        }
    ]
    exported = json.dumps(records, default=str)
    # Raw descriptor documents, authorizer settings and OAuth custom parameters never leave collection.
    for withheld in (
        CUSTOM_PARAMETER,
        "customParameters",
        '"data"',
        "issuer.example.com",
        "ResponseMetadata",
    ):
        assert withheld not in exported
    [finding] = analyze(instance, records)
    contract = finding.metadata[RECORD_KEY]
    assert parse_registry_record(contract) is not None
    assert contract == {
        "schema": "shadowscan.registry-record/v1",
        "registry": "aws-agent-registry",
        "registry_id": REGISTRY_ARN,
        "record_id": "rec000000001",
        "status": "approved",
        "descriptor_type": "agent",
        "bindings": [
            {
                "resource": RUNTIME_ARN,
                "provider": "aws",
                "account": ACCOUNT,
                "region": REGION,
                "coverage": "in-scope",
            }
        ],
        "listing_complete": True,
        "approval_mode": "manual",
        "updated_at": str(WHEN),
    }
    assert finding.kind == Kind.AGENT and finding.resource_type == "agent-registry-record"
    assert finding.resource == f"{REGISTRY_ARN}/record/rec000000001" and finding.account == ACCOUNT
    assert finding.metadata["registry_auto_approval"] is False
    assert finding.confidence == 0.5  # a declaration, not proof that the agent runs
    assert {"cloud.aws-bedrock-agents", "protocol.a2a"} <= set(finding.frameworks)
    assert not warnings(instance)


def test_bindings_are_out_of_scope_without_clean_agentcore_collection(index):
    clients = {"agent-registry-control": agent_registry_client(), "bedrock-agentcore-control": FakeClient()}
    without_agentcore = connector(index, clients, services=("registry",))
    [record] = of_kind(collect(without_agentcore), "agent-registry-record")
    assert record["provenance"][0]["_coverage"] == "out-of-scope"
    denied = FakeClient(listings={"list_agent_runtimes": [SDKError("AccessDeniedException")]})
    clients = {"agent-registry-control": agent_registry_client(), "bedrock-agentcore-control": denied}
    partial = connector(index, clients)
    [record] = of_kind(collect(partial), "agent-registry-record")
    assert record["provenance"][0]["_coverage"] == "out-of-scope"
    assert partial.ctx.stats.incomplete


def test_source_coverage_and_bindings_need_an_exact_agentcore_arn():
    regions = {REGION}
    assert source_coverage(RUNTIME_ARN, ACCOUNT, regions) == "in-scope"
    assert source_coverage(GATEWAY_ARN, ACCOUNT, regions) == "in-scope"
    assert source_coverage(RUNTIME_ARN, OTHER_ACCOUNT, regions) == "out-of-scope"
    assert source_coverage(RUNTIME_ARN, None, regions) == "out-of-scope"
    assert source_coverage(RUNTIME_ARN, ACCOUNT, {"eu-west-1"}) == "out-of-scope"
    assert source_coverage(f"{RUNTIME_ARN}/runtime-endpoint/DEFAULT", ACCOUNT, regions) == "out-of-scope"
    assert binding({"sourceId": GATEWAY_ARN, "_coverage": "in-scope"})["coverage"] == "in-scope"
    assert binding({"sourceId": RUNTIME_ARN, "_coverage": "bogus"})["coverage"] == "unknown"
    # A declared source type must agree with the ARN; any other source binds nothing.
    assert binding({"sourceId": RUNTIME_ARN, "sourceType": "AWS::BedrockAgentCore::Gateway"}) is None
    assert binding({"sourceId": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:f"}) is None
    assert binding({"sourceId": 1}) is None and binding("x") is None
    with pytest.raises(ValueError):
        provenance([{"sourceId": RUNTIME_ARN}] * 9, lambda source: "unknown")
    with pytest.raises(ValueError):
        provenance([{"relation": "DETECTED_FROM"}], lambda source: "unknown")
    assert provenance(None, lambda source: "unknown") == []


def test_agentcore_registry_records_use_their_own_namespace_and_auto_approval(index):
    server = json.dumps(
        {
            "name": "example.docs/search",
            "version": "3.0.0",
            "remotes": [{"type": "streamable-http", "url": "http://docs.agents.example.com/mcp"}],
            "packages": [{"registryType": "npm", "identifier": "@example/docs-search", "version": "3.0.0"}],
        }
    )
    tools = json.dumps({"tools": [{"name": "search_docs"}, {"description": "unnamed"}]})
    core = FakeClient(
        listings={
            "list_registries": [
                {
                    "registries": [
                        registry_summary(CORE_REGISTRY_ID, CORE_REGISTRY_ARN, authorizerType="AWS_IAM")
                    ]
                }
            ],
            "list_registry_records": [
                {
                    "registryRecords": [
                        {
                            "registryArn": CORE_REGISTRY_ARN,
                            "recordArn": f"{CORE_REGISTRY_ARN}/record/mcp000000001",
                            "recordId": "mcp000000001",
                            "name": "docs-search",
                            "descriptorType": "MCP",
                            "recordVersion": "3",
                            "status": "APPROVED",
                            "createdAt": WHEN,
                            "updatedAt": WHEN,
                        }
                    ]
                }
            ],
        },
        registries={
            CORE_REGISTRY_ID: {
                **registry_summary(CORE_REGISTRY_ID, CORE_REGISTRY_ARN),
                "approvalConfiguration": {"autoApproval": True},
            }
        },
        records={
            "mcp000000001": {
                "descriptors": {
                    "mcp": {
                        "server": {"schemaVersion": "2025-09-29", "inlineContent": server},
                        "tools": {"protocolVersion": "2025-06-18", "inlineContent": tools},
                    }
                },
                "synchronizationType": "URL",
                "synchronizationConfiguration": {
                    "fromUrl": {
                        "url": "https://docs.agents.example.com/server.json",
                        "credentialProviderConfigurations": [
                            {
                                "credentialProviderType": "IAM",
                                "credentialProvider": {
                                    "iamCredentialProvider": {
                                        "roleArn": f"arn:aws:iam::{ACCOUNT}:role/registry-sync",
                                        "service": "execute-api",
                                        "region": REGION,
                                    }
                                },
                            }
                        ],
                    }
                },
            }
        },
    )
    empty = FakeClient(listings={"list_registries": [{"registries": []}]})
    instance = connector(index, {"agent-registry-control": empty, "bedrock-agentcore-control": core})
    records = collect(instance)
    [record] = of_kind(records, "agentcore-registry-record")
    assert record["descriptorType"] == "MCP" and "recordType" not in record
    assert record["_descriptor_summary"]["mcp"] == {
        "name": "example.docs/search",
        "version": "3.0.0",
        "remotes": ["http://docs.agents.example.com/mcp"],
        "packages": ["npm:@example/docs-search@3.0.0"],
        "tools": ["search_docs"],
    }
    assert record["_descriptor_summary"]["schema_versions"] == {
        "mcp.server": "2025-09-29",
        "mcp.tools": "2025-06-18",
    }
    [finding] = analyze(instance, records)
    assert finding.kind == Kind.MCP_SERVER and finding.resource_type == "agentcore-registry-record"
    contract = finding.metadata[RECORD_KEY]
    assert (contract["registry"], contract["approval_mode"], contract["bindings"]) == (
        "aws-agentcore-registry",
        "auto",
        [],
    )
    assert finding.metadata["registry_auto_approval"] is True
    assert "not reviewed by a person" in finding.evidence[0].description
    assert "mcp-insecure-transport" in finding.tags
    # The synchronization role is a weightless correlation location, never the resource.
    roles = [e.location for e in finding.evidence if e.signal == "aws:registry-record-reference"]
    assert roles == [f"arn:aws:iam::{ACCOUNT}:role/registry-sync"]
    assert not warnings(instance)


def test_access_denied_listing_is_incomplete_with_the_canary_diagnostic(index):
    client = agent_registry_client(listings={"list_registries": [SDKError("AccessDeniedException")]})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    assert of_kind(collect(instance), "agent-registry-record") == []
    assert instance.ctx.stats.incomplete
    denied = [w for w in warnings(instance) if "list_registries" in w]
    assert denied and CANARY_DENIED.fullmatch(denied[0])
    assert all(
        "sensitive-provider-message" not in w and "secret-context" not in w for w in warnings(instance)
    )


def test_denied_record_listing_keeps_earlier_pages_and_marks_the_listing_partial(index):
    pages = [{"registryRecords": [record_summary()]}, SDKError("ThrottlingException")]
    client = agent_registry_client(listings={"list_registry_records": pages})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    records = collect(instance)
    [record] = of_kind(records, "agent-registry-record")
    assert record["_listing_complete"] is False
    assert "cloud.aws: list_registry_records collection failed (SDKError)" in warnings(instance)
    [finding] = analyze(instance, records)
    assert finding.metadata[RECORD_KEY]["listing_complete"] is False


def test_throttled_record_details_keep_the_summary(index):
    client = agent_registry_client(records={"rec000000001": SDKError("ThrottlingException")})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    records = collect(instance)
    [record] = of_kind(records, "agent-registry-record")
    assert record["_detail"] == "unknown" and record["_descriptor_parse"] == "absent"
    assert record["status"] == "APPROVED" and record["_listing_complete"] is True
    # The listing's provenance summary still binds the record.
    assert record["provenance"][0]["sourceId"] == RUNTIME_ARN
    assert "cloud.aws: get_registry_record request failed (ThrottlingException)" in warnings(instance)
    [finding] = analyze(instance, records)
    assert finding.metadata[RECORD_KEY]["status"] == "approved"
    assert "cloud.aws: registry record details unavailable; descriptor coverage unknown" in warnings(instance)


def test_denied_registry_details_leave_the_approval_mode_unknown(index):
    client = agent_registry_client(registries={REGISTRY_ID: SDKError("AccessDeniedException")})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    records = collect(instance)
    [registry] = of_kind(records, "agent-registry")
    assert registry["approvalConfiguration"] is None
    assert "cloud.aws: get_registry access denied (AccessDeniedException)" in warnings(instance)
    [finding] = analyze(instance, records)
    assert finding.metadata[RECORD_KEY]["approval_mode"] == "unknown"
    assert finding.metadata["registry_auto_approval"] is None


def test_unsupported_region_and_missing_sdk_service_are_incomplete(index):
    unreachable = agent_registry_client(
        listings={"list_registries": [EndpointConnectionError("no endpoint")]}
    )
    instance = connector(
        index, {"agent-registry-control": unreachable, "bedrock-agentcore-control": FakeClient()}
    )
    collect(instance)
    assert "cloud.aws: list_registries collection failed (EndpointConnectionError)" in warnings(instance)

    def old_sdk(service: str, region: str | None = None) -> Any:
        if service in {"agent-registry-control", "bedrock-agentcore-control"}:
            raise RuntimeError("UnknownServiceError")
        raise AssertionError(service)

    instance = connector(index, {}, services=("registry",))
    instance._client = old_sdk  # type: ignore[method-assign]
    assert collect(instance) == []
    assert warnings(instance) == [
        "cloud.aws: Agent Registry unavailable in installed SDK; collection incomplete",
        "cloud.aws: AgentCore registry unavailable in installed SDK; collection incomplete",
    ]


def test_record_pagination_limit_marks_the_listing_partial(index, monkeypatch):
    monkeypatch.setattr(aws_module, "MAX_LIST_PAGES", 1)
    pages = [{"registryRecords": [record_summary()], "nextToken": "more"}]
    client = agent_registry_client(listings={"list_registry_records": pages})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    [record] = of_kind(collect(instance), "agent-registry-record")
    assert record["_listing_complete"] is False
    assert "cloud.aws: list_registry_records pagination limit reached" in warnings(instance)


def test_max_registry_records_caps_each_namespace_per_region(index):
    summaries = [record_summary(f"rec00000000{n}", source=None) for n in range(1, 4)]
    client = agent_registry_client(
        listings={"list_registry_records": [{"registryRecords": summaries}]},
        records={s["recordId"]: {} for s in summaries},
    )
    instance = connector(
        index,
        {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()},
        max_registry_records=2,
    )
    records = of_kind(collect(instance), "agent-registry-record")
    assert [r["recordId"] for r in records] == ["rec000000001", "rec000000002"]
    assert {r["_listing_complete"] for r in records} == {False}
    assert "cloud.aws: max_registry_records reached for Agent Registry in us-east-1" in warnings(instance)
    # The third record's details were never requested.
    assert (
        "get_registry_record",
        {"registryId": REGISTRY_ID, "recordId": "rec000000003"},
    ) not in client.calls


def test_invalid_descriptor_json_is_incomplete_and_never_exported(index):
    detail = record_detail()
    detail["descriptors"]["a2aAgentCard"]["data"] = '{"name": "a", "name": "b"}'
    detail["descriptors"]["mcpServer"] = {"data": "x" * 102_401}
    client = agent_registry_client(records={"rec000000001": detail})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    records = collect(instance)
    [record] = of_kind(records, "agent-registry-record")
    assert record["_descriptor_parse"] == "invalid"
    assert "a2a" not in record["_descriptor_summary"] and "mcp" not in record["_descriptor_summary"]
    assert "x" * 1000 not in json.dumps(records, default=str)
    assert any("descriptor is not a bounded JSON document" in w for w in warnings(instance))
    analyze(instance, records)
    assert "cloud.aws: registry record descriptor invalid; descriptor coverage unknown" in warnings(instance)


@pytest.mark.parametrize(
    "descriptors,expected",
    [
        (None, ({}, "absent")),
        ({}, ({}, "absent")),
        ({"custom": {"data": "opaque text, never parsed"}}, ({"types": ["custom"]}, "ok")),
        ({"a2aAgentCard": {"data": "[1, 2]"}}, ({"types": ["a2aAgentCard"]}, "invalid")),
        ({"a2aAgentCard": {"data": 7}}, ({"types": ["a2aAgentCard"]}, "invalid")),
        ({"a2aAgentCard": {"data": "[" * 5000 + "]" * 5000}}, ({"types": ["a2aAgentCard"]}, "invalid")),
        (
            {"mcpServer": {"additionalData": {"tools": {"data": '[{"name": "t"}]'}}}},
            ({"types": ["mcpServer"], "mcp": {"tools": ["t"]}}, "ok"),
        ),
        # A credential provider of neither known type, or not an object, is left out.
        (
            {
                "http": {
                    "source": {
                        "fromUrl": {
                            "url": "https://agents.example.com/api",
                            "credentialProviderConfigurations": [{"credentialProvider": {"future": {}}}, "x"],
                        }
                    }
                }
            },
            (
                {
                    "types": ["http"],
                    "sources": [
                        {
                            "descriptor": "http",
                            "url": "https://agents.example.com/api",
                            "credential_providers": [],
                        }
                    ],
                },
                "ok",
            ),
        ),
    ],
)
def test_descriptor_summary_bounds_and_parses_strictly(descriptors, expected):
    assert descriptor_summary(AGENT_REGISTRY, descriptors) == expected


def test_a2a_card_without_security_is_tagged(index):
    detail = record_detail()
    detail["descriptors"]["a2aAgentCard"]["data"] = card(securitySchemes={})
    client = agent_registry_client(records={"rec000000001": detail})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    [finding] = analyze(instance, collect(instance))
    assert "no-auth-declared" in finding.tags


def test_malformed_record_is_skipped_and_its_registry_listing_is_partial(index):
    summaries = [{"recordArn": "no-id"}, record_summary()]
    client = agent_registry_client(listings={"list_registry_records": [{"registryRecords": summaries}]})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    [record] = of_kind(collect(instance), "agent-registry-record")
    assert record["recordId"] == "rec000000001" and record["_listing_complete"] is False
    assert any("malformed Agent Registry record record skipped (KeyError)" in w for w in warnings(instance))


def test_malformed_registry_is_skipped_and_the_others_survive(index):
    registries = [{"registryArn": REGISTRY_ARN}, registry_summary()]
    client = agent_registry_client(listings={"list_registries": [{"registries": registries}]})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    assert len(of_kind(collect(instance), "agent-registry")) == 1
    assert any("malformed Agent Registry registry record skipped (KeyError)" in w for w in warnings(instance))


def test_mistyped_provider_identifiers_and_details_are_reported(index):
    registries = [
        registry_summary(registry_id=7),
        {key: value for key, value in registry_summary("zzzz1111zzzz").items() if key != "registryArn"},
        registry_summary(),
    ]
    summaries = [{**record_summary(), "recordId": 7}, record_summary()]
    client = agent_registry_client(
        listings={
            "list_registries": [{"registries": registries}],
            "list_registry_records": [{"registryRecords": summaries}],
        },
        registries={"zzzz1111zzzz": {}, REGISTRY_ID: ["not", "a", "mapping"]},
        records={"rec000000001": "not a mapping"},
    )
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    records = collect(instance)
    [registry] = of_kind(records, "agent-registry")
    assert registry["approvalConfiguration"] is None
    [record] = of_kind(records, "agent-registry-record")
    assert record["_detail"] == "unknown" and record["_listing_complete"] is False
    assert warnings(instance) == [
        "cloud.aws: malformed Agent Registry registry record skipped (ValueError); coverage incomplete",
        "cloud.aws: malformed Agent Registry registry record skipped (ValueError); coverage incomplete",
        "cloud.aws: invalid Agent Registry registry details; approval mode unknown",
        "cloud.aws: malformed Agent Registry record record skipped (ValueError); coverage incomplete",
        "cloud.aws: invalid Agent Registry record details; descriptor coverage unknown",
    ]


def test_a_listing_never_speaks_for_another_registry(index):
    other = REGISTRY_ARN.replace(REGISTRY_ID, "ffff0000ffff")
    client = agent_registry_client(records={"rec000000001": record_detail(registryArn=other)})
    instance = connector(index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()})
    assert of_kind(collect(instance), "agent-registry-record") == []
    assert warnings(instance) == [
        "cloud.aws: malformed Agent Registry record record skipped (ValueError); coverage incomplete"
    ]
    foreign = {**discoverable_summary(), "registryArn": other, "recordArn": f"{other}/record/ext000000001"}
    discovery = discovery_client(batches=[{"registryRecords": [foreign], "errors": []}])
    clients = {
        "agent-registry-control": FakeClient(),
        "bedrock-agentcore-control": FakeClient(),
        "agent-registry": discovery,
    }
    instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
    assert of_kind(collect(instance), "agent-registry-discoverable-record") == []
    assert instance.ctx.stats.incomplete


def test_record_without_an_update_time_has_no_updated_at(index):
    record = json.loads(FIXTURE.read_text().splitlines()[6])
    del record["updatedAt"]
    [finding] = analyze(AwsConnector(context(index)), [record])
    assert "updated_at" not in finding.metadata[RECORD_KEY] and finding.last_seen is None


@pytest.mark.parametrize(
    "record_type,descriptor_type,kind",
    [
        ("MCP", "mcp", Kind.MCP_SERVER),
        ("GATEWAY", "mcp", Kind.MCP_SERVER),
        ("AGENT", "agent", Kind.AGENT),
        ("SKILL", "agent-skills", Kind.AGENT_CONFIG),
        ("CUSTOM", "custom", Kind.CLOUD_RESOURCE),
    ],
)
def test_record_types_map_to_kinds_and_identity_ignores_status(index, record_type, descriptor_type, kind):
    ids = set()
    for status in ("APPROVED", "PENDING_APPROVAL", "REJECTED", "CREATE_FAILED"):
        summary = record_summary(status=status, record_type=record_type, source=None)
        client = agent_registry_client(
            listings={"list_registry_records": [{"registryRecords": [summary]}]},
            records={"rec000000001": {}},
        )
        instance = connector(
            index, {"agent-registry-control": client, "bedrock-agentcore-control": FakeClient()}
        )
        [finding] = analyze(instance, collect(instance))
        assert finding.kind == kind and finding.metadata[RECORD_KEY]["descriptor_type"] == descriptor_type
        expected = {"APPROVED": "approved", "PENDING_APPROVAL": "pending", "REJECTED": "rejected"}
        assert finding.metadata[RECORD_KEY]["status"] == expected.get(status, "unknown")
        ids.add(finding.id)
    assert len(ids) == 1


def test_unrecognized_record_type_is_custom_and_incomplete(index):
    record = json.loads(FIXTURE.read_text().splitlines()[6])
    record["recordType"] = "FUTURE_TYPE"
    instance = AwsConnector(context(index))
    [finding] = analyze(instance, [record])
    assert finding.kind == Kind.CLOUD_RESOURCE and finding.metadata[RECORD_KEY]["descriptor_type"] == "custom"
    assert warnings(instance) == ["cloud.aws: registry record type not recognized; classified as custom"]


@pytest.mark.parametrize(
    "change",
    [
        {"recordArn": f"{CORE_REGISTRY_ARN}/record/rec000000001"},
        {"recordArn": f"{REGISTRY_ARN}/record/rec000000009"},
        {"registryArn": "arn:aws:agent-registry:us-east-1:123456789012:registry/short"},
        {"recordType": 1},
        {"status": None},
        {"name": {"nested": "name"}},
        {"provenance": "not-a-list"},
    ],
)
def test_record_fields_that_break_the_record_shape_are_invalid(index, change):
    record = json.loads(FIXTURE.read_text().splitlines()[6])
    record.update(change)
    instance = AwsConnector(context(index))
    assert analyze(instance, [record]) == []
    assert warnings(instance) == ["cloud.aws: record has invalid fields for its _kind"]


@pytest.mark.parametrize("kind", ["agent-registry", "agentcore-registry"])
def test_registry_container_records_need_a_namespace_arn(index, kind):
    instance = AwsConnector(context(index))
    arn = REGISTRY_ARN if kind == "agent-registry" else CORE_REGISTRY_ARN
    assert analyze(instance, [{"_kind": kind, "registryArn": arn}]) == []
    assert not warnings(instance)
    wrong = CORE_REGISTRY_ARN if kind == "agent-registry" else REGISTRY_ARN
    assert analyze(instance, [{"_kind": kind, "registryArn": wrong}]) == []
    assert warnings(instance) == ["cloud.aws: record has invalid fields for its _kind"]


# ------------------------------------------------------------------ discovery API (other accounts)
def discoverable_summary() -> dict[str, Any]:
    """A discovery API summary: no provenance or creator, plus the descriptor types."""
    summary = record_summary(
        "ext000000001", record_type="MCP", source=None, registry_arn=FOREIGN_REGISTRY_ARN
    )
    for field in ("createdByAutoDetection", "createdBy"):
        summary.pop(field)
    return {**summary, "descriptorTypes": ["mcpServer"]}


def discovery_client(*, batches: list[Any] | None = None, pages: list[Any] | None = None) -> FakeClient:
    summary = discoverable_summary()
    detail = {
        **{key: value for key, value in summary.items() if key != "descriptorTypes"},
        "descriptors": {
            "mcpServer": {
                "data": json.dumps(
                    {"name": "example.partner/pricing", "remotes": [{"url": "https://p.example.com/mcp"}]}
                )
            }
        },
    }
    return FakeClient(
        listings={"list_discoverable_registry_records": pages or [{"registryRecords": [summary]}]},
        batches=batches if batches is not None else [{"registryRecords": [detail], "errors": []}],
    )


def test_registry_arns_read_approved_records_of_another_account(index):
    discovery = discovery_client()
    empty = FakeClient(listings={"list_registries": [{"registries": []}]})
    clients = {
        "agent-registry-control": empty,
        "bedrock-agentcore-control": empty,
        "agent-registry": discovery,
    }
    instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
    records = collect(instance)
    [record] = of_kind(records, "agent-registry-discoverable-record")
    assert record["_listing_complete"] is True and record["_detail"] == "observed"
    assert (
        "batch_get_discoverable_registry_record",
        {"entries": [{"registryId": FOREIGN_REGISTRY_ARN, "recordIds": ["ext000000001"]}]},
    ) in discovery.calls
    [finding] = analyze(instance, records)
    # Another account's record keeps its own account and is not an unresolved identity.
    assert finding.account == OTHER_ACCOUNT and "identity_unresolved" not in finding.metadata
    assert finding.metadata["registry_coverage"] == "approved-only"
    contract = finding.metadata[RECORD_KEY]
    assert (contract["listing_complete"], contract["approval_mode"], contract["bindings"]) == (
        False,
        "unknown",
        [],
    )
    assert not warnings(instance)


def test_control_plane_records_from_another_account_stay_unresolved(index):
    record = json.loads(FIXTURE.read_text().splitlines()[6])
    foreign = REGISTRY_ARN.replace(ACCOUNT, OTHER_ACCOUNT)
    record.update(registryArn=foreign, recordArn=f"{foreign}/record/rec000000001")
    instance = AwsConnector(context(index))
    [finding] = analyze(instance, [record])
    assert finding.metadata["identity_unresolved"] is True
    assert any("identity unresolved" in w for w in warnings(instance))


def test_registry_listed_by_the_control_plane_is_not_read_again(index):
    discovery = discovery_client()
    clients = {
        "agent-registry-control": agent_registry_client(),
        "bedrock-agentcore-control": FakeClient(),
        "agent-registry": discovery,
    }
    instance = connector(index, clients, registry_arns=[REGISTRY_ARN])
    records = collect(instance)
    assert of_kind(records, "agent-registry-discoverable-record") == [] and discovery.calls == []
    assert not warnings(instance)


def test_batch_errors_report_codes_only_and_leave_details_unknown(index):
    errors = [
        {
            "registryId": FOREIGN_REGISTRY_ARN,
            "recordId": "ext000000001",
            "errorCode": "ACCESS_DENIED",
            "message": "sensitive-provider-message",
        },
        {"registryId": FOREIGN_REGISTRY_ARN, "recordId": "x", "errorCode": {"odd": 1}},
    ]
    discovery = discovery_client(batches=[{"registryRecords": [], "errors": errors}])
    clients = {
        "agent-registry-control": FakeClient(),
        "bedrock-agentcore-control": FakeClient(),
        "agent-registry": discovery,
    }
    instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
    records = collect(instance)
    [record] = of_kind(records, "agent-registry-discoverable-record")
    assert record["_detail"] == "unknown" and "errors" not in record
    assert (
        "cloud.aws: batch_get_discoverable_registry_record failed for 2 record(s) (ACCESS_DENIED, unrecognized)"
        in warnings(instance)
    )
    assert all("sensitive-provider-message" not in w for w in warnings(instance))


@pytest.mark.parametrize(
    "answer", [SDKError("ValidationException"), ["not", "a", "mapping"], {"registryRecords": []}]
)
def test_failed_or_malformed_batches_are_incomplete(index, answer):
    discovery = discovery_client(batches=[answer])
    clients = {
        "agent-registry-control": FakeClient(),
        "bedrock-agentcore-control": FakeClient(),
        "agent-registry": discovery,
    }
    instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
    [record] = of_kind(collect(instance), "agent-registry-discoverable-record")
    assert record["_detail"] == "unknown" and instance.ctx.stats.incomplete


def test_malformed_discoverable_record_is_skipped_and_the_listing_is_partial(index):
    pages = [{"registryRecords": [{**discoverable_summary(), "recordId": 7}, discoverable_summary()]}]
    discovery = discovery_client(pages=pages)
    clients = {
        "agent-registry-control": FakeClient(),
        "bedrock-agentcore-control": FakeClient(),
        "agent-registry": discovery,
    }
    instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
    [record] = of_kind(collect(instance), "agent-registry-discoverable-record")
    assert record["recordId"] == "ext000000001" and record["_listing_complete"] is False
    assert warnings(instance) == [
        "cloud.aws: malformed Agent Registry discoverable record record skipped (ValueError); coverage incomplete"
    ]


def test_jwt_registry_rejects_the_discovery_api_and_the_scan_is_incomplete(index):
    discovery = discovery_client(pages=[SDKError("UnauthorizedException")])
    clients = {
        "agent-registry-control": FakeClient(),
        "bedrock-agentcore-control": FakeClient(),
        "agent-registry": discovery,
    }
    instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
    assert of_kind(collect(instance), "agent-registry-discoverable-record") == []
    assert "cloud.aws: list_discoverable_registry_records collection failed (SDKError)" in warnings(instance)


def test_discovery_without_sdk_support_is_incomplete(index):
    clients = {"agent-registry-control": FakeClient(), "bedrock-agentcore-control": FakeClient()}
    instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
    assert collect(instance) == []
    assert (
        "cloud.aws: Agent Registry discovery unavailable in installed SDK; collection incomplete"
        in warnings(instance)
    )


# ------------------------------------------------------------------ export, replay and the engine
def test_registry_export_round_trip_keeps_identity_and_withholds_custom_parameters(tmp_path, index):
    pytest.importorskip("boto3")
    dump = tmp_path / "aws.jsonl"
    clients = {"agent-registry-control": agent_registry_client(), "bedrock-agentcore-control": FakeClient()}
    ctx = context(index, account_id=ACCOUNT, services=["registry"], regions=[REGION], _dump_path=str(dump))
    instance = AwsConnector(ctx)
    with (
        mock.patch.object(instance, "_session_", lambda: None),
        mock.patch.object(instance, "_client", lambda service, region=None: clients[service]),
    ):
        live = instance.run()
    assert not ctx.stats.incomplete and len(live) == 1
    text = dump.read_text()
    assert CUSTOM_PARAMETER not in text and "customParameters" not in text
    offline_ctx = context(index, input=str(dump))
    offline = AwsConnector(offline_ctx).run()
    assert not offline_ctx.stats.incomplete and not offline_ctx.stats.warnings
    assert [(f.id, f.resource, f.account, f.metadata[RECORD_KEY]) for f in offline] == [
        (f.id, f.resource, f.account, f.metadata[RECORD_KEY]) for f in live
    ]


@pytest.mark.parametrize(
    "marker,warning",
    [
        (
            {"_listing_complete": False},
            "cloud.aws: registry record listing incomplete; records may be missing",
        ),
        (
            {"_detail": "unknown"},
            "cloud.aws: registry record details unavailable; descriptor coverage unknown",
        ),
        (
            {"_descriptor_parse": "invalid"},
            "cloud.aws: registry record descriptor invalid; descriptor coverage unknown",
        ),
    ],
)
def test_replayed_coverage_gaps_stay_incomplete(tmp_path, index, marker, warning):
    lines = FIXTURE.read_text().splitlines()
    records = [json.loads(line) for line in lines]
    for record in records[6:8]:
        record.update(marker)
    export = tmp_path / "export.jsonl"
    export.write_text("\n".join(json.dumps(record) for record in records))
    ctx = context(index, input=str(export))
    AwsConnector(ctx).run()
    # One warning per kind of gap, however many records carry it.
    assert ctx.stats.incomplete and ctx.stats.warnings == [warning]


def _engine_run(index: Any, **options: Any) -> ScanResult:
    spec = ConnectorSpec("cloud.aws", {"input": str(FIXTURE)})
    return Engine(ScanConfig(connectors=[spec], **options), index).run()


def _by_resource(result: ScanResult) -> dict[str, Any]:
    return {finding.resource: finding for finding in result.findings}


def test_trusted_registry_sanctions_only_the_runtime_of_an_approved_manual_record(index):
    trusted = [{"registry": "aws-agent-registry", "id": REGISTRY_ARN}]
    result = _engine_run(index, trusted_registries=trusted)
    assert result.complete and result.inventory_present
    findings = _by_resource(result)
    support = findings[RUNTIME_ARN]
    billing = findings[RUNTIME_ARN.replace("support_agent-AbCdE12345", "billing_agent-FgHiJ67890")]
    shadow = findings[RUNTIME_ARN.replace("support_agent-AbCdE12345", "shadow_agent-KlMnO13579")]
    gateway = findings[GATEWAY_ARN]
    assert (support.shadow, support.registry_match) == (False, "aws-agent-registry:rec000000001")
    # Pending and draft records bind their objects but never approve them.
    assert billing.shadow is True and billing.registry_match is None
    assert gateway.shadow is True and gateway.registry_match is None
    assert shadow.shadow is True
    assert support.metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"
    assert billing.metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"
    # The registry's listing is complete, so an unlisted runtime in its account is reported.
    assert shadow.metadata[RECONCILIATION_KEY]["status"] == "observed-not-registered"
    record = findings[f"{REGISTRY_ARN}/record/rec000000001"]
    assert (record.shadow, record.registry_match) == (False, "aws-agent-registry:rec000000001")


def test_without_trusted_registries_vendor_approval_sanctions_nothing(index):
    result = _engine_run(index)
    assert result.complete and not result.inventory_present
    assert {finding.shadow for finding in result.findings} == {None}
    assert (
        _by_resource(result)[RUNTIME_ARN].metadata[RECONCILIATION_KEY]["status"] == "registered-and-observed"
    )


def test_auto_approved_records_need_allow_auto_approved(index):
    record = f"{CORE_REGISTRY_ARN}/record/mcp000000001"
    declined = _engine_run(
        index, trusted_registries=[{"registry": "aws-agentcore-registry", "id": CORE_REGISTRY_ARN}]
    )
    assert declined.complete and _by_resource(declined)[record].shadow is True
    advisory = next(stats for stats in declined.stats if stats.connector == "engine.inventory")
    assert any("auto-approved" in warning for warning in advisory.warnings) and not advisory.incomplete
    accepted = _engine_run(
        index,
        trusted_registries=[
            {"registry": "aws-agentcore-registry", "id": CORE_REGISTRY_ARN, "allow_auto_approved": True}
        ],
    )
    assert _by_resource(accepted)[record].registry_match == "aws-agentcore-registry:mcp000000001"
    assert _by_resource(accepted)[record].shadow is False


def test_trusted_registry_of_another_account_sanctions_its_approved_record(index):
    record = f"{FOREIGN_REGISTRY_ARN}/record/ext000000001"
    result = _engine_run(
        index, trusted_registries=[{"registry": "aws-agent-registry", "id": FOREIGN_REGISTRY_ARN}]
    )
    assert result.complete
    assert _by_resource(result)[record].registry_match == "aws-agent-registry:ext000000001"
    # Its records bind nothing, so no runtime is approved through it.
    assert _by_resource(result)[RUNTIME_ARN].shadow is True


def test_documented_aws_trust_example_is_a_valid_configuration():
    text = (Path(__file__).resolve().parents[2] / "docs" / "inventory.md").read_text(encoding="utf-8")
    section = text.split("### Trusting AWS registries", 1)[1]
    example = section.split("```yaml\n", 1)[1].split("```", 1)[0]
    config = ScanConfig.from_dict(yaml.safe_load(example))
    assert [(item.registry, item.id, item.allow_auto_approved) for item in config.trusted_registries] == [
        ("aws-agent-registry", REGISTRY_ARN, False),
        ("aws-agentcore-registry", CORE_REGISTRY_ARN, True),
    ]
    [spec] = config.connectors
    assert "registry" in AwsConnector(ConnectorContext(config=spec.config)).services


# ------------------------------------------------------------------ real SDK models
def test_registry_calls_match_the_installed_sdk_models(index):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    def sdk(service: str) -> Any:
        return boto3.client(
            service, region_name=REGION, aws_access_key_id="test", aws_secret_access_key="test"
        )

    control, core, discovery = (
        sdk("agent-registry-control"),
        sdk("bedrock-agentcore-control"),
        sdk("agent-registry"),
    )
    summary = record_summary()
    detail = record_detail()
    detail.pop("ResponseMetadata")
    listed = discoverable_summary()
    foreign = {key: value for key, value in listed.items() if key != "descriptorTypes"}
    with Stubber(control) as stub_control, Stubber(core) as stub_core, Stubber(discovery) as stub_discovery:
        stub_control.add_response("list_registries", {"registries": [registry_summary()]}, {})
        detail_registry = registry_detail(["APPROVE_ALL"])
        detail_registry.pop("ResponseMetadata")
        stub_control.add_response("get_registry", detail_registry, {"registryId": REGISTRY_ID})
        stub_control.add_response(
            "list_registry_records", {"registryRecords": [summary]}, {"registryId": REGISTRY_ID}
        )
        stub_control.add_response(
            "get_registry_record", detail, {"registryId": REGISTRY_ID, "recordId": "rec000000001"}
        )
        stub_core.add_response("list_registries", {"registries": []}, {})
        stub_discovery.add_response(
            "list_discoverable_registry_records",
            {"registryRecords": [listed]},
            {"registryId": FOREIGN_REGISTRY_ARN},
        )
        stub_discovery.add_response(
            "batch_get_discoverable_registry_record",
            {"registryRecords": [{**foreign, "descriptors": {"mcpServer": {"data": "{}"}}}], "errors": []},
            {"entries": [{"registryId": FOREIGN_REGISTRY_ARN, "recordIds": ["ext000000001"]}]},
        )
        clients = {
            "agent-registry-control": control,
            "bedrock-agentcore-control": core,
            "agent-registry": discovery,
        }
        instance = connector(index, clients, services=("registry",), registry_arns=[FOREIGN_REGISTRY_ARN])
        records = collect(instance)
        stub_control.assert_no_pending_responses()
        stub_core.assert_no_pending_responses()
        stub_discovery.assert_no_pending_responses()
    assert not warnings(instance)
    findings = analyze(instance, records)
    contracts = {f.metadata[RECORD_KEY]["record_id"]: f.metadata[RECORD_KEY] for f in findings}
    assert contracts["rec000000001"]["approval_mode"] == "auto"
    assert contracts["ext000000001"]["listing_complete"] is False
