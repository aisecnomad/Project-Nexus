"""OCI provider contracts exercised without credentials or external requests."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import oci
import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.models import ScanStats


def connector(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.oci", started_at="2026-09-24")
    return OciConnector(ctx)


def response(data, next_page=None):
    headers = {"opc-next-page": next_page} if next_page else {}
    return oci.response.Response(status=200, headers=headers, data=data, request=None)


@pytest.mark.parametrize("auth", ["instance_principal", "resource_principal"])
def test_oci_rejects_implicit_instance_credentials_before_requesting_signer(index, monkeypatch, auth):
    instance = Mock(side_effect=AssertionError("must not acquire instance credentials"))
    resource = Mock(side_effect=AssertionError("must not acquire resource credentials"))
    monkeypatch.setattr(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", instance)
    monkeypatch.setattr(oci.auth.signers, "get_resource_principals_signer", resource)
    scanner = connector(index, auth=auth)
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        scanner._init()
    instance.assert_not_called()
    resource.assert_not_called()


def test_oci_uses_requested_local_profile_without_principal_discovery(index, monkeypatch, tmp_path):
    config_file = tmp_path / "audit-profile"
    from_file = Mock(return_value={"tenancy": "ocid1.tenancy.audit", "region": "eu-frankfurt-1"})
    signer = Mock(side_effect=AssertionError("unexpected instance credential discovery"))
    monkeypatch.setattr(oci.config, "from_file", from_file)
    monkeypatch.setattr(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", signer)
    monkeypatch.setattr(oci.auth.signers, "get_resource_principals_signer", signer)

    scanner = connector(index, config_file=str(config_file), profile="AUDIT")
    scanner._init()
    from_file.assert_called_once_with(file_location=str(config_file), profile_name="AUDIT")
    signer.assert_not_called()
    assert scanner.tenancy == "ocid1.tenancy.audit"
    assert scanner._config["region"] == "eu-frankfurt-1"


def test_oci_explicit_resource_principal_uses_opted_in_tenancy(index, monkeypatch):
    signer = SimpleNamespace(region="uk-london-1", tenancy_id="ocid1.tenancy.signer")
    get_signer = Mock(return_value=signer)
    monkeypatch.setattr(oci.auth.signers, "get_resource_principals_signer", get_signer)

    scanner = connector(index, auth="resource_principal", allow_instance_credentials=True,
                        tenancy="ocid1.tenancy.explicit")
    scanner._init()
    get_signer.assert_called_once_with()
    assert scanner._signer is signer
    assert scanner.tenancy == "ocid1.tenancy.explicit"
    assert scanner._config == {"region": "uk-london-1"}


def test_oci_sdk_page_headers_drive_cursor_and_preserve_partial_results(index):
    scanner = connector(index)
    fetch = Mock(side_effect=[
        response(SimpleNamespace(items=[{"id": "first"}]), next_page="page-2"),
        response(SimpleNamespace(items=[{"id": "second"}])),
    ])
    assert scanner._all(fetch, "ocid1.tenancy.test", lifecycle_state="ACTIVE") == [
        {"id": "first"}, {"id": "second"},
    ]
    assert fetch.call_args_list[1].args == ("ocid1.tenancy.test",)
    assert fetch.call_args_list[1].kwargs == {"lifecycle_state": "ACTIVE", "page": "page-2"}
    assert not scanner.ctx.stats.incomplete


@pytest.mark.parametrize("ending", [
    response([{"id": "second"}], next_page="again"),
    oci.exceptions.ServiceError(429, "TooManyRequests", {}, "private diagnostic token"),
])
def test_oci_late_pagination_failure_retains_observations_without_leaking_exception(index, ending):
    scanner = connector(index)
    fetch = Mock(side_effect=[response([{"id": "first"}], next_page="again"), ending])
    records = scanner._all(fetch)
    assert records[0] == {"id": "first"}
    assert scanner.ctx.stats.incomplete
    assert "private diagnostic token" not in str(scanner.ctx.stats.warnings)
    assert fetch.call_count == 2


def _empty_client(*operations):
    client = Mock()
    for operation in operations:
        setattr(client, operation, Mock(return_value=response([])))
    return client


def test_oci_tenancy_scan_paginates_scope_and_correlates_agent_endpoint(index):
    """Subscribed regions and nested compartments must have correctly attributed records."""
    scanner = connector(index)
    scanner.tenancy = "ocid1.tenancy.audit"
    scanner._init = Mock()  # Access to the SDK is fully represented by clients below.

    identity = _empty_client("list_policies", "list_dynamic_groups")
    identity.list_compartments = Mock(side_effect=[
        response([oci.identity.models.Compartment(id="ocid1.compartment.one")], "more"),
        response([oci.identity.models.Compartment(id="ocid1.compartment.two")]),
    ])
    identity.list_region_subscriptions.return_value = response([
        oci.identity.models.RegionSubscription(region_name="uk-london-1"),
    ])

    agents = _empty_client("list_agents", "list_tools", "list_agent_endpoints", "list_knowledge_bases")

    def list_agents(*, compartment_id, **kwargs):
        assert kwargs == {}
        if compartment_id == "ocid1.compartment.one":
            return response(SimpleNamespace(items=[oci.generative_ai_agent.models.AgentSummary(
                id="ocid1.agent.audit", display_name="audit assistant", lifecycle_state="ACTIVE",
                knowledge_base_ids=["ocid1.kb.audit"],
            )]))
        return response([])

    agents.list_agents.side_effect = list_agents
    agents.list_tools.return_value = response([{"display_name": "lookup", "type": "HTTP"}])
    agents.list_agent_endpoints.side_effect = lambda *, compartment_id: response([
        oci.generative_ai_agent.models.AgentEndpointSummary(
            id="ocid1.endpoint.audit", agent_id="ocid1.agent.audit", should_enable_trace=False,
            content_moderation_config=None,
        )
    ] if compartment_id == "ocid1.compartment.one" else [])
    other_clients = {
        oci.generative_ai.GenerativeAiClient: _empty_client("list_endpoints", "list_dedicated_ai_clusters", "list_models"),
        oci.oda.OdaClient: _empty_client("list_oda_instances"),
        oci.data_science.DataScienceClient: _empty_client("list_model_deployments"),
        oci.functions.FunctionsManagementClient: _empty_client("list_applications"),
        oci.container_instances.ContainerInstanceClient: _empty_client("list_container_instances"),
        oci.vault.VaultsClient: _empty_client("list_secrets"),
    }
    clients = {oci.identity.IdentityClient: identity, oci.generative_ai_agent.GenerativeAiAgentClient: agents,
               **other_clients}
    scanner._client = Mock(side_effect=lambda cls, region=None: clients[cls])

    records = list(scanner.collect())
    assert records[0] == {"_kind": "tenancy", "tenancy": "ocid1.tenancy.audit", "compartments": 3,
                          "regions": ["uk-london-1"]}
    assert [r["_kind"] for r in records[1:]] == ["genai-agent", "genai-agent-endpoint"]
    assert records[1]["_tools"] == [{"display_name": "lookup", "type": "HTTP"}]
    findings = list(scanner.analyze(records))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.account == "ocid1.compartment.one" and finding.region == "uk-london-1"
    assert {"rag", "tool-use"} <= set(finding.capabilities)
    assert {"tracing-disabled", "no-content-moderation"} <= set(finding.tags)
    assert finding.metadata["endpoints"][0]["id"] == "ocid1.endpoint.audit"
    assert not scanner.ctx.stats.incomplete
    assert identity.list_compartments.call_args_list[1].kwargs["page"] == "more"
    assert agents.list_agents.call_count == 3  # Root and both active compartments.
    assert "private" not in json.dumps([f.to_dict() for f in findings])


def test_oci_denied_compartment_inventory_never_reports_complete_scan(index):
    scanner = connector(index, regions=["uk-london-1"])
    scanner.tenancy = "ocid1.tenancy.audit"
    scanner._init = Mock()
    identity = _empty_client("list_dynamic_groups", "list_policies")
    identity.list_compartments = Mock(side_effect=oci.exceptions.ServiceError(
        403, "NotAuthorizedOrNotFound", {}, "private cloud diagnostic",
    ))
    clients = {oci.identity.IdentityClient: identity}
    scanner._client = Mock(side_effect=lambda cls, region=None: clients[cls] if cls in clients else _empty_client(
        "list_agents", "list_agent_endpoints", "list_knowledge_bases", "list_endpoints",
        "list_dedicated_ai_clusters", "list_models", "list_oda_instances", "list_model_deployments",
        "list_applications", "list_container_instances", "list_secrets",
    ))
    records = list(scanner.collect())
    assert records[0]["compartments"] == 1  # Known tenancy remains scoped, not a clean inventory.
    assert scanner.ctx.stats.incomplete
    assert "private cloud diagnostic" not in str(scanner.ctx.stats.warnings)


def test_oci_live_inventory_classifies_models_containers_policies_and_secret_names(index):
    scanner = connector(index, regions=["uk-london-1"], compartments=["ocid1.compartment.audit"])
    scanner.tenancy = "ocid1.tenancy.audit"
    scanner._init = Mock()

    identity = _empty_client("list_dynamic_groups")
    identity.list_policies.return_value = response([oci.identity.models.Policy(
        id="ocid1.policy.audit", name="ai-runner",
        statements=["Allow dynamic-group ai-runners to manage generative-ai-family in compartment audit"],
    )])
    genai = _empty_client("list_endpoints", "list_dedicated_ai_clusters")
    genai.list_models.return_value = response([
        oci.generative_ai.models.ModelSummary(id="ocid1.model.custom", display_name="tuned",
                                               base_model_id="ocid1.model.base", capabilities=["FINE_TUNE"]),
        oci.generative_ai.models.ModelSummary(id="ocid1.model.base", display_name="foundation", vendor="meta"),
    ])
    ds = _empty_client()
    ds.list_model_deployments.return_value = response([
        oci.data_science.models.ModelDeploymentSummary(id="ocid1.deployment.ai", display_name="ollama",
            model_deployment_configuration_details={"environment_configuration_details": {
                "image": "ollama/ollama:latest", "environment_variables": {"OPENAI_API_KEY": "synthetic-secret-value"},
            }}),
        oci.data_science.models.ModelDeploymentSummary(id="ocid1.deployment.nonai", display_name="static-api"),
    ])
    containers = _empty_client()
    containers.list_container_instances.return_value = response([
        oci.container_instances.models.ContainerInstanceSummary(id="ocid1.instance.ai", display_name="ai-service"),
    ])
    containers.list_containers.return_value = response([
        oci.container_instances.models.ContainerSummary(id="ocid1.container.ai"),
    ])
    containers.get_container.return_value = response(oci.container_instances.models.Container(
        id="ocid1.container.ai", image_url="ollama/ollama:latest",
        environment_variables={"ANTHROPIC_API_KEY": "synthetic-anthropic-secret"},
    ))
    vault = _empty_client()
    vault.list_secrets.return_value = response([
        oci.vault.models.SecretSummary(id="ocid1.secret.openai", secret_name="OPENAI_API_KEY"),
        oci.vault.models.SecretSummary(id="ocid1.secret.unrelated", secret_name="invoice-signing-key"),
    ])
    clients = {
        oci.identity.IdentityClient: identity,
        oci.generative_ai_agent.GenerativeAiAgentClient: _empty_client(
            "list_agents", "list_agent_endpoints", "list_knowledge_bases"),
        oci.generative_ai.GenerativeAiClient: genai,
        oci.oda.OdaClient: _empty_client("list_oda_instances"),
        oci.data_science.DataScienceClient: ds,
        oci.functions.FunctionsManagementClient: _empty_client("list_applications"),
        oci.container_instances.ContainerInstanceClient: containers,
        oci.vault.VaultsClient: vault,
    }
    scanner._client = Mock(side_effect=lambda cls, region=None: clients[cls])

    records = list(scanner.collect())
    findings = list(scanner.analyze(records))
    by_type = {finding.resource_type: finding for finding in findings}
    assert {"iam-policy", "genai-custom-model", "model-deployment", "container-instance", "vault-secret"} <= set(by_type)
    assert by_type["iam-policy"].metadata["subjects"] == ["ai-runners"]
    assert by_type["container-instance"].resource == "ocid1.instance.ai"
    assert "provider.ollama" in by_type["model-deployment"].model_providers
    assert by_type["vault-secret"].kind.value == "secret"
    assert "ocid1.deployment.nonai" not in {finding.resource for finding in findings}
    assert "ocid1.secret.unrelated" not in {finding.resource for finding in findings}
    assert "synthetic-secret-value" not in json.dumps([finding.to_dict() for finding in findings])
    assert "synthetic-anthropic-secret" not in json.dumps([finding.to_dict() for finding in findings])
    assert not scanner.ctx.stats.incomplete
