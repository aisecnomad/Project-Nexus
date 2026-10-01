"""OCI collection and analysis contracts, exercised with fake SDK clients and offline exports."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from typing import Any
from unittest import mock
from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.models import Kind, ScanStats
from shadowscan.utils.redaction import REDACTED, sanitize

TENANCY = "ocid1.tenancy.oc1..acme"
COMPARTMENT = "ocid1.compartment.oc1..ml"
REGION = "eu-frankfurt-1"
AGENT = "ocid1.genaiagent.oc1.eu-frankfurt-1.claims"


def connector(index: Any, **config: Any) -> OciConnector:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.oci", started_at="2026-09-27")
    return OciConnector(ctx)


def _by_type(findings: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for finding in findings:
        grouped.setdefault(finding.resource_type, []).append(finding)
    return grouped


# ------------------------------------------------------------------ offline
def test_oci_offline_export_covers_every_handler_kind(run_connector, fixtures):
    findings, ctx = run_connector("cloud.oci", input=str(fixtures / "cloud" / "oci_extended_records.jsonl"))
    assert not ctx.stats.incomplete and not ctx.stats.warnings
    grouped = _by_type(findings)
    # Plain web containers, non-LLM deployments and functions, a database
    # password and a web-server dynamic group are not AI inventory.
    assert set(grouped) == {
        "genai-agent",
        "genai-knowledge-base",
        "genai-endpoint",
        "genai-dedicated-cluster",
        "genai-custom-model",
        "model-deployment",
        "container-instance",
        "iam-policy",
    }

    (agent,) = grouped["genai-agent"]
    assert agent.kind == Kind.AGENT and agent.account == COMPARTMENT and agent.region == REGION
    assert {"tracing-disabled", "no-content-moderation"} <= set(agent.tags)
    assert {"tool-use", "saas-actions", "code-exec"} <= set(agent.capabilities)
    assert agent.metadata["tools"] == [
        {"name": "warehouse-sql", "type": "SQL_TOOL_CONFIG"},
        {"name": "refund", "type": "FUNCTION_CALLING_TOOL_CONFIG"},
    ]
    assert agent.metadata["endpoints"][0]["name"] == "finance-endpoint"

    (kb,) = grouped["genai-knowledge-base"]
    assert kb.owner == "kb-team" and "rag" in kb.capabilities
    assert (kb.first_seen, kb.last_seen) == ("2025-04-01T00:00:00Z", "2025-04-02T00:00:00Z")

    (endpoint,) = grouped["genai-endpoint"]
    assert endpoint.owner == "ml-platform@acme.example"  # Oracle-Tags CreatedBy when no owner tag exists
    assert endpoint.models == ["cohere.command-r-plus"]
    assert "provider.oci-generative-ai" in endpoint.model_providers
    assert endpoint.metadata["cluster"] == "ocid1.generativeaidedicatedaicluster.oc1..hosting"

    (cluster,) = grouped["genai-dedicated-cluster"]
    assert any("units 2" in e.description for e in cluster.evidence)
    (custom,) = grouped["genai-custom-model"]
    assert any("ocid1.generativeaimodel.oc1..cohere-command" in e.description for e in custom.evidence)

    (deployment,) = grouped["model-deployment"]
    assert deployment.title == "OCI Data Science model deployment: llm-serving"
    assert deployment.metadata["image"] == "fra.ocir.io/acme/vllm-openai:0.5"
    assert deployment.metadata["model_id"] == "ocid1.datasciencemodel.oc1..mistral"
    (container,) = grouped["container-instance"]
    assert container.resource == "ocid1.computecontainerinstance.oc1..ollama"
    assert "provider.ollama" in container.model_providers

    (policy,) = grouped["iam-policy"]
    assert {"wildcard-permissions", "workload-identity"} <= set(policy.tags)
    assert policy.metadata["subjects"] == ["PlatformAdmins", "agent-runners"]
    assert policy.permissions[:2] == policy.metadata["statements"]


@pytest.mark.parametrize(
    "record,warning",
    [
        ({"_kind": "tenancy", "tenancy": 7}, "invalid fields for its _kind"),
        ({"_kind": "genai-agent-endpoint", "id": "ep"}, "invalid fields for its _kind"),
        ({"_kind": "genai-agent", "id": AGENT, "_tools": ["not-a-tool"]}, "invalid agent fields"),
        ({"_kind": "genai-cluster", "display_name": None}, "invalid fields for its _kind"),
        ({"_kind": "policy", "id": "ocid1.policy.oc1..p", "statements": [7]}, "invalid fields for its _kind"),
        ({"_kind": "vcn", "id": "ocid1.vcn.oc1..v"}, "unsupported _kind"),
    ],
)
def test_oci_malformed_export_records_are_reported_and_neighbours_kept(index, record, warning):
    scanner = connector(index)
    neighbour = {
        "_kind": "oda-instance",
        "id": "ocid1.odainstance.oc1..hr",
        "display_name": "hr-assistant",
        "_compartment": COMPARTMENT,
    }
    findings = list(scanner.analyze([record, neighbour]))
    assert [f.resource_type for f in findings] == ["oda-instance"]
    assert scanner.ctx.stats.incomplete
    assert any(warning in w for w in scanner.ctx.stats.warnings)
    assert scanner.ctx.stats.objects_examined == 2


# ------------------------------------------------------------------- live
@pytest.fixture
def sdk():
    return pytest.importorskip("oci")


def _page(sdk: Any, items: list[Any], next_page: str | None = None) -> Any:
    headers = {"opc-next-page": next_page} if next_page else {}
    return sdk.response.Response(status=200, headers=headers, data=items, request=None)


class _ServiceError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"service error {status}")
        self.status = status


def _fake_clients(sdk: Any, *, with_tools: bool = True) -> dict[str, Any]:
    """Fake SDK clients: resources exist only in the ML compartment, as real tenancies scope them."""
    models = SimpleNamespace(
        identity=sdk.identity.models,
        agent=sdk.generative_ai_agent.models,
        genai=sdk.generative_ai.models,
        oda=sdk.oda.models,
        ds=sdk.data_science.models,
        fn=sdk.functions.models,
        ci=sdk.container_instances.models,
        vault=sdk.vault.models,
    )

    def scoped(items: list[Any]) -> Any:
        def listing(comp: str | None = None, *args: Any, **kwargs: Any) -> Any:
            return _page(sdk, items if kwargs.get("compartment_id", comp) == COMPARTMENT else [])

        return listing

    identity = Mock()
    identity.list_compartments.return_value = _page(sdk, [models.identity.Compartment(id=COMPARTMENT)])
    identity.list_region_subscriptions.return_value = _page(
        sdk, [models.identity.RegionSubscription(region_name=REGION)]
    )
    identity.list_policies.side_effect = lambda comp, **kw: _page(
        sdk,
        [
            models.identity.Policy(
                id="ocid1.policy.oc1..genai",
                name="genai-agents",
                description="agent runtime",
                statements=["Allow dynamic-group agent-runners to use generative-ai-family in tenancy"],
                lifecycle_state="ACTIVE",
            ),
            models.identity.Policy(
                id="ocid1.policy.oc1..network",
                name="network",
                statements=["Allow group NetOps to manage virtual-network-family in tenancy"],
            ),
        ]
        if comp == TENANCY
        else [],
    )
    identity.list_dynamic_groups.return_value = _page(
        sdk,
        [
            models.identity.DynamicGroup(
                id="ocid1.dynamicgroup.oc1..runners",
                name="agent-runners",
                matching_rule="ALL {resource.type = 'genaiagent'}",
            )
        ],
    )

    agents = Mock(
        spec=["list_agents", "list_agent_endpoints", "list_knowledge_bases"]
        + (["list_tools"] if with_tools else [])
    )
    agents.list_agents.side_effect = scoped(
        [
            models.agent.AgentSummary(
                id=AGENT,
                display_name="claims-assistant",
                knowledge_base_ids=["kb1"],
                lifecycle_state="ACTIVE",
            )
        ]
    )
    if with_tools:
        agents.list_tools.side_effect = lambda **kw: _page(
            sdk,
            [
                models.agent.ToolSummary(
                    id="ocid1.genaiagenttool.oc1..sql",
                    display_name="claims-sql",
                    tool_config=models.agent.SqlToolConfig(tool_config_type="SQL_TOOL_CONFIG"),
                )
            ]
            if kw["agent_id"] == AGENT
            else [],
        )
    agents.list_agent_endpoints.side_effect = scoped(
        [
            models.agent.AgentEndpointSummary(
                id="ocid1.genaiagentendpoint.oc1..claims",
                agent_id=AGENT,
                display_name="claims",
                should_enable_trace=False,
            )
        ]
    )
    agents.list_knowledge_bases.side_effect = scoped(
        [
            models.agent.KnowledgeBaseSummary(
                id="ocid1.genaiagentknowledgebase.oc1..kb1",
                display_name="claims-kb",
                lifecycle_state="ACTIVE",
            )
        ]
    )

    genai = Mock()
    genai.list_endpoints.side_effect = scoped(
        [
            models.genai.EndpointSummary(
                id="ocid1.generativeaiendpoint.oc1..ep",
                display_name="command",
                model_id="cohere.command-r-plus",
            )
        ]
    )
    genai.list_dedicated_ai_clusters.side_effect = scoped(
        [
            models.genai.DedicatedAiClusterSummary(
                id="ocid1.generativeaidedicatedaicluster.oc1..c",
                display_name="hosting",
                type="HOSTING",
                unit_count=1,
            )
        ]
    )
    genai.list_models.side_effect = scoped(
        [
            models.genai.ModelSummary(
                id="ocid1.generativeaimodel.oc1..tuned",
                display_name="tuned",
                type="CUSTOM",
                base_model_id="ocid1.generativeaimodel.oc1..base",
            ),
            models.genai.ModelSummary(
                id="ocid1.generativeaimodel.oc1..base",
                display_name="cohere.command",
                type="BASE",
                capabilities=["FINE_TUNE"],
            ),
        ]
    )

    oda = Mock()
    oda.list_oda_instances.side_effect = scoped(
        [
            models.oda.OdaInstanceSummary(
                id="ocid1.odainstance.oc1..hr", display_name="hr-assistant", shape_name="PRODUCTION"
            )
        ]
    )
    ds = Mock()
    ds.list_model_deployments.side_effect = scoped(
        [
            models.ds.ModelDeploymentSummary(
                id="ocid1.datasciencemodeldeployment.oc1..md", display_name="llm-serving"
            )
        ]
    )

    fn = Mock()
    fn.list_applications.side_effect = scoped([models.fn.ApplicationSummary(id="ocid1.fnapp.oc1..agents")])
    fn.get_application.return_value = SimpleNamespace(
        data=models.fn.Application(
            id="ocid1.fnapp.oc1..agents",
            display_name="agents",
            config={"OPENAI_BASE_URL": "https://api.openai.com/v1"},
        )
    )
    fn.list_functions.return_value = _page(
        sdk, [models.fn.FunctionSummary(id="ocid1.fnfunc.oc1..summarise", display_name="summarise")]
    )
    fn.get_function.return_value = SimpleNamespace(
        data=models.fn.Function(
            id="ocid1.fnfunc.oc1..summarise",
            display_name="summarise",
            config={"OPENAI_API_KEY": "${vault:openai}"},
        )
    )

    ci = Mock()
    ci.list_container_instances.side_effect = scoped(
        [
            models.ci.ContainerInstanceSummary(
                id="ocid1.computecontainerinstance.oc1..box", display_name="ollama-box"
            )
        ]
    )
    ci.list_containers.side_effect = lambda comp, **kw: _page(
        sdk,
        [
            models.ci.ContainerSummary(id="ocid1.container.oc1..denied"),
            models.ci.ContainerSummary(id="ocid1.container.oc1..ollama"),
        ]
        if comp == COMPARTMENT
        else [],
    )

    def get_container(container_id: str) -> Any:
        if container_id.endswith("denied"):
            raise _ServiceError(404)
        return SimpleNamespace(
            data=models.ci.Container(
                id=container_id,
                display_name="ollama",
                image_url="ollama/ollama:latest",
                environment_variables={"OLLAMA_HOST": "0.0.0.0"},
            )
        )

    ci.get_container.side_effect = get_container
    vault = Mock()
    vault.list_secrets.side_effect = scoped(
        [
            models.vault.SecretSummary(
                id="ocid1.vaultsecret.oc1..openai",
                secret_name="openai-api-key",
                description="LLM gateway key",
            )
        ]
    )
    return {
        "IdentityClient": identity,
        "GenerativeAiAgentClient": agents,
        "GenerativeAiClient": genai,
        "OdaClient": oda,
        "DataScienceClient": ds,
        "FunctionsManagementClient": fn,
        "ContainerInstanceClient": ci,
        "VaultsClient": vault,
    }


def _live(index: Any, clients: dict[str, Any], missing: tuple[str, ...] = ()) -> OciConnector:
    scanner = connector(index, tenancy=TENANCY)
    scanner._init = lambda: None  # type: ignore[method-assign]
    requested: list[tuple[str, str | None]] = []

    def client(cls: Any, region: str | None = None) -> Any:
        requested.append((cls.__name__, region))
        if cls.__name__ in missing:
            raise AttributeError(cls.__name__)
        return clients[cls.__name__]

    scanner._client = client  # type: ignore[method-assign]
    scanner.requested = requested  # type: ignore[attr-defined]
    return scanner


def test_oci_collect_discovers_scope_and_every_regional_service(index, sdk):
    scanner = _live(index, _fake_clients(sdk))
    records = list(scanner.collect())
    kinds = [r["_kind"] for r in records]
    assert records[0] == {"_kind": "tenancy", "tenancy": TENANCY, "compartments": 2, "regions": [REGION]}
    assert kinds[1:] == [
        "policy",
        "dynamic-group",
        "genai-agent",
        "genai-agent-endpoint",
        "genai-knowledge-base",
        "genai-endpoint",
        "genai-cluster",
        "genai-custom-model",
        "oda-instance",
        "model-deployment",
        "function",
        "container-instance",
        "secret-name",
    ]
    # Every regional client is created for the subscribed region, per compartment.
    assert {region for name, region in scanner.requested if name != "IdentityClient"} == {REGION}
    agent = next(r for r in records if r["_kind"] == "genai-agent")
    assert agent["_tools"][0]["tool_config"]["tool_config_type"] == "SQL_TOOL_CONFIG"
    function = next(r for r in records if r["_kind"] == "function")
    assert function["environment"] == {
        "OPENAI_BASE_URL": "https://api.openai.com/v1",
        "OPENAI_API_KEY": "${vault:openai}",
    }
    assert function["_config_coverage"] == {"application": "observed", "function": "observed"}
    container = next(r for r in records if r["_kind"] == "container-instance")
    assert [c["display_name"] for c in container["_containers"]] == ["ollama"]  # the denied detail is skipped
    secret = next(r for r in records if r["_kind"] == "secret-name")
    assert secret["secret_name"] == "openai-api-key" and "time_created" in secret
    # One container detail read failed: evidence is kept but coverage is incomplete.
    assert scanner.ctx.stats.warnings == ["cloud.oci: container detail collection failed (_ServiceError)"]
    assert scanner.ctx.stats.incomplete

    grouped = _by_type(list(scanner.analyze(records)))
    (agent_finding,) = grouped["genai-agent"]
    assert "rag" in agent_finding.capabilities and "tracing-disabled" in agent_finding.tags
    assert agent_finding.metadata["endpoints"][0]["id"] == "ocid1.genaiagentendpoint.oc1..claims"
    assert [f.title for f in grouped["genai-custom-model"]] == ["OCI custom (fine-tuned) model: tuned"]
    assert grouped["oda-instance"][0].kind == Kind.AGENT
    assert "provider.openai" in grouped["function"][0].model_providers
    assert grouped["function"][0].metadata["config_coverage"] == function["_config_coverage"]
    assert grouped["vault-secret"][0].title == "OCI Vault secret for LLM provider: openai-api-key"
    assert grouped["dynamic-group"][0].metadata["matching_rule"] == "ALL {resource.type = 'genaiagent'}"


def test_oci_missing_sdk_services_are_incomplete_while_other_services_continue(index, sdk):
    scanner = _live(index, _fake_clients(sdk, with_tools=False), missing=("OdaClient", "VaultsClient"))
    records = list(scanner._collect_region_comp(REGION, COMPARTMENT))
    kinds = {r["_kind"] for r in records}
    assert "oda-instance" not in kinds and "secret-name" not in kinds
    assert {"genai-agent", "genai-endpoint", "model-deployment", "function", "container-instance"} <= kinds
    agent = next(r for r in records if r["_kind"] == "genai-agent")
    assert agent["_tools"] == []
    warnings = scanner.ctx.stats.warnings
    assert "cloud.oci: list_tools unavailable in installed SDK" in warnings
    assert "cloud.oci: oda unavailable in installed SDK" in warnings
    assert "cloud.oci: vault unavailable in installed SDK" in warnings
    assert scanner.ctx.stats.incomplete


def test_oci_configured_scope_skips_compartment_and_region_discovery(index, sdk):
    clients = _fake_clients(sdk)
    scanner = _live(index, clients)
    scanner.compartments = [COMPARTMENT]
    scanner.regions = ["us-ashburn-1"]
    records = list(scanner.collect())
    assert records[0] == {
        "_kind": "tenancy",
        "tenancy": TENANCY,
        "compartments": 1,
        "regions": ["us-ashburn-1"],
    }
    clients["IdentityClient"].list_compartments.assert_not_called()
    clients["IdentityClient"].list_region_subscriptions.assert_not_called()
    # Policies are read from the configured compartment only.
    assert [c.args for c in clients["IdentityClient"].list_policies.call_args_list] == [(COMPARTMENT,)]


# ---------------------------------------------------------------- session
def test_oci_rejects_unknown_auth_mode(index, sdk):
    with pytest.raises(ConnectorError, match="auth must be config"):
        connector(index, auth="api_key")._init()


@pytest.mark.parametrize("region,expected", [("eu-frankfurt-1", "eu-frankfurt-1"), (None, "uk-london-1")])
def test_oci_instance_principal_signer_is_bounded_and_scoped(index, sdk, monkeypatch, region, expected):
    signer = SimpleNamespace(region="uk-london-1", tenancy_id="ocid1.tenancy.oc1..signer")
    make_signer = Mock(return_value=signer)
    monkeypatch.setattr(sdk.auth.signers, "InstancePrincipalsSecurityTokenSigner", make_signer)
    config = {"auth": "instance_principal", "allow_instance_credentials": True}
    scanner = connector(index, **config, **({"region": region} if region else {}))
    scanner._clients[("stale", None)] = object()
    scanner._init()
    assert not scanner._clients  # clients signed by an earlier session are discarded
    assert scanner._signer is signer and scanner._config == {"region": expected}
    assert scanner.tenancy == "ocid1.tenancy.oc1..signer"
    kwargs = make_signer.call_args.kwargs
    assert set(kwargs) == {"retry_strategy", "federation_client_retry_strategy"}
    for strategy in kwargs.values():
        checkers = {type(checker).__name__: vars(checker) for checker in strategy.checkers.checkers}
        assert checkers["LimitBasedRetryChecker"]["max_attempts"] == 3
        assert checkers["TotalTimeExceededRetryChecker"]["time_limit_seconds"] == 120
        assert strategy.max_wait_between_calls_seconds == 10


def test_oci_clients_are_cached_per_service_and_region_with_bounded_transport(index, sdk):
    scanner = connector(index)
    scanner._config = {"region": "us-ashburn-1", "tenancy": TENANCY}
    scanner._signer = "signer"
    built: list[tuple[dict[str, Any], dict[str, Any]]] = []

    class Client:
        def __init__(self, cfg: dict[str, Any], **kwargs: Any) -> None:
            built.append((cfg, kwargs))

    first = scanner._client(Client, REGION)
    assert scanner._client(Client, REGION) is first
    assert scanner._client(Client) is not first
    assert [cfg["region"] for cfg, _ in built] == [REGION, "us-ashburn-1"]
    assert scanner._config["region"] == "us-ashburn-1"  # the session configuration is not mutated
    assert all(
        kw["timeout"] == (10, 30) and kw["signer"] == "signer" and "retry_strategy" in kw for _, kw in built
    )


def test_oci_pages_accept_item_collections_and_reject_unknown_shapes(index, sdk):
    scanner = connector(index)
    assert scanner._all(Mock(return_value=_page(sdk, {"items": [1, 2]}))) == [1, 2]
    assert scanner._all(Mock(return_value=SimpleNamespace(data=SimpleNamespace(items=(3,))))) == [3]
    assert not scanner.ctx.stats.incomplete
    listing = Mock(return_value=SimpleNamespace(data=SimpleNamespace(items=None)))
    listing.__name__ = "list_things"
    assert scanner._all(listing) == []
    assert scanner.ctx.stats.warnings == ["cloud.oci: invalid collection response for list_things"]
    assert scanner.ctx.stats.incomplete


def test_oci_record_conversion_failure_fails_closed(sdk, monkeypatch):
    # SDK models store fields as private attributes; a raw __dict__ fallback
    # would yield records whose id and display_name read as missing.
    monkeypatch.setattr(sdk.util, "to_dict", Mock(side_effect=ValueError("unsupported model")))
    model = SimpleNamespace(_id="ocid1.x", _display_name="x")
    with pytest.raises(ValueError, match=r"could not be converted \(ValueError\)"):
        OciConnector._d(model)
    monkeypatch.setattr(sdk.util, "to_dict", Mock(return_value=None))
    with pytest.raises(ValueError, match="not an object"):
        OciConnector._d(model)
    monkeypatch.setattr(sdk.util, "to_dict", vars)
    assert OciConnector._d(SimpleNamespace(id="ocid1.x")) == {"id": "ocid1.x"}


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_oci_clients_are_cached_per_region_with_timeouts(index):
    pytest.importorskip("oci")
    connector = OciConnector(context(index))
    connector._config = {"region": "us-ashburn-1"}

    class Client:
        def __init__(self, config, **kwargs):
            self.config, self.kwargs = config, kwargs

    first = connector._client(Client, "r1")
    assert connector._client(Client, "r1") is first
    other = connector._client(Client, "r2")
    assert other is not first and other.config["region"] == "r2"
    assert first.kwargs["timeout"] == (10, 30)
    assert first.kwargs["retry_strategy"] is not None


def test_oci_function_reads_environment_and_legacy_config_keys(index):
    connector = OciConnector(context(index))
    base = {
        "id": "ocid1.fnfunc.oc1..fn1",
        "display_name": "fn",
        "_region": "r",
        "_compartment": "c",
        "_application": "app",
        "image": "ollama/ollama:latest",
    }
    current = connector._h_function({**base, "environment": {"OPENAI_API_KEY": "x"}})
    legacy = connector._h_function({**base, "config": {"OPENAI_API_KEY": "x"}})
    assert current is not None and legacy is not None
    assert current.metadata["config_keys"] == legacy.metadata["config_keys"] == ["OPENAI_API_KEY"]


def test_oci_function_collection_dumps_withhold_opaque_config_values(index):
    from types import SimpleNamespace

    connector = OciConnector(context(index))
    connector._d = lambda obj: obj
    client = Mock()
    client.list_applications.return_value = SimpleNamespace(
        data=[{"id": "app", "display_name": "app"}], has_next_page=False
    )
    client.list_functions.return_value = SimpleNamespace(
        data=[{"id": "fn", "display_name": "fn"}], has_next_page=False
    )
    client.get_application.return_value = SimpleNamespace(
        data={"id": "app", "config": {"INHERITED": "opaque-app-secret"}}
    )
    client.get_function.return_value = SimpleNamespace(
        data={"id": "fn", "config": {"ARBITRARY": "opaque-function-secret"}}
    )
    (record,) = connector._collect_functions(client, "r", "c")
    assert "config" not in record
    assert set(sanitize(record)["environment"].values()) == {REDACTED}
    assert not connector.ctx.stats.incomplete


# Live provider response shapes, without cloud credentials.
def test_oci_collections_and_keyword_only_genai_calls(index, monkeypatch):
    """GenAI Agent list APIs return Collection(items), which OCI pagination flattens."""

    class Client:
        def __getattr__(self, name):
            if name.startswith("list_"):
                return lambda *args, **kwargs: []
            raise AttributeError(name)

        def list_agents(self, *, compartment_id):
            assert compartment_id == "comp"
            return SimpleNamespace(items=[SimpleNamespace(id="a1", display_name="assistant")])

        def list_tools(self, *, compartment_id, agent_id):
            assert (compartment_id, agent_id) == ("comp", "a1")
            return SimpleNamespace(items=[SimpleNamespace(id="tool1")])

        def list_agent_endpoints(self, *, compartment_id):
            assert compartment_id == "comp"
            return SimpleNamespace(items=[SimpleNamespace(id="e1", agent_id="a1")])

        def list_knowledge_bases(self, *, compartment_id):
            assert compartment_id == "comp"
            return SimpleNamespace(items=[SimpleNamespace(id="kb1")])

    client = Client()
    oci = SimpleNamespace(
        generative_ai_agent=SimpleNamespace(GenerativeAiAgentClient=Client),
        generative_ai=SimpleNamespace(GenerativeAiClient=Client),
        oda=SimpleNamespace(OdaClient=Client),
        data_science=SimpleNamespace(DataScienceClient=Client),
        functions=SimpleNamespace(FunctionsManagementClient=Client),
        container_instances=SimpleNamespace(ContainerInstanceClient=Client),
        vault=SimpleNamespace(VaultsClient=Client),
        pagination=SimpleNamespace(
            list_call_get_all_results=lambda fn, *args, **kw: SimpleNamespace(data=fn(*args, **kw))
        ),
        util=SimpleNamespace(to_dict=vars),
    )
    monkeypatch.setitem(sys.modules, "oci", oci)
    ctx = context(index)
    connector = OciConnector(ctx)
    connector._client = lambda cls, region: client
    records = list(connector._collect_region_comp("us-ashburn-1", "comp"))
    assert {r["_kind"] for r in records} >= {"genai-agent", "genai-agent-endpoint", "genai-knowledge-base"}
    assert records[0]["_tools"] == [{"id": "tool1"}]
    assert not ctx.stats.incomplete


def test_oci_denied_inventory_is_incomplete(index):
    ctx = context(index)
    connector = OciConnector(ctx)
    assert connector._all(Mock(side_effect=RuntimeError("NotAuthorizedOrNotFound: 404"))) == []
    assert ctx.stats.incomplete
    assert "collection failed" in ctx.stats.warnings[0]


def foundry_context(index):
    ctx = ConnectorContext(config={"foundry_token": "synthetic"}, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def oci_functions_client():
    oci = pytest.importorskip("oci")
    models = oci.functions.models
    client = Mock(spec=oci.functions.FunctionsManagementClient)

    def response(data):
        return oci.response.Response(status=200, headers={}, data=data, request=None)

    image_kw = (
        {"source_details": models.ContainerImageFunctionSourceDetails(image="ollama/ollama:latest")}
        if hasattr(models, "ContainerImageFunctionSourceDetails")
        else {"image": "ollama/ollama:latest"}
    )
    application = models.ApplicationSummary(id="app1", display_name="workflows")
    function = models.FunctionSummary(id="fn1", display_name="worker", application_id="app1", **image_kw)
    # Real OCI summary models must never accidentally grow fictional config fields.
    assert "config" not in application.swagger_types
    assert "config" not in function.swagger_types
    client.list_applications.return_value = response([application])
    client.list_functions.return_value = response([function])
    client.get_application.return_value = response(
        models.Application(
            id="app1",
            config={
                "OPENAI_API_KEY": "synthetic-application-secret",
                "SHARED": "application",
                "APP_ONLY": "present",
            },
        )
    )
    client.get_function.return_value = response(models.Function(id="fn1", config={"SHARED": "function"}))
    return client, response


def test_oci_reads_real_detail_models_inherits_config_and_preserves_image(index):
    client, _ = oci_functions_client()
    ctx = foundry_context(index)
    connector = OciConnector(ctx)
    records = list(connector._collect_functions(client, "us-ashburn-1", "comp"))
    assert len(records) == 1
    record = records[0]
    client.get_application.assert_called_once_with("app1")
    client.get_function.assert_called_once_with("fn1")
    assert "config" not in record
    assert record["environment"]["SHARED"] == "function"
    assert record["environment"]["APP_ONLY"] == "present"
    assert "synthetic-application-secret" not in json.dumps(sanitize(record))
    finding = connector._h_function(record)
    assert {"provider.openai", "provider.ollama"} <= set(finding.model_providers)
    assert finding.metadata["image"] == "ollama/ollama:latest"
    assert "OPENAI_API_KEY" in finding.metadata["config_keys"]
    assert "synthetic-application-secret" not in json.dumps(finding.to_dict())
    assert not ctx.stats.incomplete


def test_oci_handler_accepts_legacy_config_exports(index):
    connector = OciConnector(foundry_context(index))
    finding = connector._h_function(
        {
            "id": "fn-legacy",
            "display_name": "legacy-worker",
            "image": "ollama/ollama:latest",
            "config": {"OPENAI_API_KEY": "synthetic-legacy-secret"},
        }
    )
    assert finding is not None
    assert "provider.openai" in finding.model_providers
    assert "OPENAI_API_KEY" in finding.metadata["config_keys"]


@pytest.mark.parametrize("kind", ["application", "function"])
def test_oci_denied_detail_preserves_known_evidence_and_marks_incomplete(index, kind):
    client, _ = oci_functions_client()
    getattr(client, f"get_{kind}").side_effect = RuntimeError("do not reflect credential-bearing errors")
    ctx = foundry_context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    finding = connector._h_function(record)
    assert "provider.ollama" in finding.model_providers
    assert finding.metadata["config_coverage"][kind] == "unknown"
    assert ctx.stats.incomplete
    assert "credential-bearing" not in str(ctx.stats.warnings)


@pytest.mark.parametrize(
    "detail",
    [
        None,
        [],
        {},
        {"id": "wrong", "config": {}},
        {"id": "fn1"},
        {"id": "fn1", "config": []},
        {"id": "fn1", "config": {"BAD": 12}},
    ],
)
def test_oci_invalid_function_detail_preserves_summary(index, detail):
    client, response = oci_functions_client()
    client.get_function.return_value = response(detail)
    ctx = foundry_context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    assert record["id"] == "fn1"
    assert connector._h_function(record).metadata["image"] == "ollama/ollama:latest"
    assert ctx.stats.incomplete


def test_oci_legacy_image_shape_remains_supported(index):
    client, response = oci_functions_client()
    client.list_functions.return_value = response(
        [{"id": "fn1", "display_name": "worker", "image": "ollama/ollama:latest"}]
    )
    ctx = foundry_context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    assert connector._h_function(record).metadata["image"] == "ollama/ollama:latest"
    assert not ctx.stats.incomplete


def test_oci_non_ai_summary_is_detected_from_function_detail(index):
    client, response = oci_functions_client()
    client.list_functions.return_value = response(
        [{"id": "fn1", "display_name": "worker", "image": "registry.example/worker:v1"}]
    )
    client.get_application.return_value = response({"id": "app1", "config": {}})
    client.get_function.return_value = response(
        {"id": "fn1", "config": {"ANTHROPIC_API_KEY": "synthetic-function-secret"}}
    )
    ctx = foundry_context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    assert "provider.anthropic" in connector._h_function(record).model_providers
    assert not ctx.stats.incomplete


def _context(index, **config) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00+00:00")
    return ctx


def test_oci_custom_models_are_selected_by_type_not_vendor(index):
    oci = pytest.importorskip("oci")
    from shadowscan.connectors.cloud.oci import OciConnector

    ctx = _context(index)
    connector = OciConnector(ctx)
    connector.tenancy = "ocid1.tenancy.oc1..t"
    custom = oci.generative_ai.models.ModelSummary(
        id="ocid1.generativeaimodel.oc1..custom1",
        compartment_id="ocid1.compartment.oc1..c",
        display_name="my-finetune",
        type="CUSTOM",
        vendor="cohere",
        capabilities=["TEXT_GENERATION"],
        base_model_id="ocid1.generativeaimodel.oc1..base",
        lifecycle_state="ACTIVE",
    )
    base = oci.generative_ai.models.ModelSummary(
        id="ocid1.generativeaimodel.oc1..base",
        compartment_id="ocid1.compartment.oc1..c",
        display_name="cohere.command",
        type="BASE",
        vendor="cohere",
        capabilities=["TEXT_GENERATION", "FINE_TUNE"],
        base_model_id=None,
        lifecycle_state="ACTIVE",
    )

    class GenAI:
        def list_endpoints(self, comp, **kwargs):
            return SimpleNamespace(data=[], has_next_page=False)

        def list_dedicated_ai_clusters(self, comp, **kwargs):
            return SimpleNamespace(data=[], has_next_page=False)

        def list_models(self, comp, **kwargs):
            return SimpleNamespace(data=[custom, base], has_next_page=False)

    def client(cls, region=None):
        if cls is oci.generative_ai.GenerativeAiClient:
            return GenAI()
        raise AttributeError("service unavailable in this test")

    with mock.patch.object(connector, "_client", client):
        records = list(connector._collect_region_comp("us-chicago-1", "ocid1.compartment.oc1..c"))
    custom_models = [(r["display_name"], r["type"]) for r in records if r["_kind"] == "genai-custom-model"]
    assert custom_models == [("my-finetune", "CUSTOM")]
