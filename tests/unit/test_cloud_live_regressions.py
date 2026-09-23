"""Live provider response-shape regressions, without cloud credentials."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import Mock

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_bedrock_agent_reads_action_group_details_for_deployed_versions(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    bedrock_agent = Mock()
    bedrock_agent.get_agent.return_value = {"agent": {"agentId": "A1", "agentName": "ops", "agentStatus": "PREPARED"}}

    def get_action_group(*, agentId, agentVersion, actionGroupId):
        assert agentId == "A1"
        return {"agentActionGroup": {"actionGroupId": actionGroupId, "agentVersion": agentVersion,
                                     "actionGroupState": "ENABLED", **{
                                         "LAMBDA": {"actionGroupExecutor": {"lambda": "arn:aws:lambda:us-east-1:123:function:tool"}},
                                         "CODE": {"parentActionSignature": "AMAZON.CodeInterpreter"},
                                         "USER": {"parentActionSignature": "AMAZON.UserInput"},
                                     }[actionGroupId]}}

    bedrock_agent.get_agent_action_group.side_effect = get_action_group
    bedrock_agent.get_agent_version.return_value = {"agentVersion": {
        "version": "3", "foundationModel": "anthropic.claude-3-haiku-20240307-v1:0",
        "guardrailConfiguration": {"guardrailIdentifier": "G1", "guardrailVersion": "1"},
    }}
    bedrock = Mock()
    bedrock.get_model_invocation_logging_configuration.return_value = {"loggingConfig": {}}
    connector._client = lambda service, region: bedrock_agent if service == "bedrock-agent" else bedrock

    def pages(_client, op, _key, **kw):
        if op == "list_agents":
            return iter([{"agentId": "A1"}])
        if op == "list_agent_aliases":
            return iter([{"agentAliasName": "prod", "routingConfiguration": [{"agentVersion": "3"}]}])
        if op == "list_agent_action_groups":
            return iter([{"actionGroupId": id_, "actionGroupName": id_.lower()} for id_ in (
                ["LAMBDA", "CODE", "USER"] if kw["agentVersion"] == "3" else ["USER"]
            )])
        if op == "list_agent_knowledge_bases":
            return iter([{"knowledgeBaseId": "KB3", "knowledgeBaseState": "ENABLED"}] if kw["agentVersion"] == "3" else [])
        if op == "list_agent_collaborators":
            return iter([{"collaboratorId": "C3", "collaboratorName": "reviewer"}] if kw["agentVersion"] == "3" else [])
        return iter([])

    connector._paginate = pages
    records = list(connector._collect_bedrock("us-east-1"))
    agent = next(r for r in records if r["_kind"] == "bedrock-agent")
    assert {a["agentVersion"] for a in agent["_action_groups"]} == {"DRAFT", "3"}
    assert agent["_knowledge_bases"] == [{"knowledgeBaseId": "KB3", "knowledgeBaseState": "ENABLED", "_agentVersion": "3"}]
    assert agent["_collaborators"][0]["_agentVersion"] == "3"
    assert bedrock_agent.get_agent_action_group.call_count == 4
    finding = connector._h_bedrock_agent(agent)
    assert {"code-exec", "rag", "multi-agent"} <= set(finding.capabilities)
    assert "asks-user" in finding.tags
    assert {a["version"] for a in finding.metadata["action_groups"]} == {"DRAFT", "3"}
    assert finding.metadata["versions_scanned"] == ["3", "DRAFT"]
    bedrock_agent.get_agent_version.assert_called_once_with(agentId="A1", agentVersion="3")
    assert "anthropic.claude-3-haiku-20240307-v1:0" in finding.models
    assert "no-guardrail" not in finding.tags
    assert finding.metadata["version_guardrails"]["3"]["guardrailIdentifier"] == "G1"
    assert finding.metadata["knowledge_base_versions"][0]["version"] == "3"
    assert finding.metadata["collaborator_versions"][0]["version"] == "3"
    assert any(e.signal == "aws:code-interpreter" for e in finding.evidence)
    assert not ctx.stats.incomplete


def test_agentcore_gateway_reads_target_detail_for_lambda(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_gateway_target.return_value = {
        "targetId": "t1", "targetConfiguration": {"mcp": {"lambda": {"lambdaArn": "arn:aws:lambda:us-east-1:123:function:tool"}}}
    }
    connector._client = lambda service, region: client

    def pages(_client, op, _key, **kw):
        if op == "list_gateways":
            return iter([{"gatewayId": "g1", "name": "tools"}])
        if op == "list_gateway_targets":
            assert kw["gatewayIdentifier"] == "g1"
            return iter([{"targetId": "t1", "name": "code", "targetType": "LAMBDA"}])
        return iter([])

    connector._paginate = pages
    gateway = next(r for r in connector._collect_agentcore("us-east-1") if r["_kind"] == "agentcore-gateway")
    assert gateway["_targets"][0]["targetConfiguration"]["mcp"]["lambda"]["lambdaArn"].endswith(":tool")
    client.get_gateway_target.assert_called_once_with(gatewayIdentifier="g1", targetId="t1")
    assert "code-exec" in connector._h_agentcore_gateway(gateway).capabilities


def test_disabled_bedrock_actions_and_knowledge_bases_do_not_grant_capabilities(index):
    connector = AwsConnector(context(index))
    finding = connector._h_bedrock_agent({
        "agentId": "A1", "agentName": "ops", "_region": "us-east-1",
        "_action_groups": [{"actionGroupName": "code", "actionGroupState": "DISABLED",
                            "parentActionSignature": "AMAZON.CodeInterpreter"}],
        "_knowledge_bases": [{"knowledgeBaseId": "K1", "knowledgeBaseState": "DISABLED"}],
    })
    assert "code-exec" not in finding.capabilities
    assert "rag" not in finding.capabilities


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
        pagination=SimpleNamespace(list_call_get_all_results=lambda fn, *args, **kw: SimpleNamespace(data=fn(*args, **kw))),
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


def test_gcp_repeated_pagination_token_preserves_partial_data_but_marks_incomplete(index):
    ctx = context(index)
    connector = GcpConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"items": [{"id": "first"}], "nextPageToken": "same"},
        {"items": [{"id": "second"}], "nextPageToken": "same"},
    ]
    assert [item["id"] for item in connector._pages("https://example.googleapis.com/v1/items", "items")] == ["first", "second"]
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete


def test_gcp_page_cap_marks_incomplete(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.cloud.gcp.MAX_LIST_PAGES", 2)
    ctx = context(index)
    connector = GcpConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"items": [{"id": "first"}], "nextPageToken": "t1"},
        {"items": [{"id": "second"}], "nextPageToken": "t2"},
    ]
    assert len(list(connector._pages("https://example.googleapis.com/v1/items", "items"))) == 2
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete


def test_gcp_suppressed_rate_limit_does_not_report_clean_inventory(index):
    ctx = context(index)
    connector = GcpConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = HttpError(429, "https://example.googleapis.com/v1/items")
    assert list(connector._pages("https://example.googleapis.com/v1/items", "items")) == []
    assert ctx.stats.incomplete
