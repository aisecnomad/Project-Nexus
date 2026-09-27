"""Bedrock agents, AgentCore gateways and invocation logging, from provider-shaped responses."""

from __future__ import annotations

import json
from unittest import mock
from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.models import ScanStats
from shadowscan.utils.redaction import REDACTED

ACCOUNT = "123456789012"


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def _context(index, **config) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00+00:00")
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


def test_bedrock_agent_draft_details_are_a_snapshot_that_survives_export(tmp_path, index):
    pytest.importorskip("boto3")  # live collection path needs the [aws] extra
    class FakeAgents:
        def get_agent(self, agentId):
            return {"agent": {"agentId": agentId, "agentArn": f"arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/{agentId}",
                              "agentName": "ops", "agentStatus": "PREPARED",
                              "foundationModel": "anthropic.claude-3-haiku-20240307-v1:0",
                              "guardrailConfiguration": {"guardrailIdentifier": "g1", "guardrailVersion": "1"}}}

    def paginate(client, op, key, **kwargs):
        return iter([{"agentId": "AGENT1", "agentName": "ops", "agentStatus": "PREPARED"}] if op == "list_agents" else [])

    dump = tmp_path / "aws.jsonl"
    ctx = _context(index, services=["bedrock"], regions=["us-east-1"], _dump_path=str(dump))
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    connector._session = object()
    original_safe = connector._safe

    def safe(fn, *args, **kwargs):
        result = original_safe(fn, *args, **kwargs)
        return None if isinstance(result, mock.MagicMock) else result

    with mock.patch.object(connector, "_client", lambda svc, region=None: FakeAgents() if svc == "bedrock-agent" else mock.MagicMock()), \
            mock.patch.object(connector, "_paginate", paginate), mock.patch.object(connector, "_safe", safe), \
            mock.patch.object(connector, "_session_", lambda: None), mock.patch.object(connector, "_regions", lambda: ["us-east-1"]):
        live = connector.run()
    assert not ctx.stats.warnings and [f.metadata["version_models"] for f in live] == [{"DRAFT": "anthropic.claude-3-haiku-20240307-v1:0"}]
    exported = next(json.loads(line) for line in dump.read_text().splitlines() if '"bedrock-agent"' in line)
    assert exported["_version_details"]["DRAFT"]["foundationModel"] == "anthropic.claude-3-haiku-20240307-v1:0"
    assert not any(key.startswith("_") for key in exported["_version_details"]["DRAFT"])
    offline_ctx = _context(index, input=str(dump))
    offline = AwsConnector(offline_ctx).run()
    assert offline_ctx.stats.incomplete is False and not offline_ctx.stats.warnings
    assert offline[0].metadata["version_guardrails"] == {"DRAFT": {"guardrailIdentifier": "g1", "guardrailVersion": "1"}}


def test_bedrock_agent_reads_collapsed_draft_from_older_exports_without_incomplete_coverage(index):
    record = {"_kind": "bedrock-agent", "_region": "us-east-1", "agentId": "AGENT1",
              "agentArn": f"arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/AGENT1", "agentName": "ops", "agentStatus": "PREPARED",
              "foundationModel": "amazon.nova-pro-v1:0", "_version_details": {"DRAFT": REDACTED}, "_action_groups": [],
              "_knowledge_bases": [], "_aliases": []}
    ctx = _context(index)
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    (finding,) = list(connector.analyze([record]))
    assert finding.metadata["version_models"] == {"DRAFT": "amazon.nova-pro-v1:0"} and not ctx.stats.warnings


def test_bedrock_logging_record_without_configuration_is_unknown_coverage(index):
    ctx = _context(index)
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    findings = list(connector.analyze([
        {"_kind": "bedrock-logging", "_region": "us-east-1", "error": {"code": "AccessDenied"}},
        {"_kind": "bedrock-logging", "_region": "eu-west-1"},
        {"_kind": "bedrock-logging", "_region": "us-west-2", "loggingConfig": None},
    ]))
    assert [f.region for f in findings] == ["us-west-2"] and "no-invocation-logging" in findings[0].tags
    assert ctx.stats.incomplete and sum("logging configuration unavailable" in w for w in ctx.stats.warnings) == 2
