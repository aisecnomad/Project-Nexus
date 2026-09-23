"""Invalid optional values must not corrupt findings or conceal lost coverage."""

from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.identity.auth0 import Auth0Connector
from shadowscan.connectors.lowcode.salesforce import SalesforceConnector
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.models import ScanStats


def _context(index, **config):
    context = ConnectorContext(index=index, config=config)
    context.stats = ScanStats(connector="test", started_at="2026-01-01")
    return context


def test_auth0_invalid_audiences_preserve_valid_grants_and_mark_incomplete(index):
    context = _context(index)
    connector = Auth0Connector(context)
    finding = connector._client_finding({"client_id": "agent", "name": "Agent", "app_type": "non_interactive"}, [
        {"audience": "https://internal.example/api", "scope": ["write:tickets"]},
        {"audience": None, "scope": []},
        {"audience": {"invalid": True}, "scope": []},
    ])
    assert finding is not None
    assert finding.metadata["audiences"] == ["https://internal.example/api"]
    assert "write:tickets" in finding.permissions
    assert context.stats.incomplete


@pytest.mark.parametrize("invalid_scope", [None, {}, {"name": 111}, {"name": None}, 111])
def test_slack_invalid_scope_items_do_not_drop_the_app(index, invalid_scope):
    context = _context(index)
    connector = SlackConnector(context)
    finding = connector._app_finding("app", {"name": "Claude"}, [invalid_scope, {"name": "channels:history"}],
                                     "approved", None, [], "team")
    assert finding is not None
    assert "channels:history" in finding.permissions
    assert context.stats.incomplete


def test_slack_scalar_scopes_are_not_split_into_characters(index):
    context = _context(index)
    finding = SlackConnector(context)._app_finding("app", {"name": "Claude"}, "channels:history",  # type: ignore[arg-type]
                                                   "approved", None, [], "team")
    assert finding is not None and not finding.permissions
    assert context.stats.incomplete


def test_salesforce_missing_bot_identity_does_not_merge_or_hide_other_bots(index):
    context = _context(index)
    connector = SalesforceConnector(context)
    findings = list(connector.analyze([
        {"_kind": "BotDefinition", "MasterLabel": "Missing identity"},
        {"_kind": "BotDefinition", "Id": {"bad": "value"}},
        {"_kind": "BotDefinition", "Id": "BOT1", "DeveloperName": "Agent", "MasterLabel": "Agent"},
    ]))
    assert [finding.resource for finding in findings] == ["salesforce:bot:BOT1"]
    assert context.stats.incomplete


@pytest.mark.parametrize("invalid_link", [False, 1, {}, ["/next"]])
def test_azure_invalid_continuation_is_unknown_coverage(index, invalid_link):
    context = _context(index)
    connector = AzureConnector(context)
    connector.http = Mock()
    connector.http.get_json.return_value = {"value": [{"id": "first"}], "nextLink": invalid_link}
    assert connector._list("/subscriptions", "2022-12-01") is None
    assert context.stats.incomplete
    assert connector.http.get_json.call_count == 1


def test_azure_missing_resource_id_preserves_other_resource_graph_records(index):
    context = _context(index, subscriptions=["sub"])
    connector = AzureConnector(context)
    connector._auth = Mock()
    connector._list = Mock(return_value=[])
    connector.http = Mock()
    connector.http.post_json.return_value = {"data": [
        {"type": "microsoft.logic/workflows"},
        {"id": "/subscriptions/sub/resourceGroups/rg/providers/example/valid", "type": "example"},
    ]}
    records = list(connector.collect())
    assert len(records) == 1 and records[0]["id"].endswith("/valid")
    assert context.stats.incomplete
    connector.http.get_json.assert_not_called()


def test_azure_offline_resource_without_identity_is_not_a_none_resource(index):
    context = _context(index)
    findings = list(AzureConnector(context).analyze([
        {"_kind": "resource", "type": "microsoft.search/searchservices", "name": "Missing identity"},
        {"_kind": "resource", "type": "microsoft.search/searchservices", "name": "Valid", "id": "/search/valid"},
    ]))
    assert [finding.resource for finding in findings] == ["/search/valid"]
    assert context.stats.incomplete


@pytest.mark.parametrize("provider", ["aws", "azure"])
def test_invalid_model_does_not_discard_agent_finding(index, provider):
    context = _context(index)
    if provider == "aws":
        finding = AwsConnector(context)._h_bedrock_agent({"agentId": "AGENT", "agentName": "Agent", "foundationModel": {"invalid": True}})
    else:
        finding = AzureConnector(context)._h_foundry_agent({"id": "AGENT", "name": "Agent", "_project": "/project", "model": {"invalid": True}})
    assert finding.models == [] and finding.resource
    assert context.stats.incomplete
