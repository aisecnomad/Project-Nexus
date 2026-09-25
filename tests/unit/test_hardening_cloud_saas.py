"""Regressions for the production-review round: cloud, low-code and SaaS connectors."""

from __future__ import annotations

from unittest.mock import Mock

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.connectors.lowcode import salesforce as salesforce_module
from shadowscan.connectors.lowcode import servicenow as servicenow_module
from shadowscan.connectors.lowcode.salesforce import SalesforceConnector
from shadowscan.connectors.lowcode.servicenow import ServiceNowConnector
from shadowscan.connectors.saas import github_apps as github_apps_module
from shadowscan.connectors.saas.github_apps import GitHubAppsConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_azure_foundry_projects_inherit_subscription_and_location(index, monkeypatch):
    connector = AzureConnector(context(index, subscriptions="s1"))
    account_id = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acc"
    http = Mock()
    http.post_json.return_value = {"data": [{
        "id": account_id, "name": "acc", "type": "microsoft.cognitiveservices/accounts", "kind": "AIServices",
        "location": "eastus", "subscriptionId": "s1", "properties": {},
    }]}

    def fake_list(path, api, *, allow_partial=False):
        return [{"id": f"{account_id}/projects/p1", "name": "p1", "properties": {}}] if path.endswith("/projects") else []

    monkeypatch.setattr(connector, "_auth", lambda: setattr(connector, "http", http))
    monkeypatch.setattr(connector, "_list", fake_list)
    monkeypatch.setattr(connector, "_collect_agents", lambda account, project: iter([]))
    records = list(connector.collect())
    project = next(r for r in records if r.get("type") == "microsoft.cognitiveservices/accounts/projects")
    assert project["subscriptionId"] == "s1" and project["location"] == "eastus"
    finding = connector._resource_finding(project, [], None)
    assert finding is not None and finding.account == "s1" and finding.region == "eastus"


def test_oci_clients_are_cached_per_region_with_timeouts(index):
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


def test_salesforce_never_requests_token_values_and_survives_expired_locators(index, monkeypatch):
    assert "DeleteToken" not in salesforce_module.QUERIES["OauthToken"][1]
    assert "AccessToken" not in salesforce_module.QUERIES["OauthToken"][1]
    ctx = context(index, instance_url="https://acme.my.salesforce.com", access_token="synthetic")
    connector = SalesforceConnector(ctx)
    monkeypatch.setattr(salesforce_module, "QUERIES", {"BotDefinition": ("data", "SELECT Id FROM BotDefinition")})
    monkeypatch.setattr(connector, "_auth", lambda: None)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"records": [{"Id": "1"}], "done": False, "nextRecordsUrl": "/services/data/v62.0/query/01g-2000"},
        HttpError(400, "https://acme.my.salesforce.com/services/data/v62.0/query/01g-2000"),
    ]
    assert list(connector.collect()) == [{"Id": "1", "_kind": "BotDefinition"}]
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete and any("collection incomplete (HTTP 400)" in w for w in ctx.stats.warnings)


def test_servicenow_pagination_stops_on_a_repeated_page(index, monkeypatch):
    ctx = context(index, instance="https://acme.service-now.com", token="synthetic")
    connector = ServiceNowConnector(ctx)
    monkeypatch.setattr(servicenow_module, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(connector, "_auth", lambda: None)
    connector.http = Mock()
    # Every response is a fresh object, as it would be from the transport.
    connector.http.get_json.side_effect = lambda *args, **kwargs: {"result": [{"sys_id": str(i)} for i in range(kwargs["params"]["sysparm_limit"])]}
    records = list(connector.collect())
    assert len(records) == 500
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete and any("repeated pagination page" in warning for warning in ctx.stats.warnings)


def test_github_apps_pat_inventory_is_optional(index, monkeypatch):
    ctx = context(index, org="acme", token="synthetic")
    connector = GitHubAppsConnector(ctx)

    class FakeHttp:
        def __init__(self, *args, **kwargs):
            pass

        def paginate_link(self, path, params=None, item_key=None):
            if "personal-access-tokens" in path:
                raise HttpError(403, "https://api.github.com" + path)
            yield {"id": 101, "app_slug": "coderabbitai", "permissions": {}}

        def try_get_json(self, path, default=None, ok_statuses=None, **kwargs):
            return None

    monkeypatch.setattr(github_apps_module, "HttpClient", FakeHttp)
    records = list(connector.collect())
    assert [r["_kind"] for r in records] == ["installation"]
    assert ctx.stats.incomplete and any("PAT inventory unavailable" in warning for warning in ctx.stats.warnings)
