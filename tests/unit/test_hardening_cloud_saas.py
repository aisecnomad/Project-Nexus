"""Regressions for the production-review round: cloud, low-code and SaaS connectors."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from requests import ConnectionError as RequestsConnectionError

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.common import string_list
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.connectors.lowcode import salesforce as salesforce_module
from shadowscan.connectors.lowcode import servicenow as servicenow_module
from shadowscan.connectors.lowcode.salesforce import SalesforceConnector
from shadowscan.connectors.lowcode.servicenow import ServiceNowConnector
from shadowscan.connectors.saas import github_apps as github_apps_module
from shadowscan.connectors.saas.github_apps import GitHubAppsConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError
from shadowscan.utils.redaction import REDACTED, sanitize


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_string_list_coercion():
    assert string_list("lambda", "services") == ["lambda"]
    assert string_list(["a", " b "], "x") == ["a", "b"]
    assert string_list("", "x") is None and string_list(None, "x") is None
    assert string_list("us-east-1", "regions", pattern=r"[a-z0-9-]+") == ["us-east-1"]
    with pytest.raises(ValueError):
        string_list(["a", 1], "x")
    with pytest.raises(ValueError):
        string_list("US East", "regions", pattern=r"[a-z0-9-]+")


def test_aws_scalar_settings_are_single_items_and_unknown_services_are_rejected(index):
    connector = AwsConnector(context(index, services="lambda", regions="us-east-1"))
    assert connector.services == {"lambda"} and connector.regions == ["us-east-1"]
    with pytest.raises(ConnectorError):
        AwsConnector(context(index, services="nope"))
    with pytest.raises(ConnectorError):
        AwsConnector(context(index, regions="US East"))


def test_aws_layer_name_and_ssm_parameter_arn(index):
    connector = AwsConnector(context(index, account_id="123456789012"))
    finding = connector._h_lambda({
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:f", "FunctionName": "f", "_region": "us-east-1",
        "Layers": ["arn:aws:lambda:us-east-1:123456789012:layer:langchain-deps:4"],
    })
    assert finding is not None and "framework.langchain" in finding.frameworks
    plain = connector._h_ssm_parameter({"Name": "OPENAI_API_KEY", "_region": "us-east-1"})
    nested = connector._h_ssm_parameter({"Name": "/prod/OPENAI_API_KEY", "_region": "us-east-1"})
    assert plain is not None and plain.resource == "arn:aws:ssm:us-east-1:123456789012:parameter/OPENAI_API_KEY"
    assert nested is not None and nested.resource == "arn:aws:ssm:us-east-1:123456789012:parameter/prod/OPENAI_API_KEY"


def test_aws_clients_carry_explicit_timeouts(index, monkeypatch):
    connector = AwsConnector(context(index, account_id="123456789012"))
    session = Mock()
    connector._session = session
    connector._client("lambda", "us-east-1")
    config = session.client.call_args.kwargs["config"]
    assert config.connect_timeout == 10 and config.read_timeout == 30
    assert config.retries == {"mode": "standard", "total_max_attempts": 3}


def test_azure_detail_failures_are_incomplete_coverage_not_fatal(index):
    ctx = context(index)
    connector = AzureConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = HttpError(500, "https://management.azure.com/x")
    assert connector._get("/x", "2024-01-01") is None
    connector.http.get_json.side_effect = RequestsConnectionError()
    assert connector._get("/y", "2024-01-01") is None
    connector.http.post_json.side_effect = RequestsConnectionError()
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 2


def test_azure_scalar_subscription_is_one_subscription(index):
    assert AzureConnector(context(index, subscriptions="s1")).subscriptions == ["s1"]
    with pytest.raises(ConnectorError):
        AzureConnector(context(index, subscriptions="/subscriptions/s1"))


def test_azure_app_settings_are_redacted_in_dumps_but_analyzed_live(index):
    record = {
        "_kind": "appsettings", "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/app",
        "name": "app", "kind": "functionapp",
        "environment": {"OPENAI_API_KEY": "sk-proj-" + "a" * 40, "SENDGRID_KEY": "SG.opaque-value-1234567890"},
    }
    dumped = sanitize(record)
    assert set(dumped["environment"].values()) == {REDACTED}
    connector = AzureConnector(context(index))
    finding = connector._h_appsettings(record)
    assert finding is not None and "plaintext-credential" in finding.tags
    assert "OPENAI_API_KEY" in finding.metadata["setting_names"]
    legacy = {**record, "settings": record["environment"]}
    del legacy["environment"]
    assert connector._h_appsettings(legacy) is not None


def test_azure_foundry_projects_inherit_subscription_and_location(index, monkeypatch):
    connector = AzureConnector(context(index, subscriptions="s1"))
    account_id = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acc"
    http = Mock()
    http.post_json.return_value = {"data": [{
        "id": account_id, "name": "acc", "type": "microsoft.cognitiveservices/accounts", "kind": "AIServices",
        "location": "eastus", "subscriptionId": "s1", "properties": {},
    }]}

    def fake_list(path, api, **kwargs):
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


def test_oci_function_reads_environment_and_legacy_config_keys(index):
    connector = OciConnector(context(index))
    base = {"id": "ocid1.fnfunc.oc1..fn1", "display_name": "fn", "_region": "r", "_compartment": "c", "_application": "app", "image": "ollama/ollama:latest"}
    current = connector._h_function({**base, "environment": {"OPENAI_API_KEY": "x"}})
    legacy = connector._h_function({**base, "config": {"OPENAI_API_KEY": "x"}})
    assert current is not None and legacy is not None
    assert current.metadata["config_keys"] == legacy.metadata["config_keys"] == ["OPENAI_API_KEY"]


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
    assert ctx.stats.incomplete and any("collection incomplete (HTTP 400)" in w for w in ctx.stats.warnings)


def test_servicenow_pagination_stops_on_a_repeated_page(index, monkeypatch):
    ctx = context(index, instance="https://acme.service-now.com", token="synthetic")
    connector = ServiceNowConnector(ctx)
    monkeypatch.setattr(servicenow_module, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(connector, "_auth", lambda: None)
    connector.http = Mock()
    # Every response is a fresh object, as it would be from the transport.
    connector.http.get_json.side_effect = lambda *args, **kwargs: {"result": [{"sys_id": str(i)} for i in range(500)]}
    records = list(connector.collect())
    assert len(records) == 500
    assert connector.http.get_json.call_count == 2
    assert any("repeated pagination page" in warning for warning in ctx.stats.warnings)


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
    assert ctx.stats.incomplete and any("PAT inventory unavailable" in error for error in ctx.stats.errors)
