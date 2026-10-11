"""Azure connector: resource and app-settings collection, scope values and Foundry agent contracts."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
import requests
from requests import ConnectionError as RequestsConnectionError

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.azure import AI_ROLE_IDS, AzureConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError
from shadowscan.utils.redaction import REDACTED, sanitize

ENDPOINT = "https://example.services.ai.azure.com/api/projects/test"
PROJECT = {"id": "/project", "properties": {"endpoints": {"AI Foundry API": ENDPOINT}}}


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_azure_live_deployments_keep_collected_account(index, monkeypatch):
    connector = AzureConnector(context(index))
    connector.http = Mock()
    account = {
        "id": "/subscriptions/s1/providers/Microsoft.CognitiveServices/accounts/a",
        "name": "a",
        "type": "Microsoft.CognitiveServices/accounts",
    }
    deployment = {
        "id": f"{account['id']}/deployments/d",
        "_kind": "resource",
        "_account": "/other-account",
        "_account_name": "other-account",
    }
    monkeypatch.setattr(
        connector,
        "_list",
        lambda path, *args, **kwargs: [deployment] if path.endswith("/deployments") else [],
    )
    records = list(connector._resource_details(account, account["id"]))
    assert records[0]["_kind"] == "deployment"
    assert records[0]["_account"] == account["id"] and records[0]["_account_name"] == "a"


def test_azure_listed_subscriptions_are_not_the_principal_after_an_error(index, monkeypatch):
    connector = AzureConnector(context(index))
    subscription = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def listing(path, api, *, allow_partial=False):
        # A gap recorded as an error rather than a warning while the subscriptions were listed.
        connector.ctx.error("cloud.azure: synthetic listing error")
        return [{"subscriptionId": subscription}]

    monkeypatch.setattr(connector, "_list", listing)
    assert connector._listed_subscriptions() == [subscription]
    assert connector.ctx.scope_record([])["principal"] is None
    assert connector.ctx.stats.incomplete


def test_azure_live_role_assignments_keep_collected_subscription_and_role(index, monkeypatch):
    connector = AzureConnector(context(index, subscriptions=["s1"]))
    connector.http = Mock()
    role_id, role_name = next(iter(AI_ROLE_IDS.items()))
    assignment = {
        "id": "/assignment",
        "properties": {
            "roleDefinitionId": f"/roleDefinitions/{role_id}",
            "principalId": "p1",
            "_kind": "resource",
            "_subscription": "other-subscription",
            "role_id": "other-role",
            "role": "other-role",
        },
    }
    monkeypatch.setattr(connector, "_auth", lambda: None)
    monkeypatch.setattr(connector, "_resource_graph", lambda subs: [])
    monkeypatch.setattr(connector, "_list", lambda *args, **kwargs: [assignment])
    (record,) = connector.collect()
    assert record["_kind"] == "role-assignment" and record["_subscription"] == "s1"
    assert record["role_id"] == role_id and record["role"] == role_name


def foundry_context(index):
    ctx = ConnectorContext(config={"foundry_token": "synthetic"}, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def foundry_http(monkeypatch, pages):
    """Exercise real HttpClient URL composition; never issue a cloud request."""
    page_iter = iter(pages)
    calls = []

    def request(session, method, url, **kwargs):
        calls.append((method, url, kwargs, dict(session.headers)))
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(next(page_iter)).encode()
        response._content_consumed = True
        return response

    monkeypatch.setattr(requests.Session, "request", request)
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: [])
    return calls


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
        "_kind": "appsettings",
        "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/app",
        "name": "app",
        "kind": "functionapp",
        "environment": {
            "OPENAI_API_KEY": "sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h",
            "SENDGRID_KEY": "SG.opaque-value-1234567890",
        },
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
    http.post_json.return_value = {
        "data": [
            {
                "id": account_id,
                "name": "acc",
                "type": "microsoft.cognitiveservices/accounts",
                "kind": "AIServices",
                "location": "eastus",
                "subscriptionId": "s1",
                "properties": {},
            }
        ]
    }

    def fake_list(path, api, *, allow_partial=False):
        return (
            [{"id": f"{account_id}/projects/p1", "name": "p1", "properties": {}}]
            if path.endswith("/projects")
            else []
        )

    monkeypatch.setattr(connector, "_auth", lambda: setattr(connector, "http", http))
    monkeypatch.setattr(connector, "_list", fake_list)
    monkeypatch.setattr(connector, "_collect_agents", lambda account, project: iter([]))
    records = list(connector.collect())
    project = next(r for r in records if r.get("type") == "microsoft.cognitiveservices/accounts/projects")
    assert project["subscriptionId"] == "s1" and project["location"] == "eastus"
    finding = connector._resource_finding(project, [], None)
    assert finding is not None and finding.account == "s1" and finding.region == "eastus"


@pytest.mark.parametrize("failed", [None, [], {"error": {}}, {"properties": []}, RequestsConnectionError()])
def test_azure_invalid_or_failed_appsettings_preserves_later_resources(index, failed):
    connector = AzureConnector(context(index, subscriptions="s1"))
    connector._auth = Mock()
    connector._list = Mock(return_value=[])
    connector.http = Mock()
    rows = [
        {
            "id": f"/subscriptions/s1/providers/Microsoft.Web/sites/{name}",
            "type": "microsoft.web/sites",
            "name": name,
        }
        for name in ("failed", "good")
    ]
    connector.http.post_json.side_effect = [
        {"data": rows},
        failed,
        {"properties": {"OPENAI_API_KEY": "sk-proj-" + "b" * 40, "CUSTOM": "opaque-secret-value"}},
    ]
    records = list(connector.collect())
    assert [r["name"] for r in records if r["_kind"] == "resource"] == ["failed", "good"]
    settings = [r for r in records if r["_kind"] == "appsettings"]
    assert len(settings) == 1 and settings[0]["name"] == "good"
    assert set(sanitize(settings[0])["environment"].values()) == {REDACTED}
    assert connector.ctx.stats.incomplete


def test_foundry_classic_route_version_and_cursor_contract(index, monkeypatch):
    # Official azure-ai-agents_1.0.0 build_agents_list_agents_request:
    # GET /assistants, api-version=v1, limit and after query parameters.
    calls = foundry_http(
        monkeypatch,
        [
            {"object": "list", "data": [{"id": "asst_first"}], "has_more": True, "last_id": "asst_first"},
            {"object": "list", "data": [{"id": "asst_second"}], "has_more": False, "last_id": "asst_second"},
        ],
    )
    ctx = foundry_context(index)
    records = list(AzureConnector(ctx)._collect_agents({"id": "/account"}, PROJECT))
    assert [r["id"] for r in records] == ["asst_first", "asst_second"]
    assert len(calls) == 2
    for method, url, kwargs, headers in calls:
        assert (method, url) == ("GET", f"{ENDPOINT}/assistants")
        assert kwargs["params"]["api-version"] == "v1"
        assert headers["Authorization"] == "Bearer synthetic"
    assert calls[0][2]["params"] == {"api-version": "v1", "limit": 100}
    assert calls[1][2]["params"]["after"] == "asst_first"
    assert not ctx.stats.incomplete


@pytest.mark.parametrize(
    "page",
    [
        None,
        {},
        [],
        {"error": {"code": "denied"}},
        {"data": {}, "has_more": False},
        {"data": [], "has_more": "false"},
        {"data": []},
        {"data": [], "has_more": True, "last_id": "a"},
        {"data": [{"id": "a"}], "has_more": True, "last_id": []},
        {"data": [{"id": "a"}], "has_more": True, "last_id": "other"},
    ],
)
def test_foundry_malformed_envelopes_are_incomplete(index, monkeypatch, page):
    foundry_http(monkeypatch, [page])
    ctx = foundry_context(index)
    list(AzureConnector(ctx)._collect_agents({}, PROJECT))
    assert ctx.stats.incomplete


def test_foundry_valid_empty_inventory_is_complete(index, monkeypatch):
    foundry_http(monkeypatch, [{"object": "list", "data": [], "has_more": False, "last_id": None}])
    ctx = foundry_context(index)
    assert list(AzureConnector(ctx)._collect_agents({}, PROJECT)) == []
    assert not ctx.stats.incomplete


def test_foundry_malformed_record_preserves_neighbor(index, monkeypatch):
    foundry_http(monkeypatch, [{"data": [{"id": "a"}, {"name": "missing id"}, 4], "has_more": False}])
    ctx = foundry_context(index)
    assert [r["id"] for r in AzureConnector(ctx)._collect_agents({}, PROJECT)] == ["a"]
    assert ctx.stats.incomplete


def test_foundry_repeated_cursor_stops_with_partial_records(index, monkeypatch):
    page = {"data": [{"id": "a"}], "has_more": True, "last_id": "a"}
    calls = foundry_http(monkeypatch, [page, page])
    ctx = foundry_context(index)
    assert list(AzureConnector(ctx)._collect_agents({}, PROJECT))
    assert len(calls) == 2
    assert ctx.stats.incomplete


def test_azure_app_settings_are_exported_as_redactable_environment(index, monkeypatch):
    ctx = ConnectorContext(config={"subscriptions": ["sub1"]}, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    connector = AzureConnector(ctx)
    monkeypatch.setattr(connector, "_auth", lambda: None)
    monkeypatch.setattr(connector, "_list", lambda *args, **kwargs: [])
    connector.http = Mock()
    connector.http.post_json.side_effect = [
        {
            "data": [
                {
                    "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Web/sites/app",
                    "type": "microsoft.web/sites",
                    "name": "worker",
                    "kind": "app",
                }
            ]
        },
        {"properties": {"OPENAI_API_KEY": "synthetic-azure-app-secret"}},
    ]

    records = list(connector.collect())
    record = next(item for item in records if item.get("_kind") == "appsettings")
    assert record["environment"]["OPENAI_API_KEY"] == "synthetic-azure-app-secret"
    assert "synthetic-azure-app-secret" not in json.dumps(sanitize(record))
    finding = connector._h_appsettings(record)
    assert finding and "provider.openai" in finding.model_providers
