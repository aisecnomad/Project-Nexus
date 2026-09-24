from __future__ import annotations

from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_aws_managed_policy_grant_is_discovered(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
    iam = Mock()
    iam.get_paginator.return_value.paginate.return_value = [{"RoleDetailList": [{"RoleName": "worker", "Arn": "arn:aws:iam::123456789012:role/worker", "AttachedManagedPolicies": [{"PolicyArn": arn}]}], "Policies": [{"Arn": arn, "PolicyVersionList": [{"IsDefaultVersion": True, "Document": {"Statement": [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}]}}]}]}]
    connector._client = Mock(return_value=iam)
    records = list(connector._collect_iam())
    assert "AWSManagedPolicy" in iam.get_paginator.return_value.paginate.call_args.kwargs["Filter"]
    assert records[0]["actions"] == ["bedrock:*"]
    assert not ctx.stats.incomplete


def test_unresolved_iam_policy_is_not_silently_clean(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    connector._client = Mock()
    connector._paginate_details = Mock(return_value=iter([{"_type": "RoleDetailList", "Arn": "arn:aws:iam::123:role/a", "AttachedManagedPolicies": [{"PolicyArn": "missing"}]}]))
    assert list(connector._collect_iam()) == []
    assert ctx.stats.incomplete
    assert "unresolved" in ctx.stats.warnings[0]


def test_cloudtrail_lookup_cannot_claim_complete_runtime_visibility(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    connector._client = Mock()
    connector._paginate = Mock(return_value=iter([]))
    assert list(connector._collect_cloudtrail("us-east-1")) == []
    assert ctx.stats.incomplete
    assert "data events" in ctx.stats.warnings[0]


def test_slack_all_inventories_follow_pagination(index, monkeypatch):
    ctx = context(index, token="synthetic")
    connector = SlackConnector(ctx)
    calls = []

    def get(path, params=None):
        params = dict(params or {})
        calls.append((path, params))
        if path == "/team.info":
            return {"ok": True, "team": {"name": "test"}}
        if path == "/users.list":
            return {"ok": True, "members": [{"id": "bot", "is_bot": True}]}
        if path == "/team.integrationLogs":
            return {"ok": True, "logs": [{"id": f"log-{params['page']}"}], "paging": {"pages": 2}}
        key = {"/admin.apps.approved.list": "approved_apps", "/admin.apps.restricted.list": "restricted_apps", "/admin.apps.requests.list": "app_requests"}[path]
        second = params.get("cursor") == "next"
        return {"ok": True, key: [{"id": "second" if second else "first"}], "response_metadata": {"next_cursor": "" if second else "next"}}

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    records = list(connector.collect())
    for kind in ("approved_app", "restricted_app", "app_request", "integration_log"):
        assert len([r for r in records if r.get("_kind") == kind]) == 2
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("error", ["missing_scope", "invalid_auth", "not_allowed_token_type"])
def test_slack_http_200_error_is_incomplete(index, error):
    ctx = context(index)
    connector = SlackConnector(ctx)
    http = Mock()
    http.get_json.return_value = {"ok": False, "error": error}
    assert list(connector._cursor(http, "/users.list", {}, "members")) == []
    assert ctx.stats.incomplete
    assert error in ctx.stats.warnings[0]


def test_azure_arm_continuations_are_followed(index):
    ctx = context(index)
    connector = AzureConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = [{"value": [{"id": "first"}], "nextLink": "https://management.azure.com/next"}, {"value": [{"id": "second"}]}]
    assert [r["id"] for r in connector._list("/subscriptions", "2022-12-01")] == ["first", "second"]
    assert connector.http.get_json.call_count == 2


def test_azure_denied_diagnostics_are_unknown_not_disabled(index):
    ctx = context(index)
    connector = AzureConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = HttpError(403, "https://management.azure.com/diagnostics")
    settings = connector._list("/diagnostics", "v1")
    findings = list(connector.analyze([{"_kind": "resource", "id": "/account", "type": "microsoft.cognitiveservices/accounts", "kind": "OpenAI", "name": "test"}, {"_kind": "diagnostics", "_account": "/account", "settings": settings, "coverage": "unknown"}]))
    assert ctx.stats.incomplete
    assert "no-diagnostic-logging" not in findings[0].tags
    assert findings[0].metadata["diagnostic_logging_status"] == "unknown"


def test_azure_observed_empty_diagnostics_are_disabled(index):
    connector = AzureConnector(context(index))
    findings = list(connector.analyze([{"_kind": "resource", "id": "/account", "type": "microsoft.cognitiveservices/accounts", "kind": "OpenAI", "name": "test"}, {"_kind": "diagnostics", "_account": "/account", "settings": [], "coverage": "observed"}]))
    assert "no-diagnostic-logging" in findings[0].tags


def test_foundry_agent_cursor_pages(index, monkeypatch):
    connector = AzureConnector(context(index, foundry_token="synthetic"))
    http = Mock()
    http.get_json.side_effect = [{"data": [{"id": "first"}], "has_more": True, "last_id": "first"}, {"data": [{"id": "second"}], "has_more": False}]
    monkeypatch.setattr("shadowscan.connectors.cloud.azure.HttpClient", Mock(return_value=http))
    records = list(connector._collect_agents({"id": "/account"}, {"id": "/project", "properties": {"endpoints": {"AI Foundry API": "https://example.services.ai.azure.com/api/projects/test"}}}))
    assert [r["id"] for r in records] == ["first", "second"]
    assert http.get_json.call_args.kwargs["params"]["after"] == "first"


@pytest.mark.parametrize("endpoint", ["https://evil.example", "https://10.1.2.3/api/projects/p", "http://x.services.ai.azure.com"])
def test_foundry_rejects_untrusted_metadata_endpoint(index, monkeypatch, endpoint):
    ctx = context(index, foundry_token="synthetic")
    connector = AzureConnector(ctx)
    http = Mock()
    monkeypatch.setattr("shadowscan.connectors.cloud.azure.HttpClient", http)
    # No token leaves the process, and one untrusted project endpoint marks
    # coverage incomplete instead of abandoning the rest of the tenant.
    assert list(connector._collect_agents({}, {"properties": {"endpoints": {"AI Foundry API": endpoint}}})) == []
    http.assert_not_called()
    assert ctx.stats.incomplete
    assert any("agent coverage unknown" in warning for warning in ctx.stats.warnings)
