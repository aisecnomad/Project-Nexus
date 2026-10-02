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
    iam.get_paginator.return_value.paginate.return_value = [
        {
            "RoleDetailList": [
                {
                    "RoleName": "worker",
                    "Arn": "arn:aws:iam::123456789012:role/worker",
                    "AttachedManagedPolicies": [{"PolicyArn": arn}],
                }
            ],
            "Policies": [
                {
                    "Arn": arn,
                    "PolicyVersionList": [
                        {
                            "IsDefaultVersion": True,
                            "Document": {
                                "Statement": [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}]
                            },
                        }
                    ],
                }
            ],
        }
    ]
    connector._client = Mock(return_value=iam)
    records = list(connector._collect_iam())
    assert "AWSManagedPolicy" in iam.get_paginator.return_value.paginate.call_args.kwargs["Filter"]
    assert records[0]["actions"] == ["bedrock:*"]
    assert not ctx.stats.incomplete


def test_unresolved_iam_policy_is_not_silently_clean(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    connector._client = Mock()
    connector._paginate_details = Mock(
        return_value=iter(
            [
                {
                    "_type": "RoleDetailList",
                    "Arn": "arn:aws:iam::123:role/a",
                    "AttachedManagedPolicies": [{"PolicyArn": "missing"}],
                }
            ]
        )
    )
    assert list(connector._collect_iam()) == []
    assert ctx.stats.incomplete
    assert "unresolved" in ctx.stats.warnings[0]


def test_cloudtrail_lookup_discloses_management_events_only_visibility_without_failing_the_scan(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    connector._client = Mock()
    connector._paginate = Mock(return_value=iter([]))
    assert list(connector._collect_cloudtrail("us-east-1")) == []
    # An informational notice: the lookup itself succeeded, so completeness is unaffected.
    assert not ctx.stats.incomplete
    assert "data events" in ctx.stats.warnings[0]


def test_slack_all_inventories_follow_pagination(index, monkeypatch):
    ctx = context(index, token="synthetic")
    connector = SlackConnector(ctx)
    calls = []

    def get(path, params=None):
        params = dict(params or {})
        calls.append((path, params))
        if path == "/team.info":
            return {"ok": True, "team": {"id": "T1", "name": "test"}}
        if path == "/users.list":
            return {"ok": True, "members": [{"id": "bot", "is_bot": True}]}
        if path == "/team.integrationLogs":
            return {"ok": True, "logs": [{"id": f"log-{params['page']}"}], "paging": {"pages": 2}}
        key = {
            "/admin.apps.approved.list": "approved_apps",
            "/admin.apps.restricted.list": "restricted_apps",
            "/admin.apps.requests.list": "app_requests",
        }[path]
        second = params.get("cursor") == "next"
        return {
            "ok": True,
            key: [{"id": "second" if second else "first"}],
            "response_metadata": {"next_cursor": "" if second else "next"},
        }

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
    connector.http.get_json.side_effect = [
        {"value": [{"id": "first"}], "nextLink": "https://management.azure.com/next"},
        {"value": [{"id": "second"}]},
    ]
    assert [r["id"] for r in connector._list("/subscriptions", "2022-12-01")] == ["first", "second"]
    assert connector.http.get_json.call_count == 2


def test_azure_denied_diagnostics_are_unknown_not_disabled(index):
    ctx = context(index)
    connector = AzureConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = HttpError(403, "https://management.azure.com/diagnostics")
    settings = connector._list("/diagnostics", "v1")
    findings = list(
        connector.analyze(
            [
                {
                    "_kind": "resource",
                    "id": "/account",
                    "type": "microsoft.cognitiveservices/accounts",
                    "kind": "OpenAI",
                    "name": "test",
                },
                {"_kind": "diagnostics", "_account": "/account", "settings": settings, "coverage": "unknown"},
            ]
        )
    )
    assert ctx.stats.incomplete
    assert "no-diagnostic-logging" not in findings[0].tags
    assert findings[0].metadata["diagnostic_logging_status"] == "unknown"


def test_azure_observed_empty_diagnostics_are_disabled(index):
    connector = AzureConnector(context(index))
    findings = list(
        connector.analyze(
            [
                {
                    "_kind": "resource",
                    "id": "/account",
                    "type": "microsoft.cognitiveservices/accounts",
                    "kind": "OpenAI",
                    "name": "test",
                },
                {"_kind": "diagnostics", "_account": "/account", "settings": [], "coverage": "observed"},
            ]
        )
    )
    assert "no-diagnostic-logging" in findings[0].tags


def test_foundry_agent_cursor_pages(index, monkeypatch):
    connector = AzureConnector(context(index, foundry_token="synthetic"))
    http = Mock()
    http.get_json.side_effect = [
        {"data": [{"id": "first"}], "has_more": True, "last_id": "first"},
        {"data": [{"id": "second"}], "has_more": False},
    ]
    monkeypatch.setattr("shadowscan.connectors.cloud.azure.HttpClient", Mock(return_value=http))
    records = list(
        connector._collect_agents(
            {"id": "/account"},
            {
                "id": "/project",
                "properties": {
                    "endpoints": {"AI Foundry API": "https://example.services.ai.azure.com/api/projects/test"}
                },
            },
        )
    )
    assert [r["id"] for r in records] == ["first", "second"]
    assert http.get_json.call_args.kwargs["params"]["after"] == "first"


def test_foundry_rejects_untrusted_metadata_endpoint(index, monkeypatch):
    connector = AzureConnector(context(index, foundry_token="synthetic"))
    http = Mock()
    monkeypatch.setattr("shadowscan.connectors.cloud.azure.HttpClient", http)
    assert (
        list(
            connector._collect_agents(
                {}, {"properties": {"endpoints": {"AI Foundry API": "https://evil.example"}}}
            )
        )
        == []
    )
    assert connector.ctx.stats.incomplete
    http.assert_not_called()


# Response-derived ARM identifiers become request paths with the ARM bearer token:
# requests removes "." and ".." segments, and "?" or "#" cuts off the suffix the
# connector appends, so an unchecked id could turn the app-settings POST into a
# POST to any ARM action, such as an account's listKeys.
SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"


def test_azure_listed_subscription_ids_must_be_guids(index):
    ctx = context(index)
    connector = AzureConnector(ctx)
    connector._auth = Mock()
    connector.http = Mock()
    listed = [
        {"subscriptionId": "../../providers/Microsoft.Web"},
        {"subscriptionId": SUBSCRIPTION},
        {"subscriptionId": 7},
        {"displayName": "no id"},
    ]
    requested = []

    def fake_list(path, api, *, allow_partial=False):
        requested.append(path)
        return listed if path == "/subscriptions" else []

    connector._list = fake_list
    connector._resource_graph = Mock(return_value=[])
    assert list(connector.collect()) == []
    connector._resource_graph.assert_called_once_with([SUBSCRIPTION])
    assert requested == [
        "/subscriptions",
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleAssignments",
    ]
    assert ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "cloud.azure: 3 listed subscriptions have no valid subscription id (a GUID) and were not "
        "scanned; coverage incomplete"
    ]


@pytest.mark.parametrize(
    "resource_id",
    [
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/x/../../../../providers"
        "/Microsoft.CognitiveServices/accounts/a/listKeys",
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/x?api-version=2023-05-01#",
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/x#",
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/x%2F..%2F",
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/x\\..\\y",
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/a b",
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/x\n",
        "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/./x",
        "/subscriptions/s1//resourceGroups/rg/providers/Microsoft.Web/sites/x",
        "subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/x",
        "https://evil.example/subscriptions/s1",
    ],
)
def test_azure_resource_ids_cannot_steer_request_paths(index, resource_id):
    ctx = context(index, subscriptions=["s1"])
    connector = AzureConnector(ctx)
    connector._auth = Mock()
    connector._list = Mock(return_value=[])
    kept = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/kept"

    def post_json(path, **_kwargs):
        if path == "/providers/Microsoft.ResourceGraph/resources":
            rows = [
                {"id": resource_id, "type": "microsoft.web/sites"},
                {"id": kept, "type": "microsoft.web/sites"},
            ]
            return {"data": rows}
        return {"properties": {}}

    connector.http = Mock()
    connector.http.post_json.side_effect = post_json
    records = list(connector.collect())
    assert [r["id"] for r in records] == [kept, kept]  # the resource and its app settings
    posted = [call.args[0] for call in connector.http.post_json.call_args_list]
    assert posted == ["/providers/Microsoft.ResourceGraph/resources", f"{kept}/config/appsettings/list"]
    assert ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "cloud.azure: Resource Graph resource identifier is not a plain ARM path; resource skipped, "
        "coverage incomplete"
    ]
