"""Cloud inventories retain observed evidence and bound provider retries."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-09-24")
    return ctx


def failing_pages(first):
    yield first
    raise RuntimeError("synthetic credential-bearing provider diagnostic")


def test_aws_late_page_failure_retains_lambda_inventory(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = failing_pages({"Functions": [{
        "FunctionName": "worker", "FunctionArn": "arn:aws:lambda:us-east-1:123:function:worker",
        "Environment": {"Variables": {"OPENAI_API_KEY": "${SECRET}"}},
    }]})
    client.list_tags.return_value = {"Tags": {}}
    connector._client = Mock(return_value=client)
    records = list(connector._collect_lambda("us-east-1"))
    assert len(records) == 1
    assert connector._h_lambda(records[0]) is not None
    assert ctx.stats.incomplete
    assert "credential-bearing" not in str(ctx.stats.warnings)
    client.list_functions.assert_not_called()


def test_aws_late_iam_page_failure_retains_inline_permission_evidence(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = failing_pages({"RoleDetailList": [{
        "Arn": "arn:aws:iam::123:role/worker", "RoleName": "worker",
        "RolePolicyList": [{"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel"}]}}],
    }]})
    connector._client = Mock(return_value=client)
    records = list(connector._collect_iam())
    assert [record["actions"] for record in records] == [["bedrock:InvokeModel"]]
    assert ctx.stats.incomplete


def test_aws_manual_pagination_detects_repeated_token_without_discarding_results(index):
    ctx = context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    error = type("OperationNotPageableError", (Exception,), {})
    client.get_paginator.side_effect = error()
    client.list_items.side_effect = [
        {"items": [{"id": "one"}], "nextToken": "repeat"},
        {"items": [{"id": "two"}], "nextToken": "repeat"},
    ]
    assert list(connector._paginate(client, "list_items", "items")) == [{"id": "one"}, {"id": "two"}]
    assert client.list_items.call_count == 2
    assert ctx.stats.incomplete


@pytest.mark.parametrize("page", [None, {"items": {}}, {"items": [42, {"id": "valid"}]}])
def test_aws_malformed_pages_are_incomplete_and_preserve_valid_records(index, page):
    ctx = context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = iter([page])
    records = list(connector._paginate(client, "list_items", "items"))
    assert records == ([{"id": "valid"}] if isinstance(page, dict) and isinstance(page["items"], list) else [])
    assert ctx.stats.incomplete


def azure_connector(index, pages):
    ctx = context(index, subscriptions=["sub"])
    connector = AzureConnector(ctx)
    connector._auth = Mock()
    connector._list = Mock(return_value=[])
    connector.http = Mock()
    connector.http.post_json.side_effect = pages
    return connector, ctx


@pytest.mark.parametrize("page", [None, {}, [], {"error": {"code": "Denied"}}, {"data": {}}, {"data": None}])
def test_azure_malformed_resource_graph_response_is_incomplete(index, page):
    connector, ctx = azure_connector(index, [page])
    assert list(connector.collect()) == []
    assert ctx.stats.incomplete


def test_azure_valid_empty_resource_graph_inventory_is_complete(index):
    connector, ctx = azure_connector(index, [{"data": [], "resultTruncated": "false"}])
    assert list(connector.collect()) == []
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("second_page", [None, {"error": {}}, HttpError(429, "https://management.azure.com")])
def test_azure_failed_later_resource_graph_page_retains_observed_resources(index, second_page):
    connector, ctx = azure_connector(index, [
        {"data": [{"id": "/known-resource"}], "$skipToken": "next"}, second_page,
    ])
    assert [record["id"] for record in connector.collect()] == ["/known-resource"]
    assert ctx.stats.incomplete


@pytest.mark.parametrize("token", [False, 1, [], {}])
def test_azure_invalid_resource_graph_cursor_preserves_page_and_marks_incomplete(index, token):
    connector, ctx = azure_connector(index, [{"data": [{"id": "/known-resource"}], "$skipToken": token}])
    assert [record["id"] for record in connector.collect()] == ["/known-resource"]
    assert connector.http.post_json.call_count == 1
    assert ctx.stats.incomplete


def test_gcp_caller_observations_do_not_merge_across_resource_projects(index):
    connector = GcpConnector(context(index))
    records = [{"_kind": "audit-event", "principal": "worker@example.iam.gserviceaccount.com",
                "_project": project, "method": "Predict", "resource": f"projects/{project}/locations/us/endpoints/a"}
               for project in ("project-a", "project-a", "project-b")]
    findings = list(connector.analyze(records))
    assert {finding.account: finding.metadata["events"] for finding in findings} == {"project-a": 2, "project-b": 1}
    assert len({finding.id for finding in findings}) == 2
    assert not connector.ctx.stats.incomplete
