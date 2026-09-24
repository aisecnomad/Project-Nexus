"""Provider page failures cannot erase observed cloud resources or mix tenants."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


def _context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-09-24")
    return ctx


def _late_failure(page):
    yield page
    raise RuntimeError("provider diagnostic may contain credentials")


def test_aws_late_lambda_page_failure_keeps_first_page(index):
    ctx = _context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = _late_failure({
        "Functions": [{"FunctionName": "observed", "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:observed"}],
    })
    client.list_tags.return_value = {"Tags": {}}
    connector._client = Mock(return_value=client)
    records = list(connector._collect_lambda("us-east-1"))
    assert [r["FunctionName"] for r in records] == ["observed"]
    assert ctx.stats.incomplete
    assert "credentials" not in str(ctx.stats.warnings)
    client.list_functions.assert_not_called()


def test_aws_late_iam_page_failure_keeps_permission_evidence(index):
    ctx = _context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = _late_failure({
        "RoleDetailList": [{
            "Arn": "arn:aws:iam::123456789012:role/observed", "RoleName": "observed",
            "RolePolicyList": [{"PolicyDocument": {"Statement": [{
                "Effect": "Allow", "Action": "bedrock:InvokeModel",
            }]}}],
        }],
    })
    connector._client = Mock(return_value=client)
    records = list(connector._collect_iam())
    assert [r["actions"] for r in records] == [["bedrock:InvokeModel"]]
    assert ctx.stats.incomplete


def test_aws_repeated_manual_cursor_keeps_pages_and_marks_incomplete(index):
    ctx = _context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    not_pageable = type("OperationNotPageableError", (Exception,), {})
    client.get_paginator.side_effect = not_pageable()
    client.list_items.side_effect = [
        {"items": [{"id": "first"}], "nextToken": "again"},
        {"items": [{"id": "second"}], "nextToken": "again"},
    ]
    assert list(connector._paginate(client, "list_items", "items")) == [
        {"id": "first"}, {"id": "second"},
    ]
    assert ctx.stats.incomplete
    assert client.list_items.call_count == 2


@pytest.mark.parametrize("invalid_page", [{"message": "denied"}, {"error": {}, "items": []}])
def test_aws_missing_or_failed_collection_page_is_incomplete(index, invalid_page):
    ctx = _context(index)
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = iter([invalid_page])
    assert list(connector._paginate(client, "list_items", "items")) == []
    assert ctx.stats.incomplete
    assert any("missing or failed" in warning for warning in ctx.stats.warnings)


def test_gcp_shared_principal_is_attributed_per_resource_project(index):
    connector = GcpConnector(_context(index))
    records = [{
        "_kind": "audit-event", "principal": "agent@example.iam.gserviceaccount.com",
        "_project": project, "method": "Predict",
        "resource": f"projects/{project}/locations/us/endpoints/model",
    } for project in ("project-a", "project-a", "project-b")]
    findings = list(connector.analyze(records))
    assert {f.account: f.metadata["events"] for f in findings} == {
        "project-a": 2, "project-b": 1,
    }
    assert len({f.id for f in findings}) == 2
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("later", [HttpError(429, "https://management.azure.com"), None, {"error": {}}])
def test_azure_late_resource_graph_failure_keeps_first_page(index, later):
    ctx = _context(index, subscriptions=["sub"])
    connector = AzureConnector(ctx)
    connector._auth = Mock()
    connector._list = Mock(return_value=[])
    connector.http = Mock()
    connector.http.post_json.side_effect = [
        {"data": [{"id": "/subscriptions/sub/providers/Microsoft.KeyVault/vaults/observed", "type": "microsoft.keyvault/vaults"}], "$skipToken": "next"},
        later,
    ]
    records = list(connector.collect())
    assert [r["id"] for r in records] == ["/subscriptions/sub/providers/Microsoft.KeyVault/vaults/observed"]
    assert ctx.stats.incomplete


@pytest.mark.parametrize("cursor", [False, 1, [], {}])
def test_azure_invalid_cursor_keeps_first_page_and_stops(index, cursor):
    ctx = _context(index, subscriptions=["sub"])
    connector = AzureConnector(ctx)
    connector._auth = Mock()
    connector._list = Mock(return_value=[])
    connector.http = Mock()
    connector.http.post_json.return_value = {
        "data": [{"id": "/known-resource"}], "$skipToken": cursor,
    }
    assert [r["id"] for r in connector.collect()] == ["/known-resource"]
    assert connector.http.post_json.call_count == 1
    assert ctx.stats.incomplete
