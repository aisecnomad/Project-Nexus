"""Live cloud collection must honor requested scope before expensive reads."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import ScanStats

ACCOUNT = "123456789012"


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-09-24")
    return ctx


def test_lambda_limit_stops_lazy_listing_and_limits_detail_reads(index):
    ctx = context(index, max_lambda=2)
    connector = AwsConnector(ctx)
    client = Mock()
    client.list_tags.return_value = {"Tags": {}}
    connector._client = Mock(return_value=client)
    fetched = []

    def pages(**kwargs):
        for n in range(10):
            fetched.append(n)
            yield {"Functions": [{"FunctionName": f"worker-{n}", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker-{n}"}]}

    client.get_paginator.return_value.paginate.side_effect = pages
    assert len(list(connector._collect_lambda("us-east-1"))) == 2
    # One extra record determines truncation, without reading the full inventory.
    assert fetched == [0, 1, 2]
    assert client.list_tags.call_count == 2
    assert ctx.stats.incomplete
    assert any("max_lambda" in warning for warning in ctx.stats.warnings)


def test_gcp_project_limit_stops_discovery_before_exhausting_all_pages(index):
    ctx = context(index, max_projects=2)
    connector = GcpConnector(ctx)
    connector._auth = Mock()
    connector._collect_project = Mock(return_value=[])
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"projects": [{"projectId": f"project-{n}"}], "nextPageToken": f"token-{n}"} for n in range(10)
    ]
    assert list(connector.collect()) == []
    assert [call.args[0] for call in connector._collect_project.call_args_list] == ["project-0", "project-1"]
    assert connector.http.get_json.call_count == 3
    assert ctx.stats.incomplete
    assert any("max_projects" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("cls,setting", [(AwsConnector, "max_lambda"), (GcpConnector, "max_projects")])
@pytest.mark.parametrize("limit", [0, -1])
def test_nonpositive_resource_limit_is_rejected_before_collection(index, cls, setting, limit):
    with pytest.raises(ConnectorError, match=f"{setting} must be positive"):
        cls(context(index, **{setting: limit}))


@pytest.mark.parametrize("continuation", [{}, {"NextMarker": "next"}])
def test_aws_sdk_page_limit_does_not_request_an_extra_page(index, monkeypatch, continuation):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    client = boto3.client("lambda", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
    client._make_api_call = Mock(wraps=client._make_api_call)
    ctx = context(index)
    connector = AwsConnector(ctx)
    monkeypatch.setattr("shadowscan.connectors.cloud.aws.MAX_LIST_PAGES", 1)
    with Stubber(client) as stubber:
        stubber.add_response("list_functions", {"Functions": [{"FunctionName": "worker"}], **continuation}, {})
        assert list(connector._paginate(client, "list_functions", "Functions")) == [{"FunctionName": "worker"}]
    assert client._make_api_call.call_count == 1
    assert ctx.stats.incomplete is bool(continuation)


@pytest.mark.parametrize("configured,authenticated", [(ACCOUNT, ACCOUNT), (None, ACCOUNT)])
def test_aws_live_account_is_verified_even_when_configured(index, monkeypatch, configured, authenticated):
    pytest.importorskip("botocore")
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": authenticated}
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=Mock(return_value=session)))
    connector = AwsConnector(context(index, account_id=configured))
    assert connector._session_() is session
    session.client.return_value.get_caller_identity.assert_called_once_with()
    assert connector.account == authenticated


def test_aws_wrong_account_fails_before_any_inventory_record(index, monkeypatch):
    pytest.importorskip("botocore")
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "999999999999"}
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=Mock(return_value=session)))
    connector = AwsConnector(context(index, account_id=ACCOUNT))
    with pytest.raises(ConnectorError, match="account_id does not match"):
        next(iter(connector.collect()))
    assert connector._session is None
    assert [call.args[0] for call in session.client.call_args_list] == ["sts"]


@pytest.mark.parametrize("account", [None, "", "wrong", "１２３４５６７８９０１２", 123456789012])
def test_aws_invalid_sts_identity_fails_before_inventory(index, monkeypatch, account):
    pytest.importorskip("botocore")
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": account}
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=Mock(return_value=session)))
    connector = AwsConnector(context(index))
    with pytest.raises(ConnectorError, match="cannot authenticate"):
        next(iter(connector.collect()))
    assert connector._session is None


def test_aws_offline_account_label_does_not_require_live_authentication(index, tmp_path):
    export = tmp_path / "aws.jsonl"
    export.write_text(json.dumps({"_kind": "lambda", "FunctionName": "worker", "Environment": {"OPENAI_API_KEY": "${SECRET}"}}) + "\n")
    connector = AwsConnector(context(index, account_id="offline-account", input=str(export)))
    connector._session_ = Mock(side_effect=AssertionError("offline scans must not authenticate"))
    findings = connector.run()
    assert len(findings) == 1
    assert findings[0].account == "offline-account"
    connector._session_.assert_not_called()
