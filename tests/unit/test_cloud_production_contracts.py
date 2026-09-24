"""Cloud API contracts, partial inventory retention, and finite SDK retries."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from requests import Timeout

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.models import ScanStats
from shadowscan.utils.http import HttpError


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-09-24")
    return ctx


def test_cloud_run_discovers_project_locations_before_listing_services(index):
    # Cloud Run v2 services.list explicitly disallows the '-' wildcard.
    # Location enumeration is a v1 endpoint; resource enumeration is v2.
    # https://docs.cloud.google.com/run/docs/reference/rest/v1/projects.locations/list
    # https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/list
    connector = GcpConnector(context(index))
    calls = []

    def get(url, params=None):
        calls.append((url, params))
        if url.endswith("/services") and "serviceusage" in url:
            return {"services": [{"config": {"name": "run.googleapis.com"}}]}
        if url == "https://run.googleapis.com/v1/projects/acme/locations":
            if (params or {}).get("pageToken") == "next":
                return {"locations": [{"locationId": "europe-west2"}]}
            return {"locations": [{"locationId": "us-central1"}], "nextPageToken": "next"}
        if "run.googleapis.com/v2" in url:
            assert "/locations/-/" not in url
            return {"services": [{"name": f"{url.split('/v2/')[1]}/agent", "template": {
                "containers": [{"image": "ollama/ollama:latest"}],
            }}]}
        if url.endswith("/serviceAccounts"):
            return {"accounts": []}
        raise AssertionError(url)

    connector.http = Mock(get_json=get)
    connector.http.post_json.return_value = {}
    records = list(connector._collect_project("acme"))
    services = [r for r in records if r["_kind"] == "cloud-run-service"]
    assert {r["_location"] for r in services} == {"us-central1", "europe-west2"}
    assert len([url for url, _ in calls if "run.googleapis.com/v2" in url]) == 2
    assert len(list(connector.analyze(services))) == 2
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("unreachable", [["europe-west2"], "europe-west2", None, [3]])
def test_gcp_unreachable_locations_make_partial_inventory_incomplete(index, unreachable):
    connector = GcpConnector(context(index))
    connector.http = Mock()
    connector.http.get_json.return_value = {
        "functions": [{"name": "projects/acme/locations/us-central1/functions/agent"}],
        "unreachable": unreachable,
    }
    records = list(connector._pages(
        "https://cloudfunctions.googleapis.com/v2/projects/acme/locations/-/functions", "functions",
    ))
    assert len(records) == 1
    assert connector.ctx.stats.incomplete


def test_gcp_valid_empty_unreachable_is_complete(index):
    connector = GcpConnector(context(index))
    connector.http = Mock()
    connector.http.get_json.return_value = {"functions": [], "unreachable": []}
    assert list(connector._pages("https://cloudfunctions.googleapis.com/v2/projects/acme/locations/-/functions", "functions")) == []
    assert not connector.ctx.stats.incomplete


def test_cloud_run_bad_location_does_not_erase_valid_neighbor(index):
    connector = GcpConnector(context(index))
    connector.http = Mock()
    connector.http.post_json.return_value = {}

    def get(url, params=None):
        if "serviceusage" in url:
            return {"services": [{"config": {"name": "run.googleapis.com"}}]}
        if url.endswith("/locations"):
            return {"locations": [{"locationId": "../../projects/other"}, {"name": "missing-id"},
                                   {"locationId": "us-central1"}, {"locationId": "us-central1"}]}
        if "run.googleapis.com/v2" in url:
            assert url == "https://run.googleapis.com/v2/projects/acme/locations/us-central1/services"
            return {"services": [{"name": "projects/acme/locations/us-central1/services/worker"}]}
        return {}

    connector.http.get_json.side_effect = get
    services = [r for r in connector._collect_project("acme") if r["_kind"] == "cloud-run-service"]
    assert len(services) == 1
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("late", [
    HttpError(403, "https://management.azure.com/next"),
    HttpError(429, "https://management.azure.com/next"),
    Timeout("credential-bearing diagnostic"), None, {"error": {}}, {"value": {}},
])
def test_azure_arm_late_failure_retains_prior_inventory(index, late):
    connector = AzureConnector(context(index))
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"value": [{"id": "observed"}], "nextLink": "https://management.azure.com/next"}, late,
    ]
    assert connector._list("/resources", "v1", allow_partial=True) == [{"id": "observed"}]
    assert connector.ctx.stats.incomplete
    assert "credential-bearing" not in str(connector.ctx.stats.warnings)


@pytest.mark.parametrize("continuation", ["/resources", 7])
def test_azure_arm_invalid_continuation_retains_prior_inventory(index, continuation):
    connector = AzureConnector(context(index))
    connector.http = Mock()
    connector.http.get_json.return_value = {"value": [{"id": "observed"}], "nextLink": continuation}
    assert connector._list("/resources", "v1", allow_partial=True) == [{"id": "observed"}]
    assert connector.http.get_json.call_count == 1
    assert connector.ctx.stats.incomplete


def test_azure_arm_bad_member_retains_valid_neighbors(index):
    connector = AzureConnector(context(index))
    connector.http = Mock()
    connector.http.get_json.return_value = {"value": [None, {"id": "observed"}, 3]}
    assert connector._list("/resources", "v1", allow_partial=True) == [{"id": "observed"}]
    assert connector.ctx.stats.incomplete


def test_azure_collect_retains_deployments_and_continues_after_page_failure(index):
    connector = AzureConnector(context(index, subscriptions=["sub"]))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.post_json.return_value = {"data": [
        {"id": account, "type": "microsoft.cognitiveservices/accounts", "kind": "OpenAI"}
        for account in ("/first-account", "/second-account")
    ]}

    def get(path, **kwargs):
        if path == "/first-account/deployments":
            return {"value": [{"id": "/first-account/deployments/model"}], "nextLink": "/failed-next"}
        if path == "/failed-next":
            raise HttpError(429, "https://management.azure.com/failed-next")
        if path == "/second-account/deployments":
            return {"value": [{"id": "/second-account/deployments/model"}]}
        return {"value": []}

    connector.http.get_json.side_effect = get
    records = list(connector.collect())
    assert {r["_account"] for r in records if r["_kind"] == "deployment"} == {"/first-account", "/second-account"}
    assert connector.ctx.stats.incomplete


def test_azure_partial_diagnostics_remain_unknown(index):
    connector = AzureConnector(context(index, subscriptions=["sub"]))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.post_json.return_value = {"data": [{
        "id": "/account", "type": "microsoft.cognitiveservices/accounts", "kind": "OpenAI",
    }]}

    def get(path, **kwargs):
        if path.endswith("/diagnosticSettings"):
            return {"value": [{"id": "setting", "properties": {"logs": []}}], "nextLink": "/diagnostic-next"}
        if path == "/diagnostic-next":
            raise HttpError(403, "https://management.azure.com/diagnostic-next")
        return {"value": []}

    connector.http.get_json.side_effect = get
    records = list(connector.collect())
    diagnostics = next(r for r in records if r["_kind"] == "diagnostics")
    assert diagnostics["coverage"] == "unknown"
    finding = next(f for f in connector.analyze(records) if f.resource == "/account")
    assert finding.metadata["diagnostic_logging_status"] == "unknown"
    assert "no-diagnostic-logging" not in finding.tags
    assert connector.ctx.stats.incomplete


def test_aws_sdk_clients_bound_authentication_and_inventory_requests(index, monkeypatch):
    pytest.importorskip("botocore")
    sessions = [Mock(), Mock()]
    sessions[0].client.return_value.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "test", "SecretAccessKey": "test", "SessionToken": "test",
    }}
    sessions[1].client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=Mock(side_effect=sessions)))
    connector = AwsConnector(context(index, role_arn="arn:aws:iam::123456789012:role/audit"))
    connector._client("lambda", "us-east-1")
    calls = [*sessions[0].client.call_args_list, *sessions[1].client.call_args_list]
    assert [call.args[0] for call in calls] == ["sts", "sts", "lambda"]
    for call in calls:
        config = call.kwargs["config"]
        assert (config.connect_timeout, config.read_timeout) == (10, 30)
        assert config.retries == {"mode": "standard", "total_max_attempts": 3}


def test_oci_sdk_client_has_finite_transport_and_retry_bounds(index):
    oci = pytest.importorskip("oci")
    connector = OciConnector(context(index))
    connector._config = {"region": "us-phoenix-1"}
    connector._signer = Mock()
    factory = Mock()
    connector._client(factory, "us-ashburn-1")
    kwargs = factory.call_args.kwargs
    assert factory.call_args.args == ({"region": "us-ashburn-1"},)
    assert kwargs["signer"] is connector._signer
    assert kwargs["timeout"] == (10, 30)
    strategy = kwargs["retry_strategy"]
    # Exercise the real SDK strategy with sleeping replaced, no network calls.
    strategy.do_sleep = Mock()
    request = Mock(side_effect=oci.exceptions.ServiceError(503, "Unavailable", {}, "test"))
    request.__name__ = "list_resources"
    with pytest.raises(oci.exceptions.ServiceError):
        strategy.make_retrying_call(request)
    assert request.call_count == 3
