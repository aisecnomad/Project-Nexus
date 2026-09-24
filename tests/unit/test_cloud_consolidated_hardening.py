"""Consolidated cloud regression coverage with credential and scope policies retained."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from requests import ConnectionError as RequestsConnectionError

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.common import string_list
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector
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
        "environment": {"OPENAI_API_KEY": "sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h", "SENDGRID_KEY": "SG.opaque-value-1234567890"},
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


def test_gcp_and_oci_scalar_scope_does_not_expand_to_characters(index):
    gcp = GcpConnector(context(index, projects="project-one", locations="us-central1"))
    assert gcp.projects == ["project-one"] and gcp.locations == ["us-central1"]
    gcp._auth = Mock()
    gcp._collect_project = Mock(return_value=[])
    list(gcp.collect())
    gcp._collect_project.assert_called_once_with("project-one")
    oci = OciConnector(context(index, compartments="ocid1.compartment.oc1..abc", regions="us-ashburn-1"))
    assert oci.compartments == ["ocid1.compartment.oc1..abc"]
    assert oci.regions == ["us-ashburn-1"]


@pytest.mark.parametrize("connector,config", [
    (GcpConnector, {"locations": "evil.example/path"}),
    (GcpConnector, {"projects": "project/../../elsewhere"}),
    (OciConnector, {"regions": 42}),
    (AwsConnector, {"regions": ["all", "us-east-1"]}),
])
def test_malformed_cloud_scope_is_rejected_before_authentication(index, connector, config):
    with pytest.raises(ConnectorError):
        connector(context(index, **config))


def test_scope_values_are_deduplicated_without_reordering():
    assert string_list(["us-east-1", "us-west-2", " us-east-1 "], "regions") == ["us-east-1", "us-west-2"]


@pytest.mark.parametrize("failed", [None, [], {"error": {}}, {"properties": []}, RequestsConnectionError()])
def test_azure_invalid_or_failed_appsettings_preserves_later_resources(index, failed):
    connector = AzureConnector(context(index, subscriptions="s1"))
    connector._auth = Mock()
    connector._list = Mock(return_value=[])
    connector.http = Mock()
    rows = [{"id": f"/subscriptions/s1/providers/Microsoft.Web/sites/{name}", "type": "microsoft.web/sites", "name": name}
            for name in ("failed", "good")]
    connector.http.post_json.side_effect = [
        {"data": rows}, failed,
        {"properties": {"OPENAI_API_KEY": "sk-proj-" + "b" * 40, "CUSTOM": "opaque-secret-value"}},
    ]
    records = list(connector.collect())
    assert [r["name"] for r in records if r["_kind"] == "resource"] == ["failed", "good"]
    settings = [r for r in records if r["_kind"] == "appsettings"]
    assert len(settings) == 1 and settings[0]["name"] == "good"
    assert set(sanitize(settings[0])["environment"].values()) == {REDACTED}
    assert connector.ctx.stats.incomplete


def test_oci_function_collection_dumps_withhold_opaque_config_values(index):
    from types import SimpleNamespace

    connector = OciConnector(context(index))
    connector._d = lambda obj: obj
    client = Mock()
    client.list_applications.return_value = SimpleNamespace(data=[{"id": "app", "display_name": "app"}], has_next_page=False)
    client.list_functions.return_value = SimpleNamespace(data=[{"id": "fn", "display_name": "fn"}], has_next_page=False)
    client.get_application.return_value = SimpleNamespace(data={"id": "app", "config": {"INHERITED": "opaque-app-secret"}})
    client.get_function.return_value = SimpleNamespace(data={"id": "fn", "config": {"ARBITRARY": "opaque-function-secret"}})
    record, = connector._collect_functions(client, "r", "c")
    assert "config" not in record
    assert set(sanitize(record)["environment"].values()) == {REDACTED}
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("keys", [None, [], {"error": {}}, {"keys": None}, {"keys": [1]}])
def test_gcp_unknown_key_inventory_is_not_zero_keys(index, keys):
    connector = GcpConnector(context(index, projects="project-one"))
    account = {"name": "projects/project-one/serviceAccounts/crew@project-one.iam.gserviceaccount.com", "email": "crew@project-one.iam.gserviceaccount.com", "displayName": "n8n agent runner"}
    connector._pages = lambda url, *a, **kw: iter([account]) if url.endswith("/serviceAccounts") else iter([])
    connector._get = Mock(return_value=keys)
    connector.http = Mock()
    connector.http.post_json.return_value = {"bindings": []}
    records = list(connector._collect_project("project-one"))
    record = next(r for r in records if r["_kind"] == "service-account")
    assert record["user_managed_keys"] is None and record["key_coverage"] == "unknown"
    finding = connector._h_service_account(record)
    assert finding is not None and finding.metadata["keys"] is None
    assert finding.metadata["key_coverage"] == "unknown"
    assert any("unknown user-managed key inventory" in evidence.description for evidence in finding.evidence)
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("keys,count", [({}, 0), ({"keys": []}, 0), ({"keys": [{"name": "key-one"}]}, 1)])
def test_gcp_observed_key_inventory_keeps_true_count(index, keys, count):
    connector = GcpConnector(context(index))
    account = {"name": "projects/project-one/serviceAccounts/crew@project-one.iam.gserviceaccount.com", "displayName": "CrewAI agent runner"}
    connector._pages = lambda url, *a, **kw: iter([account]) if url.endswith("/serviceAccounts") else iter([])
    connector._get = Mock(return_value=keys)
    connector.http = Mock()
    connector.http.post_json.return_value = {"bindings": []}
    record = next(r for r in connector._collect_project("project-one") if r["_kind"] == "service-account")
    assert record["user_managed_keys"] == count and record["key_coverage"] == "observed"
    assert not connector.ctx.stats.incomplete
