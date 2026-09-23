"""Provider contract regressions for the September 2026 security review."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
import requests

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.models import ScanStats

ENDPOINT = "https://example.services.ai.azure.com/api/projects/test"
PROJECT = {"id": "/project", "properties": {"endpoints": {"AI Foundry API": ENDPOINT}}}


def context(index):
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
        return response

    monkeypatch.setattr(requests.Session, "request", request)
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: [])
    return calls


def test_foundry_classic_route_version_and_cursor_contract(index, monkeypatch):
    # Official azure-ai-agents_1.0.0 build_agents_list_agents_request:
    # GET /assistants, api-version=v1, limit and after query parameters.
    calls = foundry_http(monkeypatch, [
        {"object": "list", "data": [{"id": "asst_first"}], "has_more": True, "last_id": "asst_first"},
        {"object": "list", "data": [{"id": "asst_second"}], "has_more": False, "last_id": "asst_second"},
    ])
    ctx = context(index)
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


@pytest.mark.parametrize("page", [
    None, {}, [], {"error": {"code": "denied"}}, {"data": {}, "has_more": False},
    {"data": [], "has_more": "false"}, {"data": []},
    {"data": [], "has_more": True, "last_id": "a"},
    {"data": [{"id": "a"}], "has_more": True, "last_id": []},
    {"data": [{"id": "a"}], "has_more": True, "last_id": "other"},
])
def test_foundry_malformed_envelopes_are_incomplete(index, monkeypatch, page):
    foundry_http(monkeypatch, [page])
    ctx = context(index)
    list(AzureConnector(ctx)._collect_agents({}, PROJECT))
    assert ctx.stats.incomplete


def test_foundry_valid_empty_inventory_is_complete(index, monkeypatch):
    foundry_http(monkeypatch, [{"object": "list", "data": [], "has_more": False, "last_id": None}])
    ctx = context(index)
    assert list(AzureConnector(ctx)._collect_agents({}, PROJECT)) == []
    assert not ctx.stats.incomplete


def test_foundry_malformed_record_preserves_neighbor(index, monkeypatch):
    foundry_http(monkeypatch, [{"data": [{"id": "a"}, {"name": "missing id"}, 4], "has_more": False}])
    ctx = context(index)
    assert [r["id"] for r in AzureConnector(ctx)._collect_agents({}, PROJECT)] == ["a"]
    assert ctx.stats.incomplete


def test_foundry_repeated_cursor_stops_with_partial_records(index, monkeypatch):
    page = {"data": [{"id": "a"}], "has_more": True, "last_id": "a"}
    calls = foundry_http(monkeypatch, [page, page])
    ctx = context(index)
    assert list(AzureConnector(ctx)._collect_agents({}, PROJECT))
    assert len(calls) == 2
    assert ctx.stats.incomplete


def oci_functions_client():
    oci = pytest.importorskip("oci")
    models = oci.functions.models
    client = Mock(spec=oci.functions.FunctionsManagementClient)

    def response(data):
        return oci.response.Response(status=200, headers={}, data=data, request=None)

    image_kw = (
        {"source_details": models.ContainerImageFunctionSourceDetails(image="ollama/ollama:latest")}
        if hasattr(models, "ContainerImageFunctionSourceDetails") else {"image": "ollama/ollama:latest"}
    )
    application = models.ApplicationSummary(id="app1", display_name="workflows")
    function = models.FunctionSummary(id="fn1", display_name="worker", application_id="app1", **image_kw)
    # Real OCI summary models must never accidentally grow fictional config fields.
    assert "config" not in application.swagger_types
    assert "config" not in function.swagger_types
    client.list_applications.return_value = response([application])
    client.list_functions.return_value = response([function])
    client.get_application.return_value = response(models.Application(id="app1", config={
        "OPENAI_API_KEY": "synthetic-application-secret", "SHARED": "application", "APP_ONLY": "present",
    }))
    client.get_function.return_value = response(models.Function(id="fn1", config={"SHARED": "function"}))
    return client, response


def test_oci_reads_real_detail_models_inherits_config_and_preserves_image(index):
    client, _ = oci_functions_client()
    ctx = context(index)
    connector = OciConnector(ctx)
    records = list(connector._collect_functions(client, "us-ashburn-1", "comp"))
    assert len(records) == 1
    record = records[0]
    client.get_application.assert_called_once_with("app1")
    client.get_function.assert_called_once_with("fn1")
    assert record["config"]["SHARED"] == "function"
    assert record["config"]["APP_ONLY"] == "present"
    finding = connector._h_function(record)
    assert {"provider.openai", "provider.ollama"} <= set(finding.model_providers)
    assert finding.metadata["image"] == "ollama/ollama:latest"
    assert "OPENAI_API_KEY" in finding.metadata["config_keys"]
    assert "synthetic-application-secret" not in json.dumps(finding.to_dict())
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("kind", ["application", "function"])
def test_oci_denied_detail_preserves_known_evidence_and_marks_incomplete(index, kind):
    client, _ = oci_functions_client()
    getattr(client, f"get_{kind}").side_effect = RuntimeError("do not reflect credential-bearing errors")
    ctx = context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    finding = connector._h_function(record)
    assert "provider.ollama" in finding.model_providers
    assert finding.metadata["config_coverage"][kind] == "unknown"
    assert ctx.stats.incomplete
    assert "credential-bearing" not in str(ctx.stats.warnings)


@pytest.mark.parametrize("detail", [None, [], {}, {"id": "wrong", "config": {}},
    {"id": "fn1"}, {"id": "fn1", "config": []}, {"id": "fn1", "config": {"BAD": 12}}])
def test_oci_invalid_function_detail_preserves_summary(index, detail):
    client, response = oci_functions_client()
    client.get_function.return_value = response(detail)
    ctx = context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    assert record["id"] == "fn1"
    assert connector._h_function(record).metadata["image"] == "ollama/ollama:latest"
    assert ctx.stats.incomplete


def test_oci_legacy_image_shape_remains_supported(index):
    client, response = oci_functions_client()
    client.list_functions.return_value = response([{"id": "fn1", "display_name": "worker", "image": "ollama/ollama:latest"}])
    ctx = context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    assert connector._h_function(record).metadata["image"] == "ollama/ollama:latest"
    assert not ctx.stats.incomplete


def test_oci_non_ai_summary_is_detected_from_function_detail(index):
    client, response = oci_functions_client()
    client.list_functions.return_value = response([{"id": "fn1", "display_name": "worker", "image": "registry.example/worker:v1"}])
    client.get_application.return_value = response({"id": "app1", "config": {}})
    client.get_function.return_value = response({"id": "fn1", "config": {"ANTHROPIC_API_KEY": "synthetic-function-secret"}})
    ctx = context(index)
    connector = OciConnector(ctx)
    record = list(connector._collect_functions(client, "region", "comp"))[0]
    assert "provider.anthropic" in connector._h_function(record).model_providers
    assert not ctx.stats.incomplete
