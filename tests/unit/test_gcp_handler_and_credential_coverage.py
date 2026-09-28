"""Coverage for previously-untested GCP handlers, Cloud Audit Logs pagination
edge cases, and instance-credential transport security (redirect refusal,
timeout bound). These paths were below the connector coverage floor; the
uncovered lines included the Cloud Function plaintext-secret scanner and the
private-address bypass path for instance metadata credentials."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests as requests_lib

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import Kind, ScanStats
from shadowscan.utils.http import HttpError

IMDS_URL = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"


def _context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


# ------------------------------------------------------------- analyze()


def test_gcp_cloud_function_handler_flags_llm_secret_env(index):
    connector = GcpConnector(_context(index))
    rec = {
        "_kind": "cloud-function",
        "name": "projects/demo/locations/us-central1/functions/summarizer",
        "serviceConfig": {
            "environmentVariables": {"OPENAI_API_KEY": "configured"},
            "uri": "https://summarizer-abc.a.run.app",
            "serviceAccountEmail": "summarizer@demo.iam.gserviceaccount.com",
        },
        "updateTime": "2026-01-01T00:00:00Z",
    }
    finding = connector._h_cloud_function(rec)
    assert finding is not None
    assert finding.kind == Kind.CLOUD_RESOURCE
    assert finding.resource_type == "cloud-function"
    assert "provider.openai" in finding.model_providers
    assert finding.metadata["service_account"] == "summarizer@demo.iam.gserviceaccount.com"


def test_gcp_cloud_function_handler_ignores_functions_without_ai_signal(index):
    connector = GcpConnector(_context(index))
    rec = {
        "_kind": "cloud-function",
        "name": "projects/demo/locations/us-central1/functions/resize-image",
        "serviceConfig": {"environmentVariables": {"BUCKET": "images"}},
    }
    assert connector._h_cloud_function(rec) is None


def test_gcp_vertex_endpoint_handler_flags_deployed_model(index):
    connector = GcpConnector(_context(index))
    rec = {
        "_kind": "vertex-endpoint",
        "name": "projects/demo/locations/us-central1/endpoints/123",
        "displayName": "chatbot-endpoint",
        "deployedModels": [
            {"model": "projects/demo/locations/us-central1/models/456", "displayName": "gemini-served-model"}
        ],
    }
    finding = connector._h_vertex_endpoint(rec)
    assert finding is not None
    assert finding.resource_type == "vertex-endpoint"
    assert "provider.google-vertex-ai" in finding.model_providers
    assert finding.models == ["projects/demo/locations/us-central1/models/456"]


def test_gcp_vertex_endpoint_handler_skips_endpoint_without_deployed_models(index):
    connector = GcpConnector(_context(index))
    rec = {
        "_kind": "vertex-endpoint",
        "name": "projects/demo/locations/us-central1/endpoints/empty",
        "deployedModels": [],
    }
    assert connector._h_vertex_endpoint(rec) is None


def test_gcp_discovery_engine_handler_flags_generative_chat_engine_as_agent(index):
    connector = GcpConnector(_context(index))
    rec = {
        "_kind": "discovery-engine",
        "name": "projects/demo/locations/global/collections/default_collection/engines/support-bot",
        "displayName": "support-bot",
        "solutionType": "SOLUTION_TYPE_GENERATIVE_CHAT",
        "industryVertical": "GENERIC",
        "dataStoreIds": ["support-docs"],
    }
    finding = connector._h_discovery_engine(rec)
    assert finding.kind == Kind.AGENT
    assert "rag" in finding.capabilities
    assert finding.metadata["solution_type"] == "SOLUTION_TYPE_GENERATIVE_CHAT"


def test_gcp_discovery_engine_handler_non_chat_solution_is_cloud_resource(index):
    connector = GcpConnector(_context(index))
    rec = {
        "_kind": "discovery-engine",
        "name": "projects/demo/locations/global/collections/default_collection/engines/search",
        "displayName": "search",
        "solutionType": "SOLUTION_TYPE_SEARCH",
    }
    finding = connector._h_discovery_engine(rec)
    assert finding.kind == Kind.CLOUD_RESOURCE


# ---------------------------------------------------------- _collect_audit


def test_gcp_collect_audit_terminates_cleanly_on_empty_next_page_token(index):
    connector = GcpConnector(_context(index, audit_days=1, max_pages=10))
    connector.http = Mock()
    connector.http.post_json.return_value = {
        "entries": [
            {
                "protoPayload": {
                    "authenticationInfo": {"principalEmail": "agent@example.com"},
                    "methodName": "GenerateContent",
                }
            }
        ],
        "nextPageToken": "",
    }
    records = list(connector._collect_audit("demo"))
    assert len(records) == 1
    assert connector.http.post_json.call_count == 1
    assert not connector.ctx.stats.incomplete
    assert not connector.ctx.stats.warnings


def test_gcp_collect_audit_warns_and_stops_on_repeated_pagination_token(index):
    connector = GcpConnector(_context(index, audit_days=1, max_pages=10))
    connector.http = Mock()
    connector.http.post_json.return_value = {
        "entries": [
            {
                "protoPayload": {
                    "authenticationInfo": {"principalEmail": "agent@example.com"},
                    "methodName": "Predict",
                }
            }
        ],
        "nextPageToken": "stuck-token",
    }
    records = list(connector._collect_audit("demo"))
    assert len(records) == 2
    assert connector.http.post_json.call_count == 2
    assert any(
        "invalid or repeated audit pagination token" in warning for warning in connector.ctx.stats.warnings
    )


def test_gcp_collect_audit_invalid_response_shape_is_incomplete(index):
    connector = GcpConnector(_context(index, audit_days=1))
    connector.http = Mock()
    connector.http.post_json.return_value = {"entries": "not-a-list"}
    records = list(connector._collect_audit("demo"))
    assert records == []
    assert any("invalid audit log response" in warning for warning in connector.ctx.stats.warnings)


def test_gcp_collect_audit_invalid_entry_is_skipped_not_fatal(index):
    connector = GcpConnector(_context(index, audit_days=1))
    connector.http = Mock()
    connector.http.post_json.return_value = {
        "entries": [
            {"protoPayload": "not-a-dict"},
            {
                "protoPayload": {
                    "authenticationInfo": {"principalEmail": "agent@example.com"},
                    "methodName": "Predict",
                }
            },
        ],
        "nextPageToken": "",
    }
    records = list(connector._collect_audit("demo"))
    assert len(records) == 1
    assert any("invalid audit log entry" in warning for warning in connector.ctx.stats.warnings)


@pytest.mark.parametrize(
    "failure", [HttpError(429, "https://logging.googleapis.com"), requests_lib.ConnectionError("failed")]
)
def test_gcp_collect_audit_transport_failure_is_incomplete(index, failure):
    connector = GcpConnector(_context(index, audit_days=1))
    connector.http = Mock()
    connector.http.post_json.side_effect = failure
    records = list(connector._collect_audit("demo"))
    assert records == []
    assert any("audit logs not readable" in warning for warning in connector.ctx.stats.warnings)


# ------------------------------------------------- instance-credential transport


def _fake_default(monkeypatch, google_auth, refresh):
    monkeypatch.setattr(
        google_auth,
        "default",
        Mock(return_value=(SimpleNamespace(token=None, refresh=refresh), "demo-project")),
    )


def test_gcp_instance_credential_transport_refuses_metadata_redirect(index, monkeypatch):
    google_auth = pytest.importorskip("google.auth")
    pytest.importorskip("google.auth.transport.requests")
    from shadowscan.connectors.cloud import gcp as gcp_module

    calls: list[tuple[str, str, dict]] = []

    def fake_request(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        resp = requests_lib.Response()
        resp.status_code = 302
        resp._content_consumed = True
        return resp

    monkeypatch.setattr(gcp_module.Session, "request", fake_request)
    _fake_default(
        monkeypatch,
        google_auth,
        lambda request: request(method="GET", url=IMDS_URL, headers={"Metadata-Flavor": "Google"}),
    )

    connector = GcpConnector(_context(index, allow_instance_credentials=True))
    with pytest.raises(ValueError, match="redirects are refused"):
        connector._auth()
    assert calls and calls[0][1] == IMDS_URL
    assert calls[0][2]["allow_redirects"] is False
    assert calls[0][2]["stream"] is True


def test_gcp_instance_credential_transport_bounds_timeout_to_thirty_seconds(index, monkeypatch):
    google_auth = pytest.importorskip("google.auth")
    pytest.importorskip("google.auth.transport.requests")
    from shadowscan.connectors.cloud import gcp as gcp_module

    calls: list[dict] = []

    def fake_request(self, method, url, **kwargs):
        calls.append(kwargs)
        resp = requests_lib.Response()
        resp.status_code = 200
        resp._content = b"{}"
        resp._content_consumed = True
        return resp

    monkeypatch.setattr(gcp_module.Session, "request", fake_request)
    _fake_default(
        monkeypatch,
        google_auth,
        lambda request: request(
            method="GET",
            url=IMDS_URL,
            headers={"Metadata-Flavor": "Google"},
            timeout=9999,
        ),
    )

    connector = GcpConnector(_context(index, allow_instance_credentials=True))
    connector._auth()
    assert calls and calls[0]["timeout"] == 30.0
