"""Google Cloud collection and analysis contracts, exercised offline with fake transports."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest
import requests

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud import gcp as gcp_module
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import Kind, ScanStats
from shadowscan.utils.http import HttpError

PROJECT = "acme-search"
SA_NAME = f"projects/{PROJECT}/serviceAccounts/agent-runner@{PROJECT}.iam.gserviceaccount.com"


def context(index: Any, **config: Any) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.gcp", started_at="2026-09-27")
    return ctx


class FakeGoogle:
    """Route REST calls by URL; every request is recorded for assertions."""

    def __init__(self, routes: dict[str, Any], posts: dict[str, Any] | None = None) -> None:
        self.routes = routes
        self.posts = posts or {}
        self.gets: list[tuple[str, dict[str, Any]]] = []
        self.bodies: list[tuple[str, dict[str, Any]]] = []

    @staticmethod
    def _answer(table: dict[str, Any], url: str) -> Any:
        for suffix, answer in table.items():
            if url.endswith(suffix):
                if isinstance(answer, Exception):
                    raise answer
                return answer(url) if callable(answer) else answer
        return {}

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        self.gets.append((url, dict(params or {})))
        return self._answer(self.routes, url)

    def post_json(self, url: str, json: dict[str, Any] | None = None) -> Any:
        self.bodies.append((url, dict(json or {})))
        return self._answer(self.posts, url)


def enabled(*services: str) -> dict[str, Any]:
    return {"services": [{"config": {"name": name}} for name in services]}


@pytest.mark.parametrize(
    "service,items_key,kind,regional",
    [
        ("dialogflow.googleapis.com", "agents", "dialogflow-agent", True),
        ("discoveryengine.googleapis.com", "engines", "discovery-engine", True),
        ("cloudfunctions.googleapis.com", "functions", "cloud-function", False),
        ("apikeys.googleapis.com", "keys", "api-key", False),
        ("aiplatform.googleapis.com", "reasoningEngines", "reasoning-engine", True),
        ("aiplatform.googleapis.com", "endpoints", "vertex-endpoint", True),
    ],
)
def test_gcp_live_records_cannot_override_collected_scope(
    index, monkeypatch, service, items_key, kind, regional
):
    scanner = GcpConnector(context(index, locations=["us-central1"]))

    def pages(url, key, **params):
        if key == "services":
            return iter(enabled(service)["services"])
        if key == items_key:
            return iter(
                [
                    {
                        "name": "upstream-resource",
                        "_kind": "project",
                        "_project": "other-project",
                        "_location": "other-region",
                    }
                ]
            )
        return iter([])

    monkeypatch.setattr(scanner, "_pages", pages)
    monkeypatch.setattr(scanner, "_collect_iam_policy", lambda project: iter([]))
    records = [
        record for record in scanner._collect_project(PROJECT) if record.get("name") == "upstream-resource"
    ]
    assert records
    assert all(record["_kind"] == kind and record["_project"] == PROJECT for record in records)
    if regional:
        assert all(record["_location"] != "other-region" for record in records)


@pytest.mark.parametrize(
    "invalid_id",
    [None, 7, "", ".", "..", "../other", "project?quotaUser=other", "project/locations/other"],
)
def test_gcp_discovered_projects_reject_unsafe_scope_and_preserve_neighbours(index, monkeypatch, invalid_id):
    scanner = GcpConnector(context(index))
    monkeypatch.setattr(scanner, "_auth", lambda: None)
    monkeypatch.setattr(
        scanner,
        "_pages",
        lambda *args, **kwargs: iter([{"projectId": invalid_id}, {"projectId": PROJECT}]),
    )
    collected = []

    def project_records(project):
        collected.append(project)
        yield {"_kind": "project", "project": project, "ai_services": []}

    monkeypatch.setattr(scanner, "_collect_project", project_records)
    records = list(scanner.collect())
    assert collected == [PROJECT] and records[0]["project"] == PROJECT
    assert scanner.ctx.stats.incomplete
    assert "invalid discovered project identifier" in scanner.ctx.stats.warnings[0]


def _by_kind(findings: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for finding in findings:
        grouped.setdefault(finding.resource_type, []).append(finding)
    return grouped


# ------------------------------------------------------------------ offline
def test_gcp_offline_export_covers_every_handler_kind(run_connector, fixtures):
    findings, ctx = run_connector("cloud.gcp", input=str(fixtures / "cloud" / "gcp_extended_records.jsonl"))
    assert not ctx.stats.incomplete and not ctx.stats.warnings
    grouped = _by_kind(findings)

    (endpoint,) = grouped["vertex-endpoint"]  # the endpoint without deployed models is not an AI resource
    assert endpoint.resource.endswith("/endpoints/42") and endpoint.region == "us-central1"
    assert endpoint.models == [
        "projects/acme-search/locations/us-central1/models/llama-3-8b-instruct",
        "publishers/google/models/gemini-1.5-pro",
    ]
    assert "provider.google-vertex-ai" in endpoint.model_providers

    engines = {f.metadata["solution_type"]: f for f in grouped["discovery-engine"]}
    assert engines["SOLUTION_TYPE_CHAT"].kind == Kind.AGENT
    assert engines["SOLUTION_TYPE_CHAT"].metadata["data_stores"] == ["kb-docs", "kb-faq"]
    assert engines["SOLUTION_TYPE_SEARCH"].kind == Kind.CLOUD_RESOURCE
    assert all("rag" in f.capabilities for f in engines.values())

    (function,) = grouped["cloud-function"]  # resize-images has no AI signal
    assert function.title == "Cloud Function: summarise-tickets" and function.region == "europe-west1"
    assert "provider.anthropic" in function.model_providers and "autonomous" in function.capabilities
    assert function.metadata["trigger"] == "google.cloud.pubsub.topic.v1.messagePublished"
    assert function.metadata["service_account"] == "summariser@acme-search.iam.gserviceaccount.com"
    assert "cloud-run-service" not in grouped  # an nginx service carries no AI signal

    keys = {(f.metadata["targets"] or ["unrestricted"])[0]: f for f in grouped["api-key"]}
    assert set(keys) == {"unrestricted", "aiplatform.googleapis.com"}  # the maps key is not reported
    assert "unrestricted-api-key" in keys["unrestricted"].tags
    assert "provider.google-gemini" in keys["unrestricted"].model_providers
    assert keys["aiplatform.googleapis.com"].metadata["server_restrictions"] is True
    assert "unrestricted-api-key" not in keys["aiplatform.googleapis.com"].tags

    grants = {f.metadata["member"]: f for f in grouped["iam-binding"]}
    assert set(grants) == {"user:root@acme.example", "allAuthenticatedUsers"}  # the viewer is not AI access
    assert grants["user:root@acme.example"].metadata["broad_roles"] == ["roles/owner"]
    assert "broad-project-access" in grants["user:root@acme.example"].tags
    assert "public-principal" in grants["allAuthenticatedUsers"].tags

    (account,) = grouped["service-account"]
    assert account.metadata["keys"] is None and account.metadata["key_coverage"] == "unknown"
    assert "secret-manager-secret" not in grouped  # db-password is not an LLM credential
    (project,) = grouped["enabled-apis"]  # acme-batch enables no AI API
    assert project.account == PROJECT

    callers = {f.account: f for f in grouped["caller/principal"]}
    assert set(callers) == {"acme-search", "acme-shared"}  # one principal, one caller per project
    home = callers["acme-search"]
    assert home.metadata["events"] == 2
    assert (home.first_seen, home.last_seen) == ("2025-09-01T09:00:00Z", "2025-09-02T10:00:00Z")
    assert "delegation" in home.tags and "delegated-identity" in home.capabilities
    assert "cloud.gcp-vertex-agent-engine" in home.frameworks  # a reasoning engine was queried
    assert "framework.google-adk" in home.frameworks
    assert callers["acme-shared"].metadata["events"] == 1 and "delegation" not in callers["acme-shared"].tags


# ------------------------------------------------------------------- live
def test_gcp_project_collection_walks_every_enabled_ai_service(index):
    connector = GcpConnector(context(index, locations=["us-central1"], audit_days=1))
    engine = f"projects/{PROJECT}/locations/us-central1/reasoningEngines/7"
    fake = FakeGoogle(
        {
            "/services": enabled(
                "aiplatform.googleapis.com",
                "dialogflow.googleapis.com",
                "discoveryengine.googleapis.com",
                "cloudfunctions.googleapis.com",
                "apikeys.googleapis.com",
                "secretmanager.googleapis.com",
            ),
            "/reasoningEngines": {
                "reasoningEngines": [
                    {"name": engine, "displayName": "negotiator", "spec": {"agentFramework": "google-adk"}}
                ]
            },
            "/endpoints": {
                "endpoints": [
                    {
                        "name": f"projects/{PROJECT}/locations/us-central1/endpoints/1",
                        "deployedModels": [{"model": "publishers/google/models/gemini-1.5-pro"}],
                    }
                ]
            },
            "/global/agents": {
                "agents": [
                    {"name": f"projects/{PROJECT}/locations/global/agents/a", "displayName": "helpdesk"}
                ]
            },
            "/global/collections/default_collection/engines": {
                "engines": [
                    {
                        "name": f"projects/{PROJECT}/locations/global/collections/default_collection/engines/e",
                        "displayName": "support",
                        "solutionType": "SOLUTION_TYPE_CHAT",
                    }
                ]
            },
            "/functions": {"functions": [{"name": f"projects/{PROJECT}/locations/us-central1/functions/f"}]},
            "/serviceAccounts": {
                "accounts": [
                    {"name": SA_NAME, "displayName": "CrewAI agent runner"},
                    {"name": "projects/other/../escape", "displayName": "bad"},
                ]
            },
            # Service-account keys (IAM) and API keys (API Keys service) share the /keys suffix.
            "/keys": lambda url: (
                {"keys": [{"name": "k"}]}
                if url.startswith("https://iam.")
                else {
                    "keys": [
                        {
                            "name": "projects/1/locations/global/keys/k1",
                            "displayName": "gemini-dev",
                            "restrictions": {},
                        }
                    ]
                }
            ),
            "/secrets": {
                "secrets": [
                    {
                        "name": "projects/1/secrets/openai-api-key",
                        "createTime": "2025-01-01",
                        "labels": {"team": "ml"},
                        "replication": {"automatic": {}},
                    }
                ]
            },
        },
        posts={
            ":getIamPolicy": {
                "bindings": [{"role": "roles/aiplatform.user", "members": ["user:dev@acme.example"]}]
            },
            "entries:list": {
                "entries": [
                    {
                        "timestamp": "2025-09-01T00:00:00Z",
                        "protoPayload": {
                            "methodName": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
                            "resourceName": engine,
                            "authenticationInfo": {"principalEmail": "dev@acme.example"},
                            "requestMetadata": {
                                "callerIp": "203.0.113.5",
                                "callerSuppliedUserAgent": "langchain/0.3",
                            },
                        },
                    }
                ]
            },
        },
    )
    connector.http = fake  # type: ignore[assignment]
    records = list(connector._collect_project(PROJECT))

    assert [r["_kind"] for r in records] == [
        "project",
        "reasoning-engine",
        "vertex-endpoint",
        "dialogflow-agent",
        "discovery-engine",
        "cloud-function",
        "iam-policy",
        "service-account",
        "api-key",
        "secret-name",
        "audit-event",
    ]
    assert records[0]["ai_services"] == [
        "aiplatform.googleapis.com",
        "dialogflow.googleapis.com",
        "discoveryengine.googleapis.com",
    ]
    urls = [url for url, _ in fake.gets]
    # Vertex uses regional hosts; Dialogflow covers global plus every location; Discovery
    # Engine covers its three multi-regions.
    vertex = f"https://us-central1-aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/us-central1"
    assert f"{vertex}/reasoningEngines" in urls and f"{vertex}/endpoints" in urls
    assert sum(urlsplit(url).hostname == "dialogflow.googleapis.com" for url in urls) == 2
    assert [url.split("/locations/")[1].split("/")[0] for url in urls if "discoveryengine" in url] == [
        "global",
        "us",
        "eu",
    ]
    assert (f"https://iam.googleapis.com/v1/{SA_NAME}/keys", {"keyTypes": "USER_MANAGED"}) in fake.gets
    secret = next(r for r in records if r["_kind"] == "secret-name")
    assert set(secret) == {"_kind", "_project", "name", "createTime", "labels"}  # replication is not kept
    account = next(r for r in records if r["_kind"] == "service-account")
    assert account["user_managed_keys"] == 1 and account["key_coverage"] == "observed"
    audit = next(r for r in records if r["_kind"] == "audit-event")
    assert audit["principal"] == "dev@acme.example" and audit["ip"] == "203.0.113.5"
    url, body = fake.bodies[-1]
    assert url == "https://logging.googleapis.com/v2/entries:list"
    assert body["resourceNames"] == [f"projects/{PROJECT}"] and body["pageSize"] == 1000
    assert 'protoPayload.serviceName=("aiplatform.googleapis.com"' in body["filter"]
    assert '"GenerateContent" OR "StreamGenerateContent"' in body["filter"]
    assert "timestamp>=" in body["filter"]
    # The malformed service account name is reported rather than silently skipped.
    assert connector.ctx.stats.incomplete
    assert any("invalid service account identifier" in w for w in connector.ctx.stats.warnings)

    findings = _by_kind(list(connector.analyze(records)))
    assert findings["reasoning-engine"][0].kind == Kind.AGENT
    assert "framework.google-adk" in findings["reasoning-engine"][0].frameworks
    assert findings["dialogflow-cx-agent"][0].kind == Kind.AGENT
    assert findings["secret-manager-secret"][0].metadata["labels"] == {"team": "ml"}
    (caller,) = findings["caller/principal"]
    assert caller.metadata["user_agents"] == {"langchain/0.3": 1}


def test_gcp_invalid_iam_policy_response_is_incomplete_without_losing_accounts(index):
    connector = GcpConnector(context(index))
    connector.http = FakeGoogle(  # type: ignore[assignment]
        {
            "/services": enabled(),
            "/serviceAccounts": {"accounts": [{"name": SA_NAME}]},
            "/keys": {"keys": []},
        },
        posts={":getIamPolicy": {"error": {"code": 403, "status": "PERMISSION_DENIED"}}},
    )
    records = list(connector._collect_project(PROJECT))
    assert [r["_kind"] for r in records] == ["project", "service-account"]
    assert connector.ctx.stats.incomplete
    assert any("invalid IAM policy response" in w for w in connector.ctx.stats.warnings)


def test_gcp_empty_service_usage_response_is_not_an_empty_project(index):
    connector = GcpConnector(context(index))
    fake = FakeGoogle(
        {"/services": None, "/serviceAccounts": {"accounts": []}}, posts={":getIamPolicy": {"bindings": []}}
    )
    connector.http = fake  # type: ignore[assignment]
    records = list(connector._collect_project(PROJECT))
    assert records[0] == {"_kind": "project", "project": PROJECT, "ai_services": []}
    assert connector.ctx.stats.incomplete
    assert any("empty response" in w for w in connector.ctx.stats.warnings)


@pytest.mark.parametrize(
    "responses,warning,expected",
    [
        ([HttpError(403, "https://logging.googleapis.com")], "audit logs not readable", 0),
        ([requests.ConnectionError("reset")], "audit logs not readable", 0),
        ([{"error": {"code": 400}}], "invalid audit log response", 0),
        ([{"entries": "not-a-list"}], "invalid audit log response", 0),
        (
            [{"entries": ["bad", {"protoPayload": "bad"}, {"protoPayload": {"methodName": "Predict"}}]}],
            "invalid audit log entry",
            1,
        ),
        (
            [
                {"entries": [{"protoPayload": {}}], "nextPageToken": "a"},
                {"entries": [{"protoPayload": {}}], "nextPageToken": "a"},
            ],
            "repeated audit pagination token",
            2,
        ),
        ([{"entries": [], "nextPageToken": 5}], "repeated audit pagination token", 0),
    ],
)
def test_gcp_audit_collection_fails_closed_and_keeps_observed_events(index, responses, warning, expected):
    connector = GcpConnector(context(index, audit_days=1))
    connector.http = Mock()
    connector.http.post_json.side_effect = responses
    records = list(connector._collect_audit(PROJECT))
    assert len(records) == expected
    assert connector.ctx.stats.incomplete
    assert any(warning in w for w in connector.ctx.stats.warnings)


def test_gcp_audit_pages_forward_their_continuation_token(index):
    connector = GcpConnector(context(index, audit_days=2))
    connector.http = Mock()
    connector.http.post_json.side_effect = [
        {"entries": [{"protoPayload": {"methodName": "Predict"}}], "nextPageToken": "page-2"},
        {"entries": [{"protoPayload": {"methodName": "Query"}}]},
    ]
    records = list(connector._collect_audit(PROJECT))
    assert [r["method"] for r in records] == ["Predict", "Query"]
    assert connector.http.post_json.call_args.kwargs["json"]["pageToken"] == "page-2"
    assert not connector.ctx.stats.incomplete


def test_gcp_collect_discovers_active_projects_and_stops_at_max_projects(index):
    connector = GcpConnector(context(index, max_projects=1))
    fake = FakeGoogle(
        {
            "/v1/projects": {
                "projects": [{"projectId": "first"}, {"name": "no-id"}, {"projectId": "second"}]
            },
            "/services": enabled(),
            "/serviceAccounts": {"accounts": []},
        },
        posts={":getIamPolicy": {"bindings": []}},
    )
    connector._auth = lambda: setattr(connector, "http", fake)  # type: ignore[method-assign]
    records = list(connector.collect())
    assert [r["project"] for r in records if r["_kind"] == "project"] == ["first"]
    assert fake.gets[0] == (
        "https://cloudresourcemanager.googleapis.com/v1/projects",
        {"filter": "lifecycleState:ACTIVE"},
    )
    assert "cloud.gcp: max_projects reached" in connector.ctx.stats.warnings
    assert connector.ctx.stats.incomplete


# ------------------------------------------------------------------- auth
def test_gcp_access_token_authenticates_without_google_auth(index, monkeypatch):
    monkeypatch.setitem(sys.modules, "google.auth", None)
    connector = GcpConnector(context(index, access_token="synthetic-token"))
    connector._auth()
    assert connector.http is not None
    assert connector.http.session.headers["Authorization"] == "Bearer synthetic-token"


def test_gcp_without_token_requires_google_auth(index, monkeypatch):
    monkeypatch.delenv("GOOGLE_OAUTH_ACCESS_TOKEN", raising=False)
    monkeypatch.setitem(sys.modules, "google.auth", None)
    with pytest.raises(ConnectorError, match="install google-auth"):
        GcpConnector(context(index))._auth()


class _StreamedResponse:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status_code = status
        self.headers: dict[str, str] = {}
        self.body = body
        self.closed = False
        # requests.Response always carries ``raw``; this in-memory body has no socket.
        self.raw = None

    def iter_content(self, chunk_size: int) -> Any:
        yield self.body

    def close(self) -> None:
        self.closed = True


def _instance_credentials_request(index: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Authenticate through the opted-in default chain and return its bounded transport."""
    google_auth = pytest.importorskip("google.auth")
    pytest.importorskip("google.auth.transport.requests")
    monkeypatch.delenv("GOOGLE_OAUTH_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    refresh = Mock()
    default = Mock(return_value=(SimpleNamespace(token="minted", refresh=refresh), "project"))
    monkeypatch.setattr(google_auth, "default", default)
    connector = GcpConnector(context(index, allow_instance_credentials=True))
    connector._auth()
    assert default.call_args.kwargs["scopes"] == ["https://www.googleapis.com/auth/cloud-platform"]
    request = default.call_args.kwargs["request"]
    refresh.assert_called_once_with(request)
    assert connector.http is not None
    assert connector.http.session.headers["Authorization"] == "Bearer minted"
    return request


def test_gcp_metadata_transport_refuses_redirects_and_bounds_the_body(index, monkeypatch):
    request = _instance_credentials_request(index, monkeypatch)
    sent: list[dict[str, Any]] = []
    responses = [_StreamedResponse(302), _StreamedResponse(200, b'{"access_token": "t"}')]

    def fake_send(self: Any, method: str, url: str, **kwargs: Any) -> _StreamedResponse:
        sent.append({"method": method, "url": url, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(requests.Session, "request", fake_send)
    session = request.session
    assert session.trust_env is False
    url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    with pytest.raises(ValueError, match="redirects are refused"):
        session.request("GET", url, headers={"Metadata-Flavor": "Google"})
    response = session.request("GET", url, headers={"Metadata-Flavor": "Google"})
    assert response._content == b'{"access_token": "t"}' and response.closed
    assert all(call["allow_redirects"] is False and call["stream"] is True for call in sent)
    with pytest.raises(TypeError, match="keyword HTTP options"):
        session.request("GET", url, None)


def test_gcp_https_credential_requests_use_the_bounded_client(index, monkeypatch):
    request = _instance_credentials_request(index, monkeypatch)
    session = request.session
    session.client.request = Mock(return_value="token-response")
    assert session.request("POST", "https://oauth2.googleapis.com/token", data={"a": "b"}) == "token-response"
    session.client.request.assert_called_once_with(
        "POST",
        "https://oauth2.googleapis.com/token",
        raise_for_status=False,
        data={"a": "b"},
        stream=False,
    )
    session.client.session.close = Mock()
    session.close()
    session.client.session.close.assert_called_once_with()


@pytest.mark.parametrize("timeout,expected", [(120, 30.0), (5, 5.0), (None, 30)])
def test_gcp_credential_refresh_timeouts_are_capped(index, monkeypatch, timeout, expected):
    transport = pytest.importorskip("google.auth.transport.requests")
    request = _instance_credentials_request(index, monkeypatch)
    seen: dict[str, Any] = {}
    monkeypatch.setattr(transport.Request, "__call__", lambda self, *a, **kw: seen.update(kw) or "ok")
    assert request(url="http://metadata.google.internal/token", method="GET", timeout=timeout) == "ok"
    assert seen["timeout"] == expected


def test_gcp_local_credentials_refresh_only_reaches_public_https(index, monkeypatch, tmp_path):
    google_auth = pytest.importorskip("google.auth")
    transport = pytest.importorskip("google.auth.transport.requests")
    local = tmp_path / "adc.json"
    local.write_text("{}", encoding="utf-8")
    load = Mock(return_value=(SimpleNamespace(token="local", refresh=Mock()), "project"))
    monkeypatch.setattr(google_auth, "load_credentials_from_file", load)
    connector = GcpConnector(context(index, credentials_file=str(local), allow_instance_credentials=False))
    connector._auth()
    request = load.call_args.kwargs["request"]
    monkeypatch.setattr(transport.Request, "__call__", lambda self, *a, **kw: "sent")
    # A file-based workload identity must not redirect the refresh to instance metadata.
    with pytest.raises(ValueError, match="HTTPS"):
        request(url="http://169.254.169.254/computeMetadata/v1/token", method="GET")
    with pytest.raises(ValueError, match="cloud-metadata destination"):
        request(url="https://169.254.169.254/token", method="GET")
    checked = Mock()
    monkeypatch.setattr(gcp_module, "validate_url", checked)
    assert request("https://sts.googleapis.com/v1/token", method="POST") == "sent"
    checked.assert_called_once_with("https://sts.googleapis.com/v1/token", allow_private=False)


def stats_context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


@pytest.mark.parametrize("keys", [None, [], {"error": {}}, {"keys": None}, {"keys": [1]}])
def test_gcp_unknown_key_inventory_is_not_zero_keys(index, keys):
    connector = GcpConnector(stats_context(index, projects="project-one"))
    account = {
        "name": "projects/project-one/serviceAccounts/crew@project-one.iam.gserviceaccount.com",
        "email": "crew@project-one.iam.gserviceaccount.com",
        "displayName": "n8n agent runner",
    }
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
    connector = GcpConnector(stats_context(index))
    account = {
        "name": "projects/project-one/serviceAccounts/crew@project-one.iam.gserviceaccount.com",
        "displayName": "CrewAI agent runner",
    }
    connector._pages = lambda url, *a, **kw: iter([account]) if url.endswith("/serviceAccounts") else iter([])
    connector._get = Mock(return_value=keys)
    connector.http = Mock()
    connector.http.post_json.return_value = {"bindings": []}
    record = next(r for r in connector._collect_project("project-one") if r["_kind"] == "service-account")
    assert record["user_managed_keys"] == count and record["key_coverage"] == "observed"
    assert not connector.ctx.stats.incomplete


# Live provider response shapes, without cloud credentials.
def test_gcp_repeated_pagination_token_preserves_partial_data_but_marks_incomplete(index):
    ctx = stats_context(index)
    connector = GcpConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"items": [{"id": "first"}], "nextPageToken": "same"},
        {"items": [{"id": "second"}], "nextPageToken": "same"},
    ]
    assert [item["id"] for item in connector._pages("https://example.googleapis.com/v1/items", "items")] == [
        "first",
        "second",
    ]
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete


def test_gcp_malformed_continuation_keeps_observed_resources_without_leaking_payload(index):
    ctx = stats_context(index)
    connector = GcpConnector(ctx)
    connector.http = Mock()
    secret = "sk-proj-" + "x" * 40
    connector.http.get_json.side_effect = [
        {"items": [{"id": "observed-agent"}], "nextPageToken": "next"},
        {"items": secret},  # malformed successful response on the next page
    ]

    records = list(connector._pages("https://example.googleapis.com/v1/agents", "items"))

    assert records == [{"id": "observed-agent"}]
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete
    assert any("invalid items page" in warning for warning in ctx.stats.warnings)
    assert secret not in str(ctx.stats.warnings)


def test_gcp_page_cap_marks_incomplete(index, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.cloud.gcp.MAX_LIST_PAGES", 2)
    ctx = stats_context(index)
    connector = GcpConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"items": [{"id": "first"}], "nextPageToken": "t1"},
        {"items": [{"id": "second"}], "nextPageToken": "t2"},
    ]
    assert len(list(connector._pages("https://example.googleapis.com/v1/items", "items"))) == 2
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete


def test_gcp_suppressed_rate_limit_does_not_report_clean_inventory(index):
    ctx = stats_context(index)
    connector = GcpConnector(ctx)
    connector.http = Mock()
    connector.http.get_json.side_effect = HttpError(429, "https://example.googleapis.com/v1/items")
    assert list(connector._pages("https://example.googleapis.com/v1/items", "items")) == []
    assert ctx.stats.incomplete
