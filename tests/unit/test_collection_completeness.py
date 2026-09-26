"""Collection failures must never become clean CLI or SARIF reports."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from requests import ConnectionError

from shadowscan.cli import _exit_code
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.connectors.identity.entra import EntraConnector
from shadowscan.connectors.identity.google_workspace import GoogleWorkspaceConnector
from shadowscan.connectors.lowcode.automation import (
    MakeConnector,
    N8nConnector,
    WorkatoConnector,
    ZapierConnector,
)
from shadowscan.connectors.saas.teams import TeamsConnector
from shadowscan.models import ScanResult, ScanStats
from shadowscan.reporters.sarif import render_sarif
from shadowscan.utils.http import HttpClient, HttpError


def _context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def _assert_incomplete(connector, findings):
    result = ScanResult(findings=findings, stats=[connector.ctx.stats])
    assert not result.complete
    assert _exit_code(result, None) == 3
    invocation = json.loads(render_sarif(result))["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 503])
def test_gcp_iam_collection_failure_is_incomplete(index, status):
    connector = GcpConnector(_context(index, projects=["demo"]))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.get_json.return_value = {}
    connector.http.post_json.side_effect = HttpError(status, "https://cloudresourcemanager.googleapis.com/iam")
    findings = connector.run()
    _assert_incomplete(connector, findings)
    assert any("IAM policy" in warning for warning in connector.ctx.stats.warnings)


@pytest.mark.parametrize("failure", [HttpError(403, "https://example.com"), HttpError(429, "https://example.com"), ConnectionError("failed")])
def test_gcp_get_failures_are_incomplete(index, failure):
    connector = GcpConnector(_context(index))
    connector.http = Mock()
    connector.http.get_json.side_effect = failure
    assert list(connector._pages("https://example.com/resources", "items")) == []
    _assert_incomplete(connector, [])


def test_gcp_pagination_repetition_preserves_earlier_records(index):
    connector = GcpConnector(_context(index))
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"items": [{"name": "one"}], "nextPageToken": "repeat"},
        {"items": [{"name": "two"}], "nextPageToken": "repeat"},
    ]
    assert len(list(connector._pages("https://example.com/resources", "items"))) == 2
    assert connector.http.get_json.call_count == 2
    _assert_incomplete(connector, [])


def test_gcp_audit_page_cap_preserves_observed_caller(index):
    connector = GcpConnector(_context(index, audit_days=1, max_pages=1))
    connector.http = Mock()
    connector.http.post_json.return_value = {
        "entries": [{"protoPayload": {"authenticationInfo": {"principalEmail": "agent@example.com"}, "methodName": "GenerateContent"}}],
        "nextPageToken": "more",
    }
    records = list(connector._collect_audit("demo"))
    assert len(records) == 1
    assert "pagination limit" in connector.ctx.stats.warnings[0]
    _assert_incomplete(connector, list(connector.analyze(records)))


@pytest.mark.parametrize("status", [401, 403, 404, 429, 503])
def test_google_workspace_denied_tokens_are_incomplete_with_valid_apps_preserved(index, status):
    connector = GoogleWorkspaceConnector(_context(index))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.paginate_token.return_value = iter([{"primaryEmail": "allowed@example.com"}, {"primaryEmail": "denied@example.com"}])
    connector.http.get_json.side_effect = [
        {"id": "C01234567"},
        {"items": [{"clientId": "agent", "displayText": "Fireflies.ai Notetaker", "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]}]},
        HttpError(status, "https://admin.googleapis.com/tokens"),
    ]
    findings = connector.run()
    assert len(findings) == 1
    assert findings[0].metadata["user_count"] == 1
    _assert_incomplete(connector, findings)


def test_google_workspace_later_user_page_failure_preserves_apps(index):
    connector = GoogleWorkspaceConnector(_context(index))
    connector._auth = Mock()
    connector.http = Mock()

    def users(*args, **kwargs):
        yield {"primaryEmail": "allowed@example.com"}
        raise ConnectionError("disconnected")

    connector.http.paginate_token.side_effect = users
    connector.http.get_json.side_effect = [
        {"id": "C01234567"},
        {"items": [{"clientId": "agent", "displayText": "Fireflies.ai Notetaker"}]},
    ]
    findings = connector.run()
    assert len(findings) == 1
    _assert_incomplete(connector, findings)


@pytest.mark.parametrize("detail", ["NotAuthenticated", "NotAuthorizedOrNotFound", "404", "service not available", "retry exhausted"])
def test_oci_failures_no_longer_look_like_empty_inventories(index, detail):
    connector = OciConnector(_context(index))
    call = Mock(side_effect=RuntimeError(detail))
    assert connector._all(call, "compartment") == []
    _assert_incomplete(connector, [])


def test_oci_later_page_failure_retains_successes(index):
    connector = OciConnector(_context(index))
    call = Mock(side_effect=[SimpleNamespace(data=[{"id": "agent"}], has_next_page=True, next_page="next"), RuntimeError("NotAuthenticated")])
    assert connector._all(call, "compartment") == [{"id": "agent"}]
    assert call.call_args.kwargs["page"] == "next"
    _assert_incomplete(connector, [])


@pytest.mark.parametrize("max_pages", [1, 10])
def test_oci_caps_and_repeated_pages_are_incomplete(index, max_pages):
    connector = OciConnector(_context(index, max_pages=max_pages))
    call = Mock(return_value=SimpleNamespace(data=SimpleNamespace(items=[{"id": "agent"}]), has_next_page=True, next_page="repeat"))
    assert connector._all(call)
    assert call.call_count == min(max_pages, 2)
    _assert_incomplete(connector, [])


@pytest.mark.parametrize("failure_path", ["/servicePrincipals", "/oauth2PermissionGrants", "/servicePrincipals/sp-1/appRoleAssignments", "/applications"])
def test_entra_partial_collection_retains_observed_apps(index, failure_path):
    connector = EntraConnector(_context(index))
    connector._auth = Mock()
    connector.http = Mock()

    def pages(path, **kwargs):
        if path == "/servicePrincipals":
            yield {"id": "sp-1", "appId": "a", "displayName": "Fireflies.ai Notetaker"}
        if path == failure_path:
            raise HttpError(403, "https://graph.microsoft.com" + path)

    connector.http.paginate_odata.side_effect = pages
    findings = connector.run()
    assert len(findings) == 1
    _assert_incomplete(connector, findings)


@pytest.mark.parametrize("failure_path", ["/appCatalogs/teamsApps", "/teams", "/teams/team-1/installedApps"])
def test_teams_partial_collection_retains_catalog_apps(index, failure_path):
    connector = TeamsConnector(_context(index))
    http = Mock()
    connector._client = Mock(return_value=http)

    def pages(path, **kwargs):
        if path == "/appCatalogs/teamsApps":
            yield {"id": "app-1", "displayName": "Agent", "distributionMethod": "organization"}
        if path == "/teams":
            yield {"id": "team-1"}
        if path == failure_path:
            raise HttpError(403, "https://graph.microsoft.com" + path)

    http.paginate_odata.side_effect = pages
    findings = connector.run()
    assert len(findings) == 1
    _assert_incomplete(connector, findings)


@pytest.mark.parametrize("failed_path", ["/scenarios/one/blueprint", "/ai-agents/v1/agents"])
def test_make_collection_failures_are_incomplete(index, monkeypatch, failed_path):
    connector = MakeConnector(_context(index, api_url="https://eu1.make.com/api/v2", token="test", team_id="team"))

    def get(path, **kwargs):
        if path == failed_path:
            raise HttpError(403, "https://eu1.make.com" + path)
        return {
            "/scenarios": {"scenarios": [{"id": "one", "name": "scenario"}]},
            "/scenarios/one/blueprint": {"response": {"blueprint": {"flow": [{"module": "openai:Action"}]}}},
            "/ai-agents/v1/agents": [{"id": "agent", "name": "Agent", "defaultModel": "gpt-4o"}],
        }[path]

    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=Mock(get_json=get)))
    findings = connector.run()
    assert findings
    _assert_incomplete(connector, findings)


def test_make_invalid_team_record_is_skipped_not_fatal(index, monkeypatch):
    # A malformed team costs that one team, not the whole organization: every
    # other team in the same /teams page must still be collected.
    connector = MakeConnector(_context(index, api_url="https://eu1.make.com/api/v2", token="test", organization_id="org"))

    def get(path, **kwargs):
        return {
            "/teams": {"teams": [{"name": "no id here"}, {"id": "team-1"}]},
            "/scenarios": {"scenarios": [{"id": "s1", "name": "scenario"}]},
            "/scenarios/s1/blueprint": {"response": {"blueprint": {"flow": [{"module": "openai:Action"}]}}},
            "/ai-agents/v1/agents": [],
        }[path]

    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=Mock(get_json=get)))
    records = list(connector.collect())
    assert any("invalid team record" in w for w in connector.ctx.stats.warnings)
    scenarios = [r for r in records if r.get("_kind") == "scenario"]
    assert scenarios and all(r["_team"] == "team-1" for r in scenarios)


def test_make_invalid_scenario_record_is_skipped_not_fatal(index, monkeypatch):
    # A malformed scenario costs that one scenario, not the rest of the team
    # (and, previously, every subsequent team in the same organization).
    connector = MakeConnector(_context(index, api_url="https://eu1.make.com/api/v2", token="test", team_id="team-1"))

    def get(path, **kwargs):
        return {
            "/scenarios": {"scenarios": [{"name": "no id here"}, {"id": "s1", "name": "scenario"}]},
            "/scenarios/s1/blueprint": {"response": {"blueprint": {"flow": [{"module": "openai:Action"}]}}},
            "/ai-agents/v1/agents": [],
        }[path]

    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=Mock(get_json=get)))
    records = list(connector.collect())
    assert any("invalid scenario record" in w for w in connector.ctx.stats.warnings)
    scenarios = [r for r in records if r.get("_kind") == "scenario"]
    assert [r["id"] for r in scenarios] == ["s1"]


def test_make_all_organization_teams_are_enumerated(index):
    connector = MakeConnector(_context(index))
    http = Mock()
    http.get_json.side_effect = [{"teams": [{"id": n} for n in range(100)]}, {"teams": [{"id": 100}]}]
    assert len(list(connector._offset_pages(http, "/teams", "teams", organizationId="org"))) == 101
    assert http.get_json.call_args.kwargs["params"]["pg[offset]"] == 100
    assert not connector.ctx.stats.incomplete


def test_make_repeated_pages_stop(index):
    connector = MakeConnector(_context(index))
    http = Mock()
    http.get_json.return_value = {"scenarios": [{"id": n} for n in range(100)]}
    assert len(list(connector._offset_pages(http, "/scenarios", "scenarios"))) == 100
    assert http.get_json.call_count == 2
    _assert_incomplete(connector, [])


@pytest.mark.parametrize("cls,config,responses", [
    (ZapierConnector, {"token": "test"}, [{"data": [], "links": {"next": "/v2/zaps"}}]),
    (WorkatoConnector, {"token": "test"}, [{"items": [{"id": n} for n in range(100)]}]),
    (N8nConnector, {"api_url": "https://n8n.example.com", "api_key": "test"}, [{"data": [], "nextCursor": "repeat"}]),
])
def test_automation_pagination_is_bounded(index, monkeypatch, cls, config, responses):
    connector = cls(_context(index, **config))
    http = HttpClient("https://example.com")
    http.get_json = Mock(return_value=responses[0])
    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=http))
    findings = connector.run()
    assert http.get_json.call_count <= 2
    _assert_incomplete(connector, findings)
