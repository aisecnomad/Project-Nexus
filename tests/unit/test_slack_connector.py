"""Slack connector coverage: malformed success responses, pagination and workspace identity."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
import responses
from requests import ConnectionError, Timeout

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.models import ScanResult


def _slack_response(path: str, params=None):
    if path == "/team.info":
        return {"ok": True, "team": {"id": "T1", "name": "test"}}
    if path == "/users.list":
        return {"ok": True, "members": []}
    if path == "/admin.apps.approved.list":
        return {"ok": True, "approved_apps": [{"app": {"id": "A1", "name": "Claude"}, "scopes": []}]}
    if path == "/admin.apps.restricted.list":
        return {"ok": True, "restricted_apps": []}
    if path == "/admin.apps.requests.list":
        return {"ok": True, "app_requests": []}
    if path == "/team.integrationLogs":
        return {"ok": True, "logs": [], "paging": {"pages": 1}}
    raise AssertionError(path)


def slack(index, monkeypatch, responses, **config):
    connector = SlackConnector(ConnectorContext(index=index, config={"token": "test", **config}))
    calls = []

    def get(path, params=None):
        calls.append(path)
        default = {
            "/team.info": {"ok": True, "team": {"id": "T1", "name": "Example"}},
            "/users.list": {"ok": True, "members": []},
            "/admin.apps.approved.list": {"ok": True, "approved_apps": []},
            "/admin.apps.restricted.list": {"ok": True, "restricted_apps": []},
            "/admin.apps.requests.list": {"ok": True, "app_requests": []},
            "/team.integrationLogs": {"ok": True, "logs": [], "paging": {"pages": 0}},
        }
        response = responses.get(path, default[path])
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    return connector, calls


def test_slack_live_team_and_logs_keep_collected_record_kinds(index, monkeypatch):
    connector, _ = slack(
        index,
        monkeypatch,
        {
            "/team.info": {"ok": True, "team": {"id": "T1", "name": "Example", "_kind": "bot_user"}},
            "/team.integrationLogs": {
                "ok": True,
                "logs": [{"app_id": "A1", "app_type": "app", "app_name": "Claude", "_kind": "team"}],
                "paging": {"pages": 1},
            },
        },
    )
    records = list(connector.collect())
    assert [record["_kind"] for record in records] == ["team", "integration_log"]


@pytest.mark.parametrize(
    "path",
    [
        "/team.info",
        "/users.list",
        "/admin.apps.approved.list",
        "/admin.apps.restricted.list",
        "/admin.apps.requests.list",
        "/team.integrationLogs",
    ],
)
@pytest.mark.parametrize(
    "broken",
    [
        {"ok": True},
        {
            "ok": True,
            "members": None,
            "approved_apps": {},
            "restricted_apps": 4,
            "app_requests": "",
            "logs": None,
            "team": [],
        },
    ],
)
def test_slack_missing_or_malformed_success_collection_is_incomplete(index, monkeypatch, path, broken):
    http = Mock(
        get_json=Mock(
            side_effect=lambda requested, params=None: (
                broken if requested == path else _slack_response(requested, params)
            )
        )
    )
    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=http))
    connector = SlackConnector(ConnectorContext({"token": "synthetic"}, index=index))
    findings = connector.run()
    result = ScanResult(findings=findings, stats=[connector.ctx.stats])
    assert not result.complete
    assert connector.ctx.stats.incomplete and connector.ctx.stats.warnings
    if path not in {"/team.info", "/admin.apps.approved.list"}:
        assert len(findings) == 1
    if path == "/team.info":
        assert not findings  # Workspace identity must be verified before attribution.


def test_slack_explicit_empty_collections_are_complete(index, monkeypatch):
    def get(path, params=None):
        response = _slack_response(path, params)
        if path == "/admin.apps.approved.list":
            response["approved_apps"] = []
        return response

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    connector = SlackConnector(ConnectorContext({"token": "synthetic"}, index=index))
    findings = connector.run()
    assert findings == []
    assert ScanResult(findings=findings, stats=[connector.ctx.stats]).complete


@pytest.mark.parametrize(
    "path,key",
    [
        ("/users.list", "members"),
        ("/admin.apps.approved.list", "approved_apps"),
        ("/team.integrationLogs", "logs"),
    ],
)
def test_slack_bad_item_marks_partial_coverage_but_keeps_other_apps(index, monkeypatch, path, key):
    def get(requested, params=None):
        response = _slack_response(requested, params)
        if requested == path:
            response[key] = [None, *response[key]]
        return response

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    connector = SlackConnector(ConnectorContext({"token": "synthetic"}, index=index))
    findings = connector.run()
    assert len(findings) == 1 and connector.ctx.stats.incomplete


@pytest.mark.parametrize(
    "path,field,value",
    [
        ("/users.list", "response_metadata", []),
        ("/users.list", "response_metadata", {"next_cursor": False}),
        ("/team.integrationLogs", "paging", {}),
        ("/team.integrationLogs", "paging", {"pages": "many"}),
    ],
)
def test_slack_invalid_pagination_metadata_marks_incomplete(index, monkeypatch, path, field, value):
    def get(requested, params=None):
        response = _slack_response(requested, params)
        if requested == path:
            response[field] = value
        return response

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    connector = SlackConnector(ConnectorContext({"token": "synthetic"}, index=index))
    findings = connector.run()
    assert len(findings) == 1 and connector.ctx.stats.incomplete


def test_slack_contradictory_success_error_is_incomplete_without_losing_observed_apps(index, monkeypatch):
    def get(path, params=None):
        response = _slack_response(path, params)
        if path == "/admin.apps.approved.list":
            response["error"] = "opaque synthetic upstream error"
        return response

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    connector = SlackConnector(ConnectorContext({"token": "synthetic"}, index=index))
    findings = connector.run()
    assert len(findings) == 1 and connector.ctx.stats.incomplete
    assert "opaque synthetic upstream error" not in repr(connector.ctx.stats)


def test_slack_rejected_api_response_does_not_echo_opaque_error(index, monkeypatch):
    secret = "opaque synthetic upstream secret"

    def get(path, params=None):
        return {"ok": False, "error": secret} if path == "/users.list" else _slack_response(path, params)

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    connector = SlackConnector(ConnectorContext({"token": "synthetic"}, index=index))
    findings = connector.run()
    assert len(findings) == 1 and connector.ctx.stats.incomplete
    assert secret not in repr(connector.ctx.stats)


@pytest.mark.parametrize(
    "path,key",
    [
        ("/users.list", "members"),
        ("/admin.apps.approved.list", "approved_apps"),
        ("/admin.apps.restricted.list", "restricted_apps"),
        ("/admin.apps.requests.list", "app_requests"),
        ("/team.integrationLogs", "logs"),
    ],
)
@pytest.mark.parametrize("value", [None, "missing", {}, "invalid"])
def test_slack_missing_or_invalid_success_collections_are_incomplete(index, monkeypatch, path, key, value):
    response = {"ok": True, "paging": {"pages": 0}}
    if value != "missing":
        response[key] = value
    connector, _ = slack(index, monkeypatch, {path: response})
    assert connector.run() == []
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


def test_slack_explicit_empty_inventories_are_complete(index, monkeypatch):
    connector, _ = slack(index, monkeypatch, {}, team_id="T1")
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize(
    "response", [{"ok": True}, {"ok": True, "team": {}}, {"ok": True, "team": {"id": "T2"}}]
)
def test_slack_unknown_or_mismatched_workspace_stops_before_inventory(index, monkeypatch, response):
    connector, calls = slack(index, monkeypatch, {"/team.info": response}, team_id="T1")
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert calls == ["/team.info"]


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionError("sensitive-provider-message"),
        Timeout("sensitive-provider-message"),
        ValueError("sensitive-provider-message"),
    ],
)
def test_slack_later_transport_or_parse_failure_preserves_collected_bot(index, monkeypatch, failure):
    connector, calls = slack(
        index,
        monkeypatch,
        {
            "/users.list": {
                "ok": True,
                "members": [
                    {
                        "id": "U1",
                        "name": "Claude",
                        "is_bot": True,
                        "profile": {"api_app_id": "A1", "real_name": "Claude"},
                    }
                ],
            },
            "/admin.apps.approved.list": failure,
        },
    )
    (finding,) = connector.run()
    assert finding.resource == "slack:app:A1"
    assert "/admin.apps.restricted.list" in calls
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors
    assert "sensitive-provider-message" not in str(connector.ctx.stats.warnings)


@pytest.mark.parametrize(
    "metadata", [None, [], {"next_cursor": True}, {"next_cursor": 1}, {"next_cursor": None}]
)
def test_slack_invalid_cursor_is_unknown_coverage(index, monkeypatch, metadata):
    connector, _ = slack(
        index, monkeypatch, {"/users.list": {"ok": True, "members": [], "response_metadata": metadata}}
    )
    assert connector.run() == []
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("paging", [None, {}, {"pages": "1"}, {"pages": True}, {"pages": -1}])
def test_slack_invalid_integration_paging_is_unknown_coverage(index, monkeypatch, paging):
    connector, _ = slack(
        index, monkeypatch, {"/team.integrationLogs": {"ok": True, "logs": [], "paging": paging}}
    )
    assert connector.run() == []
    assert connector.ctx.stats.incomplete


@responses.activate
def test_slack_non_dict_list_entries_are_skipped_not_fatal(run_connector):
    api = "https://slack.com/api"
    responses.get(
        f"{api}/team.info", json={"ok": True, "team": {"id": "T1", "name": "acme", "domain": "acme"}}
    )
    responses.get(
        f"{api}/users.list",
        json={
            "ok": True,
            "members": [
                "garbage",
                {"id": "U1", "is_bot": True, "profile": {"api_app_id": "A1", "real_name": "Otter.ai"}},
            ],
        },
    )
    responses.get(
        f"{api}/admin.apps.approved.list",
        json={
            "ok": True,
            "approved_apps": [
                42,
                {"app": {"id": "A2", "name": "ChatGPT"}, "scopes": [{"name": "chat:write"}]},
            ],
        },
    )
    responses.get(f"{api}/admin.apps.restricted.list", json={"ok": True, "restricted_apps": []})
    responses.get(f"{api}/admin.apps.requests.list", json={"ok": True, "app_requests": []})
    responses.get(
        f"{api}/team.integrationLogs", json={"ok": True, "logs": ["garbage"], "paging": {"pages": 1}}
    )
    findings, ctx = run_connector("saas.slack", token="xoxb-synthetic-test-token-000000")
    assert {f.title for f in findings} == {"Slack app (bot): Otter.ai", "Slack app: ChatGPT"}
    assert not ctx.stats.errors and ctx.stats.incomplete


def test_record_of_another_workspace_is_skipped_not_scan_wide(run_connector, tmp_path):
    # One Slack Connect bot from another workspace used to withhold every finding.
    records = [
        {"_kind": "team", "id": "T0AAA", "name": "Acme", "domain": "acme"},
        {
            "id": "U1",
            "is_bot": True,
            "team_id": "T0AAA",
            "profile": {"api_app_id": "A1", "real_name": "OpenAI ChatGPT Bot"},
            "name": "chatgpt",
        },
        {
            "id": "U2",
            "is_bot": True,
            "team_id": "T0ZZZ",
            "profile": {"api_app_id": "A1", "real_name": "Some Connect Bot"},
            "name": "connect",
        },
        {
            "id": "U3",
            "is_bot": True,
            "team_id": 7,
            "profile": {"api_app_id": "A3", "real_name": "x"},
            "name": "x",
        },
    ]
    export = tmp_path / "slack.json"
    export.write_text(json.dumps(records))
    findings, ctx = run_connector("saas.slack", input=str(export))
    assert [f.resource for f in findings] == ["slack:app:A1"]
    assert findings[0].metadata["workspace_name"] == "Acme"
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert ctx.stats.warnings == [
        "saas.slack: skipped 2 records that name another or an invalid workspace; coverage incomplete"
    ]
