"""Page identities and malformed successful responses must not hide collection gaps."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.models import ScanResult

_APP = {"_kind": "approved_app", "app": {"id": "A1", "name": "Claude"}, "scopes": []}


def _cli_scan(tmp_path, connector: str, body: object):
    source = tmp_path / "export.json"
    report = tmp_path / "report.json"
    source.write_text(json.dumps(body), encoding="utf-8")
    outcome = CliRunner().invoke(
        main, ["run", connector, "--input", str(source), "--format", "json", "-o", str(report), "--fail-on", "high"]
        + (["--set", "team_id=T1"] if connector == "saas.slack" else [])
    )
    return outcome, json.loads(report.read_text(encoding="utf-8"))


@pytest.mark.parametrize("connector,record", [
    ("saas.slack", _APP),
    ("identity.entra", {"_kind": "servicePrincipal", "id": "sp-1", "appId": "app-1", "displayName": "Claude"}),
    ("lowcode.power-platform", {"_kind": "bot", "botid": "bot-1", "name": "Claude Agent"}),
])
def test_id_on_export_envelope_does_not_hide_items(tmp_path, connector, record):
    outcome, report = _cli_scan(tmp_path, connector, {"id": "export-1", "items": [record]})
    assert outcome.exit_code in {0, 2}, outcome.output
    assert report["summary"]["complete"] is True
    assert len(report["findings"]) == 1
    assert not report["stats"][0]["incomplete"]


@pytest.mark.parametrize("connector", ["saas.slack", "identity.entra", "lowcode.power-platform"])
@pytest.mark.parametrize("body", [
    {"id": "export-1", "error": {"code": "access_denied", "message": "synthetic denied"}},
    {"id": "export-1", "ok": False, "error": "access_denied"},
    {"id": "export-1", "name": "OpenAI", "error": "access_denied"},
    {"object": "error", "error": "access_denied"},
    {"id": "export-1", "items": [], "error": "access_denied"},
])
def test_provider_error_with_page_id_is_incomplete_for_cli(tmp_path, connector, body):
    outcome, report = _cli_scan(tmp_path, connector, body)
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert not report["findings"]
    assert report["stats"][0]["incomplete"] and report["stats"][0]["errors"]


def test_export_error_keeps_valid_items_without_claiming_completeness(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"id": "export-1", "error": "later page denied", "items": [_APP]})
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 1


def test_id_on_explicit_empty_envelope_is_complete(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"id": "export-1", "items": []})
    assert outcome.exit_code == 0, outcome.output
    assert report["summary"]["complete"] is True
    assert not report["findings"]


def test_native_resource_with_id_name_and_items_is_not_unwrapped():
    native = {"id": "app-1", "name": "Native", "type": "app", "items": [{"id": "child"}]}
    assert list(BaseConnector._unwrap(native)) == [native]


def test_labelled_export_items_are_unwrapped(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"name": "export-1", "items": [_APP]})
    assert outcome.exit_code in {0, 2}, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is True


def test_jsonl_error_with_request_id_is_incomplete_and_preserves_neighbor(tmp_path):
    source = tmp_path / "export.jsonl"
    output = tmp_path / "report.json"
    source.write_text(json.dumps({"error": "permission denied", "id": "req1"}) + "\n" + json.dumps(_APP) + "\n")
    outcome = CliRunner().invoke(
        main, ["run", "saas.slack", "--input", str(source), "--format", "json", "-o", str(output), "--fail-on", "high", "--set", "team_id=T1"]
    )
    report = json.loads(output.read_text())
    assert outcome.exit_code == 3, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is False


def test_csv_error_row_is_incomplete_and_preserves_valid_neighbor(tmp_path):
    source = tmp_path / "export.csv"
    output = tmp_path / "report.json"
    source.write_text("id,name,error\napp1,Claude,\nreq1,,permission denied\n")
    outcome = CliRunner().invoke(
        main, ["run", "saas.generic", "--input", str(source), "--format", "json", "-o", str(output), "--fail-on", "high"]
    )
    report = json.loads(output.read_text())
    assert outcome.exit_code == 3, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is False


def test_csv_native_log_event_with_error_column_is_preserved():
    errors: list[str] = []
    records = list(BaseConnector._csv_records("id,name,error,timestamp\nlog-1,OpenAI,timeout,2026-01-01\n", errors.append))
    assert len(records) == 1 and records[0]["id"] == "log-1" and not errors


@pytest.mark.parametrize("connector,record", [
    ("saas.microsoft-teams", {
        "_kind": "teamsApp", "id": "A1", "displayName": "OpenAI", "distributionMethod": "organization",
        "error": "access_denied",
    }),
    ("saas.generic", {"_kind": "saas-app", "id": "A1", "name": "Claude", "error": "access_denied"}),
])
@pytest.mark.parametrize("as_array", [False, True])
def test_typed_provider_error_is_not_a_complete_native_app(tmp_path, connector, record, as_array):
    outcome, report = _cli_scan(tmp_path, connector, [record] if as_array else record)
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert report["findings"] == []


@pytest.mark.parametrize("record", [
    {"_kind": "cloudtrail-event", "eventName": "InvokeModel", "eventTime": "2026-01-01", "error": "AccessDenied"},
    {"_kind": "audit-event", "principal": "agent@example.test", "timestamp": "2026-01-01", "error": "AccessDenied"},
    {"_kind": "integration_log", "change_type": "enabled", "app_id": "A1", "error": "install-failed"},
])
def test_known_native_error_event_is_preserved(record):
    assert list(BaseConnector._unwrap(record)) == [record]
    assert list(BaseConnector._unwrap([record])) == [record]


def test_failed_nested_page_keeps_observed_items_but_marks_incomplete(tmp_path):
    another = {"_kind": "approved_app", "app": {"id": "A2", "name": "Claude"}, "scopes": []}
    outcome, report = _cli_scan(tmp_path, "saas.slack", [_APP, {"id": "req1", "error": "denied", "items": [another]}])
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 2


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


@pytest.mark.parametrize("path", [
    "/team.info", "/users.list", "/admin.apps.approved.list",
    "/admin.apps.restricted.list", "/admin.apps.requests.list", "/team.integrationLogs",
])
@pytest.mark.parametrize("broken", [{"ok": True}, {"ok": True, "members": None, "approved_apps": {}, "restricted_apps": 4, "app_requests": "", "logs": None, "team": []}])
def test_slack_missing_or_malformed_success_collection_is_incomplete(index, monkeypatch, path, broken):
    http = Mock(get_json=Mock(side_effect=lambda requested, params=None: broken if requested == path else _slack_response(requested, params)))
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


@pytest.mark.parametrize("path,key", [
    ("/users.list", "members"), ("/admin.apps.approved.list", "approved_apps"),
    ("/team.integrationLogs", "logs"),
])
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


@pytest.mark.parametrize("path,field,value", [
    ("/users.list", "response_metadata", []),
    ("/users.list", "response_metadata", {"next_cursor": False}),
    ("/team.integrationLogs", "paging", {}),
    ("/team.integrationLogs", "paging", {"pages": "many"}),
])
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
