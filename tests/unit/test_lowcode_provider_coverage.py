"""Low-code inventories preserve observed records and disclose lost coverage."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from requests import ConnectionError

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.lowcode import salesforce, servicenow
from shadowscan.utils.http import HttpError


def _live(index, cls, responses, **config):
    connector = cls(ConnectorContext(index=index, config=config))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.get_json.side_effect = responses
    return connector


@pytest.mark.parametrize("page", [{}, {"records": None}, {"records": [], "done": False}, {"records": [], "done": True, "error": "denied"}])
def test_salesforce_invalid_or_truncated_page_is_incomplete(index, monkeypatch, page):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    connector = _live(index, salesforce.SalesforceConnector, [page])
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors


@pytest.mark.parametrize("failure", [HttpError(403, "https://example.test/opaque-secret"), ConnectionError("opaque-secret")])
def test_salesforce_later_page_failure_preserves_previous_records(index, monkeypatch, failure):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query"), "GenAiPlannerDefinition": ("tooling", "query")})
    connector = _live(index, salesforce.SalesforceConnector, [
        {"records": [{"Id": "bot-1", "DeveloperName": "Assistant"}], "done": False, "nextRecordsUrl": "/next"},
        failure,
        {"records": [{"Id": "planner-1", "DeveloperName": "Planner"}], "done": True},
    ])
    findings = connector.run()
    assert {f.resource for f in findings} == {"salesforce:bot:bot-1", "salesforce:genai-planner:planner-1"}
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors
    assert "opaque-secret" not in " ".join(connector.ctx.stats.warnings)


@pytest.mark.parametrize("max_pages,expected_calls", [(1, 1), (10, 2)])
def test_salesforce_page_limit_and_repeated_links_are_bounded(index, monkeypatch, max_pages, expected_calls):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    page = {"records": [{"Id": "bot-1", "DeveloperName": "Assistant"}], "done": False, "nextRecordsUrl": "/next"}
    connector = _live(index, salesforce.SalesforceConnector, [page, page, RuntimeError("guard against unbounded loop")], max_pages=max_pages)
    findings = connector.run()
    assert len(findings) == 1
    assert connector.http.get_json.call_count == expected_calls
    assert connector.ctx.stats.incomplete
    assert not connector.ctx.stats.errors


@pytest.mark.parametrize("page", [{}, {"result": None}, {"result": "invalid"}, {"result": [], "error": "denied"}])
def test_servicenow_invalid_page_is_incomplete(index, monkeypatch, page):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    connector = _live(index, servicenow.ServiceNowConnector, [page])
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors


@pytest.mark.parametrize("max_pages,expected_calls", [(1, 1), (10, 2)])
def test_servicenow_page_limit_and_repeated_pages_are_bounded(index, monkeypatch, max_pages, expected_calls):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    # Keep this pagination test independent of regex timing for 500 identical
    # display names. Native agent findings do not depend on name enrichment.
    match_names = Mock(return_value=[])
    monkeypatch.setattr(servicenow, "name_matches", match_names)
    page = {"result": [{"sys_id": f"agent-{number}", "name": "Assistant"} for number in range(500)]}
    connector = _live(index, servicenow.ServiceNowConnector, [page, page, RuntimeError("guard against unbounded loop")], max_pages=max_pages)
    findings = connector.run()
    assert not connector.ctx.stats.errors, connector.ctx.stats.errors
    assert len(findings) == 500
    assert match_names.call_count == 500
    assert connector.http.get_json.call_count == expected_calls
    assert connector.ctx.stats.incomplete


def test_servicenow_native_table_export_keeps_valid_neighbors(tmp_path, run_connector):
    source = tmp_path / "table.json"
    source.write_text(json.dumps({"table": "sn_aia_agent", "result": [
        "bad-row", {"sys_id": "bad", "description": ["invalid"]},
        {"sys_id": "agent-1", "name": "Assistant"},
    ]}))
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert [f.resource for f in findings] == ["servicenow:sn_aia_agent:agent-1"]
    assert ctx.stats.incomplete and not ctx.stats.errors


def test_salesforce_malformed_token_keeps_bot_and_valid_token(tmp_path, run_connector):
    source = tmp_path / "salesforce.json"
    source.write_text(json.dumps([
        {"attributes": {"type": "BotDefinition"}, "Id": "bot-1", "DeveloperName": "Assistant"},
        {"attributes": {"type": "OauthToken"}, "AppName": "Claude", "UserId": "user-1", "UseCount": "not-a-count"},
        {"attributes": {"type": "OauthToken"}, "AppName": "Claude", "UserId": "user-2", "UseCount": 2},
    ]))
    findings, ctx = run_connector("lowcode.salesforce", input=str(source))
    assert len(findings) == 2
    assert any(f.resource == "salesforce:bot:bot-1" for f in findings)
    assert ctx.stats.incomplete and not ctx.stats.errors


def test_servicenow_reference_uses_sys_id_before_display_name(tmp_path, run_connector):
    source = tmp_path / "servicenow.json"
    source.write_text(json.dumps([
        {"_table": "sn_aia_agent", "sys_id": "agent-1", "name": "New display name"},
        {"_table": "sn_aia_tool", "sys_id": "tool-1", "name": "Execute", "tool_type": "script", "agent": {"value": "agent-1", "display_value": "Old display name"}},
    ]))
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert len(findings) == 1 and not ctx.stats.incomplete
    assert "code-exec" in findings[0].capabilities
    assert findings[0].metadata["tools"] == [{"name": "Execute", "type": "script"}]


@pytest.mark.parametrize("markers", [{"done": False}, {"done": "true"}, {"nextRecordsUrl": "/next"}])
def test_salesforce_offline_query_continuation_preserves_partial_findings(tmp_path, run_connector, markers):
    source = tmp_path / "query.json"
    source.write_text(json.dumps({"records": [
        {"attributes": {"type": "BotDefinition"}, "Id": "bot-1", "DeveloperName": "Assistant"},
    ], **markers}))
    findings, ctx = run_connector("lowcode.salesforce", input=str(source))
    assert [f.resource for f in findings] == ["salesforce:bot:bot-1"]
    assert ctx.stats.incomplete


@pytest.mark.parametrize("connector,empty", [
    ("lowcode.salesforce", {"records": [], "done": True}),
    ("lowcode.servicenow", {"table": "sn_aia_agent", "result": []}),
])
def test_explicit_empty_provider_exports_remain_complete(tmp_path, run_connector, connector, empty):
    source = tmp_path / "empty.json"
    source.write_text(json.dumps(empty))
    findings, ctx = run_connector(connector, input=str(source))
    assert not findings and not ctx.stats.incomplete


def test_salesforce_normal_query_pagination_is_complete(index, monkeypatch):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    connector = _live(index, salesforce.SalesforceConnector, [
        {"records": [{"Id": "bot-1", "DeveloperName": "Assistant"}], "done": False, "nextRecordsUrl": "/next"},
        {"records": [{"Id": "bot-2", "DeveloperName": "Assistant"}], "done": True},
    ])
    assert len(connector.run()) == 2
    assert not connector.ctx.stats.incomplete
    assert connector.http.get_json.call_args.kwargs == {"params": None}
