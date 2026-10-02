"""Low-code inventories preserve observed records and disclose lost coverage."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from requests import ConnectionError

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.lowcode import automation, salesforce, servicenow
from shadowscan.connectors.lowcode.automation import MakeConnector, N8nConnector
from shadowscan.connectors.lowcode.salesforce import SalesforceConnector
from shadowscan.connectors.lowcode.servicenow import ServiceNowConnector
from shadowscan.models import ScanStats
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpError


def _live(index, cls, responses, **config):
    connector = cls(ConnectorContext(index=index, config=config))
    connector._auth = Mock()
    connector.http = Mock()
    connector.http.get_json.side_effect = responses
    return connector


@pytest.mark.parametrize(
    "page",
    [{}, {"records": None}, {"records": [], "done": False}, {"records": [], "done": True, "error": "denied"}],
)
def test_salesforce_invalid_or_truncated_page_is_incomplete(index, monkeypatch, page):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    connector = _live(index, salesforce.SalesforceConnector, [page])
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors


@pytest.mark.parametrize(
    "failure", [HttpError(403, "https://example.test/opaque-secret"), ConnectionError("opaque-secret")]
)
def test_salesforce_later_page_failure_preserves_previous_records(index, monkeypatch, failure):
    monkeypatch.setattr(
        salesforce,
        "QUERIES",
        {"BotDefinition": ("data", "query"), "GenAiPlannerDefinition": ("tooling", "query")},
    )
    connector = _live(
        index,
        salesforce.SalesforceConnector,
        [
            {
                "records": [{"Id": "bot-1", "DeveloperName": "Assistant"}],
                "done": False,
                "nextRecordsUrl": "/next",
            },
            failure,
            {"records": [{"Id": "planner-1", "DeveloperName": "Planner"}], "done": True},
        ],
    )
    findings = connector.run()
    assert {f.resource for f in findings} == {"salesforce:bot:bot-1", "salesforce:genai-planner:planner-1"}
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.warnings and not connector.ctx.stats.errors
    assert "opaque-secret" not in " ".join(connector.ctx.stats.warnings)


@pytest.mark.parametrize("max_pages,expected_calls", [(1, 1), (10, 2)])
def test_salesforce_page_limit_and_repeated_links_are_bounded(index, monkeypatch, max_pages, expected_calls):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    page = {
        "records": [{"Id": "bot-1", "DeveloperName": "Assistant"}],
        "done": False,
        "nextRecordsUrl": "/next",
    }
    connector = _live(
        index,
        salesforce.SalesforceConnector,
        [page, page, RuntimeError("guard against unbounded loop")],
        max_pages=max_pages,
    )
    findings = connector.run()
    assert len(findings) == 1
    assert connector.http.get_json.call_count == expected_calls
    assert connector.ctx.stats.incomplete
    assert not connector.ctx.stats.errors


@pytest.mark.parametrize(
    "page", [{}, {"result": None}, {"result": "invalid"}, {"result": [], "error": "denied"}]
)
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
    connector = _live(
        index,
        servicenow.ServiceNowConnector,
        [page, page, RuntimeError("guard against unbounded loop")],
        max_pages=max_pages,
    )
    findings = connector.run()
    assert not connector.ctx.stats.errors, connector.ctx.stats.errors
    assert len(findings) == 500
    assert match_names.call_count == 500
    assert connector.http.get_json.call_count == expected_calls
    assert connector.ctx.stats.incomplete


def _snow_page(start, count):
    return {
        "result": [
            {"sys_id": f"agent-{number}", "name": "Assistant"} for number in range(start, start + count)
        ]
    }


def test_servicenow_short_page_is_not_the_last_page(index, monkeypatch):
    # ACLs filter rows after sysparm_limit: 100 of 500 rows came back while
    # more existed, and collection stopped with 100 findings, complete.
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    connector = _live(
        index,
        servicenow.ServiceNowConnector,
        [
            _snow_page(0, 100),
            _snow_page(100, 37),
            {"result": []},
            RuntimeError("guard against unbounded loop"),
        ],
    )
    findings = connector.run()
    assert len(findings) == 137
    assert connector.http.get_json.call_count == 3
    offsets = [call.kwargs["params"]["sysparm_offset"] for call in connector.http.get_json.call_args_list]
    assert offsets == [0, 500, 1000]
    assert not connector.ctx.stats.incomplete and not connector.ctx.stats.warnings


def test_servicenow_short_pages_up_to_the_page_bound_are_incomplete(index, monkeypatch):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    connector = _live(
        index,
        servicenow.ServiceNowConnector,
        [_snow_page(0, 100), _snow_page(100, 100), RuntimeError("guard against unbounded loop")],
        max_pages=2,
    )
    assert len(connector.run()) == 200
    assert connector.http.get_json.call_count == 2
    assert connector.ctx.stats.incomplete
    assert any("pagination limit reached" in warning for warning in connector.ctx.stats.warnings)


def test_servicenow_name_matching_timeout_preserves_native_agents(index, monkeypatch):
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    calls = 0

    def match_names(*_args):
        nonlocal calls
        calls += 1
        if calls == 37:
            raise MatchTimeoutError("untrusted display name must not be logged")
        return []

    monkeypatch.setattr(servicenow, "name_matches", match_names)
    page = {"result": [{"sys_id": f"agent-{number}", "name": "Assistant"} for number in range(500)]}
    connector = _live(index, servicenow.ServiceNowConnector, [page, {"result": []}])
    findings = connector.run()
    assert len(findings) == 500
    assert {finding.resource for finding in findings} == {
        f"servicenow:sn_aia_agent:agent-{number}" for number in range(500)
    }
    assert calls == 37  # remaining native records do not retry failed optional enrichment
    assert connector.http.get_json.call_count == 2
    assert connector.ctx.stats.incomplete
    assert len(connector.ctx.stats.warnings) == 1 and not connector.ctx.stats.errors
    assert "untrusted display name" not in " ".join(connector.ctx.stats.warnings)


def test_servicenow_flow_name_timeout_preserves_accumulated_native_agents(
    tmp_path, run_connector, monkeypatch
):
    match_names = Mock(side_effect=MatchTimeoutError("opaque input must not be logged"))
    monkeypatch.setattr(servicenow, "name_matches", match_names)
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [
                {"_table": "sn_aia_agent", "sys_id": "agent-1", "name": "Assistant"},
                {"_table": "sys_hub_flow", "sys_id": "flow-1", "name": "Now Assist flow"},
            ]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert {finding.resource for finding in findings} == {
        "servicenow:sn_aia_agent:agent-1",
        "servicenow:sys_hub_flow:flow-1",
    }
    assert match_names.call_count == 1
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1 and not ctx.stats.errors
    assert "opaque input" not in " ".join(ctx.stats.warnings)


def test_servicenow_oauth_timeout_preserves_accumulated_native_agents(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(servicenow, "name_matches", Mock(return_value=[]))
    match_app = Mock(side_effect=MatchTimeoutError("opaque input must not be logged"))
    monkeypatch.setattr(servicenow, "assess_app", match_app)
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [
                {"_table": "sn_aia_agent", "sys_id": "agent-1", "name": "Assistant"},
                {"_table": "oauth_entity", "sys_id": "oauth-1", "name": "AI app"},
                {"_table": "oauth_entity", "sys_id": "oauth-2", "name": "AI app"},
            ]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert {finding.resource for finding in findings} == {"servicenow:sn_aia_agent:agent-1"}
    assert match_app.call_count == 1
    assert ctx.stats.incomplete and len(ctx.stats.warnings) == 1 and not ctx.stats.errors
    assert "opaque input" not in " ".join(ctx.stats.warnings)


def test_servicenow_native_table_export_keeps_valid_neighbors(tmp_path, run_connector):
    source = tmp_path / "table.json"
    source.write_text(
        json.dumps(
            {
                "table": "sn_aia_agent",
                "result": [
                    "bad-row",
                    {"sys_id": "bad", "description": ["invalid"]},
                    {"sys_id": "agent-1", "name": "Assistant"},
                ],
            }
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert [f.resource for f in findings] == ["servicenow:sn_aia_agent:agent-1"]
    assert ctx.stats.incomplete and not ctx.stats.errors


def test_salesforce_malformed_token_keeps_bot_and_valid_token(tmp_path, run_connector):
    source = tmp_path / "salesforce.json"
    source.write_text(
        json.dumps(
            [
                {"attributes": {"type": "BotDefinition"}, "Id": "bot-1", "DeveloperName": "Assistant"},
                {
                    "attributes": {"type": "OauthToken"},
                    "AppName": "Claude",
                    "UserId": "user-1",
                    "UseCount": "not-a-count",
                },
                {
                    "attributes": {"type": "OauthToken"},
                    "AppName": "Claude",
                    "UserId": "user-2",
                    "UseCount": 2,
                },
            ]
        )
    )
    findings, ctx = run_connector("lowcode.salesforce", input=str(source))
    assert len(findings) == 2
    assert any(f.resource == "salesforce:bot:bot-1" for f in findings)
    assert ctx.stats.incomplete and not ctx.stats.errors


def test_servicenow_reference_uses_sys_id_before_display_name(tmp_path, run_connector):
    source = tmp_path / "servicenow.json"
    source.write_text(
        json.dumps(
            [
                {"_table": "sn_aia_agent", "sys_id": "agent-1", "name": "New display name"},
                {
                    "_table": "sn_aia_tool",
                    "sys_id": "tool-1",
                    "name": "Execute",
                    "tool_type": "script",
                    "agent": {"value": "agent-1", "display_value": "Old display name"},
                },
            ]
        )
    )
    findings, ctx = run_connector("lowcode.servicenow", input=str(source))
    assert len(findings) == 1 and not ctx.stats.incomplete
    assert "code-exec" in findings[0].capabilities
    assert findings[0].metadata["tools"] == [{"name": "Execute", "type": "script"}]


@pytest.mark.parametrize("markers", [{"done": False}, {"done": "true"}, {"nextRecordsUrl": "/next"}])
def test_salesforce_offline_query_continuation_preserves_partial_findings(tmp_path, run_connector, markers):
    source = tmp_path / "query.json"
    source.write_text(
        json.dumps(
            {
                "records": [
                    {"attributes": {"type": "BotDefinition"}, "Id": "bot-1", "DeveloperName": "Assistant"},
                ],
                **markers,
            }
        )
    )
    findings, ctx = run_connector("lowcode.salesforce", input=str(source))
    assert [f.resource for f in findings] == ["salesforce:bot:bot-1"]
    assert ctx.stats.incomplete


@pytest.mark.parametrize(
    "connector,empty",
    [
        ("lowcode.salesforce", {"records": [], "done": True}),
        ("lowcode.servicenow", {"table": "sn_aia_agent", "result": []}),
    ],
)
def test_explicit_empty_provider_exports_remain_complete(tmp_path, run_connector, connector, empty):
    source = tmp_path / "empty.json"
    source.write_text(json.dumps(empty))
    findings, ctx = run_connector(connector, input=str(source))
    assert not findings and not ctx.stats.incomplete


def test_salesforce_normal_query_pagination_is_complete(index, monkeypatch):
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "query")})
    connector = _live(
        index,
        salesforce.SalesforceConnector,
        [
            {
                "records": [{"Id": "bot-1", "DeveloperName": "Assistant"}],
                "done": False,
                "nextRecordsUrl": "/next",
            },
            {"records": [{"Id": "bot-2", "DeveloperName": "Assistant"}], "done": True},
        ],
    )
    assert len(connector.run()) == 2
    assert not connector.ctx.stats.incomplete
    assert connector.http.get_json.call_args.kwargs == {"params": None}


POWER_AI_FLOW = {
    "_kind": "flow",
    "name": "flow-ai",
    "properties": {
        "displayName": "Summarise with OpenAI",
        "connectionReferences": {"shared_openai": {"connectionName": "shared_openai"}},
    },
}


def test_power_platform_oversized_flow_keeps_valid_neighbours(tmp_path, run_connector):
    # A 3 MiB definition used to exhaust the matching budget and abort the
    # connector: 0 findings, even for valid flows after it.
    words = ["invoke", "openai", "api_key", "model=", "import", "tool", "{{", "}}", "https://example.com/x"]
    definition = " ".join(f"{words[i % len(words)]}_{i:x}" for i in range(320_000))
    assert len(definition) > 3 * 1024 * 1024
    big = {
        "_kind": "flow",
        "name": "flow-big",
        "properties": {"displayName": "Huge flow", "definition": definition},
    }
    export = tmp_path / "flows.json"
    export.write_text(json.dumps([big, POWER_AI_FLOW]))
    findings, ctx = run_connector("lowcode.power-platform", input=str(export))
    assert "Power Automate flow using OpenAI (independent publisher): Summarise with OpenAI" in [
        finding.title for finding in findings
    ]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("definition exceeds 300000 characters" in warning for warning in ctx.stats.warnings)


def test_power_platform_match_timeout_skips_only_that_record(tmp_path, run_connector, monkeypatch):
    from shadowscan.connectors.lowcode import power_platform

    real = power_platform.blob_matches

    def blob_matches(index, text, **kwargs):
        if "hostile-marker" in text:
            raise MatchTimeoutError("untrusted definition text must not be logged")
        return real(index, text, **kwargs)

    monkeypatch.setattr(power_platform, "blob_matches", blob_matches)
    hostile = {"_kind": "flow", "name": "flow-x", "properties": {"definition": {"note": "hostile-marker"}}}
    export = tmp_path / "flows.json"
    export.write_text(json.dumps([hostile, POWER_AI_FLOW]))
    findings, ctx = run_connector("lowcode.power-platform", input=str(export))
    assert [finding.title for finding in findings] == [
        "Power Automate flow using OpenAI (independent publisher): Summarise with OpenAI"
    ]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert ctx.stats.warnings == [
        "lowcode.power-platform: skipped a flow record that could not be analysed "
        "(MatchTimeoutError); coverage incomplete"
    ]


@pytest.mark.parametrize("graph", [{}, {"nodes": None}, {"nodes": {}}, {"nodes": [], "error": "denied"}])
def test_n8n_missing_or_invalid_graph_preserves_next_workflow(index, graph):
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(
        return_value=iter(
            [
                {"id": "bad", "name": "unknown", **graph},
                {
                    "id": "good",
                    "name": "assistant",
                    "nodes": [{"type": "@n8n/n8n-nodes-langchain.agent", "name": "Agent"}],
                },
            ]
        )
    )
    (finding,) = connector.run()
    assert finding.resource == "n8n:workflow:good"
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


def test_n8n_empty_graph_is_known_empty(index):
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([{"id": "empty", "name": "Empty", "nodes": []}]))
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_salesforce_never_requests_token_values_and_survives_expired_locators(index, monkeypatch):
    assert "DeleteToken" not in salesforce.QUERIES["OauthToken"][1]
    assert "AccessToken" not in salesforce.QUERIES["OauthToken"][1]
    ctx = context(index, instance_url="https://acme.my.salesforce.com", access_token="synthetic")
    connector = SalesforceConnector(ctx)
    monkeypatch.setattr(salesforce, "QUERIES", {"BotDefinition": ("data", "SELECT Id FROM BotDefinition")})
    monkeypatch.setattr(connector, "_auth", lambda: None)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"records": [{"Id": "1"}], "done": False, "nextRecordsUrl": "/services/data/v62.0/query/01g-2000"},
        HttpError(400, "https://acme.my.salesforce.com/services/data/v62.0/query/01g-2000"),
    ]
    assert list(connector.collect()) == [{"Id": "1", "_kind": "BotDefinition"}]
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete and any("collection incomplete (HTTP 400)" in w for w in ctx.stats.warnings)


def test_servicenow_pagination_stops_on_a_repeated_page(index, monkeypatch):
    ctx = context(index, instance="https://acme.service-now.com", token="synthetic")
    connector = ServiceNowConnector(ctx)
    monkeypatch.setattr(servicenow, "TABLES", {"sn_aia_agent": "sys_id,name"})
    monkeypatch.setattr(connector, "_auth", lambda: None)
    connector.http = Mock()
    # Every response is a fresh object, as it would be from the transport.
    connector.http.get_json.side_effect = lambda *args, **kwargs: {
        "result": [{"sys_id": str(i)} for i in range(kwargs["params"]["sysparm_limit"])]
    }
    records = list(connector.collect())
    assert len(records) == 500
    assert connector.http.get_json.call_count == 2
    assert ctx.stats.incomplete and any(
        "repeated pagination page" in warning for warning in ctx.stats.warnings
    )


def test_make_missing_blueprint_and_agents_marks_scan_incomplete(monkeypatch, run_connector):
    class MakeAPI:
        def __init__(self, *args, **kwargs):
            pass

        def get_json(self, path, params=None):
            if path == "/scenarios":
                return {
                    "scenarios": [
                        {"id": "with-blueprint", "name": "Classification flow"},
                        {"id": "without-blueprint", "name": "Routine backup"},
                    ]
                }
            if path == "/scenarios/with-blueprint/blueprint":
                return {"response": {"blueprint": {"flow": [{"module": "openai:CreateCompletion"}]}}}
            if path == "/scenarios/without-blueprint/blueprint":
                raise HttpError(403, "https://eu1.make.com/api/v2/scenarios/without-blueprint/blueprint")
            if path == "/ai-agents/v1/agents":
                raise HttpError(403, "https://eu1.make.com/api/v2/ai-agents/v1/agents")
            raise AssertionError(path)

    monkeypatch.setattr(automation, "HttpClient", MakeAPI)
    findings, ctx = run_connector(
        "lowcode.make", api_url="https://eu1.make.com/api/v2", token="dummy", team_id="team-1"
    )
    assert any(f.resource == "make:scenario:with-blueprint" for f in findings)
    assert ctx.stats.incomplete
    assert not ctx.stats.errors
    assert any("blueprints unreadable" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)
    assert any("AI agents unreadable" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)


def test_make_invalid_page_is_incomplete_not_fatal(index, monkeypatch):
    connector = MakeConnector(
        ConnectorContext(
            config={"api_url": "https://eu1.make.com/api/v2", "token": "synthetic", "team_id": "1"},
            index=index,
        )
    )
    http = Mock()
    http.get_json.side_effect = ValueError("Invalid JSON response")
    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=http))
    assert connector.run() == []
    assert not connector.ctx.stats.errors
    assert connector.ctx.stats.incomplete and connector.ctx.stats.warnings
