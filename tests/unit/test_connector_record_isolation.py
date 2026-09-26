"""One oversized or hostile record costs only itself, in every connector family."""

from __future__ import annotations

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.lowcode import automation
from shadowscan.connectors.lowcode.automation import ZapierConnector
from shadowscan.connectors.lowcode.power_platform import PowerPlatformConnector
from shadowscan.connectors.saas.atlassian import AtlassianConnector
from shadowscan.models import ScanStats
from shadowscan.signatures.matcher import MatchTimeoutError


def context(index, name, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector=name, started_at="2026-09-25T00:00:00Z")
    return ctx


def flow(name):
    return {"_kind": "flow", "id": name, "name": name, "properties": {"displayName": name, "definitionSummary": {
        "triggers": [{"type": "Request", "kind": "Http"}],
        "actions": [{"type": "OpenApiConnection", "swaggerOperationId": "CreateCompletion"}],
    }}}


def test_matcher_budget_failure_on_one_record_keeps_later_records(index, monkeypatch):
    ctx = context(index, "lowcode.power-platform", input="x")
    connector = PowerPlatformConnector(ctx)
    original = connector._flow_finding
    calls = []

    def flaky(rec):
        calls.append(rec["name"])
        if rec["name"] == "first":
            raise MatchTimeoutError("signature matching exceeded the input execution budget")
        return original(rec)

    monkeypatch.setattr(connector, "_flow_finding", flaky)
    list(connector.analyze([flow("first"), flow("second")]))
    assert calls == ["first", "second"]
    assert ctx.stats.incomplete is True
    assert any("flow analysis failed (MatchTimeoutError)" in w for w in ctx.stats.warnings)


def test_automation_definition_budget_failure_skips_only_that_workflow(index, monkeypatch):
    ctx = context(index, "lowcode.zapier", input="x")
    connector = ZapierConnector(ctx)
    real = automation.blob_matches
    names = []

    def flaky(idx, blob):
        names.append(blob)
        if "explode" in blob:
            raise MatchTimeoutError("budget")
        return real(idx, blob)

    monkeypatch.setattr(automation, "blob_matches", flaky)
    zaps = [
        {"id": 1, "title": "explode", "steps": [{"app": {"title": "ChatGPT"}}]},
        {"id": 2, "title": "fine", "steps": [{"app": {"title": "ChatGPT"}}]},
    ]
    findings = list(connector.analyze(zaps))
    assert [f.metadata.get("url") is None for f in findings] == [True]
    assert findings[0].title.endswith("fine")
    assert ctx.stats.incomplete is True


def test_scalar_list_settings_are_one_item_not_characters(index):
    ctx = context(index, "saas.atlassian", input="x", products="jira")
    assert AtlassianConnector(ctx).products == ["jira"]
    ctx = context(index, "lowcode.power-platform", input="x", environments="Default-1234")
    assert PowerPlatformConnector(ctx).only_envs == {"Default-1234"}


def test_salesforce_flow_budget_failure_keeps_later_flows(index, monkeypatch):
    from shadowscan.connectors.lowcode import salesforce
    from shadowscan.connectors.lowcode.salesforce import SalesforceConnector

    ctx = context(index, "lowcode.salesforce", instance="https://acme.my.salesforce.com", input="x")
    connector = SalesforceConnector(ctx)
    real = salesforce.name_matches

    def flaky(idx, *texts):
        if any(t and "Oversized" in t for t in texts):
            raise MatchTimeoutError("budget")
        return real(idx, *texts)

    monkeypatch.setattr(salesforce, "name_matches", flaky)
    flows = [
        {"_kind": "FlowDefinitionView", "Id": "1", "ApiName": "Oversized", "Label": "Oversized", "ProcessType": "Flow"},
        {"_kind": "FlowDefinitionView", "Id": "2", "ApiName": "Summary", "Label": "Einstein GPT summary", "ProcessType": "Flow"},
    ]
    findings = list(connector.analyze(flows))
    assert [f.title for f in findings] == ["Salesforce flow with AI hints: Einstein GPT summary"]
    assert ctx.stats.incomplete is True


def test_azure_list_failure_names_the_failing_collection(index):
    from unittest.mock import Mock

    from shadowscan.connectors.cloud.azure import AzureConnector
    from shadowscan.utils.http import HttpError

    ctx = context(index, "cloud.azure", input="x")
    connector = AzureConnector(ctx)
    connector.http = Mock()
    path = "/subscriptions/11111111-2222-3333-4444-555555555555/providers/Microsoft.CognitiveServices/accounts"
    connector.http.get_json.side_effect = HttpError(403, "https://management.azure.com" + path + "?api-version=1&$skiptoken=secret")
    assert not connector._list(path + "?$skiptoken=abc", "2024-10-01")
    assert len(ctx.stats.warnings) == 1
    assert path in ctx.stats.warnings[0] and "skiptoken" not in ctx.stats.warnings[0]
