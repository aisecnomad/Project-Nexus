"""The word "agent" alone is not an AI feature in low-code platforms."""

from __future__ import annotations

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.lowcode.automation import N8nConnector, ZapierConnector
from shadowscan.connectors.lowcode.salesforce import SalesforceConnector
from shadowscan.connectors.lowcode.servicenow import ServiceNowConnector
from shadowscan.models import Kind, ScanStats


def context(index, name, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector=name, started_at="2026-09-25T00:00:00Z")
    return ctx


def test_salesforce_flow_named_after_human_agents_is_not_an_ai_hint(index):
    connector = SalesforceConnector(context(index, "lowcode.salesforce", instance="https://acme.my.salesforce.com", input="x"))
    record = {"Id": "301", "ApiName": "Route_Case", "Label": "Route Case to Agent", "Description": "Assign the case to a support agent",
              "ProcessType": "AutoLaunchedFlow", "TriggerType": "RecordAfterSave"}
    assert connector._flow_finding(record) is None
    record["Label"] = "Einstein GPT case summarizer"
    finding = connector._flow_finding(record)
    assert finding is not None and finding.kind == Kind.WORKFLOW


def test_servicenow_flow_named_after_human_agents_is_not_an_ai_hint(index):
    connector = ServiceNowConnector(context(index, "lowcode.servicenow", instance="https://acme.service-now.com", input="x"))
    record = {"sys_id": "abc", "name": "Assign incident to agent", "description": "Route to the on-call agent", "type": "flow", "active": "true"}
    assert connector._flow_finding(record) is None
    record["description"] = "Uses Now Assist to summarize the incident"
    assert connector._flow_finding(record) is not None


def test_zapier_crm_named_agentbox_and_agent_titles_are_not_ai_agents(index):
    connector = ZapierConnector(context(index, "lowcode.zapier", input="x"))
    zap = {"id": 1, "title": "Notify agent on new lead", "steps": [{"app": {"title": "Agentbox"}}, {"app": {"title": "Slack"}}], "is_enabled": True}
    assert list(connector.analyze([zap])) == []
    zap = {"id": 2, "title": "Draft reply", "steps": [{"app": {"title": "Gmail"}}, {"app": {"title": "ChatGPT"}}], "is_enabled": True}
    findings = list(connector.analyze([zap]))
    assert [f.kind for f in findings] == [Kind.WORKFLOW]
    zap = {"id": 3, "title": "Support agent", "type": "agent", "instructions": "Answer tickets", "steps": [{"app": {"title": "Zendesk"}}]}
    assert [f.kind for f in connector.analyze([zap])] == [Kind.AGENT]


def test_n8n_manual_and_chat_triggers_are_not_autonomous(index):
    connector = N8nConnector(context(index, "lowcode.n8n", input="x"))
    workflow = {"id": "w1", "name": "Ask the agent", "active": True, "nodes": [
        {"type": "n8n-nodes-base.manualTrigger", "name": "When clicking", "parameters": {}},
        {"type": "@n8n/n8n-nodes-langchain.agent", "name": "AI Agent", "parameters": {}},
    ]}
    findings = list(connector.analyze([workflow]))
    assert [f.kind for f in findings] == [Kind.AGENT]
    assert "autonomous" not in findings[0].capabilities
    assert "event-triggered" not in findings[0].tags
    workflow["nodes"][0] = {"type": "n8n-nodes-base.scheduleTrigger", "name": "Every hour", "parameters": {}}
    findings = list(connector.analyze([workflow]))
    assert "autonomous" in findings[0].capabilities


def test_ai_qualified_flow_names_remain_ai_hints(index):
    salesforce = SalesforceConnector(context(index, "lowcode.salesforce", instance="https://acme.my.salesforce.com", input="x"))
    servicenow = ServiceNowConnector(context(index, "lowcode.servicenow", instance="https://acme.service-now.com", input="x"))
    for label in ("Route Case to AI Agent", "Chatbot escalation to support", "RAG knowledge lookup", "Autonomous agent handoff"):
        record = {"Id": "301", "ApiName": "X", "Label": label, "Description": "", "ProcessType": "Flow", "TriggerType": "RecordAfterSave"}
        assert salesforce._flow_finding(record) is not None, label
        assert servicenow._flow_finding({"sys_id": "a", "name": label, "description": "", "type": "flow"}) is not None, label
    for label in ("Route Case to Agent", "Assistant manager approval"):
        record = {"Id": "301", "ApiName": "X", "Label": label, "Description": "", "ProcessType": "Flow", "TriggerType": "RecordAfterSave"}
        assert salesforce._flow_finding(record) is None, label


def test_zap_titles_mentioning_ai_agents_need_an_ai_step(index):
    connector = ZapierConnector(context(index, "lowcode.zapier", input="x"))
    newsletter = {"id": 4, "title": "Weekly AI agents newsletter digest", "steps": [{"app": {"title": "RSS by Zapier"}}, {"app": {"title": "Email by Zapier"}}]}
    assert list(connector.analyze([newsletter])) == []
    triage = {"id": 5, "title": "AI agent ticket triage", "steps": [{"app": {"title": "Zendesk"}}, {"app": {"title": "ChatGPT"}}]}
    findings = list(connector.analyze([triage]))
    assert [f.kind for f in findings] == [Kind.AGENT]
    assert not any("Zapier Agent" in e.description for e in findings[0].evidence)


def test_make_scenario_owner_without_a_name_is_unknown_not_the_string_none(index):
    from shadowscan.connectors.lowcode.automation import MakeConnector

    connector = MakeConnector(context(index, "lowcode.make", input="x"))
    scenario = {"id": 9, "name": "Summarize tickets", "createdByUser": {"id": 7},
                "blueprint": {"name": "Summarize tickets", "flow": [{"module": "openai-gpt-3:CreateCompletion"}]}}
    findings = list(connector.analyze([scenario]))
    assert findings and findings[0].owner is None
