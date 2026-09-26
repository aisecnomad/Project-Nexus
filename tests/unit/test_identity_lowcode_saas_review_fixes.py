"""Regressions from the identity / low-code / SaaS production-readiness review.

Every value here is synthetic. Each test failed on the pre-review code.
"""

from __future__ import annotations

import json
import time
from unittest.mock import Mock

import jwt as pyjwt
import pytest
import responses

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.identity.google_workspace import GoogleWorkspaceConnector
from shadowscan.connectors.lowcode.automation import MakeConnector
from shadowscan.connectors.saas.atlassian import AtlassianConnector
from shadowscan.utils.http import HttpClient

_NOW = int(time.time())
_TEST_HMAC_KEY = "synthetic-test-only-hmac-key-0123456789abcdef"
_OKTA = "https://acme.okta.com/oauth2/default"


def _token(**claims):
    return pyjwt.encode({"iat": _NOW, "exp": _NOW + 3600, **claims}, _TEST_HMAC_KEY, algorithm="HS256")


def _offline(run_connector, tmp_path, name, payload, **config):
    path = tmp_path / f"{name.replace('.', '_')}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return run_connector(name, input=str(path), **config)


def _jwt_findings(run_connector, tmp_path, *tokens):
    findings, ctx = _offline(run_connector, tmp_path, "identity.jwt", [{"token": token} for token in tokens])
    assert not ctx.stats.errors and not ctx.stats.warnings
    return findings


def _type_weight(finding):
    return next(e.weight for e in finding.evidence if e.signal == f"jwt:{finding.metadata['identity_type']}")


# ---------------------------------------------------------------- finding 1
def test_jwt_naming_claim_presence_does_not_reclassify_human_token(run_connector, tmp_path):
    # Every Entra v1 delegated token carries app_displayname; Auth0/Okta add client_name.
    entra_v1 = _token(iss="https://sts.windows.net/tid/", aud="https://graph.microsoft.com", sub="AAAA", oid="u-1", upn="alice@example.test", name="Alice", appid="app-1", app_displayname="Graph Explorer", scp="User.Read")
    auth0 = _token(iss="https://acme.eu.auth0.com/", aud="api://x", sub="auth0|1", email="bob@example.test", client_name="Acme Web Portal")
    for finding in _jwt_findings(run_connector, tmp_path, entra_v1, auth0):
        assert finding.metadata["identity_type"] == "human"
        assert "agent-claims" not in finding.tags and finding.metadata["agent_claims"] == {}


def test_jwt_naming_claim_matching_an_ai_product_and_structural_keys_still_count(run_connector, tmp_path):
    notetaker = _token(iss=_OKTA, aud="api://x", sub="alice", email="alice@example.test", client_name="Otter.ai Meeting Notes")
    structural = _token(iss=_OKTA, aud="api://x", sub="alice", email="alice@example.test", agent_id="negotiator-7")
    findings = _jwt_findings(run_connector, tmp_path, notetaker, structural)
    assert [f.metadata["identity_type"] for f in findings] == ["agent", "agent"]
    assert findings[0].metadata["agent_claims"] == {"client_name": "Otter.ai Meeting Notes"}


# ---------------------------------------------------------------- finding 2
def test_jwt_agent_actor_on_user_token_is_delegated_agent(run_connector, tmp_path):
    base = {"iss": _OKTA, "aud": "api://tools", "sub": "alice@example.test", "email": "alice@example.test", "agent_id": "negotiator-7"}
    with_act, without_act, plain = _jwt_findings(
        run_connector, tmp_path,
        _token(**base, act={"sub": "svc-client"}),
        _token(**base),
        _token(iss=_OKTA, aud="api://tools", sub="alice@example.test", email="alice@example.test", act={"sub": "svc-client"}),
    )
    assert with_act.metadata["identity_type"] == "delegated-agent"
    assert without_act.metadata["identity_type"] == "agent"
    assert _type_weight(with_act) >= _type_weight(without_act)
    assert plain.metadata["identity_type"] == "delegated"  # no agent claims: plain delegation


# ---------------------------------------------------------------- finding 7
def test_jwt_nested_token_inside_agent_claim_is_sanitized_before_truncation(run_connector, tmp_path):
    inner = _token(iss="https://inner.example.test/", aud="b", sub="alice@example.test", pad="x" * 400)
    outer = _token(iss=_OKTA, sub="svc", cid="svc", obo={"assertion": inner})
    (finding,) = _jwt_findings(run_connector, tmp_path, outer)
    report = json.dumps(finding.to_dict())
    assert inner[:40] not in report and outer not in report
    assert "[REDACTED]" in finding.metadata["agent_claims"]["obo"]


# ---------------------------------------------------------------- finding 5
def test_google_workspace_unwraps_admin_sdk_token_list_envelope(run_connector, tmp_path):
    envelope = {"kind": "admin#directory#tokenList", "etag": "x", "items": [{
        "kind": "admin#directory#token", "clientId": "1234.apps.googleusercontent.com", "displayText": "Fireflies.ai Notetaker",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"], "userKey": "alice@example.test",
    }]}
    findings, ctx = _offline(run_connector, tmp_path, "identity.google-workspace", envelope, customer="C01234567")
    assert [f.title for f in findings] == ["Google Workspace OAuth app: Fireflies.ai Notetaker"]
    assert findings[0].metadata["user_count"] == 1
    assert not ctx.stats.warnings and not ctx.stats.incomplete


# --------------------------------------------------------------- finding 10
@responses.activate
def test_google_workspace_encodes_user_key_in_token_path(run_connector, monkeypatch):
    def auth(connector):
        connector.http = HttpClient("https://admin.googleapis.com")

    monkeypatch.setattr(GoogleWorkspaceConnector, "_auth", auth)
    responses.get("https://admin.googleapis.com/admin/directory/v1/customers/my_customer", json={"id": "C01234567"})
    responses.get("https://admin.googleapis.com/admin/directory/v1/users", json={"users": [{"primaryEmail": "a/b#c@example.test"}]})
    responses.get("https://admin.googleapis.com/admin/directory/v1/users/a%2Fb%23c@example.test/tokens", json={"kind": "admin#directory#tokenList"})
    findings, ctx = run_connector("identity.google-workspace")
    assert findings == [] and not ctx.stats.incomplete
    assert responses.calls[-1].request.path_url == "/admin/directory/v1/users/a%2Fb%23c@example.test/tokens"


# ---------------------------------------------------------------- finding 6
def test_entra_account_is_the_scanned_tenant_not_the_app_owner(run_connector, tmp_path):
    records = [
        {"_kind": "servicePrincipal", "id": "sp-1", "appId": "app-1", "displayName": "Otter.ai", "servicePrincipalType": "Application", "appOwnerOrganizationId": "vendor-tenant"},
        {"_kind": "oauth2PermissionGrant", "clientId": "sp-1", "consentType": "Principal", "principalId": "u1", "scope": "Mail.Read"},
    ]
    (without_tenant,), _ = _offline(run_connector, tmp_path, "identity.entra", records)
    (with_tenant,), _ = _offline(run_connector, tmp_path, "identity.entra", records, tenant_id="scanned-tenant")
    assert without_tenant.account is None
    assert without_tenant.metadata["owner_tenant"] == "vendor-tenant"
    assert with_tenant.account == "scanned-tenant" and with_tenant.metadata["owner_tenant"] == "vendor-tenant"


# ---------------------------------------------------------------- finding 3
@pytest.mark.parametrize("connector,body", [
    ("lowcode.n8n", {"message": "'X-N8N-API-KEY' header required"}),
    ("lowcode.make", {"detail": "Access denied", "message": "Access denied", "code": "IM002"}),
    ("lowcode.workato", {"message": "Unauthorized"}),
    ("saas.notion", {"object": "error", "status": 401, "code": "unauthorized", "message": "API token is invalid."}),
])
def test_provider_error_bodies_are_not_empty_inventories(run_connector, tmp_path, connector, body):
    findings, ctx = _offline(run_connector, tmp_path, connector, body)
    assert findings == []
    assert ctx.stats.incomplete and ctx.stats.warnings and not ctx.stats.errors


# ---------------------------------------------------------------- finding 4
_GOOD = {
    "lowcode.n8n": ({"id": "w1", "name": "Good workflow", "nodes": [{"name": "Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {"model": "gpt-4o"}}]}, "Good workflow"),
    "lowcode.workato": ({"id": 1, "name": "Good recipe", "code": "{\"provider\":\"openai\"}", "config": [{"provider": "openai"}]}, "Good recipe"),
    "lowcode.make": ({"_kind": "ai-agent", "id": "ag1", "name": "Good agent", "model": "gpt-4o"}, "Good agent"),
    "lowcode.zapier": ({"id": "z1", "title": "Claude summarizer", "steps": [{"app": {"title": "Anthropic (Claude)"}}]}, "Claude summarizer"),
    "saas.microsoft-teams": ({"id": "app-1", "displayName": "Copilot Helper Bot", "distributionMethod": "organization", "appDefinitions": [{"displayName": "Copilot Helper Bot", "bot": {"id": "bot-1"}}]}, "Copilot Helper Bot"),
    "saas.generic": ({"name": "ChatGPT", "scopes": ["drive.readonly"]}, "ChatGPT"),
    "saas.notion": ({"object": "user", "id": "n1", "type": "bot", "name": "Notion AI helper", "bot": {"owner": {"type": "workspace"}, "workspace_name": "Acme"}}, "Notion AI helper"),
}


@pytest.mark.parametrize("connector,bad,rejected", [
    ("lowcode.n8n", {"id": "w0", "name": "Bad", "nodes": ["not-a-node"]}, True),
    ("lowcode.workato", {"id": 0, "name": "Bad", "code": "{truncated", "config": []}, True),
    ("lowcode.workato", {"id": 0, "name": "Bad", "code": "", "config": 5}, True),
    ("lowcode.make", {"_kind": "ai-agent", "id": "ag0", "name": "Bad", "model": "gpt-4o", "tools": 5}, True),
    ("lowcode.make", {"_kind": "scenario", "id": 7, "name": "Bad", "blueprint": {"flow": 5}}, True),
    ("saas.microsoft-teams", {"id": "app-0", "displayName": "Bad", "appDefinitions": [{"bot": "not-a-dict"}]}, True),
    ("saas.microsoft-teams", {"id": "inst-0", "teamsApp": "not-a-dict", "teamsAppDefinition": {"teamsAppId": "x"}}, True),
    ("saas.notion", {"object": "user", "id": "n0", "type": "bot", "name": "Bad", "bot": "not-a-dict"}, True),
    # Scalar-typed fields are coerced to text instead of rejected; coverage stays complete.
    ("lowcode.zapier", {"id": "z0", "title": 123, "steps": []}, False),
    ("saas.generic", {"name": "Otter.ai", "scopes": ["admin", 5]}, False),
    ("saas.generic", {"name": "Otter.ai", "url": [123]}, False),
])
def test_one_malformed_record_does_not_abort_analysis(run_connector, tmp_path, connector, bad, rejected):
    good, title = _GOOD[connector]
    findings, ctx = _offline(run_connector, tmp_path, connector, [bad, good])
    assert not ctx.stats.errors
    assert any(title in f.title for f in findings)
    if rejected:
        assert ctx.stats.incomplete and ctx.stats.warnings
    else:
        assert not ctx.stats.incomplete and not ctx.stats.warnings


@responses.activate
def test_slack_non_dict_list_entries_are_skipped_not_fatal(run_connector):
    api = "https://slack.com/api"
    responses.get(f"{api}/team.info", json={"ok": True, "team": {"id": "T1", "name": "acme", "domain": "acme"}})
    responses.get(f"{api}/users.list", json={"ok": True, "members": ["garbage", {"id": "U1", "is_bot": True, "profile": {"api_app_id": "A1", "real_name": "Otter.ai"}}]})
    responses.get(f"{api}/admin.apps.approved.list", json={"ok": True, "approved_apps": [42, {"app": {"id": "A2", "name": "ChatGPT"}, "scopes": [{"name": "chat:write"}]}]})
    responses.get(f"{api}/admin.apps.restricted.list", json={"ok": True, "restricted_apps": []})
    responses.get(f"{api}/admin.apps.requests.list", json={"ok": True, "app_requests": []})
    responses.get(f"{api}/team.integrationLogs", json={"ok": True, "logs": ["garbage"], "paging": {"pages": 1}})
    findings, ctx = run_connector("saas.slack", token="xoxb-synthetic-test-token-000000")
    assert {f.title for f in findings} == {"Slack app (bot): Otter.ai", "Slack app: ChatGPT"}
    assert not ctx.stats.errors and ctx.stats.incomplete


# ---------------------------------------------------------------- finding 8
def test_atlassian_products_string_is_normalised_and_validated(index):
    assert AtlassianConnector(ConnectorContext(config={"products": "jira"}, index=index)).products == ["jira"]
    assert AtlassianConnector(ConnectorContext(config={"products": "confluence, jira"}, index=index)).products == ["confluence", "jira"]
    assert AtlassianConnector(ConnectorContext(config={}, index=index)).products == ["jira", "confluence"]
    with pytest.raises(ConnectorError):
        AtlassianConnector(ConnectorContext(config={"products": ["bitbucket"]}, index=index))


# ---------------------------------------------------------------- finding 9
def test_make_invalid_page_is_incomplete_not_fatal(index, monkeypatch):
    connector = MakeConnector(ConnectorContext(config={"api_url": "https://eu1.make.com/api/v2", "token": "synthetic", "team_id": "1"}, index=index))
    http = Mock()
    http.get_json.side_effect = ValueError("Invalid JSON response")
    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=http))
    assert connector.run() == []
    assert not connector.ctx.stats.errors
    assert connector.ctx.stats.incomplete and connector.ctx.stats.warnings
