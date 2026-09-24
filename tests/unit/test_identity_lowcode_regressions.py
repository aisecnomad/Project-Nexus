"""Live collection coverage and requested versus granted identity permissions."""

from __future__ import annotations

import json

from shadowscan.connectors.identity.entra import FIRST_PARTY_OWNER, EntraConnector
from shadowscan.connectors.identity.google_workspace import GoogleWorkspaceConnector
from shadowscan.connectors.lowcode import automation
from shadowscan.risk import assess
from shadowscan.utils.http import HttpError


def test_entra_assignment_denial_preserves_grants_but_marks_scan_incomplete(monkeypatch, run_connector):
    class Graph:
        def paginate_odata(self, path, params=None):
            if path == "/servicePrincipals":
                yield {"id": "sp-1", "appId": "agent-app", "displayName": "LangGraph agent", "servicePrincipalType": "Application"}
                return
            if path == "/oauth2PermissionGrants":
                yield {"clientId": "sp-1", "scope": "Mail.Read", "consentType": "AllPrincipals"}
                return
            if path.endswith("/appRoleAssignments"):
                raise HttpError(403, "https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/appRoleAssignments")
            assert path == "/applications"

    def fake_auth(self):
        self.http = Graph()

    monkeypatch.setattr(EntraConnector, "_auth", fake_auth)
    findings, ctx = run_connector("identity.entra", tenant_id="example-tenant")
    assert any(f.resource == "entra:sp:sp-1" and "Mail.Read" in f.permissions for f in findings)
    assert ctx.stats.incomplete
    assert not ctx.stats.errors
    assert "appRoleAssignments unreadable" in " ".join(ctx.stats.warnings)
    assert "HTTP 403" in " ".join(ctx.stats.warnings)


def test_entra_requested_permissions_are_not_reported_as_granted(tmp_path, run_connector, index):
    data = [
        {"_kind": "roleMap", "roles": {"role-id": "Directory.ReadWrite.All"}},
        {"_kind": "application", "id": "reg-1", "appId": "request-only", "displayName": "Ordinary scheduler", "requiredResourceAccess": [{"resourceAppId": "graph", "resourceAccess": [{"id": "role-id", "type": "Role"}]}]},
    ]
    source = tmp_path / "entra.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    findings, ctx = run_connector("identity.entra", input=str(source), tenant_id="example-tenant")
    assert not ctx.stats.incomplete
    assert len(findings) == 1  # requested privileged scope remains discoverable
    registration = findings[0]
    assert registration.metadata["requested_application_permissions"] == ["Directory.ReadWrite.All"]
    assert "policy.privileged-scopes" in registration.metadata["requested_permission_classes"]
    assert registration.permissions == []
    assert "policy.privileged-scopes" not in registration.tags
    assert "permissions-requested" in registration.tags
    assert "policy.privileged-scopes" not in {factor.id.removeprefix("tag:") for factor in assess(registration, index).factors}


def test_entra_resolves_requested_delegated_permission_ids_in_live_collection(monkeypatch, run_connector):
    class Graph:
        def paginate_odata(self, path, params=None):
            if path == "/servicePrincipals":
                yield {"id": "graph-sp", "appId": "graph", "displayName": "Microsoft Graph", "appOwnerOrganizationId": FIRST_PARTY_OWNER, "oauth2PermissionScopes": [{"id": "scope-id", "value": "Directory.ReadWrite.All"}]}
            elif path == "/applications":
                yield {"id": "reg-1", "appId": "request-only", "displayName": "Ordinary scheduler", "requiredResourceAccess": [{"resourceAppId": "graph", "resourceAccess": [{"id": "scope-id", "type": "Scope"}]}]}
            else:
                assert path == "/oauth2PermissionGrants"

    def fake_auth(self):
        self.http = Graph()

    monkeypatch.setattr(EntraConnector, "_auth", fake_auth)
    findings, ctx = run_connector("identity.entra", tenant_id="example-tenant")
    assert not ctx.stats.incomplete
    registration = next(f for f in findings if f.resource == "entra:app:request-only")
    assert registration.metadata["requested_delegated_scopes"] == ["Directory.ReadWrite.All"]
    assert registration.permissions == []
    assert "policy.privileged-scopes" not in registration.tags


def test_google_token_denial_marks_scan_incomplete_and_preserves_other_users(monkeypatch, run_connector):
    class Directory:
        def paginate_token(self, path, params=None, items_key=None, expected_empty_kind=None):
            assert path == "/admin/directory/v1/users"
            yield {"primaryEmail": "first@example.test"}
            yield {"primaryEmail": "second@example.test"}

        def get_json(self, path):
            if "second@example.test" in path:
                raise HttpError(403, "https://admin.googleapis.com/admin/directory/v1/users/second/tokens")
            return {"items": [{"clientId": "client-1", "displayText": "Fireflies.ai", "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]}]}

    def fake_auth(self):
        self.http = Directory()

    monkeypatch.setattr(GoogleWorkspaceConnector, "_auth", fake_auth)
    findings, ctx = run_connector("identity.google-workspace")
    assert len(findings) == 1
    assert findings[0].metadata["user_count"] == 1
    assert ctx.stats.incomplete
    assert "OAuth tokens unreadable for 1 user(s) (HTTP 403: 1)" in " ".join(ctx.stats.warnings)


def test_make_missing_blueprint_and_agents_marks_scan_incomplete(monkeypatch, run_connector):
    class MakeAPI:
        def __init__(self, *args, **kwargs):
            pass

        def get_json(self, path, params=None):
            if path == "/scenarios":
                return {"scenarios": [{"id": "with-blueprint", "name": "Classification flow"}, {"id": "without-blueprint", "name": "Routine backup"}]}
            if path == "/scenarios/with-blueprint/blueprint":
                return {"response": {"blueprint": {"flow": [{"module": "openai:CreateCompletion"}]}}}
            if path == "/scenarios/without-blueprint/blueprint":
                raise HttpError(403, "https://eu1.make.com/api/v2/scenarios/without-blueprint/blueprint")
            if path == "/ai-agents/v1/agents":
                raise HttpError(403, "https://eu1.make.com/api/v2/ai-agents/v1/agents")
            raise AssertionError(path)

    monkeypatch.setattr(automation, "HttpClient", MakeAPI)
    findings, ctx = run_connector("lowcode.make", api_url="https://eu1.make.com/api/v2", token="dummy", team_id="team-1")
    assert any(f.resource == "make:scenario:with-blueprint" for f in findings)
    assert ctx.stats.incomplete
    assert not ctx.stats.errors
    assert any("blueprints unreadable" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)
    assert any("AI agents unreadable" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)
