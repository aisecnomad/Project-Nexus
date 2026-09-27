from __future__ import annotations

import json
import time

import jwt as pyjwt

from shadowscan.connectors.identity.entra import FIRST_PARTY_OWNER, EntraConnector
from shadowscan.models import Kind
from shadowscan.risk import assess
from shadowscan.utils.http import HttpError


def test_okta_fixture(run_connector, fixtures):
    findings, ctx = run_connector("identity.okta", input=str(fixtures / "identity" / "okta_apps.json"), org_url="https://acme.okta.com")
    assert not ctx.stats.errors
    by_title = {f.title: f for f in findings}
    otter = by_title["Okta OAuth app: Otter.ai Meeting Notes"]
    assert otter.kind == Kind.OAUTH_GRANT and "identity-app.meeting-notetakers" in otter.frameworks
    assert otter.metadata["consenting_users"] == 2 and "policy.data-access-scopes" in otter.tags
    svc = by_title["Okta service app: svc-agent-orchestrator"]
    assert svc.kind == Kind.SERVICE_IDENTITY and "machine-identity" in svc.tags and "delegation" in svc.tags
    assert "Intranet wiki" not in " ".join(by_title)  # bookmark app filtered


def test_entra_fixture(run_connector, fixtures):
    findings, ctx = run_connector("identity.entra", input=str(fixtures / "identity" / "entra_graph.json"), tenant_id="t")
    assert not ctx.stats.errors
    by_res = {f.resource: f for f in findings}
    otter = by_res["entra:sp:sp-1"]
    assert otter.kind == Kind.OAUTH_GRANT and otter.metadata["consenting_users"] == 2
    assert "OnlineMeetingTranscript.Read.All" in otter.permissions and "policy.data-access-scopes" in otter.tags
    agent = by_res["entra:sp:sp-2"]
    assert agent.kind == Kind.SERVICE_IDENTITY and "app-only-permissions" in agent.tags
    assert {"Mail.ReadWrite", "Files.ReadWrite.All"} <= set(agent.metadata["application_permissions"])  # role ids resolved to names
    assert "entra:sp:sp-4" not in by_res  # boring SSO app without AI / permission signals
    reg = by_res["entra:app:app-agent"]
    assert reg.kind == Kind.SERVICE_IDENTITY and "client-secret" in reg.tags


def test_google_workspace_aggregates_per_client(run_connector, fixtures):
    findings, _ = run_connector("identity.google-workspace", input=str(fixtures / "identity" / "google_tokens.json"))
    by_title = {f.title: f for f in findings}
    ff = by_title["Google Workspace OAuth app: Fireflies.ai Notetaker"]
    assert ff.metadata["user_count"] == 2 and "identity-app.meeting-notetakers" in ff.frameworks
    assert "https://www.googleapis.com/auth/gmail.readonly" in ff.permissions
    assert "Google Workspace OAuth app: Expense Tool" not in by_title


def test_auth0_m2m(run_connector, fixtures):
    findings, _ = run_connector("identity.auth0", input=str(fixtures / "identity" / "auth0_clients.json"), domain="acme.eu.auth0.com")
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == Kind.SERVICE_IDENTITY and "machine-identity" in f.tags and "write:tickets" in f.permissions


def test_jwt_classification(run_connector, fixtures):
    findings, ctx = run_connector("identity.jwt", input=str(fixtures / "identity" / "tokens.txt"))
    assert not ctx.stats.errors and len(findings) == 4
    by_type = {f.metadata["identity_type"]: f for f in findings}
    assert set(by_type) == {"service", "delegated-agent", "human"}  # two service tokens collapse into one key; check individually below
    types = sorted(f.metadata["identity_type"] for f in findings)
    assert types == ["delegated-agent", "human", "service", "service"]
    entra = next(f for f in findings if f.metadata["issuer_family"] == "entra")
    assert "token-hygiene" in entra.tags and entra.metadata["lifetime_hours"] == 72.0 and "policy.privileged-scopes" in entra.tags
    okta = next(f for f in findings if f.metadata["issuer_family"] == "okta")
    assert okta.metadata["identity_type"] == "delegated-agent" and "delegation" in okta.tags and okta.metadata["agent_claims"].get("agent_id") == "negotiator-7"
    human = next(f for f in findings if f.metadata["issuer_family"] == "google")
    assert human.confidence < 0.2 and human.owner == "alice@acme.com"
    for f in findings:
        assert f.resource.startswith("jwt:") and len(f.resource) == 20  # hash only, never the token


# Live collection coverage and requested versus granted identity permissions.
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


def test_jwt_nested_token_inside_agent_claim_is_sanitized_before_truncation(run_connector, tmp_path):
    inner = _token(iss="https://inner.example.test/", aud="b", sub="alice@example.test", pad="x" * 400)
    outer = _token(iss=_OKTA, sub="svc", cid="svc", obo={"assertion": inner})
    (finding,) = _jwt_findings(run_connector, tmp_path, outer)
    report = json.dumps(finding.to_dict())
    assert inner[:40] not in report and outer not in report
    assert "[REDACTED]" in finding.metadata["agent_claims"]["obo"]


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
