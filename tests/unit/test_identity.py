from __future__ import annotations

from shadowscan.models import Kind


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
