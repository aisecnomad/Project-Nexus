"""Retain known identities when individual records or enrichment calls fail."""

from __future__ import annotations

import json

import pytest
import responses

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.identity.auth0 import Auth0Connector
from shadowscan.connectors.identity.okta import OktaConnector
from shadowscan.models import ScanStats, now_iso
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpClient


def _auth0_client(client_id="good"):
    return {"client_id": client_id, "name": "LangGraph worker", "app_type": "non_interactive"}


def _okta_app(app_id="good", **overrides):
    return {
        "id": app_id,
        "name": "oidc_client",
        "label": "Otter.ai worker",
        "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        **overrides,
    }


@pytest.mark.parametrize(
    "bad",
    [
        {"client_id": "bad", "client_metadata": ["invalid"]},
        {"client_id": ["bad"]},
        {"client_id": "bad", "grant_types": [1]},
        {"client_id": "bad", "callbacks": {"invalid": True}},
        {"name": "LangGraph agent"},
        {"error": "denied"},
    ],
)
def test_auth0_malformed_neighbor_preserves_valid_client(tmp_path, run_connector, bad):
    source = tmp_path / "clients.json"
    source.write_text(json.dumps([bad, _auth0_client()]))
    findings, ctx = run_connector("identity.auth0", input=str(source))
    assert [f.resource for f in findings] == ["auth0:client:good"]
    assert ctx.stats.incomplete
    assert bool(ctx.stats.errors) is ("error" in bad)


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "bad", "settings": ["invalid"]},
        {"id": "bad", "settings": {"oauthClient": {"grant_types": [1]}}},
        {"id": {"invalid": True}},
        {"error": "denied"},
    ],
)
def test_okta_malformed_neighbor_preserves_valid_app(tmp_path, run_connector, bad):
    source = tmp_path / "apps.json"
    source.write_text(json.dumps([bad, _okta_app()]))
    findings, ctx = run_connector("identity.okta", input=str(source))
    assert [f.resource for f in findings] == ["okta:app:good"]
    assert ctx.stats.incomplete
    assert bool(ctx.stats.errors) is ("error" in bad)


def test_okta_empty_app_links_is_valid(tmp_path, run_connector):
    source = tmp_path / "apps.json"
    source.write_text(json.dumps([_okta_app(_links={"appLinks": []})]))
    findings, ctx = run_connector("identity.okta", input=str(source))
    assert [f.resource for f in findings] == ["okta:app:good"]
    assert not ctx.stats.incomplete


@responses.activate
def test_auth0_grant_denial_keeps_collected_clients(monkeypatch, run_connector):
    def auth(self):
        self.http = HttpClient("https://tenant.auth0.com")

    monkeypatch.setattr(Auth0Connector, "_auth", auth)
    responses.get("https://tenant.auth0.com/api/v2/clients", json=[_auth0_client()])
    responses.get("https://tenant.auth0.com/api/v2/client-grants", status=403)
    findings, ctx = run_connector("identity.auth0")
    assert [f.resource for f in findings] == ["auth0:client:good"]
    assert ctx.stats.incomplete
    assert not ctx.stats.errors


@responses.activate
def test_auth0_repeated_page_is_bounded_and_preserves_clients(monkeypatch, run_connector):
    def auth(self):
        self.http = HttpClient("https://tenant.auth0.com")

    monkeypatch.setattr(Auth0Connector, "_auth", auth)
    # Keep pagination independent of name-signature matching under coverage.
    batch = [{**_auth0_client(str(i)), "name": f"Example {i}"} for i in range(100)]
    responses.get("https://tenant.auth0.com/api/v2/clients", json=batch)
    # End the regression run even before the fix instead of hanging forever.
    responses.get("https://tenant.auth0.com/api/v2/clients", json=batch)
    responses.get("https://tenant.auth0.com/api/v2/clients", json=[])
    responses.get("https://tenant.auth0.com/api/v2/client-grants", json=[])
    findings, ctx = run_connector("identity.auth0")
    missing = set(map(str, range(100))) - {f.metadata["client_id"] for f in findings}
    assert len(findings) == 100, (sorted(missing), ctx.stats.warnings)
    assert ctx.stats.incomplete
    assert len(responses.calls) == 3


@responses.activate
def test_auth0_page_cap_marks_inventory_incomplete(monkeypatch, run_connector):
    def auth(self):
        self.http = HttpClient("https://tenant.auth0.com")

    monkeypatch.setattr(Auth0Connector, "_auth", auth)
    responses.get(
        "https://tenant.auth0.com/api/v2/clients",
        json=[{**_auth0_client(str(i)), "name": f"Example {i}"} for i in range(100)],
    )
    responses.get("https://tenant.auth0.com/api/v2/clients", json=[])
    responses.get("https://tenant.auth0.com/api/v2/client-grants", json=[])
    findings, ctx = run_connector("identity.auth0", max_pages=1)
    assert len(findings) == 100
    assert ctx.stats.incomplete
    assert len(responses.calls) == 2


@responses.activate
def test_okta_grants_pagination_and_failed_enrichment_keep_apps(run_connector):
    base = "https://tenant.okta.com"
    responses.get(base + "/api/v1/apps", json=[_okta_app("first"), _okta_app("second")])
    responses.get(
        base + "/api/v1/apps/first/grants",
        json=[{"scopeId": "okta.users.read"}],
        headers={"Link": f'<{base}/api/v1/apps/first/grants?after=2>; rel="next"'},
    )
    responses.get(base + "/api/v1/apps/first/grants?after=2", json=[{"scopeId": "okta.groups.manage"}])
    responses.get(base + "/api/v1/apps/first/tokens", status=403)
    responses.get(base + "/api/v1/apps/second/grants", status=403)
    responses.get(base + "/api/v1/apps/second/tokens", json=[])
    findings, ctx = run_connector("identity.okta", org_url=base, token="dummy")
    assert {f.resource for f in findings} == {"okta:app:first", "okta:app:second"}
    first = next(f for f in findings if f.resource == "okta:app:first")
    assert {"okta.users.read", "okta.groups.manage"} <= set(first.permissions)
    assert ctx.stats.incomplete
    assert not ctx.stats.errors


def context(index, **config):
    ctx = ConnectorContext(index=index, config=config)
    ctx.stats = ScanStats(connector="test", started_at="now")
    return ctx


@pytest.mark.parametrize(
    "connector_class,method,records",
    [
        (
            Auth0Connector,
            "_client_finding",
            [{"client_id": "a"}, {"client_id": "b", "app_type": "non_interactive"}],
        ),
        (
            OktaConnector,
            "_app_finding",
            [
                {"id": "a"},
                {
                    "id": "b",
                    "signOnMode": "OPENID_CONNECT",
                    "settings": {"oauthClient": {"application_type": "service"}},
                },
            ],
        ),
    ],
)
def test_identity_match_timeout_is_isolated(index, monkeypatch, connector_class, method, records):
    ctx = context(index)
    connector = connector_class(ctx)
    original = getattr(connector, method)
    calls = 0

    def analyze(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise MatchTimeoutError("signature matching timed out (custom.pattern)")
        return original(*args)

    monkeypatch.setattr(connector, method, analyze)
    findings = list(connector.analyze(records))
    assert len(findings) == 1 and findings[0].resource.endswith(":b")
    assert ctx.stats.incomplete
    assert any("custom.pattern" in warning for warning in ctx.stats.warnings)


def _ctx(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at=now_iso())
    return ctx


def _okta_service_app(app_id: str, **overrides):
    app = {
        "id": app_id,
        "name": "oidc_client",
        "label": f"Service {app_id}",
        "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "settings": {"oauthClient": {"application_type": "service", "grant_types": ["client_credentials"]}},
        "credentials": {"oauthClient": {"client_id": f"client-{app_id}"}},
        "_grants": [{"scopeId": "okta.users.read"}],
        "_tokens": [],
    }
    app.update(overrides)
    return app


def test_okta_isolates_a_malformed_application_record(index):
    ctx = _ctx(index)
    connector = OktaConnector(ctx)
    records = [
        _okta_service_app("a"),
        _okta_service_app("b", settings="not-an-object"),
        _okta_service_app("c"),
    ]
    findings = list(connector.analyze(records))
    assert [f.title for f in findings] == ["Okta service app: Service a", "Okta service app: Service c"]
    assert ctx.stats.incomplete and any("malformed application record" in w for w in ctx.stats.warnings)


def test_auth0_isolates_a_malformed_client_record(index):
    ctx = _ctx(index)
    connector = Auth0Connector(ctx)
    good = {
        "_kind": "client",
        "client_id": "c1",
        "name": "support-agent-m2m",
        "app_type": "non_interactive",
        "grant_types": ["client_credentials"],
    }
    bad = {**good, "client_id": "c2", "name": "broken", "client_metadata": ["x"]}
    findings = list(connector.analyze([good, bad, {**good, "client_id": "c3", "name": "other-m2m"}]))
    assert len(findings) == 2
    assert ctx.stats.incomplete and any("malformed client or grant record" in w for w in ctx.stats.warnings)
