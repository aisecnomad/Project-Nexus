"""Provider environment metadata cannot authorize a new credential destination."""

from __future__ import annotations

import pytest

from shadowscan.connectors.lowcode.power_platform import (
    BAP,
    FLOW,
    PAPPS,
    PowerPlatformConnector,
    _dataverse_origin,
)
from shadowscan.utils.http import HttpClient


def _environment(name: str, instance_url: str, *, domain: str = "acme", tenant: str = "tenant") -> dict:
    return {
        "name": name,
        "properties": {
            "tenantId": tenant,
            "linkedEnvironmentMetadata": {"instanceUrl": instance_url, "domainName": domain},
        },
    }


@pytest.mark.parametrize("host", [
    "acme.crm.dynamics.com",
    "acme.api.crm4.dynamics.com",
    "acme.crm.microsoftdynamics.de",
    "acme.crm.microsoftdynamics.us",
    "acme.crm.dynamics.cn",
    "acme.crm.appsplatform.us",
])
def test_dataverse_origin_accepts_documented_microsoft_organization_domains(host):
    url = f"https://{host}/"
    assert _dataverse_origin(url, _environment("env", url), "tenant") == f"https://{host}"


@pytest.mark.parametrize("url,domain,tenant", [
    ("https://attacker.example/", "acme", "tenant"),
    ("https://acme.crm.dynamics.com.attacker.example/", "acme", "tenant"),
    ("https://attacker.example@acme.crm.dynamics.com/", "acme", "tenant"),
    ("https://acme.crm.dynamics.com:444/", "acme", "tenant"),
    ("https://acme.crm.dynamics.com/path", "acme", "tenant"),
    ("https://acme.crm.dynamics.com/?sig=opaque", "acme", "tenant"),
    ("https://acme.crm.dynamics.com/#fragment", "acme", "tenant"),
    ("https://other.crm.dynamics.com/", "acme", "tenant"),
    ("https://acme.crm.dynamics.com/", "acme", "other-tenant"),
])
def test_dataverse_origin_rejects_unbound_destinations(url, domain, tenant):
    with pytest.raises(ValueError, match="Dataverse"):
        _dataverse_origin(url, _environment("env", url, domain=domain, tenant=tenant), "tenant")


@pytest.mark.parametrize("properties", [
    "malformed",
    {"linkedEnvironmentMetadata": "malformed"},
    {"linkedEnvironmentMetadata": 1},
    {"linkedEnvironmentMetadata": []},
])
def test_dataverse_origin_rejects_malformed_environment_metadata(properties):
    with pytest.raises(ValueError, match="Dataverse environment metadata"):
        _dataverse_origin("https://acme.crm.dynamics.com/", {"properties": properties}, "tenant")


@pytest.mark.parametrize(("bad_environment", "warning"), [
    ({"name": "malformed", "properties": {"linkedEnvironmentMetadata": "malformed"}}, "metadata is malformed"),
    ({"name": "malformed", "properties": {"linkedEnvironmentMetadata": 1}}, "metadata is malformed"),
    ({"name": "malformed", "properties": {"linkedEnvironmentMetadata": []}}, "metadata is malformed"),
    ({"name": "malformed", "properties": "malformed"}, "malformed provider record"),
    ({"name": "malformed", "properties": True}, "malformed provider record"),
])
def test_live_malformed_dataverse_metadata_marks_incomplete_and_scans_next_environment(
    bad_environment, warning, monkeypatch, run_connector,
):
    scopes: list[str] = []

    def token(self, scope):
        scopes.append(scope)
        return "synthetic-bearer"

    def get_json(self, path, *, params=None):
        if self.base_url == BAP:
            return {"value": [
                bad_environment,
                _environment("good", "https://acme.crm4.dynamics.com/"),
            ]}
        if self.base_url in (FLOW, PAPPS):
            return {"value": []}
        if path.endswith("/api/data/v9.2/bots"):
            return {"value": [{"botid": "bot-1", "name": "Known agent"}]}
        return {"value": []}

    monkeypatch.setattr(PowerPlatformConnector, "_token", token)
    monkeypatch.setattr(HttpClient, "get_json", get_json)
    findings, ctx = run_connector(
        "lowcode.power-platform", tenant_id="tenant", client_id="app", client_secret="secret",
    )

    assert any(f.resource == "power-platform:bot:bot-1" for f in findings)
    assert ctx.stats.incomplete
    assert any(warning in message for message in ctx.stats.warnings)
    assert [scope for scope in scopes if "crm" in scope] == ["https://acme.crm4.dynamics.com/.default"]


def test_hostile_environment_cannot_mint_or_receive_bearer_and_valid_environment_continues(monkeypatch, run_connector):
    calls: list[tuple[str, str, str]] = []
    scopes: list[str] = []

    def token(self, scope):
        scopes.append(scope)
        return "synthetic-bearer"

    def get_json(self, path, *, params=None):
        calls.append((self.base_url, self.session.headers.get("Authorization", ""), path))
        if self.base_url == BAP:
            return {"value": [
                _environment("bad", "https://attacker.example/"),
                _environment("good", "https://acme.crm4.dynamics.com/"),
            ]}
        if self.base_url in (FLOW, PAPPS):
            return {"value": []}
        if path.endswith("/api/data/v9.2/bots"):
            return {"value": [{"botid": "bot-1", "name": "Known agent"}]}
        return {"value": []}

    monkeypatch.setattr(PowerPlatformConnector, "_token", token)
    monkeypatch.setattr(HttpClient, "get_json", get_json)
    findings, ctx = run_connector(
        "lowcode.power-platform", tenant_id="tenant", client_id="app", client_secret="secret",
    )

    origin = "https://acme.crm4.dynamics.com"
    assert any(f.resource == "power-platform:bot:bot-1" for f in findings)
    assert ctx.stats.incomplete
    assert any("origin is untrusted" in warning for warning in ctx.stats.warnings)
    assert not any("attacker.example" in scope for scope in scopes)
    assert all(base != "https://attacker.example" for base, _, _ in calls)
    assert (origin, "Bearer synthetic-bearer", f"{origin}/api/data/v9.2/bots") in calls
    assert f"{origin}/.default" in scopes
