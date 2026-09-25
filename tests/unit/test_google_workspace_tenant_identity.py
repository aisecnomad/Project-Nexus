"""Synthetic tenant attribution contracts; these are not live acceptance tests."""

from __future__ import annotations

import json

import pytest
import responses
import yaml

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.identity.google_workspace import SCOPES
from shadowscan.engine import Engine
from shadowscan.models import Finding
from shadowscan.registry import Inventory, InventoryEntry, card_stub_for

BASE = "https://admin.googleapis.com/admin/directory/v1"
CUSTOMER = "C01234567"
TOKEN = {
    "clientId": "1234567890.apps.googleusercontent.com",
    "displayText": "Fireflies.ai Notetaker",
    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
}


def _provider_responses(customer_body=None, *, status=200, user_customer=CUSTOMER, customer_key="my_customer"):
    responses.get(f"{BASE}/customers/{customer_key}", json=customer_body if customer_body is not None else {"kind": "admin#directory#customer", "id": CUSTOMER}, status=status)
    responses.get(f"{BASE}/users", json={"kind": "admin#directory#users", "users": [
        {"kind": "admin#directory#user", "primaryEmail": "reviewer@example.test", "customerId": user_customer},
    ]})
    responses.get(f"{BASE}/users/reviewer@example.test/tokens", json={"kind": "admin#directory#tokenList", "items": [TOKEN]})


@responses.activate
def test_live_customer_alias_resolves_before_token_collection(run_connector):
    _provider_responses()
    findings, ctx = run_connector("identity.google-workspace", access_token="synthetic-google-token")
    assert not ctx.stats.incomplete and len(findings) == 1
    assert findings[0].account == CUSTOMER
    assert findings[0].identity_discriminator == "oauth-client"
    assert findings[0].resource == f"google-workspace:oauth-client:{TOKEN['clientId']}"
    assert responses.calls[0].request.url == f"{BASE}/customers/my_customer"
    assert all(call.request.headers["Authorization"] == "Bearer synthetic-google-token" for call in responses.calls)
    assert "https://www.googleapis.com/auth/admin.directory.customer.readonly" in SCOPES.split()
    assert not any(scope.endswith("/admin.directory.customer") for scope in SCOPES.split())


@responses.activate
def test_live_empty_user_collection_still_verifies_customer(run_connector):
    responses.get(f"{BASE}/customers/my_customer", json={"id": CUSTOMER})
    responses.get(f"{BASE}/users", json={"kind": "admin#directory#users"})
    findings, ctx = run_connector("identity.google-workspace", access_token="synthetic-google-token")
    assert not ctx.stats.incomplete and findings == []


@pytest.mark.parametrize("body,status", [
    ({"error": {"code": 403}}, 403),
    ({"error": "denied", "id": CUSTOMER}, 200),
    ({}, 200),
    ({"id": "my_customer"}, 200),
    ({"id": "example.test"}, 200),
    ({"id": None}, 200),
    ({"kind": "unexpected", "id": CUSTOMER}, 200),
    ([], 200),
])
@responses.activate
def test_unverified_live_customer_preserves_nonapprovable_evidence(run_connector, body, status):
    _provider_responses(body, status=status)
    findings, ctx = run_connector("identity.google-workspace", access_token="synthetic-google-token")
    assert ctx.stats.incomplete and len(findings) == 1
    finding = findings[0]
    assert finding.account is None
    assert finding.metadata["identity_unresolved"] is True
    assert card_stub_for(finding)["discovery"]["resources"] == []
    assert Inventory([InventoryEntry(agent_id="broad", resources=["*"])]).match(finding) is None


@pytest.mark.parametrize("source", ["customer-response", "user-response", "malformed-user-customer"])
@responses.activate
def test_customer_disagreement_cannot_confer_configured_tenant_approval(run_connector, source):
    _provider_responses(
        {"id": "C99999999"} if source == "customer-response" else {"id": CUSTOMER},
        customer_key=CUSTOMER,
        user_customer="C99999999" if source == "user-response" else (None if source == "malformed-user-customer" else CUSTOMER),
    )
    findings, ctx = run_connector("identity.google-workspace", customer=CUSTOMER, access_token="synthetic-google-token")
    assert ctx.stats.incomplete and len(findings) == 1
    assert findings[0].account is None
    assert findings[0].metadata["identity_unresolved"] is True


def test_same_public_client_in_two_tenants_never_merges_or_inherits_approval(tmp_path, index, fixtures):
    source = fixtures / "identity" / "google_workspace_scoped_tokens.json"
    connectors = [ConnectorSpec("identity.google-workspace", {"input": str(source), "customer": customer}) for customer in (CUSTOMER, "C99999999")]
    report = Engine(ScanConfig(connectors=connectors), index).run()
    assert report.complete and len(report.findings) == 2
    by_account = {finding.account: finding for finding in report.findings}
    first, second = by_account[CUSTOMER], by_account["C99999999"]
    assert first.resource == second.resource
    assert first.id != second.id

    card = card_stub_for(first)
    assert card["discovery"]["accounts"] == [CUSTOMER]
    path = tmp_path / "approval.yaml"
    path.write_text(yaml.safe_dump(card))
    inventory = Inventory.load([path])
    assert inventory.match(first) is not None
    assert inventory.match(second) is None
    reconciled = Engine(ScanConfig(connectors=connectors, inventory=[str(path)]), index).run()
    assert reconciled.complete and len(reconciled.findings) == 2
    assert {finding.account: finding.shadow for finding in reconciled.findings} == {CUSTOMER: False, "C99999999": True}

    # Historical generated approvals with accounts: [] must not silently
    # approve every customer now that the provider resolves their identities.
    old = Inventory([InventoryEntry(agent_id="historical", resources=[first.resource])])
    assert old.match(first) is None and old.match(second) is None


def test_unknown_offline_tenants_are_isolated_and_never_approve(tmp_path, fixtures, index):
    content = (fixtures / "identity" / "google_workspace_scoped_tokens.json").read_text()
    connectors = []
    for name in ("first", "second"):
        path = tmp_path / f"{name}.json"
        path.write_text(content)
        connectors.append(ConnectorSpec("identity.google-workspace", {"input": str(path)}))
    report = Engine(ScanConfig(connectors=connectors), index).run()
    assert not report.complete and len(report.findings) == 2
    assert len({finding.id for finding in report.findings}) == 2
    for finding in report.findings:
        assert finding.account is None
        assert finding.metadata["identity_unresolved"] is True
        assert card_stub_for(finding)["discovery"]["resources"] == []
        restored = Finding.from_dict(finding.to_dict())
        assert Inventory([InventoryEntry(agent_id="broad", resources=["*"])]).match(restored) is None


@pytest.mark.parametrize("customer_id,configured", [(CUSTOMER, False), ("C99999999", True), (None, True)])
def test_exported_customer_id_cannot_supply_or_override_trusted_scope(tmp_path, run_connector, customer_id, configured):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps([{"user": "reviewer@example.test", "customerId": customer_id, "tokens": [TOKEN]}]))
    config = {"customer": CUSTOMER} if configured else {}
    findings, ctx = run_connector("identity.google-workspace", input=str(path), **config)
    assert ctx.stats.incomplete and len(findings) == 1
    assert findings[0].account is None


def test_configured_offline_scope_can_be_corroborated_by_export(tmp_path, run_connector):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps([{"user": "reviewer@example.test", "customerId": CUSTOMER, "tokens": [{**TOKEN, "customerId": CUSTOMER}]}]))
    findings, ctx = run_connector("identity.google-workspace", input=str(path), customer=CUSTOMER)
    assert not ctx.stats.incomplete and findings[0].account == CUSTOMER


@pytest.mark.parametrize("customer", ["example.test", "admin@example.test", "", 123, "unknown", "C../tenant"])
def test_customer_configuration_never_accepts_domain_or_placeholder(run_connector, customer):
    with pytest.raises(ConnectorError, match="immutable customer ID"):
        run_connector("identity.google-workspace", customer=customer)
