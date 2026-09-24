"""Google's omitted empty lists require an identifiable collection envelope."""

from __future__ import annotations

import pytest
import responses

from shadowscan.connectors.identity.google_workspace import GoogleWorkspaceConnector
from shadowscan.utils.http import HttpClient

BASE = "https://admin.googleapis.com"


@pytest.fixture
def directory(monkeypatch):
    def auth(connector):
        connector.http = HttpClient(BASE)

    monkeypatch.setattr(GoogleWorkspaceConnector, "_auth", auth)


@pytest.mark.parametrize("body,complete", [
    ({"kind": "admin#directory#users"}, True),
    ({"users": []}, True),
    ({}, False),
    ({"error": "upstream failure"}, False),
    ({"kind": "admin#directory#users", "users": None}, False),
    ({"kind": "admin#directory#users", "nextPageToken": "more"}, False),
])
@responses.activate
def test_google_user_collection_shapes(directory, run_connector, body, complete):
    responses.get(f"{BASE}/admin/directory/v1/users", json=body)
    findings, ctx = run_connector("identity.google-workspace")
    assert findings == []
    assert ctx.stats.incomplete is not complete


@pytest.mark.parametrize("body,complete", [
    ({"kind": "admin#directory#tokenList"}, True),
    ({"items": []}, True),
    ({}, False),
    ({"kind": "unexpected"}, False),
    ({"kind": "admin#directory#tokenList", "items": None}, False),
    ({"kind": "admin#directory#tokenList", "error": "denied"}, False),
])
@responses.activate
def test_google_token_collection_shapes(directory, run_connector, body, complete):
    responses.get(f"{BASE}/admin/directory/v1/users", json={"users": [
        {"primaryEmail": "first@example.test"}, {"primaryEmail": "second@example.test"},
    ]})
    responses.get(f"{BASE}/admin/directory/v1/users/first@example.test/tokens", json=body)
    responses.get(f"{BASE}/admin/directory/v1/users/second@example.test/tokens", json={"items": [{
        "clientId": "client-1", "displayText": "Fireflies.ai",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
    }]})
    findings, ctx = run_connector("identity.google-workspace")
    assert len(findings) == 1
    assert findings[0].metadata["user_count"] == 1
    assert ctx.stats.incomplete is not complete


@responses.activate
def test_google_invalid_token_json_preserves_other_users(directory, run_connector):
    responses.get(f"{BASE}/admin/directory/v1/users", json={"users": [
        {"primaryEmail": "first@example.test"}, {"primaryEmail": "second@example.test"},
    ]})
    responses.get(f"{BASE}/admin/directory/v1/users/first@example.test/tokens", body="not JSON")
    responses.get(f"{BASE}/admin/directory/v1/users/second@example.test/tokens", json={"items": [{
        "clientId": "client-1", "displayText": "Fireflies.ai",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
    }]})
    findings, ctx = run_connector("identity.google-workspace")
    assert len(findings) == 1
    assert ctx.stats.incomplete
    assert not ctx.stats.errors
