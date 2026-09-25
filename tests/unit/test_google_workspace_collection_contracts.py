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
