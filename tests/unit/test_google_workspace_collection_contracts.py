"""Google's omitted empty lists require an identifiable collection envelope."""

from __future__ import annotations

import json

import pytest
import responses

from shadowscan.connectors.identity.google_workspace import GoogleWorkspaceConnector
from shadowscan.utils.http import HttpClient, HttpError

BASE = "https://admin.googleapis.com"


@pytest.fixture
def directory(monkeypatch):
    def auth(connector):
        connector.http = HttpClient(BASE)
        responses.get(f"{BASE}/admin/directory/v1/customers/my_customer", json={"id": "C01234567"})

    monkeypatch.setattr(GoogleWorkspaceConnector, "_auth", auth)


@pytest.mark.parametrize(
    "body,complete",
    [
        ({"kind": "admin#directory#users"}, True),
        ({"users": []}, True),
        ({}, False),
        ({"error": "upstream failure"}, False),
        ({"kind": "admin#directory#users", "users": None}, False),
        ({"kind": "admin#directory#users", "nextPageToken": "more"}, False),
    ],
)
@responses.activate
def test_google_user_collection_shapes(directory, run_connector, body, complete):
    responses.get(f"{BASE}/admin/directory/v1/users", json=body)
    findings, ctx = run_connector("identity.google-workspace")
    assert findings == []
    assert ctx.stats.incomplete is not complete


@pytest.mark.parametrize(
    "body,complete",
    [
        ({"kind": "admin#directory#tokenList"}, True),
        ({"items": []}, True),
        ({}, False),
        ({"kind": "unexpected"}, False),
        ({"kind": "admin#directory#tokenList", "items": None}, False),
        ({"kind": "admin#directory#tokenList", "error": "denied"}, False),
    ],
)
@responses.activate
def test_google_token_collection_shapes(directory, run_connector, body, complete):
    responses.get(
        f"{BASE}/admin/directory/v1/users",
        json={
            "users": [
                {"primaryEmail": "first@example.test"},
                {"primaryEmail": "second@example.test"},
            ]
        },
    )
    responses.get(f"{BASE}/admin/directory/v1/users/first@example.test/tokens", json=body)
    responses.get(
        f"{BASE}/admin/directory/v1/users/second@example.test/tokens",
        json={
            "items": [
                {
                    "clientId": "client-1",
                    "displayText": "Fireflies.ai",
                    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                }
            ]
        },
    )
    findings, ctx = run_connector("identity.google-workspace")
    assert len(findings) == 1
    assert findings[0].metadata["user_count"] == 1
    assert ctx.stats.incomplete is not complete


@responses.activate
def test_google_invalid_token_json_preserves_other_users(directory, run_connector):
    responses.get(
        f"{BASE}/admin/directory/v1/users",
        json={
            "users": [
                {"primaryEmail": "first@example.test"},
                {"primaryEmail": "second@example.test"},
            ]
        },
    )
    responses.get(f"{BASE}/admin/directory/v1/users/first@example.test/tokens", body="not JSON")
    responses.get(
        f"{BASE}/admin/directory/v1/users/second@example.test/tokens",
        json={
            "items": [
                {
                    "clientId": "client-1",
                    "displayText": "Fireflies.ai",
                    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                }
            ]
        },
    )
    findings, ctx = run_connector("identity.google-workspace")
    assert len(findings) == 1
    assert ctx.stats.incomplete
    assert not ctx.stats.errors


def test_google_token_denial_marks_scan_incomplete_and_preserves_other_users(monkeypatch, run_connector):
    class Directory:
        def paginate_token(self, path, params=None, items_key=None, expected_empty_kind=None):
            assert path == "/admin/directory/v1/users"
            yield {"primaryEmail": "first@example.test"}
            yield {"primaryEmail": "second@example.test"}

        def get_json(self, path):
            if path == "/admin/directory/v1/customers/my_customer":
                return {"id": "C01234567"}
            if "second@example.test" in path:
                raise HttpError(403, "https://admin.googleapis.com/admin/directory/v1/users/second/tokens")
            return {
                "items": [
                    {
                        "clientId": "client-1",
                        "displayText": "Fireflies.ai",
                        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                    }
                ]
            }

    def fake_auth(self):
        self.http = Directory()

    monkeypatch.setattr(GoogleWorkspaceConnector, "_auth", fake_auth)
    findings, ctx = run_connector("identity.google-workspace")
    assert len(findings) == 1
    assert findings[0].metadata["user_count"] == 1
    assert ctx.stats.incomplete
    assert "OAuth tokens unreadable for 1 user(s) (HTTP 403: 1)" in " ".join(ctx.stats.warnings)


def _offline(run_connector, tmp_path, name, payload, **config):
    path = tmp_path / f"{name.replace('.', '_')}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return run_connector(name, input=str(path), **config)


def test_google_workspace_unwraps_admin_sdk_token_list_envelope(run_connector, tmp_path):
    envelope = {
        "kind": "admin#directory#tokenList",
        "etag": "x",
        "items": [
            {
                "kind": "admin#directory#token",
                "clientId": "1234.apps.googleusercontent.com",
                "displayText": "Fireflies.ai Notetaker",
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "userKey": "alice@example.test",
            }
        ],
    }
    findings, ctx = _offline(
        run_connector, tmp_path, "identity.google-workspace", envelope, customer="C01234567"
    )
    assert [f.title for f in findings] == ["Google Workspace OAuth app: Fireflies.ai Notetaker"]
    assert findings[0].metadata["user_count"] == 1
    assert not ctx.stats.warnings and not ctx.stats.incomplete


@responses.activate
def test_google_workspace_encodes_user_key_in_token_path(run_connector, monkeypatch):
    def auth(connector):
        connector.http = HttpClient("https://admin.googleapis.com")

    monkeypatch.setattr(GoogleWorkspaceConnector, "_auth", auth)
    responses.get(
        "https://admin.googleapis.com/admin/directory/v1/customers/my_customer", json={"id": "C01234567"}
    )
    responses.get(
        "https://admin.googleapis.com/admin/directory/v1/users",
        json={"users": [{"primaryEmail": "a/b#c@example.test"}]},
    )
    responses.get(
        "https://admin.googleapis.com/admin/directory/v1/users/a%2Fb%23c@example.test/tokens",
        json={"kind": "admin#directory#tokenList"},
    )
    findings, ctx = run_connector("identity.google-workspace")
    assert findings == [] and not ctx.stats.incomplete
    assert responses.calls[-1].request.path_url == "/admin/directory/v1/users/a%2Fb%23c@example.test/tokens"
