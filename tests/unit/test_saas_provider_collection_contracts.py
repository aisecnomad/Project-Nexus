"""Provider-shaped live responses must preserve findings and coverage status."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import responses


def _installation(app_id: int, slug: str) -> dict:
    return {
        "id": app_id,
        "app_id": app_id,
        "app_slug": slug,
        "account": {"login": "acme"},
        "repository_selection": "all",
        "permissions": {"contents": "write", "metadata": "read"},
        "events": ["pull_request"],
    }


@responses.activate
def test_github_apps_live_pages_billing_and_pat_are_separate_findings(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(
        f"{base}/installations",
        json={"total_count": 2, "installations": [_installation(101, "coderabbitai")]},
        headers={"Link": f'<{base}/installations?per_page=100&page=2>; rel="next"'},
    )
    responses.get(f"{base}/installations", json={"total_count": 2, "installations": [_installation(102, "claude")]})
    responses.get(
        f"{base}/copilot/billing",
        json={"plan_type": "business", "seat_breakdown": {"total": 5, "active_this_cycle": 3}},
    )
    responses.get(
        f"{base}/personal-access-tokens",
        json=[{
            "token_id": 501,
            "token_name": "Claude workflow",
            "owner": {"login": "dev"},
            "repository_selection": "selected",
            "permissions": {"repository": {"contents": "write"}},
        }],
    )

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-readonly-token")

    assert {f.resource for f in findings} == {
        "github:installation:101", "github:installation:102", "github:acme/copilot", "github:pat:501",
    }
    assert next(f for f in findings if f.resource == "github:installation:101").metadata["write_permissions"] == ["contents"]
    assert next(f for f in findings if f.resource == "github:pat:501").owner == "dev"
    assert ctx.stats.objects_examined == 4 and not ctx.stats.incomplete
    assert parse_qs(urlsplit(responses.calls[1].request.url).query) == {"per_page": ["100"], "page": ["2"]}


@responses.activate
def test_github_apps_optional_billing_denial_preserves_installations_and_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"total_count": 1, "installations": [_installation(101, "claude")]})
    responses.get(f"{base}/copilot/billing", status=403, json={"message": "Billing access denied"})
    responses.get(f"{base}/personal-access-tokens", json=[])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-readonly-token")

    assert [f.resource for f in findings] == ["github:installation:101"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("copilot/billing" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)
    assert len(responses.calls) == 3


@responses.activate
def test_github_apps_pat_denial_does_not_reclassify_partial_scan_as_complete(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"total_count": 1, "installations": [_installation(101, "claude")]})
    responses.get(f"{base}/copilot/billing", status=404)
    responses.get(f"{base}/personal-access-tokens", status=403)

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-readonly-token")

    assert [f.resource for f in findings] == ["github:installation:101"]
    assert ctx.stats.incomplete and ctx.stats.errors
    assert "example-readonly-token" not in str(ctx.stats.errors)


def _zoom_app(app_id: str, name: str) -> dict:
    # The Marketplace list endpoint supplies object-shaped scopes, not only strings.
    return {
        "app_id": app_id,
        "app_name": name,
        "app_description": "AI meeting notes",
        "app_type": "ZoomApp",
        "app_usage": 1,
        "app_status": "PUBLISHED",
        "app_directory_url": f"https://marketplace.zoom.us/apps/{app_id}",
        "scopes": [{"scope_name": "recording:read:admin", "scope_description": "Read recordings"}],
    }


@responses.activate
def test_zoom_live_uses_supported_categories_and_preserves_provider_scopes(run_connector):
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"apps": [_zoom_app("z1", "Fathom AI Notetaker")], "next_page_token": "next"})
    responses.get(url, json={"apps": [_zoom_app("z2", "Otter.ai")], "next_page_token": ""})
    responses.get(url, json={"apps": [_zoom_app("z3", "Claude meeting assistant")], "next_page_token": ""})

    findings, ctx = run_connector("saas.zoom", access_token="example-token", account_id="acme")

    assert {f.resource for f in findings} == {"zoom:app:z1", "zoom:app:z2", "zoom:app:z3"}
    assert {"recording:read:admin"} <= set(findings[0].permissions)
    assert findings[0].metadata["status"] == "PUBLISHED"
    assert findings[0].metadata["marketplace_category"] == "public"
    public_evidence = next(ev.description for ev in findings[0].evidence if ev.signal == "zoom:app")
    created_evidence = next(ev.description for ev in findings[2].evidence if ev.signal == "zoom:app")
    assert "approved public app" in public_evidence
    assert "installed" not in public_evidence.lower()
    assert "account-created app" in created_evidence
    assert not ctx.stats.incomplete and ctx.stats.objects_examined == 3
    queries = [parse_qs(urlsplit(call.request.url).query) for call in responses.calls]
    assert [query["type"] for query in queries] == [["public"], ["public"], ["account_created"]]
    assert queries[1]["next_page_token"] == ["next"]


@responses.activate
def test_zoom_partial_public_pagination_retains_records_and_collects_created_apps(run_connector):
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"apps": [_zoom_app("z1", "Fathom AI Notetaker")], "next_page_token": "next"})
    responses.get(url, status=403, json={"message": "insufficient scope"})
    responses.get(url, json={"apps": [_zoom_app("z2", "Otter.ai")], "next_page_token": ""})

    findings, ctx = run_connector("saas.zoom", access_token="example-token", account_id="acme")

    assert {f.resource for f in findings} == {"zoom:app:z1", "zoom:app:z2"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("public" in warning and "403" in warning for warning in ctx.stats.warnings)
    assert "example-token" not in str(ctx.stats.warnings)
    assert len(responses.calls) == 3


@responses.activate
def test_zoom_bad_collection_is_incomplete_even_when_created_apps_are_empty(run_connector):
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"error": "example-token"})
    responses.get(url, json={"apps": [], "next_page_token": ""})

    findings, ctx = run_connector("saas.zoom", access_token="example-token")

    assert findings == []
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "example-token" not in str(ctx.stats.warnings)
    assert len(responses.calls) == 2


@responses.activate
def test_zoom_server_to_server_token_exchange_uses_account_credentials(run_connector):
    responses.post("https://zoom.us/oauth/token", json={"access_token": "short-lived-token", "token_type": "bearer"})
    url = "https://api.zoom.us/v2/marketplace/apps"
    responses.get(url, json={"apps": [_zoom_app("z1", "Fathom AI Notetaker")], "next_page_token": ""})
    responses.get(url, json={"apps": [], "next_page_token": ""})

    findings, ctx = run_connector(
        "saas.zoom", account_id="acme", client_id="client-id", client_secret="example-secret",
    )

    assert [f.resource for f in findings] == ["zoom:app:z1"]
    assert not ctx.stats.incomplete
    auth_request = responses.calls[0].request
    assert parse_qs(urlsplit(auth_request.url).query) == {
        "grant_type": ["account_credentials"], "account_id": ["acme"],
    }
    assert auth_request.headers["Authorization"].startswith("Basic ")
    assert responses.calls[1].request.headers["Authorization"] == "Bearer short-lived-token"


@responses.activate
def test_zoom_rejected_token_exchange_cannot_be_reported_as_empty_inventory(run_connector):
    responses.post("https://zoom.us/oauth/token", json={"error": "invalid_client", "message": "example-secret"})

    findings, ctx = run_connector(
        "saas.zoom", account_id="acme", client_id="client-id", client_secret="example-secret",
    )

    assert findings == []
    assert ctx.stats.incomplete and ctx.stats.errors
    assert "example-secret" not in str(ctx.stats.errors)
    assert len(responses.calls) == 1


def test_zoom_malformed_scopes_keep_valid_neighbors_and_mark_incomplete(tmp_path, run_connector):
    first = _zoom_app("z1", "Fathom AI Notetaker")
    first["scopes"] = "invalid:scalar"
    second = _zoom_app("z2", "Otter.ai")
    second["scopes"] = [None, {"scope_name": "recording:read:admin"}]
    second["installed_users_count"] = 0
    source = tmp_path / "zoom-apps.json"
    source.write_text(json.dumps({"apps": [first, second]}))

    findings, ctx = run_connector("saas.zoom", input=str(source))

    assert {f.resource for f in findings} == {"zoom:app:z1", "zoom:app:z2"}
    assert "recording:read:admin" in findings[1].permissions
    assert "0 reported users" in next(ev.description for ev in findings[1].evidence if ev.signal == "zoom:app")
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(ctx.stats.warnings) == 2


@responses.activate
def test_atlassian_confluence_denial_preserves_jira_inventory(run_connector):
    base = "https://acme.atlassian.net"
    responses.get(f"{base}/rest/plugins/1.0/", json={"plugins": [
        {"key": "com.atlassian.rovo.agents", "name": "Rovo Agents", "userInstalled": True, "enabled": True},
        {"key": "plain-plugin", "name": "Plain dashboard", "userInstalled": True},
    ]})
    responses.get(f"{base}/wiki/rest/plugins/1.0/", status=403)

    findings, ctx = run_connector("saas.atlassian", site=base, email="admin@example.com", api_token="example-token")

    assert [f.resource for f in findings] == ["atlassian:jira:app:com.atlassian.rovo.agents"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("confluence" in warning and "403" in warning for warning in ctx.stats.warnings)
    assert "example-token" not in str(ctx.stats.warnings)
    assert len(responses.calls) == 2


@responses.activate
def test_atlassian_invalid_jira_collection_does_not_hide_valid_confluence_apps(run_connector):
    base = "https://acme.atlassian.net"
    responses.get(f"{base}/rest/plugins/1.0/", json={"message": "plugins missing"})
    responses.get(f"{base}/wiki/rest/plugins/1.0/", json={"plugins": [
        None,
        {"key": "ai.glean.confluence", "name": "Glean AI", "userInstalled": True},
    ]})

    findings, ctx = run_connector("saas.atlassian", site=base, email="admin@example.com", api_token="example-token")

    assert [f.resource for f in findings] == ["atlassian:confluence:app:ai.glean.confluence"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(ctx.stats.warnings) == 2
