"""Consolidated provider collection and deterministic report regressions."""

from __future__ import annotations

import json

import pytest
import responses
from requests import ConnectionError

from shadowscan.connectors.common import classify_permissions
from shadowscan.models import Finding, Kind, Surface


def _installation(**overrides):
    return {
        "id": 101,
        "app_id": 1001,
        "app_slug": "claude",
        "account": {"login": "acme"},
        "permissions": {"contents": "write"},
        "events": ["pull_request"],
        **overrides,
    }


def _pat(**overrides):
    return {
        "token_id": 501,
        "token_name": "Claude workflow",
        "owner": {"login": "developer"},
        "permissions": {"repository": {"contents": "write"}},
        **overrides,
    }


@responses.activate
def test_github_installation_denial_keeps_independent_billing_and_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", status=403, json={"message": "opaque-provider-secret"})
    responses.get(f"{base}/copilot/billing", json={"plan_type": "business", "seat_breakdown": {"total": 3}})
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:acme/copilot", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert any("installation inventory" in warning and "HTTP 403" in warning for warning in ctx.stats.warnings)
    assert "opaque-provider-secret" not in str(ctx.stats)
    assert len(responses.calls) == 3


@responses.activate
def test_github_failed_installation_continuation_preserves_pages_and_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(
        f"{base}/installations",
        json={"installations": [_installation()]},
        headers={"Link": f'<{base}/installations?page=2>; rel="next"'},
    )
    responses.get(f"{base}/installations", status=403)
    responses.get(f"{base}/copilot/billing", status=404)
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:installation:101", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(responses.calls) == 4


@pytest.mark.parametrize("billing", [[], {}, {"seat_breakdown": []}, {"error": "opaque-provider-secret"}])
@responses.activate
def test_github_malformed_billing_keeps_installations_and_pat(run_connector, billing):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"installations": [_installation()]})
    responses.get(f"{base}/copilot/billing", json=billing)
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert {f.resource for f in findings} == {"github:installation:101", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)


@responses.activate
def test_github_billing_network_failure_keeps_pat(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"installations": []})
    responses.get(f"{base}/copilot/billing", body=ConnectionError("opaque-provider-secret"))
    responses.get(f"{base}/personal-access-tokens", json=[_pat()])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert [f.resource for f in findings] == ["github:pat:501"]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)


@pytest.mark.parametrize("bad_record", [
    _installation(id={"invalid": "opaque-provider-secret"}),
    _installation(permissions={"contents": ["write"]}),
    _installation(events=[{"invalid": "opaque-provider-secret"}]),
    _installation(account=["invalid"]),
    _installation(app_slug={"invalid": "opaque-provider-secret"}),
    _pat(permissions={"repository": ["invalid"]}),
    _pat(owner={"login": ["invalid"]}),
    {"_kind": "unsupported", "app_slug": "claude"},
    {"_kind": "copilot_billing", "seat_breakdown": "invalid"},
])
def test_github_malformed_records_preserve_valid_neighbors(tmp_path, run_connector, bad_record):
    source = tmp_path / "github.json"
    source.write_text(json.dumps([bad_record, _installation(), _pat()]))

    findings, ctx = run_connector("saas.github-apps", input=str(source), org="acme")

    assert {f.resource for f in findings} == {"github:installation:101", "github:pat:501"}
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)


@responses.activate
def test_github_live_billing_kind_is_assigned_by_collector(run_connector):
    base = "https://api.github.com/orgs/acme"
    responses.get(f"{base}/installations", json={"installations": []})
    responses.get(f"{base}/copilot/billing", json={"_kind": "pat", "plan_type": "business", "seat_breakdown": {"total": 3}})
    responses.get(f"{base}/personal-access-tokens", json=[])

    findings, ctx = run_connector("saas.github-apps", org="acme", token="example-token")

    assert [f.resource for f in findings] == ["github:acme/copilot"]
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("container", [set, frozenset])
def test_unordered_permissions_have_stable_order(index, container):
    finding = Finding(surface=Surface.SAAS, connector="test", kind=Kind.BOT_APP, title="Agent", resource="test:agent", resource_type="app")
    scopes = container(["repo:write", "admin:org", "read:user"])

    classify_permissions(index, finding, scopes)

    assert finding.permissions == ["admin:org", "read:user", "repo:write"]


def test_ordered_permissions_preserve_provider_order(index):
    finding = Finding(surface=Surface.SAAS, connector="test", kind=Kind.BOT_APP, title="Agent", resource="test:agent", resource_type="app")

    classify_permissions(index, finding, ["repo:write", "read:user", "admin:org"])

    assert finding.permissions == ["repo:write", "read:user", "admin:org"]


@pytest.mark.parametrize("connector,bad,valid,resource", [
    ("saas.atlassian", {"key": "broken", "name": ["opaque-provider-secret"]}, {"key": "ai.glean", "name": "Glean AI"}, "atlassian:jira:app:ai.glean"),
    ("saas.atlassian", {"key": "broken", "description": ["opaque-provider-secret"]}, {"key": "ai.glean", "name": "Glean AI"}, "atlassian:jira:app:ai.glean"),
    ("saas.atlassian", {"key": "broken", "scopes": "read:confluence-content.all"}, {"key": "ai.glean", "name": "Glean AI"}, "atlassian:jira:app:ai.glean"),
    ("saas.atlassian", {"key": "broken", "vendor": {"link": ["opaque-provider-secret"]}}, {"key": "ai.glean", "name": "Glean AI"}, "atlassian:jira:app:ai.glean"),
    ("saas.zoom", {"app_id": "broken", "app_name": ["opaque-provider-secret"]}, {"app_id": "valid", "app_name": "Fathom AI Notetaker"}, "zoom:app:valid"),
    ("saas.zoom", {"app_id": "broken", "app_description": ["opaque-provider-secret"]}, {"app_id": "valid", "app_name": "Fathom AI Notetaker"}, "zoom:app:valid"),
    ("saas.zoom", {"app_id": "broken", "owner": {"name": "opaque-provider-secret"}}, {"app_id": "valid", "app_name": "Fathom AI Notetaker"}, "zoom:app:valid"),
    ("saas.zoom", {"app_id": "broken", "installed_users_count": -1}, {"app_id": "valid", "app_name": "Fathom AI Notetaker"}, "zoom:app:valid"),
])
def test_malformed_saas_apps_preserve_valid_neighbors(tmp_path, run_connector, connector, bad, valid, resource):
    source = tmp_path / "apps.json"
    source.write_text(json.dumps([bad, valid]))

    findings, ctx = run_connector(connector, input=str(source))

    assert [f.resource for f in findings] == [resource]
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert "opaque-provider-secret" not in str(ctx.stats)
