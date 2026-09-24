"""Live collection must not mistake skipped pages for a complete inventory."""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from shadowscan.connectors.lowcode.power_platform import BAP, FLOW, PAPPS, PowerPlatformConnector
from shadowscan.utils.http import HttpClient, HttpError


def _env(name: str) -> dict:
    return {"name": name, "properties": {"displayName": name}}


def _app(name: str) -> dict:
    # Matches Microsoft's 2024-10-01 AdminApps response fields.
    return {
        "name": name,
        "properties": {
            "displayName": "AI-powered app",
            "owner": {"userPrincipalName": "owner@example.test"},
            "connectionReferences": [{"id": "/providers/Microsoft.PowerApps/apis/shared_openai"}],
        },
    }


def _flow(name: str) -> dict:
    return {
        "name": name,
        "properties": {"displayName": "AI flow", "connectionReferences": {"openai": "shared_openai"}},
    }


def _mock_live_power_api(monkeypatch, responder):
    calls: list[tuple[str, str, str, dict | None]] = []

    def token(self, scope):
        return scope  # Authentication is mocked; the requested audience stays observable.

    def get_json(self, path, *, params=None):
        calls.append((self.base_url, self.session.headers["Authorization"], path, params))
        return responder(self.base_url, path, params)

    monkeypatch.setattr(PowerPlatformConnector, "_token", token)
    monkeypatch.setattr(HttpClient, "get_json", get_json)
    return calls


def test_power_platform_collects_all_environment_pages_and_uses_separate_app_audience(monkeypatch, run_connector):
    def respond(base, path, params):
        if base == BAP:
            if "nextLink" in path:
                return {"value": [_env("env-2")]}
            return {"value": [_env("env-1")], "nextLink": BAP + "/environments?nextLink=2"}
        if base == FLOW:
            return {"value": [_flow("flow-1")]}
        assert base == PAPPS
        return {"value": [_app("app-1")]}

    calls = _mock_live_power_api(monkeypatch, respond)
    findings, ctx = run_connector("lowcode.power-platform", tenant_id="tenant", client_id="app", client_secret="secret", include_bots=False)

    assert not ctx.stats.incomplete
    assert len(findings) == 4
    assert {f.account for f in findings} == {"env-1", "env-2"}
    assert {f.owner for f in findings if f.resource_type == "power-app"} == {"owner@example.test"}
    bap_calls = [call for call in calls if call[0] == BAP]
    app_calls = [call for call in calls if call[0] == PAPPS]
    assert len(bap_calls) == 2
    assert len(app_calls) == 2
    assert bap_calls[1][3] is None  # Do not append first-page params to an absolute nextLink.
    assert all(call[1] == "Bearer https://service.powerapps.com/.default" for call in bap_calls)
    assert all(call[1] == "Bearer https://api.powerplatform.com/.default" for call in app_calls)
    assert all(urlsplit(call[2]).netloc == "api.powerplatform.com" for call in app_calls)
    assert all(call[3] == {"api-version": "2024-10-01", "$top": 250} for call in app_calls)


def test_power_platform_rejects_cross_origin_environment_continuation(monkeypatch, run_connector):
    def respond(base, path, params):
        if base == BAP:
            return {"value": [_env("env-1")], "nextLink": "https://attacker.example/collect?token=secret"}
        return {"value": [_app("app-1")]} if base == PAPPS else {"value": []}

    calls = _mock_live_power_api(monkeypatch, respond)
    findings, ctx = run_connector("lowcode.power-platform", tenant_id="tenant", client_id="app", client_secret="secret", include_bots=False)

    assert any(f.resource == "power-platform:app:app-1" for f in findings)
    assert ctx.stats.incomplete
    assert len([call for call in calls if call[0] == BAP]) == 1
    assert "attacker.example" not in " ".join(ctx.stats.errors)


def test_power_platform_app_later_page_failure_keeps_findings_and_scans_next_environment(monkeypatch, run_connector):
    def respond(base, path, params):
        if base == BAP:
            return {"value": [_env("env-1"), _env("env-2")]}
        if base == FLOW:
            return {"value": []}
        if "env-1" in path and "$skiptoken" in path:
            raise HttpError(403, PAPPS + "/powerapps/environments/env-1/apps?secret=do-not-log")
        if "env-1" in path:
            return {"value": [_app("first")], "nextLink": PAPPS + "/powerapps/environments/env-1/apps?$skiptoken=opaque"}
        return {"value": [_app("second")]}

    calls = _mock_live_power_api(monkeypatch, respond)
    findings, ctx = run_connector("lowcode.power-platform", tenant_id="tenant", client_id="app", client_secret="secret", include_bots=False)

    assert {f.resource for f in findings} == {"power-platform:app:first", "power-platform:app:second"}
    assert ctx.stats.incomplete
    assert any("apps in env-1: HTTP 403" in warning for warning in ctx.stats.warnings)
    assert all("secret=" not in warning for warning in ctx.stats.warnings)
    assert len([call for call in calls if call[0] == PAPPS]) == 3


@pytest.mark.parametrize(
    ("responses", "max_pages", "warning"),
    [
        ([{"results": [{"id": "bot-1", "type": "bot"}], "has_more": True}], 1000, "without next_cursor"),
        ([{"results": [{"id": "bot-1", "type": "bot"}], "has_more": True, "next_cursor": "same"},
          {"results": [{"id": "bot-2", "type": "bot"}], "has_more": True, "next_cursor": "same"}], 1000, "repeated users cursor"),
        ([{"results": [{"id": "bot-1", "type": "bot"}], "has_more": True, "next_cursor": "remaining"}], 1, "page limit"),
    ],
)
def test_notion_bad_continuation_or_page_cap_is_incomplete(monkeypatch, run_connector, responses, max_pages, warning):
    calls = []
    pages = iter(responses)

    def get_json(self, path, *, params):
        calls.append(params)
        return next(pages)

    monkeypatch.setattr(HttpClient, "get_json", get_json)
    findings, ctx = run_connector("saas.notion", token="test", max_pages=max_pages)

    assert {f.resource for f in findings} == {f"notion:bot:bot-{i}" for i in range(1, len(responses) + 1)}
    assert ctx.stats.incomplete
    assert warning in " ".join(ctx.stats.warnings)
    assert len(calls) == len(responses)


def test_notion_normal_pagination_is_complete(monkeypatch, run_connector):
    seen = []

    def get_json(self, path, *, params):
        seen.append(params)
        if "start_cursor" in params:
            return {"results": [{"id": "bot-2", "type": "bot"}], "has_more": False, "next_cursor": None}
        return {"results": [{"id": "bot-1", "type": "bot"}], "has_more": True, "next_cursor": "cursor-1"}

    monkeypatch.setattr(HttpClient, "get_json", get_json)
    findings, ctx = run_connector("saas.notion", token="test")

    assert not ctx.stats.incomplete
    assert {f.resource for f in findings} == {"notion:bot:bot-1", "notion:bot:bot-2"}
    assert seen == [{"page_size": 100}, {"page_size": 100, "start_cursor": "cursor-1"}]


@pytest.mark.parametrize(
    "page",
    [
        {"results": [{"id": "bot-1", "type": "bot"}], "next_cursor": "uncollected"},
        {"results": [{"id": "bot-1", "type": "bot"}], "has_more": "false", "next_cursor": "uncollected"},
        {"results": [{"id": "bot-1", "type": "bot"}], "has_more": 0},
    ],
)
def test_notion_missing_or_nonboolean_has_more_is_incomplete(monkeypatch, run_connector, page):
    calls = []

    def get_json(self, path, *, params):
        calls.append(params)
        return page

    monkeypatch.setattr(HttpClient, "get_json", get_json)
    findings, ctx = run_connector("saas.notion", token="test")

    assert [f.resource for f in findings] == ["notion:bot:bot-1"]
    assert ctx.stats.incomplete
    assert "invalid has_more" in " ".join(ctx.stats.warnings)
    assert len(calls) == 1
