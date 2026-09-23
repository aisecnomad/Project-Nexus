"""Okta: OAuth/OIDC applications, service apps (client credentials), consent grants and user tokens.

Live API (SSWS token or OAuth bearer with ``okta.apps.read``):

* ``GET /api/v1/apps``                       – all applications
* ``GET /api/v1/apps/{id}/grants``           – OAuth 2.0 scope consent grants (admin granted)
* ``GET /api/v1/apps/{id}/tokens``           – refresh tokens users issued to the app (user consent)

Offline export: list of app objects, optionally with ``_grants`` and ``_tokens`` arrays embedded.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, identity_kind_for, summarize_scopes
from shadowscan.models import Evidence, Finding, Surface
from shadowscan.utils.http import HttpClient


class OktaConnector(BaseConnector):
    name: ClassVar[str] = "identity.okta"
    surface: ClassVar[Surface] = Surface.IDENTITY
    provider: ClassVar[str | None] = "okta"
    description: ClassVar[str] = "Okta applications, OAuth service apps, admin/user consent grants."
    config_keys: ClassVar[dict[str, str]] = {
        "org_url": "https://<org>.okta.com (env OKTA_ORG_URL)",
        "token": "SSWS API token (env OKTA_API_TOKEN) or set `bearer` for OAuth access token",
        "include_inactive": "include INACTIVE apps (default false)",
        "fetch_tokens": "call /tokens per OIDC app to count user consents (default true)",
        "input": "offline: JSON export of /api/v1/apps (with optional _grants/_tokens)",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.org_url = str(ctx.get("org_url", env="OKTA_ORG_URL") or "").rstrip("/")
        token = ctx.get("token", env="OKTA_API_TOKEN")
        bearer = ctx.get("bearer", env="OKTA_ACCESS_TOKEN")
        headers = {}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        elif token:
            headers["Authorization"] = f"SSWS {token}"
        self.http = HttpClient(self.org_url, headers=headers) if self.org_url else None
        self.include_inactive = bool(ctx.get("include_inactive", False))
        self.fetch_tokens = bool(ctx.get("fetch_tokens", True))

    def collect(self) -> Iterable[dict[str, Any]]:
        if not self.http or "Authorization" not in self.http.session.headers:
            raise ConnectorError("identity.okta: org_url and token (or bearer) are required")
        for app in self.http.paginate_link("/api/v1/apps", params={"limit": 200}):
            if app.get("status") != "ACTIVE" and not self.include_inactive:
                continue
            app_id = app["id"]
            if app.get("signOnMode") == "OPENID_CONNECT":
                app["_grants"] = self.http.try_get_json(f"/api/v1/apps/{app_id}/grants", default=[]) or []
                if self.fetch_tokens:
                    app["_tokens"] = list(self.http.paginate_link(f"/api/v1/apps/{app_id}/tokens", params={"limit": 200}))
            yield app

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for app in records:
            self.ctx.examined()
            f = self._app_finding(app)
            if f:
                yield f

    def _app_finding(self, app: dict[str, Any]) -> Finding | None:
        app_id = app.get("id") or app.get("name")
        label = app.get("label") or app.get("name") or str(app_id)
        oauth = ((app.get("settings") or {}).get("oauthClient") or {})
        creds = ((app.get("credentials") or {}).get("oauthClient") or {})
        grant_types = oauth.get("grant_types") or []
        app_type = oauth.get("application_type")
        machine = app_type == "service" or "client_credentials" in grant_types
        grants = app.get("_grants") or []
        tokens = app.get("_tokens") or []
        scopes: set[str] = set()
        for g in grants:
            if g.get("scopeId"):
                scopes.add(g["scopeId"])
        for t in tokens:
            for s in t.get("scopes") or []:
                scopes.add(s)
        users = {t.get("userId") for t in tokens if t.get("userId")}
        kind = identity_kind_for(user_consented=bool(users), machine=machine)
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=kind,
            title=f"Okta {'service app' if machine else 'OAuth app'}: {label}",
            resource=f"okta:app:{app_id}",
            resource_type="okta-application",
            provider="okta",
            account=self.org_url or None,
            first_seen=app.get("created"),
            last_seen=app.get("lastUpdated"),
        )
        urls = [oauth.get("initiate_login_uri"), *(oauth.get("redirect_uris") or []), *(oauth.get("post_logout_redirect_uris") or []), (app.get("_links") or {}).get("appLinks", [{}])[0].get("href") if isinstance((app.get("_links") or {}).get("appLinks"), list) else None]
        assess_app(
            self.index,
            f,
            name=label,
            description=app.get("name"),
            urls=urls,
            scopes=scopes,
            client_id=creds.get("client_id"),
            grant_types=grant_types,
            auth_method=creds.get("token_endpoint_auth_method"),
        )
        f.add_evidence(
            Evidence(
                signal="okta:app",
                description=f"{app.get('signOnMode')} application, status {app.get('status')}, type {app_type or 'n/a'}, grant types {', '.join(grant_types) or 'n/a'}",
                location=f"{self.org_url}/admin/app/{app.get('name')}/instance/{app_id}" if self.org_url else None,
                weight=0.15 if not machine else 0.35,
            )
        )
        if users:
            f.add_evidence(Evidence(signal="okta:user-consent", description=f"{len(users)} user(s) issued tokens to this app", weight=0.2))
        if app.get("signOnMode") not in {"OPENID_CONNECT", "SAML_2_0", "SAML_1_1", "WS_FEDERATION"} and not f.frameworks:
            # bookmark / SWA apps without AI signals are noise
            return None
        if not f.frameworks and not machine and not scopes:
            return None
        f.metadata.update(
            {
                "okta_name": app.get("name"),
                "sign_on_mode": app.get("signOnMode"),
                "status": app.get("status"),
                "application_type": app_type,
                "grant_types": grant_types,
                "client_id": creds.get("client_id"),
                "scopes": summarize_scopes(scopes),
                "consenting_users": len(users),
                "admin_grants": len(grants),
            }
        )
        finalize(f, self.index)
        f.kind = kind
        return f
