"""Zoom: Marketplace apps installed on the account (meeting bots, note-takers, AI companions).

Live: Server-to-Server OAuth app (``account_id`` / ``client_id`` / ``client_secret``) with
``marketplace:read:admin``; ``GET /v2/marketplace/apps``.

Offline export: marketplace apps JSON (``apps`` array) or list of app objects.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient


class ZoomConnector(BaseConnector):
    name: ClassVar[str] = "saas.zoom"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "zoom"
    description: ClassVar[str] = "Zoom Marketplace apps installed on the account (meeting bots, AI note-takers)."
    config_keys: ClassVar[dict[str, str]] = {
        "account_id": "env ZOOM_ACCOUNT_ID",
        "client_id": "env ZOOM_CLIENT_ID",
        "client_secret": "env ZOOM_CLIENT_SECRET",
        "access_token": "pre-issued token (env ZOOM_ACCESS_TOKEN)",
        "input": "offline: marketplace apps JSON",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.account_id = ctx.get("account_id", env="ZOOM_ACCOUNT_ID")

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("access_token", env="ZOOM_ACCESS_TOKEN")
        if not token:
            cid = self.ctx.get("client_id", env="ZOOM_CLIENT_ID")
            secret = self.ctx.get("client_secret", env="ZOOM_CLIENT_SECRET")
            if not (self.account_id and cid and secret):
                raise ConnectorError("saas.zoom: account_id, client_id, client_secret (or access_token) required")
            client = HttpClient()
            resp = client.post("https://zoom.us/oauth/token", params={"grant_type": "account_credentials", "account_id": self.account_id}, auth=(cid, secret))
            token = client.read_json_response(resp)["access_token"]
        http = HttpClient("https://api.zoom.us/v2", headers={"Authorization": f"Bearer {token}"})
        for app_type in ("installed", "created"):
            try:
                for app in http.paginate_token("/marketplace/apps", params={"type": app_type, "page_size": 100}, items_key="apps", token_key="next_page_token", token_param="next_page_token"):
                    app["_type"] = app_type
                    yield app
            except Exception as exc:  # noqa: BLE001
                self.ctx.warn(f"saas.zoom: marketplace apps ({app_type}) not readable: {exc}")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for app in records:
            self.ctx.examined()
            f = self._app_finding(app)
            if f:
                yield f

    def _app_finding(self, app: dict[str, Any]) -> Finding | None:
        name = app.get("app_name") or app.get("name") or app.get("app_id")
        scopes = [s if isinstance(s, str) else s.get("name") for s in (app.get("scopes") or app.get("app_scopes") or [])]
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"Zoom app: {name}",
            resource=f"zoom:app:{app.get('app_id') or app.get('id') or name}",
            resource_type="zoom-marketplace-app",
            provider="zoom",
            account=self.account_id,
            owner=app.get("developer_name") or app.get("created_by") or app.get("owner"),
            first_seen=app.get("created_at") or app.get("install_date"),
        )
        assess_app(self.index, f, name=name, publisher=app.get("developer_name") or app.get("publisher"), description=app.get("app_description") or app.get("description"), urls=[app.get("app_url"), app.get("landing_page"), app.get("redirect_url")], scopes=[s for s in scopes if s])
        if not f.frameworks and not any(t.startswith("policy.") for t in f.tags):
            return None
        f.add_evidence(Evidence(signal="zoom:app", description=f"{app.get('_type') or app.get('app_type') or 'installed'} app '{name}' ({app.get('app_usage') or app.get('usage') or 'account'} usage); scopes {', '.join(s for s in scopes if s)[:300] or 'unknown'}; installed on {app.get('installed_users_count') or app.get('users_count') or '?'} users", weight=0.3))
        f.metadata.update({"app_id": app.get("app_id") or app.get("id"), "type": app.get("_type") or app.get("app_type"), "usage": app.get("app_usage"), "scopes": summarize_scopes([s for s in scopes if s]), "users": app.get("installed_users_count") or app.get("users_count"), "status": app.get("status")})
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f
