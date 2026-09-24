"""Zoom: Marketplace approved and account-created apps (meeting bots, note-takers).

Live: Server-to-Server OAuth app (``account_id`` / ``client_id`` / ``client_secret``) with
``marketplace:read:list_apps:admin``; ``GET /v2/marketplace/apps``.

Offline export: marketplace apps JSON (``apps`` array) or list of app objects.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError


class ZoomConnector(BaseConnector):
    name: ClassVar[str] = "saas.zoom"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "zoom"
    description: ClassVar[str] = "Zoom Marketplace approved and account-created apps (not a per-user installation inventory)."
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
        # Zoom's list-apps API exposes approved public apps and apps created by
        # the account. These are not proof that an individual installed an app.
        for app_type in ("public", "account_created"):
            try:
                for app in http.paginate_token("/marketplace/apps", params={"type": app_type, "page_size": 100}, items_key="apps", token_key="next_page_token", token_param="next_page_token"):
                    app["_type"] = app_type
                    yield app
            except Exception as exc:  # noqa: BLE001 - preserve the next independent category
                reason = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
                self.ctx.warn(f"saas.zoom: marketplace apps ({app_type}) not readable ({reason})")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for app in records:
            if not self._valid_provider_record(app):
                self.ctx.warn("saas.zoom: unsupported or malformed app record; coverage incomplete")
                continue
            self.ctx.examined()
            f = self._app_finding(app)
            if f:
                yield f

    def _valid_provider_record(self, app: Any) -> bool:
        if not self._record_fields_valid(
            app,
            strings=("app_id", "app_name", "name", "developer_name", "created_by", "owner", "publisher", "created_at", "install_date", "app_description", "description", "app_directory_url", "app_url", "landing_page", "redirect_url", "_type"),
        ):
            return False
        return (
            bool((app.get("app_id") or app.get("app_name") or app.get("name") or "").strip())
            and (app.get("id") is None or isinstance(app["id"], str) or type(app["id"]) is int)
            and all(app.get(key) is None or (type(app[key]) is int and app[key] >= 0) for key in ("installed_users_count", "users_count"))
        )

    def _app_finding(self, app: dict[str, Any]) -> Finding | None:
        name = app.get("app_name") or app.get("name") or app.get("app_id")
        raw_scopes = app.get("scopes") or app.get("app_scopes") or []
        if not isinstance(raw_scopes, list):
            self.ctx.warn("saas.zoom: invalid app scopes; coverage incomplete")
            raw_scopes = []
        scopes: list[str] = []
        for entry in raw_scopes:
            # Marketplace list responses use scope_name, while older exports
            # and some app detail responses contain strings or name objects.
            value = entry if isinstance(entry, str) else (entry.get("scope_name") or entry.get("name")) if isinstance(entry, dict) else None
            if isinstance(value, str) and value.strip():
                scopes.append(value.strip())
            else:
                self.ctx.warn("saas.zoom: invalid app scope entry; coverage incomplete")
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
        assess_app(self.index, f, name=name, publisher=app.get("developer_name") or app.get("publisher"), description=app.get("app_description") or app.get("description"), urls=[app.get("app_directory_url"), app.get("app_url"), app.get("landing_page"), app.get("redirect_url")], scopes=scopes)
        if not f.frameworks and not any(t.startswith("policy.") for t in f.tags):
            return None
        category = app.get("_type")
        if not isinstance(category, str):
            category = None
        source = (
            {"public": "approved public", "account_created": "account-created"}.get(category, "exported")
            if category else "exported"
        )
        users = app.get("installed_users_count")
        if users is None:
            users = app.get("users_count")
        description = f"{source} app '{name}' ({app.get('app_usage') or app.get('usage') or 'unknown'} usage); scopes {', '.join(scopes)[:300] or 'unknown'}"
        if users is not None:
            description += f"; {users} reported users"
        f.add_evidence(Evidence(signal="zoom:app", description=description, weight=0.3))
        f.metadata.update({"app_id": app.get("app_id") or app.get("id"), "type": category or app.get("app_type"), "app_type": app.get("app_type"), "marketplace_category": category, "usage": app.get("app_usage"), "scopes": summarize_scopes(scopes), "users": users, "status": app.get("app_status") or app.get("status")})
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f
