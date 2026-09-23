"""Generic SaaS app-inventory connector (offline exports from any admin console or CASB).

Feed it a CSV / JSON export of installed apps, OAuth grants or integrations from a
platform ShadowScan has no native connector for (Google Workspace Marketplace, HubSpot,
Box, Dropbox, Salesforce AppExchange, Okta Integration Network reports, Netskope /
Zscaler / Microsoft Defender for Cloud Apps discovered-app exports...). Column
names are mapped through ``fields``; sensible defaults cover common exports.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface

DEFAULT_FIELDS: dict[str, list[str]] = {
    "name": ["name", "app", "app_name", "application", "app name", "application name", "display_name", "displayName", "title", "integration", "product"],
    "id": ["id", "app_id", "client_id", "clientId", "application_id", "appId", "key"],
    "publisher": ["publisher", "vendor", "developer", "company", "owner_org", "provider"],
    "description": ["description", "category", "categories", "summary", "notes"],
    "url": ["url", "homepage", "website", "domain", "domains", "redirect_uri", "redirect_uris", "app_url"],
    "scopes": ["scopes", "scope", "permissions", "permission", "oauth_scopes", "access", "granted_scopes"],
    "users": ["users", "user_count", "num_users", "installs", "install_count", "seats", "user"],
    "owner": ["owner", "installed_by", "requested_by", "admin", "installer", "created_by", "user_email", "email"],
    "installed_at": ["installed_at", "created_at", "date", "first_seen", "install_date", "granted_at"],
    "last_used": ["last_used", "last_used_at", "last_activity", "last_seen", "updated_at"],
    "status": ["status", "state", "approval", "sanctioned", "risk", "risk_score"],
}


class GenericSaaSConnector(BaseConnector):
    name: ClassVar[str] = "saas.generic"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "saas"
    description: ClassVar[str] = "Offline app-inventory export from any SaaS admin console or CASB (column mapping via `fields`)."
    config_keys: ClassVar[dict[str, str]] = {
        "input": "CSV / JSON export (required)",
        "platform": "label for the platform the export came from (e.g. 'google-marketplace', 'hubspot', 'defender-mcas')",
        "fields": "optional column mapping {name: 'App Name', scopes: 'Permissions', ...}",
        "keep_all": "emit every app, not only AI / privileged matches (default false)",
    }
    offline_formats: ClassVar[str] = "CSV / JSON"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.platform = str(ctx.get("platform") or "saas")
        self.keep_all = bool(ctx.get("keep_all", False))
        user_fields = ctx.get("fields") or {}
        self.fields = {k: ([user_fields[k]] if k in user_fields else []) + v for k, v in DEFAULT_FIELDS.items()}

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError("saas.generic: offline only; set 'input' to an export file")

    def _get(self, rec: dict[str, Any], key: str) -> Any:
        lower = {str(k).lower(): v for k, v in rec.items()}
        for cand in self.fields[key]:
            if cand in rec and rec[cand] not in (None, ""):
                return rec[cand]
            if cand.lower() in lower and lower[cand.lower()] not in (None, ""):
                return lower[cand.lower()]
        return None

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            self.ctx.examined()
            f = self._finding(rec)
            if f:
                yield f

    def _finding(self, rec: dict[str, Any]) -> Finding | None:
        name = self._get(rec, "name")
        if not name:
            return None
        raw_scopes = self._get(rec, "scopes")
        scopes = raw_scopes if isinstance(raw_scopes, list) else [s.strip() for s in re.split(r"[,;\s]+", str(raw_scopes or "")) if s.strip()]
        urls = self._get(rec, "url")
        url_list = urls if isinstance(urls, list) else [u.strip() for u in re.split(r"[,;\s]+", str(urls or "")) if u.strip()]
        app_id = self._get(rec, "id")
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.OAUTH_GRANT if scopes else Kind.BOT_APP,
            title=f"{self.platform} app: {name}",
            resource=f"{self.platform}:app:{app_id or name}",
            resource_type="saas-app",
            provider=self.platform,
            owner=str(self._get(rec, "owner") or "") or None,
            first_seen=str(self._get(rec, "installed_at") or "") or None,
            last_seen=str(self._get(rec, "last_used") or "") or None,
        )
        assess_app(self.index, f, name=str(name), publisher=str(self._get(rec, "publisher") or "") or None, description=str(self._get(rec, "description") or "") or None, urls=url_list, scopes=scopes, client_id=str(app_id) if app_id else None)
        interesting = bool(f.frameworks) or any(t.startswith("policy.") for t in f.tags)
        if not interesting and not self.keep_all:
            return None
        users = self._get(rec, "users")
        try:
            user_count = int(str(users).replace(",", "")) if users is not None and str(users).replace(",", "").isdigit() else None
        except ValueError:
            user_count = None
        f.add_evidence(Evidence(signal=f"{self.platform}:app", description=f"'{name}' from {self.platform} export; status {self._get(rec, 'status') or 'n/a'}; users {user_count if user_count is not None else users or '?'}; scopes {', '.join(scopes)[:300] or 'n/a'}", weight=0.2 + (min(0.2, user_count / 500) if user_count else 0)))
        f.metadata.update({"platform": self.platform, "status": self._get(rec, "status"), "users": user_count if user_count is not None else users, "scopes": summarize_scopes(scopes)})
        finalize(f, self.index)
        f.sanitize()
        return f
