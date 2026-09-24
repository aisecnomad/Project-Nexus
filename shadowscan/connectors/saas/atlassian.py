"""Atlassian Cloud (Jira / Confluence): user-installed Marketplace & Forge apps, Rovo agents.

Live: Universal Plugin Manager ``GET /rest/plugins/1.0/`` (site admin, basic auth with API token)
on the Jira site and, if configured, the Confluence site (``/wiki/rest/plugins/1.0/``).
Optionally Atlassian Admin API ``GET /admin/v1/orgs/{orgId}/...`` is not required.

Offline export: UPM ``plugins`` array (or a list of app objects with name / key / vendor).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path


class AtlassianConnector(BaseConnector):
    name: ClassVar[str] = "saas.atlassian"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "atlassian"
    description: ClassVar[str] = "Marketplace / Forge apps installed on Jira & Confluence Cloud (AI assistants, Rovo agents, automation bots)."
    config_keys: ClassVar[dict[str, str]] = {
        "site": "https://<org>.atlassian.net (env ATLASSIAN_SITE)",
        "email": "site admin email (env ATLASSIAN_EMAIL)",
        "api_token": "API token (env ATLASSIAN_API_TOKEN)",
        "products": "list of jira|confluence to query (default both)",
        "input": "offline: UPM plugins JSON",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.site = str(ctx.get("site", env="ATLASSIAN_SITE") or "").rstrip("/")
        self.products = ctx.get("products") or ["jira", "confluence"]

    def collect(self) -> Iterable[dict[str, Any]]:
        email = self.ctx.get("email", env="ATLASSIAN_EMAIL")
        token = self.ctx.get("api_token", env="ATLASSIAN_API_TOKEN")
        if not (self.site and email and token):
            raise ConnectorError("saas.atlassian: site, email and api_token required")
        http = HttpClient(self.site, auth=(email, token))
        for product in self.products:
            path = "/rest/plugins/1.0/" if product == "jira" else "/wiki/rest/plugins/1.0/"
            try:
                data = http.get_json(path, params={"os_authType": "basic"}) or {}
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                reason = str(exc.status) if isinstance(exc, HttpError) else type(exc).__name__
                self.ctx.warn(f"saas.atlassian: {product} UPM not readable ({reason})")
                continue
            if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
                self.ctx.warn(f"saas.atlassian: {product} UPM returned an invalid collection")
                continue
            for p in data["plugins"]:
                if not isinstance(p, dict):
                    self.ctx.warn(f"saas.atlassian: {product} UPM returned an invalid plugin entry")
                    continue
                p["_product"] = product
                yield p

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for p in records:
            if not self._valid_provider_record(p):
                self.ctx.warn("saas.atlassian: unsupported or malformed app record; coverage incomplete")
                continue
            if not p.get("userInstalled", True) and not p.get("_force"):
                continue
            self.ctx.examined()
            f = self._app_finding(p)
            if f:
                yield f

    def _valid_provider_record(self, p: Any) -> bool:
        if not self._record_fields_valid(
            p, strings=("name", "key", "description", "version", "_product"),
            mappings=("links",), arrays=("scopes",),
        ):
            return False
        vendor = p.get("vendor")
        return (
            bool((p.get("key") or p.get("name") or "").strip())
            and (vendor is None or isinstance(vendor, str) or self._record_fields_valid(vendor, strings=("name", "link")))
            and self._record_fields_valid(p.get("links") or {}, strings=("self",))
            and all(isinstance(scope, str) for scope in (p.get("scopes") or []))
            and all(p.get(key) is None or isinstance(p[key], bool) for key in ("userInstalled", "enabled", "_force"))
        )

    def _app_finding(self, p: dict[str, Any]) -> Finding | None:
        name = p.get("name") or p.get("key")
        vendor = get_path(p, "vendor.name") or p.get("vendor")
        product = p.get("_product") or "jira"
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"Atlassian app ({product}): {name}",
            resource=f"atlassian:{product}:app:{p.get('key') or name}",
            resource_type="atlassian-app",
            provider="atlassian",
            account=self.site or None,
        )
        assess_app(self.index, f, name=name, publisher=str(vendor) if vendor else None, description=" ".join(x for x in [p.get("description"), p.get("key")] if x), urls=[get_path(p, "vendor.link"), get_path(p, "links.self")], scopes=[s for s in (p.get("scopes") or []) if isinstance(s, str)])
        if not f.frameworks:
            return None
        f.add_evidence(Evidence(signal="atlassian:app", description=f"{'Enabled' if p.get('enabled', True) else 'Disabled'} {'user-installed ' if p.get('userInstalled') else ''}app '{name}' ({p.get('key')}) by {vendor or 'unknown vendor'} v{p.get('version') or '?'}", weight=0.3))
        if p.get("enabled") is False:
            f.add_tag("disabled")
        f.metadata.update({"key": p.get("key"), "vendor": vendor, "version": p.get("version"), "enabled": p.get("enabled"), "user_installed": p.get("userInstalled"), "product": product})
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f
