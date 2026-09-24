"""Microsoft Teams: org-catalog and store apps with bots / Copilot agents installed in teams.

Live (Microsoft Graph, app permissions ``AppCatalog.Read.All``, ``Team.ReadBasic.All``,
``TeamsAppInstallation.ReadForTeam.All``):

* ``/appCatalogs/teamsApps?$expand=appDefinitions($expand=bot)`` – custom (organization) apps
* ``/teams`` + ``/teams/{id}/installedApps?$expand=teamsApp,teamsAppDefinition`` – installations (capped)

Offline export: teamsApp objects (with ``appDefinitions``) and/or installedApps objects.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path

GRAPH = "https://graph.microsoft.com/v1.0"


class TeamsConnector(BaseConnector):
    name: ClassVar[str] = "saas.microsoft-teams"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "microsoft-teams"
    description: ClassVar[str] = "Teams apps (custom + store) with bots, message extensions and Copilot agents, plus their installations."
    config_keys: ClassVar[dict[str, str]] = {
        "tenant_id": "env AZURE_TENANT_ID",
        "client_id": "env AZURE_CLIENT_ID",
        "client_secret": "env AZURE_CLIENT_SECRET",
        "access_token": "pre-issued Graph token (env GRAPH_ACCESS_TOKEN)",
        "include_store": "also list store apps in the catalog (default false; installations always inspected)",
        "max_teams": "cap on teams whose installed apps are enumerated (default 300)",
        "input": "offline: JSON export of teamsApps / installedApps",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.tenant = ctx.get("tenant_id", env="AZURE_TENANT_ID")
        self.include_store = bool(ctx.get("include_store", False))
        self.max_teams = int(ctx.get("max_teams", 300))

    def _client(self) -> HttpClient:
        token = self.ctx.get("access_token", env="GRAPH_ACCESS_TOKEN")
        if not token:
            cid = self.ctx.get("client_id", env="AZURE_CLIENT_ID")
            secret = self.ctx.get("client_secret", env="AZURE_CLIENT_SECRET")
            if not (self.tenant and cid and secret):
                raise ConnectorError("saas.microsoft-teams: tenant_id, client_id, client_secret (or access_token) required")
            client = HttpClient()
            resp = client.post(f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token", data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret, "scope": "https://graph.microsoft.com/.default"})
            token = client.read_json_response(resp)["access_token"]
        return HttpClient(GRAPH, headers={"Authorization": f"Bearer {token}"})

    def _pages(self, http: HttpClient, path: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        try:
            yield from http.paginate_odata(path, **kwargs)
        except (HttpError, RequestException, RuntimeError, ValueError) as exc:
            status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
            self.ctx.warn(f"saas.microsoft-teams: collection incomplete for {path} ({status})")

    def collect(self) -> Iterable[dict[str, Any]]:
        http = self._client()
        flt = None if self.include_store else "distributionMethod eq 'organization'"
        params = {"$expand": "appDefinitions($expand=bot)"}
        if flt:
            params["$filter"] = flt
        for app in self._pages(http, "/appCatalogs/teamsApps", params=params):
            app["_kind"] = "teamsApp"
            yield app
        for n, team in enumerate(self._pages(http, "/teams", params={"$select": "id,displayName", "$top": 999})):
            if n >= self.max_teams:
                self.ctx.warn("saas.microsoft-teams: max_teams reached")
                break
            for inst in self._pages(http, f"/teams/{team['id']}/installedApps", params={"$expand": "teamsApp,teamsAppDefinition"}):
                inst["_kind"] = "installedApp"
                inst["_team"] = team.get("displayName")
                yield inst

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        apps: dict[str, dict[str, Any]] = {}
        installs: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                self.ctx.warn("saas.microsoft-teams: unsupported or malformed provider record; coverage incomplete")
                continue
            if kind == "teamsApp":
                apps[str(rec.get("id"))] = rec
            else:
                app = rec.get("teamsApp") or {}
                app_id = str(app.get("id") or get_path(rec, "teamsAppDefinition.teamsAppId") or rec.get("id"))
                installs.setdefault(app_id, []).append(rec)
                if app_id not in apps and app:
                    apps[app_id] = {**app, "appDefinitions": [rec.get("teamsAppDefinition")] if rec.get("teamsAppDefinition") else [], "_from_install": True}
        for app_id, app in apps.items():
            self.ctx.examined()
            try:
                f = self._app_finding(app_id, app, installs.get(app_id, []))
            except (AttributeError, TypeError, ValueError, KeyError, RecursionError, MatchTimeoutError) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"saas.microsoft-teams: skipped a malformed app record ({type(exc).__name__}){detail}")
                continue
            if f:
                yield f

    def _record_kind(self, rec: Any) -> str | None:
        """Check the fields analysis consumes without disclosing rejected values."""
        if not self._record_fields_valid(
            rec, strings=("_kind", "id", "displayName", "distributionMethod", "externalId", "_team"),
            mappings=("teamsApp", "teamsAppDefinition"), arrays=("appDefinitions",),
        ):
            return None
        kind = rec.get("_kind") or ("installedApp" if "teamsApp" in rec or "teamsAppDefinition" in rec else "teamsApp")
        if kind == "teamsApp":
            if not self._record_fields_valid(rec, required=("id",)):
                return None
            definitions = list(rec.get("appDefinitions") or [])
        elif kind == "installedApp":
            app = rec.get("teamsApp") or {}
            if not self._record_fields_valid(app, strings=("id", "displayName", "distributionMethod", "externalId")):
                return None
            identifiers = (app.get("id"), get_path(rec, "teamsAppDefinition.teamsAppId"), rec.get("id"))
            if not any(isinstance(value, str) and value.strip() for value in identifiers):
                return None
            definitions = [rec["teamsAppDefinition"]] if rec.get("teamsAppDefinition") else []
        else:
            return None
        return kind if all(self._definition_valid(definition) for definition in definitions) else None

    def _definition_valid(self, definition: Any) -> bool:
        if not self._record_fields_valid(
            definition,
            strings=("teamsAppId", "displayName", "description", "shortDescription", "version", "publishingState", "lastModifiedDateTime"),
            mappings=("bot", "authorization", "createdBy"),
        ):
            return False
        permissions = get_path(definition, "authorization.requiredPermissionSet.resourceSpecificPermissions")
        return permissions is None or (isinstance(permissions, list) and all(isinstance(item, dict) for item in permissions))

    def _app_finding(self, app_id: str, app: dict[str, Any], installs: list[dict[str, Any]]) -> Finding | None:
        defs = [d for d in app.get("appDefinitions") or [] if isinstance(d, dict)]
        latest = defs[-1] if defs else {}
        name = app.get("displayName") or latest.get("displayName") or app_id
        publisher = latest.get("publishingState") and latest.get("createdBy") or None
        bot = latest.get("bot") or {}
        perms: list[str] = []
        rsc = get_path(latest, "authorization.requiredPermissionSet.resourceSpecificPermissions") or []
        for p in rsc:
            if isinstance(p, dict) and p.get("permissionValue"):
                perms.append(p["permissionValue"])
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"Teams app{' with bot' if bot else ''}: {name}",
            resource=f"teams:app:{app_id}",
            resource_type="teams-app",
            provider="microsoft-teams",
            account=self.tenant,
            owner=get_path(latest, "createdBy.user.displayName", "createdBy.application.displayName"),
            first_seen=latest.get("lastModifiedDateTime"),
        )
        assess_app(self.index, f, name=name, publisher=str(publisher) if publisher else None, description=" ".join(x for x in [latest.get("description"), latest.get("shortDescription")] if x), scopes=perms, client_id=bot.get("id") if isinstance(bot, dict) else None)
        is_custom = app.get("distributionMethod") == "organization"
        if not f.frameworks and not bot and not is_custom:
            return None
        f.add_evidence(Evidence(signal="teams:app", description=f"{app.get('distributionMethod') or 'unknown'} app '{name}' v{latest.get('version') or '?'}{' with bot ' + str(bot.get('id')) if bot else ''}; installed in {len(installs)} team(s); RSC permissions: {', '.join(perms) or 'none'}", weight=0.35 if bot else 0.15))
        if bot:
            f.add_tag("bot")
            f.add_framework("framework.bot-framework")
        if is_custom:
            f.add_tag("custom-app")
        f.metadata.update({"distribution": app.get("distributionMethod"), "external_id": app.get("externalId"), "version": latest.get("version"), "bot_id": bot.get("id") if isinstance(bot, dict) else None, "publishing_state": latest.get("publishingState"), "installed_teams": sorted({str(i.get("_team")) for i in installs if i.get("_team")})[:20], "install_count": len(installs), "rsc_permissions": summarize_scopes(perms)})
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f
