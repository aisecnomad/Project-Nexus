"""Salesforce: Agentforce agents, Einstein bots, prompt templates, connected apps and OAuth tokens.

Live (REST + Tooling API, API version 62.0+):

* ``BotDefinition`` / ``BotVersion``            – Einstein Bots and Agentforce agents (Type = Agent...)
* Tooling ``GenAiPlannerDefinition``, ``GenAiPluginDefinition``, ``GenAiFunctionDefinition``,
  ``GenAiPromptTemplate``                        – Agentforce topics / actions / prompt templates
* ``ConnectedApplication``                       – connected apps (OAuth clients) incl. AI vendors
* ``OauthToken``                                 – user-authorised connected apps (aggregated per app)
* ``FlowDefinitionView``                         – flows whose label/description mention AI / prompts

Auth: ``instance_url`` + ``access_token`` (env SFDC_INSTANCE_URL / SFDC_ACCESS_TOKEN) or a connected
app with the client-credentials flow (``client_id`` / ``client_secret``).

Offline export: SOQL/Tooling query results (records carry ``attributes.type``) or records with ``_kind``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import apply_matches, finalize, name_matches
from shadowscan.connectors.identity.common import assess_app
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path, truncate

API = "v62.0"

QUERIES: dict[str, tuple[str, str]] = {
    # kind: (api, soql)
    "BotDefinition": ("data", "SELECT Id, DeveloperName, MasterLabel, Description, CreatedDate, LastModifiedDate, CreatedBy.Name, LastModifiedBy.Name FROM BotDefinition"),
    "BotVersion": ("data", "SELECT Id, DeveloperName, BotDefinitionId, Status, VersionNumber, LastModifiedDate FROM BotVersion"),
    "GenAiPlannerDefinition": ("tooling", "SELECT Id, DeveloperName, MasterLabel, Description, CreatedDate, LastModifiedDate, CreatedBy.Name FROM GenAiPlannerDefinition"),
    "GenAiPluginDefinition": ("tooling", "SELECT Id, DeveloperName, MasterLabel, Description, CreatedDate, LastModifiedDate FROM GenAiPluginDefinition"),
    "GenAiFunctionDefinition": ("tooling", "SELECT Id, DeveloperName, MasterLabel, Description, InvocationTarget, InvocationTargetType, CreatedDate FROM GenAiFunctionDefinition"),
    "GenAiPromptTemplate": ("tooling", "SELECT Id, DeveloperName, MasterLabel, Description, Type, CreatedDate, LastModifiedDate, CreatedBy.Name FROM GenAiPromptTemplate"),
    "ConnectedApplication": ("data", "SELECT Id, Name, CreatedDate, LastModifiedDate, CreatedBy.Name, OptionsAllowAdminApprovedUsersOnly, OptionsRefreshTokenValidityMetric, MobileSessionTimeout FROM ConnectedApplication"),
    "OauthToken": ("data", "SELECT Id, AppName, UserId, User.Username, LastUsedDate, UseCount, CreatedDate, DeleteToken, AccessToken FROM OauthToken"),
    "FlowDefinitionView": ("data", "SELECT Id, ApiName, Label, Description, ProcessType, TriggerType, IsActive, ActiveVersionId, LastModifiedDate, LastModifiedBy FROM FlowDefinitionView WHERE IsActive = true"),
}


class SalesforceConnector(BaseConnector):
    name: ClassVar[str] = "lowcode.salesforce"
    surface: ClassVar[Surface] = Surface.LOWCODE
    provider: ClassVar[str | None] = "salesforce"
    description: ClassVar[str] = "Agentforce agents, Einstein bots, prompt templates, AI flows, connected apps and user OAuth tokens."
    config_keys: ClassVar[dict[str, str]] = {
        "instance_url": "https://<org>.my.salesforce.com (env SFDC_INSTANCE_URL)",
        "access_token": "session / OAuth token (env SFDC_ACCESS_TOKEN)",
        "client_id": "connected app consumer key for client-credentials flow (env SFDC_CLIENT_ID)",
        "client_secret": "env SFDC_CLIENT_SECRET",
        "api_version": f"default {API}",
        "input": "offline: JSON export of SOQL / Tooling query results",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.instance = str(ctx.get("instance_url", env="SFDC_INSTANCE_URL") or "").rstrip("/")
        self.api = str(ctx.get("api_version", API))
        self.http: HttpClient | None = None

    def _auth(self) -> None:
        if not self.instance:
            raise ConnectorError("lowcode.salesforce: instance_url is required")
        token = self.ctx.get("access_token", env="SFDC_ACCESS_TOKEN")
        if not token:
            cid = self.ctx.get("client_id", env="SFDC_CLIENT_ID")
            secret = self.ctx.get("client_secret", env="SFDC_CLIENT_SECRET")
            if not (cid and secret):
                raise ConnectorError("lowcode.salesforce: access_token or client_id/client_secret required")
            resp = HttpClient().post(f"{self.instance}/services/oauth2/token", data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret})
            token = resp.json()["access_token"]
        self.http = HttpClient(self.instance, headers={"Authorization": f"Bearer {token}"})

    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        assert self.http
        for kind, (api, soql) in QUERIES.items():
            path = f"/services/data/{self.api}/query" if api == "data" else f"/services/data/{self.api}/tooling/query"
            try:
                data = self.http.get_json(path, params={"q": soql})
            except HttpError as exc:
                self.log.debug("salesforce %s: %s", kind, exc)
                self.ctx.warn(f"lowcode.salesforce: {kind} not queryable ({exc.status})")
                continue
            while data:
                for rec in data.get("records", []):
                    rec["_kind"] = kind
                    yield rec
                nxt = data.get("nextRecordsUrl")
                data = self.http.get_json(nxt) if nxt else None

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        bots: dict[str, dict[str, Any]] = {}
        versions: dict[str, list[dict[str, Any]]] = {}
        planners: list[dict[str, Any]] = []
        plugins: list[dict[str, Any]] = []
        functions: list[dict[str, Any]] = []
        templates: list[dict[str, Any]] = []
        apps: list[dict[str, Any]] = []
        tokens: dict[str, dict[str, Any]] = {}
        for rec in records:
            kind = rec.get("_kind") or get_path(rec, "attributes.type") or ""
            if kind == "BotDefinition":
                bots[rec.get("Id") or rec.get("DeveloperName")] = rec
            elif kind == "BotVersion":
                versions.setdefault(rec.get("BotDefinitionId", ""), []).append(rec)
            elif kind == "GenAiPlannerDefinition":
                planners.append(rec)
            elif kind == "GenAiPluginDefinition":
                plugins.append(rec)
            elif kind == "GenAiFunctionDefinition":
                functions.append(rec)
            elif kind == "GenAiPromptTemplate":
                templates.append(rec)
            elif kind == "ConnectedApplication":
                apps.append(rec)
            elif kind == "OauthToken":
                agg = tokens.setdefault(rec.get("AppName", "?"), {"users": set(), "uses": 0, "last": None, "first": None})
                agg["users"].add(get_path(rec, "User.Username") or rec.get("UserId"))
                agg["uses"] += int(rec.get("UseCount") or 0)
                for k, field in (("last", "LastUsedDate"), ("first", "CreatedDate")):
                    v = rec.get(field)
                    if v and (agg[k] is None or (v > agg[k] if k == "last" else v < agg[k])):
                        agg[k] = v
            elif kind == "FlowDefinitionView":
                self.ctx.examined()
                f = self._flow_finding(rec)
                if f:
                    yield f
        for bid, bot in bots.items():
            self.ctx.examined()
            yield self._bot_finding(bot, versions.get(bid, []))
        for p in planners:
            self.ctx.examined()
            yield self._agentforce_finding("planner", p, plugins, functions)
        if templates:
            self.ctx.examined(len(templates))
            yield self._templates_finding(templates)
        for app in apps:
            self.ctx.examined()
            f = self._connected_app_finding(app, tokens.get(app.get("Name", "")))
            if f:
                yield f
        for app_name, agg in tokens.items():
            if any(a.get("Name") == app_name for a in apps):
                continue
            f = self._connected_app_finding({"Name": app_name, "_tokens_only": True}, agg)
            if f:
                yield f

    def _bot_finding(self, bot: dict[str, Any], versions: list[dict[str, Any]]) -> Finding:
        name = bot.get("MasterLabel") or bot.get("DeveloperName")
        active = [v for v in versions if v.get("Status") == "Active"]
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.AGENT,
            title=f"Salesforce bot/agent: {name}",
            resource=f"salesforce:bot:{bot.get('Id') or bot.get('DeveloperName')}",
            resource_type="bot-definition",
            provider="salesforce",
            account=self.instance or None,
            owner=get_path(bot, "CreatedBy.Name") or get_path(bot, "LastModifiedBy.Name"),
            first_seen=bot.get("CreatedDate"),
            last_seen=bot.get("LastModifiedDate"),
        )
        f.add_framework("platform.salesforce-agentforce")
        f.add_evidence(Evidence(signal="salesforce:bot", description=f"BotDefinition '{name}' ({bot.get('DeveloperName')}) with {len(active)} active version(s) of {len(versions)}", weight=0.9, signature="platform.salesforce-agentforce"))
        apply_matches(f, name_matches(self.index, name, bot.get("Description")), weight_scale=0.5)
        if active:
            f.add_tag("active")
        f.metadata.update({"developer_name": bot.get("DeveloperName"), "description": truncate(bot.get("Description")), "versions": len(versions), "active_versions": len(active)})
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f

    def _agentforce_finding(self, what: str, rec: dict[str, Any], plugins: list[dict[str, Any]], functions: list[dict[str, Any]]) -> Finding:
        name = rec.get("MasterLabel") or rec.get("DeveloperName")
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.AGENT,
            title=f"Agentforce agent ({what}): {name}",
            resource=f"salesforce:genai-{what}:{rec.get('Id') or rec.get('DeveloperName')}",
            resource_type=f"agentforce-{what}",
            provider="salesforce",
            account=self.instance or None,
            owner=get_path(rec, "CreatedBy.Name"),
            first_seen=rec.get("CreatedDate"),
            last_seen=rec.get("LastModifiedDate"),
        )
        f.add_framework("platform.salesforce-agentforce")
        f.add_capability("tool-use")
        f.add_capability("saas-actions")
        f.add_evidence(Evidence(signal="salesforce:genai-planner", description=f"GenAiPlannerDefinition '{name}'; org has {len(plugins)} topic(s) (GenAiPlugin) and {len(functions)} action(s) (GenAiFunction)", weight=0.95, signature="platform.salesforce-agentforce"))
        targets = sorted({str(fn.get("InvocationTargetType")) for fn in functions if fn.get("InvocationTargetType")})
        if any(t.lower() in {"apex", "flow", "externalservice", "prompt"} for t in targets):
            f.add_evidence(Evidence(signal="salesforce:actions", description=f"Actions invoke: {', '.join(targets)}", weight=0.3))
        if "apex" in {t.lower() for t in targets}:
            f.add_capability("code-exec")
        f.metadata.update({"developer_name": rec.get("DeveloperName"), "description": truncate(rec.get("Description")), "topics": [p.get("MasterLabel") or p.get("DeveloperName") for p in plugins][:30], "actions": [fn.get("MasterLabel") or fn.get("DeveloperName") for fn in functions][:50], "invocation_targets": targets})
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f

    def _templates_finding(self, templates: list[dict[str, Any]]) -> Finding:
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.FRAMEWORK_USAGE,
            title=f"Salesforce prompt templates ({len(templates)})",
            resource="salesforce:genai-prompt-templates",
            resource_type="prompt-templates",
            provider="salesforce",
            account=self.instance or None,
        )
        f.add_framework("platform.salesforce-agentforce")
        f.add_evidence(Evidence(signal="salesforce:prompt-templates", description=f"{len(templates)} GenAiPromptTemplate(s): {', '.join(str(t.get('MasterLabel') or t.get('DeveloperName')) for t in templates[:10])}", weight=0.6, signature="platform.salesforce-agentforce"))
        f.metadata["templates"] = [{"name": t.get("MasterLabel") or t.get("DeveloperName"), "type": t.get("Type"), "created_by": get_path(t, "CreatedBy.Name")} for t in templates[:100]]
        finalize(f, self.index)
        f.kind = Kind.FRAMEWORK_USAGE
        return f

    def _flow_finding(self, rec: dict[str, Any]) -> Finding | None:
        text = " ".join(str(rec.get(k) or "") for k in ("ApiName", "Label", "Description"))
        matches = name_matches(self.index, text)
        if not matches and not any(k in text.lower() for k in ("prompt", "einstein", "gpt", "agentforce", "llm", "generative")):
            return None
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.WORKFLOW,
            title=f"Salesforce flow with AI hints: {rec.get('Label') or rec.get('ApiName')}",
            resource=f"salesforce:flow:{rec.get('Id') or rec.get('ApiName')}",
            resource_type="flow",
            provider="salesforce",
            account=self.instance or None,
            owner=rec.get("LastModifiedBy"),
            last_seen=rec.get("LastModifiedDate"),
        )
        f.add_framework("platform.salesforce-agentforce")
        f.add_evidence(Evidence(signal="salesforce:flow", description=f"{rec.get('ProcessType')} flow (trigger {rec.get('TriggerType')}) whose name/description references AI: {truncate(text, 160)}", weight=0.4))
        apply_matches(f, matches, weight_scale=0.5)
        if rec.get("TriggerType") in {"Scheduled", "RecordAfterSave", "RecordBeforeSave", "PlatformEvent"}:
            f.add_capability("autonomous")
        f.metadata.update({"api_name": rec.get("ApiName"), "process_type": rec.get("ProcessType"), "trigger_type": rec.get("TriggerType")})
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _connected_app_finding(self, app: dict[str, Any], agg: dict[str, Any] | None) -> Finding | None:
        name = app.get("Name")
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.OAUTH_GRANT,
            title=f"Salesforce connected app: {name}",
            resource=f"salesforce:connected-app:{app.get('Id') or name}",
            resource_type="connected-app",
            provider="salesforce",
            account=self.instance or None,
            owner=get_path(app, "CreatedBy.Name"),
            first_seen=app.get("CreatedDate") or (agg or {}).get("first"),
            last_seen=(agg or {}).get("last") or app.get("LastModifiedDate"),
        )
        assess_app(self.index, f, name=name)
        if not f.frameworks:
            return None
        users = (agg or {}).get("users") or set()
        f.add_evidence(Evidence(signal="salesforce:connected-app", description=f"Connected app '{name}'" + (f" authorised by {len(users)} user(s), {agg['uses']} uses" if agg else "") + ("; admin-approved users only" if app.get("OptionsAllowAdminApprovedUsersOnly") else "; any user may self-authorise"), weight=0.3))
        if app.get("OptionsAllowAdminApprovedUsersOnly") is False:
            f.add_tag("self-authorisable")
        f.metadata.update({"users": len(users), "uses": (agg or {}).get("uses"), "admin_approved_only": app.get("OptionsAllowAdminApprovedUsersOnly"), "tokens_only": app.get("_tokens_only", False)})
        finalize(f, self.index)
        f.kind = Kind.OAUTH_GRANT
        return f
