"""Microsoft Power Platform: Copilot Studio agents, Power Automate flows and Power Apps using AI.

Live (Entra app registered as a Power Platform *application user* / tenant admin):

* environments – ``api.bap.microsoft.com`` admin API
* flows        – ``api.flow.microsoft.com`` admin listing per environment (connection references reveal
                 ``shared_openai`` / ``shared_azureopenai`` / ``shared_aibuilder`` / ``shared_microsoftcopilotstudio``...)
* apps         – ``api.powerplatform.com`` admin listing (connection references)
* bots         – Dataverse ``bots`` + ``botcomponents`` of each environment (Copilot Studio agents, topics,
                 generative-answer components, actions, authentication mode)

Offline export: records carrying ``_kind`` (environment | flow | app | bot | botcomponent) or the raw
API objects (kind inferred from shape).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, ClassVar
from urllib.parse import quote

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import apply_matches, blob_matches, finalize, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path

BAP = "https://api.bap.microsoft.com"
FLOW = "https://api.flow.microsoft.com"
PAPPS = "https://api.powerplatform.com"

AI_CONNECTORS = {
    "shared_openai": "OpenAI (independent publisher)",
    "shared_azureopenai": "Azure OpenAI",
    "shared_aibuilder": "AI Builder",
    "shared_microsoftcopilotstudio": "Copilot Studio",
    "shared_chatgpt": "ChatGPT",
    "shared_cognitiveservicestextanalytics": "Azure AI Language",
    "shared_cognitiveservicescomputervision": "Azure AI Vision",
    "shared_azuredocumentintelligence": "Azure Document Intelligence",
    "shared_googlegemini": "Google Gemini",
    "shared_huggingface": "Hugging Face",
    "shared_perplexity": "Perplexity",
    "shared_mistral": "Mistral",
    "shared_anthropic": "Anthropic",
    "shared_cohere": "Cohere",
    "shared_azureaisearch": "Azure AI Search",
    "shared_copilotstudio": "Copilot Studio",
}


class PowerPlatformConnector(BaseConnector):
    name: ClassVar[str] = "lowcode.power-platform"
    surface: ClassVar[Surface] = Surface.LOWCODE
    provider: ClassVar[str | None] = "power-platform"
    description: ClassVar[str] = "Copilot Studio agents, Power Automate flows and Power Apps that use AI connectors."
    config_keys: ClassVar[dict[str, str]] = {
        "tenant_id": "env AZURE_TENANT_ID",
        "client_id": "env AZURE_CLIENT_ID (must be a Power Platform application user)",
        "client_secret": "env AZURE_CLIENT_SECRET",
        "environments": "optional list of environment names to restrict to",
        "include_bots": "query Dataverse for Copilot Studio agents (default true)",
        "input": "offline: JSON export of environments / flows / apps / bots / botcomponents",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.tenant = ctx.get("tenant_id", env="AZURE_TENANT_ID")
        self.client_id = ctx.get("client_id", env="AZURE_CLIENT_ID")
        self.client_secret = ctx.get("client_secret", env="AZURE_CLIENT_SECRET")
        self.only_envs = set(ctx.get("environments", []) or [])
        self.include_bots = bool(ctx.get("include_bots", True))
        self._tokens: dict[str, str] = {}

    # ------------------------------------------------------------------ auth
    def _token(self, scope: str) -> str:
        if scope in self._tokens:
            return self._tokens[scope]
        if not (self.tenant and self.client_id and self.client_secret):
            raise ConnectorError("lowcode.power-platform: tenant_id, client_id, client_secret required")
        client = HttpClient()
        resp = client.post(
            f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret, "scope": scope},
        )
        tok = client.read_json_response(resp)["access_token"]
        self._tokens[scope] = tok
        return tok

    def _client(self, base: str, scope: str) -> HttpClient:
        return HttpClient(base, headers={"Authorization": f"Bearer {self._token(scope)}"})

    # --------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        bap = self._client(BAP, "https://service.powerapps.com/.default")
        for env in bap.paginate_odata(
            "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments",
            params={"api-version": "2021-04-01"},
        ):
            name = env.get("name")
            display = get_path(env, "properties.displayName")
            if self.only_envs and name not in self.only_envs and display not in self.only_envs:
                continue
            if not isinstance(name, str) or not name:
                self.ctx.warn("lowcode.power-platform: environment missing name; child resources cannot be listed")
                continue
            env["_kind"] = "environment"
            yield env
            env_id = quote(name, safe="")
            flow = self._client(FLOW, "https://service.flow.microsoft.com/.default")
            try:
                for fl in flow.paginate_odata(f"/providers/Microsoft.ProcessSimple/scopes/admin/environments/{env_id}/v2/flows", params={"api-version": "2016-11-01", "$top": 250}):
                    fl["_kind"] = "flow"
                    fl["_environment"] = display or name
                    yield fl
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                self.ctx.warn(f"lowcode.power-platform: flows in {name}: {self._failure_reason(exc)}")
            try:
                # AdminApps uses a distinct credential audience from the legacy BAP
                # environment API. HttpClient pins all nextLink pages to this origin.
                apps = self._client(PAPPS, "https://api.powerplatform.com/.default")
                for app in apps.paginate_odata(f"/powerapps/environments/{env_id}/apps", params={"api-version": "2024-10-01", "$top": 250}):
                    app["_kind"] = "app"
                    app["_environment"] = display or name
                    yield app
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                self.ctx.warn(f"lowcode.power-platform: apps in {name}: {self._failure_reason(exc)}")
            instance_url = get_path(env, "properties.linkedEnvironmentMetadata.instanceUrl")
            if self.include_bots and instance_url:
                try:
                    dv = self._client(instance_url.rstrip("/"), f"{instance_url.rstrip('/')}/.default")
                    for bot in dv.paginate_odata("/api/data/v9.2/bots", params={"$select": "botid,name,schemaname,statecode,statuscode,createdon,modifiedon,publishedon,authenticationmode,accesscontrolpolicy,authenticationtrigger,configuration,language,_ownerid_value,_createdby_value"}):
                        bot["_kind"] = "bot"
                        bot["_environment"] = display or name
                        yield bot
                    for comp in dv.paginate_odata("/api/data/v9.2/botcomponents", params={"$select": "botcomponentid,name,componenttype,statecode,data,_parentbotid_value,modifiedon"}):
                        comp["_kind"] = "botcomponent"
                        comp["_environment"] = display or name
                        yield comp
                except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                    self.ctx.warn(f"lowcode.power-platform: Dataverse in {name}: {self._failure_reason(exc)}")

    @staticmethod
    def _failure_reason(exc: HttpError | RequestException | RuntimeError | ValueError) -> str:
        # Pagination exceptions are generic; never include server-supplied URLs
        # (which can contain opaque skip tokens) in scan warnings.
        return f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        bots: dict[str, dict[str, Any]] = {}
        components: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                self.ctx.warn("lowcode.power-platform: unsupported or malformed provider record; coverage incomplete")
                continue
            if kind == "flow":
                self.ctx.examined()
                f = self._flow_finding(rec)
                if f:
                    yield f
            elif kind == "app":
                self.ctx.examined()
                f = self._app_finding(rec)
                if f:
                    yield f
            elif kind == "bot":
                bots[str(rec.get("botid") or rec.get("id") or rec.get("schemaname"))] = rec
            elif kind == "botcomponent":
                components.setdefault(str(rec.get("_parentbotid_value") or rec.get("parentbotid") or ""), []).append(rec)
        for bid, bot in bots.items():
            self.ctx.examined()
            yield self._bot_finding(bot, components.get(bid, []))

    def _record_kind(self, rec: dict[str, Any]) -> str | None:
        if not self._record_fields_valid(
            rec, strings=("_kind", "id", "name", "type", "botid", "botcomponentid", "schemaname", "_parentbotid_value", "parentbotid", "_environment"),
            mappings=("properties",),
        ):
            return None
        kind = rec.get("_kind") or _infer(rec)
        identifiers = {
            "environment": ("name", "id"), "flow": ("name", "id"), "app": ("name", "id"),
            "bot": ("botid", "id", "schemaname"), "botcomponent": ("botcomponentid", "id"),
        }
        if kind not in identifiers or not any(isinstance(rec.get(key), str) and rec[key].strip() for key in identifiers[kind]):
            return None
        if kind == "botcomponent" and not (rec.get("_parentbotid_value") or rec.get("parentbotid")):
            return None
        props = rec.get("properties") or {}
        if not self._record_fields_valid(props, strings=("displayName",), mappings=("definitionSummary",)):
            return None
        summary = props.get("definitionSummary") or {}
        if not self._record_fields_valid(summary, arrays=("triggers", "actions")):
            return None
        if any(not self._record_fields_valid(item, strings=("type", "kind", "swaggerOperationId")) for field in ("triggers", "actions") for item in summary.get(field) or []):
            return None
        return kind

    # ---------------------------------------------------------------- flows
    def _ai_refs(self, blob: str) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        low = blob.lower()
        for key, label in AI_CONNECTORS.items():
            if key in low:
                found.append((key, label))
        return found

    def _flow_finding(self, fl: dict[str, Any]) -> Finding | None:
        props = fl.get("properties") or {}
        blob = json.dumps({"definitionSummary": props.get("definitionSummary"), "connectionReferences": props.get("connectionReferences"), "definition": props.get("definition")}, default=str)
        refs = self._ai_refs(blob)
        matches = blob_matches(self.index, blob)
        if not refs and not matches:
            return None
        name = props.get("displayName") or fl.get("name")
        env = fl.get("_environment") or get_path(props, "environment.name")
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.WORKFLOW,
            title=f"Power Automate flow using {', '.join(sorted({l for _, l in refs})) or 'AI services'}: {name}",
            resource=f"power-platform:flow:{fl.get('name') or fl.get('id')}",
            resource_type="power-automate-flow",
            provider="power-platform",
            account=env,
            owner=get_path(props, "creator.userPrincipalName", "creator.userId", "creator.objectId"),
            first_seen=props.get("createdTime"),
            last_seen=props.get("lastModifiedTime"),
        )
        f.add_framework("platform.power-platform-ai")
        for key, label in refs:
            f.add_evidence(Evidence(signal=f"connector:{key}", description=f"Flow references AI connector {label} ({key})", weight=0.85, signature="platform.power-platform-ai"))
        apply_matches(f, matches, weight_scale=0.7)
        triggers = list((props.get("definitionSummary") or {}).get("triggers") or [])
        trig_types = sorted({str(t.get("type") or t.get("kind") or t.get("swaggerOperationId") or "") for t in triggers if isinstance(t, dict)})
        actions = list((props.get("definitionSummary") or {}).get("actions") or [])
        if any("recurrence" in t.lower() or "schedule" in t.lower() for t in trig_types):
            f.add_capability("autonomous")
            f.add_tag("scheduled")
        if any(a.get("type") in {"Http", "HttpWebhook", "OpenApiConnection", "ApiConnection"} for a in actions if isinstance(a, dict)):
            f.add_capability("saas-actions")
        f.add_capability("tool-use")
        f.metadata.update({"environment": env, "state": props.get("state"), "trigger_types": trig_types, "action_count": len(actions), "ai_connectors": sorted({k for k, _ in refs}), "flow_id": fl.get("name")})
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _app_finding(self, app: dict[str, Any]) -> Finding | None:
        props = app.get("properties") or {}
        blob = json.dumps({"connectionReferences": props.get("connectionReferences"), "usedConnections": props.get("usedConnections"), "appPlan": props.get("appPlanClassification")}, default=str)
        refs = self._ai_refs(blob)
        matches = blob_matches(self.index, blob)
        if not refs and not matches:
            return None
        name = props.get("displayName") or app.get("name")
        env = app.get("_environment") or get_path(props, "environment.name")
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.WORKFLOW,
            title=f"Power App using {', '.join(sorted({l for _, l in refs})) or 'AI services'}: {name}",
            resource=f"power-platform:app:{app.get('name') or app.get('id')}",
            resource_type="power-app",
            provider="power-platform",
            account=env,
            owner=get_path(props, "owner.userPrincipalName", "owner.email", "createdBy.userPrincipalName", "owner.id"),
            first_seen=props.get("createdTime"),
            last_seen=props.get("lastModifiedTime"),
        )
        f.add_framework("platform.power-platform-ai")
        for key, label in refs:
            f.add_evidence(Evidence(signal=f"connector:{key}", description=f"App references AI connector {label} ({key})", weight=0.8, signature="platform.power-platform-ai"))
        apply_matches(f, matches, weight_scale=0.7)
        f.metadata.update({"environment": env, "app_type": props.get("appType"), "shared_users": get_path(props, "sharedUsersCount"), "shared_groups": get_path(props, "sharedGroupsCount"), "ai_connectors": sorted({k for k, _ in refs})})
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    # ----------------------------------------------------------------- bots
    def _bot_finding(self, bot: dict[str, Any], comps: list[dict[str, Any]]) -> Finding:
        name = bot.get("name") or bot.get("schemaname") or bot.get("botid")
        env = bot.get("_environment")
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.AGENT,
            title=f"Copilot Studio agent: {name}",
            resource=f"power-platform:bot:{bot.get('botid') or bot.get('id') or bot.get('schemaname')}",
            resource_type="copilot-studio-agent",
            provider="power-platform",
            account=env,
            owner=bot.get("_ownerid_value@OData.Community.Display.V1.FormattedValue") or bot.get("owner") or bot.get("_ownerid_value") or bot.get("_createdby_value"),
            first_seen=bot.get("createdon"),
            last_seen=bot.get("modifiedon") or bot.get("publishedon"),
        )
        f.add_framework("platform.copilot-studio")
        f.add_evidence(Evidence(signal="dataverse:bot", description=f"Copilot Studio agent '{name}' (schema {bot.get('schemaname')}), state {bot.get('statecode')}, auth mode {bot.get('authenticationmode')}, published {bot.get('publishedon') or 'never'}", weight=0.95, signature="platform.copilot-studio"))
        gen_ai = False
        actions: list[str] = []
        knowledge: list[str] = []
        topics = 0
        for c in comps:
            data = c.get("data") or ""
            blob = data if isinstance(data, str) else json.dumps(data)
            low = blob.lower()
            ctype = c.get("componenttype")
            if "gptcomponentmetadata" in low or "generativeanswers" in low or "searchandsummarizecontent" in low or "kind: gptcomponentmetadata" in low:
                gen_ai = True
            if "kind: invokeflowaction" in low or "invokeflowaction" in low or "kind: invokeconnectoraction" in low or "httprequestaction" in low or "invokeaiskill" in low or "kind: invokeskillaction" in low or "mcp" in low and "server" in low:
                actions.append(str(c.get("name")))
            if "kind: knowledgesource" in low or "knowledge" in low and ("sharepoint" in low or "dataverse" in low or "publicwebsite" in low or "file" in low):
                knowledge.append(str(c.get("name")))
            if ctype in (0, "0", 9, "9") or "kind: adaptivedialog" in low:
                topics += 1
            for m in blob_matches(self.index, blob[:100_000]):
                if m.signature_id not in {"platform.copilot-studio"}:
                    apply_matches(f, [m], weight_scale=0.6)
        if gen_ai:
            f.add_evidence(Evidence(signal="copilot-studio:generative", description="Generative answers / orchestration enabled", weight=0.5))
            f.add_capability("rag")
        if actions:
            f.add_capability("tool-use")
            f.add_capability("saas-actions")
            f.add_evidence(Evidence(signal="copilot-studio:actions", description=f"{len(actions)} action(s) (flows / connectors / HTTP / MCP): {', '.join(actions[:8])}", weight=0.5))
        auth = str(bot.get("authenticationmode") or "")
        if auth in {"0", "None", "none"} or bot.get("authenticationmode") == 0:
            f.add_tag("no-authentication")
            f.add_evidence(Evidence(signal="copilot-studio:no-auth", description="Agent configured with no end-user authentication (anonymous access if published to web)", weight=0.2))
        if bot.get("publishedon"):
            f.add_tag("published")
        apply_matches(f, name_matches(self.index, name), weight_scale=0.5)
        f.metadata.update({"environment": env, "schema_name": bot.get("schemaname"), "state": bot.get("statecode"), "status": bot.get("statuscode"), "authentication_mode": bot.get("authenticationmode"), "access_control_policy": bot.get("accesscontrolpolicy"), "published_on": bot.get("publishedon"), "topics": topics, "actions": actions[:20], "knowledge_sources": knowledge[:20], "generative_ai": gen_ai, "language": bot.get("language")})
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f


def _infer(rec: dict[str, Any]) -> str:
    props = rec.get("properties") or {}
    if "botid" in rec or "schemaname" in rec and "authenticationmode" in rec:
        return "bot"
    if "botcomponentid" in rec or "_parentbotid_value" in rec or "componenttype" in rec:
        return "botcomponent"
    if "definitionSummary" in props or "definition" in props or str(rec.get("type", "")).endswith("/flows"):
        return "flow"
    if "appType" in props or "appVersion" in props or str(rec.get("type", "")).endswith("/apps"):
        return "app"
    if "linkedEnvironmentMetadata" in props or str(rec.get("type", "")).endswith("/environments"):
        return "environment"
    return "unknown"
