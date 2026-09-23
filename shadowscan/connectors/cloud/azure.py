"""Azure subscription scanner (ARM REST with azure-identity or a supplied access token).

Uses Azure Resource Graph for a single inventory query across subscriptions, then
data-plane / ARM detail calls:

* Azure OpenAI / AI Services accounts and their model deployments
* Azure AI Foundry accounts & projects (+ Agent Service agents via the project endpoint)
* Azure Bot Service bots, Logic Apps with AI connectors / agent loops
* App Service / Function apps (app-setting names, plaintext credentials), Container Apps (images, env)
* user-assigned managed identities and role assignments granting AI roles (``iam-grant``)
* diagnostic settings on OpenAI accounts (auditability)

Offline export: JSONL of dumped records (``_kind`` per record).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, ClassVar, TypedDict
from urllib.parse import parse_qs, urlsplit

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.common import (
    cloud_finding,
    done,
    name_hint,
    scan_blob,
    scan_env,
    scan_iam_actions,
)
from shadowscan.connectors.common import apply_matches, model_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError, validate_url
from shadowscan.utils.text import get_path, truncate

ARM = "https://management.azure.com"
ARG_QUERY = """
resources
| where type in~ (
    'microsoft.cognitiveservices/accounts',
    'microsoft.cognitiveservices/accounts/projects',
    'microsoft.machinelearningservices/workspaces',
    'microsoft.botservice/botservices',
    'microsoft.logic/workflows',
    'microsoft.web/sites',
    'microsoft.app/containerapps',
    'microsoft.managedidentity/userassignedidentities',
    'microsoft.search/searchservices',
    'microsoft.keyvault/vaults')
| project id, name, type, kind, location, resourceGroup, subscriptionId, tags, properties, identity
"""
AI_ROLE_IDS = {
    "5e0bd9bd-7b93-4f28-af87-19fc36ad61bd": "Cognitive Services OpenAI User",
    "a001fd3d-188f-4b5d-821b-7da978bf7442": "Cognitive Services OpenAI Contributor",
    "a97b65f3-24c7-4388-baec-2e87135dc908": "Cognitive Services User",
    "25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68": "Cognitive Services Contributor",
    "64702f94-c99e-4e88-8e0b-ba3389c66a89": "Azure AI Developer",
    "53ca6127-db72-4b80-b1b0-d745d6d5456d": "Azure AI User",
    "eadc314b-1a2d-4efa-be10-5d325db5065e": "Azure AI Project Manager",
    "e503ece1-11d0-4e8e-8e2c-7a6c3bf38815": "Azure AI Account Owner",
    "b78c5d69-af96-48a3-bf8d-a8b4d589de94": "Azure AI Administrator",
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
}


class _ResourceBase(TypedDict):
    account: str | None
    region: str | None
    owner: str | None


class AzureConnector(BaseConnector):
    name: ClassVar[str] = "cloud.azure"
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "azure"
    requires: ClassVar[list[str]] = []
    description: ClassVar[str] = "Azure OpenAI deployments, AI Foundry projects & agents, Bot Service, Logic Apps, Function/Web/Container apps, managed identities and AI role assignments."
    config_keys: ClassVar[dict[str, str]] = {
        "subscriptions": "list of subscription ids (default: all visible)",
        "access_token": "ARM token (env AZURE_ACCESS_TOKEN); otherwise DefaultAzureCredential from azure-identity",
        "foundry_token": "token for https://ai.azure.com/.default to list Foundry agents (auto-minted with azure-identity)",
        "include_app_settings": "read App Service settings (names + credential detection) (default true)",
        "input": "offline: JSONL dump of records",
    }
    offline_formats: ClassVar[str] = "JSONL dump of records"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.include_app_settings = bool(ctx.get("include_app_settings", True))
        self.http: HttpClient | None = None
        self._cred: Any = None
        self._foundry_token: str | None = ctx.get("foundry_token")

    def _auth(self) -> None:
        token = self.ctx.get("access_token", env="AZURE_ACCESS_TOKEN")
        if not token:
            try:
                from azure.identity import DefaultAzureCredential
            except ImportError as exc:
                raise ConnectorError("cloud.azure: install azure-identity (pip install 'shadowscan[azure]') or provide access_token") from exc
            self._cred = DefaultAzureCredential()
            token = self._cred.get_token("https://management.azure.com/.default").token
        self.http = HttpClient(ARM, headers={"Authorization": f"Bearer {token}"})

    def _foundry(self) -> str | None:
        if self._foundry_token:
            return self._foundry_token
        if self._cred is not None:
            try:
                self._foundry_token = self._cred.get_token("https://ai.azure.com/.default").token
            except Exception as exc:  # noqa: BLE001
                self.log.debug("foundry token: %s", exc)
        return self._foundry_token

    def _get(self, path: str, api: str, **params: Any) -> Any:
        assert self.http
        try:
            if "api-version" not in parse_qs(urlsplit(path).query):
                params = {"api-version": api, **params}
            return self.http.get_json(path, params=params or None)
        except HttpError as exc:
            if exc.status in (400, 401, 403, 404, 409):
                self.ctx.warn(f"cloud.azure: HTTP {exc.status} for {path}; coverage unknown", incomplete=True)
                return None
            raise

    def _list(self, path: str, api: str) -> list[dict[str, Any]] | None:
        """Collect ARM nextLink pages; None means coverage is unknown."""
        assert self.http
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for _ in range(1000):
            if path in seen:
                self.ctx.warn("cloud.azure: repeated list continuation", incomplete=True)
                return None
            seen.add(path)
            data = self._get(path, api)
            if not isinstance(data, dict) or not isinstance(data.get("value"), list):
                if data is not None:
                    self.ctx.warn("cloud.azure: invalid list response; coverage unknown", incomplete=True)
                return None
            items.extend(data["value"])
            next_path = data.get("nextLink") or data.get("@odata.nextLink")
            if not next_path:
                return items
            path = str(next_path)
            # _get/HttpClient reject any nextLink outside ARM before sending auth.
        self.ctx.warn("cloud.azure: list page limit reached", incomplete=True)
        return None

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        assert self.http
        subs = self.ctx.get("subscriptions") or [s["subscriptionId"] for s in self._list("/subscriptions", "2022-12-01") or []]
        if not subs:
            raise ConnectorError("cloud.azure: no subscriptions visible")
        rows: list[dict[str, Any]] = []
        skip_token = None
        seen_tokens: set[str] = set()
        for _ in range(1000):
            options: dict[str, Any] = {"$top": 1000, "resultFormat": "objectArray"}
            if skip_token:
                options["$skipToken"] = skip_token
            body = {"subscriptions": subs, "query": ARG_QUERY, "options": options}
            data = self.http.post_json("/providers/Microsoft.ResourceGraph/resources", params={"api-version": "2021-03-01"}, json=body) or {}
            batch = data.get("data", [])
            rows.extend(batch)
            skip_token = data.get("$skipToken")
            if not skip_token:
                if str(data.get("resultTruncated", "false")).lower() == "true":
                    self.ctx.warn("cloud.azure: Resource Graph results truncated without continuation", incomplete=True)
                break
            if skip_token in seen_tokens:
                self.ctx.warn("cloud.azure: repeated Resource Graph continuation", incomplete=True)
                break
            seen_tokens.add(skip_token)
        else:
            self.ctx.warn("cloud.azure: Resource Graph page limit reached", incomplete=True)
        for r in rows:
            r["_kind"] = "resource"
            yield r
            t = str(r.get("type", "")).lower()
            rid = r.get("id")
            if t == "microsoft.cognitiveservices/accounts":
                for d in self._list(f"{rid}/deployments", "2024-10-01") or []:
                    yield {"_kind": "deployment", "_account": rid, "_account_name": r.get("name"), **d}
                diag = self._list(f"{rid}/providers/Microsoft.Insights/diagnosticSettings", "2021-05-01-preview")
                yield {"_kind": "diagnostics", "_account": rid, "settings": diag, "coverage": "unknown" if diag is None else "observed"}
                for p in self._list(f"{rid}/projects", "2025-04-01-preview") or []:
                    p["_kind"] = "resource"
                    p["type"] = "microsoft.cognitiveservices/accounts/projects"
                    p["_account"] = rid
                    yield p
                    yield from self._collect_agents(r, p)
            elif t == "microsoft.logic/workflows":
                wf = self._get(str(rid), "2019-05-01") or {}
                yield {"_kind": "logicapp-definition", "id": rid, "name": r.get("name"), "definition": get_path(wf, "properties.definition"), "connections": get_path(wf, "properties.parameters.$connections.value"), "state": get_path(wf, "properties.state")}
            elif t == "microsoft.web/sites" and self.include_app_settings:
                try:
                    settings = self.http.post_json(f"{rid}/config/appsettings/list", params={"api-version": "2022-03-01"}) or {}
                    yield {"_kind": "appsettings", "id": rid, "name": r.get("name"), "kind": r.get("kind"), "settings": settings.get("properties") or {}}
                except HttpError as exc:
                    self.ctx.warn(f"cloud.azure: appsettings HTTP {exc.status} for {rid}", incomplete=True)
        for sub in subs:
            for ra in self._list(f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments", "2022-04-01") or []:
                role_id = str(get_path(ra, "properties.roleDefinitionId", default="")).rsplit("/", 1)[-1]
                if role_id in AI_ROLE_IDS:
                    yield {"_kind": "role-assignment", "_subscription": sub, "role_id": role_id, "role": AI_ROLE_IDS[role_id], **(ra.get("properties") or {}), "id": ra.get("id")}

    def _collect_agents(self, account: dict[str, Any], project: dict[str, Any]) -> Iterator[dict[str, Any]]:
        token = self._foundry()
        endpoint = get_path(project, "properties.endpoints.AI Foundry API") or get_path(account, "properties.endpoints.AI Foundry API")
        if not (token and endpoint):
            self.ctx.warn("cloud.azure: Foundry agent inventory unavailable; token or endpoint missing", incomplete=True)
            return
        validate_url(str(endpoint))
        host = urlsplit(str(endpoint)).hostname or ""
        if not any(host.endswith(suffix) for suffix in (".services.ai.azure.com", ".cognitiveservices.azure.com", ".api.azureml.ms")):
            raise ConnectorError("cloud.azure: refusing Foundry credentials to an unrecognized endpoint origin")
        http = HttpClient(str(endpoint).rstrip("/"), headers={"Authorization": f"Bearer {token}"})
        params: dict[str, Any] = {"api-version": "2025-05-01", "limit": 100}
        seen: set[str] = set()
        for _ in range(1000):
            try:
                data = http.get_json("/agents", params=params) or {}
            except HttpError as exc:
                self.ctx.warn(f"cloud.azure: Foundry agents HTTP {exc.status}; coverage unknown", incomplete=True)
                return
            for a in data.get("data", []):
                yield {"_kind": "foundry-agent", "_project": project.get("id"), "_project_name": project.get("name"), "_account": account.get("id"), "_endpoint": endpoint, **a}
            if not data.get("has_more"):
                return
            after = data.get("last_id")
            if not after or after in seen:
                self.ctx.warn("cloud.azure: invalid Foundry agent continuation", incomplete=True)
                return
            seen.add(after)
            params["after"] = after
        self.ctx.warn("cloud.azure: Foundry agent page limit reached", incomplete=True)

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        identities: dict[str, str] = {}
        deployments: dict[str, list[dict[str, Any]]] = {}
        diagnostics: dict[str, list[dict[str, Any]] | None] = {}
        resources: list[dict[str, Any]] = []
        others: list[dict[str, Any]] = []
        for rec in records:
            kind = rec.get("_kind")
            if kind == "resource":
                resources.append(rec)
                if str(rec.get("type", "")).lower() == "microsoft.managedidentity/userassignedidentities":
                    pid = get_path(rec, "properties.principalId")
                    if pid:
                        identities[str(pid)] = str(rec.get("name"))
                sys_pid = get_path(rec, "identity.principalId")
                if sys_pid:
                    identities[str(sys_pid)] = f"{rec.get('name')} (system-assigned)"
            elif kind == "deployment":
                deployments.setdefault(str(rec.get("_account")), []).append(rec)
            elif kind == "diagnostics":
                diagnostics[str(rec.get("_account"))] = None if rec.get("coverage") == "unknown" or rec.get("settings") is None else rec["settings"]
            else:
                others.append(rec)
        for r in resources:
            self.ctx.examined()
            f = self._resource_finding(r, deployments.get(str(r.get("id")), []), diagnostics.get(str(r.get("id"))))
            if f:
                yield f
        for rec in others:
            self.ctx.examined()
            kind = rec.get("_kind")
            handler = getattr(self, f"_h_{str(kind).replace('-', '_')}", None)
            if handler:
                f = handler(rec, identities) if kind == "role-assignment" else handler(rec)
                if f:
                    yield f

    def _resource_finding(self, r: dict[str, Any], deps: list[dict[str, Any]], diag: list[dict[str, Any]] | None) -> Finding | None:
        t = str(r.get("type", "")).lower()
        rid = str(r.get("id"))
        props = r.get("properties") or {}
        tags = r.get("tags") or {}
        owner = tags.get("owner") or tags.get("Owner") or tags.get("team") or tags.get("CreatedBy")
        base: _ResourceBase = {"account": r.get("subscriptionId"), "region": r.get("location"), "owner": owner}
        if t == "microsoft.cognitiveservices/accounts":
            kind = str(r.get("kind") or "")
            if kind.lower() not in {"openai", "aiservices"} and not deps:
                return None
            f = cloud_finding(self.name, "azure", kind=Kind.CLOUD_RESOURCE, title=f"Azure {'OpenAI' if kind.lower() == 'openai' else 'AI Services'} account: {r.get('name')} ({len(deps)} deployment(s))", resource=rid, resource_type=f"cognitive-services/{kind}", **base)
            f.add_model_provider("provider.azure-openai")
            if kind.lower() == "aiservices" or get_path(props, "allowProjectManagement"):
                f.add_framework("cloud.azure-ai-foundry-agents")
            f.models = [str(get_path(d, "properties.model.name")) for d in deps if get_path(d, "properties.model.name")]
            apply_matches(f, model_matches(self.index, *f.models), weight_scale=0.4)
            dep_summary = ", ".join(f"{d.get('name')}={get_path(d, 'properties.model.name')}" for d in deps)[:300] or "none"
            f.add_evidence(Evidence(signal="azure:cognitive-account", description=f"{kind} account '{r.get('name')}' deployments: {dep_summary}; public network {props.get('publicNetworkAccess')}; local auth disabled {props.get('disableLocalAuth')}", location=rid, weight=0.6))
            if props.get("disableLocalAuth") is not True:
                f.add_tag("api-key-auth-enabled")
            if props.get("publicNetworkAccess", "Enabled") == "Enabled":
                f.add_tag("public-network")
            if diag is not None and not any(any(l.get("enabled") for l in (d.get("properties") or {}).get("logs") or []) for d in diag):
                f.add_tag("no-diagnostic-logging")
                f.add_evidence(Evidence(signal="azure:no-diagnostics", description="No diagnostic setting sends request logs anywhere — usage is not auditable", weight=0.1))
            f.metadata["diagnostic_logging_status"] = "unknown" if diag is None else "observed"
            f.metadata.update({"kind": kind, "endpoint": props.get("endpoint"), "deployments": [{"name": d.get("name"), "model": get_path(d, "properties.model.name"), "version": get_path(d, "properties.model.version"), "capacity": get_path(d, "sku.capacity")} for d in deps], "public_network_access": props.get("publicNetworkAccess"), "disable_local_auth": props.get("disableLocalAuth"), "tags": tags})
            return done(f, self.index, Kind.CLOUD_RESOURCE)
        if t == "microsoft.cognitiveservices/accounts/projects":
            f = cloud_finding(self.name, "azure", kind=Kind.CLOUD_RESOURCE, title=f"Azure AI Foundry project: {r.get('name')}", resource=rid, resource_type="ai-foundry-project", **base)
            f.add_framework("cloud.azure-ai-foundry-agents")
            f.add_evidence(Evidence(signal="azure:foundry-project", description=f"Foundry project '{r.get('name')}' ({props.get('provisioningState')}) endpoints {', '.join((props.get('endpoints') or {}).keys())[:200]}", location=rid, weight=0.7, signature="cloud.azure-ai-foundry-agents"))
            f.metadata.update({"endpoints": props.get("endpoints"), "description": truncate(props.get("description")), "tags": tags})
            return done(f, self.index, Kind.CLOUD_RESOURCE)
        if t == "microsoft.machinelearningservices/workspaces":
            kind = str(r.get("kind") or "Default")
            if kind.lower() not in {"hub", "project"}:
                return None
            f = cloud_finding(self.name, "azure", kind=Kind.CLOUD_RESOURCE, title=f"Azure AI Foundry {kind.lower()} (hub-based): {r.get('name')}", resource=rid, resource_type=f"ml-workspace/{kind.lower()}", **base)
            f.add_framework("cloud.azure-ai-foundry-agents")
            f.add_evidence(Evidence(signal="azure:ml-workspace", description=f"{kind} workspace '{r.get('name')}' discovery {props.get('discoveryUrl')}", location=rid, weight=0.6, signature="cloud.azure-ai-foundry-agents"))
            f.metadata.update({"kind": kind, "hub": props.get("hubResourceId"), "tags": tags})
            return done(f, self.index, Kind.CLOUD_RESOURCE)
        if t == "microsoft.botservice/botservices":
            f = cloud_finding(self.name, "azure", kind=Kind.AGENT, title=f"Azure Bot: {props.get('displayName') or r.get('name')}", resource=rid, resource_type="bot-service", **base)
            f.add_framework("platform.copilot-studio" if "copilot" in str(props.get("endpoint", "")).lower() or "powerplatform" in str(props.get("endpoint", "")).lower() or "pva" in str(props.get("endpoint", "")).lower() else "framework.bot-framework")
            f.add_evidence(Evidence(signal="azure:bot", description=f"Bot '{props.get('displayName')}' endpoint {props.get('endpoint')} app id {props.get('msaAppId')} channels {', '.join(props.get('enabledChannels') or [])}", location=rid, weight=0.85))
            apply_matches(f, self.index.match_domains_in_text(str(props.get("endpoint") or "")), weight_scale=0.6)
            f.metadata.update({"endpoint": props.get("endpoint"), "msa_app_id": props.get("msaAppId"), "msa_app_type": props.get("msaAppType"), "channels": props.get("enabledChannels"), "is_streaming": props.get("isStreamingSupported"), "tags": tags})
            return done(f, self.index, Kind.AGENT)
        if t == "microsoft.app/containerapps":
            f = cloud_finding(self.name, "azure", kind=Kind.CLOUD_RESOURCE, title=f"Container App: {r.get('name')}", resource=rid, resource_type="container-app", **base)
            for c in get_path(props, "template.containers", default=[]) or []:
                if c.get("image"):
                    apply_matches(f, self.index.match_image(c["image"]), location=rid)
                env = {e.get("name"): e.get("value") for e in c.get("env") or [] if e.get("name")}
                scan_env(self.index, f, env, location=rid)
            name_hint(self.index, f, r.get("name"))
            if not f.frameworks and not f.model_providers:
                return None
            f.add_evidence(Evidence(signal="azure:container-app", description=f"Container app '{r.get('name')}' images {', '.join(str(c.get('image')) for c in get_path(props, 'template.containers', default=[]) or [])[:200]}; external ingress {get_path(props, 'configuration.ingress.external')}", location=rid, weight=0.25))
            if get_path(props, "configuration.ingress.external"):
                f.add_tag("public-ingress")
            f.metadata.update({"images": [c.get("image") for c in get_path(props, "template.containers", default=[]) or []], "identity": r.get("identity"), "tags": tags})
            return done(f, self.index, Kind.CLOUD_RESOURCE)
        if t == "microsoft.managedidentity/userassignedidentities":
            f = cloud_finding(self.name, "azure", kind=Kind.SERVICE_IDENTITY, title=f"User-assigned managed identity: {r.get('name')}", resource=rid, resource_type="managed-identity", surface=Surface.IDENTITY, **base)
            name_hint(self.index, f, r.get("name"))
            if not f.frameworks:
                return None
            f.add_evidence(Evidence(signal="azure:managed-identity", description=f"Managed identity '{r.get('name')}' principal {props.get('principalId')}", location=rid, weight=0.3))
            f.metadata.update({"principal_id": props.get("principalId"), "client_id": props.get("clientId"), "tags": tags})
            return done(f, self.index, Kind.SERVICE_IDENTITY)
        if t == "microsoft.search/searchservices":
            f = cloud_finding(self.name, "azure", kind=Kind.CLOUD_RESOURCE, title=f"Azure AI Search: {r.get('name')}", resource=rid, resource_type="search-service", **base)
            f.add_framework("memory.vector-stores")
            f.add_evidence(Evidence(signal="azure:search", description=f"AI Search service '{r.get('name')}' (RAG retrieval tier); public network {props.get('publicNetworkAccess')}", location=rid, weight=0.3))
            return done(f, self.index, Kind.CLOUD_RESOURCE)
        return None

    def _h_foundry_agent(self, rec: dict[str, Any]) -> Finding:
        tools = [t.get("type") for t in rec.get("tools") or [] if isinstance(t, dict)]
        f = cloud_finding(self.name, "azure", kind=Kind.AGENT, title=f"Azure AI Foundry agent: {rec.get('name') or rec.get('id')}", resource=f"{rec.get('_project')}/agents/{rec.get('id')}", resource_type="foundry-agent", account=str(rec.get("_project", "")).split("/subscriptions/")[-1].split("/")[0] if "/subscriptions/" in str(rec.get("_project", "")) else None, first_seen=str(rec.get("created_at")) if rec.get("created_at") else None)
        f.add_framework("cloud.azure-ai-foundry-agents")
        f.add_model_provider("provider.azure-openai")
        f.add_capability("tool-use")
        f.models = [str(rec["model"])] if rec.get("model") else []
        apply_matches(f, model_matches(self.index, rec.get("model")), weight_scale=0.4)
        f.add_evidence(Evidence(signal="azure:foundry-agent", description=f"Agent '{rec.get('name')}' on {rec.get('model')} with tools {', '.join(str(t) for t in tools) or 'none'} in project {rec.get('_project_name')}", location=rec.get("_endpoint"), weight=0.97, signature="cloud.azure-ai-foundry-agents"))
        if "code_interpreter" in tools:
            f.add_capability("code-exec")
        if any(t in {"bing_grounding", "bing_custom_search"} for t in tools):
            f.add_capability("browsing")
        if any(t in {"openapi", "azure_function", "function", "connected_agent", "mcp", "sharepoint_grounding", "fabric_dataagent"} for t in tools):
            f.add_capability("saas-actions")
        if "connected_agent" in tools:
            f.add_capability("multi-agent")
        if any(t in {"file_search", "azure_ai_search", "sharepoint_grounding"} for t in tools):
            f.add_capability("rag")
        f.metadata.update({"agent_id": rec.get("id"), "model": rec.get("model"), "tools": tools, "instructions": truncate(str(rec.get("instructions") or ""), 300), "project": rec.get("_project_name"), "metadata": rec.get("metadata")})
        return done(f, self.index, Kind.AGENT)

    def _h_logicapp_definition(self, rec: dict[str, Any]) -> Finding | None:
        rid = rec.get("id", "")
        f = cloud_finding(self.name, "azure", kind=Kind.WORKFLOW, title=f"Logic App with AI steps: {rec.get('name')}", resource=rid, resource_type="logic-app", account=rid.split("/subscriptions/")[-1].split("/")[0] if "/subscriptions/" in rid else None)
        hits = scan_blob(self.index, f, {"definition": rec.get("definition"), "connections": rec.get("connections")}, location=rid)
        if not f.frameworks and not f.model_providers:
            return None
        f.add_framework("cloud.azure-logic-apps-ai")
        f.add_evidence(Evidence(signal="azure:logic-app", description=f"Logic App '{rec.get('name')}' ({rec.get('state')}) references AI connectors / agent actions", location=rid, weight=0.6, signature="cloud.azure-logic-apps-ai"))
        triggers = list(((rec.get("definition") or {}).get("triggers") or {}).keys())
        if any("recurrence" in str(((rec.get("definition") or {}).get("triggers") or {}).get(t, {}).get("type", "")).lower() for t in triggers):
            f.add_capability("autonomous")
        f.add_capability("saas-actions")
        f.metadata.update({"state": rec.get("state"), "triggers": triggers, "agent_indicators": hits})
        return done(f, self.index, Kind.WORKFLOW)

    def _h_appsettings(self, rec: dict[str, Any]) -> Finding | None:
        rid = rec.get("id", "")
        f = cloud_finding(self.name, "azure", kind=Kind.CLOUD_RESOURCE, title=f"{'Function' if 'functionapp' in str(rec.get('kind', '')).lower() else 'Web'} app: {rec.get('name')}", resource=rid, resource_type=f"web-site/{rec.get('kind')}", account=rid.split("/subscriptions/")[-1].split("/")[0] if "/subscriptions/" in rid else None)
        scan_env(self.index, f, rec.get("settings"), location=rid)
        name_hint(self.index, f, rec.get("name"))
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(Evidence(signal="azure:app-settings", description=f"App '{rec.get('name')}' has LLM-related app settings: {', '.join(f.metadata.get('env_matches', []))[:200]}", location=rid, weight=0.3))
        f.metadata["setting_names"] = sorted((rec.get("settings") or {}).keys())[:60]
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_role_assignment(self, rec: dict[str, Any], identities: dict[str, str]) -> Finding | None:
        pid = str(rec.get("principalId"))
        ptype = rec.get("principalType")
        role = rec.get("role")
        f = cloud_finding(self.name, "azure", kind=Kind.IAM_GRANT, title=f"{role} granted to {ptype} {identities.get(pid, pid)}", resource=rec.get("id") or f"{pid}:{rec.get('role_id')}", resource_type="role-assignment", account=rec.get("_subscription"), surface=Surface.IDENTITY)
        llm = scan_iam_actions(self.index, f, [str(role), str(rec.get("role_id"))], location=rec.get("scope"))
        if not llm and role not in {"Owner", "Contributor"}:
            return None
        if role in {"Owner", "Contributor"} and ptype != "ServicePrincipal":
            return None
        f.add_evidence(Evidence(signal="azure:role-assignment", description=f"{ptype} {identities.get(pid, pid)} has '{role}' on {rec.get('scope')}", weight=0.45 if ptype == "ServicePrincipal" else 0.2))
        if ptype == "ServicePrincipal":
            f.add_tag("service-principal")
        name_hint(self.index, f, identities.get(pid))
        f.metadata.update({"principal_id": pid, "principal_type": ptype, "principal_name": identities.get(pid), "role": role, "scope": rec.get("scope"), "created": rec.get("createdOn")})
        return done(f, self.index, Kind.IAM_GRANT)
