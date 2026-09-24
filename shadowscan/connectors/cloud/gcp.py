"""Google Cloud project scanner (REST APIs with google-auth or a supplied access token).

Per project:

* enabled AI APIs (Service Usage)
* Vertex AI Agent Engine (reasoning engines) and endpoints per location
* Dialogflow CX agents, Discovery Engine / Agentspace engines
* Cloud Run services and Cloud Functions (images, env names, plaintext credentials, service accounts)
* IAM policy bindings granting Vertex / Dialogflow / Discovery Engine roles (``iam-grant``)
* service accounts (agent-like names, user-managed keys)
* API keys restricted to the Gemini API (``secret``), Secret Manager secret names
* optional: Cloud Audit Logs callers of ``aiplatform.googleapis.com`` (``gateway-caller``)

Offline export: JSONL of dumped records (``_kind`` per record).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.common import cloud_finding, done, name_hint, scan_env, scan_iam_actions
from shadowscan.connectors.common import apply_matches, model_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path, truncate

DEFAULT_LOCATIONS = ["us-central1", "us-east4", "us-west1", "europe-west1", "europe-west4", "asia-southeast1", "asia-northeast1"]
MAX_LIST_PAGES = 500
AI_SERVICES = {"aiplatform.googleapis.com": "Vertex AI", "generativelanguage.googleapis.com": "Gemini API", "dialogflow.googleapis.com": "Dialogflow", "discoveryengine.googleapis.com": "Vertex AI Search / Agent Builder / Agentspace", "notebooks.googleapis.com": "Vertex AI Workbench", "speech.googleapis.com": "Speech", "documentai.googleapis.com": "Document AI", "contactcenteraiplatform.googleapis.com": "CCAI"}


class GcpConnector(BaseConnector):
    name: ClassVar[str] = "cloud.gcp"
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "gcp"
    requires: ClassVar[list[str]] = []
    description: ClassVar[str] = "Vertex AI Agent Engine, Dialogflow CX, Agentspace/Discovery Engine, Cloud Run/Functions, IAM bindings, service accounts, Gemini API keys, secret names, audit-log callers."
    config_keys: ClassVar[dict[str, str]] = {
        "projects": "list of project ids (default: all projects visible to the credentials)",
        "locations": f"Vertex/Dialogflow locations (default {DEFAULT_LOCATIONS})",
        "access_token": "OAuth token (env GOOGLE_OAUTH_ACCESS_TOKEN); otherwise Application Default Credentials via google-auth",
        "audit_days": "look back N days in Cloud Audit Logs for Vertex callers (default 0 = off)",
        "max_projects": "default 200",
        "input": "offline: JSONL dump of records",
    }
    offline_formats: ClassVar[str] = "JSONL dump of records"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.locations = ctx.get("locations") or DEFAULT_LOCATIONS
        self.audit_days = int(ctx.get("audit_days", 0))
        self.max_projects = int(ctx.get("max_projects", 200))
        if self.max_projects < 1:
            raise ConnectorError("cloud.gcp: max_projects must be positive")
        self.max_pages = max(1, int(ctx.get("max_pages", 1000)))
        self.http: HttpClient | None = None

    def _auth(self) -> None:
        token = self.ctx.get("access_token", env="GOOGLE_OAUTH_ACCESS_TOKEN")
        if not token:
            try:
                import google.auth
                import google.auth.transport.requests
            except ImportError as exc:
                raise ConnectorError("cloud.gcp: install google-auth (pip install 'shadowscan[gcp]') or provide access_token") from exc
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            creds.refresh(google.auth.transport.requests.Request())
            token = creds.token
        self.http = HttpClient(headers={"Authorization": f"Bearer {token}"})

    def _get(self, url: str, **params: Any) -> Any:
        assert self.http
        try:
            data = self.http.get_json(url, params=params or None)
            if data is None:
                self.ctx.warn(f"cloud.gcp: empty response for {url.split('?')[0]}")
            return data
        except (HttpError, RequestException, ValueError) as exc:
            status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
            self.ctx.warn(f"cloud.gcp: collection failed for {url.split('?')[0]} ({status})")
            return None

    def _pages(self, url: str, items_key: str, **params: Any) -> Iterator[dict[str, Any]]:
        token: str | None = None
        seen: set[str] = set()
        for _ in range(min(MAX_LIST_PAGES, self.max_pages)):
            p = dict(params)
            if token:
                p["pageToken"] = token
            data = self._get(url, **p)
            if data is None:
                return  # _get has already recorded the collection failure
            if not isinstance(data, dict) or "error" in data:
                self.ctx.warn(f"cloud.gcp: invalid response for {url}")
                return
            # Aggregated list APIs may succeed while omitting unavailable regions.
            # Keep reachable observations, but never turn partial success into a
            # complete inventory (Cloud Functions v2 and Cloud Run v2 contract).
            unreachable = data.get("unreachable", [])
            if not isinstance(unreachable, list) or any(not isinstance(loc, str) or not loc for loc in unreachable):
                self.ctx.warn(f"cloud.gcp: invalid unreachable locations for {url}")
            elif unreachable:
                self.ctx.warn(f"cloud.gcp: {len(unreachable)} unreachable location(s) for {url}; coverage unknown")
            items = data.get(items_key, [])
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                self.ctx.warn(f"cloud.gcp: invalid {items_key} page for {url}")
                return
            yield from items
            token = data.get("nextPageToken")
            if token is None or token == "":
                return
            if not isinstance(token, str) or token in seen:
                self.ctx.warn(f"cloud.gcp: invalid or repeated pagination token for {url}")
                return
            seen.add(token)
        self.ctx.warn(f"cloud.gcp: pagination limit reached for {url}")

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        projects: Iterable[str] = self.ctx.get("projects") or []
        if not projects:
            projects = (p["projectId"] for p in self._pages("https://cloudresourcemanager.googleapis.com/v1/projects", "projects", filter="lifecycleState:ACTIVE") if p.get("projectId"))
        for i, project in enumerate(projects):
            if i >= self.max_projects:
                self.ctx.warn("cloud.gcp: max_projects reached")
                break
            yield from self._collect_project(project)

    def _collect_project(self, project: str) -> Iterator[dict[str, Any]]:
        enabled = [s.get("config", {}).get("name") for s in self._pages(f"https://serviceusage.googleapis.com/v1/projects/{project}/services", "services", filter="state:ENABLED", pageSize=200)]
        ai_enabled = [s for s in enabled if s in AI_SERVICES]
        yield {"_kind": "project", "project": project, "ai_services": ai_enabled}
        if "aiplatform.googleapis.com" in enabled:
            for loc in self.locations:
                for re_ in self._pages(f"https://{loc}-aiplatform.googleapis.com/v1/projects/{project}/locations/{loc}/reasoningEngines", "reasoningEngines"):
                    yield {"_kind": "reasoning-engine", "_project": project, "_location": loc, **re_}
                for ep in self._pages(f"https://{loc}-aiplatform.googleapis.com/v1/projects/{project}/locations/{loc}/endpoints", "endpoints"):
                    yield {"_kind": "vertex-endpoint", "_project": project, "_location": loc, **ep}
        if "dialogflow.googleapis.com" in enabled:
            for loc in ["global", *self.locations]:
                for agent in self._pages(f"https://dialogflow.googleapis.com/v3/projects/{project}/locations/{loc}/agents", "agents"):
                    yield {"_kind": "dialogflow-agent", "_project": project, "_location": loc, **agent}
        if "discoveryengine.googleapis.com" in enabled:
            for loc in ["global", "us", "eu"]:
                for eng in self._pages(f"https://discoveryengine.googleapis.com/v1/projects/{project}/locations/{loc}/collections/default_collection/engines", "engines"):
                    yield {"_kind": "discovery-engine", "_project": project, "_location": loc, **eng}
        if "run.googleapis.com" in enabled:
            # Cloud Run v2 services.list rejects the '-' wildcard. Enumerate
            # project-visible locations through the documented v1 locations API.
            seen_locations: set[str] = set()
            for location in self._pages(f"https://run.googleapis.com/v1/projects/{project}/locations", "locations"):
                loc = location.get("locationId")
                if not isinstance(loc, str) or not re.fullmatch(r"[a-z][a-z0-9-]*[0-9]", loc):
                    self.ctx.warn(f"cloud.gcp: invalid Cloud Run location for {project}; coverage unknown")
                    continue
                if loc in seen_locations:
                    continue
                seen_locations.add(loc)
                for svc in self._pages(f"https://run.googleapis.com/v2/projects/{project}/locations/{loc}/services", "services"):
                    yield {**svc, "_kind": "cloud-run-service", "_project": project, "_location": loc}
        if "cloudfunctions.googleapis.com" in enabled:
            for fn in self._pages(f"https://cloudfunctions.googleapis.com/v2/projects/{project}/locations/-/functions", "functions"):
                yield {"_kind": "cloud-function", "_project": project, **fn}
        assert self.http
        try:
            policy = self.http.post_json(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy", json={})
            if not isinstance(policy, dict) or "error" in policy:
                self.ctx.warn(f"cloud.gcp: invalid IAM policy response for {project}")
            else:
                yield {"_kind": "iam-policy", "_project": project, "bindings": policy.get("bindings", [])}
        except (HttpError, RequestException) as exc:
            status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
            self.ctx.warn(f"cloud.gcp: IAM policy not readable for {project} ({status})")
        for sa in self._pages(f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts", "accounts"):
            keys = self._get(f"https://iam.googleapis.com/v1/{sa['name']}/keys", keyTypes="USER_MANAGED") or {}
            yield {"_kind": "service-account", "_project": project, "user_managed_keys": len(keys.get("keys", [])), **sa}
        if "apikeys.googleapis.com" in enabled:
            for key in self._pages(f"https://apikeys.googleapis.com/v2/projects/{project}/locations/global/keys", "keys"):
                yield {"_kind": "api-key", "_project": project, **key}
        if "secretmanager.googleapis.com" in enabled:
            for s in self._pages(f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets", "secrets"):
                yield {"_kind": "secret-name", "_project": project, "name": s.get("name"), "createTime": s.get("createTime"), "labels": s.get("labels")}
        if self.audit_days > 0 and "aiplatform.googleapis.com" in enabled:
            yield from self._collect_audit(project)

    def _collect_audit(self, project: str) -> Iterator[dict[str, Any]]:
        assert self.http
        since = (datetime.now(UTC) - timedelta(days=self.audit_days)).isoformat()
        body = {"resourceNames": [f"projects/{project}"], "filter": f'protoPayload.serviceName=("aiplatform.googleapis.com" OR "dialogflow.googleapis.com" OR "discoveryengine.googleapis.com") AND (protoPayload.methodName:("Predict" OR "GenerateContent" OR "StreamGenerateContent" OR "Query" OR "DetectIntent" OR "Converse" OR "Answer")) AND timestamp>="{since}"', "pageSize": 1000, "orderBy": "timestamp desc"}
        token: str | None = None
        seen: set[str] = set()
        for _ in range(min(50, self.max_pages)):
            if token:
                body["pageToken"] = token
            try:
                data = self.http.post_json("https://logging.googleapis.com/v2/entries:list", json=body)
            except (HttpError, RequestException) as exc:
                status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
                self.ctx.warn(f"cloud.gcp: audit logs not readable for {project} ({status})")
                return
            if not isinstance(data, dict) or "error" in data or not isinstance(data.get("entries", []), list):
                self.ctx.warn(f"cloud.gcp: invalid audit log response for {project}")
                return
            for e in data.get("entries", []):
                if not isinstance(e, dict) or not isinstance(e.get("protoPayload") or {}, dict):
                    self.ctx.warn(f"cloud.gcp: invalid audit log entry for {project}")
                    continue
                pp = e.get("protoPayload") or {}
                yield {"_kind": "audit-event", "_project": project, "principal": get_path(pp, "authenticationInfo.principalEmail"), "method": pp.get("methodName"), "resource": pp.get("resourceName"), "timestamp": e.get("timestamp"), "userAgent": get_path(pp, "requestMetadata.callerSuppliedUserAgent"), "ip": get_path(pp, "requestMetadata.callerIp"), "delegation": get_path(pp, "authenticationInfo.serviceAccountDelegationInfo")}
            token = data.get("nextPageToken")
            if token is None or token == "":
                return
            if not isinstance(token, str) or token in seen:
                self.ctx.warn(f"cloud.gcp: invalid or repeated audit pagination token for {project}")
                return
            seen.add(token)
        self.ctx.warn(f"cloud.gcp: audit pagination limit reached for {project}")

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        callers: dict[tuple[str | None, str], dict[str, Any]] = {}
        handlers = {name[3:].replace("_", "-"): getattr(self, name) for name in dir(type(self)) if name.startswith("_h_")}
        for rec in records:
            self.ctx.examined()
            kind = rec.get("_kind") if isinstance(rec, dict) else None
            if not isinstance(kind, str) or kind not in handlers.keys() | {"audit-event"}:
                self.ctx.warn("cloud.gcp: record has missing, invalid, or unsupported _kind")
                continue
            try:
                if kind == "audit-event":
                    for field in ("principal", "method", "resource", "userAgent", "timestamp", "_project"):
                        if rec.get(field) is not None and not isinstance(rec[field], str):
                            raise ValueError("event field")
                    # A principal may call resources in several projects. A
                    # shared bucket would attribute all events to the first.
                    key = (rec.get("_project"), rec.get("principal") or "unknown")
                    agg = callers.setdefault(key, {"events": 0, "methods": {}, "resources": {}, "agents": {}, "first": None, "last": None, "project": rec.get("_project"), "delegated": False})
                    agg["events"] += 1
                    agg["methods"][rec.get("method")] = agg["methods"].get(rec.get("method"), 0) + 1
                    r = re.sub(r"projects/[^/]+/", "", str(rec.get("resource") or ""))[:120]
                    agg["resources"][r] = agg["resources"].get(r, 0) + 1
                    if rec.get("userAgent"):
                        agg["agents"][rec["userAgent"]] = agg["agents"].get(rec["userAgent"], 0) + 1
                    if rec.get("delegation"):
                        agg["delegated"] = True
                    t = rec.get("timestamp")
                    if t:
                        agg["first"] = t if not agg["first"] or t < agg["first"] else agg["first"]
                        agg["last"] = t if not agg["last"] or t > agg["last"] else agg["last"]
                    continue
                result = handlers[kind](rec)
                if isinstance(result, Finding):
                    yield result
                elif result:
                    yield from result
            except (ValueError, TypeError, KeyError, AttributeError):
                self.ctx.warn("cloud.gcp: record has invalid fields for its _kind")
        for (_, principal), agg in callers.items():
            try:
                yield self._caller_finding(principal, agg)
            except (ValueError, TypeError, KeyError, AttributeError):
                self.ctx.warn("cloud.gcp: invalid aggregated caller fields")

    def _h_project(self, rec: dict[str, Any]) -> Finding | None:
        services = rec.get("ai_services") or []
        if not services:
            return None
        f = cloud_finding(self.name, "gcp", kind=Kind.CLOUD_RESOURCE, title=f"AI APIs enabled in project {rec.get('project')}: {', '.join(AI_SERVICES.get(s, s) for s in services)}", resource=f"projects/{rec.get('project')}/ai-apis", resource_type="enabled-apis", account=rec.get("project"))
        for s in services:
            if s == "aiplatform.googleapis.com":
                f.add_model_provider("provider.google-vertex-ai")
            elif s == "generativelanguage.googleapis.com":
                f.add_model_provider("provider.google-gemini")
            elif s in {"dialogflow.googleapis.com", "discoveryengine.googleapis.com"}:
                f.add_framework("cloud.gcp-vertex-agent-engine")
        f.add_evidence(Evidence(signal="gcp:enabled-apis", description=f"Enabled: {', '.join(services)}", weight=0.3))
        f.metadata["services"] = services
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_reasoning_engine(self, rec: dict[str, Any]) -> Finding:
        name = rec.get("name", "")
        f = cloud_finding(self.name, "gcp", kind=Kind.AGENT, title=f"Vertex AI Agent Engine: {rec.get('displayName') or name.rsplit('/', 1)[-1]}", resource=name, resource_type="reasoning-engine", account=rec.get("_project"), region=rec.get("_location"), first_seen=rec.get("createTime"), last_seen=rec.get("updateTime"))
        f.add_framework("cloud.gcp-vertex-agent-engine")
        f.add_model_provider("provider.google-vertex-ai")
        f.add_capability("tool-use")
        spec = rec.get("spec") or {}
        pkg = spec.get("packageSpec") or {}
        deps = str(pkg.get("requirementsGcsUri") or "")
        class_methods = spec.get("classMethods") or []
        agent_framework = str(spec.get("agentFramework") or get_path(spec, "deploymentSpec.agentFramework") or "")
        for key, sig in (("adk", "framework.google-adk"), ("langgraph", "framework.langgraph"), ("langchain", "framework.langchain"), ("ag2", "framework.autogen"), ("autogen", "framework.autogen"), ("llama", "framework.llamaindex"), ("crewai", "framework.crewai")):
            if key in agent_framework.lower():
                f.add_framework(sig)
        f.add_evidence(Evidence(signal="gcp:reasoning-engine", description=f"Agent Engine '{rec.get('displayName')}' framework={agent_framework or 'unknown'}, {len(class_methods)} exposed method(s), python {pkg.get('pythonVersion')}: {truncate(rec.get('description'), 120)}", location=name, weight=0.97, signature="cloud.gcp-vertex-agent-engine"))
        name_hint(self.index, f, rec.get("displayName"), rec.get("description"))
        f.metadata.update({"framework": agent_framework, "class_methods": [m.get("name") for m in class_methods if isinstance(m, dict)][:20], "requirements": deps, "python": pkg.get("pythonVersion"), "description": truncate(rec.get("description"), 300)})
        return done(f, self.index, Kind.AGENT)

    def _h_vertex_endpoint(self, rec: dict[str, Any]) -> Finding | None:
        models = rec.get("deployedModels") or []
        if not models:
            return None
        name = rec.get("name", "")
        f = cloud_finding(self.name, "gcp", kind=Kind.CLOUD_RESOURCE, title=f"Vertex AI endpoint: {rec.get('displayName')}", resource=name, resource_type="vertex-endpoint", account=rec.get("_project"), region=rec.get("_location"), first_seen=rec.get("createTime"), last_seen=rec.get("updateTime"))
        f.add_model_provider("provider.google-vertex-ai")
        f.add_evidence(Evidence(signal="gcp:vertex-endpoint", description=f"Endpoint '{rec.get('displayName')}' serves {len(models)} model(s): {', '.join(str(m.get('displayName') or m.get('model')) for m in models[:5])}", location=name, weight=0.5))
        f.models = [str(m.get("model")) for m in models][:10]
        apply_matches(f, model_matches(self.index, *f.models), weight_scale=0.5)
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_dialogflow_agent(self, rec: dict[str, Any]) -> Finding:
        name = rec.get("name", "")
        f = cloud_finding(self.name, "gcp", kind=Kind.AGENT, title=f"Dialogflow CX agent: {rec.get('displayName')}", resource=name, resource_type="dialogflow-cx-agent", account=rec.get("_project"), region=rec.get("_location"))
        f.add_framework("cloud.gcp-vertex-agent-engine")
        gen = rec.get("genAppBuilderSettings") or rec.get("generativeSettings") or {}
        f.add_evidence(Evidence(signal="gcp:dialogflow", description=f"Dialogflow CX agent '{rec.get('displayName')}' ({rec.get('defaultLanguageCode')}), generative settings: {bool(gen)}, playbooks: {rec.get('startPlaybook') is not None}", location=name, weight=0.9, signature="cloud.gcp-vertex-agent-engine"))
        if gen or rec.get("startPlaybook"):
            f.add_capability("tool-use")
        f.metadata.update({"description": truncate(rec.get("description")), "generative": bool(gen), "start_playbook": rec.get("startPlaybook"), "enable_stackdriver_logging": rec.get("enableStackdriverLogging")})
        return done(f, self.index, Kind.AGENT)

    def _h_discovery_engine(self, rec: dict[str, Any]) -> Finding:
        name = rec.get("name", "")
        solution = rec.get("solutionType")
        f = cloud_finding(self.name, "gcp", kind=Kind.AGENT if solution in {"SOLUTION_TYPE_CHAT", "SOLUTION_TYPE_GENERATIVE_CHAT"} else Kind.CLOUD_RESOURCE, title=f"Vertex AI Search / Agentspace engine: {rec.get('displayName')}", resource=name, resource_type="discovery-engine", account=rec.get("_project"), region=rec.get("_location"), first_seen=rec.get("createTime"), last_seen=rec.get("updateTime"))
        f.add_framework("cloud.gcp-vertex-agent-engine")
        f.add_capability("rag")
        f.add_evidence(Evidence(signal="gcp:discovery-engine", description=f"Engine '{rec.get('displayName')}' type {solution} industry {rec.get('industryVertical')} data stores {', '.join(rec.get('dataStoreIds') or [])[:200]}", location=name, weight=0.85, signature="cloud.gcp-vertex-agent-engine"))
        f.metadata.update({"solution_type": solution, "data_stores": rec.get("dataStoreIds")})
        return done(f, self.index, f.kind)

    def _h_cloud_run_service(self, rec: dict[str, Any]) -> Finding | None:
        name = rec.get("name", "")
        tmpl = rec.get("template") or {}
        f = cloud_finding(self.name, "gcp", kind=Kind.CLOUD_RESOURCE, title=f"Cloud Run service: {name.rsplit('/', 1)[-1]}", resource=name, resource_type="cloud-run-service", account=rec.get("_project"), region=name.split("/locations/")[1].split("/")[0] if "/locations/" in name else None, first_seen=rec.get("createTime"), last_seen=rec.get("updateTime"))
        for c in tmpl.get("containers") or []:
            if c.get("image"):
                apply_matches(f, self.index.match_image(c["image"]), location=name)
            env = {e.get("name"): e.get("value") for e in c.get("env") or [] if e.get("name")}
            scan_env(self.index, f, env, location=name)
            for e in c.get("env") or []:
                if e.get("valueSource") and e.get("name"):
                    apply_matches(f, self.index.match_env(e["name"]), location=name, weight_scale=0.6)
        name_hint(self.index, f, name.rsplit("/", 1)[-1], rec.get("description"))
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(Evidence(signal="gcp:cloud-run", description=f"Service '{name.rsplit('/', 1)[-1]}' images {', '.join(str(c.get('image')) for c in tmpl.get('containers') or [])[:200]}; service account {tmpl.get('serviceAccount')}; ingress {rec.get('ingress')}", location=rec.get("uri") or name, weight=0.25))
        if rec.get("ingress") == "INGRESS_TRAFFIC_ALL":
            f.add_tag("public-ingress")
        f.owner = (rec.get("labels") or {}).get("owner") or (rec.get("labels") or {}).get("team") or rec.get("lastModifier") or rec.get("creator")
        f.metadata.update({"service_account": tmpl.get("serviceAccount"), "uri": rec.get("uri"), "ingress": rec.get("ingress"), "images": [c.get("image") for c in tmpl.get("containers") or []], "labels": rec.get("labels")})
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_cloud_function(self, rec: dict[str, Any]) -> Finding | None:
        name = rec.get("name", "")
        svc = rec.get("serviceConfig") or {}
        f = cloud_finding(self.name, "gcp", kind=Kind.CLOUD_RESOURCE, title=f"Cloud Function: {name.rsplit('/', 1)[-1]}", resource=name, resource_type="cloud-function", account=rec.get("_project"), region=name.split("/locations/")[1].split("/")[0] if "/locations/" in name else None, last_seen=rec.get("updateTime"))
        scan_env(self.index, f, svc.get("environmentVariables"), location=name)
        for s in svc.get("secretEnvironmentVariables") or []:
            apply_matches(f, self.index.match_env(str(s.get("key"))), location=name, weight_scale=0.6)
        name_hint(self.index, f, name.rsplit("/", 1)[-1], rec.get("description"))
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(Evidence(signal="gcp:cloud-function", description=f"Function '{name.rsplit('/', 1)[-1]}' runtime {get_path(rec, 'buildConfig.runtime')} service account {svc.get('serviceAccountEmail')} ingress {svc.get('ingressSettings')}; trigger {get_path(rec, 'eventTrigger.eventType') or 'https'}", location=svc.get("uri") or name, weight=0.25))
        if rec.get("eventTrigger"):
            f.add_capability("autonomous")
        f.metadata.update({"runtime": get_path(rec, "buildConfig.runtime"), "service_account": svc.get("serviceAccountEmail"), "trigger": get_path(rec, "eventTrigger.eventType"), "uri": svc.get("uri"), "labels": rec.get("labels")})
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_iam_policy(self, rec: dict[str, Any]) -> Iterator[Finding]:
        project = rec.get("_project")
        per_member: dict[str, list[str]] = {}
        for b in rec.get("bindings") or []:
            role = b.get("role", "")
            if self.index.match_scope(role) or role in {"roles/owner", "roles/editor"}:
                for m in b.get("members") or []:
                    per_member.setdefault(m, []).append(role)
        for member, roles in per_member.items():
            roles = sorted(set(roles))
            broad_roles = [role for role in roles if role in {"roles/owner", "roles/editor"}]
            f = cloud_finding(self.name, "gcp", kind=Kind.IAM_GRANT, title=f"IAM member with AI or broad project access in {project}: {member}", resource=f"projects/{project}/iam/{member}", resource_type="iam-binding", account=project, surface=Surface.IDENTITY)
            llm = scan_iam_actions(self.index, f, roles, location=f"projects/{project}")
            if not llm and not broad_roles:
                continue
            f.add_evidence(Evidence(signal="gcp:iam", description=f"{member} holds {', '.join(roles)}", weight=0.45 if member.startswith("serviceAccount:") else 0.25))
            if broad_roles:
                f.add_tag("broad-project-access")
                f.add_evidence(Evidence(signal="gcp:iam-broad-role", description=f"Broad project grant ({', '.join(broad_roles)}) can enable AI access, subject to applicable policies and service availability; this is access evidence, not observed AI execution.", location=f"projects/{project}", weight=0.25))
            if member.startswith("serviceAccount:"):
                f.add_tag("service-account")
            if member.startswith(("allUsers", "allAuthenticatedUsers")):
                f.add_tag("public-principal")
            name_hint(self.index, f, member)
            f.metadata.update({"member": member, "roles": roles, "broad_roles": broad_roles, "evidence_class": "access-grant"})
            yield done(f, self.index, Kind.IAM_GRANT)

    def _h_service_account(self, rec: dict[str, Any]) -> Finding | None:
        email = rec.get("email", "")
        f = cloud_finding(self.name, "gcp", kind=Kind.SERVICE_IDENTITY, title=f"Service account: {email}", resource=rec.get("name") or email, resource_type="service-account", account=rec.get("_project"), surface=Surface.IDENTITY)
        name_hint(self.index, f, rec.get("displayName"), rec.get("description"), email.split("@")[0])
        if not f.frameworks:
            return None
        f.add_evidence(Evidence(signal="gcp:service-account", description=f"Service account '{rec.get('displayName') or email}' with {rec.get('user_managed_keys', 0)} user-managed key(s); disabled={rec.get('disabled', False)}", weight=0.35))
        if rec.get("user_managed_keys"):
            f.add_tag("user-managed-keys")
        f.metadata.update({"email": email, "keys": rec.get("user_managed_keys"), "disabled": rec.get("disabled")})
        return done(f, self.index, Kind.SERVICE_IDENTITY)

    def _h_api_key(self, rec: dict[str, Any]) -> Finding | None:
        targets = [t.get("service") for t in (rec.get("restrictions") or {}).get("apiTargets") or []]
        ai_targets = [t for t in targets if t in AI_SERVICES]
        unrestricted = not targets
        if not ai_targets and not unrestricted:
            return None
        f = cloud_finding(self.name, "gcp", kind=Kind.SECRET, title=f"API key {'for ' + ', '.join(AI_SERVICES[t] for t in ai_targets) if ai_targets else '(unrestricted)'}: {rec.get('displayName') or rec.get('uid')}", resource=str(rec.get("name") or rec.get("uid") or ""), resource_type="api-key", account=rec.get("_project"), first_seen=rec.get("createTime"), last_seen=rec.get("updateTime"))
        if "generativelanguage.googleapis.com" in ai_targets or unrestricted:
            f.add_model_provider("provider.google-gemini")
        if "aiplatform.googleapis.com" in ai_targets:
            f.add_model_provider("provider.google-vertex-ai")
        f.add_evidence(Evidence(signal="gcp:api-key", description=f"API key '{rec.get('displayName')}' restricted to {', '.join(targets) or 'nothing (all APIs)'}", weight=0.5 if ai_targets else 0.25))
        if unrestricted:
            f.add_tag("unrestricted-api-key")
        f.metadata.update({"targets": targets, "browser_restrictions": bool((rec.get("restrictions") or {}).get("browserKeyRestrictions")), "server_restrictions": bool((rec.get("restrictions") or {}).get("serverKeyRestrictions"))})
        return done(f, self.index, Kind.SECRET)

    def _h_secret_name(self, rec: dict[str, Any]) -> Finding | None:
        name = str(rec.get("name", "")).rsplit("/", 1)[-1]
        norm = "".join(ch if ch.isalnum() else "_" for ch in name).upper().strip("_")
        matches = self.index.match_env(norm)
        if not matches and not any(k in name.lower() for k in ("openai", "anthropic", "claude", "gemini", "llm", "huggingface", "mistral", "cohere", "groq", "langsmith", "langfuse", "pinecone", "tavily")):
            return None
        f = cloud_finding(self.name, "gcp", kind=Kind.SECRET, title=f"Secret Manager secret for LLM provider: {name}", resource=rec.get("name") or name, resource_type="secret-manager-secret", account=rec.get("_project"), first_seen=rec.get("createTime"))
        apply_matches(f, matches, weight_scale=0.7)
        f.add_evidence(Evidence(signal="gcp:secret", description=f"Secret '{name}' looks like an LLM provider credential (name only)", weight=0.4))
        f.add_tag("managed-secret")
        f.metadata["labels"] = rec.get("labels")
        return done(f, self.index, Kind.SECRET)

    def _caller_finding(self, principal: str, agg: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "gcp", kind=Kind.GATEWAY_CALLER, title=f"Vertex AI caller: {principal} — {agg['events']} call(s)", resource=f"audit:{principal}", resource_type="caller/principal", account=agg.get("project"), first_seen=agg["first"], last_seen=agg["last"], surface=Surface.GATEWAY)
        f.add_model_provider("provider.google-vertex-ai")
        for ua in list(agg["agents"])[:10]:
            apply_matches(f, self.index.match_user_agent(ua))
        f.models = sorted(agg["resources"], key=lambda r: -agg["resources"][r])[:10]
        f.add_evidence(Evidence(signal="gcp:audit", description=f"{agg['events']} call(s) ({', '.join(f'{k}×{v}' for k, v in list(agg['methods'].items())[:5])}) by {principal}", weight=0.45 if principal.endswith("gserviceaccount.com") else 0.25))
        if principal.endswith("gserviceaccount.com"):
            f.add_tag("service-account")
        if agg.get("delegated"):
            f.add_tag("delegation")
            f.add_capability("delegated-identity")
        if any("reasoningEngines" in r for r in agg["resources"]):
            f.add_framework("cloud.gcp-vertex-agent-engine")
        name_hint(self.index, f, principal)
        f.metadata.update({"principal": principal, "events": agg["events"], "methods": agg["methods"], "resources": dict(sorted(agg["resources"].items(), key=lambda kv: -kv[1])[:10]), "user_agents": dict(sorted(agg["agents"].items(), key=lambda kv: -kv[1])[:5])})
        return done(f, self.index, Kind.GATEWAY_CALLER)
