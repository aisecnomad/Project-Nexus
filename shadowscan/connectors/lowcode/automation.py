"""Automation platforms with native AI / agent steps: n8n, Make, Zapier, Workato.

Each connector lists workflows (and, where the platform has them, dedicated
agents), fingerprints AI steps with the platform signatures and emits one
``workflow`` / ``agent`` finding per AI-enabled definition.

Offline exports:

* n8n     – ``/api/v1/workflows`` JSON (or exported workflow JSON files)
* Make    – ``/api/v2/scenarios`` list with embedded ``blueprint`` (or blueprint JSON files) and ``/api/v2/ai-agents``
* Zapier  – Zapier for Companies / Enterprise CSV or JSON export of Zaps (title, status, apps/steps, owner)
* Workato – ``/api/recipes`` JSON (``items`` with ``code`` and ``config``)
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import apply_matches, blob_matches, finalize, model_matches, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path, truncate


class _AutomationBase(BaseConnector):
    surface: ClassVar[Surface] = Surface.LOWCODE
    platform_signature: ClassVar[str] = ""

    def _guarded_finding(
        self, rec: dict[str, Any], build: Callable[[dict[str, Any]], Finding | None], what: str,
    ) -> Finding | None:
        """Isolate one malformed record so the rest of the export is still analysed."""
        try:
            return build(rec)
        except (AttributeError, TypeError, ValueError, KeyError, RecursionError, MatchTimeoutError) as exc:
            detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
            self.ctx.warn(f"{self.name}: skipped a malformed {what} record ({type(exc).__name__}){detail}")
            return None

    @staticmethod
    def _identified(rec: dict[str, Any], *keys: str) -> bool:
        return any(rec.get(key) not in (None, "") for key in keys)

    def _workflow_finding(
        self,
        *,
        wid: str,
        name: str,
        blob: str,
        owner: str | None,
        account: str | None,
        active: bool | None,
        created: str | None,
        updated: str | None,
        triggers: list[str],
        ai_steps: list[str],
        kind: Kind = Kind.WORKFLOW,
        resource_type: str = "workflow",
        extra: dict[str, Any] | None = None,
        url: str | None = None,
    ) -> Finding | None:
        matches = blob_matches(self.index, blob)
        if not matches and not ai_steps:
            return None
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=kind,
            title=f"{self.index.get(self.platform_signature).name if self.index.get(self.platform_signature) else self.provider} {'agent' if kind == Kind.AGENT else 'workflow'} with AI steps: {name}",  # type: ignore[union-attr]
            resource=f"{self.provider}:{resource_type}:{wid}",
            resource_type=resource_type,
            provider=self.provider,
            account=account,
            owner=owner,
            first_seen=created,
            last_seen=updated,
        )
        f.add_framework(self.platform_signature)
        apply_matches(f, matches, location=url)
        if ai_steps:
            f.add_evidence(Evidence(signal=f"{self.provider}:ai-steps", description=f"AI steps: {', '.join(ai_steps[:10])}", location=url, weight=0.8, signature=self.platform_signature))
            f.add_capability("tool-use")
        if any(re.search(r"(?i)cron|schedule|interval|timer|recurr", t) for t in triggers):
            f.add_capability("autonomous")
            f.add_tag("scheduled")
        if any(re.search(r"(?i)webhook|trigger|event|poll", t) for t in triggers):
            f.add_capability("autonomous")
            f.add_tag("event-triggered")
        if active is False:
            f.add_tag("inactive")
        f.metadata.update({"active": active, "triggers": triggers[:10], "ai_steps": ai_steps[:20], "url": url, **(extra or {})})
        finalize(f, self.index)
        f.kind = kind
        return f


# ------------------------------------------------------------------ n8n
class N8nConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.n8n"
    provider: ClassVar[str | None] = "n8n"
    platform_signature: ClassVar[str] = "platform.n8n"
    description: ClassVar[str] = "n8n workflows using AI Agent / LLM / MCP nodes."
    config_keys: ClassVar[dict[str, str]] = {
        "api_url": "https://n8n.example.com/api/v1 (env N8N_API_URL)",
        "api_key": "X-N8N-API-KEY (env N8N_API_KEY)",
        "input": "offline: workflow list JSON or directory of exported workflows",
    }

    def collect(self) -> Iterable[dict[str, Any]]:
        base = str(self.ctx.get("api_url", env="N8N_API_URL") or "").rstrip("/")
        key = self.ctx.get("api_key", env="N8N_API_KEY")
        if not (base and key):
            raise ConnectorError("lowcode.n8n: api_url and api_key required")
        http = HttpClient(base, headers={"X-N8N-API-KEY": key})
        yield from http.paginate_token("/workflows", params={"limit": 250}, items_key="data", token_key="nextCursor", token_param="cursor", max_pages=max(1, int(self.ctx.get("max_pages", 1000))))

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for w in records:
            if not self._valid_workflow(w):
                # Error bodies ({"message": ...}) must not pass as an empty inventory.
                self.ctx.warn("lowcode.n8n: unsupported or malformed workflow record; coverage incomplete")
                continue
            self.ctx.examined()
            f = self._guarded_finding(w, self._n8n_finding, "workflow")
            if f:
                yield f

    def _valid_workflow(self, w: Any) -> bool:
        return (
            self._record_fields_valid(w, strings=("name", "createdAt", "updatedAt"), mappings=("homeProject",), arrays=("nodes", "tags"))
            and isinstance(w.get("nodes"), list)
            and all(isinstance(n, dict) for n in w["nodes"])
        )

    def _n8n_finding(self, w: dict[str, Any]) -> Finding | None:
        nodes = w.get("nodes") or []
        types = [str(n.get("type", "")) for n in nodes]
        ai_steps = [f"{n.get('name')} ({n.get('type')})" for n in nodes if re.search(r"n8n-nodes-langchain|openAi|anthropic|gemini|mistral|ollama|huggingFace|\.agent$|mcp", str(n.get("type", "")), re.I)]
        triggers = [t for t in types if re.search(r"trigger|cron|schedule|webhook", t, re.I)]
        models = [str(get_path(n, "parameters.model.value", "parameters.model", "parameters.modelId.value", "parameters.options.model")) for n in nodes if get_path(n, "parameters.model", "parameters.modelId")]
        f = self._workflow_finding(
            wid=str(w.get("id") or w.get("name")),
            name=str(w.get("name")),
            blob=json.dumps({"nodes": [{"type": n.get("type"), "parameters": n.get("parameters")} for n in nodes]}, default=str)[:300_000],
            owner=get_path(w, "homeProject.name", "shared.0.project.name", "owner", "createdBy"),
            account=self.ctx.get("api_url", env="N8N_API_URL"),
            active=w.get("active"),
            created=w.get("createdAt"),
            updated=w.get("updatedAt"),
            triggers=triggers,
            ai_steps=ai_steps,
            kind=Kind.AGENT if any(t.endswith(".agent") or t.endswith("agentTool") for t in types) else Kind.WORKFLOW,
            extra={"node_count": len(nodes), "node_types": sorted(set(types))[:40], "tags": [t.get("name") for t in w.get("tags") or [] if isinstance(t, dict)]},
        )
        if f:
            apply_matches(f, model_matches(self.index, *models), weight_scale=0.5)
            f.models = sorted({m for m in models if m and m != "None"})
            if any("toolCode" in t or "executeCommand" in t or "n8n-nodes-base.code" in t or "ssh" in t.lower() for t in types):
                f.add_capability("code-exec")
        return f


# ------------------------------------------------------------------ Make
class MakeConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.make"
    provider: ClassVar[str | None] = "make"
    platform_signature: ClassVar[str] = "platform.make"
    description: ClassVar[str] = "Make (Integromat) scenarios with AI modules and Make AI Agents."
    config_keys: ClassVar[dict[str, str]] = {
        "api_url": "zone API base, e.g. https://eu1.make.com/api/v2 (env MAKE_API_URL)",
        "token": "API token (env MAKE_API_TOKEN)",
        "team_id": "team id (or organization_id to enumerate teams)",
        "input": "offline: scenarios JSON (with blueprint) / ai-agents JSON / blueprint files",
    }

    def _offset_pages(self, http: HttpClient, path: str, items_key: str, **params: Any) -> Iterator[dict[str, Any]]:
        seen: set[str] = set()
        for page in range(max(1, int(self.ctx.get("max_pages", 1000)))):
            try:
                data = http.get_json(path, params={**params, "pg[limit]": 100, "pg[offset]": page * 100})
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
                self.ctx.warn(f"lowcode.make: collection incomplete for {path} ({status})")
                return
            items = data.get(items_key) if isinstance(data, dict) else None
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                self.ctx.warn(f"lowcode.make: invalid {items_key} page")
                return
            fingerprint = hashlib.sha256(json.dumps(items, sort_keys=True, default=str).encode()).hexdigest()
            if fingerprint in seen:
                self.ctx.warn(f"lowcode.make: repeated pagination page for {path}")
                return
            seen.add(fingerprint)
            yield from items
            if len(items) < 100:
                return
        self.ctx.warn(f"lowcode.make: pagination limit reached for {path}")

    def collect(self) -> Iterable[dict[str, Any]]:
        base = str(self.ctx.get("api_url", env="MAKE_API_URL") or "").rstrip("/")
        token = self.ctx.get("token", env="MAKE_API_TOKEN")
        if not (base and token):
            raise ConnectorError("lowcode.make: api_url and token required")
        http = HttpClient(base, headers={"Authorization": f"Token {token}"})
        teams: list[str] = []
        if self.ctx.get("team_id"):
            teams = [str(self.ctx.get("team_id"))]
        elif self.ctx.get("organization_id"):
            teams = [str(t["id"]) for t in self._offset_pages(http, "/teams", "teams", organizationId=self.ctx.get("organization_id"))]
        else:
            raise ConnectorError("lowcode.make: team_id or organization_id required")
        for team in teams:
            blueprint_errors: dict[str, int] = {}
            for s in self._offset_pages(http, "/scenarios", "scenarios", teamId=team):
                try:
                    bp = http.get_json(f"/scenarios/{s['id']}/blueprint")
                    response = bp.get("response") if isinstance(bp, dict) else None
                    blueprint = (response.get("blueprint") if isinstance(response, dict) else None) or bp
                    if not isinstance(blueprint, dict):
                        self.ctx.warn(f"lowcode.make: invalid blueprint for scenario {s['id']}")
                    else:
                        s["blueprint"] = blueprint
                except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                    status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
                    blueprint_errors[status] = blueprint_errors.get(status, 0) + 1
                yield {**s, "_kind": "scenario", "_team": team}
            if blueprint_errors:
                details = ", ".join(f"{status}: {total}" for status, total in sorted(blueprint_errors.items()))
                self.ctx.warn(f"lowcode.make: blueprints unreadable for {sum(blueprint_errors.values())} scenario(s) in team {team} ({details}); workflow inventory incomplete")
            try:
                data = http.get_json("/ai-agents/v1/agents", params={"teamId": team})
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
                self.ctx.warn(f"lowcode.make: AI agents unreadable for team {team} ({status}); agent inventory incomplete")
                continue
            agents = data
            if isinstance(data, dict):
                agents = [data] if data.get("id") and data.get("name") else data.get("aiAgents", data.get("agents"))
            if not isinstance(agents, list):
                self.ctx.warn(f"lowcode.make: invalid AI agents response for team {team}")
                continue
            for agent in agents:
                if not isinstance(agent, dict):
                    self.ctx.warn(f"lowcode.make: invalid AI agent record for team {team}")
                    continue
                yield {**agent, "_kind": "ai-agent", "_team": team}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                # Error bodies ({"message": ..., "code": ...}) must not pass as an empty inventory.
                self.ctx.warn("lowcode.make: unsupported or malformed provider record; coverage incomplete")
                continue
            self.ctx.examined()
            f = self._guarded_finding(rec, self._agent_finding if kind == "ai-agent" else self._scenario_finding, kind)
            if f:
                yield f

    def _record_kind(self, rec: Any) -> str | None:
        if not self._record_fields_valid(rec, strings=("_kind", "name", "_team"), mappings=("blueprint", "createdByUser", "scheduling"), arrays=("tools",)):
            return None
        kind = rec.get("_kind") or ("ai-agent" if "agentId" in rec or ("model" in rec and "systemPrompt" in rec) else "scenario")
        if kind == "ai-agent":
            return kind if self._identified(rec, "id", "agentId", "name") else None
        if kind != "scenario":
            return None
        blueprint = rec.get("blueprint")
        identified = self._identified(rec, "id", "name") or (isinstance(blueprint, dict) and ("flow" in blueprint or bool(blueprint.get("name"))))
        return kind if identified else None

    def _agent_finding(self, rec: dict[str, Any]) -> Finding | None:
        f = self._workflow_finding(
            wid=str(rec.get("id") or rec.get("agentId") or rec.get("name")),
            name=str(rec.get("name")),
            blob=json.dumps(rec, default=str)[:100_000],
            owner=str(rec.get("createdBy") or rec.get("ownerId") or "") or None,
            account=str(rec.get("_team") or rec.get("teamId") or "") or None,
            active=rec.get("active", True),
            created=rec.get("createdAt"),
            updated=rec.get("updatedAt"),
            triggers=[],
            ai_steps=[f"Make AI Agent (model {rec.get('model') or rec.get('llmModel') or rec.get('defaultModel') or '?'})"],
            kind=Kind.AGENT,
            resource_type="ai-agent",
            extra={"model": rec.get("model") or rec.get("llmModel") or rec.get("defaultModel"), "tools": [t.get("name") for t in rec.get("tools") or [] if isinstance(t, dict)][:20], "system_prompt": truncate(str(rec.get("systemPrompt") or ""), 200)},
        )
        if f:
            apply_matches(f, model_matches(self.index, rec.get("model") or rec.get("llmModel") or rec.get("defaultModel")), weight_scale=0.5)
        return f

    def _scenario_finding(self, rec: dict[str, Any]) -> Finding | None:
        bp = rec.get("blueprint") or rec
        flow = bp.get("flow") if isinstance(bp, dict) else None
        modules = [str(m.get("module", "")) for m in (flow or []) if isinstance(m, dict)]
        ai_steps = [m for m in modules if re.search(r"openai|anthropic|claude|gemini|mistral|ai-agents|perplexity|hugging|eden-ai|cohere|groq|deepseek|assistants", m, re.I)]
        triggers = [m for m in modules[:1]] + [m for m in modules if re.search(r"webhook|watch|schedule|trigger", m, re.I)]
        return self._workflow_finding(
            wid=str(rec.get("id") or rec.get("name")),
            name=str(rec.get("name") or bp.get("name") if isinstance(bp, dict) else rec.get("name")),
            blob=json.dumps(bp, default=str)[:300_000],
            owner=str(rec.get("createdByUser", {}).get("name") if isinstance(rec.get("createdByUser"), dict) else rec.get("createdBy") or "") or None,
            account=str(rec.get("_team") or rec.get("teamId") or "") or None,
            active=rec.get("isActive", rec.get("active")),
            created=rec.get("createdAt") or rec.get("created"),
            updated=rec.get("lastEdit") or rec.get("updatedAt"),
            triggers=triggers,
            ai_steps=ai_steps,
            kind=Kind.AGENT if any("ai-agents" in m for m in modules) else Kind.WORKFLOW,
            resource_type="scenario",
            extra={"module_count": len(modules), "modules": sorted(set(modules))[:40], "scheduling": rec.get("scheduling")},
        )


# ---------------------------------------------------------------- Zapier
class ZapierConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.zapier"
    provider: ClassVar[str | None] = "zapier"
    platform_signature: ClassVar[str] = "platform.zapier"
    description: ClassVar[str] = "Zaps with AI steps (ChatGPT, Claude, Gemini, AI by Zapier) and Zapier Agents from account exports."
    config_keys: ClassVar[dict[str, str]] = {
        "token": "OAuth bearer with `zap` scope for https://api.zapier.com/v2/zaps (env ZAPIER_TOKEN)",
        "input": "offline: Zapier for Companies CSV/JSON export of Zaps or Agents",
    }
    offline_formats: ClassVar[str] = "CSV / JSON export"

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("token", env="ZAPIER_TOKEN")
        if not token:
            raise ConnectorError("lowcode.zapier: token required (or use an offline export)")
        http = HttpClient("https://api.zapier.com", headers={"Authorization": f"Bearer {token}"})
        url: str | None = "/v2/zaps"
        seen: set[str] = set()
        for _ in range(max(1, int(self.ctx.get("max_pages", 1000)))):
            if not url:
                return
            if not isinstance(url, str) or url in seen:
                self.ctx.warn("lowcode.zapier: invalid or repeated pagination link")
                return
            seen.add(url)
            data = http.get_json(url, params={"limit": 100})
            if not isinstance(data, dict) or not isinstance(data.get("data"), list):
                raise ConnectorError("lowcode.zapier: invalid collection response")
            yield from data["data"]
            url = get_path(data, "links.next")
        if url:
            self.ctx.warn("lowcode.zapier: pagination limit reached")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            self.ctx.examined()
            f = self._guarded_finding(rec, self._zap_finding, "zap")
            if f:
                yield f

    def _zap_finding(self, rec: dict[str, Any]) -> Finding | None:
        # JSON exports may carry numeric titles; CSV columns are always text.
        title = str(rec.get("title") or rec.get("name") or rec.get("Title") or rec.get("Zap") or rec.get("id"))
        steps = rec.get("steps") or rec.get("Steps") or rec.get("apps") or rec.get("Apps") or []
        if isinstance(steps, str):
            steps_list = [s.strip() for s in re.split(r"[,;|>→]", steps) if s.strip()]
        else:
            steps_list = [str(get_path(s, "app.title", "app", "title", "action") or s) for s in steps] if isinstance(steps, list) else []
        blob = json.dumps(rec, default=str)[:100_000]
        ai_steps = [s for s in steps_list if re.search(r"(?i)chatgpt|openai|claude|anthropic|gemini|ai by zapier|zapier ai|agent|copilot|gpt|perplexity|mistral|hugging", s)]
        owner = rec.get("owner") or rec.get("Owner") or get_path(rec, "owner.email", "user.email", "creator")
        kind = Kind.AGENT if re.search(r"(?i)\bagent\b", title) or rec.get("type") == "agent" or "instructions" in rec else Kind.WORKFLOW
        f = self._workflow_finding(
            wid=str(rec.get("id") or rec.get("Id") or title),
            name=title,
            blob=blob,
            owner=str(owner) if owner else None,
            account=str(rec.get("account") or rec.get("Account") or rec.get("team") or "") or None,
            active=_truthy(rec.get("is_enabled", rec.get("status", rec.get("Status")))),
            created=rec.get("created_at") or rec.get("Created"),
            updated=rec.get("updated_at") or rec.get("Modified") or rec.get("last_run"),
            triggers=steps_list[:1],
            ai_steps=ai_steps,
            kind=kind,
            # Title-based agent classification can change without changing
            # the source entity. Only structural source type selects its
            # namespace; a zap named "AI agent" remains the same zap.
            resource_type="agent" if rec.get("type") == "agent" or "instructions" in rec else "zap",
            extra={"steps": steps_list[:20], "status": rec.get("status") or rec.get("Status")},
            url=rec.get("url") or rec.get("editor_url"),
        )
        if f:
            apply_matches(f, name_matches(self.index, " ".join(ai_steps)), weight_scale=0.5)
        return f


# --------------------------------------------------------------- Workato
class WorkatoConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.workato"
    provider: ClassVar[str | None] = "workato"
    platform_signature: ClassVar[str] = "platform.workato"
    description: ClassVar[str] = "Workato recipes using GenAI / LLM connectors and agentic recipes."
    config_keys: ClassVar[dict[str, str]] = {
        "api_url": "default https://www.workato.com/api (EU: https://app.eu.workato.com/api)",
        "token": "API client token (env WORKATO_API_TOKEN)",
        "input": "offline: /api/recipes JSON",
    }

    def collect(self) -> Iterable[dict[str, Any]]:
        base = str(self.ctx.get("api_url", "https://www.workato.com/api", env="WORKATO_API_URL")).rstrip("/")
        token = self.ctx.get("token", env="WORKATO_API_TOKEN")
        if not token:
            raise ConnectorError("lowcode.workato: token required")
        http = HttpClient(base, headers={"Authorization": f"Bearer {token}"})
        seen: set[str] = set()
        for page in range(1, max(1, int(self.ctx.get("max_pages", 1000))) + 1):
            data = http.get_json("/recipes", params={"per_page": 100, "page": page})
            items = data.get("items") if isinstance(data, dict) else data
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ConnectorError("lowcode.workato: invalid recipe page")
            fingerprint = hashlib.sha256(json.dumps(items, sort_keys=True, default=str).encode()).hexdigest()
            if fingerprint in seen:
                self.ctx.warn("lowcode.workato: repeated pagination page")
                return
            seen.add(fingerprint)
            yield from items
            if len(items) < 100:
                return
        self.ctx.warn("lowcode.workato: pagination limit reached")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for r in records:
            if not self._valid_recipe(r):
                # Error bodies ({"message": ...}) must not pass as an empty inventory.
                self.ctx.warn("lowcode.workato: unsupported or malformed recipe record; coverage incomplete")
                continue
            self.ctx.examined()
            f = self._guarded_finding(r, self._recipe_finding, "recipe")
            if f:
                yield f

    def _valid_recipe(self, r: Any) -> bool:
        return (
            self._record_fields_valid(r, strings=("name", "author_name", "created_at", "updated_at", "last_run_at"), arrays=("config",))
            and self._identified(r, "id", "name")
            and (r.get("code") is None or isinstance(r["code"], (str, dict, list)))
        )

    def _recipe_finding(self, r: dict[str, Any]) -> Finding | None:
        code = r.get("code") or ""
        config = r.get("config") or []
        providers = sorted({str(c.get("provider") or c.get("keyword") or "") for c in config if isinstance(c, dict)})
        ai_steps = [p for p in providers if re.search(r"(?i)openai|genai|anthropic|claude|gemini|vertex|bedrock|cohere|mistral|azure_openai|workato_agent|agentic|copilot|llm", p)]
        blob = (code if isinstance(code, str) else json.dumps(code)) + " " + json.dumps(config, default=str)
        parsed: Any = {}
        if isinstance(code, str) and code.startswith("{"):
            try:
                parsed = json.loads(code)
            except (ValueError, RecursionError):
                # A corrupt recipe body loses only its trigger attribution.
                self.ctx.warn("lowcode.workato: recipe code is not valid JSON; trigger coverage incomplete")
        triggers = [str(get_path(parsed, "keyword", "provider") or "")] if code else []
        return self._workflow_finding(
            wid=str(r.get("id") or r.get("name")),
            name=str(r.get("name")),
            blob=blob[:300_000],
            owner=str(r.get("author_name") or r.get("user_id") or "") or None,
            account=str(r.get("folder_id") or "") or None,
            active=r.get("running"),
            created=r.get("created_at"),
            updated=r.get("updated_at") or r.get("last_run_at"),
            triggers=triggers + (["schedule"] if "scheduler" in blob.lower() else []),
            ai_steps=ai_steps,
            kind=Kind.AGENT if any("agent" in p.lower() for p in providers) else Kind.WORKFLOW,
            resource_type="recipe",
            extra={"providers": providers[:30], "job_succeeded_count": r.get("job_succeeded_count"), "folder": r.get("folder_id")},
        )


def _truthy(v: Any) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"true", "1", "on", "enabled", "active", "yes", "running"}


def load_offline_dir_or_file(conn: BaseConnector, path: str) -> Iterator[dict[str, Any]]:
    yield from BaseConnector.load_offline(conn, path)
