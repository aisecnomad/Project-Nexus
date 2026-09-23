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

import json
import re
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import apply_matches, blob_matches, finalize, model_matches, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path, truncate


class _AutomationBase(BaseConnector):
    surface: ClassVar[Surface] = Surface.LOWCODE
    platform_signature: ClassVar[str] = ""

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
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"limit": 250}
            if cursor:
                params["cursor"] = cursor
            data = http.get_json("/workflows", params=params) or {}
            for w in data.get("data", []):
                yield w
            cursor = data.get("nextCursor")
            if not cursor:
                break

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for w in records:
            if "nodes" not in w:
                continue
            self.ctx.examined()
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
                yield f


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
            data = http.get_json("/teams", params={"organizationId": self.ctx.get("organization_id"), "pg[limit]": 100}) or {}
            teams = [str(t["id"]) for t in data.get("teams", [])]
        else:
            raise ConnectorError("lowcode.make: team_id or organization_id required")
        for team in teams:
            blueprint_errors: dict[int, int] = {}
            offset = 0
            while True:
                data = http.get_json("/scenarios", params={"teamId": team, "pg[limit]": 100, "pg[offset]": offset}) or {}
                scenarios = data.get("scenarios", [])
                for s in scenarios:
                    try:
                        bp = http.get_json(f"/scenarios/{s['id']}/blueprint")
                        s["blueprint"] = (bp or {}).get("response", {}).get("blueprint") or bp
                    except HttpError as exc:
                        blueprint_errors[exc.status] = blueprint_errors.get(exc.status, 0) + 1
                    s["_kind"] = "scenario"
                    s["_team"] = team
                    yield s
                if len(scenarios) < 100:
                    break
                offset += 100
            if blueprint_errors:
                details = ", ".join(f"HTTP {status}: {count}" for status, count in sorted(blueprint_errors.items()))
                self.ctx.warn(f"lowcode.make: blueprints unreadable for {sum(blueprint_errors.values())} scenario(s) in team {team} ({details}); workflow inventory incomplete")
            try:
                for a in (http.get_json("/ai-agents", params={"teamId": team}) or {}).get("aiAgents", []) or []:
                    a["_kind"] = "ai-agent"
                    a["_team"] = team
                    yield a
            except HttpError as exc:
                self.ctx.warn(f"lowcode.make: AI agents unreadable for team {team} (HTTP {exc.status}); agent inventory incomplete")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            kind = rec.get("_kind") or ("ai-agent" if "agentId" in rec or ("model" in rec and "systemPrompt" in rec) else "scenario")
            self.ctx.examined()
            if kind == "ai-agent":
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
                    ai_steps=[f"Make AI Agent (model {rec.get('model') or rec.get('llmModel') or '?'})"],
                    kind=Kind.AGENT,
                    resource_type="ai-agent",
                    extra={"model": rec.get("model") or rec.get("llmModel"), "tools": [t.get("name") for t in rec.get("tools") or [] if isinstance(t, dict)][:20], "system_prompt": truncate(str(rec.get("systemPrompt") or ""), 200)},
                )
                if f:
                    apply_matches(f, model_matches(self.index, rec.get("model") or rec.get("llmModel")), weight_scale=0.5)
                    yield f
                continue
            bp = rec.get("blueprint") or rec
            flow = bp.get("flow") if isinstance(bp, dict) else None
            modules = [str(m.get("module", "")) for m in (flow or []) if isinstance(m, dict)]
            ai_steps = [m for m in modules if re.search(r"openai|anthropic|claude|gemini|mistral|ai-agents|perplexity|hugging|eden-ai|cohere|groq|deepseek|assistants", m, re.I)]
            triggers = [m for m in modules[:1]] + [m for m in modules if re.search(r"webhook|watch|schedule|trigger", m, re.I)]
            f = self._workflow_finding(
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
            if f:
                yield f


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
        while url:
            data = http.get_json(url, params={"limit": 100}) or {}
            for z in data.get("data", []):
                yield z
            url = get_path(data, "links.next")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            self.ctx.examined()
            title = rec.get("title") or rec.get("name") or rec.get("Title") or rec.get("Zap") or str(rec.get("id"))
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
                name=str(title),
                blob=blob,
                owner=str(owner) if owner else None,
                account=str(rec.get("account") or rec.get("Account") or rec.get("team") or "") or None,
                active=_truthy(rec.get("is_enabled", rec.get("status", rec.get("Status")))),
                created=rec.get("created_at") or rec.get("Created"),
                updated=rec.get("updated_at") or rec.get("Modified") or rec.get("last_run"),
                triggers=steps_list[:1],
                ai_steps=ai_steps,
                kind=kind,
                resource_type="zap" if kind == Kind.WORKFLOW else "agent",
                extra={"steps": steps_list[:20], "status": rec.get("status") or rec.get("Status")},
                url=rec.get("url") or rec.get("editor_url"),
            )
            if f:
                apply_matches(f, name_matches(self.index, " ".join(ai_steps)), weight_scale=0.5)
                yield f


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
        page = 1
        while True:
            data = http.get_json("/recipes", params={"per_page": 100, "page": page}) or {}
            items = data.get("items", data if isinstance(data, list) else [])
            for r in items:
                yield r
            if len(items) < 100:
                break
            page += 1

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for r in records:
            self.ctx.examined()
            code = r.get("code") or ""
            config = r.get("config") or []
            providers = sorted({str(c.get("provider") or c.get("keyword") or "") for c in config if isinstance(c, dict)})
            ai_steps = [p for p in providers if re.search(r"(?i)openai|genai|anthropic|claude|gemini|vertex|bedrock|cohere|mistral|azure_openai|workato_agent|agentic|copilot|llm", p)]
            blob = (code if isinstance(code, str) else json.dumps(code)) + " " + json.dumps(config, default=str)
            triggers = [str(get_path(json.loads(code) if isinstance(code, str) and code.startswith("{") else {}, "keyword", "provider") or "")] if code else []
            f = self._workflow_finding(
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
            if f:
                yield f


def _truthy(v: Any) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"true", "1", "on", "enabled", "active", "yes", "running"}


def load_offline_dir_or_file(conn: BaseConnector, path: str) -> Iterator[dict[str, Any]]:
    yield from BaseConnector.load_offline(conn, path)
