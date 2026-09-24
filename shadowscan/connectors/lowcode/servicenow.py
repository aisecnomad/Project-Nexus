"""ServiceNow: Now Assist AI Agents, use cases, tools, AI-related flows and OAuth application registries.

Live (Table API, basic auth or bearer):

* ``sn_aia_agent``   – AI agents (AI Agent Studio)
* ``sn_aia_usecase`` – use cases grouping agents
* ``sn_aia_tool``    – tools (script / flow / subflow / REST / record operation)
* ``sn_aia_trigger`` – triggers (event / record based execution)
* ``sys_hub_flow``   – Flow Designer flows whose name/description mention AI
* ``oauth_entity``   – OAuth application registries (third-party AI apps, client credentials)

Offline export: records carrying ``_table`` / ``sys_class_name`` or wrapped as
``{"table": "sn_aia_agent", "result": [...]}`` (the Table API response shape).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import apply_matches, finalize, name_matches
from shadowscan.connectors.identity.common import assess_app
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import truncate

TABLES = {
    "sn_aia_agent": "sys_id,name,description,instructions,active,sys_created_by,sys_created_on,sys_updated_on,sys_updated_by,role,agent_type,model,llm_model,autonomous",
    "sn_aia_usecase": "sys_id,name,description,active,sys_created_by,sys_updated_on,agents,trigger_type",
    "sn_aia_tool": "sys_id,name,description,type,agent,tool_type,script,flow,subflow,rest_message,table,active,sys_updated_on",
    "sn_aia_trigger": "sys_id,name,usecase,trigger_type,table,condition,active,sys_updated_on",
    "sys_hub_flow": "sys_id,name,description,active,type,sys_created_by,sys_updated_on,sys_scope",
    "oauth_entity": "sys_id,name,client_id,type,active,oauth_entity_scope,redirect_url,sys_created_by,sys_created_on,sys_updated_on,refresh_token_lifespan,access_token_lifespan",
}


def _val(v: Any) -> Any:
    """Table API returns reference fields as {"value": ..., "display_value": ...}."""
    if isinstance(v, dict) and "value" in v:
        return v.get("display_value") or v.get("value")
    return v


_PAGE_SIZE = 500
_MAX_TABLE_PAGES = 1000  # 500,000 rows per table before coverage is reported incomplete


class ServiceNowConnector(BaseConnector):
    name: ClassVar[str] = "lowcode.servicenow"
    surface: ClassVar[Surface] = Surface.LOWCODE
    provider: ClassVar[str | None] = "servicenow"
    description: ClassVar[str] = "Now Assist AI agents, tools, triggers, AI flows and OAuth application registries."
    config_keys: ClassVar[dict[str, str]] = {
        "instance": "https://<instance>.service-now.com (env SNOW_INSTANCE)",
        "username": "basic auth user (env SNOW_USERNAME)",
        "password": "env SNOW_PASSWORD",
        "token": "OAuth bearer token instead of basic auth (env SNOW_TOKEN)",
        "input": "offline: JSON export of table records",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.instance = str(ctx.get("instance", env="SNOW_INSTANCE") or "").rstrip("/")
        if self.instance and not self.instance.startswith("http"):
            self.instance = f"https://{self.instance}"
        self.http: HttpClient | None = None

    def _auth(self) -> None:
        if not self.instance:
            raise ConnectorError("lowcode.servicenow: instance is required")
        token = self.ctx.get("token", env="SNOW_TOKEN")
        if token:
            self.http = HttpClient(self.instance, headers={"Authorization": f"Bearer {token}"})
            return
        user = self.ctx.get("username", env="SNOW_USERNAME")
        pw = self.ctx.get("password", env="SNOW_PASSWORD")
        if not (user and pw):
            raise ConnectorError("lowcode.servicenow: token or username/password required")
        self.http = HttpClient(self.instance, auth=(user, pw))

    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        assert self.http
        for table, fields in TABLES.items():
            offset = 0
            seen_pages: set[str] = set()
            for _ in range(_MAX_TABLE_PAGES):
                try:
                    data = self.http.get_json(f"/api/now/table/{table}", params={"sysparm_fields": fields, "sysparm_limit": _PAGE_SIZE, "sysparm_offset": offset, "sysparm_display_value": "all"})
                except HttpError as exc:
                    if exc.status in (400, 403, 404):
                        self.ctx.warn(f"lowcode.servicenow: table {table} not readable ({exc.status})")
                        break
                    raise
                rows = (data or {}).get("result", []) or []
                if not isinstance(rows, list):
                    self.ctx.warn(f"lowcode.servicenow: table {table} returned an invalid page; coverage incomplete")
                    break
                # An instance or proxy that ignores sysparm_offset returns the
                # same full page forever; detect it instead of looping.
                digest = hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()
                if rows and digest in seen_pages:
                    self.ctx.warn(f"lowcode.servicenow: table {table} repeated a page; coverage incomplete")
                    break
                seen_pages.add(digest)
                for r in rows:
                    if isinstance(r, dict):
                        r["_table"] = table
                        yield r
                if len(rows) < _PAGE_SIZE:
                    break
                offset += _PAGE_SIZE
            else:
                self.ctx.warn(f"lowcode.servicenow: table {table} page limit reached; coverage incomplete")

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        for rec in super().load_offline(path):
            if "result" in rec and isinstance(rec["result"], list):
                table = rec.get("table") or rec.get("_table")
                for r in rec["result"]:
                    if table and "_table" not in r:
                        r["_table"] = table
                    yield r
            else:
                yield rec

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        agents: list[dict[str, Any]] = []
        tools: dict[str, list[dict[str, Any]]] = {}
        usecases: list[dict[str, Any]] = []
        triggers: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            table = rec.get("_table") or _val(rec.get("sys_class_name")) or ""
            if table == "sn_aia_agent":
                agents.append(rec)
            elif table == "sn_aia_tool":
                tools.setdefault(str(_val(rec.get("agent")) or ""), []).append(rec)
            elif table == "sn_aia_usecase":
                usecases.append(rec)
            elif table == "sn_aia_trigger":
                triggers.setdefault(str(_val(rec.get("usecase")) or ""), []).append(rec)
            elif table == "sys_hub_flow":
                self.ctx.examined()
                f = self._flow_finding(rec)
                if f:
                    yield f
            elif table == "oauth_entity":
                self.ctx.examined()
                f = self._oauth_finding(rec)
                if f:
                    yield f
        for a in agents:
            self.ctx.examined()
            key_candidates = {str(_val(a.get("sys_id"))), str(_val(a.get("name")))}
            my_tools = [t for k, ts in tools.items() for t in ts if k in key_candidates]
            yield self._agent_finding(a, my_tools)
        for u in usecases:
            self.ctx.examined()
            key_candidates = {str(_val(u.get("sys_id"))), str(_val(u.get("name")))}
            my_triggers = [t for k, ts in triggers.items() for t in ts if k in key_candidates]
            yield self._usecase_finding(u, my_triggers)

    def _agent_finding(self, a: dict[str, Any], tools: list[dict[str, Any]]) -> Finding:
        name = _val(a.get("name")) or _val(a.get("sys_id"))
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.AGENT,
            title=f"ServiceNow AI agent: {name}",
            resource=f"servicenow:sn_aia_agent:{_val(a.get('sys_id')) or name}",
            resource_type="now-assist-agent",
            provider="servicenow",
            account=self.instance or None,
            owner=_val(a.get("sys_created_by")) or _val(a.get("sys_updated_by")),
            first_seen=_val(a.get("sys_created_on")),
            last_seen=_val(a.get("sys_updated_on")),
        )
        f.add_framework("platform.servicenow-now-assist")
        f.add_capability("tool-use")
        f.add_capability("saas-actions")
        f.add_evidence(Evidence(signal="servicenow:sn_aia_agent", description=f"AI Agent '{name}' (active={_val(a.get('active'))}, type={_val(a.get('agent_type'))}, model={_val(a.get('model')) or _val(a.get('llm_model')) or 'default'}) with {len(tools)} tool(s)", weight=0.95, signature="platform.servicenow-now-assist"))
        tool_types = sorted({str(_val(t.get("type")) or _val(t.get("tool_type")) or "?") for t in tools})
        if any("script" in t.lower() for t in tool_types):
            f.add_capability("code-exec")
            f.add_evidence(Evidence(signal="servicenow:script-tool", description="Agent has script tools (server-side JavaScript execution)", weight=0.4))
        if str(_val(a.get("autonomous"))).lower() in {"true", "1", "yes"} or "autonomous" in str(_val(a.get("agent_type")) or "").lower():
            f.add_capability("autonomous")
        apply_matches(f, name_matches(self.index, name, _val(a.get("description"))), weight_scale=0.4)
        f.metadata.update({"active": _val(a.get("active")), "description": truncate(_val(a.get("description"))), "instructions": truncate(_val(a.get("instructions")), 300), "role": _val(a.get("role")), "model": _val(a.get("model")) or _val(a.get("llm_model")), "tools": [{"name": _val(t.get("name")), "type": _val(t.get("type")) or _val(t.get("tool_type"))} for t in tools][:30], "tool_types": tool_types})
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f

    def _usecase_finding(self, u: dict[str, Any], triggers: list[dict[str, Any]]) -> Finding:
        name = _val(u.get("name")) or _val(u.get("sys_id"))
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.WORKFLOW,
            title=f"ServiceNow AI agent use case: {name}",
            resource=f"servicenow:sn_aia_usecase:{_val(u.get('sys_id')) or name}",
            resource_type="now-assist-usecase",
            provider="servicenow",
            account=self.instance or None,
            owner=_val(u.get("sys_created_by")),
            last_seen=_val(u.get("sys_updated_on")),
        )
        f.add_framework("platform.servicenow-now-assist")
        f.add_evidence(Evidence(signal="servicenow:sn_aia_usecase", description=f"Use case '{name}' (active={_val(u.get('active'))}) with {len(triggers)} trigger(s): {', '.join(str(_val(t.get('trigger_type')) or _val(t.get('table')) or '?') for t in triggers[:5])}", weight=0.8, signature="platform.servicenow-now-assist"))
        if triggers or str(_val(u.get("trigger_type") or "")).lower() not in {"", "manual", "none"}:
            f.add_capability("autonomous")
            f.add_tag("event-triggered")
        f.metadata.update({"active": _val(u.get("active")), "description": truncate(_val(u.get("description"))), "agents": _val(u.get("agents")), "triggers": [{"type": _val(t.get("trigger_type")), "table": _val(t.get("table")), "condition": truncate(_val(t.get("condition")), 120)} for t in triggers][:20]})
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _flow_finding(self, rec: dict[str, Any]) -> Finding | None:
        name = _val(rec.get("name")) or ""
        text = f"{name} {_val(rec.get('description')) or ''} {_val(rec.get('sys_scope')) or ''}"
        matches = name_matches(self.index, text)
        low = text.lower()
        if not matches and not any(k in low for k in ("now assist", "generative", "gen ai", "genai", "gpt", "llm", "sn_generative_ai", "sn_aia", "ai agent")):
            return None
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.WORKFLOW,
            title=f"ServiceNow flow with AI hints: {name}",
            resource=f"servicenow:sys_hub_flow:{_val(rec.get('sys_id')) or name}",
            resource_type="flow",
            provider="servicenow",
            account=self.instance or None,
            owner=_val(rec.get("sys_created_by")),
            last_seen=_val(rec.get("sys_updated_on")),
        )
        f.add_framework("platform.servicenow-now-assist")
        f.add_evidence(Evidence(signal="servicenow:flow", description=f"Flow '{name}' ({_val(rec.get('type'))}, active={_val(rec.get('active'))}) references AI: {truncate(text, 160)}", weight=0.4))
        apply_matches(f, matches, weight_scale=0.5)
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _oauth_finding(self, rec: dict[str, Any]) -> Finding | None:
        name = _val(rec.get("name")) or _val(rec.get("client_id"))
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.OAUTH_GRANT,
            title=f"ServiceNow OAuth application: {name}",
            resource=f"servicenow:oauth_entity:{_val(rec.get('sys_id')) or name}",
            resource_type="oauth-application-registry",
            provider="servicenow",
            account=self.instance or None,
            owner=_val(rec.get("sys_created_by")),
            first_seen=_val(rec.get("sys_created_on")),
            last_seen=_val(rec.get("sys_updated_on")),
        )
        scopes = [s.strip() for s in str(_val(rec.get("oauth_entity_scope")) or "").split(",") if s.strip()]
        assess_app(self.index, f, name=name, urls=[_val(rec.get("redirect_url"))], scopes=scopes, client_id=_val(rec.get("client_id")))
        if not f.frameworks:
            return None
        f.add_evidence(Evidence(signal="servicenow:oauth_entity", description=f"OAuth {_val(rec.get('type')) or 'client'} '{name}' (active={_val(rec.get('active'))}), refresh token lifespan {_val(rec.get('refresh_token_lifespan'))}s", weight=0.3))
        f.metadata.update({"type": _val(rec.get("type")), "active": _val(rec.get("active")), "client_id": _val(rec.get("client_id")), "scopes": scopes})
        finalize(f, self.index)
        f.kind = Kind.OAUTH_GRANT
        return f
