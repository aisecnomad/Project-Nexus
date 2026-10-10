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

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import (
    apply_matches,
    failure_summary,
    finalize,
    max_pages_limit,
    name_matches,
)
from shadowscan.connectors.identity.common import assess_app
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import truncate

TABLES = {
    "sn_aia_agent": (
        "sys_id,name,description,instructions,active,sys_created_by,sys_created_on,sys_updated_on,"
        "sys_updated_by,role,agent_type,model,llm_model,autonomous"
    ),
    "sn_aia_usecase": "sys_id,name,description,active,sys_created_by,sys_updated_on,agents,trigger_type",
    "sn_aia_tool": (
        "sys_id,name,description,type,agent,tool_type,script,flow,subflow,rest_message,table,active,"
        "sys_updated_on"
    ),
    "sn_aia_trigger": "sys_id,name,usecase,trigger_type,table,condition,active,sys_updated_on",
    "sys_hub_flow": "sys_id,name,description,active,type,sys_created_by,sys_updated_on,sys_scope",
    "oauth_entity": (
        "sys_id,name,client_id,type,active,oauth_entity_scope,redirect_url,sys_created_by,sys_created_on,"
        "sys_updated_on,refresh_token_lifespan,access_token_lifespan"
    ),
}


def _val(v: Any) -> Any:
    """Table API returns reference fields as {"value": ..., "display_value": ...}."""
    if isinstance(v, dict) and "value" in v:
        return v.get("display_value") or v.get("value")
    return v


def _reference(v: Any) -> Any:
    """Join reference fields by stable sys_id, retaining display-only exports."""
    if isinstance(v, dict):
        return v.get("value") or v.get("display_value")
    return v


_PAGE_SIZE = 500
_MAX_TABLE_PAGES = 1000  # 500,000 rows per table before coverage is reported incomplete


def _total_count(headers: Any) -> int | None:
    """The Table API ``X-Total-Count`` header as a row count, or None when absent or malformed."""
    value = headers.get("X-Total-Count") if hasattr(headers, "get") else None
    # Bounded decimal digits only: a count never needs more than 12 of them.
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 12:
        return int(value)
    return None


class ServiceNowConnector(BaseConnector):
    name: ClassVar[str] = "lowcode.servicenow"
    surface: ClassVar[Surface] = Surface.LOWCODE
    provider: ClassVar[str | None] = "servicenow"
    description: ClassVar[str] = (
        "Now Assist AI agents, tools, triggers, AI flows and OAuth application registries."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "instance": "https://<instance>.service-now.com (env SNOW_INSTANCE)",
        "username": "basic auth user (env SNOW_USERNAME)",
        "password": "env SNOW_PASSWORD",
        "token": "OAuth bearer token instead of basic auth (env SNOW_TOKEN)",
        "max_pages": "maximum pages per table, capped at 1000 (default 1000)",
        "input": "offline: JSON export of table records",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.instance = str(ctx.get("instance", env="SNOW_INSTANCE") or "").rstrip("/")
        if self.instance and not self.instance.startswith("http"):
            self.instance = f"https://{self.instance}"
        self.http: HttpClient | None = None
        self._name_matching_limited = False
        self._oauth_matching_limited = False

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
        max_pages = max_pages_limit(self.ctx.get("max_pages", 1000))
        for table, fields in TABLES.items():
            seen: set[str] = set()
            for page in range(max_pages):
                try:
                    data, total = self._table_page(table, fields, page)
                except (HttpError, RequestException, ValueError, RuntimeError) as exc:
                    status = failure_summary(exc)
                    self.ctx.warn(f"lowcode.servicenow: table {table} collection incomplete ({status})")
                    break
                if not isinstance(data, dict) or not isinstance(data.get("result"), list):
                    self.ctx.warn(f"lowcode.servicenow: invalid result page for {table}")
                    break
                if self._is_error_record(data):
                    self.ctx.warn(f"lowcode.servicenow: provider error in {table} page; coverage incomplete")
                rows = data["result"]
                if rows:
                    # An empty page can legitimately repeat: ACLs hid every row of its window.
                    fingerprint = hashlib.sha256(
                        json.dumps(rows, sort_keys=True, default=str).encode()
                    ).hexdigest()
                    if fingerprint in seen:
                        self.ctx.warn(f"lowcode.servicenow: repeated pagination page for {table}")
                        break
                    seen.add(fingerprint)
                for r in rows:
                    if not isinstance(r, dict):
                        self.ctx.warn(f"lowcode.servicenow: invalid record in {table} page")
                        continue
                    yield {**r, "_table": table}
                # ACLs filter rows after sysparm_limit is applied, so a short or
                # even empty page is not the last one. X-Total-Count counts the
                # rows the query matches before that filter, so the table ends
                # once the windows cover it.
                if total is not None:
                    if (page + 1) * _PAGE_SIZE >= total:
                        break
                elif not rows:
                    self.ctx.warn(
                        f"lowcode.servicenow: table {table} sent no valid X-Total-Count; ACLs can empty a "
                        "page before the end of a table, so its end is unproven and coverage is incomplete"
                    )
                    break
            else:
                self.ctx.warn(f"lowcode.servicenow: pagination limit reached for {table}")

    def _table_page(self, table: str, fields: str, page: int) -> tuple[Any, int | None]:
        """One Table API window and its X-Total-Count, or None when that header is absent or malformed."""
        assert self.http
        totals: list[int | None] = []
        data = self.http.get_json(
            f"/api/now/table/{table}",
            params={
                "sysparm_fields": fields,
                "sysparm_limit": _PAGE_SIZE,
                "sysparm_offset": page * _PAGE_SIZE,
                "sysparm_display_value": "all",
            },
            on_response=lambda response: totals.append(_total_count(response.headers)),
        )
        return data, (totals[0] if totals else None)

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        for rec in super().load_offline(path):
            if "result" in rec:
                if not isinstance(rec["result"], list):
                    self.ctx.warn("lowcode.servicenow: invalid result collection in export")
                    continue
                table = rec.get("table") or rec.get("_table")
                for r in rec["result"]:
                    if not isinstance(r, dict):
                        self.ctx.warn("lowcode.servicenow: malformed table export record")
                        continue
                    if table and "_table" not in r:
                        r = {**r, "_table": table}
                    yield r
            else:
                yield rec

    def _valid_provider_record(self, rec: Any, table: Any) -> bool:
        if (
            not isinstance(rec, dict)
            or self._is_error_record(rec)
            or not isinstance(table, str)
            or table not in TABLES
        ):
            return False
        for key in TABLES[table].split(","):
            value = rec.get(key)
            if isinstance(value, dict):
                if "value" not in value or any(
                    value.get(k) is not None and not isinstance(value[k], (str, int, float, bool))
                    for k in ("value", "display_value")
                ):
                    return False
            elif value is not None and not isinstance(value, (str, int, float, bool)):
                return False
            if (
                key
                in {
                    "name",
                    "description",
                    "instructions",
                    "condition",
                    "redirect_url",
                    "client_id",
                    "sys_created_by",
                    "sys_updated_by",
                    "sys_created_on",
                    "sys_updated_on",
                }
                and _val(value) is not None
                and not isinstance(_val(value), str)
            ):
                return False
        identifier = _reference(rec.get("sys_id")) or _val(rec.get("name"))
        if not isinstance(identifier, str) or not identifier.strip():
            return False
        parent = {"sn_aia_tool": "agent", "sn_aia_trigger": "usecase"}.get(table)
        return not parent or bool(
            isinstance(_reference(rec.get(parent)), str) and _reference(rec.get(parent)).strip()
        )

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        self._name_matching_limited = False
        self._oauth_matching_limited = False
        agents: list[dict[str, Any]] = []
        tools: dict[str, list[dict[str, Any]]] = {}
        usecases: list[dict[str, Any]] = []
        triggers: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            table = (
                (rec.get("_table") or _val(rec.get("sys_class_name")) or "") if isinstance(rec, dict) else ""
            )
            if not self._valid_provider_record(rec, table):
                self.ctx.warn(
                    "lowcode.servicenow: unsupported or malformed table record; coverage incomplete"
                )
                continue
            if table == "sn_aia_agent":
                agents.append(rec)
            elif table == "sn_aia_tool":
                tools.setdefault(str(_reference(rec.get("agent"))), []).append(rec)
            elif table == "sn_aia_usecase":
                usecases.append(rec)
            elif table == "sn_aia_trigger":
                triggers.setdefault(str(_reference(rec.get("usecase"))), []).append(rec)
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
        matched_tools: set[str] = set()
        matched_triggers: set[str] = set()
        for a in agents:
            self.ctx.examined()
            key_candidates = {
                value
                for value in (_reference(a.get("sys_id")), _val(a.get("name")))
                if isinstance(value, str) and value.strip()
            }
            matched_tools.update(key_candidates)
            my_tools = [t for k, ts in tools.items() for t in ts if k in key_candidates]
            yield self._agent_finding(a, my_tools)
        for u in usecases:
            self.ctx.examined()
            key_candidates = {
                value
                for value in (_reference(u.get("sys_id")), _val(u.get("name")))
                if isinstance(value, str) and value.strip()
            }
            matched_triggers.update(key_candidates)
            my_triggers = [t for k, ts in triggers.items() for t in ts if k in key_candidates]
            yield self._usecase_finding(u, my_triggers)
        for parent_table, children, matched in (
            ("sn_aia_agent", tools, matched_tools),
            ("sn_aia_usecase", triggers, matched_triggers),
        ):
            for parent in sorted(children.keys() - matched):
                self.ctx.examined(len(children[parent]))
                self.ctx.warn(
                    "lowcode.servicenow: child records reference an unresolved parent; coverage incomplete"
                )
                yield self._unresolved_child_finding(parent_table, parent, children[parent])

    def _unresolved_child_finding(
        self, parent_table: str, parent: str, children: list[dict[str, Any]]
    ) -> Finding:
        """Keep observed tool/trigger configuration without inventing a parent agent."""
        tools = parent_table == "sn_aia_agent"
        child_type = "tool" if tools else "trigger"
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.AGENT_CONFIG,
            title=f"ServiceNow {child_type} configuration for unresolved parent",
            resource=f"servicenow:unresolved:{parent_table}:{parent}",
            resource_type="unresolved-parent-configuration",
            provider="servicenow",
            account=self.instance or None,
            identity_discriminator="unresolved-parent",
            metadata={
                "identity_unresolved": True,
                "parent_table": parent_table,
                "parent_reference": parent,
                "child_count": len(children),
                "children": [
                    {
                        "id": _reference(child.get("sys_id")),
                        "name": _val(child.get("name")),
                        "type": _val(child.get("type")) or _val(child.get("tool_type"))
                        if tools
                        else _val(child.get("trigger_type")),
                    }
                    for child in children[:30]
                ],
            },
        )
        f.add_tag("unresolved-identity")
        f.add_framework("platform.servicenow-now-assist")
        if tools:
            f.add_capability("tool-use")
            if any(
                "script" in str(_val(child.get("type")) or _val(child.get("tool_type")) or "").lower()
                for child in children
            ):
                f.add_capability("code-exec")
        else:
            # Autonomy: initiation evidence (the event-triggered tag), not approval-bypass evidence.
            f.add_capability("autonomous")
            f.add_tag("event-triggered")
        f.add_evidence(
            Evidence(
                signal=f"servicenow:unresolved-{child_type}",
                description=(
                    f"Observed {len(children)} {child_type} record(s) referencing {parent_table} {parent}; "
                    "the parent is missing from the inventory and its identity and execution are unknown"
                ),
                weight=0.5,
            )
        )
        return finalize(f, self.index)

    def _optional_name_matches(self, *texts: str | None) -> list[Match]:
        if self._name_matching_limited:
            return []
        try:
            return name_matches(self.index, *texts)
        except MatchTimeoutError:
            # A name hint is optional for native agents and recognisable flows.
            # Keep observed records, disclose lost enrichment, and avoid retrying
            # the same expensive matching on every remaining record.
            self._name_matching_limited = True
            self.ctx.warn("lowcode.servicenow: display-name matching timed out; coverage incomplete")
            return []

    def _agent_finding(self, a: dict[str, Any], tools: list[dict[str, Any]]) -> Finding:
        name = _val(a.get("name")) or _val(a.get("sys_id"))
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.AGENT,
            title=f"ServiceNow AI agent: {name}",
            resource=f"servicenow:sn_aia_agent:{_reference(a.get('sys_id')) or name}",
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
        f.add_evidence(
            Evidence(
                signal="servicenow:sn_aia_agent",
                description=(
                    f"AI Agent '{name}' (active={_val(a.get('active'))}, type={_val(a.get('agent_type'))}, "
                    f"model={_val(a.get('model')) or _val(a.get('llm_model')) or 'default'}) with "
                    f"{len(tools)} tool(s)"
                ),
                weight=0.95,
                signature="platform.servicenow-now-assist",
            )
        )
        tool_types = sorted({str(_val(t.get("type")) or _val(t.get("tool_type")) or "?") for t in tools})
        if any("script" in t.lower() for t in tool_types):
            f.add_capability("code-exec")
            f.add_evidence(
                Evidence(
                    signal="servicenow:script-tool",
                    description="Agent has script tools (server-side JavaScript execution)",
                    weight=0.4,
                )
            )
        if (
            str(_val(a.get("autonomous"))).lower() in {"true", "1", "yes"}
            or "autonomous" in str(_val(a.get("agent_type")) or "").lower()
        ):
            # Autonomy: approval-bypass evidence (the agent is configured to act without a person).
            f.add_capability("autonomous")
        apply_matches(f, self._optional_name_matches(name, _val(a.get("description"))), weight_scale=0.4)
        f.metadata.update(
            {
                "active": _val(a.get("active")),
                "description": truncate(_val(a.get("description"))),
                "instructions": truncate(_val(a.get("instructions")), 300),
                "role": _val(a.get("role")),
                "model": _val(a.get("model")) or _val(a.get("llm_model")),
                "tools": [
                    {"name": _val(t.get("name")), "type": _val(t.get("type")) or _val(t.get("tool_type"))}
                    for t in tools
                ][:30],
                "tool_types": tool_types,
            }
        )
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
            resource=f"servicenow:sn_aia_usecase:{_reference(u.get('sys_id')) or name}",
            resource_type="now-assist-usecase",
            provider="servicenow",
            account=self.instance or None,
            owner=_val(u.get("sys_created_by")),
            last_seen=_val(u.get("sys_updated_on")),
        )
        f.add_framework("platform.servicenow-now-assist")
        trigger_labels = ", ".join(
            str(_val(t.get("trigger_type")) or _val(t.get("table")) or "?") for t in triggers[:5]
        )
        f.add_evidence(
            Evidence(
                signal="servicenow:sn_aia_usecase",
                description=(
                    f"Use case '{name}' (active={_val(u.get('active'))}) with {len(triggers)} trigger(s): "
                    f"{trigger_labels}"
                ),
                weight=0.8,
                signature="platform.servicenow-now-assist",
            )
        )
        if triggers or str(_val(u.get("trigger_type") or "")).lower() not in {"", "manual", "none"}:
            # Autonomy: initiation evidence (the event-triggered tag), not approval-bypass evidence.
            f.add_capability("autonomous")
            f.add_tag("event-triggered")
        f.metadata.update(
            {
                "active": _val(u.get("active")),
                "description": truncate(_val(u.get("description"))),
                "agents": _val(u.get("agents")),
                "triggers": [
                    {
                        "type": _val(t.get("trigger_type")),
                        "table": _val(t.get("table")),
                        "condition": truncate(_val(t.get("condition")), 120),
                    }
                    for t in triggers
                ][:20],
            }
        )
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _flow_finding(self, rec: dict[str, Any]) -> Finding | None:
        name = _val(rec.get("name")) or ""
        text = f"{name} {_val(rec.get('description')) or ''} {_val(rec.get('sys_scope')) or ''}"
        matches = self._optional_name_matches(text)
        low = text.lower()
        if not matches and not any(
            k in low
            for k in (
                "now assist",
                "generative",
                "gen ai",
                "genai",
                "gpt",
                "llm",
                "sn_generative_ai",
                "sn_aia",
                "ai agent",
            )
        ):
            return None
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=Kind.WORKFLOW,
            title=f"ServiceNow flow with AI hints: {name}",
            resource=f"servicenow:sys_hub_flow:{_reference(rec.get('sys_id')) or name}",
            resource_type="flow",
            provider="servicenow",
            account=self.instance or None,
            owner=_val(rec.get("sys_created_by")),
            last_seen=_val(rec.get("sys_updated_on")),
        )
        f.add_framework("platform.servicenow-now-assist")
        f.add_evidence(
            Evidence(
                signal="servicenow:flow",
                description=(
                    f"Flow '{name}' ({_val(rec.get('type'))}, active={_val(rec.get('active'))}) references "
                    f"AI: {truncate(text, 160)}"
                ),
                weight=0.4,
            )
        )
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
            resource=f"servicenow:oauth_entity:{_reference(rec.get('sys_id')) or name}",
            resource_type="oauth-application-registry",
            provider="servicenow",
            account=self.instance or None,
            owner=_val(rec.get("sys_created_by")),
            first_seen=_val(rec.get("sys_created_on")),
            last_seen=_val(rec.get("sys_updated_on")),
        )
        scopes = [s.strip() for s in str(_val(rec.get("oauth_entity_scope")) or "").split(",") if s.strip()]
        if self._oauth_matching_limited:
            return None
        try:
            assess_app(
                self.index,
                f,
                name=name,
                urls=[_val(rec.get("redirect_url"))],
                scopes=scopes,
                client_id=_val(rec.get("client_id")),
            )
        except MatchTimeoutError:
            # OAuth classification depends on those matches; skip this record
            # and later OAuth enrichment, but continue with native agents.
            self._oauth_matching_limited = True
            self.ctx.warn("lowcode.servicenow: OAuth signature matching timed out; coverage incomplete")
            return None
        if not f.frameworks:
            return None
        f.add_evidence(
            Evidence(
                signal="servicenow:oauth_entity",
                description=(
                    f"OAuth {_val(rec.get('type')) or 'client'} '{name}' (active={_val(rec.get('active'))}), "
                    f"refresh token lifespan {_val(rec.get('refresh_token_lifespan'))}s"
                ),
                weight=0.3,
            )
        )
        f.metadata.update(
            {
                "type": _val(rec.get("type")),
                "active": _val(rec.get("active")),
                "client_id": _val(rec.get("client_id")),
                "scopes": scopes,
            }
        )
        finalize(f, self.index)
        f.kind = Kind.OAUTH_GRANT
        return f
