"""LLM inference gateway / proxy log analysis.

Reads logs exported from an AI gateway or provider and reconstructs *who is
calling which models, how, and how autonomously*. Each distinct caller
(API key / principal / service / user-agent / source IP, depending on what the
schema exposes) becomes a ``gateway-caller`` finding with:

* models and providers used, request volume, first/last seen
* framework fingerprints from user agents (LangChain, LiteLLM, CrewAI, Claude Code...)
* tool/function-calling usage (agentic behaviour) when request bodies / flags are present
* temporal shape: 24x7 / off-hours activity suggests an unattended agent
* cost / token volume when present

Supported schemas (auto-detected per record; can be forced with ``format``):

``litellm`` (SpendLogs / proxy logs), ``portkey``, ``kong`` (ai-proxy), ``cloudflare``
(AI Gateway), ``helicone``, ``langfuse`` (observations/traces export), ``bedrock``
(model invocation logs), ``azure-openai`` (RequestResponse / Audit diagnostic
logs), ``vertex`` (Cloud Audit Logs for aiplatform), ``openai-usage`` (OpenAI
Admin usage / audit logs), ``anthropic-usage``, ``access-log`` (nginx / envoy /
ALB / CloudFront JSON or combined-format lines), ``generic`` (any JSON with
model / user / api key style fields).

Input: JSONL / JSON / CSV / plain text access logs, file or directory.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import apply_matches, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.redaction import credential_id, sanitize
from shadowscan.utils.text import get_path, host_of, parse_timestamp, redact, to_iso

# ---------------------------------------------------------------- schemas


@dataclass(slots=True)
class Event:
    """Normalised LLM call record."""

    caller: str  # identity key (api key hash, principal, service...)
    caller_kind: str  # api-key | principal | service | user | user-agent | ip
    caller_label: str  # human readable
    timestamp: datetime | None = None
    interval_end: datetime | None = None
    request_count: int = 1
    aggregated: bool = False
    model: str | None = None
    provider: str | None = None
    host: str | None = None
    user_agent: str | None = None
    ip: str | None = None
    user: str | None = None  # end-user / on-behalf-of
    team: str | None = None
    tools: bool | None = None  # request carried tool/function definitions
    tool_calls: bool | None = None  # response contained tool calls
    streaming: bool | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float = 0.0
    status: str | None = None
    path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    schema: str = "generic"
    scope: dict[str, str] = field(default_factory=dict)
    environment: str | None = None
    runtime_frameworks: list[str] = field(default_factory=list)
    code_resources: list[str] = field(default_factory=list)


def _b(v: Any) -> bool | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v > 0
    s = str(v).lower()
    if s in {"true", "1", "yes", "y"}:
        return True
    if s in {"false", "0", "no", "n", "[]", "{}", "null", "none"}:
        return False
    return len(s) > 2


def _i(v: Any) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _f(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _has_tools(obj: Any) -> bool | None:
    if obj is None:
        return None
    if isinstance(obj, str):
        if not obj.strip().startswith(("{", "[")):
            return None
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError:
            return None
    if isinstance(obj, dict):
        for wrapper in ("body", "request", "payload", "json"):
            inner = obj.get(wrapper)
            if isinstance(inner, (dict, str)) and not any(k in obj for k in ("tools", "functions", "messages", "input")):
                return _has_tools(inner)
        for key in ("tools", "functions", "tool_choice", "toolConfig", "tool_config", "function_declarations"):
            v = obj.get(key)
            if v not in (None, [], {}, ""):
                return True
        msgs = obj.get("messages") or obj.get("input") or []
        if isinstance(msgs, list):
            for m in msgs:
                if isinstance(m, dict) and (m.get("tool_calls") or m.get("role") in {"tool", "function"} or m.get("type") in {"function_call", "function_call_output", "tool_use", "tool_result"}):
                    return True
        return False
    return None


def _has_tool_calls(obj: Any) -> bool | None:
    if obj is None:
        return None
    if isinstance(obj, str):
        if not obj.strip().startswith(("{", "[")):
            return None
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError:
            return None
    if not isinstance(obj, (dict, list)):
        return None
    # Inspect structured response fields, never serialized keys or free text:
    # optional null/empty fields are normal in non-tool model responses.
    pending = [obj]
    while pending:
        item = pending.pop()
        if isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, dict):
            if isinstance(item.get("tool_calls"), list) and any(isinstance(call, dict) and call for call in item["tool_calls"]):
                return True
            for key in ("function_call", "functionCall", "tool_use"):
                if isinstance(item.get(key), dict) and item[key]:
                    return True
            if item.get("type") in {"tool_use", "function_call"} or item.get("stop_reason") == "tool_use" or item.get("finish_reason") in {"tool_calls", "function_call"}:
                return True
            pending.extend(value for value in item.values() if isinstance(value, (dict, list)))
    return False


def detect_schema(rec: dict[str, Any]) -> str:
    keys = set(rec.keys())
    if "schemaType" in rec and rec.get("schemaType") == "ModelInvocationLog" or ("modelId" in rec and "identity" in rec and "input" in rec):
        return "bedrock"
    if "protoPayload" in rec and "aiplatform" in json.dumps(rec.get("protoPayload", {}))[:500]:
        return "vertex"
    if rec.get("category") in {"RequestResponse", "Audit", "Trace"} and ("properties" in rec or "callerIpAddress" in rec) and ("resourceId" in rec or "ResourceId" in rec):
        return "azure-openai"
    if "spend" in rec and ("api_key" in rec or "call_type" in rec or "request_id" in rec):
        return "litellm"
    if "ai.proxy" in json.dumps(rec)[:2000] or "ai" in rec and isinstance(rec.get("ai"), dict) and "proxy" in rec["ai"]:
        return "kong"
    if "gateway_id" in rec or ("provider" in rec and "request_type" in rec and "tokens_in" in rec) or "ai_gateway" in rec:
        return "cloudflare"
    if "trace_id" in rec and "virtual_key" in rec or "portkey" in json.dumps(rec)[:500].lower() or "x-portkey" in json.dumps(rec)[:2000].lower():
        return "portkey"
    if "helicone" in json.dumps(rec)[:1000].lower() or "request_properties" in rec and "helicone-request-id" in json.dumps(rec)[:5000].lower():
        return "helicone"
    if "observation_id" in rec or ("traceId" in rec and "usageDetails" in rec) or ("type" in rec and rec.get("type") == "GENERATION" and "model" in rec) or ("project_id" in rec and "trace_id" in rec and "model" in rec):
        return "langfuse"
    if "n_context_tokens_total" in rec or ("object" in rec and str(rec.get("object", "")).startswith("organization.usage")) or ("api_key_id" in rec and "input_tokens" in rec) or ("actor" in rec and "effective_at" in rec):
        return "openai-usage"
    if "workspace_id" in rec and "api_key_id" in rec and "uncached_input_tokens" in rec or ("uncached_input_tokens" in rec and "model" in rec):
        return "anthropic-usage"
    if ("request" in rec and isinstance(rec.get("request"), str)) or ("http_user_agent" in keys or "user_agent" in keys or "userAgent" in keys or "http.user_agent" in keys) and ("model" not in keys):
        return "access-log"
    if {"remote_addr", "request_uri"} & keys or {"clientIp", "requestUri"} & keys or "c-ip" in keys or "elb" in keys:
        return "access-log"
    return "generic"


def normalise(rec: dict[str, Any], schema: str) -> Event | None:
    """Normalize without retaining credentials, including in nested metadata."""
    ev = _normalise(rec, schema)
    if ev is None:
        return None
    # Validate scalar fields before attribution or counters are updated. JSON
    # containers in headers/identity fields otherwise fail partway through
    # accumulation and can discard all callers collected before that record.
    if isinstance(ev.status, int) and not isinstance(ev.status, bool):
        ev.status = str(ev.status)
    for name in ("caller", "caller_kind", "caller_label", "model", "provider", "host",
                 "user_agent", "ip", "user", "team", "status", "path"):
        value = getattr(ev, name)
        if value is not None and not isinstance(value, str):
            raise ConnectorError(f"gateway.logs: normalized {name} must be a string")
    if ev.caller_kind == "api-key":
        namespace, _, raw_key = ev.caller.partition(":")
        opaque_id = credential_id(raw_key)
        ev.caller = f"{namespace}:{opaque_id}"
        if not ev.caller_label or ev.caller_label == raw_key or ev.caller_label in raw_key:
            ev.caller_label = opaque_id
        if schema == "litellm" and not get_path(rec, "api_key_alias", "key_alias", "metadata.user_api_key_alias"):
            ev.caller_label = opaque_id
    # Include original credential-bearing fields so duplicated opaque secrets in
    # unrelated metadata are scrubbed before samples are truncated.
    clean = sanitize({"record": rec, "event": asdict(ev)})["event"]
    return Event(**clean)


def _normalise(rec: dict[str, Any], schema: str) -> Event | None:
    if schema == "litellm":
        key = rec.get("api_key") or rec.get("hashed_api_key") or rec.get("key_hash") or ""
        alias = rec.get("api_key_alias") or rec.get("key_alias") or get_path(rec, "metadata.user_api_key_alias") or ""
        team = rec.get("team_id") or get_path(rec, "metadata.user_api_key_team_id", "metadata.user_api_key_team_alias")
        user = rec.get("user") or rec.get("end_user") or get_path(rec, "metadata.user_api_key_user_id", "metadata.user_api_key_user_email")
        ua = get_path(rec, "metadata.user_agent", "metadata.headers.user-agent", "request_tags.user_agent", "metadata.requester_metadata.user_agent")
        tools = _has_tools(rec.get("proxy_server_request") or rec.get("request") or get_path(rec, "metadata.proxy_server_request.body"))
        caller = f"litellm-key:{key or alias or 'anonymous'}"
        return Event(
            caller=caller,
            caller_kind="api-key",
            caller_label=alias or (redact(str(key)) if key else "anonymous"),
            timestamp=parse_timestamp(rec.get("startTime") or rec.get("start_time") or rec.get("endTime") or rec.get("timestamp")),
            model=rec.get("model") or rec.get("model_group"),
            provider=rec.get("custom_llm_provider") or rec.get("provider"),
            host=host_of(rec.get("api_base")),
            user_agent=ua,
            ip=get_path(rec, "metadata.requester_ip_address", "requester_ip_address"),
            user=str(user) if user else None,
            team=str(team) if team else None,
            tools=tools,
            tool_calls=_has_tool_calls(rec.get("response")),
            tokens_in=_i(rec.get("prompt_tokens")),
            tokens_out=_i(rec.get("completion_tokens")),
            cost=_f(rec.get("spend")),
            status=rec.get("status"),
            path=rec.get("call_type"),
            metadata={"request_tags": rec.get("request_tags"), "cache_hit": rec.get("cache_hit")},
            schema=schema,
        )
    if schema == "portkey":
        vk = rec.get("virtual_key") or get_path(rec, "config.virtual_key", "metadata.virtual_key")
        api_key = rec.get("api_key") or get_path(rec, "metadata._user", "metadata.user", "metadata.user_id")
        ua = get_path(rec, "request.headers.user-agent", "metadata.user_agent", "headers.user-agent")
        req_body = get_path(rec, "request.body", "request")
        caller = f"portkey:{vk or api_key or 'unknown'}"
        return Event(
            caller=caller,
            caller_kind="api-key",
            caller_label=str(vk or api_key or "unknown"),
            timestamp=parse_timestamp(rec.get("created_at") or rec.get("timestamp") or rec.get("time")),
            model=rec.get("ai_model") or rec.get("model") or get_path(rec, "response.body.model", "request.body.model"),
            provider=rec.get("ai_provider") or rec.get("provider"),
            user_agent=ua,
            user=str(get_path(rec, "metadata._user", "metadata.user")) if get_path(rec, "metadata._user", "metadata.user") else None,
            tools=_has_tools(req_body),
            tool_calls=_has_tool_calls(get_path(rec, "response.body", "response")),
            tokens_in=_i(rec.get("prompt_tokens") or get_path(rec, "response.body.usage.prompt_tokens")),
            tokens_out=_i(rec.get("completion_tokens") or get_path(rec, "response.body.usage.completion_tokens")),
            cost=_f(rec.get("cost")),
            status=str(rec.get("status") or rec.get("response_status") or ""),
            path=rec.get("endpoint") or get_path(rec, "request.url"),
            metadata={"trace_id": rec.get("trace_id"), "metadata": rec.get("metadata")},
            schema=schema,
        )
    if schema == "kong":
        ai = rec.get("ai") or {}
        proxy = ai.get("proxy") if isinstance(ai, dict) else None
        proxy = proxy or get_path(rec, "ai.proxy") or {}
        meta = proxy.get("meta", {}) if isinstance(proxy, dict) else {}
        usage = proxy.get("usage", {}) if isinstance(proxy, dict) else {}
        consumer = get_path(rec, "consumer.username", "consumer.id", "authenticated_entity.consumer_id")
        headers = get_path(rec, "request.headers") or {}
        return Event(
            caller=f"kong:{consumer or get_path(rec, 'client_ip') or 'anonymous'}",
            caller_kind="principal" if consumer else "ip",
            caller_label=str(consumer or get_path(rec, "client_ip") or "anonymous"),
            timestamp=parse_timestamp(rec.get("started_at") or rec.get("timestamp")),
            model=meta.get("response_model") or meta.get("request_model") or get_path(rec, "ai.proxy.meta.request_model"),
            provider=meta.get("provider_name"),
            host=host_of(get_path(rec, "upstream_uri", "request.url")),
            user_agent=headers.get("user-agent") if isinstance(headers, dict) else None,
            ip=get_path(rec, "client_ip"),
            tools=None,
            tokens_in=_i(usage.get("prompt_tokens")),
            tokens_out=_i(usage.get("completion_tokens")),
            cost=_f(usage.get("cost")),
            status=str(get_path(rec, "response.status") or ""),
            path=get_path(rec, "request.uri", "route.paths.0"),
            metadata={"plugin": meta.get("plugin_id"), "route": get_path(rec, "route.name"), "service": get_path(rec, "service.name")},
            schema=schema,
        )
    if schema == "cloudflare":
        meta = rec.get("metadata") or {}
        user = meta.get("user") or meta.get("user_id") or meta.get("userId") if isinstance(meta, dict) else None
        caller = user or rec.get("api_key_id") or rec.get("gateway_id") or "unknown"
        return Event(
            caller=f"cloudflare:{caller}",
            caller_kind="user" if user else "api-key",
            caller_label=str(caller),
            timestamp=parse_timestamp(rec.get("created_at") or rec.get("timestamp")),
            model=rec.get("model"),
            provider=rec.get("provider"),
            user_agent=get_path(rec, "request_head.headers.user-agent", "request_headers.user-agent"),
            tools=_has_tools(rec.get("request_head") or rec.get("request_body")),
            tool_calls=_has_tool_calls(rec.get("response_head") or rec.get("response_body")),
            tokens_in=_i(rec.get("tokens_in")),
            tokens_out=_i(rec.get("tokens_out")),
            cost=_f(rec.get("cost")),
            status=str(rec.get("status_code") or rec.get("success") or ""),
            path=rec.get("path") or rec.get("request_type"),
            metadata={"gateway_id": rec.get("gateway_id"), "cached": rec.get("cached"), "metadata": meta},
            schema=schema,
        )
    if schema == "helicone":
        props = rec.get("request_properties") or rec.get("properties") or {}
        user = rec.get("request_user_id") or rec.get("user_id") or props.get("Helicone-User-Id")
        return Event(
            caller=f"helicone:{user or props.get('Helicone-Property-App') or 'unknown'}",
            caller_kind="user" if user else "principal",
            caller_label=str(user or props.get("Helicone-Property-App") or "unknown"),
            timestamp=parse_timestamp(rec.get("request_created_at") or rec.get("created_at")),
            model=rec.get("request_model") or rec.get("response_model") or rec.get("model"),
            provider=rec.get("provider"),
            host=host_of(rec.get("request_path") or rec.get("target_url")),
            tools=_has_tools(rec.get("request_body")),
            tool_calls=_has_tool_calls(rec.get("response_body")),
            tokens_in=_i(rec.get("prompt_tokens")),
            tokens_out=_i(rec.get("completion_tokens")),
            cost=_f(rec.get("cost") or rec.get("costUSD")),
            status=str(rec.get("response_status") or ""),
            path=rec.get("request_path"),
            metadata={"properties": props},
            schema=schema,
        )
    if schema == "langfuse":
        user = rec.get("userId") or rec.get("user_id") or get_path(rec, "trace.userId")
        name = rec.get("name") or get_path(rec, "trace.name") or rec.get("traceName")
        caller = user or name or rec.get("projectId") or rec.get("project_id") or "unknown"
        return Event(
            caller=f"langfuse:{caller}",
            caller_kind="user" if user else "service",
            caller_label=str(caller),
            timestamp=parse_timestamp(rec.get("startTime") or rec.get("start_time") or rec.get("timestamp") or rec.get("createdAt")),
            model=rec.get("model") or get_path(rec, "modelParameters.model"),
            provider=None,
            tools=_has_tools(rec.get("input")) if isinstance(rec.get("input"), (dict, str)) else (True if isinstance(rec.get("input"), list) and any(isinstance(m, dict) and (m.get("tool_calls") or m.get("role") == "tool") for m in rec["input"]) else None),
            tool_calls=_has_tool_calls(rec.get("output")),
            tokens_in=_i(get_path(rec, "usage.input", "usageDetails.input", "usage.promptTokens", "promptTokens")),
            tokens_out=_i(get_path(rec, "usage.output", "usageDetails.output", "usage.completionTokens", "completionTokens")),
            cost=_f(get_path(rec, "calculatedTotalCost", "totalCost", "costDetails.total")),
            status=rec.get("level"),
            path=name,
            metadata={"trace": rec.get("traceId") or rec.get("trace_id"), "tags": rec.get("tags"), "session": rec.get("sessionId")},
            schema=schema,
        )
    if schema == "bedrock":
        ident = rec.get("identity") or {}
        arn = ident.get("arn") if isinstance(ident, dict) else str(ident)
        inp = rec.get("input") or {}
        body = inp.get("inputBodyJson") if isinstance(inp, dict) else None
        out = rec.get("output") or {}
        obody = out.get("outputBodyJson") if isinstance(out, dict) else None
        return Event(
            caller=f"aws:{arn or 'unknown'}",
            caller_kind="principal",
            caller_label=str(arn or "unknown"),
            timestamp=parse_timestamp(rec.get("timestamp")),
            model=rec.get("modelId"),
            provider="aws-bedrock",
            host=f"bedrock-runtime.{rec.get('region', 'unknown')}.amazonaws.com",
            ip=rec.get("sourceIp") or get_path(rec, "requestMetadata.sourceIp"),
            tools=_has_tools(body) if body else None,
            tool_calls=_has_tool_calls(obody) if obody else None,
            tokens_in=_i(inp.get("inputTokenCount") if isinstance(inp, dict) else 0),
            tokens_out=_i(out.get("outputTokenCount") if isinstance(out, dict) else 0),
            status="ok" if not rec.get("errorCode") else str(rec.get("errorCode")),
            path=rec.get("operation"),
            metadata={"account": rec.get("accountId"), "region": rec.get("region"), "request_id": rec.get("requestId"), "inference_region": rec.get("inferenceRegion"), "request_metadata": rec.get("requestMetadata")},
            schema=schema,
        )
    if schema == "azure-openai":
        props = rec.get("properties") or {}
        if isinstance(props, str):
            props = json.loads(props)
        if not isinstance(props, dict):
            raise ConnectorError("gateway.logs: Azure properties must be an object")
        ident = rec.get("identity") or props.get("identity") or {}
        oid = get_path(ident, "claims.oid", "authorization.objectId", "claims.appid", "oid") if isinstance(ident, dict) else None
        upn = get_path(ident, "claims.upn", "claims.name", "claims.email", "claims.appid") if isinstance(ident, dict) else None
        caller = oid or upn or rec.get("callerIpAddress") or rec.get("CallerIPAddress") or "unknown"
        return Event(
            caller=f"azure:{caller}",
            caller_kind="principal" if oid or upn else "ip",
            caller_label=str(upn or oid or caller),
            timestamp=parse_timestamp(rec.get("time") or rec.get("TimeGenerated") or rec.get("timestamp")),
            model=props.get("modelName") or props.get("modelDeploymentName") or props.get("deploymentName") or props.get("model"),
            provider="azure-openai",
            host=host_of(rec.get("resourceId") or rec.get("ResourceId")),
            user_agent=props.get("userAgent") or get_path(rec, "properties.headers.user-agent"),
            ip=rec.get("callerIpAddress") or rec.get("CallerIPAddress"),
            user=str(upn) if upn else None,
            tools=_has_tools(props.get("requestBody") or props.get("request")),
            tool_calls=_has_tool_calls(props.get("responseBody") or props.get("response")),
            tokens_in=_i(props.get("promptTokens") or get_path(props, "usage.prompt_tokens")),
            tokens_out=_i(props.get("completionTokens") or get_path(props, "usage.completion_tokens")),
            status=str(rec.get("resultSignature") or rec.get("ResultSignature") or props.get("statusCode") or ""),
            path=rec.get("operationName") or rec.get("OperationName") or props.get("apiName"),
            metadata={"resource_id": rec.get("resourceId") or rec.get("ResourceId"), "deployment": props.get("modelDeploymentName"), "api_version": props.get("apiVersion"), "object_id": oid, "tenant": get_path(ident, "claims.tid") if isinstance(ident, dict) else None},
            schema=schema,
        )
    if schema == "vertex":
        pp = rec.get("protoPayload") or {}
        principal = get_path(pp, "authenticationInfo.principalEmail") or get_path(pp, "authenticationInfo.principalSubject")
        method = pp.get("methodName", "")
        resource = pp.get("resourceName", "")
        model = None
        m = re.search(r"(publishers/[^/]+/models/[^/:\s]+|endpoints/[^/:\s]+|reasoningEngines/[^/:\s]+|models/[^/:\s]+)", str(resource))
        if m:
            model = m.group(1)
        ua = get_path(pp, "requestMetadata.callerSuppliedUserAgent")
        return Event(
            caller=f"gcp:{principal or 'unknown'}",
            caller_kind="principal",
            caller_label=str(principal or "unknown"),
            timestamp=parse_timestamp(rec.get("timestamp") or rec.get("receiveTimestamp")),
            model=model,
            provider="google-vertex-ai",
            host=pp.get("serviceName"),
            user_agent=ua,
            ip=get_path(pp, "requestMetadata.callerIp"),
            tools=_has_tools(pp.get("request")),
            tool_calls=_has_tool_calls(pp.get("response")),
            status=str(get_path(pp, "status.code") or "ok"),
            path=method,
            metadata={"project": get_path(rec, "resource.labels.project_id"), "location": get_path(rec, "resource.labels.location"), "resource": resource, "service_account_delegation": get_path(pp, "authenticationInfo.serviceAccountDelegationInfo")},
            schema=schema,
        )
    if schema == "openai-usage":
        actor = rec.get("actor") or {}
        key_id = rec.get("api_key_id") or get_path(actor, "api_key.id") or get_path(rec, "api_key.id")
        user = rec.get("user_id") or get_path(actor, "session.user.email", "api_key.user.email", "api_key.service_account.name", "session.user.id")
        sa = get_path(actor, "api_key.service_account.id", "api_key.service_account.name")
        caller = key_id or sa or user or rec.get("project_id") or "unknown"
        aggregate = any(key in rec for key in ("num_model_requests", "n_requests"))
        count = rec.get("num_model_requests", rec.get("n_requests", 1))
        if aggregate:
            if isinstance(count, str) and count.isdecimal():
                count = int(count)
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ConnectorError("gateway.logs: OpenAI usage request count must be a nonnegative integer")
        return Event(
            caller=f"openai:{caller}",
            caller_kind="api-key" if key_id else ("service" if sa else "user"),
            caller_label=str(sa or user or key_id or caller),
            timestamp=parse_timestamp(get_path(rec, "start_time", "effective_at", "aggregation_timestamp", "timestamp")),
            interval_end=parse_timestamp(rec.get("end_time")) if aggregate else None,
            request_count=count,
            aggregated=aggregate,
            model=rec.get("model") or rec.get("snapshot_id"),
            provider="openai",
            host="api.openai.com",
            user=str(user) if user else None,
            team=rec.get("project_id") or rec.get("project_name"),
            tokens_in=_i(rec.get("input_tokens") or rec.get("n_context_tokens_total")),
            tokens_out=_i(rec.get("output_tokens") or rec.get("n_generated_tokens_total")),
            path=rec.get("operation") or rec.get("type") or rec.get("endpoint"),
            metadata={"project": rec.get("project_id"), "num_requests": rec.get("num_model_requests") or rec.get("n_requests"), "batch": rec.get("batch"), "service_account": sa, "event_type": rec.get("type")},
            schema=schema,
        )
    if schema == "anthropic-usage":
        caller = rec.get("api_key_id") or rec.get("workspace_id") or "unknown"
        return Event(
            caller=f"anthropic:{caller}",
            caller_kind="api-key" if rec.get("api_key_id") else "principal",
            caller_label=str(caller),
            timestamp=parse_timestamp(rec.get("starting_at") or rec.get("timestamp")),
            model=rec.get("model"),
            provider="anthropic",
            host="api.anthropic.com",
            team=rec.get("workspace_id"),
            tokens_in=_i(rec.get("uncached_input_tokens")) + _i(get_path(rec, "cache_read_input_tokens")),
            tokens_out=_i(rec.get("output_tokens")),
            path=rec.get("service_tier") or rec.get("context_window"),
            metadata={"workspace": rec.get("workspace_id"), "service_tier": rec.get("service_tier")},
            schema=schema,
        )
    if schema == "access-log":
        ua = get_path(rec, "http_user_agent", "user_agent", "userAgent", "http.user_agent", "request.headers.user-agent", "cs(User-Agent)", "cs-user-agent", "useragent")
        ip = get_path(rec, "remote_addr", "client_ip", "clientIp", "c-ip", "x_forwarded_for", "http.client_ip", "source_ip", "src_ip", "client.ip")
        host = get_path(rec, "host", "http_host", "server_name", "upstream_host", "authority", "http.host", "cs-host", "x-forwarded-host", "domain")
        path = get_path(rec, "request_uri", "requestUri", "uri", "path", "http.url", "cs-uri-stem", "request_path", "url")
        req = rec.get("request")
        if isinstance(req, str) and " " in req and not path:
            parts = req.split()
            path = parts[1] if len(parts) > 1 else req
        user = get_path(rec, "remote_user", "user", "username", "auth_user", "principal", "sub", "x_user", "http.user")
        api_key = get_path(rec, "api_key", "x_api_key", "apikey", "authorization_hash", "consumer", "client_id")
        caller = api_key or user or ua or ip or "unknown"
        kind = "api-key" if api_key else "user" if user else "user-agent" if ua else "ip"
        return Event(
            caller=f"access:{caller}",
            caller_kind=kind,
            caller_label=str(caller)[:120],
            timestamp=parse_timestamp(get_path(rec, "time", "timestamp", "@timestamp", "time_local", "time_iso8601", "start_time", "date", "ts", "datetime")),
            model=get_path(rec, "model", "x_model", "request_model", "llm_model"),
            host=host,
            user_agent=ua,
            ip=str(ip) if ip else None,
            user=str(user) if user else None,
            status=str(get_path(rec, "status", "status_code", "response_code", "sc-status", "http.status_code") or ""),
            path=path,
            metadata={"method": get_path(rec, "request_method", "method", "cs-method", "http.method"), "bytes": get_path(rec, "body_bytes_sent", "bytes", "sc-bytes")},
            schema=schema,
        )
    # generic
    key = get_path(rec, "api_key", "apiKey", "api_key_id", "key", "key_id", "key_alias", "virtual_key", "token_id", "client_id", "clientId")
    principal = get_path(rec, "principal", "principal_id", "identity", "identity.arn", "caller", "service", "service_name", "app", "application", "app_name", "source", "team", "team_id", "org", "project")
    user = get_path(rec, "user", "user_id", "userId", "username", "email", "end_user", "sub", "actor")
    ua = get_path(rec, "user_agent", "userAgent", "http_user_agent", "headers.user-agent", "request.headers.user-agent", "metadata.user_agent")
    ip = get_path(rec, "ip", "client_ip", "source_ip", "remote_addr", "callerIp")
    who = key or principal or user or ua or ip
    if who is None:
        return None
    kind = "api-key" if key else "principal" if principal else "user" if user else "user-agent" if ua else "ip"
    req = rec.get("request") or rec.get("request_body") or rec.get("input") or rec.get("body") or rec.get("messages")
    resp = rec.get("response") or rec.get("response_body") or rec.get("output") or rec.get("completion")
    return Event(
        caller=f"{kind}:{who}",
        caller_kind=kind,
        caller_label=str(who)[:120],
        timestamp=parse_timestamp(get_path(rec, "timestamp", "time", "@timestamp", "ts", "created_at", "createdAt", "start_time", "startTime", "date", "datetime", "event_time")),
        model=get_path(rec, "model", "model_id", "modelId", "model_name", "deployment", "engine", "llm", "response.model", "request.model"),
        provider=get_path(rec, "provider", "llm_provider", "custom_llm_provider", "vendor", "platform"),
        host=host_of(get_path(rec, "host", "url", "endpoint", "api_base", "base_url", "upstream")),
        user_agent=ua,
        ip=str(ip) if ip else None,
        user=str(user) if user else None,
        team=get_path(rec, "team", "team_id", "org", "project", "workspace"),
        tools=_has_tools(req) if req is not None else _b(get_path(rec, "tools", "has_tools", "tool_count", "function_call", "tool_choice")),
        tool_calls=_has_tool_calls(resp) if resp is not None else _b(get_path(rec, "tool_calls", "has_tool_calls")),
        streaming=_b(get_path(rec, "stream", "streaming")),
        tokens_in=_i(get_path(rec, "prompt_tokens", "input_tokens", "tokens_in", "usage.prompt_tokens", "usage.input_tokens", "promptTokens")),
        tokens_out=_i(get_path(rec, "completion_tokens", "output_tokens", "tokens_out", "usage.completion_tokens", "usage.output_tokens", "completionTokens")),
        cost=_f(get_path(rec, "cost", "spend", "total_cost", "cost_usd")),
        status=str(get_path(rec, "status", "status_code", "http_status") or ""),
        path=get_path(rec, "path", "endpoint", "operation", "call_type", "route", "method_name"),
        metadata={},
        schema="generic",
    )


# --------------------------------------------------------------- text logs

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?(?: "(?P<extra>[^"]*)")?'
)
_HOST_IN_LINE = re.compile(r"\b(?:host|authority|upstream_host|server_name)[=:]\s*\"?([A-Za-z0-9.-]+\.[a-z]{2,})", re.I)


def parse_text_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    if line.startswith(("{", "[")):
        rec = json.loads(line)
        if not isinstance(rec, dict):
            raise ValueError("gateway text log JSON must be an object")
        return rec
    m = _COMBINED.match(line)
    if m:
        d = m.groupdict()
        h = _HOST_IN_LINE.search(line)
        rec = {"remote_addr": d["ip"], "remote_user": None if d["user"] == "-" else d["user"], "time_local": d["time"], "request_method": d["method"], "request_uri": d["path"], "status": d["status"], "http_user_agent": d.get("ua"), "host": h.group(1) if h else None}
        return rec
    # key=value logfmt
    if "=" in line and " " in line:
        kv = dict(re.findall(r'(\w[\w.-]*)=("[^"]*"|\S+)', line))
        if kv:
            return {k: v.strip('"') for k, v in kv.items()}
    return None


PROVIDER_ALIASES = {
    "openai": "provider.openai", "azure": "provider.azure-openai", "azure_openai": "provider.azure-openai", "azure-openai": "provider.azure-openai", "azure_ai": "provider.azure-openai",
    "anthropic": "provider.anthropic", "bedrock": "provider.aws-bedrock", "aws-bedrock": "provider.aws-bedrock", "aws_bedrock": "provider.aws-bedrock", "amazon-bedrock": "provider.aws-bedrock", "bedrock_converse": "provider.aws-bedrock",
    "vertex_ai": "provider.google-vertex-ai", "vertex-ai": "provider.google-vertex-ai", "vertexai": "provider.google-vertex-ai", "google-vertex-ai": "provider.google-vertex-ai", "vertex_ai_beta": "provider.google-vertex-ai",
    "gemini": "provider.google-gemini", "google": "provider.google-gemini", "google-ai-studio": "provider.google-gemini", "google_ai_studio": "provider.google-gemini",
    "mistral": "provider.mistral", "cohere": "provider.cohere", "cohere_chat": "provider.cohere", "groq": "provider.groq", "together_ai": "provider.together", "together": "provider.together",
    "fireworks_ai": "provider.fireworks", "fireworks": "provider.fireworks", "openrouter": "provider.openrouter", "ollama": "provider.ollama", "ollama_chat": "provider.ollama", "vllm": "provider.vllm",
    "huggingface": "provider.huggingface", "hugging-face": "provider.huggingface", "xai": "provider.xai", "deepseek": "provider.deepseek", "perplexity": "provider.perplexity", "replicate": "provider.replicate",
    "cerebras": "provider.cerebras", "sambanova": "provider.sambanova", "nvidia_nim": "provider.nvidia-nim", "nvidia": "provider.nvidia-nim", "oci": "provider.oci-generative-ai", "oci_genai": "provider.oci-generative-ai",
    "watsonx": "provider.ibm-watsonx", "databricks": "provider.databricks", "cloudflare": "provider.cloudflare-workers-ai", "workers-ai": "provider.cloudflare-workers-ai", "snowflake": "provider.snowflake-cortex",
}


def _provider_signature(index: Any, name: str | None) -> str | None:
    if not name:
        return None
    key = str(name).strip().lower()
    if key in PROVIDER_ALIASES:
        return PROVIDER_ALIASES[key]
    slug = key.replace("_", "-")
    for sig in index.by_category("provider"):
        if sig.id.split(".", 1)[1] == slug:
            return sig.id
    return None


# ------------------------------------------------------------- connector


@dataclass
class _Caller:
    key: str
    kind: str
    label: str
    events: int = 0
    records: int = 0
    usage_intervals: list[dict[str, Any]] = field(default_factory=list)
    first: datetime | None = None
    last: datetime | None = None
    models: Counter = field(default_factory=Counter)
    providers: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    ips: Counter = field(default_factory=Counter)
    users: Counter = field(default_factory=Counter)
    teams: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    tools_requests: int = 0
    tool_call_responses: int = 0
    tool_known: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float = 0.0
    errors: int = 0
    hours: Counter = field(default_factory=Counter)  # hour-of-day UTC
    weekdays: Counter = field(default_factory=Counter)
    schemas: Counter = field(default_factory=Counter)
    metadata_samples: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, str] = field(default_factory=dict)
    observations: dict[str, dict[str, Any]] = field(default_factory=dict)


class GatewayLogConnector(BaseConnector):
    name: ClassVar[str] = "gateway.logs"
    surface: ClassVar[Surface] = Surface.GATEWAY
    provider: ClassVar[str | None] = "gateway"
    description: ClassVar[str] = "Reconstruct LLM callers (API keys, principals, services, user agents) from AI gateway / provider / proxy logs."
    config_keys: ClassVar[dict[str, str]] = {
        "input": "log file or directory (JSONL / JSON / CSV / nginx-envoy text)",
        "format": "force schema: litellm|portkey|kong|cloudflare|helicone|langfuse|bedrock|azure-openai|vertex|openai-usage|anthropic-usage|access-log|generic (default auto)",
        "min_events": "ignore callers with fewer events (default 1)",
        "llm_hosts_only": "for access logs, keep only requests to known LLM/agent hosts (default true)",
        "max_records": "stop after N records (default 5,000,000)",
        "correlation_bindings": "explicit [{code_resource, caller, scope}] mappings; scope must exactly match log tenant/account/project/workspace fields ({} for unscoped exports)",
    }
    offline_formats: ClassVar[str] = "JSONL / JSON / CSV / text access logs"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.format = ctx.get("format")
        self.min_events = int(ctx.get("min_events", 1))
        self.llm_hosts_only = bool(ctx.get("llm_hosts_only", True))
        self.max_records = int(ctx.get("max_records", 5_000_000))
        self.label = ctx.get("label") or ctx.get("gateway_name")
        if self.format not in {None, "litellm", "portkey", "kong", "cloudflare", "helicone", "langfuse", "bedrock", "azure-openai", "vertex", "openai-usage", "anthropic-usage", "access-log", "generic"}:
            raise ConnectorError("gateway.logs: unsupported format")
        # A caller is scoped to its configured export source. Repeating the same
        # source is idempotent; distinct sources retain their own observations.
        self.correlation_bindings = ctx.get("correlation_bindings", [])
        if not isinstance(self.correlation_bindings, list):
            raise ConnectorError("gateway.logs: correlation_bindings must be a list")
        for binding in self.correlation_bindings:
            if (
                not isinstance(binding, dict)
                or not isinstance(binding.get("code_resource"), str) or not binding["code_resource"]
                or not isinstance(binding.get("caller"), str) or not binding["caller"]
                or not isinstance(binding.get("scope"), dict)
                or any(k not in {"tenant", "account", "project", "workspace"} or not isinstance(v, str) or not v for k, v in binding["scope"].items())
            ):
                raise ConnectorError("gateway.logs: each correlation binding requires exact code_resource, caller and scope mapping")
        source = str(Path(ctx.input_path).expanduser().resolve()) if ctx.input_path else ""
        identity = json.dumps([source, self.label, self.format, self.min_events,
                               self.llm_hosts_only, self.max_records,
                               sorted(self.correlation_bindings, key=lambda b: json.dumps(b, sort_keys=True))], sort_keys=True)
        self.source_id = hashlib.sha256(identity.encode()).hexdigest()

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError("gateway.logs: this connector reads exported logs; set 'input' to a file or directory")

    def _parse_line(self, line: str, location: str) -> dict[str, Any] | None:
        if not line.strip():
            return None
        try:
            rec = parse_text_line(line)
        except (ValueError, TypeError, RecursionError):
            self.ctx.warn(f"gateway.logs: invalid JSON/text record at {location}")
            return None
        if rec is None:
            self.ctx.warn(f"gateway.logs: unrecognized text record at {location}")
        return rec

    def _expand_record(self, rec: dict[str, Any]) -> Iterator[dict[str, Any]]:
        # Base loading removes the outer data[] page. OpenAI usage requires a
        # second, schema-specific expansion; bucket boundaries are provenance,
        # not individual request timestamps.
        if rec.get("object") == "bucket" or (self.format == "openai-usage" and "results" in rec):
            results = rec.get("results")
            first, last = parse_timestamp(rec.get("start_time")), parse_timestamp(rec.get("end_time"))
            if not isinstance(results, list) or first is None or last is None or last <= first:
                self.ctx.warn("gateway.logs: malformed OpenAI usage bucket (results and a valid interval are required)")
                return
            for result in results:
                if not isinstance(result, dict) or not any(k in result for k in ("num_model_requests", "n_requests")):
                    self.ctx.warn("gateway.logs: malformed OpenAI usage result (request count is required)")
                    continue
                if "object" in result and not str(result["object"]).startswith("organization.usage."):
                    self.ctx.warn("gateway.logs: unsupported OpenAI usage result type")
                    continue
                yield {**result, "object": result.get("object") or "organization.usage.completions.result",
                       "start_time": rec["start_time"], "end_time": rec["end_time"]}
            return
        if "logEvents" in rec and isinstance(rec["logEvents"], list):
            for event in rec["logEvents"]:
                if isinstance(event, dict):
                    yield from self._expand_record(event)
                else:
                    self.ctx.warn("gateway.logs: malformed CloudWatch log event")
            return
        for key in ("message", "textPayload"):
            if isinstance(rec.get(key), str) and (key == "textPayload" or rec[key].strip().startswith(("{", "[")) and len(rec) <= 4):
                inner = self._parse_line(rec[key], key)
                if inner is not None:
                    yield from self._expand_record(inner)
                return
        if "jsonPayload" in rec and "protoPayload" not in rec:
            if isinstance(rec["jsonPayload"], dict):
                yield from self._expand_record(rec["jsonPayload"])
            else:
                self.ctx.warn("gateway.logs: jsonPayload must be an object")
            return
        yield rec

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        suffixes = {".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".gz"}
        for source in self._offline_files(path, suffixes):
            text: str | None
            suffix = source.suffix.lower()
            if suffix not in {".gz", ".log", ".txt"}:
                for rec in super().load_offline(str(source)):
                    yield from self._expand_record(rec)
                continue
            if suffix == ".gz":
                import gzip
                import io
                import zlib

                raw = self._read_offline_bytes(source)
                if raw is None:
                    continue
                remaining = self._MAX_OFFLINE_TOTAL_BYTES - getattr(self, "_offline_bytes_read", 0)
                limit = min(self._MAX_OFFLINE_FILE_BYTES, remaining)
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                        expanded = stream.read(limit + 1)
                    self._offline_bytes_read += len(expanded)
                    if len(expanded) > limit:
                        raise ValueError("expanded log exceeds byte limit")
                    text = expanded.decode("utf-8-sig")
                except (OSError, EOFError, ValueError, zlib.error):
                    self.ctx.error("gateway.logs: compressed log is invalid or exceeds byte limit")
                    continue
            else:
                text = self._read_offline_text(source)
                if text is None:
                    continue
            if not text.strip():
                self.ctx.warn("gateway.logs: empty text export; use [] for an empty JSON export")
            for number, line in enumerate(text.splitlines(), 1):
                parsed = self._parse_line(line, f"line {number}")
                if parsed is not None:
                    yield from self._expand_record(parsed)

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        callers: dict[str, _Caller] = {}
        n = 0
        skipped = 0
        for rec in records:
            n += 1
            if n > self.max_records:
                self.ctx.warn(f"gateway.logs: max_records ({self.max_records}) reached")
                break
            try:
                schema = self.format or detect_schema(rec)
                ev = normalise(rec, schema)
                if ev is None:
                    self.ctx.warn(f"gateway.logs: unrecognized record {n}; could not identify a caller")
                    skipped += 1
                    continue
                if ev.request_count == 0:
                    continue
                if schema == "access-log" and self.llm_hosts_only and not self._is_llm_traffic(ev):
                    skipped += 1
                    continue
                self._runtime_context(ev, rec)
                self._accumulate(callers, ev)
            except (ValueError, TypeError, AttributeError, KeyError, OverflowError,
                    RecursionError, ConnectorError, MatchTimeoutError) as exc:
                self.ctx.warn(f"gateway.logs: invalid record {n}: {type(exc).__name__}")
                continue
        self.ctx.examined(n)
        if skipped:
            self.log.info("gateway.logs: %d/%d records skipped (unrecognised or non-LLM)", skipped, n)
        for c in callers.values():
            if c.events < self.min_events:
                continue
            yield self._finding(c)

    def _runtime_context(self, ev: Event, rec: dict[str, Any]) -> None:
        """Operator bindings identify workloads; log names alone never do."""
        rec = sanitize(rec)
        aliases = {
            "tenant": ("tenant_id", "tenant", "organization_id", "org_id", "metadata.tenant_id", "metadata.tenant", "identity.claims.tid", "properties.identity.claims.tid"),
            "account": ("account_id", "accountId", "account", "subscription_id", "subscriptionId", "metadata.account_id", "metadata.account"),
            "project": ("project_id", "projectId", "project", "metadata.project_id", "resource.labels.project_id"),
            "workspace": ("workspace_id", "workspace", "metadata.workspace_id"),
        }
        for key, paths in aliases.items():
            value = get_path(rec, *paths)
            if value is None:
                value = ev.metadata.get(key)
            if isinstance(value, (str, int)) and str(value):
                ev.scope[key] = str(value)
        environment = get_path(rec, "environment", "deployment_environment", "metadata.environment", "metadata.deployment_environment")
        if isinstance(environment, str) and environment:
            ev.environment = environment.strip().lower()
        ev.runtime_frameworks = sorted({
            match.signature.id for match in self.index.match_user_agent(ev.user_agent or "")
            if match.signature.category == "framework"
        })
        ev.code_resources = sorted({
            binding["code_resource"] for binding in self.correlation_bindings
            if binding["caller"] == ev.caller and binding["scope"] == ev.scope
        })

    def _is_llm_traffic(self, ev: Event) -> bool:
        if ev.model:
            return True
        text = " ".join(x for x in (ev.host, ev.path) if x)
        if ev.host and self.index.match_domain(ev.host):
            return True
        if ev.path and re.search(r"/v1/(?:chat/completions|completions|responses|messages|embeddings|models|assistants|threads|runs|audio|images|files|batches|realtime)|/openai/deployments/|/generateContent|:generateContent|:streamGenerateContent|/invoke(?:-with-response-stream)?|/converse|/mcp\b|/sse\b|/a2a\b|/agents?/|/predict\b|/api/(?:chat|generate|tags)\b", text):
            return True
        return bool(ev.user_agent and self.index.match_user_agent(ev.user_agent))

    @staticmethod
    def _accumulate(callers: dict[str, _Caller], ev: Event) -> None:
        identity = json.dumps([ev.caller, ev.scope], sort_keys=True)
        c = callers.get(identity)
        if c is None:
            c = callers[identity] = _Caller(ev.caller, ev.caller_kind, ev.caller_label, scope=dict(ev.scope))
        c.events += ev.request_count
        c.records += 1
        c.schemas[ev.schema] += 1
        if ev.timestamp:
            c.first = ev.timestamp if not c.first or ev.timestamp < c.first else c.first
            end = ev.interval_end or ev.timestamp
            c.last = end if not c.last or end > c.last else c.last
            if not ev.aggregated:
                c.hours[ev.timestamp.hour] += 1
                c.weekdays[ev.timestamp.weekday()] += 1
        if ev.aggregated:
            c.usage_intervals.append({"start": to_iso(ev.timestamp), "end": to_iso(ev.interval_end),
                                      "requests": ev.request_count, "model": ev.model})
        if ev.model:
            c.models[str(ev.model)] += ev.request_count
        if ev.provider:
            c.providers[str(ev.provider)] += ev.request_count
        if ev.host:
            c.hosts[ev.host] += ev.request_count
        if ev.user_agent:
            c.user_agents[str(ev.user_agent)[:160]] += ev.request_count
        if ev.ip:
            c.ips[ev.ip] += ev.request_count
        if ev.user:
            c.users[ev.user] += ev.request_count
        if ev.team:
            c.teams[str(ev.team)] += ev.request_count
        if ev.path:
            c.paths[str(ev.path)[:120]] += ev.request_count
        if ev.tools is not None:
            c.tool_known += 1
            if ev.tools:
                c.tools_requests += 1
        if ev.tool_calls:
            c.tool_call_responses += 1
        c.tokens_in += ev.tokens_in
        c.tokens_out += ev.tokens_out
        c.cost += ev.cost
        if ev.status and (ev.status.startswith(("4", "5")) or ev.status.lower() in {"error", "failure", "failed"}):
            c.errors += 1
        for k, v in ev.metadata.items():
            if v not in (None, "", {}, []) and k not in c.metadata_samples:
                c.metadata_samples[k] = v if isinstance(v, (str, int, float, bool)) else json.dumps(v, default=str)[:300]
        bucket = json.dumps([ev.code_resources, ev.runtime_frameworks, ev.environment])
        observation = c.observations.setdefault(bucket, {
            "code_resources": ev.code_resources,
            "frameworks": ev.runtime_frameworks,
            "environment": ev.environment,
            "scope": dict(ev.scope),
            "events": 0,
            "timestamped_events": 0,
            "first_seen": None,
            "last_seen": None,
            "identity_basis": "configured-exact-caller-and-scope",
        })
        observation["events"] += ev.request_count
        if ev.timestamp and not ev.aggregated:
            timestamp = to_iso(ev.timestamp)
            observation["timestamped_events"] += 1
            observation["first_seen"] = min(observation["first_seen"], timestamp) if observation["first_seen"] else timestamp
            observation["last_seen"] = max(observation["last_seen"], timestamp) if observation["last_seen"] else timestamp

    def _finding(self, c: _Caller) -> Finding:
        f = Finding(
            surface=Surface.GATEWAY,
            connector=self.name,
            kind=Kind.GATEWAY_CALLER,
            title="",
            resource=c.key,
            resource_type=f"caller/{c.kind}",
            provider=self.label or (c.schemas.most_common(1)[0][0] if c.schemas else "gateway"),
            account=json.dumps(c.scope, sort_keys=True) if c.scope else self.label,
            first_seen=to_iso(c.first),
            last_seen=to_iso(c.last),
        )
        top_models = [m for m, _ in c.models.most_common(10)]
        f.models = top_models
        for m in top_models:
            apply_matches(f, self.index.match_model(m), weight_scale=0.5)
        for h, _ in c.hosts.most_common(10):
            apply_matches(f, self.index.match_domain(h), weight_scale=0.6)
        for ua, _ in c.user_agents.most_common(10):
            apply_matches(f, self.index.match_user_agent(ua), weight_scale=1.0)
        for p, _ in c.providers.most_common(5):
            sid = _provider_signature(self.index, p)
            if sid:
                f.add_model_provider(sid)
        apply_matches(f, self.index.match_name(c.label), weight_scale=0.6)
        for u, _ in c.users.most_common(3):
            apply_matches(f, self.index.match_name(str(u)), weight_scale=0.4)

        base_weight = {"api-key": 0.35, "principal": 0.35, "service": 0.45, "user": 0.15, "user-agent": 0.2, "ip": 0.15}[c.kind]
        f.add_evidence(Evidence(signal=f"gateway:{c.kind}", description=f"{c.events} LLM request(s) by {c.kind} '{c.label}' to models {', '.join(top_models[:5]) or 'unknown'}", weight=base_weight))

        tool_ratio = (c.tools_requests / c.tool_known) if c.tool_known else None
        if tool_ratio is not None and tool_ratio > 0:
            f.add_capability("tool-use")
            f.add_evidence(Evidence(signal="gateway:tool-use", description=f"{c.tools_requests}/{c.tool_known} inspected requests carried tool/function definitions ({tool_ratio:.0%}); {c.tool_call_responses} responses invoked tools", weight=min(0.9, 0.4 + tool_ratio * 0.5)))
            f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
        if c.tool_call_responses and tool_ratio is None:
            f.add_capability("tool-use")
            f.add_evidence(Evidence(signal="gateway:tool-calls", description=f"{c.tool_call_responses} responses contained tool calls", weight=0.6))
            f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1

        # temporal shape: automated callers run around the clock and on weekends
        total_ts = sum(c.hours.values())
        if total_ts >= 50:
            night = sum(v for h, v in c.hours.items() if h < 6 or h >= 22) / total_ts
            weekend = sum(v for d, v in c.weekdays.items() if d >= 5) / total_ts
            active_hours = len(c.hours)
            if active_hours >= 20 or (night > 0.25 and weekend > 0.15):
                f.add_capability("autonomous")
                f.add_tag("always-on")
                f.add_evidence(Evidence(signal="gateway:always-on", description=f"Activity across {active_hours}/24 hours, {night:.0%} at night, {weekend:.0%} on weekends: unattended / scheduled caller", weight=0.5))
                f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
            f.metadata["activity"] = {"active_hours": active_hours, "night_share": round(night, 2), "weekend_share": round(weekend, 2)}
        if c.events >= 1000:
            f.add_evidence(Evidence(signal="gateway:volume", description=f"High volume: {c.events} requests", weight=0.2))
        if len(c.models) >= 4:
            f.add_evidence(Evidence(signal="gateway:multi-model", description=f"Uses {len(c.models)} different models (router / orchestrator behaviour)", weight=0.2))
        if c.kind in {"api-key", "service", "principal"} and not c.users:
            f.add_tag("no-end-user-attribution")
        if c.errors and c.errors / c.events > 0.2:
            f.add_tag("high-error-rate")

        f.owner = (c.users.most_common(1)[0][0] if c.users else None) or (c.teams.most_common(1)[0][0] if c.teams else None)
        f.metadata.update(
            {
                "caller_kind": c.kind,
                "caller": c.label,
                "events": c.events,
                "records": c.records,
                "usage_intervals": c.usage_intervals,
                "event_counting": "Request totals within this source; aggregate bucket counts are preserved. Distinct sources are not deduplicated against each other.",
                "models": dict(c.models.most_common(10)),
                "providers": dict(c.providers.most_common(5)),
                "hosts": dict(c.hosts.most_common(5)),
                "user_agents": dict(c.user_agents.most_common(5)),
                "source_ips": dict(c.ips.most_common(5)),
                "end_users": dict(c.users.most_common(5)),
                "teams": dict(c.teams.most_common(3)),
                "operations": dict(c.paths.most_common(5)),
                "tool_requests": c.tools_requests,
                "tool_call_responses": c.tool_call_responses,
                "tokens_in": c.tokens_in,
                "tokens_out": c.tokens_out,
                "cost": round(c.cost, 4),
                "errors": c.errors,
                "schemas": dict(c.schemas),
                "samples": c.metadata_samples,
                "correlation_scope": c.scope,
                "runtime_observations": list(c.observations.values()),
                "runtime_source": {"id": self.source_id, "input": str(self.ctx.input_path or ""), "label": self.label, "schemas": sorted(c.schemas)},
            }
        )
        f.id = "ss-" + hashlib.sha256(f"{f.compute_id()}|{self.source_id}".encode()).hexdigest()[:16]
        finalize(f, self.index)
        f.kind = Kind.GATEWAY_CALLER
        what = "Agentic caller" if f.metadata.get("agent_indicators") else "LLM caller"
        fw = [self.index.get(s).name for s in f.frameworks[:2] if self.index.get(s)]  # type: ignore[union-attr]
        f.title = f"{what} '{c.label}' ({c.kind}): {c.events} requests" + (f" via {', '.join(fw)}" if fw else "") + (f" to {top_models[0]}" if top_models else "")
        return f
