"""Per-schema normalisation of gateway log records into :class:`Event` objects.

Each supported export schema has one small normaliser that maps a raw record to
an ``Event``. ``NORMALISERS`` registers them by schema id and ``_normalise``
dispatches to the right one, falling back to the generic normaliser for an
unknown schema id. ``detect_schema`` picks the schema of an unlabelled record
from an ordered table of detectors.

Normalisers only extract fields. They never redact: opaque caller and scope
identities are derived afterwards by ``logs.normalise_with_record``.

Public names remain importable from ``shadowscan.connectors.gateway.logs``.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from shadowscan.connectors.base import ConnectorError
from shadowscan.utils.text import get_path, host_of, parse_timestamp

# ------------------------------------------------------------------ event


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
    scope_redacted: bool = False
    caller_redacted: bool = False
    binding_caller: str | None = field(default=None, repr=False)  # private exact-match key; never exported
    environment: str | None = None
    runtime_frameworks: list[str] = field(default_factory=list)
    code_resources: list[str] = field(default_factory=list)
    identity_assurance: str = "unverified"


Normaliser = Callable[[dict[str, Any]], Event | None]

# --------------------------------------------------------- field coercion


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
        number = float(v)
    except (TypeError, ValueError, OverflowError):
        return 0
    return int(number) if math.isfinite(number) else 0


def _f(v: Any) -> float:
    """Finite floats only: NaN/Infinity would poison caller totals and the JSON report."""
    try:
        number = float(v)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _first(rec: Mapping[str, Any], *keys: str) -> Any:
    """``rec.get(k1) or rec.get(k2) or ...``: the first truthy value, else the last one read.

    Returning the last value rather than None keeps the exact ``or`` chain
    semantics for falsy non-null values such as ``0`` or ``""``.
    """
    value = None
    for key in keys:
        value = rec.get(key)
        if value:
            return value
    return value


def _text(value: Any) -> str | None:
    """``str(value) if value else None`` for optional identity fields."""
    return str(value) if value else None


def _label(value: Any) -> str:
    """``str(value or "")`` for status and label fields that are strings, never None."""
    return str(value or "")


def _timestamp(rec: Mapping[str, Any], *keys: str) -> datetime | None:
    """Parse the first set timestamp field among ``keys``."""
    return parse_timestamp(_first(rec, *keys))


def _mapping(value: Any) -> dict[str, Any]:
    """The value when it is an object, else an empty one."""
    return value if isinstance(value, dict) else {}


def _identity(*candidates: tuple[str, Any]) -> tuple[str, Any]:
    """Return the first ``(kind, value)`` whose value is set, else the last candidate.

    Mirrors ``key or principal or user or ...`` paired with the matching
    ``"api-key" if key else "principal" if principal ...`` ladder.
    """
    for kind, value in candidates:
        if value:
            return kind, value
    return candidates[-1]


# ------------------------------------------------------ tool-use detection

_TOOL_MESSAGE_TYPES = {"function_call", "function_call_output", "tool_use", "tool_result"}


def _is_tool_message(item: Any) -> bool:
    """A chat message that carries tool calls or comes from a tool."""
    return isinstance(item, dict) and bool(
        item.get("tool_calls") or item.get("role") in {"tool", "function"} or item.get("type") in _TOOL_MESSAGE_TYPES
    )


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
        return _mapping_has_tools(obj)
    if isinstance(obj, list):
        return any(_is_tool_message(item) or _has_tools(item) is True for item in obj)
    return None


def _declared_tools(obj: dict[str, Any]) -> bool:
    """A non-empty tool, function or function declaration list, possibly serialised."""
    for key in ("tools", "functions", "function_declarations"):
        v = obj.get(key)
        if isinstance(v, str) and v.strip().startswith(("[", "{")):
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                pass
        if v not in (None, [], {}, ""):
            return True
    return False


def _mapping_has_tools(obj: dict[str, Any]) -> bool | None:
    choice = obj.get("tool_choice")
    if choice == "none" or isinstance(choice, dict) and choice.get("type") == "none":
        return False
    for wrapper in ("body", "request", "payload", "json"):
        inner = obj.get(wrapper)
        if isinstance(inner, (dict, str)) and not any(k in obj for k in ("tools", "functions", "messages", "input")):
            return _has_tools(inner)
    if _declared_tools(obj):
        return True
    for key in ("toolConfig", "tool_config"):
        if isinstance(obj.get(key), (dict, str)) and _has_tools(obj[key]):
            return True
    # A choice of "none" (or "auto" without definitions) does not
    # establish that a tool was available or invoked.
    if isinstance(choice, dict) and choice.get("type") not in {"none", "auto", None}:
        return True
    msgs = obj.get("messages") or obj.get("input") or []
    return isinstance(msgs, list) and any(_is_tool_message(m) for m in msgs)


def _embedded_json(value: Any) -> Any:
    """Decode a JSON container serialised into a string field; None when it is not one."""
    if isinstance(value, str) and value.strip().startswith(("[", "{")):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return value


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
    finish_marker = False
    explicit_empty = False
    while pending:
        item = pending.pop()
        if isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, dict):
            called = _item_tool_calls(item)
            if called is True:
                return True
            explicit_empty = explicit_empty or called is False
            if item.get("stop_reason") == "tool_use" or item.get("finish_reason") in {"tool_calls", "function_call"}:
                finish_marker = True
            pending.extend(value for value in item.values() if isinstance(value, (dict, list)))
    return finish_marker and not explicit_empty


def _item_tool_calls(item: dict[str, Any]) -> bool | None:
    """True when a response object invoked a tool, False when it explicitly did not, else None."""
    explicit_empty = False
    calls = _embedded_json(item.get("tool_calls"))
    if isinstance(calls, list) and any(isinstance(call, dict) and call for call in calls):
        return True
    if "tool_calls" in item and calls in (None, [], {}, "", False):
        explicit_empty = True
    for key in ("function_call", "functionCall", "tool_use"):
        value = _embedded_json(item.get(key))
        if isinstance(value, dict) and value:
            return True
        if key in item and value in (None, [], {}, "", False):
            explicit_empty = True
    if item.get("type") in {"tool_use", "function_call"}:
        return True
    return False if explicit_empty else None


# -------------------------------------------------------- schema detection

_ACCESS_LOG_AGENT_KEYS = ("http_user_agent", "user_agent", "userAgent", "http.user_agent")
_ACCESS_LOG_CLIENT_KEYS = ("remote_addr", "request_uri", "clientIp", "requestUri", "c-ip", "elb")


def _looks_bedrock(rec: dict[str, Any]) -> bool:
    return rec.get("schemaType") == "ModelInvocationLog" or ("modelId" in rec and "identity" in rec and "input" in rec)


def _looks_vertex(rec: dict[str, Any]) -> bool:
    return "protoPayload" in rec and "aiplatform" in json.dumps(rec.get("protoPayload", {}))[:500]


def _looks_azure_openai(rec: dict[str, Any]) -> bool:
    return (
        rec.get("category") in {"RequestResponse", "Audit", "Trace"}
        and ("properties" in rec or "callerIpAddress" in rec)
        and ("resourceId" in rec or "ResourceId" in rec)
    )


def _looks_litellm(rec: dict[str, Any]) -> bool:
    return "spend" in rec and ("api_key" in rec or "call_type" in rec or "request_id" in rec)


def _looks_kong(rec: dict[str, Any]) -> bool:
    return "ai.proxy" in json.dumps(rec)[:2000] or (isinstance(rec.get("ai"), dict) and "proxy" in rec["ai"])


def _looks_cloudflare(rec: dict[str, Any]) -> bool:
    return "gateway_id" in rec or ("provider" in rec and "request_type" in rec and "tokens_in" in rec) or "ai_gateway" in rec


def _looks_portkey(rec: dict[str, Any]) -> bool:
    if "trace_id" in rec and "virtual_key" in rec:
        return True
    dump = json.dumps(rec)
    return "portkey" in dump[:500].lower() or "x-portkey" in dump[:2000].lower()


def _looks_helicone(rec: dict[str, Any]) -> bool:
    dump = json.dumps(rec)
    return "helicone" in dump[:1000].lower() or ("request_properties" in rec and "helicone-request-id" in dump[:5000].lower())


def _looks_langfuse(rec: dict[str, Any]) -> bool:
    return (
        "observation_id" in rec
        or ("traceId" in rec and "usageDetails" in rec)
        or (rec.get("type") == "GENERATION" and "model" in rec)
        or ("project_id" in rec and "trace_id" in rec and "model" in rec)
    )


def _looks_openai_usage(rec: dict[str, Any]) -> bool:
    return (
        "n_context_tokens_total" in rec
        or ("object" in rec and str(rec.get("object", "")).startswith("organization.usage"))
        or ("api_key_id" in rec and "input_tokens" in rec)
        or ("actor" in rec and "effective_at" in rec)
    )


def _looks_anthropic_usage(rec: dict[str, Any]) -> bool:
    return (
        ("workspace_id" in rec and "api_key_id" in rec and "uncached_input_tokens" in rec)
        or ("uncached_input_tokens" in rec and "model" in rec)
    )


def _looks_access_log(rec: dict[str, Any]) -> bool:
    if isinstance(rec.get("request"), str):
        return True
    if any(key in rec for key in _ACCESS_LOG_AGENT_KEYS) and "model" not in rec:
        return True
    return any(key in rec for key in _ACCESS_LOG_CLIENT_KEYS)


# Detection order matters: earlier, more specific exports win over later
# ones that share field names. The generic schema is the fallback.
_DETECTORS: tuple[tuple[str, Callable[[dict[str, Any]], bool]], ...] = (
    ("bedrock", _looks_bedrock),
    ("vertex", _looks_vertex),
    ("azure-openai", _looks_azure_openai),
    ("litellm", _looks_litellm),
    ("kong", _looks_kong),
    ("cloudflare", _looks_cloudflare),
    ("portkey", _looks_portkey),
    ("helicone", _looks_helicone),
    ("langfuse", _looks_langfuse),
    ("openai-usage", _looks_openai_usage),
    ("anthropic-usage", _looks_anthropic_usage),
    ("access-log", _looks_access_log),
)


def detect_schema(rec: dict[str, Any]) -> str:
    """Return the schema id of an export record, ``generic`` when no detector matches."""
    for schema, matches in _DETECTORS:
        if matches(rec):
            return schema
    return "generic"


# ------------------------------------------------------------ normalisers


def _normalise_litellm(rec: dict[str, Any]) -> Event:
    key = _first(rec, "api_key", "hashed_api_key", "key_hash") or ""
    alias = _first(rec, "api_key_alias", "key_alias") or get_path(rec, "metadata.user_api_key_alias") or ""
    team = rec.get("team_id") or get_path(rec, "metadata.user_api_key_team_id", "metadata.user_api_key_team_alias")
    user = _first(rec, "user", "end_user") or get_path(rec, "metadata.user_api_key_user_id", "metadata.user_api_key_user_email")
    request = _first(rec, "proxy_server_request", "request") or get_path(rec, "metadata.proxy_server_request.body")
    return Event(
        caller=f"litellm-key:{key or alias or 'anonymous'}",
        caller_kind="api-key",
        caller_label=alias or str(key or "anonymous"),
        timestamp=_timestamp(rec, "startTime", "start_time", "endTime", "timestamp"),
        model=_first(rec, "model", "model_group"),
        provider=_first(rec, "custom_llm_provider", "provider"),
        host=host_of(rec.get("api_base")),
        user_agent=get_path(rec, "metadata.user_agent", "metadata.headers.user-agent", "request_tags.user_agent", "metadata.requester_metadata.user_agent"),
        ip=get_path(rec, "metadata.requester_ip_address", "requester_ip_address"),
        user=_text(user),
        team=_text(team),
        tools=_has_tools(request),
        tool_calls=_has_tool_calls(rec.get("response")),
        tokens_in=_i(rec.get("prompt_tokens")),
        tokens_out=_i(rec.get("completion_tokens")),
        cost=_f(rec.get("spend")),
        status=rec.get("status"),
        path=rec.get("call_type"),
        metadata={"request_tags": rec.get("request_tags"), "cache_hit": rec.get("cache_hit")},
        schema="litellm",
    )


def _normalise_portkey(rec: dict[str, Any]) -> Event:
    vk = rec.get("virtual_key") or get_path(rec, "config.virtual_key", "metadata.virtual_key")
    api_key = rec.get("api_key") or get_path(rec, "metadata._user", "metadata.user", "metadata.user_id")
    return Event(
        caller=f"portkey:{vk or api_key or 'unknown'}",
        caller_kind="api-key",
        caller_label=str(vk or api_key or "unknown"),
        timestamp=_timestamp(rec, "created_at", "timestamp", "time"),
        model=_first(rec, "ai_model", "model") or get_path(rec, "response.body.model", "request.body.model"),
        provider=_first(rec, "ai_provider", "provider"),
        user_agent=get_path(rec, "request.headers.user-agent", "metadata.user_agent", "headers.user-agent"),
        user=_text(get_path(rec, "metadata._user", "metadata.user")),
        tools=_has_tools(get_path(rec, "request.body", "request")),
        tool_calls=_has_tool_calls(get_path(rec, "response.body", "response")),
        tokens_in=_i(rec.get("prompt_tokens") or get_path(rec, "response.body.usage.prompt_tokens")),
        tokens_out=_i(rec.get("completion_tokens") or get_path(rec, "response.body.usage.completion_tokens")),
        cost=_f(rec.get("cost")),
        status=_label(_first(rec, "status", "response_status")),
        path=rec.get("endpoint") or get_path(rec, "request.url"),
        metadata={"trace_id": rec.get("trace_id"), "metadata": rec.get("metadata")},
        schema="portkey",
    )


def _normalise_kong(rec: dict[str, Any]) -> Event:
    proxy = _mapping(rec.get("ai")).get("proxy") or get_path(rec, "ai.proxy") or {}
    meta = proxy.get("meta", {}) if isinstance(proxy, dict) else {}
    usage = proxy.get("usage", {}) if isinstance(proxy, dict) else {}
    consumer = get_path(rec, "consumer.username", "consumer.id", "authenticated_entity.consumer_id")
    client_ip = get_path(rec, "client_ip")
    headers = get_path(rec, "request.headers") or {}
    return Event(
        caller=f"kong:{consumer or client_ip or 'anonymous'}",
        caller_kind="principal" if consumer else "ip",
        caller_label=str(consumer or client_ip or "anonymous"),
        timestamp=_timestamp(rec, "started_at", "timestamp"),
        model=meta.get("response_model") or meta.get("request_model") or get_path(rec, "ai.proxy.meta.request_model"),
        provider=meta.get("provider_name"),
        host=host_of(get_path(rec, "upstream_uri", "request.url")),
        user_agent=headers.get("user-agent") if isinstance(headers, dict) else None,
        ip=client_ip,
        tools=None,
        tokens_in=_i(usage.get("prompt_tokens")),
        tokens_out=_i(usage.get("completion_tokens")),
        cost=_f(usage.get("cost")),
        status=_label(get_path(rec, "response.status")),
        path=get_path(rec, "request.uri", "route.paths.0"),
        metadata={"plugin": meta.get("plugin_id"), "route": get_path(rec, "route.name"), "service": get_path(rec, "service.name")},
        schema="kong",
    )


def _normalise_cloudflare(rec: dict[str, Any]) -> Event:
    meta = rec.get("metadata") or {}
    user = meta.get("user") or meta.get("user_id") or meta.get("userId") if isinstance(meta, dict) else None
    caller = rec.get("api_key_id") or user or rec.get("gateway_id") or "unknown"
    return Event(
        caller=f"cloudflare:{caller}",
        caller_kind="api-key" if rec.get("api_key_id") else ("user" if user else "service"),
        caller_label=str(caller),
        timestamp=_timestamp(rec, "created_at", "timestamp"),
        model=rec.get("model"),
        provider=rec.get("provider"),
        user_agent=get_path(rec, "request_head.headers.user-agent", "request_headers.user-agent"),
        tools=_has_tools(_first(rec, "request_head", "request_body")),
        tool_calls=_has_tool_calls(_first(rec, "response_head", "response_body")),
        tokens_in=_i(rec.get("tokens_in")),
        tokens_out=_i(rec.get("tokens_out")),
        cost=_f(rec.get("cost")),
        status=_label(_first(rec, "status_code", "success")),
        path=_first(rec, "path", "request_type"),
        metadata={"gateway_id": rec.get("gateway_id"), "cached": rec.get("cached"), "metadata": meta},
        schema="cloudflare",
    )


def _normalise_helicone(rec: dict[str, Any]) -> Event:
    props = _first(rec, "request_properties", "properties") or {}
    user = _first(rec, "request_user_id", "user_id") or props.get("Helicone-User-Id")
    app = props.get("Helicone-Property-App")
    return Event(
        caller=f"helicone:{user or app or 'unknown'}",
        caller_kind="user" if user else "principal",
        caller_label=str(user or app or "unknown"),
        timestamp=_timestamp(rec, "request_created_at", "created_at"),
        model=_first(rec, "request_model", "response_model", "model"),
        provider=rec.get("provider"),
        host=host_of(_first(rec, "request_path", "target_url")),
        tools=_has_tools(rec.get("request_body")),
        tool_calls=_has_tool_calls(rec.get("response_body")),
        tokens_in=_i(rec.get("prompt_tokens")),
        tokens_out=_i(rec.get("completion_tokens")),
        cost=_f(_first(rec, "cost", "costUSD")),
        status=_label(rec.get("response_status")),
        path=rec.get("request_path"),
        metadata={"properties": props},
        schema="helicone",
    )


def _langfuse_tools(value: Any) -> bool | None:
    """Langfuse stores the prompt as an object, a serialised object or a message list."""
    if isinstance(value, (dict, str)):
        return _has_tools(value)
    if isinstance(value, list) and any(isinstance(m, dict) and (m.get("tool_calls") or m.get("role") == "tool") for m in value):
        return True
    return None


def _normalise_langfuse(rec: dict[str, Any]) -> Event:
    user = _first(rec, "userId", "user_id") or get_path(rec, "trace.userId")
    name = rec.get("name") or get_path(rec, "trace.name") or rec.get("traceName")
    caller = user or name or _first(rec, "projectId", "project_id") or "unknown"
    return Event(
        caller=f"langfuse:{caller}",
        caller_kind="user" if user else "service",
        caller_label=str(caller),
        timestamp=_timestamp(rec, "startTime", "start_time", "timestamp", "createdAt"),
        model=rec.get("model") or get_path(rec, "modelParameters.model"),
        provider=None,
        tools=_langfuse_tools(rec.get("input")),
        tool_calls=_has_tool_calls(rec.get("output")),
        tokens_in=_i(get_path(rec, "usage.input", "usageDetails.input", "usage.promptTokens", "promptTokens")),
        tokens_out=_i(get_path(rec, "usage.output", "usageDetails.output", "usage.completionTokens", "completionTokens")),
        cost=_f(get_path(rec, "calculatedTotalCost", "totalCost", "costDetails.total")),
        status=rec.get("level"),
        path=name,
        metadata={"trace": _first(rec, "traceId", "trace_id"), "tags": rec.get("tags"), "session": rec.get("sessionId")},
        schema="langfuse",
    )


def _normalise_bedrock(rec: dict[str, Any]) -> Event:
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
        schema="bedrock",
    )


def _azure_properties(rec: dict[str, Any]) -> dict[str, Any]:
    """The diagnostic ``properties`` object, which some exports serialise as a string."""
    props = rec.get("properties") or {}
    if isinstance(props, str):
        props = json.loads(props)
    if not isinstance(props, dict):
        raise ConnectorError("gateway.logs: Azure properties must be an object")
    return props


def _azure_identity(rec: dict[str, Any], props: dict[str, Any]) -> tuple[Any, Any, Any]:
    """Object id, user principal name and tenant from the caller identity claims."""
    ident = rec.get("identity") or props.get("identity") or {}
    if not isinstance(ident, dict):
        return None, None, None
    oid = get_path(ident, "claims.oid", "authorization.objectId", "claims.appid", "oid")
    upn = get_path(ident, "claims.upn", "claims.name", "claims.email", "claims.appid")
    return oid, upn, get_path(ident, "claims.tid")


def _normalise_azure_openai(rec: dict[str, Any]) -> Event:
    props = _azure_properties(rec)
    oid, upn, tenant = _azure_identity(rec, props)
    caller_ip = _first(rec, "callerIpAddress", "CallerIPAddress")
    caller = oid or upn or caller_ip or "unknown"
    resource_id = _first(rec, "resourceId", "ResourceId")
    return Event(
        caller=f"azure:{caller}",
        caller_kind="principal" if oid or upn else "ip",
        caller_label=str(upn or oid or caller),
        timestamp=_timestamp(rec, "time", "TimeGenerated", "timestamp"),
        model=props.get("modelName") or props.get("modelDeploymentName") or props.get("deploymentName") or props.get("model"),
        provider="azure-openai",
        host=host_of(resource_id),
        user_agent=props.get("userAgent") or get_path(rec, "properties.headers.user-agent"),
        ip=caller_ip,
        user=_text(upn),
        tools=_has_tools(props.get("requestBody") or props.get("request")),
        tool_calls=_has_tool_calls(props.get("responseBody") or props.get("response")),
        tokens_in=_i(props.get("promptTokens") or get_path(props, "usage.prompt_tokens")),
        tokens_out=_i(props.get("completionTokens") or get_path(props, "usage.completion_tokens")),
        status=_label(_first(rec, "resultSignature", "ResultSignature") or props.get("statusCode")),
        path=_first(rec, "operationName", "OperationName") or props.get("apiName"),
        metadata={"resource_id": resource_id, "deployment": props.get("modelDeploymentName"), "api_version": props.get("apiVersion"), "object_id": oid, "tenant": tenant},
        schema="azure-openai",
    )


_VERTEX_MODEL = re.compile(r"(publishers/[^/]+/models/[^/:\s]+|endpoints/[^/:\s]+|reasoningEngines/[^/:\s]+|models/[^/:\s]+)")


def _normalise_vertex(rec: dict[str, Any]) -> Event:
    pp = rec.get("protoPayload") or {}
    principal = get_path(pp, "authenticationInfo.principalEmail") or get_path(pp, "authenticationInfo.principalSubject")
    resource = pp.get("resourceName", "")
    match = _VERTEX_MODEL.search(str(resource))
    return Event(
        caller=f"gcp:{principal or 'unknown'}",
        caller_kind="principal",
        caller_label=str(principal or "unknown"),
        timestamp=_timestamp(rec, "timestamp", "receiveTimestamp"),
        model=match.group(1) if match else None,
        provider="google-vertex-ai",
        host=pp.get("serviceName"),
        user_agent=get_path(pp, "requestMetadata.callerSuppliedUserAgent"),
        ip=get_path(pp, "requestMetadata.callerIp"),
        tools=_has_tools(pp.get("request")),
        tool_calls=_has_tool_calls(pp.get("response")),
        status=str(get_path(pp, "status.code") or "ok"),
        path=pp.get("methodName", ""),
        metadata={"project": get_path(rec, "resource.labels.project_id"), "location": get_path(rec, "resource.labels.location"), "resource": resource, "service_account_delegation": get_path(pp, "authenticationInfo.serviceAccountDelegationInfo")},
        schema="vertex",
    )


def _usage_request_count(rec: dict[str, Any]) -> tuple[bool, int]:
    """Whether an OpenAI usage record aggregates an interval, and its request count."""
    aggregate = any(key in rec for key in ("num_model_requests", "n_requests"))
    count = rec.get("num_model_requests", rec.get("n_requests", 1))
    if aggregate:
        if isinstance(count, str) and count.isdecimal():
            count = int(count)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ConnectorError("gateway.logs: OpenAI usage request count must be a nonnegative integer")
    return aggregate, count


def _normalise_openai_usage(rec: dict[str, Any]) -> Event:
    actor = rec.get("actor") or {}
    key_id = rec.get("api_key_id") or get_path(actor, "api_key.id") or get_path(rec, "api_key.id")
    user = rec.get("user_id") or get_path(actor, "session.user.email", "api_key.user.email", "api_key.service_account.name", "session.user.id")
    sa = get_path(actor, "api_key.service_account.id", "api_key.service_account.name")
    caller = key_id or sa or user or rec.get("project_id") or "unknown"
    aggregate, count = _usage_request_count(rec)
    return Event(
        caller=f"openai:{caller}",
        caller_kind="api-key" if key_id else ("service" if sa else "user"),
        caller_label=str(sa or user or key_id or caller),
        timestamp=parse_timestamp(get_path(rec, "start_time", "effective_at", "aggregation_timestamp", "timestamp")),
        interval_end=parse_timestamp(rec.get("end_time")) if aggregate else None,
        request_count=count,
        aggregated=aggregate,
        model=_first(rec, "model", "snapshot_id"),
        provider="openai",
        host="api.openai.com",
        user=_text(user),
        team=_first(rec, "project_id", "project_name"),
        tokens_in=_i(_first(rec, "input_tokens", "n_context_tokens_total")),
        tokens_out=_i(_first(rec, "output_tokens", "n_generated_tokens_total")),
        path=_first(rec, "operation", "type", "endpoint"),
        metadata={"project": rec.get("project_id"), "num_requests": _first(rec, "num_model_requests", "n_requests"), "batch": rec.get("batch"), "service_account": sa, "event_type": rec.get("type")},
        schema="openai-usage",
    )


def _normalise_anthropic_usage(rec: dict[str, Any]) -> Event:
    caller = _first(rec, "api_key_id", "workspace_id") or "unknown"
    return Event(
        caller=f"anthropic:{caller}",
        caller_kind="api-key" if rec.get("api_key_id") else "principal",
        caller_label=str(caller),
        timestamp=_timestamp(rec, "starting_at", "timestamp"),
        model=rec.get("model"),
        provider="anthropic",
        host="api.anthropic.com",
        team=rec.get("workspace_id"),
        tokens_in=_i(rec.get("uncached_input_tokens")) + _i(get_path(rec, "cache_read_input_tokens")),
        tokens_out=_i(rec.get("output_tokens")),
        path=_first(rec, "service_tier", "context_window"),
        metadata={"workspace": rec.get("workspace_id"), "service_tier": rec.get("service_tier")},
        schema="anthropic-usage",
    )


def _access_log_path(rec: dict[str, Any]) -> Any:
    """The request path, taken from the request line when no path field is present."""
    path = get_path(rec, "request_uri", "requestUri", "uri", "path", "http.url", "cs-uri-stem", "request_path", "url")
    req = rec.get("request")
    if isinstance(req, str) and " " in req and not path:
        parts = req.split()
        path = parts[1] if len(parts) > 1 else req
    return path


def _normalise_access_log(rec: dict[str, Any]) -> Event:
    ua = get_path(rec, "http_user_agent", "user_agent", "userAgent", "http.user_agent", "request.headers.user-agent", "cs(User-Agent)", "cs-user-agent", "useragent")
    ip = get_path(rec, "remote_addr", "client_ip", "clientIp", "c-ip", "x_forwarded_for", "http.client_ip", "source_ip", "src_ip", "client.ip")
    user = get_path(rec, "remote_user", "user", "username", "auth_user", "principal", "sub", "x_user", "http.user")
    api_key = get_path(rec, "api_key", "x_api_key", "apikey", "authorization_hash", "consumer", "client_id")
    kind, caller = _identity(("api-key", api_key), ("user", user), ("user-agent", ua), ("ip", ip))
    caller = caller or "unknown"
    return Event(
        caller=f"access:{caller}",
        caller_kind=kind,
        caller_label=str(caller)[:120],
        timestamp=parse_timestamp(get_path(rec, "time", "timestamp", "@timestamp", "time_local", "time_iso8601", "start_time", "date", "ts", "datetime")),
        model=get_path(rec, "model", "x_model", "request_model", "llm_model"),
        host=get_path(rec, "host", "http_host", "server_name", "upstream_host", "authority", "http.host", "cs-host", "x-forwarded-host", "domain"),
        user_agent=ua,
        ip=_text(ip),
        user=_text(user),
        status=_label(get_path(rec, "status", "status_code", "response_code", "sc-status", "http.status_code")),
        path=_access_log_path(rec),
        metadata={"method": get_path(rec, "request_method", "method", "cs-method", "http.method"), "bytes": get_path(rec, "body_bytes_sent", "bytes", "sc-bytes")},
        schema="access-log",
    )


_GENERIC_TOOL_KEYS = ("tools", "functions", "function_declarations", "tool_choice", "toolConfig", "tool_config")


def _generic_tools(rec: dict[str, Any]) -> bool | None:
    """Tool definitions from the request body, the record itself, or a summary flag."""
    req = _first(rec, "request", "request_body", "input", "body", "messages")
    if req is not None:
        return _has_tools(req)
    if any(key in rec for key in _GENERIC_TOOL_KEYS):
        return _has_tools(rec)
    return _b(get_path(rec, "has_tools", "tool_count", "function_call"))


def _generic_tool_calls(rec: dict[str, Any]) -> bool | None:
    """Tool invocations from the response body, or a summary flag."""
    resp = _first(rec, "response", "response_body", "output", "completion")
    if resp is not None:
        return _has_tool_calls(resp)
    return _b(get_path(rec, "tool_calls", "has_tool_calls"))


def _normalise_generic(rec: dict[str, Any]) -> Event | None:
    key = get_path(rec, "api_key", "apiKey", "api_key_id", "key", "key_id", "key_alias", "virtual_key", "token_id", "client_id", "clientId")
    principal = get_path(rec, "principal", "principal_id", "identity", "identity.arn", "caller", "service", "service_name", "app", "application", "app_name", "source", "team", "team_id", "org", "project")
    user = get_path(rec, "user", "user_id", "userId", "username", "email", "end_user", "sub", "actor")
    ua = get_path(rec, "user_agent", "userAgent", "http_user_agent", "headers.user-agent", "request.headers.user-agent", "metadata.user_agent")
    ip = get_path(rec, "ip", "client_ip", "source_ip", "remote_addr", "callerIp")
    kind, who = _identity(("api-key", key), ("principal", principal), ("user", user), ("user-agent", ua), ("ip", ip))
    if who is None:
        return None
    return Event(
        caller=f"{kind}:{who}",
        caller_kind=kind,
        caller_label=str(who)[:120],
        timestamp=parse_timestamp(get_path(rec, "timestamp", "time", "@timestamp", "ts", "created_at", "createdAt", "start_time", "startTime", "date", "datetime", "event_time")),
        model=get_path(rec, "model", "model_id", "modelId", "model_name", "deployment", "engine", "llm", "response.model", "request.model"),
        provider=get_path(rec, "provider", "llm_provider", "custom_llm_provider", "vendor", "platform"),
        host=host_of(get_path(rec, "host", "url", "endpoint", "api_base", "base_url", "upstream")),
        user_agent=ua,
        ip=_text(ip),
        user=_text(user),
        team=get_path(rec, "team", "team_id", "org", "project", "workspace"),
        tools=_generic_tools(rec),
        tool_calls=_generic_tool_calls(rec),
        streaming=_b(get_path(rec, "stream", "streaming")),
        tokens_in=_i(get_path(rec, "prompt_tokens", "input_tokens", "tokens_in", "usage.prompt_tokens", "usage.input_tokens", "promptTokens")),
        tokens_out=_i(get_path(rec, "completion_tokens", "output_tokens", "tokens_out", "usage.completion_tokens", "usage.output_tokens", "completionTokens")),
        cost=_f(get_path(rec, "cost", "spend", "total_cost", "cost_usd")),
        status=_label(get_path(rec, "status", "status_code", "http_status")),
        path=get_path(rec, "path", "endpoint", "operation", "call_type", "route", "method_name"),
        metadata={},
        schema="generic",
    )


# Schema id to normaliser. Detection and the ``format`` option use the same ids.
NORMALISERS: dict[str, Normaliser] = {
    "litellm": _normalise_litellm,
    "portkey": _normalise_portkey,
    "kong": _normalise_kong,
    "cloudflare": _normalise_cloudflare,
    "helicone": _normalise_helicone,
    "langfuse": _normalise_langfuse,
    "bedrock": _normalise_bedrock,
    "azure-openai": _normalise_azure_openai,
    "vertex": _normalise_vertex,
    "openai-usage": _normalise_openai_usage,
    "anthropic-usage": _normalise_anthropic_usage,
    "access-log": _normalise_access_log,
    "generic": _normalise_generic,
}


def _normalise(rec: dict[str, Any], schema: str) -> Event | None:
    """Build an Event from a raw record; an unknown schema id uses the generic normaliser."""
    return NORMALISERS.get(schema, _normalise_generic)(rec)
