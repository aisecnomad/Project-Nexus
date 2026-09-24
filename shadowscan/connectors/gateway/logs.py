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
import hmac
import json
import math
import re
import secrets
from collections import Counter, OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.base import (
    _MAX_OFFLINE_LINE_BYTES,
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    _NoDump,
    _positive_limit,
)
from shadowscan.connectors.common import apply_matches, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.redaction import REDACTED, credential_id, sanitize
from shadowscan.utils.text import get_path, host_of, parse_timestamp, to_iso

_MAX_CACHED_USER_AGENTS = 256
_MAX_CACHED_USER_AGENT_CHARS = 1024
_OPAQUE_SCOPE_PREFIX = "scope:hmac-sha256:"
_LEGACY_SCOPE_PREFIX = "scope:sha256:"
_PUBLIC_CREDENTIAL_ID = re.compile(r"credential:sha256:[0-9a-f]{64}\Z")

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
    scope_redacted: bool = False
    caller_redacted: bool = False
    binding_caller: str | None = field(default=None, repr=False)  # private exact-match key; never exported
    environment: str | None = None
    runtime_frameworks: list[str] = field(default_factory=list)
    code_resources: list[str] = field(default_factory=list)
    identity_assurance: str = "unverified"


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
        choice = obj.get("tool_choice")
        if choice == "none" or isinstance(choice, dict) and choice.get("type") == "none":
            return False
        for wrapper in ("body", "request", "payload", "json"):
            inner = obj.get(wrapper)
            if isinstance(inner, (dict, str)) and not any(k in obj for k in ("tools", "functions", "messages", "input")):
                return _has_tools(inner)
        for key in ("tools", "functions", "function_declarations"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip().startswith(("[", "{")):
                try:
                    v = json.loads(v)
                except json.JSONDecodeError:
                    pass
            if v not in (None, [], {}, ""):
                return True
        for key in ("toolConfig", "tool_config"):
            if isinstance(obj.get(key), (dict, str)) and _has_tools(obj[key]):
                return True
        # A choice of "none" (or "auto" without definitions) does not
        # establish that a tool was available or invoked.
        if isinstance(choice, dict) and choice.get("type") not in {"none", "auto", None}:
            return True
        msgs = obj.get("messages") or obj.get("input") or []
        if isinstance(msgs, list):
            for m in msgs:
                if isinstance(m, dict) and (m.get("tool_calls") or m.get("role") in {"tool", "function"} or m.get("type") in {"function_call", "function_call_output", "tool_use", "tool_result"}):
                    return True
        return False
    if isinstance(obj, list):
        return any(
            isinstance(item, dict) and (
                bool(item.get("tool_calls")) or item.get("role") in {"tool", "function"}
                or item.get("type") in {"function_call", "function_call_output", "tool_use", "tool_result"}
            ) or _has_tools(item) is True
            for item in obj
        )
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
    finish_marker = False
    explicit_empty = False
    while pending:
        item = pending.pop()
        if isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, dict):
            calls = item.get("tool_calls")
            if isinstance(calls, str) and calls.strip().startswith(("[", "{")):
                try:
                    calls = json.loads(calls)
                except json.JSONDecodeError:
                    calls = None
            if isinstance(calls, list) and any(isinstance(call, dict) and call for call in calls):
                return True
            if "tool_calls" in item and calls in (None, [], {}, "", False):
                explicit_empty = True
            for key in ("function_call", "functionCall", "tool_use"):
                value = item.get(key)
                if isinstance(value, str) and value.strip().startswith(("[", "{")):
                    try:
                        value = json.loads(value)
                    except json.JSONDecodeError:
                        value = None
                if isinstance(value, dict) and value:
                    return True
                if key in item and value in (None, [], {}, "", False):
                    explicit_empty = True
            if item.get("type") in {"tool_use", "function_call"}:
                return True
            if item.get("stop_reason") == "tool_use" or item.get("finish_reason") in {"tool_calls", "function_call"}:
                finish_marker = True
            pending.extend(value for value in item.values() if isinstance(value, (dict, list)))
    return finish_marker and not explicit_empty


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
    return normalise_with_record(rec, schema)[0]


def _runtime_labels(rec: dict[str, Any], metadata: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    """Extract known context fields before redaction can replace source keys."""
    aliases = {
        "tenant": ("tenant_id", "tenant", "organization_id", "org_id", "metadata.tenant_id", "metadata.tenant", "identity.claims.tid", "properties.identity.claims.tid"),
        "account": ("account_id", "accountId", "account", "subscription_id", "subscriptionId", "metadata.account_id", "metadata.account"),
        "project": ("project_id", "projectId", "project", "metadata.project_id", "resource.labels.project_id"),
        "workspace": ("workspace_id", "workspace", "metadata.workspace_id"),
    }
    scope = {}
    for key, paths in aliases.items():
        value = get_path(rec, *paths)
        if value is None:
            value = metadata.get(key)
        if isinstance(value, (str, int)) and str(value):
            scope[key] = str(value)
    environment = get_path(rec, "environment", "deployment_environment", "metadata.environment", "metadata.deployment_environment")
    return scope, environment if isinstance(environment, str) and environment else None


def _restore_scope(
    scope: dict[str, str], clean_values: Iterable[tuple[str]], scope_key: bytes,
) -> tuple[dict[str, str], bool]:
    """Keep redacted scope identities distinct without disclosing their labels.

    The random key belongs to this connector instance, never to a report. An
    unkeyed hash would disclose a short scope by offline dictionary search.
    Both current and legacy prefixes are reserved so raw labels cannot
    impersonate an opaque label. credential_id() is unsuitable here: it is
    idempotent and its public SHA-256 fingerprint is enumerable.
    """
    result = {}
    redacted = False
    for (key, original), (clean,) in zip(scope.items(), clean_values, strict=True):
        changed = clean != original or original.startswith((_OPAQUE_SCOPE_PREFIX, _LEGACY_SCOPE_PREFIX))
        if changed:
            identity = json.dumps(["shadowscan.gateway.scope.v1", key, original], separators=(",", ":"))
            result[key] = _OPAQUE_SCOPE_PREFIX + hmac.digest(scope_key, identity.encode(), "sha256").hex()
        else:
            result[key] = clean
        redacted = redacted or changed
    return result, redacted


def _withhold_public_credential_id(value: Any, identifier: str) -> Any:
    """Remove a supplied public key fingerprint from sanitized gateway data.

    The shared sanitizer treats existing fingerprints as idempotent, but an
    imported fingerprint of a short key is enumerable. Input structure and
    string work were already bounded by sanitize() before this linear pass.
    """
    if isinstance(value, str):
        return value.replace(identifier, REDACTED)
    if isinstance(value, dict):
        # A credential-bearing metadata key must not survive as a dictionary
        # key or collide with a different key after replacement.
        return {key: _withhold_public_credential_id(child, identifier)
                for key, child in value.items() if not isinstance(key, str) or identifier not in key}
    if isinstance(value, list):
        return [_withhold_public_credential_id(child, identifier) for child in value]
    if isinstance(value, tuple):
        return tuple(_withhold_public_credential_id(child, identifier) for child in value)
    return value


def normalise_with_record(
    rec: dict[str, Any], schema: str, *, scope_key: bytes | None = None,
) -> tuple[Event | None, dict[str, Any] | None]:
    """Normalize and also return the sanitized source record.

    Sanitizing a record is the dominant per-record cost; callers that need the
    clean record for scope attribution must not sanitize it a second time.
    """
    ev = _normalise(rec, schema)
    if ev is None:
        return None, None
    scope_key = scope_key if scope_key is not None else secrets.token_bytes(32)
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
    opaque_id = None
    raw_key = None
    if ev.caller_kind == "api-key":
        namespace, _, raw_key = ev.caller.partition(":")
        ev.binding_caller = f"{namespace}:{credential_id(raw_key)}"
        # No publicly enumerable digest of a caller-supplied API key or key ID
        # may appear in a report. Even provider key IDs can be guessable.
        material = json.dumps(["shadowscan.gateway.credential.v1", namespace, raw_key], separators=(",", ":"))
        opaque_id = "credential:hmac-sha256:" + hmac.digest(scope_key, material.encode(), "sha256").hex()
        ev.caller = f"{namespace}:{opaque_id}"
        ev.caller_redacted = True
        if not ev.caller_label or raw_key in ev.caller_label or ev.caller_label in raw_key:
            ev.caller_label = opaque_id
        if schema == "litellm" and not get_path(rec, "api_key_alias", "key_alias", "metadata.user_api_key_alias"):
            ev.caller_label = opaque_id
    # Include original credential-bearing fields so duplicated opaque secrets in
    # unrelated metadata are scrubbed before samples are truncated. Preserve
    # trusted Event field names: even a one-character credential can match a
    # schema key, and sanitization of mapping keys must not corrupt the Event.
    raw_scope, ev.environment = _runtime_labels(rec, ev.metadata)
    fields = asdict(ev)
    # Only the reportable Event fields enter sanitization. The legacy exact
    # binding fingerprint remains private and is never returned in a report.
    fields.pop("binding_caller")
    # Singleton wrappers prevent unrelated scalar fields from being interpreted
    # as adjacent command-line arguments (e.g. a label '--token', timestamp).
    # IDs such as api_key_id are not universally secret to other connectors.
    # Inside a gateway export, they can be short credentials or share bytes
    # with aliases, owners, metadata, and scope labels. Register the raw value
    # locally before sanitizing all reportable Event fields and the record.
    clean_record, clean_fields, clean_scope, _ = sanitize((
        rec, [(value,) for value in fields.values()], [(value,) for value in raw_scope.values()],
        {"api_key": raw_key} if raw_key is not None else {},
    ))
    if raw_key is not None and _PUBLIC_CREDENTIAL_ID.fullmatch(raw_key):
        clean_record, clean_fields, clean_scope = _withhold_public_credential_id(
            (clean_record, clean_fields, clean_scope), raw_key,
        )
    cleaned = dict(zip(fields, (value for (value,) in clean_fields), strict=True))
    cleaned["scope"], cleaned["scope_redacted"] = _restore_scope(
        raw_scope, clean_scope, scope_key,
    )
    cleaned["caller_kind"] = ev.caller_kind  # normalized enum, not a source field
    cleaned["schema"] = ev.schema  # detected/validated provider schema
    if cleaned["caller"] != ev.caller:
        # Preserve separation if sanitization changed an unrelated identity,
        # without exposing its short credential to a public hash dictionary.
        if opaque_id:
            # A short key may occur by chance in an HMAC's hex digits. The
            # generated identity is safe despite that substring overlap.
            cleaned["caller"] = ev.caller
        else:
            material = json.dumps(["shadowscan.gateway.caller.v1", ev.caller], separators=(",", ":"))
            cleaned["caller"] = f"{ev.caller_kind}:caller:hmac-sha256:{hmac.digest(scope_key, material.encode(), 'sha256').hex()}"
            cleaned["caller_redacted"] = True
    if opaque_id and ev.caller_label == opaque_id:
        cleaned["caller_label"] = opaque_id
    cleaned["binding_caller"] = ev.binding_caller
    return Event(**cleaned), clean_record


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
            caller_label=alias or str(key or "anonymous"),
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
        caller = rec.get("api_key_id") or user or rec.get("gateway_id") or "unknown"
        return Event(
            caller=f"cloudflare:{caller}",
            caller_kind="api-key" if rec.get("api_key_id") else ("user" if user else "service"),
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
    if req is not None:
        has_tools = _has_tools(req)
    elif any(key in rec for key in ("tools", "functions", "function_declarations", "tool_choice", "toolConfig", "tool_config")):
        has_tools = _has_tools(rec)
    else:
        has_tools = _b(get_path(rec, "has_tools", "tool_count", "function_call"))
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
        tools=has_tools,
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

# These stdlib patterns run outside the signature engine's regex timeouts, so
# they must be linear: possessive tokens (Python 3.11+) never backtrack into a
# long unterminated request or a bare token blob to retry a failed match.
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^\s"]++)[^"]*" (?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?(?: "(?P<extra>[^"]*)")?'
)
_LOGFMT_PAIR = re.compile(r'(?<![\w.-])(\w[\w.-]*+)=("[^"]*"|\S+)')
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
        kv = dict(_LOGFMT_PAIR.findall(line))
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
    aggregate_records: int = 0
    usage_intervals: list[dict[str, Any]] = field(default_factory=list)
    usage_intervals_dropped: int = 0
    usage_interval_requests_dropped: int = 0
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
    scope_redacted: bool = False
    observations: dict[str, dict[str, Any]] = field(default_factory=dict)
    observations_dropped: int = 0
    distribution_events_dropped: Counter = field(default_factory=Counter)


# Per-caller distributions keep this many distinct keys. Counts for omitted
# labels are tracked separately so no synthetic label can become a model,
# provider, or owner. Memory remains bounded as record cardinality increases.
_MAX_DISTINCT_KEYS = 2000
_MAX_INVALID_LINE_ERRORS = 20
_MAX_DISTINCT_CALLERS = 10_000
_MAX_USAGE_INTERVALS = 2_000
_MAX_TOTAL_USAGE_INTERVALS = 20_000
_MAX_TOTAL_DETAIL_KEYS = 50_000


@dataclass(slots=True)
class _DetailBudget:
    """One shared budget for retained distribution and observation keys."""

    used: int = 0
    observations_omitted: int = 0
    observation_requests_omitted: int = 0


def _count(counter: Counter, key: str, amount: int, dropped: Counter, dimension: str,
           budget: _DetailBudget | None = None) -> None:
    """Bound retained labels, counting lost requests without inventing a label."""
    if key not in counter:
        if len(counter) >= _MAX_DISTINCT_KEYS or (budget is not None and budget.used >= _MAX_TOTAL_DETAIL_KEYS):
            # Count requests, never distinct attacker-provided labels.
            dropped[dimension] += amount
            return
        if budget is not None:
            budget.used += 1
    counter[key] += amount


def _json_lines_fallback(lines: list[str]) -> bool:
    """Reject obvious pretty-printed documents; retain later valid JSONL rows."""
    first = next((line.strip() for line in lines if line.strip()), "")
    return bool(first) and first != "{" and not first.startswith("[")


class GatewayLogConnector(BaseConnector, _NoDump):
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
        "max_input_bytes": "maximum expanded bytes read across offline files (default 256 MiB)",
        "max_input_file_bytes": "maximum expanded bytes read from one offline file (default 32 MiB)",
        "max_input_files": "maximum offline files in a directory input (default 10,000)",
        "correlation_bindings": "explicit [{code_resource, caller, scope}] mappings to workload identities; scope must exactly match log tenant/account/project/workspace fields ({} for unscoped exports)",
    }
    offline_formats: ClassVar[str] = "JSONL / JSON / CSV / text access logs"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        # Engine.run shares one key across its gateway jobs; direct connector
        # use gets an isolated key. Never place this key in config or reports.
        self._scope_key = ctx.gateway_identity_key or secrets.token_bytes(32)
        self.format = ctx.get("format")
        self.min_events = int(ctx.get("min_events", 1))
        self.llm_hosts_only = bool(ctx.get("llm_hosts_only", True))
        self.max_records = _positive_limit(ctx.get("max_records", 5_000_000), "max_records")
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
        # Any source configuration may contain guessable labels or bindings;
        # never disclose an unkeyed digest even if rows are filtered out.
        self.source_id = hmac.digest(self._scope_key, identity.encode(), "sha256").hex()

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

    @staticmethod
    def _envelope_context(rec: dict[str, Any]) -> dict[str, Any]:
        """Keep source timestamps and scope when an export wraps an event."""
        return {
            key: rec[key] for key in (
                "timestamp", "receiveTimestamp", "resource", "labels",
                "project_id", "logName",
            ) if key in rec
        }

    def _expand_record(self, rec: dict[str, Any], depth: int = 0) -> Iterator[dict[str, Any]]:
        if depth >= 16:
            self.ctx.warn("gateway.logs: export wrapper nesting limit exceeded")
            return
        if rec.get("object") == "bucket" or (self.format == "openai-usage" and "results" in rec):
            # Usage results are aggregate intervals, not individual transactions.
            results = rec.get("results")
            first, last = parse_timestamp(rec.get("start_time")), parse_timestamp(rec.get("end_time"))
            if not isinstance(results, list) or first is None or last is None or last <= first:
                self.ctx.warn("gateway.logs: malformed OpenAI usage bucket (results and a valid interval are required)")
                return
            for result in results:
                if not isinstance(result, dict) or not any(key in result for key in ("num_model_requests", "n_requests")):
                    self.ctx.warn("gateway.logs: malformed OpenAI usage result (request count is required)")
                    continue
                if "object" in result and not str(result["object"]).startswith("organization.usage."):
                    self.ctx.warn("gateway.logs: unsupported OpenAI usage result type")
                    continue
                yield {
                    **result,
                    "object": result.get("object") or "organization.usage.completions.result",
                    "start_time": rec["start_time"], "end_time": rec["end_time"],
                }
            return
        if "logEvents" in rec:
            events = rec["logEvents"]
            if not isinstance(events, list):
                self.ctx.warn("gateway.logs: logEvents must be an array")
                return
            for event in events:
                if isinstance(event, dict):
                    yield from self._expand_record({**self._envelope_context(rec), **event}, depth + 1)
                else:
                    self.ctx.warn("gateway.logs: malformed CloudWatch log event")
            return
        if "jsonPayload" in rec and "protoPayload" not in rec:
            payload = rec["jsonPayload"]
            if not isinstance(payload, dict):
                self.ctx.warn("gateway.logs: jsonPayload must be an object")
                return
            yield from self._expand_record({**self._envelope_context(rec), **payload}, depth + 1)
            return
        for key in ("message", "textPayload"):
            body = rec.get(key)
            if body is None:
                continue
            # Some gateways have a model field and a descriptive message; keep
            # those events intact rather than treating the description as a log.
            if key == "message" and any(k in rec for k in ("model", "provider", "api_key", "service")):
                break
            if isinstance(body, dict):
                yield from self._expand_record({**self._envelope_context(rec), **body}, depth + 1)
                return
            if isinstance(body, str):
                parsed = self._parse_line(body, key)
                if parsed is not None:
                    yield from self._expand_record({**self._envelope_context(rec), **parsed}, depth + 1)
                return
            self.ctx.warn(f"gateway.logs: {key} must be an object or string")
            return
        yield rec

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        suffixes = {".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".gz"}
        budget = self._offline_budget()
        for source in self._iter_offline_files(path, budget, suffixes):
            suffix = source.suffix.lower()
            if suffix == ".csv":
                for rec in self._load_offline_file(source, budget):
                    yield from self._expand_record(rec)
                continue
            if suffix in {".jsonl", ".ndjson"}:
                saw_record = False
                for number, line in enumerate(self._iter_bounded_lines(source, budget), 1):
                    if not line.strip():
                        continue
                    saw_record = True
                    try:
                        data = json.loads(line)
                    except (json.JSONDecodeError, RecursionError, ValueError):
                        self.ctx.error(f"gateway.logs: invalid JSON record at line {number}")
                        continue
                    if not isinstance(data, dict):
                        self.ctx.error(f"gateway.logs: line {number}: JSONL records must be objects")
                        continue
                    for rec in self._gateway_records(data):
                        yield from self._expand_record(rec)
                if not saw_record:
                    self.ctx.error("gateway.logs: empty offline export; use [] for an empty inventory")
                continue
            if suffix == ".json":
                text = self._read_offline_text(source, budget)
                if text is None:
                    continue
                if not text.strip():
                    self.ctx.error("gateway.logs: empty offline export; use [] for an empty inventory")
                    continue
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    # A .json export may contain one JSON object per line. A
                    # corrupted pretty-printed document is not one: reporting
                    # every line of it individually would flood the report.
                    lines = text.splitlines()
                    if _json_lines_fallback(lines):
                        yield from self._json_gateway_lines(lines)
                    else:
                        self.ctx.error("gateway.logs: invalid JSON export")
                except (RecursionError, ValueError):
                    self.ctx.error("gateway.logs: invalid JSON export")
                else:
                    for rec in self._gateway_records(data):
                        yield from self._expand_record(rec)
                continue
            saw_content = False
            for number, line in enumerate(
                self._iter_bounded_lines(source, budget, compressed=suffix == ".gz"), 1
            ):
                saw_content = saw_content or bool(line.strip())
                parsed = self._parse_line(line, f"line {number}")
                if parsed is not None:
                    yield from self._expand_record(parsed)
            if not saw_content:
                self.ctx.warn("gateway.logs: empty text export; use [] for an empty JSON export")

    def _gateway_records(self, data: Any) -> Iterator[dict[str, Any]]:
        # CloudWatch and usage buckets carry context on the enclosing object.
        # The generic offline list unwrapping would discard its scope or interval.
        if isinstance(data, dict) and (
            "logEvents" in data or data.get("object") == "bucket"
            or (self.format == "openai-usage" and "results" in data)
        ):
            if not self._valid_record(data):
                self.ctx.error("gateway.logs: invalid export record")
                return
            if any(data.get(key) for key in (
                "has_more", "next_page", "nextPage", "next_page_token",
                "nextPageToken", "nextToken", "NextToken", "@odata.nextLink",
                "nextLink", "nextCursor",
            )):
                self.ctx.error("gateway.logs: offline export contains an uncollected next page")
            yield data
        else:
            yield from self._unwrap(data, lambda message: self.ctx.error(f"gateway.logs: {message}"))

    def _json_gateway_lines(self, lines: Iterable[str]) -> Iterator[dict[str, Any]]:
        invalid = 0
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > _MAX_OFFLINE_LINE_BYTES:
                self.ctx.warn(f"gateway.logs: max_input_line_bytes ({_MAX_OFFLINE_LINE_BYTES}) reached")
                return
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ValueError("JSONL records must be objects")
            except (json.JSONDecodeError, RecursionError, ValueError) as exc:
                invalid += 1
                if invalid <= _MAX_INVALID_LINE_ERRORS:
                    detail = "JSONL records must be objects" if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else "invalid JSON record"
                    self.ctx.error(f"gateway.logs: line {number}: {detail}")
                elif invalid == _MAX_INVALID_LINE_ERRORS + 1:
                    self.ctx.error("gateway.logs: further invalid records in this export are not listed individually")
                continue
            for rec in self._gateway_records(data):
                yield from self._expand_record(rec)


    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        callers: dict[str, _Caller] = {}
        # Cache successful immutable framework summaries for this analysis only.
        framework_cache: OrderedDict[str, tuple[str, ...]] = OrderedDict()
        detail_budget = _DetailBudget()
        n = 0
        skipped = 0
        omitted_caller_records = 0
        omitted_caller_requests = 0
        retained_intervals = 0
        for rec in records:
            if n >= self.max_records:
                self.ctx.warn(f"gateway.logs: max_records ({self.max_records}) reached")
                break
            n += 1
            try:
                schema = self.format or detect_schema(rec)
                ev, clean = normalise_with_record(rec, schema, scope_key=self._scope_key)
                if ev is None:
                    self.ctx.warn(f"gateway.logs: unrecognized record {n}; could not identify a caller")
                    skipped += 1
                    continue
                if ev.request_count == 0:
                    continue
                if schema in {"access-log", "generic"} and self.llm_hosts_only and not self._is_llm_traffic(ev):
                    skipped += 1
                    continue
                self._runtime_context(ev, rec, framework_cache, clean)
                identity = json.dumps([ev.caller, ev.scope], sort_keys=True)
                if identity not in callers and len(callers) >= _MAX_DISTINCT_CALLERS:
                    # The export can contain millions of distinct identities.
                    # Keep exact totals for retained callers; never attribute
                    # omitted activity to a made-up or unrelated caller.
                    omitted_caller_records += 1
                    omitted_caller_requests += ev.request_count
                    continue
                retained_intervals += self._accumulate(
                    callers, ev, identity, retained_intervals < _MAX_TOTAL_USAGE_INTERVALS,
                    detail_budget,
                )
            except (ValueError, TypeError, AttributeError, KeyError, OverflowError,
                    RecursionError, ConnectorError, MatchTimeoutError) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"gateway.logs: invalid record {n}: {type(exc).__name__}{detail}")
                continue
        self.ctx.examined(n)
        if omitted_caller_records:
            self.ctx.warn(
                f"gateway.logs: distinct caller limit ({_MAX_DISTINCT_CALLERS}) reached; "
                f"omitted {omitted_caller_records} records representing {omitted_caller_requests} requests; "
                "caller coverage incomplete"
            )
        interval_details_dropped = sum(c.usage_intervals_dropped for c in callers.values())
        if interval_details_dropped:
            self.ctx.warn(
                f"gateway.logs: usage interval detail limit (per caller {_MAX_USAGE_INTERVALS}, "
                f"total {_MAX_TOTAL_USAGE_INTERVALS}) reached for "
                f"{sum(bool(c.usage_intervals_dropped) for c in callers.values())} callers; "
                f"omitted {interval_details_dropped} interval details while retaining request totals"
            )
        distribution_requests_dropped = sum(sum(c.distribution_events_dropped.values()) for c in callers.values())
        if distribution_requests_dropped or detail_budget.observations_omitted:
            self.ctx.warn(
                f"gateway.logs: distribution limit or bounded detail budget ({_MAX_TOTAL_DETAIL_KEYS} keys total, "
                f"{_MAX_DISTINCT_KEYS} per distribution or caller observations) reached; "
                f"omitted {distribution_requests_dropped} distribution dimension-request counts; "
                f"omitted {detail_budget.observations_omitted} observation records representing "
                f"{detail_budget.observation_requests_omitted} requests; "
                "classification, attribution, and detail telemetry may be incomplete"
            )
        if skipped:
            self.log.info("gateway.logs: %d/%d records skipped (unrecognised or non-LLM)", skipped, n)
        for c in callers.values():
            if c.events < self.min_events:
                continue
            try:
                yield self._finding(c)
            except (ValueError, TypeError, AttributeError, KeyError, OverflowError,
                    RecursionError, ConnectorError, MatchTimeoutError) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"gateway.logs: caller analysis failed ({type(exc).__name__}){detail}")

    def _runtime_context(
        self,
        ev: Event,
        rec: dict[str, Any],
        framework_cache: OrderedDict[str, tuple[str, ...]],
        clean: dict[str, Any] | None = None,
    ) -> None:
        """Operator bindings identify workloads; log names alone never do.

        ``rec`` is the raw record (its credential field decides binding
        assurance); ``clean`` signals that normalization already extracted and
        sanitized context under trusted field names in one pass.
        """
        identity_assurance = self._binding_identity_assurance(ev, rec)
        if clean is None:
            # Private callers may enrich an Event without using normalise().
            raw_scope, environment = _runtime_labels(rec, ev.metadata)
            _, clean_scope, (ev.environment,) = sanitize((
                rec, [(value,) for value in raw_scope.values()], (environment,),
            ))
            ev.scope, ev.scope_redacted = _restore_scope(raw_scope, clean_scope, self._scope_key)
        if ev.scope_redacted:
            self.ctx.warn("gateway.logs: scope labels were redacted; distinct opaque scopes retained; runtime attribution incomplete")
            identity_assurance = "unverified"
        if ev.caller_redacted and not ev.binding_caller:
            identity_assurance = "unverified"
        if ev.environment:
            ev.environment = ev.environment.strip().lower()
        ua = ev.user_agent or ""
        cached = framework_cache.get(ua)
        if cached is None:
            frameworks = tuple(sorted({
                match.signature.id for match in self.index.match_user_agent(ua)
                if match.signature.category == "framework"
            }))
            if len(ua) <= _MAX_CACHED_USER_AGENT_CHARS:
                framework_cache[ua] = frameworks
                if len(framework_cache) > _MAX_CACHED_USER_AGENTS:
                    framework_cache.popitem(last=False)
        else:
            frameworks = cached
            framework_cache.move_to_end(ua)
        ev.runtime_frameworks = list(frameworks)
        ev.identity_assurance = identity_assurance
        caller_for_binding = ev.binding_caller or ev.caller
        ev.code_resources = sorted({
            binding["code_resource"] for binding in self.correlation_bindings
            if ev.identity_assurance != "unverified" and binding["caller"] == caller_for_binding and binding["scope"] == ev.scope
        })

    @staticmethod
    def _binding_identity_assurance(ev: Event, rec: dict[str, Any]) -> str:
        """Bind only a workload credential/principal, never a client hint or a shared scope.

        Generic log principal/service values are explicitly asserted by the
        operator's exact binding; their authenticity cannot be proven here.
        """
        if ev.caller_kind not in {"api-key", "principal", "service"}:
            return "unverified"
        schema = ev.schema
        candidates = {
            "litellm": get_path(rec, "api_key", "hashed_api_key", "key_hash"),
            "portkey": get_path(rec, "virtual_key", "config.virtual_key", "metadata.virtual_key", "api_key"),
            "kong": get_path(rec, "consumer.username", "consumer.id", "authenticated_entity.consumer_id"),
            "cloudflare": rec.get("api_key_id"),
            "bedrock": get_path(rec, "identity.arn"),
            "azure-openai": get_path(rec, "identity.claims.oid", "identity.authorization.objectId", "properties.identity.claims.oid", "properties.identity.authorization.objectId"),
            "vertex": get_path(rec, "protoPayload.authenticationInfo.principalEmail", "protoPayload.authenticationInfo.principalSubject"),
            "openai-usage": get_path(rec, "api_key_id", "actor.api_key.id", "api_key.id", "actor.api_key.service_account.id", "actor.api_key.service_account.name"),
            "anthropic-usage": rec.get("api_key_id"),
            "access-log": get_path(rec, "api_key", "authorization_hash", "consumer"),
            "generic": get_path(rec, "api_key", "apiKey", "api_key_id", "key", "key_id", "key_alias", "virtual_key", "token_id") if ev.caller_kind == "api-key" else get_path(rec, "principal", "principal_id", "identity.arn", "caller", "service", "service_name", "app", "application", "app_name"),
        }
        # Sentinels often appear in partial exports. A binding to one is not
        # workload specific even if it matches byte-for-byte.
        value = str(candidates.get(schema) or "").strip().lower()
        if value in {"", "anonymous", "unknown", "none", "null", "-", "gateway", "shared"}:
            return "unverified"
        return "operator-asserted" if schema in {"generic", "access-log"} else "provider-authenticated-field"

    def _is_llm_traffic(self, ev: Event) -> bool:
        if ev.path and re.search(r"(?:^|/)(?:favicon\.ico|robots\.txt|healthz?|readyz?|livez?|metrics)(?:$|[/?#])|\.(?:css|js|map|png|jpe?g|gif|ico|svg|woff2?)(?:$|[?#])", ev.path, re.I):
            return False
        text = " ".join(x for x in (ev.host, ev.path) if x)
        if ev.path and re.search(r"/v1/(?:chat/completions|completions|responses|messages|embeddings|models|assistants|threads|runs|audio|images|files|batches|realtime)|/openai/deployments/|/generateContent|:generateContent|:streamGenerateContent|/invoke(?:-with-response-stream)?|/converse|/mcp\b|/sse\b|/a2a\b|/agents?/|/predict\b|/api/(?:chat|generate|tags)\b", text):
            return True
        if ev.schema == "access-log" and ev.path:
            return False
        if ev.model:
            return True
        if ev.schema == "generic" and _provider_signature(self.index, ev.provider):
            if ev.tokens_in > 0 or ev.tokens_out > 0:
                return True
            if ev.path and re.search(r"(?:chat|completions|responses|messages|embeddings|generate|invoke|predict)", ev.path, re.I):
                return True
        # Domain-only egress logs can identify a model provider. A path such as
        # /favicon.ico on that host is not an inference transaction.
        return bool(ev.host and not ev.path and self.index.match_domain(ev.host))

    @staticmethod
    def _accumulate(
        callers: dict[str, _Caller], ev: Event, identity: str | None = None,
        retain_interval: bool = True, detail_budget: _DetailBudget | None = None,
    ) -> bool:
        if identity is None:
            identity = json.dumps([ev.caller, ev.scope], sort_keys=True)
        c = callers.get(identity)
        total_cost = (c.cost if c is not None else 0.0) + ev.cost
        if not math.isfinite(total_cost):
            # Validate before changing any caller counts, preserving atomic
            # accumulation when individually finite costs overflow in aggregate.
            raise ValueError("gateway cost total exceeds finite numeric range")
        if c is None:
            c = callers[identity] = _Caller(ev.caller, ev.caller_kind, ev.caller_label, scope=dict(ev.scope))
        c.scope_redacted = c.scope_redacted or ev.scope_redacted
        c.events += ev.request_count
        c.records += 1
        if ev.aggregated:
            c.aggregate_records += 1
        c.schemas[ev.schema] += 1
        if ev.timestamp:
            c.first = ev.timestamp if not c.first or ev.timestamp < c.first else c.first
            end = ev.interval_end or ev.timestamp
            c.last = end if not c.last or end > c.last else c.last
            if not ev.aggregated:
                c.hours[ev.timestamp.hour] += 1
                c.weekdays[ev.timestamp.weekday()] += 1
        interval_stored = False
        if ev.aggregated:
            if retain_interval and len(c.usage_intervals) < min(_MAX_USAGE_INTERVALS, _MAX_DISTINCT_KEYS):
                c.usage_intervals.append({"start": to_iso(ev.timestamp), "end": to_iso(ev.interval_end),
                                          "requests": ev.request_count, "model": ev.model})
                interval_stored = True
            else:
                c.usage_intervals_dropped += 1
                c.usage_interval_requests_dropped += ev.request_count
        if ev.model:
            _count(c.models, str(ev.model), ev.request_count, c.distribution_events_dropped, "models", detail_budget)
        if ev.provider:
            _count(c.providers, str(ev.provider), ev.request_count, c.distribution_events_dropped, "providers", detail_budget)
        if ev.host:
            _count(c.hosts, ev.host, ev.request_count, c.distribution_events_dropped, "hosts", detail_budget)
        if ev.user_agent:
            _count(c.user_agents, str(ev.user_agent)[:160], ev.request_count, c.distribution_events_dropped, "user_agents", detail_budget)
        if ev.ip:
            _count(c.ips, ev.ip, ev.request_count, c.distribution_events_dropped, "source_ips", detail_budget)
        if ev.user:
            _count(c.users, ev.user, ev.request_count, c.distribution_events_dropped, "end_users", detail_budget)
        if ev.team:
            _count(c.teams, str(ev.team), ev.request_count, c.distribution_events_dropped, "teams", detail_budget)
        if ev.path:
            # Query strings carry per-request identifiers; the operation is the path.
            _count(
                c.paths, str(ev.path).split("?", 1)[0][:120], ev.request_count,
                c.distribution_events_dropped, "operations", detail_budget,
            )
        if ev.tools is not None:
            c.tool_known += ev.request_count
            if ev.tools:
                c.tools_requests += ev.request_count
        if ev.tool_calls:
            c.tool_call_responses += ev.request_count
        c.tokens_in += ev.tokens_in
        c.tokens_out += ev.tokens_out
        c.cost = total_cost
        if ev.status and (ev.status.startswith(("4", "5")) or ev.status.lower() in {"error", "failure", "failed"}):
            c.errors += 1
        for k, v in ev.metadata.items():
            if v not in (None, "", {}, []) and k not in c.metadata_samples:
                c.metadata_samples[k] = v if isinstance(v, (str, int, float, bool)) else json.dumps(v, default=str)[:300]
        bucket = json.dumps([ev.code_resources, ev.runtime_frameworks, ev.environment, ev.identity_assurance])
        if bucket not in c.observations:
            if len(c.observations) >= _MAX_DISTINCT_KEYS or (detail_budget is not None and detail_budget.used >= _MAX_TOTAL_DETAIL_KEYS):
                # Hostile exports can vary the environment label per record.
                c.observations_dropped += ev.request_count
                if detail_budget is not None:
                    detail_budget.observations_omitted += 1
                    detail_budget.observation_requests_omitted += ev.request_count
                return interval_stored
            if detail_budget is not None:
                detail_budget.used += 1
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
            "identity_assurance": ev.identity_assurance,
            "environment_assurance": "event-label-unverified" if ev.environment else "absent",
        })
        observation["events"] += ev.request_count
        if ev.timestamp and not ev.aggregated:
            timestamp = to_iso(ev.timestamp)
            observation["timestamped_events"] += 1
            observation["first_seen"] = min(observation["first_seen"], timestamp) if observation["first_seen"] else timestamp
            observation["last_seen"] = max(observation["last_seen"], timestamp) if observation["last_seen"] else timestamp
        return interval_stored

    def _finding(self, c: _Caller, *, source_id: str | None = None) -> Finding:
        source_id = source_id or self.source_id
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
        framework_user_agent = False
        for ua, _ in c.user_agents.most_common(10):
            ua_matches = self.index.match_user_agent(ua)
            apply_matches(f, ua_matches, weight_scale=1.0)
            framework_user_agent = framework_user_agent or any(m.signature.category in {"framework", "coding-agent"} for m in ua_matches)
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

        # Non-temporal automation indicators: tool use (counted above), an
        # agent framework user agent, or an identity that no end user owns.
        unattributed = c.kind in {"api-key", "service", "principal"} and not c.users
        service_style = c.kind in {"service", "principal"}
        # temporal shape: automated callers run around the clock and on weekends
        total_ts = sum(c.hours.values())
        if total_ts >= 50:
            night = sum(v for h, v in c.hours.items() if h < 6 or h >= 22) / total_ts
            weekend = sum(v for d, v in c.weekdays.items() if d >= 5) / total_ts
            active_hours = len(c.hours)
            always_on = active_hours >= 20 or (night > 0.25 and weekend > 0.15)
            # A shared key used across time zones also produces round-the-clock
            # activity; the pattern alone must not promote a human-attributed
            # caller to an agent. The tag stays informational.
            corroborated = always_on and (bool(f.metadata.get("agent_indicators")) or framework_user_agent or unattributed or service_style)
            if always_on:
                f.add_tag("always-on")
                shape = f"Activity across {active_hours}/24 hours, {night:.0%} at night, {weekend:.0%} on weekends"
                if corroborated:
                    f.add_capability("autonomous")
                    f.add_evidence(Evidence(signal="gateway:always-on", description=f"{shape}: unattended / scheduled caller", weight=0.5))
                    f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
                else:
                    f.add_evidence(Evidence(signal="gateway:always-on", description=f"{shape}: round-the-clock activity without tool use, an agent framework or an unattended identity", weight=0.3))
            f.metadata["activity"] = {"active_hours": active_hours, "night_share": round(night, 2), "weekend_share": round(weekend, 2), "always_on": always_on, "always_on_corroborated": corroborated}
        if c.events >= 1000:
            f.add_evidence(Evidence(signal="gateway:volume", description=f"High volume: {c.events} requests", weight=0.2))
        if len(c.models) >= 4:
            f.add_evidence(Evidence(signal="gateway:multi-model", description=f"Uses {len(c.models)} different models (router / orchestrator behaviour)", weight=0.2))
        if c.kind in {"api-key", "service", "principal"} and not c.users:
            f.add_tag("no-end-user-attribution")
        if c.errors and c.errors / c.events > 0.2:
            f.add_tag("high-error-rate")

        # A truncated distribution cannot establish its most frequent owner.
        # Leave attribution unknown rather than promote the retained subset.
        if not c.distribution_events_dropped.get("end_users"):
            if c.users:
                f.owner = c.users.most_common(1)[0][0]
            elif c.teams and not c.distribution_events_dropped.get("teams"):
                f.owner = c.teams.most_common(1)[0][0]
        f.metadata.update(
            {
                "caller_kind": c.kind,
                "caller": c.label,
                "events": c.events,
                "records": c.records,
                "aggregate_records": c.aggregate_records,
                "usage_intervals": c.usage_intervals,
                "usage_intervals_dropped": c.usage_intervals_dropped,
                "usage_interval_requests_dropped": c.usage_interval_requests_dropped,
                "event_counting": "Request totals within this source; aggregate bucket counts are preserved. Distinct sources are not deduplicated against each other.",
                "models": dict(c.models.most_common(10)),
                "providers": dict(c.providers.most_common(5)),
                "hosts": dict(c.hosts.most_common(5)),
                "user_agents": dict(c.user_agents.most_common(5)),
                "source_ips": dict(c.ips.most_common(5)),
                "end_users": dict(c.users.most_common(5)),
                "teams": dict(c.teams.most_common(3)),
                "operations": dict(c.paths.most_common(5)),
                "distribution_events_dropped": dict(c.distribution_events_dropped),
                "distribution_limit": _MAX_DISTINCT_KEYS,
                "classification_incomplete": any(c.distribution_events_dropped.get(name) for name in (
                    "models", "providers", "hosts", "user_agents", "end_users", "teams",
                )),
                "tool_requests": c.tools_requests,
                "tool_call_responses": c.tool_call_responses,
                "tokens_in": c.tokens_in,
                "tokens_out": c.tokens_out,
                "cost": round(c.cost, 4),
                "errors": c.errors,
                "schemas": dict(c.schemas),
                "samples": c.metadata_samples,
                "correlation_scope": c.scope,
                "correlation_scope_redacted": c.scope_redacted,
                "runtime_observations": list(c.observations.values()),
                "runtime_observations_dropped": c.observations_dropped,
                "runtime_source": {"id": source_id, "input": str(self.ctx.input_path or ""), "label": self.label, "schemas": sorted(c.schemas)},
            }
        )
        f.id = "ss-" + hashlib.sha256(f"{f.compute_id()}|{source_id}".encode()).hexdigest()[:16]
        finalize(f, self.index)
        f.kind = Kind.GATEWAY_CALLER
        what = "Agentic caller" if f.metadata.get("agent_indicators") else "LLM caller"
        fw = [self.index.get(s).name for s in f.frameworks[:2] if self.index.get(s)]  # type: ignore[union-attr]
        f.title = f"{what} '{c.label}' ({c.kind}): {c.events} requests" + (f" via {', '.join(fw)}" if fw else "") + (f" to {top_models[0]}" if top_models else "")
        return f
