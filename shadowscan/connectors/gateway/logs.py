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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.agent_behavior import (
    LOOP_MAX_GAP_SECONDS,
    LOOP_MIN_CALLS,
    AgentOperation,
    agent_operations,
    host_service,
    is_browser_user_agent,
    is_generation,
    is_mcp_request,
    loop_cadence,
)
from shadowscan.connectors.base import (
    _MAX_OFFLINE_LINE_BYTES,
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    _NoDump,
    _OfflineInputBudget,
    _positive_limit,
)
from shadowscan.connectors.common import apply_matches, config_boolean, finalize
from shadowscan.connectors.gateway.normalise import (  # noqa: F401
    # Re-exported: callers and tests import these names from this module.
    NORMALISERS,
    Event,
    _b,
    _f,
    _has_tool_calls,
    _has_tools,
    _i,
    _normalise,
    detect_schema,
)
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import Match, MatchTimeoutError, SignatureIndex
from shadowscan.utils.redaction import REDACTED, sanitize
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.text import get_path, parse_timestamp, to_iso

_MAX_CACHED_USER_AGENTS = 256
_MAX_CACHED_USER_AGENT_CHARS = 1024
_OPAQUE_SCOPE_PREFIX = "scope:hmac-sha256:"
_LEGACY_SCOPE_PREFIX = "scope:sha256:"
_PUBLIC_CREDENTIAL_ID = re.compile(r"credential:sha256:[0-9a-f]{64}\Z")
_IMPORTED_CREDENTIAL_ID = re.compile(r"credential:(?:hmac-)?sha256:[0-9a-f]{64}\Z")
_OPAQUE_CALLER_PREFIX = "caller:hmac-sha256:"
_OPAQUE_LABEL_PREFIXES = ("credential:hmac-sha256:", _OPAQUE_CALLER_PREFIX)
# Retained labels are bounded only after sanitization, so a report never
# embeds an attacker-sized model, host, owner or sample string.
_MAX_CALLER_LABEL_CHARS = 120
_MAX_LABEL_CHARS = 160
_MAX_SAMPLE_CHARS = 300


def _binding_credential_id(value: str) -> str:
    """Legacy exact binding only: never publish this enumerable digest.

    Existing private gateway correlation mappings retain their SHA-256
    spelling. Public gateway pseudonyms continue to use their own keyed,
    domain-separated identities; code/cloud evidence uses credential_id().
    """
    if _PUBLIC_CREDENTIAL_ID.fullmatch(value):
        return value
    return "credential:sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalise(rec: dict[str, Any], schema: str) -> Event | None:
    """Normalize without retaining credentials, including in nested metadata."""
    return normalise_with_record(rec, schema)[0]


def _runtime_labels(rec: dict[str, Any], metadata: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    """Extract known context fields before redaction can replace source keys."""
    aliases = {
        "tenant": (
            "tenant_id",
            "tenant",
            "organization_id",
            "org_id",
            "metadata.tenant_id",
            "metadata.tenant",
            "identity.claims.tid",
            "properties.identity.claims.tid",
        ),
        "account": (
            "account_id",
            "accountId",
            "account",
            "subscription_id",
            "subscriptionId",
            "metadata.account_id",
            "metadata.account",
        ),
        "project": (
            "project_id",
            "projectId",
            "project",
            "metadata.project_id",
            "resource.labels.project_id",
        ),
        "workspace": ("workspace_id", "workspace", "metadata.workspace_id"),
    }
    scope = {}
    for key, paths in aliases.items():
        value = get_path(rec, *paths)
        if value is None:
            value = metadata.get(key)
        if isinstance(value, (str, int)) and str(value):
            scope[key] = str(value)
    environment = get_path(
        rec,
        "environment",
        "deployment_environment",
        "metadata.environment",
        "metadata.deployment_environment",
    )
    return scope, environment if isinstance(environment, str) and environment else None


def _restore_scope(
    scope: dict[str, str],
    clean_values: Iterable[tuple[str]],
    scope_key: bytes,
) -> tuple[dict[str, str], bool]:
    """Keep redacted scope identities distinct without disclosing their labels.

    The random key belongs to this connector instance, never to a report. An
    unkeyed hash would disclose a short scope by offline dictionary search.
    Both current and legacy prefixes are reserved so raw labels cannot
    impersonate an opaque label. Scope identities use their own domain rather
    than the code/cloud credential pseudonym domain.
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
        return {
            key: _withhold_public_credential_id(child, identifier)
            for key, child in value.items()
            if not isinstance(key, str) or identifier not in key
        }
    if isinstance(value, list):
        return [_withhold_public_credential_id(child, identifier) for child in value]
    if isinstance(value, tuple):
        return tuple(_withhold_public_credential_id(child, identifier) for child in value)
    return value


def _validate_scalar_fields(ev: Event) -> None:
    """Reject JSON containers in identity fields before any counter is updated.

    Validate scalar fields before attribution or counters are updated. JSON
    containers in headers/identity fields otherwise fail partway through
    accumulation and can discard all callers collected before that record.
    """
    status: object = ev.status  # schemas copy raw JSON values into the field
    if isinstance(status, int) and not isinstance(status, bool):
        ev.status = str(status)
    for name in (
        "caller",
        "caller_kind",
        "caller_label",
        "model",
        "provider",
        "host",
        "user_agent",
        "ip",
        "user",
        "team",
        "status",
        "path",
        "method",
    ):
        value = getattr(ev, name)
        if value is not None and not isinstance(value, str):
            raise ConnectorError(f"gateway.logs: normalized {name} must be a string")


def _conceal_api_key(
    ev: Event,
    rec: dict[str, Any],
    schema: str,
    scope_key: bytes,
) -> tuple[str | None, str | None]:
    """Replace an API key caller with a keyed opaque identity.

    Returns ``(opaque_id, raw_key)``, both None for callers that are not API
    keys. The exact-match binding key stays private on the Event.
    """
    if ev.caller_kind != "api-key":
        return None, None
    namespace, _, raw_key = ev.caller.partition(":")
    ev.binding_caller = f"{namespace}:{_binding_credential_id(raw_key)}"
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
    return opaque_id, raw_key


def normalise_with_record(
    rec: dict[str, Any],
    schema: str,
    *,
    scope_key: bytes | None = None,
) -> tuple[Event | None, dict[str, Any] | None]:
    """Normalize and also return the sanitized source record.

    Sanitizing a record is the dominant per-record cost; callers that need the
    clean record for scope attribution must not sanitize it a second time.
    """
    ev = _normalise(rec, schema)
    if ev is None:
        return None, None
    scope_key = scope_key if scope_key is not None else secrets.token_bytes(32)
    _validate_scalar_fields(ev)
    opaque_id, raw_key = _conceal_api_key(ev, rec, schema, scope_key)
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
    clean_record, clean_fields, clean_scope, _ = sanitize(
        (
            rec,
            [(value,) for value in fields.values()],
            [(value,) for value in raw_scope.values()],
            {"api_key": raw_key} if raw_key is not None else {},
        )
    )
    if raw_key is not None and _IMPORTED_CREDENTIAL_ID.fullmatch(raw_key):
        clean_record, clean_fields, clean_scope = _withhold_public_credential_id(
            (clean_record, clean_fields, clean_scope),
            raw_key,
        )
    cleaned = dict(zip(fields, (value for (value,) in clean_fields), strict=True))
    cleaned["scope"], cleaned["scope_redacted"] = _restore_scope(
        raw_scope,
        clean_scope,
        scope_key,
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
            digest = hmac.digest(scope_key, material.encode(), "sha256").hex()
            cleaned["caller"] = f"{ev.caller_kind}:{_OPAQUE_CALLER_PREFIX}{digest}"
            cleaned["caller_redacted"] = True
            if cleaned["caller_label"] != ev.caller_label:
                # The label carried the same credential-like value; a stable
                # opaque label keeps callers distinguishable without it.
                cleaned["caller_label"] = _OPAQUE_CALLER_PREFIX + digest
    if opaque_id and ev.caller_label == opaque_id:
        cleaned["caller_label"] = opaque_id
    # Bound the label only after sanitization: truncating first can cut a
    # token below the length its redaction pattern recognises.
    cleaned["caller_label"] = cleaned["caller_label"][:_MAX_CALLER_LABEL_CHARS]
    cleaned["binding_caller"] = ev.binding_caller
    return Event(**cleaned), clean_record


# --------------------------------------------------------------- text logs

# These stdlib patterns run outside the signature engine's regex timeouts, so
# they must be linear: possessive tokens (Python 3.11+) never backtrack into a
# long unterminated request or a bare token blob to retry a failed match.
# A quoted field keeps backslash escapes (Apache writes \" and \\) inside it.
_QUOTED_TEXT = r'(?:[^"\\]++|\\.)*+'
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) '
    r'(?P<path>(?:[^\s"\\]++|\\\S)++)' + _QUOTED_TEXT + r'" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>' + _QUOTED_TEXT + r')" "(?P<ua>' + _QUOTED_TEXT + r')")?'
    r'(?: "(?P<extra>' + _QUOTED_TEXT + r')")?'
)
# One logfmt token: key=value, key="quoted value" or quoted text without a key.
# A key starts a whitespace-separated token, so text inside a value or quoted
# text (``?model=x``, ``&host=y``) never becomes a field. A quote that opens a
# token and is never closed makes the record malformed, not a bare token.
_LOGFMT_TOKEN = re.compile(
    r'(?<!\S)(?:(?P<key>\w[\w.-]*+)=(?:"(?P<quoted>' + _QUOTED_TEXT + r')"|(?P<bare>\S++))'
    r'|"' + _QUOTED_TEXT + r'"|(?P<stray>"))'
)
_LOGFMT_ESCAPE = re.compile(r'\\(["\\])')
# Static assets and health probes are not inference traffic. Only the routed
# request path is tested: a client chooses the query string (``?_=.js``) and
# ``;name=value`` path parameters, which servlet containers drop before
# routing, and must not be able to hide an inference call with them.
_STATIC_OR_PROBE_PATH = re.compile(
    r"(?:^|/)(?:favicon\.ico|robots\.txt|healthz?|readyz?|livez?|metrics)/?$"
    r"|\.(?:css|js|map|png|jpe?g|gif|ico|svg|woff2?)$",
    re.I,
)
_PATH_PARAMETERS = re.compile(r";[^/]*+")
# An inference operation that a suffix-matching router also serves with a static
# suffix (/v1/chat/completions.css) is not a static asset. Only the operation
# itself is exempt: files under an agent-like prefix (/agents/app.js,
# /v1/images/logo.png) are still a web page's or an image API's static assets.
_SUFFIXED_INFERENCE_OPERATION = re.compile(
    r"(?:/v1/(?:chat/completions|completions|responses|messages|embeddings)"
    r"|[:/](?:generateContent|streamGenerateContent)|/invoke(?:-with-response-stream)?|/converse(?:-stream)?"
    r"|/api/(?:chat|generate))"
    r"\.(?:css|js|map|png|jpe?g|gif|ico|svg|woff2?)$",
    re.I,
)
# Access-log trailer keys that name the requested host, and the host a value starts with.
_TRAILER_HOST_KEYS = frozenset({"host", "authority", "upstream_host", "server_name"})
_HOST_VALUE = re.compile(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# A parsed access-log record field holding a host token that a client could have
# written. Analysis never attributes traffic to it, only reports when it would
# have made a request LLM traffic.
_UNTRUSTED_HOST_FIELD = "_untrusted_host"


# Field names that the gateway schemas read event times from.
_TIMESTAMP_FIELDS = (
    "timestamp",
    "time",
    "@timestamp",
    "ts",
    "date",
    "datetime",
    "event_time",
    "time_local",
    "time_iso8601",
    "created_at",
    "createdAt",
    "request_created_at",
    "start_time",
    "startTime",
    "started_at",
    "starting_at",
    "endTime",
    "TimeGenerated",
    "receiveTimestamp",
    "effective_at",
    "aggregation_timestamp",
)


def _has_unparsed_timestamp(rec: dict[str, Any]) -> bool:
    """Whether a timestamp field holds a value that no supported format parses."""
    return any(
        rec.get(key) not in (None, "") and parse_timestamp(rec[key]) is None for key in _TIMESTAMP_FIELDS
    )


def _is_static_or_probe(path: str | None) -> bool:
    """Whether the routed request path names a static asset or probe.

    The query string, fragment and ``;name=value`` path parameters are removed
    first, and a known inference operation with a static suffix is not static.
    """
    if not path:
        return False
    request_path = _PATH_PARAMETERS.sub("", path.partition("?")[0].partition("#")[0])
    return (
        _STATIC_OR_PROBE_PATH.search(request_path) is not None
        and _SUFFIXED_INFERENCE_OPERATION.search(request_path) is None
    )


def _logfmt_pairs(line: str) -> dict[str, str]:
    """Parse logfmt pairs; an unterminated quote or a repeated key makes the line malformed.

    A repeated key would let the last occurrence (for example one smuggled
    into a client-controlled value) override the gateway's own field.
    """
    pairs: dict[str, str] = {}
    for token in _LOGFMT_TOKEN.finditer(line):
        key, bare = token["key"], token["bare"]
        if key is None:
            if token["stray"] is not None:
                raise ValueError("logfmt record has an unterminated quoted value")
            continue  # quoted text without a key is text, never a field
        if key in pairs:
            raise ValueError("logfmt record repeats a key")
        if bare is not None and bare.startswith('"'):
            raise ValueError("logfmt record has an unterminated quoted value")
        pairs[key] = bare.strip('"') if bare is not None else _LOGFMT_ESCAPE.sub(r"\1", token["quoted"])
    return pairs


def _host_field(pairs: dict[str, str]) -> str | None:
    """The first host named by a ``host=``, ``authority=``, ``upstream_host=`` or ``server_name=`` pair."""
    for key, value in pairs.items():
        if key.lower() in _TRAILER_HOST_KEYS and (host := _HOST_VALUE.match(value)):
            return host.group(0)
    return None


def parse_text_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    if line.startswith(("{", "[")):
        rec = strict_json_loads(line)
        if not isinstance(rec, dict):
            raise ValueError("gateway text log JSON must be an object")
        return rec
    m = _COMBINED.match(line)
    if m:
        d = m.groupdict()
        # The request line, referer, user agent and any further quoted field are
        # client-controlled, and a gateway that does not escape quotes lets a
        # client close its field early and write tokens after it. Only text after
        # the final quote is written by the server, so the host is read from a
        # key=value token there and nowhere else. The whole trailer is tokenized
        # as logfmt: an unterminated quote (a truncated line) or a repeated key
        # makes the line malformed, and text inside a value is never a key.
        trailer = _logfmt_pairs(line[m.end() :])
        host = _host_field(_logfmt_pairs(line.rpartition('"')[2]))
        rec = {
            "remote_addr": d["ip"],
            "remote_user": None if d["user"] == "-" else d["user"],
            "time_local": d["time"],
            "request_method": d["method"],
            "request_uri": d["path"],
            "status": d["status"],
            "http_user_agent": d.get("ua"),
            "host": host,
        }
        # A host token in or before a quoted trailer field (``host="x"``, or one
        # followed by a quoted forwarded-for field) may be the server's or a
        # client's. It is kept apart so analysis can report what it would change.
        untrusted = _host_field(trailer) if host is None else None
        if untrusted is not None:
            rec[_UNTRUSTED_HOST_FIELD] = untrusted
        return rec
    # key=value logfmt
    if "=" in line and " " in line:
        kv = _logfmt_pairs(line)
        if kv:
            return kv
    return None


PROVIDER_ALIASES = {
    "openai": "provider.openai",
    "azure": "provider.azure-openai",
    "azure_openai": "provider.azure-openai",
    "azure-openai": "provider.azure-openai",
    "azure_ai": "provider.azure-openai",
    "anthropic": "provider.anthropic",
    "bedrock": "provider.aws-bedrock",
    "aws-bedrock": "provider.aws-bedrock",
    "aws_bedrock": "provider.aws-bedrock",
    "amazon-bedrock": "provider.aws-bedrock",
    "bedrock_converse": "provider.aws-bedrock",
    "vertex_ai": "provider.google-vertex-ai",
    "vertex-ai": "provider.google-vertex-ai",
    "vertexai": "provider.google-vertex-ai",
    "google-vertex-ai": "provider.google-vertex-ai",
    "vertex_ai_beta": "provider.google-vertex-ai",
    "gemini": "provider.google-gemini",
    "google": "provider.google-gemini",
    "google-ai-studio": "provider.google-gemini",
    "google_ai_studio": "provider.google-gemini",
    "mistral": "provider.mistral",
    "cohere": "provider.cohere",
    "cohere_chat": "provider.cohere",
    "groq": "provider.groq",
    "together_ai": "provider.together",
    "together": "provider.together",
    "fireworks_ai": "provider.fireworks",
    "fireworks": "provider.fireworks",
    "openrouter": "provider.openrouter",
    "ollama": "provider.ollama",
    "ollama_chat": "provider.ollama",
    "vllm": "provider.vllm",
    "huggingface": "provider.huggingface",
    "hugging-face": "provider.huggingface",
    "xai": "provider.xai",
    "deepseek": "provider.deepseek",
    "perplexity": "provider.perplexity",
    "replicate": "provider.replicate",
    "cerebras": "provider.cerebras",
    "sambanova": "provider.sambanova",
    "nvidia_nim": "provider.nvidia-nim",
    "nvidia": "provider.nvidia-nim",
    "oci": "provider.oci-generative-ai",
    "oci_genai": "provider.oci-generative-ai",
    "watsonx": "provider.ibm-watsonx",
    "databricks": "provider.databricks",
    "cloudflare": "provider.cloudflare-workers-ai",
    "workers-ai": "provider.cloudflare-workers-ai",
    "snowflake": "provider.snowflake-cortex",
}


def _provider_signature(index: SignatureIndex, name: str | None) -> str | None:
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
    agent_operations: Counter = field(default_factory=Counter)
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
    # Behavioural agent indicators (shadowscan.connectors.agent_behavior).
    call_times: list[float] = field(default_factory=list)
    call_times_dropped: int = 0
    browser_requests: int = 0
    mcp_candidates: Counter = field(default_factory=Counter)


# Per-caller distributions keep this many distinct keys. Counts for omitted
# labels are tracked separately so no synthetic label can become a model,
# provider, or owner. Memory remains bounded as record cardinality increases.
_MAX_DISTINCT_KEYS = 2000
_MAX_INVALID_LINE_ERRORS = 20
# Domain signals weighted below this are hints, not evidence of inference traffic.
_MIN_LLM_HOST_WEIGHT = 0.3
_MAX_DISTINCT_CALLERS = 10_000
_MAX_USAGE_INTERVALS = 2_000
_MAX_TOTAL_USAGE_INTERVALS = 20_000
_MAX_TOTAL_DETAIL_KEYS = 50_000
# Token counts and spend beyond this are not plausible usage. A negative or
# absurd figure in an untrusted log must not offset real usage or be reported
# verbatim in caller totals.
_MAX_USAGE_VALUE = 10**15
# Request times kept for agent-loop cadence, per caller and across callers.
_MAX_CALL_TIMES = 1_000
_MAX_TOTAL_CALL_TIMES = 200_000
_MAX_MCP_CANDIDATES = 50
_MCP_CANDIDATE_PATH = re.compile(r"(?:^|/)(?:mcp|sse|messages)/?$", re.IGNORECASE)


@dataclass(slots=True)
class _DetailBudget:
    """One shared budget for retained distribution and observation keys."""

    used: int = 0
    observations_omitted: int = 0
    observation_requests_omitted: int = 0
    call_times_used: int = 0


def _count(
    counter: Counter,
    key: str,
    amount: int,
    dropped: Counter,
    dimension: str,
    budget: _DetailBudget | None = None,
) -> None:
    """Bound retained labels, counting lost requests without inventing a label."""
    if key not in counter:
        # The first label of a distribution is always retained (bounded by
        # callers x dimensions), so an exhausted shared budget degrades detail
        # rather than a caller's basic classification.
        if len(counter) >= _MAX_DISTINCT_KEYS or (
            counter and budget is not None and budget.used >= _MAX_TOTAL_DETAIL_KEYS
        ):
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


def _discard_unusable_usage(ev: Event) -> bool:
    """Zero negative or absurd token and cost figures; report whether any were dropped."""
    dropped = False
    if not 0 <= ev.tokens_in <= _MAX_USAGE_VALUE:
        ev.tokens_in = 0
        dropped = True
    if not 0 <= ev.tokens_out <= _MAX_USAGE_VALUE:
        ev.tokens_out = 0
        dropped = True
    if not 0 <= ev.cost <= _MAX_USAGE_VALUE:
        ev.cost = 0.0
        dropped = True
    return dropped


def _record_activity(c: _Caller, ev: Event) -> None:
    """Track first/last seen and, for individual requests, the hour and weekday."""
    if ev.timestamp:
        c.first = ev.timestamp if not c.first or ev.timestamp < c.first else c.first
        end = ev.interval_end or ev.timestamp
        c.last = end if not c.last or end > c.last else c.last
        if not ev.aggregated:
            # Normalize offset-bearing exports to the same UTC activity bucket.
            moment = ev.timestamp.astimezone(UTC)
            c.hours[moment.hour] += 1
            c.weekdays[moment.weekday()] += 1


def _record_interval(c: _Caller, ev: Event, retain_interval: bool) -> bool:
    """Keep an aggregate interval's detail within the caller's bound; report whether it was stored."""
    if not ev.aggregated:
        return False
    if retain_interval and len(c.usage_intervals) < min(_MAX_USAGE_INTERVALS, _MAX_DISTINCT_KEYS):
        c.usage_intervals.append(
            {
                "start": to_iso(ev.timestamp),
                "end": to_iso(ev.interval_end),
                "requests": ev.request_count,
                "model": ev.model,
            }
        )
        return True
    c.usage_intervals_dropped += 1
    c.usage_interval_requests_dropped += ev.request_count
    return False


def _record_behaviour(c: _Caller, ev: Event, detail_budget: _DetailBudget | None) -> None:
    """Keep what the behavioural agent indicators need: call times, browser share, MCP endpoints."""
    if is_browser_user_agent(ev.user_agent):
        c.browser_requests += ev.request_count
    if ev.path:
        # Classify before truncating or aggregating: methods and hosts from
        # different requests must never corroborate each other's paths.
        for operation in agent_operations(
            {ev.path: ev.request_count}, method=ev.method, host=ev.host, schema=ev.schema
        ):
            c.agent_operations[(operation.label, operation.signature)] += operation.requests
        bare = str(ev.path).split("?", 1)[0][:120]
        candidate = (str(ev.host or "")[:_MAX_LABEL_CHARS], bare)
        if _MCP_CANDIDATE_PATH.search(bare) and (
            candidate in c.mcp_candidates or len(c.mcp_candidates) < _MAX_MCP_CANDIDATES
        ):
            c.mcp_candidates[candidate] += ev.request_count
    if ev.timestamp is None or ev.aggregated or not is_generation(ev.path, ev.model, ev.method):
        return
    budget_left = detail_budget is None or detail_budget.call_times_used < _MAX_TOTAL_CALL_TIMES
    if len(c.call_times) < _MAX_CALL_TIMES and budget_left:
        c.call_times.append(ev.timestamp.timestamp())
        if detail_budget is not None:
            detail_budget.call_times_used += 1
    else:
        c.call_times_dropped += 1


def _record_distributions(c: _Caller, ev: Event, detail_budget: _DetailBudget | None) -> None:
    """Count the event's labels in every bounded per-caller distribution."""
    n, dropped = ev.request_count, c.distribution_events_dropped
    if ev.model:
        _count(c.models, str(ev.model)[:_MAX_LABEL_CHARS], n, dropped, "models", detail_budget)
    if ev.provider:
        _count(c.providers, str(ev.provider)[:_MAX_LABEL_CHARS], n, dropped, "providers", detail_budget)
    if ev.host:
        _count(c.hosts, ev.host[:_MAX_LABEL_CHARS], n, dropped, "hosts", detail_budget)
    if ev.user_agent:
        _count(c.user_agents, str(ev.user_agent)[:_MAX_LABEL_CHARS], n, dropped, "user_agents", detail_budget)
    if ev.ip:
        _count(c.ips, ev.ip[:_MAX_LABEL_CHARS], n, dropped, "source_ips", detail_budget)
    if ev.user:
        _count(c.users, ev.user[:_MAX_LABEL_CHARS], n, dropped, "end_users", detail_budget)
    if ev.team:
        _count(c.teams, str(ev.team)[:_MAX_LABEL_CHARS], n, dropped, "teams", detail_budget)
    if ev.path:
        # Query strings carry per-request identifiers; the operation is the path.
        _count(c.paths, str(ev.path).split("?", 1)[0][:120], n, dropped, "operations", detail_budget)


def _record_usage(c: _Caller, ev: Event, total_cost: float) -> None:
    """Tool use, token, cost and error totals, plus the first metadata sample per key."""
    if ev.tools is not None:
        c.tool_known += ev.request_count
        if ev.tools:
            c.tools_requests += ev.request_count
    if ev.tool_calls:
        c.tool_call_responses += ev.request_count
    c.tokens_in += ev.tokens_in
    c.tokens_out += ev.tokens_out
    c.cost = total_cost
    if ev.status and (
        ev.status.startswith(("4", "5")) or ev.status.lower() in {"error", "failure", "failed"}
    ):
        c.errors += 1
    for k, v in ev.metadata.items():
        if v not in (None, "", {}, []) and k not in c.metadata_samples:
            if isinstance(v, str):
                c.metadata_samples[k] = v[:_MAX_SAMPLE_CHARS]
            else:
                c.metadata_samples[k] = (
                    v if isinstance(v, (int, float, bool)) else json.dumps(v, default=str)[:_MAX_SAMPLE_CHARS]
                )


def _record_observation(c: _Caller, ev: Event, detail_budget: _DetailBudget | None) -> None:
    """Group the event into its runtime observation (workload, frameworks, environment, assurance)."""
    bucket = json.dumps([ev.code_resources, ev.runtime_frameworks, ev.environment, ev.identity_assurance])
    if bucket not in c.observations:
        if len(c.observations) >= _MAX_DISTINCT_KEYS or (
            detail_budget is not None and detail_budget.used >= _MAX_TOTAL_DETAIL_KEYS
        ):
            # Hostile exports can vary the environment label per record.
            c.observations_dropped += ev.request_count
            if detail_budget is not None:
                detail_budget.observations_omitted += 1
                detail_budget.observation_requests_omitted += ev.request_count
            return
        if detail_budget is not None:
            detail_budget.used += 1
    observation = c.observations.setdefault(
        bucket,
        {
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
        },
    )
    observation["events"] += ev.request_count
    if ev.timestamp and not ev.aggregated:
        timestamp = to_iso(ev.timestamp)
        observation["timestamped_events"] += 1
        observation["first_seen"] = (
            min(observation["first_seen"], timestamp) if observation["first_seen"] else timestamp
        )
        observation["last_seen"] = (
            max(observation["last_seen"], timestamp) if observation["last_seen"] else timestamp
        )


# Accepted ``format`` values; None auto-detects the schema per record.
_FORMATS = frozenset(
    {
        None,
        "litellm",
        "portkey",
        "kong",
        "cloudflare",
        "helicone",
        "langfuse",
        "bedrock",
        "azure-openai",
        "vertex",
        "openai-usage",
        "anthropic-usage",
        "access-log",
        "generic",
    }
)

# Generic exports: the credential or principal fields an exact binding may name.
_GENERIC_KEY_FIELDS = (
    "api_key",
    "apiKey",
    "api_key_id",
    "key",
    "key_id",
    "key_alias",
    "virtual_key",
    "token_id",
)
_GENERIC_PRINCIPAL_FIELDS = (
    "principal",
    "principal_id",
    "identity.arn",
    "caller",
    "service",
    "service_name",
    "app",
    "application",
    "app_name",
)

_CALLER_KIND_WEIGHT = {
    "api-key": 0.35,
    "principal": 0.35,
    "service": 0.45,
    "user": 0.15,
    "user-agent": 0.2,
    "ip": 0.15,
}


def _caller_indicator(match: Match) -> bool:
    """Whether a signature match says the caller itself is an agent.

    AI SaaS app signatures (``identity-app``) mark an OAuth grant to ChatGPT or
    Claude as agentic, and their domains (``*.openai.com``, ``*.anthropic.com``)
    also cover the model APIs. Calling a model API, or naming a key after the
    vendor, is LLM use: it does not make the caller an agent. A product name
    matched in a key alias or a user name is a hint, not behaviour: a person
    called Jules is not Google's Jules agent.
    """
    return (
        match.signature.category != "identity-app"
        and match.signal.type != "name"
        and not (match.signature.category == "cloud-service" and match.signal.type == "domain")
    )


def _service_indicator(owner: str | None) -> Callable[[Match], bool]:
    """Count a host's agent indicator only from the service that owns the host."""

    def accept(match: Match) -> bool:
        return match.signature.id == owner and _caller_indicator(match)

    return accept


def _tool_use_evidence(f: Finding, c: _Caller) -> None:
    """Tool definitions in requests, or tool calls in responses, mark an agentic caller."""
    tool_ratio = (c.tools_requests / c.tool_known) if c.tool_known else None
    if tool_ratio is not None and tool_ratio > 0:
        f.add_capability("tool-use")
        f.add_evidence(
            Evidence(
                signal="gateway:tool-use",
                description=(
                    f"{c.tools_requests}/{c.tool_known} inspected requests carried tool/function definitions "
                    f"({tool_ratio:.0%}); {c.tool_call_responses} responses invoked tools"
                ),
                weight=min(0.9, 0.4 + tool_ratio * 0.5),
            )
        )
        f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
    if c.tool_call_responses and not (tool_ratio is not None and tool_ratio > 0):
        f.add_capability("tool-use")
        f.add_evidence(
            Evidence(
                signal="gateway:tool-calls",
                description=f"{c.tool_call_responses} responses contained tool calls",
                weight=0.6,
            )
        )
        f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1


def _temporal_evidence(f: Finding, c: _Caller, framework_user_agent: bool) -> None:
    """Round-the-clock activity: an agent indicator only when another signal corroborates it.

    A shared key used across time zones also produces round-the-clock
    activity; the pattern alone must not promote a human-attributed caller to
    an agent. Without corroboration the tag stays informational.
    """
    # Non-temporal automation indicators: tool use (counted above), an
    # agent framework user agent, or an identity that no end user owns.
    unattributed = c.kind in {"api-key", "service", "principal"} and not c.users
    service_style = c.kind in {"service", "principal"}
    # temporal shape: automated callers run around the clock and on weekends
    total_ts = sum(c.hours.values())
    if total_ts < 50:
        return
    night = sum(v for h, v in c.hours.items() if h < 6 or h >= 22) / total_ts
    weekend = sum(v for d, v in c.weekdays.items() if d >= 5) / total_ts
    active_hours = len(c.hours)
    always_on = active_hours >= 20 or (night > 0.25 and weekend > 0.15)
    corroborated = always_on and (
        bool(f.metadata.get("agent_indicators")) or framework_user_agent or unattributed or service_style
    )
    if always_on:
        f.add_tag("always-on")
        shape = f"Activity across {active_hours}/24 hours, {night:.0%} at night, {weekend:.0%} on weekends"
        if corroborated:
            # Autonomy: cadence, recorded as initiation evidence through the always-on tag. An
            # unattended caller says nothing about whether its actions are approved.
            f.add_capability("autonomous")
            f.add_evidence(
                Evidence(
                    signal="gateway:always-on",
                    description=f"{shape}: unattended / scheduled caller",
                    weight=0.5,
                )
            )
            f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
        else:
            f.add_evidence(
                Evidence(
                    signal="gateway:always-on",
                    description=(
                        f"{shape}: round-the-clock activity without tool use, an agent framework or an "
                        "unattended identity"
                    ),
                    weight=0.3,
                )
            )
    f.metadata["activity"] = {
        "active_hours": active_hours,
        "night_share": round(night, 2),
        "weekend_share": round(weekend, 2),
        "always_on": always_on,
        "always_on_corroborated": corroborated,
    }


def _volume_evidence(f: Finding, c: _Caller) -> None:
    """Volume, model breadth, attribution and error-rate signals."""
    if c.events >= 1000:
        f.add_evidence(
            Evidence(signal="gateway:volume", description=f"High volume: {c.events} requests", weight=0.2)
        )
    if len(c.models) >= 4:
        f.add_evidence(
            Evidence(
                signal="gateway:multi-model",
                description=f"Uses {len(c.models)} different models (router / orchestrator behaviour)",
                weight=0.2,
            )
        )
    if c.kind in {"api-key", "service", "principal"} and not c.users:
        f.add_tag("no-end-user-attribution")
    if c.errors and c.errors / c.events > 0.2:
        f.add_tag("high-error-rate")


def _assign_owner(f: Finding, c: _Caller) -> None:
    """The most frequent end user, else team, owns the caller.

    A truncated distribution cannot establish its most frequent owner. Leave
    attribution unknown rather than promote the retained subset.
    """
    if not c.distribution_events_dropped.get("end_users"):
        if c.users:
            f.owner = c.users.most_common(1)[0][0]
        elif c.teams and not c.distribution_events_dropped.get("teams"):
            f.owner = c.teams.most_common(1)[0][0]


class GatewayLogConnector(BaseConnector, _NoDump):
    # Engine hook: identical sources in one report share opaque caller/scope IDs.
    uses_run_identity_key: ClassVar[bool] = True

    name: ClassVar[str] = "gateway.logs"
    surface: ClassVar[Surface] = Surface.GATEWAY
    provider: ClassVar[str | None] = "gateway"
    description: ClassVar[str] = (
        "Reconstruct LLM callers (API keys, principals, services, user agents) from AI gateway / provider / "
        "proxy logs."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "input": "log file or directory (JSONL / JSON / CSV / nginx-envoy text)",
        "format": (
            "force schema: litellm|portkey|kong|cloudflare|helicone|langfuse|bedrock|azure-openai|vertex|"
            "openai-usage|anthropic-usage|access-log|generic (default auto)"
        ),
        "min_events": "ignore callers with fewer events, a positive integer (default 1)",
        "llm_hosts_only": "for access logs, keep only requests to known LLM/agent hosts (default true)",
        "max_records": "stop after N records (default 5,000,000)",
        "label": (
            "gateway name recorded as the finding provider and as the account of unscoped callers (defaults "
            "to the entry's `label`)"
        ),
        "gateway_name": "fallback for `label` when the connector entry has none",
        "correlation_bindings": (
            "explicit [{code_resource, caller, scope}] mappings to workload identities; scope must exactly "
            "match log tenant/account/project/workspace fields ({} for unscoped exports)"
        ),
    }
    offline_formats: ClassVar[str] = "JSONL / JSON / CSV / text access logs"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        # Engine.run shares one key across its gateway jobs; direct connector
        # use gets an isolated key. Never place this key in config or reports.
        self._scope_key = ctx.gateway_identity_key or secrets.token_bytes(32)
        # "keyed": the operator's stable key, so equal inputs keep equal IDs
        # across scans. "run": IDs and pseudonyms are scan-local by design.
        self.identity_scope = (
            "keyed" if ctx.gateway_identity_key and ctx.gateway_identity_key_stable else "run"
        )
        self.format = ctx.get("format")
        self.min_events = _positive_limit(ctx.get("min_events", 1), "min_events")
        self.llm_hosts_only = config_boolean(ctx.get("llm_hosts_only", True), "llm_hosts_only")
        self.max_records = _positive_limit(ctx.get("max_records", 5_000_000), "max_records")
        self.label = ctx.get("label") or ctx.get("gateway_name")
        if self.format not in _FORMATS:
            raise ConnectorError("gateway.logs: unsupported format")
        # A caller is scoped to its configured export source. Repeating the same
        # source is idempotent; distinct sources retain their own observations.
        self.correlation_bindings = ctx.get("correlation_bindings", [])
        if not isinstance(self.correlation_bindings, list):
            raise ConnectorError("gateway.logs: correlation_bindings must be a list")
        for binding in self.correlation_bindings:
            if (
                not isinstance(binding, dict)
                or not isinstance(binding.get("code_resource"), str)
                or not binding["code_resource"]
                or not isinstance(binding.get("caller"), str)
                or not binding["caller"]
                or not isinstance(binding.get("scope"), dict)
                or any(
                    k not in {"tenant", "account", "project", "workspace"} or not isinstance(v, str) or not v
                    for k, v in binding["scope"].items()
                )
            ):
                raise ConnectorError(
                    "gateway.logs: each correlation binding requires exact code_resource, caller and scope "
                    "mapping"
                )
        source = str(Path(ctx.input_path).expanduser().resolve()) if ctx.input_path else ""
        identity = json.dumps(
            [
                source,
                self.label,
                self.format,
                self.min_events,
                self.llm_hosts_only,
                self.max_records,
                sorted(self.correlation_bindings, key=lambda b: json.dumps(b, sort_keys=True)),
            ],
            sort_keys=True,
        )
        # Any source configuration may contain guessable labels or bindings;
        # never disclose an unkeyed digest even if rows are filtered out.
        self.source_id = hmac.digest(self._scope_key, identity.encode(), "sha256").hex()

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError(
            "gateway.logs: this connector reads exported logs; set 'input' to a file or directory"
        )

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
            key: rec[key]
            for key in (
                "timestamp",
                "receiveTimestamp",
                "resource",
                "labels",
                "project_id",
                "logName",
            )
            if key in rec
        }

    def _expand_usage_bucket(self, rec: dict[str, Any]) -> Iterator[dict[str, Any]]:
        """Usage results are aggregate intervals, not individual transactions."""
        results = rec.get("results")
        first, last = parse_timestamp(rec.get("start_time")), parse_timestamp(rec.get("end_time"))
        if not isinstance(results, list) or first is None or last is None or last <= first:
            self.ctx.warn(
                "gateway.logs: malformed OpenAI usage bucket (results and a valid interval are required)"
            )
            return
        for result in results:
            if not isinstance(result, dict) or not any(
                key in result for key in ("num_model_requests", "n_requests")
            ):
                self.ctx.warn("gateway.logs: malformed OpenAI usage result (request count is required)")
                continue
            if "object" in result and not str(result["object"]).startswith("organization.usage."):
                self.ctx.warn("gateway.logs: unsupported OpenAI usage result type")
                continue
            yield {
                **result,
                "object": result.get("object") or "organization.usage.completions.result",
                "start_time": rec["start_time"],
                "end_time": rec["end_time"],
            }

    def _expand_log_events(self, rec: dict[str, Any], depth: int) -> Iterator[dict[str, Any]]:
        """CloudWatch subscription batches: each log event inherits the batch context."""
        events = rec["logEvents"]
        if not isinstance(events, list):
            self.ctx.warn("gateway.logs: logEvents must be an array")
            return
        for event in events:
            if isinstance(event, dict):
                yield from self._expand_record({**self._envelope_context(rec), **event}, depth + 1)
            else:
                self.ctx.warn("gateway.logs: malformed CloudWatch log event")

    def _expand_record(self, rec: dict[str, Any], depth: int = 0) -> Iterator[dict[str, Any]]:
        if depth >= 16:
            self.ctx.warn("gateway.logs: export wrapper nesting limit exceeded")
            return
        if rec.get("object") == "bucket" or (self.format == "openai-usage" and "results" in rec):
            yield from self._expand_usage_bucket(rec)
            return
        if "logEvents" in rec:
            yield from self._expand_log_events(rec, depth)
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
            if key == "message" and any(
                k in rec
                for k in (
                    "model",
                    "model_name",
                    "modelId",
                    "provider",
                    "api_key",
                    "apiKey",
                    "service",
                    "user",
                    "user_id",
                    "principal",
                )
            ):
                break
            if isinstance(body, dict):
                yield from self._expand_record({**self._envelope_context(rec), **body}, depth + 1)
                return
            if isinstance(body, str):
                try:
                    parsed = parse_text_line(body)
                except (ValueError, TypeError, RecursionError):
                    self.ctx.warn(f"gateway.logs: invalid JSON/text record at {key}")
                    return
                if parsed is not None:
                    yield from self._expand_record({**self._envelope_context(rec), **parsed}, depth + 1)
                    return
                self.ctx.warn(f"gateway.logs: unrecognized text record at {key}")
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
                        data = strict_json_loads(line)
                    except (json.JSONDecodeError, RecursionError, ValueError):
                        self.ctx.error(f"gateway.logs: invalid JSON record at line {number}")
                        continue
                    if not isinstance(data, dict):
                        self.ctx.error(f"gateway.logs: line {number}: JSONL records must be objects")
                        continue
                    for rec in self._gateway_records(data):
                        yield from self._expand_record(rec)
                if not saw_record:
                    self.ctx.error(f"gateway.logs: {self._empty_export_message(budget)}")
                continue
            if suffix == ".json":
                yield from self._load_json_export(source, budget)
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
                message = (
                    self._empty_export_message(budget)
                    if budget.limit_hit
                    else "empty text export; use [] for an empty JSON export"
                )
                self.ctx.warn(f"gateway.logs: {message}")

    def _load_json_export(self, source: Path, budget: _OfflineInputBudget) -> Iterator[dict[str, Any]]:
        """A .json export: one document, or one object per line as a fallback."""
        text = self._read_offline_text(source, budget)
        if text is None:
            return
        if not text.strip():
            self.ctx.error("gateway.logs: empty offline export; use [] for an empty inventory")
            return
        try:
            data = strict_json_loads(text)
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

    def _gateway_records(self, data: Any) -> Iterator[dict[str, Any]]:
        # CloudWatch and usage buckets carry context on the enclosing object.
        # The generic offline list unwrapping would discard its scope or interval.
        if isinstance(data, dict) and (
            "logEvents" in data
            or data.get("object") == "bucket"
            or (self.format == "openai-usage" and "results" in data)
        ):
            if not self._valid_record(data):
                self.ctx.error("gateway.logs: invalid export record")
                return
            pagination_issue = self._offline_pagination_issue(data)
            if pagination_issue:
                self.ctx.error(f"gateway.logs: {pagination_issue}")
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
                data = strict_json_loads(line)
                if not isinstance(data, dict):
                    raise TypeError("JSONL records must be objects")
            except (json.JSONDecodeError, RecursionError, ValueError, TypeError) as exc:
                invalid += 1
                if invalid <= _MAX_INVALID_LINE_ERRORS:
                    detail = (
                        "JSONL records must be objects"
                        if isinstance(exc, TypeError)
                        else "invalid JSON record"
                    )
                    self.ctx.error(f"gateway.logs: line {number}: {detail}")
                elif invalid == _MAX_INVALID_LINE_ERRORS + 1:
                    self.ctx.error(
                        "gateway.logs: further invalid records in this export are not listed individually"
                    )
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
        unusable_usage = 0
        static_excluded = 0
        untrusted_host_requests = 0
        untimed = 0
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
                if (
                    schema in {"access-log", "generic"}
                    and self.llm_hosts_only
                    and not self._is_llm_traffic(ev)
                ):
                    skipped += 1
                    static_excluded += _is_static_or_probe(ev.path)
                    untrusted_host_requests += self._untrusted_host_is_llm(ev, rec)
                    continue
                unusable_usage += _discard_unusable_usage(ev)
                if ev.timestamp is None and _has_unparsed_timestamp(rec):
                    untimed += 1
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
                    callers,
                    ev,
                    identity,
                    retained_intervals < _MAX_TOTAL_USAGE_INTERVALS,
                    detail_budget,
                )
            except (
                ValueError,
                TypeError,
                AttributeError,
                KeyError,
                OverflowError,
                RecursionError,
                ConnectorError,
                MatchTimeoutError,
            ) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"gateway.logs: invalid record {n}: {type(exc).__name__}{detail}")
                continue
        self.ctx.examined(n)
        self._report_limits(callers, detail_budget, omitted_caller_records, omitted_caller_requests)
        if unusable_usage:
            self.ctx.warn(
                f"gateway.logs: {unusable_usage} record(s) carried negative or out of range token or cost "
                "values; those values were ignored and token and cost totals are incomplete"
            )
        if untimed:
            self.ctx.warn(
                f"gateway.logs: records with an unparseable timestamp field: {untimed}; their requests "
                "are counted without activity timing"
            )
        if untrusted_host_requests:
            self.ctx.warn(
                f"gateway.logs: {untrusted_host_requests} access-log requests name an LLM host only in or "
                "before a quoted field, where a client can write it; they were not counted as LLM traffic "
                "and LLM traffic coverage is incomplete. Log the host as an unquoted token after the last "
                "quoted field"
            )
        if static_excluded:
            self.ctx.warn(
                "gateway.logs: requests for static assets or health probes not counted as LLM traffic: "
                f"{static_excluded}",
                incomplete=False,
            )
        if skipped:
            self.log.info("gateway.logs: %d/%d records skipped (unrecognised or non-LLM)", skipped, n)
        for c in callers.values():
            if c.events < self.min_events:
                continue
            try:
                yield self._finding(c)
            except (
                ValueError,
                TypeError,
                AttributeError,
                KeyError,
                OverflowError,
                RecursionError,
                ConnectorError,
                MatchTimeoutError,
            ) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"gateway.logs: caller analysis failed ({type(exc).__name__}){detail}")

    def _report_limits(
        self,
        callers: dict[str, _Caller],
        detail_budget: _DetailBudget,
        omitted_caller_records: int,
        omitted_caller_requests: int,
    ) -> None:
        """Warn about every bound that truncated caller coverage or detail."""
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
        distribution_requests_dropped = sum(
            sum(c.distribution_events_dropped.values()) for c in callers.values()
        )
        if distribution_requests_dropped or detail_budget.observations_omitted:
            self.ctx.warn(
                "gateway.logs: distribution limit or bounded detail budget "
                f"({_MAX_TOTAL_DETAIL_KEYS} keys total, "
                f"{_MAX_DISTINCT_KEYS} per distribution or caller observations) reached; "
                f"omitted {distribution_requests_dropped} distribution dimension-request counts; "
                f"omitted {detail_budget.observations_omitted} observation records representing "
                f"{detail_budget.observation_requests_omitted} requests; "
                "classification, attribution, and detail telemetry may be incomplete"
            )

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
            _, clean_scope, (ev.environment,) = sanitize(
                (
                    rec,
                    [(value,) for value in raw_scope.values()],
                    (environment,),
                )
            )
            ev.scope, ev.scope_redacted = _restore_scope(raw_scope, clean_scope, self._scope_key)
        if ev.scope_redacted:
            self.ctx.warn(
                "gateway.logs: scope labels were redacted; distinct opaque scopes retained; runtime "
                "attribution incomplete"
            )
            identity_assurance = "unverified"
        if ev.caller_redacted and not ev.binding_caller:
            identity_assurance = "unverified"
        if ev.environment:
            ev.environment = ev.environment.strip().lower()
        ua = ev.user_agent or ""
        cached = framework_cache.get(ua)
        if cached is None:
            frameworks = tuple(
                sorted(
                    {
                        match.signature.id
                        for match in self.index.match_user_agent(ua)
                        if match.signature.category == "framework"
                    }
                )
            )
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
        ev.code_resources = sorted(
            {
                binding["code_resource"]
                for binding in self.correlation_bindings
                if ev.identity_assurance != "unverified"
                and binding["caller"] == caller_for_binding
                and binding["scope"] == ev.scope
            }
        )

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
            "azure-openai": get_path(
                rec,
                "identity.claims.oid",
                "identity.authorization.objectId",
                "properties.identity.claims.oid",
                "properties.identity.authorization.objectId",
            ),
            "vertex": get_path(
                rec,
                "protoPayload.authenticationInfo.principalEmail",
                "protoPayload.authenticationInfo.principalSubject",
            ),
            "openai-usage": get_path(
                rec,
                "api_key_id",
                "actor.api_key.id",
                "api_key.id",
                "actor.api_key.service_account.id",
                "actor.api_key.service_account.name",
            ),
            "anthropic-usage": rec.get("api_key_id"),
            "access-log": get_path(rec, "api_key", "authorization_hash", "consumer"),
            "generic": get_path(
                rec, *(_GENERIC_KEY_FIELDS if ev.caller_kind == "api-key" else _GENERIC_PRINCIPAL_FIELDS)
            ),
        }
        # Sentinels often appear in partial exports. A binding to one is not
        # workload specific even if it matches byte-for-byte.
        value = str(candidates.get(schema) or "").strip().lower()
        if value in {"", "anonymous", "unknown", "none", "null", "-", "gateway", "shared"}:
            return "unverified"
        return "operator-asserted" if schema in {"generic", "access-log"} else "provider-authenticated-field"

    def _is_llm_traffic(self, ev: Event) -> bool:
        # Static assets and probes are excluded first, except an inference
        # operation with a static suffix, which a suffix-matching router serves
        # as the endpoint (_is_static_or_probe).
        if _is_static_or_probe(ev.path):
            return False
        text = " ".join(x for x in (ev.host, ev.path) if x)
        if ev.path and re.search(
            r"/v1/(?:chat/completions|completions|responses|messages|embeddings|models|assistants|threads"
            r"|runs|audio|images|files|batches|realtime)"
            r"|/openai/deployments/|/generateContent|:generateContent|:streamGenerateContent"
            r"|/invoke(?:-with-response-stream)?|/converse|/mcp\b|/sse\b|/a2a\b|/agents?/|/predict\b"
            r"|/api/(?:chat|generate|tags)\b"
            # Cloudflare Workers AI inference on the general api.cloudflare.com REST API.
            r"|/accounts/[^/\s?#]+/ai/(?:run|v1)/",
            text,
        ):
            return True
        if ev.schema == "access-log" and ev.path:
            # A known provider/agent host identifies inference traffic even
            # when the operation is not an enumerated endpoint; static assets
            # and health probes were excluded above.
            return self._is_llm_host(ev.host)
        if ev.model:
            return True
        if ev.schema == "generic" and _provider_signature(self.index, ev.provider):
            if ev.tokens_in > 0 or ev.tokens_out > 0:
                return True
            if ev.path and re.search(
                r"(?:chat|completions|responses|messages|embeddings|generate|invoke|predict)", ev.path, re.I
            ):
                return True
        # Domain-only egress logs can identify a model provider. A path such as
        # /favicon.ico on that host is not an inference transaction.
        return bool(not ev.path and self._is_llm_host(ev.host))

    def _is_llm_host(self, host: str | None) -> bool:
        # Generic vendor hosts (a general REST API, a dataset site) carry hint weights below
        # the threshold and do not identify inference traffic by themselves.
        return bool(host) and any(
            m.weight >= _MIN_LLM_HOST_WEIGHT for m in self.index.match_domain(host or "")
        )

    def _untrusted_host_is_llm(self, ev: Event, rec: dict[str, Any]) -> bool:
        """Whether an excluded request would be LLM traffic with a host token a client could have written."""
        untrusted = rec.get(_UNTRUSTED_HOST_FIELD)
        return (
            ev.schema == "access-log"
            and ev.host is None
            and isinstance(untrusted, str)
            and self._is_llm_traffic(replace(ev, host=untrusted))
        )

    @staticmethod
    def _accumulate(
        callers: dict[str, _Caller],
        ev: Event,
        identity: str | None = None,
        retain_interval: bool = True,
        detail_budget: _DetailBudget | None = None,
    ) -> bool:
        if identity is None:
            identity = json.dumps([ev.caller, ev.scope], sort_keys=True)
        c = callers.get(identity)
        total_cost = (c.cost if c is not None else 0.0) + ev.cost
        if not math.isfinite(total_cost):
            # Validate before changing any caller counts, preserving atomic
            # accumulation when individually finite costs overflow in aggregate.
            raise ValueError("gateway cost total exceeds finite numeric range")
        # A valid offset-bearing ISO date can still fall outside datetime's
        # range when converted to UTC. Check both ends before retaining any
        # caller state; otherwise a rejected record poisons first/last seen
        # and can suppress this caller's valid neighboring observations.
        for moment in (ev.timestamp, ev.interval_end):
            if moment is not None:
                moment.astimezone(UTC)
        if c is None:
            c = callers[identity] = _Caller(ev.caller, ev.caller_kind, ev.caller_label, scope=dict(ev.scope))
        c.scope_redacted = c.scope_redacted or ev.scope_redacted
        c.events += ev.request_count
        c.records += 1
        if ev.aggregated:
            c.aggregate_records += 1
        c.schemas[ev.schema] += 1
        _record_activity(c, ev)
        interval_stored = _record_interval(c, ev, retain_interval)
        _record_distributions(c, ev, detail_budget)
        _record_behaviour(c, ev, detail_budget)
        _record_usage(c, ev, total_cost)
        _record_observation(c, ev, detail_budget)
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
        top_models, framework_user_agent = self._match_signatures(f, c)
        f.add_evidence(
            Evidence(
                signal=f"gateway:{c.kind}",
                description=(
                    f"{c.events} LLM request(s) by {c.kind} '{c.label}' to models "
                    f"{', '.join(top_models[:5]) or 'unknown'}"
                ),
                weight=_CALLER_KIND_WEIGHT[c.kind],
            )
        )
        _tool_use_evidence(f, c)
        self._behaviour_evidence(f, c)
        _temporal_evidence(f, c, framework_user_agent)
        _volume_evidence(f, c)
        _assign_owner(f, c)
        f.metadata.update(self._finding_metadata(c, source_id))
        f.id = "ss-" + hashlib.sha256(f"{f.compute_id()}|{source_id}".encode()).hexdigest()[:16]
        finalize(f, self.index)
        f.kind = Kind.GATEWAY_CALLER
        f.title = self._finding_title(f, c, top_models)
        return f

    def _behaviour_evidence(self, f: Finding, c: _Caller) -> None:
        """Agent indicators from operations, MCP endpoints and call cadence (no request bodies needed)."""
        summary: dict[str, Any] = {}
        operations = [AgentOperation(label, sig, n) for (label, sig), n in c.agent_operations.most_common()]
        if operations:
            for op in operations:
                if op.signature and self.index.get(op.signature) is not None:
                    f.add_framework(op.signature)
            total = sum(op.requests for op in operations)
            f.add_tag("agent-runtime-api")
            f.add_evidence(
                Evidence(
                    signal="gateway:agent-runtime-api",
                    description=(
                        f"{total} request(s) targeted hosted agent runtime invocation operations: "
                        + ", ".join(f"{op.label} ×{op.requests}" for op in operations[:5])
                        + "; request metadata does not establish successful execution or tool use"
                    ),
                    weight=0.7,
                )
            )
            f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
            summary["agent_operations"] = {op.label: op.requests for op in operations[:5]}
        mcp_hosts: dict[str, bool] = {}
        mcp_requests = 0
        for (host, path), n in c.mcp_candidates.items():
            if host not in mcp_hosts:
                mcp_hosts[host] = bool(host) and any(
                    m.signature.id == "protocol.mcp" for m in self.index.match_domain(host)
                )
            if is_mcp_request(path, mcp_hosts[host]):
                mcp_requests += n
        if mcp_requests:
            if self.index.get("protocol.mcp") is not None:
                f.add_framework("protocol.mcp")
            f.add_capability("tool-use")
            f.add_tag("mcp-client")
            f.add_evidence(
                Evidence(
                    signal="gateway:mcp-client",
                    description=(
                        f"{mcp_requests} request(s) to MCP server endpoints: an MCP client calling tools"
                    ),
                    weight=0.6,
                )
            )
            f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
            summary["mcp_requests"] = mcp_requests
        cadence = loop_cadence(c.call_times)
        # A browser session is a person typing, however fast the calls arrive.
        programmatic = c.browser_requests * 2 < c.events
        if cadence.loops and programmatic:
            f.add_tag("agent-loop")
            f.add_evidence(
                Evidence(
                    signal="gateway:agent-loop",
                    description=(
                        f"{cadence.loops} run(s) of {LOOP_MIN_CALLS}+ model calls at most "
                        f"{LOOP_MAX_GAP_SECONDS:.0f}s apart (longest {cadence.longest} calls, "
                        f"{cadence.share:.0%} of {cadence.calls} timed calls): agent-loop cadence; a batch "
                        "script or a chat front end making several calls per message looks the same"
                    ),
                    weight=0.45,
                )
            )
            # Cadence is compatible with ordinary batch scripts and chat front ends.
            # Keep the hint without promoting the caller to an agent by itself.
        if cadence.loops:
            summary["loop_cadence"] = {
                "loops": cadence.loops,
                "longest": cadence.longest,
                "calls_in_loops": cadence.calls_in_loops,
                "timed_calls": cadence.calls,
                "timed_calls_dropped": c.call_times_dropped,
                "browser_requests": c.browser_requests,
            }
        if summary:
            f.metadata["agent_behaviour"] = summary

    def _match_signatures(self, f: Finding, c: _Caller) -> tuple[list[str], bool]:
        """Apply model, host, user agent, provider and name signatures.

        Returns the caller's most used models and whether a user agent matched
        an agent framework or coding agent.
        """
        top_models = [m for m, _ in c.models.most_common(10)]
        f.models = top_models
        for m in top_models:
            apply_matches(f, self.index.match_model(m), weight_scale=0.5, indicator_filter=_caller_indicator)
        for h, _ in c.hosts.most_common(10):
            host_matches = self.index.match_domain(h)
            # A host is evidence of the one service it belongs to.
            service = host_service(host_matches)
            apply_matches(
                f,
                host_matches,
                weight_scale=0.6,
                # A managed service hostname establishes contact, not its
                # caller's tool use or agent execution.
                capabilities=service is None or service.signature.category != "cloud-service",
                indicator_filter=_service_indicator(service.signature.id if service is not None else None),
            )
        framework_user_agent = False
        for ua, _ in c.user_agents.most_common(10):
            ua_matches = self.index.match_user_agent(ua)
            apply_matches(f, ua_matches, weight_scale=1.0, indicator_filter=_caller_indicator)
            framework_user_agent = framework_user_agent or any(
                m.signature.category in {"framework", "coding-agent"} for m in ua_matches
            )
        for p, _ in c.providers.most_common(5):
            sid = _provider_signature(self.index, p)
            if sid:
                f.add_model_provider(sid)
        if c.label != REDACTED and not c.label.startswith(_OPAQUE_LABEL_PREFIXES):
            # An opaque pseudonym cannot carry a display name; skip the pass.
            apply_matches(
                f,
                self.index.match_name(c.label),
                weight_scale=0.6,
                capabilities=False,
                indicator_filter=_caller_indicator,
            )
        for u, _ in c.users.most_common(3):
            apply_matches(
                f,
                self.index.match_name(str(u)),
                weight_scale=0.4,
                capabilities=False,
                indicator_filter=_caller_indicator,
            )
        return top_models, framework_user_agent

    def _finding_metadata(self, c: _Caller, source_id: str) -> dict[str, Any]:
        """The caller's totals, bounded distributions and runtime observations."""
        return {
            "caller_kind": c.kind,
            "caller": c.label,
            "events": c.events,
            "records": c.records,
            "aggregate_records": c.aggregate_records,
            "usage_intervals": c.usage_intervals,
            "usage_intervals_dropped": c.usage_intervals_dropped,
            "usage_interval_requests_dropped": c.usage_interval_requests_dropped,
            "event_counting": (
                "Request totals within this source; aggregate bucket counts are preserved. Distinct sources "
                "are not deduplicated against each other."
            ),
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
            "classification_incomplete": any(
                c.distribution_events_dropped.get(name)
                for name in ("models", "providers", "hosts", "user_agents", "end_users", "teams")
            ),
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
            "runtime_source": {
                "id": source_id,
                "input": str(self.ctx.input_path or ""),
                "label": self.label,
                "schemas": sorted(c.schemas),
            },
            # With a per-scan key, another report's ID for this caller differs;
            # report comparison must not read that as a new or resolved caller.
            "identity_scope": self.identity_scope,
        }

    def _finding_title(self, f: Finding, c: _Caller, top_models: list[str]) -> str:
        """Caller kind, request volume, up to two frameworks and the top model."""
        what = "Agentic caller" if f.metadata.get("agent_indicators") else "LLM caller"
        fw = [
            self.index.get(s).name  # type: ignore[union-attr]
            for s in f.frameworks[:2]
            if self.index.get(s)
        ]
        return (
            f"{what} '{c.label}' ({c.kind}): {c.events} requests"
            + (f" via {', '.join(fw)}" if fw else "")
            + (f" to {top_models[0]}" if top_models else "")
        )
