# Gateway connectors

The gateway connector reconstructs LLM API callers from proxy and gateway
logs, identifying agentic patterns like high tool-use ratios, 24/7 activity,
and specific framework user-agent strings.

!!! info "Log-based"
    The gateway connector is inherently offline — it reads log files and
    exports from LLM proxies. It does not call any live API.

### `gateway.logs`
Auto-detects the schema per record: `litellm`, `portkey`, `kong`, `cloudflare`,
`helicone`, `langfuse`, `bedrock` (model invocation logs, CloudWatch export or
S3), `azure-openai` (diagnostic `RequestResponse`/`Audit`), `vertex` (Cloud
Audit Logs), `openai-usage`, `anthropic-usage`, `access-log` (nginx/envoy/ALB
combined or JSON, keeps only LLM/agent hosts and paths by default) or
`generic`. Each caller (API key, principal, service, user, user agent or IP)
becomes a finding with models, providers, frameworks (user agent
fingerprints), tool-use ratio, tool-call responses, temporal shape (24×7 /
night / weekend → `always-on`), volume, tokens, cost, errors. A gateway finding
for an anonymous, shared or user-agent/IP fallback caller cannot establish
the identity of a code workload in cross-layer correlation. Aggregate provider
usage exports count requests from provider counters; aggregate buckets are
not individual timestamped transaction events. Log fields for environment
and caller identity are evidence from the supplied export; assess the
producer and delivery chain before treating them as verified production facts.

For text (combined-format) access logs the host is read only from a
`host=`, `authority=`, `upstream_host=` or `server_name=` token that follows
the final quoted field, as in `... "ua" host=api.openai.com`. The request line,
referer, user agent and any other quoted field are client-controlled and are
never a host source; a line without such a trailing token has no host and is
kept only when its path is a known LLM endpoint. JSON and CSV access logs use
their structured host field. Trailer and logfmt tokens are read as logfmt: a
key must start a whitespace-separated token, so a client value such as
`args=a&host=b` or `/path?model=x` never becomes a field, quoted text without
a key is never parsed for fields, and an unterminated quote (for example a line
truncated inside the user agent) or a repeated key makes the line malformed
(incomplete). A host token in or before a quoted trailer field (`host="x"`, or
`host=x "203.0.113.7"`) is not trusted, because a gateway that does not escape
quotes lets a client write the same text through its user agent. When such a
token names an LLM host and would have made a request LLM traffic, the request
is not counted and a warning makes the scan incomplete; log the host as an
unquoted token after the last quoted field to attribute that traffic.
`;name=value` path parameters are removed before the static-asset and probe
test, and an inference operation with a static suffix
(`/v1/chat/completions.css`, which a suffix-matching router serves as the
endpoint) is not a static asset. Static files under an inference-like prefix
(`/agents/app.js`, `/v1/images/logo.png`) still are.

Directory inputs read files with a supported suffix (`.json`, `.jsonl`,
`.ndjson`, `.csv`, `.log`, `.txt`, `.gz`). Other files, such as rotated logs
(`access.log.1`, `access.log-20250901`) or `.zst` and `.bak` copies, are not
read: a warning lists up to five of them and the scan is incomplete. Negative
token counts or cost, and values above 10^15, are ignored with a warning that
also marks the scan incomplete, so a forged record cannot offset real usage.

Hour-of-day and weekday statistics (`night_share`, `weekend_share`,
`always-on`) are computed in UTC and the connector has no timezone option. A
single-timezone team sharing one unattributed key can look round-the-clock, so
read `always-on` against the organisation's local working hours.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
