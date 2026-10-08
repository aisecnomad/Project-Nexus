# Gateway connectors

The gateway connector reconstructs LLM API callers from proxy and gateway
logs, identifying agentic patterns like high tool-use ratios, 24/7 activity,
and specific framework user-agent strings.

!!! info "Log-based"
    The gateway connector is inherently offline — it reads log files and
    exports from LLM proxies. It does not call any live API.

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

## `gateway.logs`
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

A caller is titled **Agentic caller** when at least one agent indicator
holds: requests carried tool definitions or responses invoked tools; a user
agent belongs to a coding agent or agent framework; requests targeted a hosted
agent invocation operation; requests reached an MCP endpoint (`/mcp`, or `/sse`
and `/messages` on a known MCP host; tag `mcp-client`); or corroborated
round-the-clock activity.

Hosted invocation classification (tag `agent-runtime-api`) requires an HTTP
`POST`, an exact invocation path, and the matching service host **from the same
record**. Supported operations are Bedrock `InvokeAgent`, AgentCore runtime
invocations, OpenAI/Azure Assistants run creation or tool-output submission,
Vertex AI Agent Engine queries, and Dialogflow CX session invocation. Listing,
reading, creating or deleting assistant definitions and updating/cancelling
runs do not count. Paths alone, a provider name, an unknown upstream host or a
missing method do not prove invocation. Native Vertex audit logs can instead
identify an exact `ReasoningEngineExecutionService.QueryReasoningEngine` or
`StreamQueryReasoningEngine` RPC on the `aiplatform.googleapis.com` service.
Requests to these operations establish attempted invocation; they do not prove
successful execution or add `tool-use` capability without separate tool
evidence. In particular, a 403 remains a failed attempt.

HTTP methods are read from `request_method`, `method`, `http_method`,
`cs-method`, `http.method`, `request.method`, `httpRequest.requestMethod`,
`proxy_server_request.method`, or `properties.httpMethod`. Access logs can
also retain the method from an HTTP request line. Preserve the provider
hostname in `host` when exporting gateway/proxy records; the proxy's own host
does not identify an upstream provider. Absolute URLs, custom domains, private
endpoint aliases, and unrecognized route prefixes are not mapped to these
operations. Export a path and the canonical upstream host; unsupported aliases
remain ordinary service-contact evidence. Managed cloud-service host matches
alone also do not add agent or tool-use indicators.

Operation matching follows the provider request contracts: [Bedrock
InvokeAgent](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html),
[AgentCore InvokeAgentRuntime](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_InvokeAgentRuntime.html),
[AgentCore service endpoints](https://docs.aws.amazon.com/general/latest/gr/bedrock_agentcore.html),
and the [Vertex execution service](https://docs.cloud.google.com/dotnet/docs/reference/Google.Cloud.AIPlatform.V1/latest/Google.Cloud.AIPlatform.V1.ReasoningEngineExecutionServiceClient).

A programmatic caller making runs of three or more model calls at distinct
times at most 30 seconds apart receives the informational `agent-loop` tag.
Simultaneous calls count once. Cadence alone does **not** promote a caller to
**Agentic caller**: a batch script or chat front end can produce the same
pattern. Management operations and HTTP requests without a supported
generation path and `POST` method are excluded. Native model records may
supply a model and native operation instead. A caller whose requests mostly
carry a browser user agent is never tagged as a loop. Inspect
`metadata.agent_behaviour` alongside corroborating evidence.

Calling a model API is LLM use: the domains
and names of AI SaaS apps (`*.openai.com`, `*.anthropic.com`) do not make a
caller agentic. A product name matched in a key alias or a user name is a
hint, never an agent indicator, and a host counts only through the one
service it belongs to (its highest-weight signature), so browsing
`chatgpt.com` is AI use while traffic to `api2.cursor.sh` is a coding agent.

Directory inputs read files with a supported suffix (`.json`, `.jsonl`,
`.ndjson`, `.csv`, `.log`, `.txt`, `.gz`). Other files, such as rotated logs
(`access.log.1`, `access.log-20250901`) or `.zst` and `.bak` copies, are not
read: a warning lists up to five of them and the scan is incomplete. Negative
token counts or cost, and values above 10^15, are ignored with a warning that
also marks the scan incomplete, so a forged record cannot offset real usage.

Hour-of-day and weekday statistics (`night_share`, `weekend_share`,
`always-on`) are computed in UTC and the connector has no timezone option. A
single-timezone team sharing one unattributed key can look round-the-clock, so
read `always-on` against the organization's local working hours.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
