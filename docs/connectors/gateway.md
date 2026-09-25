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


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
