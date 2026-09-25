# Project Nexus · ShadowScan

[![CI](https://github.com/aisecnomad/Project-Nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/aisecnomad/Project-Nexus/actions/workflows/ci.yml)
[![CodeQL](https://github.com/aisecnomad/Project-Nexus/actions/workflows/codeql.yml/badge.svg)](https://github.com/aisecnomad/Project-Nexus/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Docs](https://img.shields.io/badge/docs-source-blue.svg)](https://github.com/aisecnomad/Project-Nexus/tree/main/docs)

**ShadowScan is an open-source tool that discovers evidence of AI agents and related integrations, then reconciles it against your approved agent registry.**

It inspects six surfaces: code repositories, identity providers, LLM gateway logs,
low-code platforms, SaaS apps, and cloud accounts. It fingerprints frameworks and
model providers, scores findings, and reconciles discoveries against your approved
registry of
[Agent Cards](agent-card.yaml). Static code signals identify candidates; trusted runtime evidence is needed to establish execution.
Counts and severity labels need an analyst review before they drive enforcement.

Example findings (totals vary as signatures evolve):

```
$ shadowscan scan -c examples/shadowscan.offline.yaml --max-rows 5

╭──────────────────────────────── ShadowScan ────────────────────────────────╮
│ 101 findings  •  97 shadow (inventory: 3 registered agents)                 │
│ critical 14  high 52  medium 35  •  code 12 identity 19 cloud 27 …          │
╰────────────────────────────────────────────────────────────────────────────╯
 CRITICAL 100  SHADOW  saas      bot-app      GitHub App installed: claude
 CRITICAL 95  SHADOW  code      mcp-server   MCP configuration: .mcp.json (inline GitHub PAT, Zapier remote MCP, docker/postgres)
 CRITICAL 90  SHADOW  code      secret       LLM provider credential in services/research-agent/app/config.py
 HIGH     73  SHADOW  lowcode   agent        Copilot Studio agent: HR Helper
 MEDIUM   33  ops-provisioning-04  cloud  agent  Bedrock Agent: ops-provisioning-04   ← registered via its card's resource binding; owner from the AWS resource tag
```

## Why

Agents are no longer only Python scripts. 
They are Copilot Studio bots built by HR, `n8n` flows with an *AI Agent* node, OAuth grants to meeting note-takers,
Bedrock Agents provisioned by Terraform, MCP servers wired into every 
developer's editor, service principals with `Mail.ReadWrite` acting on behalf of nobody, and JWTs carrying an `act` claim. 
Each surface has its own discovery API and its own vocabulary. 
ShadowScan normalizes these observations into one finding model with evidence,
so investigators or auditors can ask: *Who owns this AI Agent? What can it do, and is it
registered in the registry supplied for this scan?*

| Observation | What it establishes | Next check |
|---|---|---|
| Source dependency, import, or configuration | A repository contains a potential integration. | Inspect executable code and deployment; comments, examples, and unused dependencies can mislead. |
| Cloud or SaaS resource | The collector observed a configured resource within its granted scope. | Check resource state and authenticated runtime telemetry before claiming execution. |
| Gateway event | The supplied log contains a request or tool-use signal. | Verify the log's origin, caller binding, and observation window before attributing it to a deployed agent. |
| `shadow: true` | No single explicit binding in the **supplied** inventory matched the finding. | Confirm the inventory's scope and freshness; an unmatched finding alone does not prove unauthorized use. |

Confidence is a heuristic evidence score, not a measured probability. Detection
quality depends on the repositories, providers, tenant permissions, and log
provenance in your environment. The bundled evaluation corpora are
author-written regression cases, including multi-file cases with documented
misses, not a field precision or recall estimate. See
[evaluation](docs/evaluation.md) and
[rollout acceptance](docs/production.md#rollout-acceptance) before using a risk
threshold as a production gate.

The [assurance results](docs/assurance-results.md) preserve the baseline and
subsequent results on a frozen, independently AI-labeled corpus of 42 public
files (30 negatives). [Read-only AWS and Slack canaries](docs/canaries.md)
validate named tenant controls when approved credentials are supplied; offline
replay does not establish live tenant acceptance.

Deployment evidence can be checked with the offline
[acceptance verifier](tools/acceptance/README.md). It requires current source and
signature identities, declared human-reviewed holdout evidence, and live tenant
receipts for supported live deployment scopes. It validates supplied evidence;
it cannot authenticate reviewer independence or manufacture tenant acceptance.
The [release-evidence workflow](.github/workflows/release.yml) builds a candidate
wheel and retains hashes, a runtime dependency SBOM, and provenance after the
selected commit passes CI and CodeQL. Artifact provenance does not establish deployment
acceptance, and the workflow does not publish a release.

## Surfaces & connectors

| Surface | Connectors | What is discovered |
|---|---|---|
| **Code** | `code.filesystem`, `code.github`, `code.gitlab` | Agent frameworks & LLM SDKs (deps, imports, idioms), MCP client/server configs, coding-agent configs (Claude Code sub-agents, Copilot custom agents, Cursor/Codex/Gemini CLI…), A2A agent cards, M365 declarative agents, CrewAI/LangGraph manifests, exported n8n/Flowise/Langflow/Dify flows, IaC provisioning Bedrock/Vertex/Foundry/OCI agents, container images, CI secret names, hard-coded provider keys (redacted) |
| **Identity** | `identity.okta`, `identity.entra`, `identity.google-workspace`, `identity.auth0`, `identity.jwt` | OAuth apps & consent grants to AI SaaS, service apps / service principals / managed identities with LLM or data permissions, app registrations that look like agents, JWT classification (human / service / workload / delegated-agent) with privilege and hygiene analysis |
| **Gateway** | `gateway.logs` | Callers reconstructed from LiteLLM, Portkey, Kong AI, Cloudflare AI Gateway, Helicone, Langfuse, Bedrock invocation logs, Azure OpenAI diagnostics, Vertex audit logs, OpenAI/Anthropic usage exports, nginx/envoy/ALB access logs or any JSON: models, frameworks (from user agents), tool-use ratio, 24x7 activity, volume, cost |
| **Low-code** | `lowcode.power-platform`, `lowcode.salesforce`, `lowcode.servicenow`, `lowcode.n8n`, `lowcode.make`, `lowcode.zapier`, `lowcode.workato` | Copilot Studio agents & topics, Power Automate/Apps using AI connectors, Agentforce planners/topics/actions, Einstein bots, prompt templates, Now Assist AI agents/tools/triggers, automation workflows with AI or agent steps |
| **SaaS** | `saas.slack`, `saas.microsoft-teams`, `saas.github-apps`, `saas.atlassian`, `saas.notion`, `saas.zoom`, `saas.generic` | Bots and apps with their scopes, pending install requests, Teams apps with bots / Copilot agents, GitHub Apps (AI reviewers, coding agents) and their permissions, Rovo/Marketplace apps, Notion integrations, Zoom approved and account-created Marketplace apps (approval does not prove installation), any CSV/JSON app inventory (CASB exports) |
| **Cloud** | `cloud.aws`, `cloud.gcp`, `cloud.azure`, `cloud.oci` | Bedrock Agents / AgentCore / Flows / Q Business / Lex, Lambda/ECS/SageMaker/Step Functions with LLM signals, Vertex AI Agent Engine, Dialogflow CX, Agentspace, Cloud Run/Functions, Azure OpenAI deployments, AI Foundry agents, Bot Service, Logic Apps, Function/Container apps, OCI Generative AI Agents, Digital Assistant, GenAI endpoints, IAM roles/bindings/policies granting LLM access, secret *names*, API keys, CloudTrail / audit-log LLM callers |

Connectors support **live** API collection, **offline** JSON/CSV/log exports,
or both; see the connector guide for the supported modes and provider scope.
Offline analysis can run in CI, on an analyst laptop or against a SIEM export.

## Frameworks & products recognised

215 signatures / 994 signals, YAML-defined with explicit opt-in overrides:

* **Orchestrators** – LangChain, LangGraph, Deep Agents, LlamaIndex, CrewAI, Google ADK, AWS Strands Agents, Microsoft Agent Framework, Semantic Kernel, AutoGen/AG2, Hugging Face smolagents, OpenAI Agents SDK, OpenAI Swarm, Claude Agent SDK, Pydantic AI, Vercel AI SDK, Mastra, Haystack, DSPy, Agno, Letta, MetaGPT, CAMEL, Griptape, Composio, Langroid, AgentScope, Swarms, AutoGPT, BabyAGI, BeeAI, Atomic Agents, Julep, Marvin, Mirascope, Qwen-Agent, NVIDIA NeMo Agent Toolkit, Dapr Agents, PraisonAI, SWE-agent, GPT Engineer, Open Interpreter, Chainlit, Prompt flow, Guardrails AI / NeMo Guardrails / LLM Guard, LangChain4j, Spring AI, Rig, LangChainGo, Genkit, Eino, M365 Agents SDK, Bot Framework, Teams AI, Cloudflare Agents, Inngest AgentKit, VoltAgent, CopilotKit/AG-UI, Rasa, Botpress, Browser Use, Stagehand, OpenHands, Nova Act, Anthropic computer use
* **Protocols** – MCP (all client config locations, servers, registries, remote MCP hosts), A2A agent cards, ACP, tool/function-calling request shapes, ChatGPT plugin/GPT Action manifests
* **Coding agents** – Claude Code, GitHub Copilot coding agent, Cursor, Windsurf, Cline, Roo, OpenAI Codex, Gemini CLI/Jules, Amazon Q/Kiro, Goose, Aider, Continue, Cody/Amp, Junie, AGENTS.md, PR review bots (CodeRabbit, Sweep, Ellipsis, Greptile, Qodo…)
* **Platforms/gateways** – LiteLLM, Portkey, Kong AI Gateway, Helicone, OpenAI AgentKit, Dify, Flowise, Langflow, n8n, Make, Zapier, Workato, Copilot Studio, Power Platform AI connectors, M365 declarative agents, Agentforce, Now Assist, IBM watsonx Orchestrate, Retool, Open WebUI/LibreChat/AnythingLLM, Coze/Relevance/Lindy/Vellum…
* **Model providers** – OpenAI, Anthropic, Gemini API, Vertex AI, Bedrock, Azure OpenAI, Mistral, Cohere, Groq, Together, Fireworks, OpenRouter, Ollama, vLLM, SGLang, llama.cpp, LM Studio, LocalAI, Llama Stack, Meta Llama API, Hugging Face, xAI, DeepSeek, Alibaba DashScope/Qwen, Moonshot/Kimi, AI21, Perplexity, Replicate, Cerebras, SambaNova, NVIDIA NIM, OCI Generative AI, watsonx, Databricks, Cloudflare Workers AI, Snowflake Cortex (deps, imports, endpoints, env vars, user agents, model IDs, **key formats**)
* **Observability/memory/sandboxes** – LangSmith, Langfuse, Phoenix, AgentOps, Traceloop, Weave, Braintrust…, Mem0, Zep, vector stores, E2B, Daytona, web search/scrape tool providers
* **AI SaaS as OAuth apps** – ChatGPT, Claude, Gemini, Copilot, Perplexity, Mistral Le Chat, DeepSeek, Qwen, Kimi, Grok, Poe, Character.ai, Glean, meeting note-takers (Otter, Fireflies, Read.ai, Fathom, tl;dv, Gong…), writing/coding/automation/research/media products, browser AI extensions
* **Permission policies** – privileged, data-access and LLM-access scope classes across Graph, Google, Okta, Slack, GitHub, GitLab, Salesforce, Atlassian, Zoom, Notion, HubSpot, AWS IAM, Azure RBAC, GCP IAM, OCI

`shadowscan signatures list` shows everything; `shadowscan signatures test <value>`
tells you what a package, host, user agent, model id, scope or file path maps to.


## Install

Select the full 40-character commit SHA after reviewing its changes and CI
results. Set `SHADOWSCAN_REVISION` to that SHA; do not use a moving branch or an
unpublished tag in a deployment job. Install the core scanner **or** the cloud
extra in a clean virtual environment:

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
python -m pip install "git+https://github.com/aisecnomad/Project-Nexus.git@${SHADOWSCAN_REVISION}"
```

For cloud collection, install the extra from the same reviewed revision:

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
python -m pip install "shadowscan[cloud] @ git+https://github.com/aisecnomad/Project-Nexus.git@${SHADOWSCAN_REVISION}"
```

The current `0.1.1` source version is an unreleased candidate; the version
string does not imply a published or signed artifact. These VCS installs resolve
transitive dependencies at install time. For deployment, use the locked install
below. Python 3.11+ is required; CI covers 3.11, 3.12, and 3.13. Core dependencies
include `click`, `rich`, `PyYAML`, `requests`, `urllib3`,
`PyJWT[crypto]` and `regex`. Cloud SDKs are optional extras; every cloud connector
also accepts an offline record dump.

For deployment on Linux x86_64 with Python 3.11 to 3.13, the checked-in
`requirements.lock` pins and hashes the core and all cloud runtime dependencies.
Build and retain a wheel from the selected commit; see
[locked installs and release evidence](docs/production.md#install-from-a-reviewed-revision).
The [consumer GitHub Action example](examples/github-action-code-scan.yml) requires
the repository variable `SHADOWSCAN_REVISION` to hold that reviewed full SHA;
it fails until the variable is set.

## Quick start

```bash
# 1. Scan a checkout (or your whole ~/src) — no credentials needed
shadowscan code . --inventory agent-card.yaml

# 2. Try every connector against the bundled fixtures (offline demo)
shadowscan scan -c examples/shadowscan.offline.yaml --format html -o report.html

# 3. Real estate: one config, live connectors, secrets from the environment
shadowscan scan -c shadowscan.yaml --format sarif -o shadowscan.sarif

# 4. Single connector, ad-hoc
shadowscan run identity.entra --set tenant_id=$AZURE_TENANT_ID
shadowscan run cloud.aws --set regions=us-east-1,eu-west-1 --dump-records ./exports
# Read exports/manifest.json and use the exported filename for this instance:
shadowscan run cloud.aws --input ./exports/0001-cloud_aws.jsonl   # re-analyse later, offline

# 5. Logs and tokens
shadowscan gateway litellm-spend.jsonl bedrock-invocations/ egress-proxy.log
shadowscan jwt --file ./token.jwt --jwks-url https://acme.okta.com/oauth2/default/v1/keys

# 6. Register what you found
shadowscan inventory stubs report.json -o inventory/pending/    # capability-card stubs for shadow agents
shadowscan diff last-week.json today.json                        # what is new / resolved/changed
```

Steps 1 and 2 need a repository checkout: `agent-card.yaml`, `examples/` and
the sample exports under `tests/fixtures/` are not shipped in the wheel. Steps
5 and 6 use your own logs, token, and an earlier JSON report
(`--format json -o report.json`); sample gateway logs live under
`tests/fixtures/gateway/` in a checkout.

### Configuration

```yaml
# shadowscan.yaml
inventory: [./inventory]              # Agent Capability Cards, agents.yaml or CSV
signatures: [./custom-signatures]     # optional: extra packs; overrides require opt-in
options:
  plugins: []                        # exact names of reviewed third-party connectors
  allow_signature_override: false
  allow_private_origin: false        # opt in only for trusted private HTTPS APIs
  allow_credential_mixing: false     # separate repository scans from live tenant access
  allow_instance_credentials: false # cloud metadata credentials require explicit opt-in
  connector_timeout_seconds: 120    # soft deadline; also enforce a host job timeout
  parallel: 4                        # worker threads; use 1-2 for CPU-bound offline scans
  min_confidence: 0.3
  dump_records: ./exports             # sanitized records for offline re-runs; excludes JWTs
connectors:
  - name: identity.entra
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: identity.google-workspace
    service_account_file: ./sa.json
    admin_email: admin@acme.com
  - name: gateway.logs
    label: litellm-prod                # names this entry in --only, progress and exports
    input: ./exports/litellm-spend.jsonl
  - name: lowcode.power-platform
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: saas.slack
    enabled: false                     # keep the entry, skip it on this run
    token: ${SLACK_TOKEN}
  - name: cloud.aws
    regions: [us-east-1, eu-west-1]
    cloudtrail_days: 7
```

`shadowscan connectors` lists every connector with its configuration keys and
required extras; `shadowscan connectors --json` also includes each connector's
offline export formats. Every entry also accepts `enabled` (default true) and
`label` (a distinct id when a connector runs more than once). See
[docs/connectors.md](docs/connectors.md) for entry keys, credentials and
least-privilege scopes per connector. Run repository scans in
a separate job/configuration from live tenant collection. Mixing these credential
boundaries requires an explicit `allow_credential_mixing` exception; keep the
separation for untrusted repositories. Cloud instance-metadata credentials require
`allow_instance_credentials: true`; use an explicit audit identity by default.

Use `--incremental` to reuse completed scans of unchanged local checkouts and
static cloud exports. Live APIs and gateway logs are refreshed on every run.
Configure `gateway.logs.correlation_bindings` to link a code resource to a
specific gateway caller and scope; matching timestamped framework fingerprints
then appear in `metadata.runtime_activity`, including the observation window
and any production label claimed in the logs. Treat caller and environment
fields according to the export's provenance; ShadowScan does not authenticate
the source of an imported log. See [scan state and runtime correlation](docs/scanning.md)
for configuration, limitations, and migration guidance.

Oversize files that the scanner would inspect and symbolic links that leave the
scan root make coverage incomplete (exit 3) by default. `--strict-coverage`
(`strict_coverage: true`) records them as errors instead of warnings; explicitly
declared `oversize_skip_globs` remain warnings. In-root file links stay complete
only when their real targets are included and analyzed; directory links are
incomplete because their alias paths are not scanned. Evidence found only in test or fixture code
cannot establish an agent unless `--include-tests` is set.

The CLI exits **3** for incomplete scans, **2** for a completed scan that reaches
`--fail-on`, and **0** for a completed scan that passes. SARIF records incomplete
scans as unsuccessful, while preserving findings from successfully assessed inputs.
Enable `--fail-on` only after a [frozen, independently adjudicated holdout](docs/evaluation.md#gate-a-frozen-holdout)
and [read-only tenant canary](docs/evaluation.md#read-only-tenant-canary-procedure)
establish an acceptable threshold for that environment. A complete static scan
does not prove that an agent executed or that every eligible resource was collected.
The CLI normally exits promptly after a connector deadline even when a blocked
worker cannot be joined. A filesystem publication already in progress can still
delay timeout handling; enforce a host job timeout for hard limits.
Confidence thresholds must be finite numbers from 0 to 1; invalid CLI or YAML
values stop the scan before the risk gate runs.

Git history enrichment is disabled by default. Set connector `use_git: true`
only for a reviewed local checkout when author/history metadata is needed;
metadata commands cannot fetch missing objects. Every explicit `--only` selector
must match an enabled connector name or label. Unsupported records and saved API
error responses cannot establish an empty, successful inventory.

After upgrading from reports without the v2 finding-identity schema, regenerate
your comparison baseline. Findings now keep their identity when inferred classification changes;
legacy baselines cannot establish resolution under the new identity schema.
See [deployment and migration](docs/production.md) for the rollout checks.

## What a finding looks like

```json
{
  "id": "ss-3f9c1e2a7b4d8c10",
  "surface": "cloud", "connector": "cloud.aws", "kind": "agent",
  "title": "Bedrock AgentCore runtime: strands_support_agent",
  "resource": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt1",
  "account": "123456789012", "region": "us-east-1", "owner": null,
  "frameworks": ["cloud.aws-bedrock-agents"], "model_providers": ["provider.openai"],
  "capabilities": ["tool-use"], "tags": ["plaintext-credential", "secret-in-env"],
  "confidence": 1.0, "likelihood": "confirmed",
  "shadow": true, "registry_match": null,
  "risk": {"score": 90, "level": "critical", "factors": [
      {"id": "shadow", "description": "not present in the sanctioned agent inventory", "weight": 25},
      {"id": "tag:plaintext-credential", "description": "plaintext credential in environment/configuration", "weight": 25},
      {"id": "no-owner", "description": "no identifiable owner", "weight": 10}, "..."]},
  "evidence": [
      {"signal": "aws:agentcore-runtime", "description": "AgentCore runtime 'strands_support_agent' (READY) role arn:aws:iam::…", "weight": 0.97},
      {"signal": "secret: provider.openai", "description": "Plaintext OpenAI API key in environment variable OPENAI_API_KEY: sk-p…KLMN", "weight": 0.6}],
  "metadata": {"status": "READY", "protocol": "HTTP", "network": "PUBLIC", "related": ["ss-…"]}
}
```

* **confidence** combines evidence weights with noisy-OR. Correlated source evidence is grouped first, so repeated matches cannot inflate the score. It is a heuristic evidence score, not a calibrated probability or proof that an agent executed.
* **risk** is additive and explainable: kind, capabilities (code-exec, autonomous, SaaS actions…), permission classes, credential exposure, exposure/auditability tags, registration status, ownership — scaled by confidence. The listed factors always add up to `score`; confidence scaling and the 0–100 bounds appear as factors.
* **danger_score** is the same model without the governance factors (inventory registration and ownership): what the agent can do, independent of whether anyone approved it. Set `options.risk_basis: danger` to base `level` and `--fail-on` on it, and `options.risk_weights` to tune weights (see [Risk policy](#risk-policy)).
* **shadow** is `true` unless exactly one inventory entry matches an explicit resource pattern and its configured scope restrictions; names only suggest entries for review. An approved entry lends its owner to the finding.
* **related** links findings across surfaces (the Terraform that provisions an agent ↔ the agent in the account ↔ the role calling Bedrock ↔ the CloudTrail caller).

Outputs: `table` (terminal), `json`, `sarif` (GitHub code scanning; code
findings carry file: line locations), `csv`, `markdown`, `html` (self-contained,
filterable, with evidence drill-down).

### Risk policy

```yaml
options:
  risk_basis: danger          # combined (default) | danger: level from capabilities, not registration
  risk_weights:               # integers -100..100; unknown groups, kinds or governance keys are rejected
    capabilities: {code-exec: 25}
    tags: {meeting-bot: 20}
    providers: {provider.deepseek: 20}
    kinds: {agent: 20}
    governance: {shadow: 15, no-owner: 5, registered: -10}
```

## Sanctioned inventory

Drop your Agent Cards in a directory. The card's `metadata.agent_id`
identifies the registration; explicit `discovery.resources` bind it to concrete resources:

```yaml
metadata:
  agent_id: "ops-provisioning-04"
  owner_team: "Platform-Engineering"
discovery:
  resources:
    - "arn:aws:bedrock:*:123456789012:agent/AGENT1"
    - "github: acme/infra-agents"
  names: ["ops provisioning agent"]
```

Simple `agents.yaml` lists and CSV work too. `shadowscan inventory stubs`
turns shadow findings into card skeletons for review. See
[docs/inventory.md](docs/inventory.md).

## Extending

* **Signatures** are YAML; add a pack directory with `--signatures` / `signatures:`
  to add products. Replacing built-in signatures requires explicit opt-in. Schema and authoring guide in
  [docs/signatures.md](docs/signatures.md).
* **Connectors** implement `collect()` (live) and `analyze()` (records → findings)
  and register through the `shadowscan.connectors` entry-point group. Execution
  requires an exact-name `options.plugins` allowlist entry. See
  [docs/architecture.md](docs/architecture.md).

## Development

```bash
pip install -e ".[cloud,dev]"
python -m shadowscan.signatures.validate
ruff check shadowscan tests tools
mypy shadowscan tools/evaluation tools/canaries tools/acceptance tools/release
pip-audit --progress-spinner off
pytest -q --cov=shadowscan --cov-fail-under=80
shadowscan scan -c examples/shadowscan.offline.yaml
```

Install the `cloud` extra for the same connector coverage as CI. Tests that
require missing optional SDKs can be skipped, so a core-only run does not validate all
connectors. See [CONTRIBUTING.md](CONTRIBUTING.md#getting-started).

## Community and contributing

Contributions are welcome from developers, security practitioners, technical
writers and people testing the scanner against their own authorized data.
A small documentation fix or a reproducible false-positive report is useful.

| I want to… | Start here |
|---|---|
| Learn, ask a question or troubleshoot a scan | [Support guide](SUPPORT.md) |
| Report a bug or suggest a connector | [Issue forms](https://github.com/aisecnomad/Project-Nexus/issues/new/choose) |
| Make a first contribution | [Contributor guide](CONTRIBUTING.md) |
| Understand decisions, review and release requirements | [Governance](GOVERNANCE.md) |
| Report a vulnerability privately | [Security policy](SECURITY.md#reporting) |
| Understand participation standards or report harmful conduct | [Code of conduct](CODE_OF_CONDUCT.md) |

Use synthetic, minimal examples in public reports. Scan results can contain
credentials, personal data, and sensitive inventory even after redaction.

## Safety notes

* Known credential formats, sensitive configuration fields, and credential-bearing URLs are **redacted** before findings or sanitized record exports are persisted. Redaction cannot identify every arbitrary secret; reports still contain security-sensitive inventory data.
* Secret stores (Secrets Manager, Key Vault, Secret Manager, OCI Vault) are read for **names only**.
* JWTs are never persisted; findings reference a truncated hash.
* Built-in collectors inspect provider resources using read operations. Scope the audit identity to the documented read permissions and review any enabled third-party plugin separately.

Deployment behavior, migration options, and limits are documented in
[SECURITY.md](SECURITY.md) and [docs/production.md](docs/production.md).

License: Apache-2.0.
