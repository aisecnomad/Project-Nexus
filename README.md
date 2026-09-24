# Project Nexus · ShadowScan

**ShadowScan finds unregistered AI agents running in your non-production and production environments. ****

It sweeps the six places agents hide — code repositories, identity providers,
LLM gateway logs, low-code platforms, SaaS apps, and cloud accounts. 
Fingerprints the frameworks and model providers they use, scores their risk, and reconciles
every discovery against your sanctioned inventory of
[Agent Cards](agent-card.yaml).*.

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
 MEDIUM   33  ops-provisioning-04  cloud  agent  Bedrock Agent: ops-provisioning-04   ← registered, owner inherited from its card
```

## Why

Agents are no longer only Python scripts. 
They are Copilot Studio bots built by HR, `n8n` flows with an *AI Agent* node, OAuth grants to meeting note-takers,
Bedrock Agents provisioned by Terraform, MCP servers wired into every 
developer's editor, service principals with `Mail.ReadWrite` acting on behalf of nobody, and JWTs carrying an `act` claim. 
Each surface has its own discovery API and its own vocabulary. 
ShadowScan normalizes all of them into one finding model with evidence, so you can answer three questions for every
agent in the estate: *who owns it, what can it do, and did anyone approve it?*

## Surfaces & connectors

| Surface | Connectors | What is discovered |
|---|---|---|
| **Code** | `code.filesystem`, `code.github`, `code.gitlab` | Agent frameworks & LLM SDKs (deps, imports, idioms), MCP client/server configs, coding-agent configs (Claude Code sub-agents, Copilot custom agents, Cursor/Codex/Gemini CLI…), A2A agent cards, M365 declarative agents, CrewAI/LangGraph manifests, exported n8n/Flowise/Langflow/Dify flows, IaC provisioning Bedrock/Vertex/Foundry/OCI agents, container images, CI secret names, hard-coded provider keys (redacted) |
| **Identity** | `identity.okta`, `identity.entra`, `identity.google-workspace`, `identity.auth0`, `identity.jwt` | OAuth apps & consent grants to AI SaaS, service apps / service principals / managed identities with LLM or data permissions, app registrations that look like agents, JWT classification (human / service / workload / delegated-agent) with privilege and hygiene analysis |
| **Gateway** | `gateway.logs` | Callers reconstructed from LiteLLM, Portkey, Kong AI, Cloudflare AI Gateway, Helicone, Langfuse, Bedrock invocation logs, Azure OpenAI diagnostics, Vertex audit logs, OpenAI/Anthropic usage exports, nginx/envoy/ALB access logs or any JSON: models, frameworks (from user agents), tool-use ratio, 24x7 activity, volume, cost |
| **Low-code** | `lowcode.power-platform`, `lowcode.salesforce`, `lowcode.servicenow`, `lowcode.n8n`, `lowcode.make`, `lowcode.zapier`, `lowcode.workato` | Copilot Studio agents & topics, Power Automate/Apps using AI connectors, Agentforce planners/topics/actions, Einstein bots, prompt templates, Now Assist AI agents/tools/triggers, automation workflows with AI or agent steps |
| **SaaS** | `saas.slack`, `saas.microsoft-teams`, `saas.github-apps`, `saas.atlassian`, `saas.notion`, `saas.zoom`, `saas.generic` | Bots and apps with their scopes, pending install requests, Teams apps with bots / Copilot agents, GitHub Apps (AI reviewers, coding agents) and their permissions, Rovo/Marketplace apps, Notion integrations, Zoom meeting bots, any CSV/JSON app inventory (CASB exports) |
| **Cloud** | `cloud.aws`, `cloud.gcp`, `cloud.azure`, `cloud.oci` | Bedrock Agents / AgentCore / Flows / Q Business / Lex, Lambda/ECS/SageMaker/Step Functions with LLM signals, Vertex AI Agent Engine, Dialogflow CX, Agentspace, Cloud Run/Functions, Azure OpenAI deployments, AI Foundry agents, Bot Service, Logic Apps, Function/Container apps, OCI Generative AI Agents, Digital Assistant, GenAI endpoints, IAM roles/bindings/policies granting LLM access, secret *names*, API keys, CloudTrail / audit-log LLM callers |

Every connector runs **live** (API credentials) or **offline** (a JSON/CSV/log
export, or a record dump from a previous live run), so the same detection
logic works in a CI job, on an analyst laptop, or from a SIEM export.

## Frameworks & products recognised

178 signatures / 790 signals, YAML-defined with explicit opt-in overrides:

* **Orchestrators** – LangChain, LangGraph, LlamaIndex, CrewAI, Google ADK, AWS Strands Agents, Microsoft Agent Framework, Semantic Kernel, AutoGen/AG2, Hugging Face smolagents, OpenAI Agents SDK, OpenAI Swarm, Claude Agent SDK, Pydantic AI, Vercel AI SDK, Mastra, Haystack, DSPy, Agno, Letta, MetaGPT, CAMEL, Griptape, Composio, Langroid, AgentScope, Swarms, AutoGPT, BabyAGI, BeeAI, Atomic Agents, Julep, Marvin, Mirascope, LangChain4j, Spring AI, Rig, LangChainGo, Genkit, Eino, M365 Agents SDK, Bot Framework, Teams AI, Cloudflare Agents, Inngest AgentKit, VoltAgent, CopilotKit/AG-UI, Rasa, Botpress, Browser Use, Stagehand, OpenHands, Nova Act, Anthropic computer use
* **Protocols** – MCP (all client config locations, servers, registries, remote MCP hosts), A2A agent cards, ACP, tool/function-calling request shapes, ChatGPT plugin/GPT Action manifests
* **Coding agents** – Claude Code, GitHub Copilot coding agent, Cursor, Windsurf, Cline, Roo, OpenAI Codex, Gemini CLI/Jules, Amazon Q/Kiro, Goose, Aider, Continue, Cody/Amp, Junie, AGENTS.md, PR review bots (CodeRabbit, Sweep, Ellipsis, Greptile, Qodo…)
* **Platforms/gateways** – LiteLLM, Portkey, Kong AI Gateway, Helicone, OpenAI AgentKit, Dify, Flowise, Langflow, n8n, Make, Zapier, Workato, Copilot Studio, Power Platform AI connectors, M365 declarative agents, Agentforce, Now Assist, Retool, Open WebUI/LibreChat/AnythingLLM, Coze/Relevance/Lindy/Vellum…
* **Model providers** – OpenAI, Anthropic, Gemini API, Vertex AI, Bedrock, Azure OpenAI, Mistral, Cohere, Groq, Together, Fireworks, OpenRouter, Ollama, vLLM, Hugging Face, xAI, DeepSeek, Perplexity, Replicate, Cerebras, SambaNova, NVIDIA NIM, OCI Generative AI, watsonx, Databricks, Cloudflare Workers AI, Snowflake Cortex (deps, imports, endpoints, env vars, user agents, model IDs, **key formats**)
* **Observability/memory/sandboxes** – LangSmith, Langfuse, Phoenix, AgentOps, Traceloop, Weave, Braintrust…, Mem0, Zep, vector stores, E2B, Daytona, web search/scrape tool providers
* **AI SaaS as OAuth apps** – ChatGPT, Claude, Gemini, Copilot, Perplexity, Glean, meeting note-takers (Otter, Fireflies, Read.ai, Fathom, tl;dv, Gong…), writing/coding/automation/research/media products, browser AI extensions
* **Permission policies** – privileged, data-access and LLM-access scope classes across Graph, Google, Okta, Slack, GitHub, GitLab, Salesforce, Atlassian, Zoom, Notion, HubSpot, AWS IAM, Azure RBAC, GCP IAM, OCI

`shadowscan signatures list` shows everything; `shadowscan signatures test <value>`
tells you what a package, host, user agent, model id, scope or file path maps to.

## Install

```bash
pip install "git+https://github.com/aisecnomad/Project-Nexus.git@31fbf62c1ea9e8df64ced753cf237a3dcff65ef0"           # core (code, identity, gateway, low-code, SaaS via REST)
pip install "shadowscan[cloud] @ git+https://github.com/aisecnomad/Project-Nexus.git@31fbf62c1ea9e8df64ced753cf237a3dcff65ef0"   # + boto3, google-auth, azure-identity, oci
```

These examples pin the reviewed implementation. Python 3.11+ is required. Core
dependencies include `click`, `rich`, `PyYAML`, `requests`, `urllib3`,
`PyJWT[crypto]` and `regex`. Cloud SDKs are optional extras; every cloud connector
also accepts an offline record dump.

## Quick start

```bash
# 1. Scan a checkout (or your whole ~/src) — no credentials needed
shadowscan code . --inventory agent-card.yaml

# 2. Try every connector against the bundled fixtures (offline demo)
shadowscan scan -c examples/shadowscan.offline.yaml --format html -o report.html

# 3. Real estate: one config, live connectors, secrets from the environment
shadowscan scan -c shadowscan.yaml --format sarif -o shadowscan.sarif --fail-on high

# 4. Single connector, ad-hoc
shadowscan run identity.entra --set tenant_id=$AZURE_TENANT_ID
shadowscan run cloud.aws --set regions=us-east-1,eu-west-1 --dump-records ./exports
# Read exports/manifest.json and use the exported filename for this instance:
shadowscan run cloud.aws --input ./exports/0001-cloud_aws.jsonl   # re-analyse later, offline

# 5. Logs and tokens
shadowscan gateway litellm-spend.jsonl bedrock-invocations/ egress-proxy.log
shadowscan jwt "$TOKEN" --jwks-url https://acme.okta.com/oauth2/default/v1/keys

# 6. Register what you found
shadowscan inventory stubs report.json -o inventory/pending/    # capability-card stubs for shadow agents
shadowscan diff last-week.json today.json                        # what is new / resolved/changed
```

### Configuration

```yaml
# shadowscan.yaml
inventory: [./inventory]              # Agent Capability Cards, agents.yaml or CSV
signatures: [./custom-signatures]     # optional: extra packs; overrides require opt-in
options:
  plugins: []                        # exact names of reviewed third-party connectors
  allow_signature_override: false
  allow_private_origin: false        # opt in only for trusted private HTTPS APIs
  min_confidence: 0.3
  fail_on: high
  dump_records: ./exports             # sanitized records for offline re-runs; excludes JWTs
connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
  - name: identity.entra
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: identity.google-workspace
    service_account_file: ./sa.json
    admin_email: admin@acme.com
  - name: gateway.logs
    input: ./exports/litellm-spend.jsonl
  - name: lowcode.power-platform
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: saas.slack
    token: ${SLACK_TOKEN}
  - name: cloud.aws
    regions: [us-east-1, eu-west-1]
    cloudtrail_days: 7
```

`shadowscan connectors` lists every connector with its configuration keys,
required extras, and offline format. See [docs/connectors.md](docs/connectors.md)
for credentials and least-privilege scopes per connector.

Use `--incremental` to reuse completed scans of unchanged local checkouts and
static cloud exports. Live APIs and gateway logs are refreshed on every run.
Configure `gateway.logs.correlation_bindings` to link a code resource to a
specific gateway caller and scope; matching timestamped framework fingerprints
then appear in `metadata.runtime_activity`, including the observation window
and any production label claimed in the logs. Treat caller and environment
fields according to the export's provenance; ShadowScan does not authenticate
the source of an imported log. See [scan state and runtime correlation](docs/scanning.md)
for configuration, limitations, and migration guidance.

The CLI exits **3** for incomplete scans, **2** for a completed scan that reaches
`--fail-on`, and **0** for a completed scan that passes. SARIF records incomplete
scans as unsuccessful, while preserving findings from successfully assessed inputs.
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

* **confidence** is a noisy-OR of evidence weights — how sure we are this is an agent / agent enabler (not just "a project that imports `openai`").
* **risk** is additive and explainable: kind, capabilities (code-exec, autonomous, SaaS actions…), permission classes, credential exposure, exposure/auditability tags, registration status, ownership — scaled by confidence.
* **shadow** is `true` unless exactly one inventory entry matches an explicit resource pattern and its configured scope restrictions; names only suggest entries for review. An approved entry lends its owner to the finding.
* **related** links findings across surfaces (the Terraform that provisions an agent ↔ the agent in the account ↔ the role calling Bedrock ↔ the CloudTrail caller).

Outputs: `table` (terminal), `json`, `sarif` (GitHub code scanning; code
findings carry file: line locations), `csv`, `markdown`, `html` (self-contained,
filterable, with evidence drill-down).

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

Simple `agents.yaml` lists and CSV work too. `shadowscan inventory stubs.`
Turns shadow findings into card skeletons for review. See
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
pip install -e ".[dev]"
python -m shadowscan. signatures.validate
ruff check shadowscan tests
mypy shadowscan
pip-audit --progress-spinner off
pytest -q --cov=shadowscan --cov-fail-under=80
shadowscan scan -c examples/shadowscan.offline.yaml
```

## Safety notes

* Known credential formats, sensitive configuration fields, and credential-bearing URLs are **redacted** before findings or sanitized record exports are persisted. Redaction cannot identify every arbitrary secret; reports still contain security-sensitive inventory data.
* Secret stores (Secrets Manager, Key Vault, Secret Manager, OCI Vault) are read for **names only**.
* JWTs are never persisted; findings reference a truncated hash.
* Connectors never modify anything; every API call is read-only.

Deployment behavior, migration options, and limits are documented in
[SECURITY.md](SECURITY.md) and [docs/production.md](docs/production.md).

License: Apache-2.0.
