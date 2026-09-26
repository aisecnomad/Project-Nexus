# Cloud connectors

Cloud connectors discover AI agents, managed AI services, LLM deployments,
and IAM roles with AI-related permissions across major cloud providers.

!!! info "Live and offline"
    Cloud connectors support live SDK collection (requires optional cloud
    extras) and offline record dump analysis.

    Install cloud extras: `pip install "shadowscan[cloud]"`

All cloud connectors need the matching extra (`shadowscan[aws|gcp|azure|oci]`)
for live mode, or a JSONL record dump for offline mode. They use read-only
list/describe/get calls only.

### `cloud.aws`
Bedrock Agents (action groups, knowledge bases, aliases, collaborators,
guardrails, memory), Flows, AgentCore (runtimes, gateways = MCP, memories,
browsers, code interpreters, workload identities), model invocation logging
state, Lambda (env names, plaintext keys, layers, images, tags), ECS task
definitions referenced by running tasks and service deployments, plus latest
registered definitions, SageMaker endpoints (LLM containers), Step Functions with Bedrock
states, Q Business, Lex, Secrets Manager / SSM names, IAM principals with LLM
actions (via `get_account_authorization_details`), CloudTrail LLM callers.
Options: `profile`, `role_arn`, `regions` (`all`), `services`, `cloudtrail_days`,
`max_ecs_api_calls` (default 2000 per region). ECS uses exact task-definition ARNs
for deployed references, including referenced inactive revisions. Findings
separate running-task/service references from registered-only definitions; a
reference does not establish successful AI execution. Exhausted API budgets or
partial/denied responses mark coverage incomplete. Account identity is resolved
before collection emits account metadata. Live `account_id` is an expected
12-digit account, verified through STS even when explicitly configured;
mismatches stop collection. AWS SDK clients use finite connection/read timeouts
and retry attempts. `max_lambda` limits streamed enumeration.
Offline exports resolve their account from `account` records wherever they
appear. Several different or invalid `account` records, or a resource ARN from
another account (CloudTrail callers excepted), leave short resource identities
unresolved and the scan incomplete; generated ARNs for Bedrock logging, Q
Business, Lex and SSM parameters take the resolved account or none. Such
findings cannot be approved by an inventory card.
IAM analysis includes both local and AWS-managed attached policies. Unresolved
attachments make collection incomplete. CloudTrail LookupEvents only supplies
management events: `InvokeAgent` / `InvokeInlineAgent` data events require a
separately configured trail or event data store and an export to `gateway.logs`.
The collector reports this coverage gap when CloudTrail collection is enabled.

Lambda `Environment.Error` is unknown environment coverage, not an empty set of
variables. The `environment_coverage` marker survives sanitized exports and replay;
other valid function evidence is retained while completeness fails.

IAM findings are policy evidence, not effective authorization. `Allow/NotAction`
is inspected against representative AI operations and resource service scope,
with potential actions and explicit limitations recorded. Conditions, denies,
policy boundaries, unsupported resource semantics and the full action universe
are not evaluated; partial semantics make coverage incomplete. S3/IAM-only
wildcards do not independently produce LLM grants. Effective access also depends
on applicable policies outside this collector's view.

AWS clients ignore configured endpoint URL overrides and use bundled SDK models;
external model paths (`AWS_DATA_PATH`, user SDK model directories) cannot replace
service endpoint rules, including after role assumption. This does not replace
worker egress controls or establish the trustworthiness of installed SDK packages.

### `cloud.gcp`
Service Usage (AI APIs enabled), Vertex AI reasoning engines (Agent Engine)
and endpoints per location, Dialogflow CX agents, Discovery Engine /
Agentspace engines, Cloud Run services, Cloud Functions, project IAM bindings,
service accounts (user-managed keys), API keys restricted to Gemini, Secret
Manager names, optional Cloud Audit Log callers (`audit_days`). Auth: ADC via
`google-auth` or `access_token`. Owner-only and Editor-only IAM principals are
retained as privileged access findings even without an AI-specific role. A grant
shows access, not observed agent execution.
Cloud Run discovery enumerates project locations and then lists services in each
concrete region (`run.locations.list` and `run.services.list` permissions).
Unreachable locations reported by GCP make the scan incomplete. `max_projects`
limits discovery without loading all projects first.

### `cloud.azure`
Azure Resource Graph inventory across subscriptions, then: OpenAI/AI Services
accounts + deployments + diagnostic settings, AI Foundry accounts/projects
(+ agents via the project endpoint), hub-based ML workspaces, Bot Service,
Logic Apps (AI connectors / agent loops), Web & Function app settings,
Container Apps, user-assigned identities, role assignments with AI roles.
Auth: `DefaultAzureCredential` or `access_token` (+ `foundry_token`).
Resource Graph, ARM and Foundry collections follow pagination. A denied or failed
diagnostic-settings request is reported as unknown; only a successful empty
response supports a missing-diagnostics finding.
Foundry agent discovery targets the classic Agent Service contract:
`GET <project-endpoint>/assistants?api-version=v1`. Newer `/agents` API families
require their own contract and are not implied by this support. Missing, denied
or malformed collections remain incomplete; pagination must finish before
absence can be inferred.

### `cloud.oci`
Generative AI Agents (agents, endpoints, tools, knowledge bases), Digital
Assistant, GenAI endpoints/clusters/custom models, Data Science model
deployments, Functions, Container Instances, Vault secret names, IAM policies
granting `generative-ai*`, dynamic groups. Auth: `~/.oci/config` profile,
instance or resource principal.
Function inspection retrieves application and function details, combines
inherited configuration with function overrides, and supports both legacy image
fields and `source_details.image`. Denied or invalid detail reads mark coverage
incomplete while preserving available resource evidence. Audit credentials need
the corresponding application/function read permissions; list-only access is
insufficient to inspect configuration.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
