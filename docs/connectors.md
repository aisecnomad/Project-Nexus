# Connectors

Most connectors have a **live** mode (API credentials) and an **offline** mode
(`input:` pointing at an export). `gateway.logs` reads supplied logs and
`identity.jwt` reads supplied tokens. Live runs can persist sanitized records with
`--dump-records DIR` / `options.dump_records` for offline re-analysis. Exports are
written atomically with mode 0600 and JWT inputs are never exported. Redaction
removes sensitive values, so an export is not a lossless copy of the API response.
Live HTTP endpoints require HTTPS; redirects and pagination cannot send credentials
to another origin. Denied access, collection failures and pagination limits make
the scan incomplete rather than producing a clean result.

Offline file and directory inputs use shared safety limits: 10,000 files,
32 MiB per file and 256 MiB total per connector by default. JSONL, CSV and gateway
text logs stream line by line, with a 4 MiB line cap; gzip gateway logs are bounded
by expanded size. Override `max_input_files`, `max_input_file_bytes` or
`max_input_bytes` in the connector config when a trusted export needs larger
limits. The existing hard ceilings remain 64 MiB per file and 512 MiB total.
Any skipped symlink or input-limit hit marks the connector incomplete.

See [scan state and runtime correlation](scanning.md) for incremental scans,
gateway workload bindings and completion semantics.

`shadowscan connectors` prints the up-to-date option list for every connector.

## Code

### `code.filesystem`
Scans a directory tree. Project roots are detected from manifests
(`package.json`, `pyproject.toml`, `go.mod`, `pom.xml`, …); each root yields one
finding summarising frameworks, model providers, capabilities, models and
evidence. Extra findings: MCP configs (`.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `claude_desktop_config.json`, Codex `config.toml`,
Continue, Kiro, Amazon Q…), coding-agent configs (`CLAUDE.md`, `.claude/agents`,
`.github/agents/*.agent.md`, `.cursor/rules`, `AGENTS.md`, `GEMINI.md`…),
A2A agent cards, M365 declarative agents, LangGraph/CrewAI manifests, exported
low-code flows, IaC (Terraform, CloudFormation, ARM/Bicep, wrangler) and
container files, `.env`/CI secret references, provider credentials (redacted).
Owner comes from `CODEOWNERS`, then the last git author.

Options: `path`/`paths`, `exclude`, `max_file_size`, `max_files`, `scan_secrets`,
`use_git`, `label`.

### `code.github`
Enumerates an organisation, a user or an explicit `repos:` list, fetches
content by shallow clone (default) or the contents API (`mode: api`, bounded
file sample) and runs the filesystem scanner. Adds CI secret/variable *names*
matching LLM providers. Token: fine-grained PAT or GitHub App token with
`contents:read`, `metadata:read`; `secrets:read` for secret names. Offline
input: a directory of clones.

### `code.gitlab`
Group (with subgroups) or `projects:` list on gitlab.com or self-managed;
clone or API mode; also CI/CD variable names (masked flag), group service
accounts, group/project access tokens, project bots and GitLab Duo enablement.
Token: PAT with `read_api` + `read_repository`.

## Identity

### `identity.okta`
`/api/v1/apps` (+ `/grants`, `/tokens` for OIDC apps). Reports OAuth apps that
match AI SaaS signatures or hold privileged scopes, and service apps
(`application_type: service` / `client_credentials` / token-exchange).
Token: SSWS API token or OAuth bearer with `okta.apps.read`.

### `identity.entra`
Microsoft Graph: service principals, delegated `oauth2PermissionGrants`,
app-only `appRoleAssignments` (role ids resolved to names such as
`Mail.ReadWrite`), tenant app registrations, managed identities. First-party
Microsoft SPs are skipped unless they match AI signatures (Copilot).
Permissions (application): `Application.Read.All`, `DelegatedPermissionGrant.Read.All`,
`Directory.Read.All`. Or pass `access_token`.

### `identity.google-workspace`
Admin SDK `users/{id}/tokens` for every user, aggregated per OAuth client:
"Fireflies has Gmail + Calendar for 214 users". Auth: service account with
domain-wide delegation impersonating an admin (`service_account_file` +
`admin_email`; scopes `admin.directory.user.readonly`,
`admin.directory.user.security`) or `access_token`.

### `identity.auth0`
Management API `clients` and `client-grants`: M2M applications, their
audiences and scopes, AI-named apps. Auth: M2M client for the Management API
(`read:clients`, `read:client_grants`) or `token`.

### `identity.jwt`
Decodes tokens (never stored) and classifies the holder as `human`, `service`,
`workload`, `delegated`, `agent` or `delegated-agent` using issuer-specific
conventions (Entra `idtyp=app`, Okta `cid == sub`, Auth0 `gty`, Google service
accounts, Cognito, Keycloak, SPIFFE) plus RFC 8693 `act` chains and
agent-related claims. Scopes/roles are classified by the policy signatures;
lifetime and algorithm hygiene are flagged. Optional JWKS verification.

## Gateway

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

## Low-code

### `lowcode.power-platform`
BAP admin API (environments), Power Automate admin flows, Power Apps admin
apps (AI connector references: `shared_openai`, `shared_azureopenai`,
`shared_aibuilder`, `shared_microsoftcopilotstudio`…), Dataverse `bots` +
`botcomponents` (Copilot Studio agents: generative answers, actions, knowledge,
authentication mode, publish state). Auth: Entra app registered as a Power
Platform application user / tenant admin.

### `lowcode.salesforce`
SOQL/Tooling: `BotDefinition`/`BotVersion` (Einstein bots & Agentforce
agents), `GenAiPlannerDefinition`/`GenAiPluginDefinition`/`GenAiFunctionDefinition`
(topics, actions, Apex/Flow targets), `GenAiPromptTemplate`, `FlowDefinitionView`
with AI hints, `ConnectedApplication` + `OauthToken` (user-authorised apps,
aggregated). Auth: `access_token` or client-credentials connected app.

### `lowcode.servicenow`
Table API: `sn_aia_agent`, `sn_aia_tool`, `sn_aia_usecase`, `sn_aia_trigger`,
`sys_hub_flow` (AI hints), `oauth_entity`. Auth: basic or bearer.

### `lowcode.n8n` · `lowcode.make` · `lowcode.zapier` · `lowcode.workato`
Workflows/scenarios/zaps/recipes with AI or agent steps (n8n LangChain nodes,
Make AI modules and AI Agents, Zapier AI/Agents from account exports, Workato
GenAI/agentic providers); triggers (schedule/webhook → autonomous), code
steps (→ code-exec), models.

## SaaS

### `saas.slack`
`users.list` (bots), `admin.apps.approved.list` / `restricted` / `requests`
(scopes, pending requests), `team.integrationLogs` (who installed what).

### `saas.microsoft-teams`
Graph app catalog (custom apps with bot definitions and RSC permissions) and
installed apps per team (capped by `max_teams`).

### `saas.github-apps`
Org installations with permissions and repository selection (AI reviewers,
coding agents), Copilot billing/seat settings, fine-grained PATs approved for
the org.

### `saas.atlassian` · `saas.notion` · `saas.zoom`
UPM user-installed apps (Jira/Confluence), Notion bot users, Zoom Marketplace
apps with scopes and install counts.

### `saas.generic`
Any CSV/JSON app inventory (Google Marketplace, HubSpot, CASB discovered-apps
exports…). Map columns with `fields:`; findings are produced for AI matches
and privileged/data scopes (`keep_all: true` to emit everything).

## Cloud

All cloud connectors need the matching extra (`shadowscan[aws|gcp|azure|oci]`)
for live mode, or a JSONL record dump for offline mode. They use read-only
list/describe/get calls only.

### `cloud.aws`
Bedrock Agents (action groups, knowledge bases, aliases, collaborators,
guardrails, memory), Flows, AgentCore (runtimes, gateways = MCP, memories,
browsers, code interpreters, workload identities), model invocation logging
state, Lambda (env names, plaintext keys, layers, images, tags), ECS task
definitions, SageMaker endpoints (LLM containers), Step Functions with Bedrock
states, Q Business, Lex, Secrets Manager / SSM names, IAM principals with LLM
actions (via `get_account_authorization_details`), CloudTrail LLM callers.
Options: `profile`, `role_arn`, `regions` (`all`), `services`, `cloudtrail_days`.
IAM analysis includes both local and AWS-managed attached policies. Unresolved
attachments make collection incomplete. CloudTrail LookupEvents only supplies
management events: `InvokeAgent` / `InvokeInlineAgent` data events require a
separately configured trail or event data store and an export to `gateway.logs`.
The collector reports this coverage gap when CloudTrail collection is enabled.

### `cloud.gcp`
Service Usage (AI APIs enabled), Vertex AI reasoning engines (Agent Engine)
and endpoints per location, Dialogflow CX agents, Discovery Engine /
Agentspace engines, Cloud Run services, Cloud Functions, project IAM bindings,
service accounts (user-managed keys), API keys restricted to Gemini, Secret
Manager names, optional Cloud Audit Log callers (`audit_days`). Auth: ADC via
`google-auth` or `access_token`.

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

### `cloud.oci`
Generative AI Agents (agents, endpoints, tools, knowledge bases), Digital
Assistant, GenAI endpoints/clusters/custom models, Data Science model
deployments, Functions, Container Instances, Vault secret names, IAM policies
granting `generative-ai*`, dynamic groups. Auth: `~/.oci/config` profile,
instance or resource principal.

## Least privilege

All connectors are read-only. Prefer dedicated audit credentials:

| Connector | Minimum |
|---|---|
| GitHub | fine-grained PAT: contents/metadata read (`secrets:read` optional) |
| GitLab | PAT `read_api`, `read_repository` |
| Okta | API token from a read-only admin, or OAuth `okta.apps.read` |
| Entra / Teams / Power Platform | app permissions `Application.Read.All`, `DelegatedPermissionGrant.Read.All`, `Directory.Read.All`, `AppCatalog.Read.All`, `Team.ReadBasic.All`, `TeamsAppInstallation.ReadForTeam.All`; Power Platform admin application user |
| Google Workspace | DWD scopes `admin.directory.user.readonly`, `admin.directory.user.security` |
| AWS | `SecurityAudit` managed policy + `bedrock:List*/Get*`, `bedrock-agentcore:List*/Get*`, `cloudtrail:LookupEvents` |
| GCP | `roles/viewer` + `roles/iam.securityReviewer` (+ `roles/logging.privateLogViewer` for audit logs) |
| Azure | `Reader` on subscriptions (+ `Cognitive Services OpenAI User`/`Azure AI User` to list Foundry agents; Website Contributor to read app settings) |
| OCI | policy `Allow group audit to read all-resources in tenancy` |
