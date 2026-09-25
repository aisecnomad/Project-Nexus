# Connectors

Most connectors have a **live** mode (API credentials) and an **offline** mode
(`input:` pointing at an export). `gateway.logs` reads supplied logs and
`identity.jwt` reads supplied tokens. Live runs can persist sanitized records with
`--dump-records DIR` / `options.dump_records` for offline re-analysis. Exports are
written atomically with mode 0600 in a 0700 directory and JWT inputs are never
exported. Every connector instance has a collision-resistant export filename,
including repeated connector names or labels that normalize to the same text. Redaction
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
These three keys are declared once on `BaseConnector.shared_config_keys` and
apply to every connector that reads an export file, so `shadowscan connectors`
lists them after each connector's own keys. `code.filesystem`, `code.github` and
`code.gitlab` scan checkouts instead of exports: they are bounded by `max_files`,
`max_repos` and `max_projects` and do not advertise the export limits. They
ignore those three keys, but a value supplied for one must still be a positive
integer or the entry fails validation.

See [scan state and runtime correlation](scanning.md) for incremental scans,
gateway workload bindings and completion semantics.

`shadowscan connectors` prints the up-to-date option list for every connector.
A configuration key that a built-in connector does not read is rejected when
the YAML file or `--set` option is parsed (`connector 'identity.okta' does not
accept 'fetch_tokenz'`), so a typo cannot silently disable an option. Keys
starting with an underscore are reserved for the engine. Third-party plugins
are not imported while parsing, so their keys are not checked at that point.

## Connector entry keys

Every entry under `connectors:` in a scan configuration accepts these keys in
addition to the connector's own options:

- `name` (required): the connector, for example `identity.okta`. A bare string
  entry is shorthand for `{name: ...}`.
- `enabled`: `true` (default) or `false` to keep the entry but skip it on this
  run. Environment-backed strings such as `"false"`, `"no"`, `"off"` or `"0"` are
  accepted; any other value fails validation. A disabled entry is not a valid
  `--only` selector.
- `label`: a name for this entry. Give each repeated connector a distinct
  label; nothing else tells the entries apart. It is the entry's id in
  `--only`, progress and `dump_records` file names, and it is passed to the
  connector as the `label` key:
  `code.filesystem` prefixes resource ids with it and `gateway.logs` records it
  as the gateway name.
- `config`: an optional nested mapping merged into the top-level keys, for
  configurations that keep credentials apart from entry metadata. A nested
  key replaces a top-level key of the same name.
- `input`: the offline export path; each connector's offline format is listed
  below and by `shadowscan connectors`.

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

Python and common JavaScript/TypeScript constructors are resolved against imports,
including aliases, namespaces and ordinary CommonJS bindings. Generic loops,
subprocess calls and repeated weak idioms cannot independently establish an agent.
Confidence groups cap repeated observations of the same technology. Unsupported
dynamic imports, re-exports and uncertain bindings remain usage evidence. Other
languages use lexical signatures and require matching framework import/dependency
corroboration before agent classification; uncorroborated lexical framework code
is capped at 0.6 confidence. These are static candidate classifications, not proof
that code ran or that a deployment is autonomous.

Agent filenames select structural discovery checks. Empty/invalid LangGraph,
A2A, M365 and CrewAI manifests yield incomplete coverage instead of confirmed
agents. JSON/YAML descriptions are not executed or treated as source; low-code
matching projects operational fields only. These predicates are not complete
versioned vendor schema validators.
Owner comes from `CODEOWNERS` and configured inventory. Git author/history
enrichment is disabled by default; `use_git: true` explicitly enables it for
reviewed local metadata. The metadata command must support `--no-lazy-fetch`;
unsupported Git versions or failed history reads mark the scan incomplete.
Metadata reads cannot initiate a transport, fetch missing objects or use hooks.

Options: `path`/`paths`, `root_ids`, `exclude`, `max_file_size`, `max_files`,
`scan_timeout`, `scan_secrets`, `strict_coverage`, `include_tests`, `use_git`, `label`. When using labeled `paths`,
supply unique `root_ids` aligned with those paths for IDs that survive moving
checkouts. `account`, `owner` and `provider` set the corresponding finding
fields. A configured `owner` is recorded on every finding and takes precedence
over CODEOWNERS and inventory attribution; leave it unset to attribute by
CODEOWNERS, then the git author when `use_git` is on, then the inventory.
`metadata` is a mapping merged into every finding's metadata.

### `code.github`
Enumerates an organisation, a user or an explicit `repos:` list, fetches
content by shallow clone (default) or the contents API (`mode: api`, bounded
file sample) and runs the filesystem scanner. Adds CI secret/variable *names*
matching LLM providers. Token: fine-grained PAT or GitHub App token with
`contents:read`, `metadata:read`; `secrets:read` for secret names. Offline
input: a directory of clones. Code findings retain the scanned Git tree/commit
identity in `metadata.source_snapshot`; API blob bytes are checked against their
enumerated Git object IDs.
Live API records cannot choose local scan paths. `use_git` has the same explicit
opt-in policy as `code.filesystem`; cloning retains its separate HTTPS policy.
`clone_max_bytes` (default 256 MiB) checks GitHub's reported repository size
before cloning, and `clone_timeout_seconds` (default 120) bounds each clone.
An oversized repository or missing/malformed size estimate falls back to sampled
API mode without launching Git and marks coverage incomplete. A failed clone or
Git being unavailable for explicit `mode: clone` also marks the scan incomplete.
The provider's size is an estimate, not a download or disk quota. Run remote
scans with a host/container wall-clock limit and a writable disk quota.

Options: `org` (env `GITHUB_ORG`), `user` or `repos`; `token` (env
`GITHUB_TOKEN`, falling back to `github_token` / env `GH_TOKEN`); `api_url`,
`mode`, `include_archived`, `include_forks`, `max_repos`, `clone_depth`,
`topics`. The filesystem scanner options `exclude`, `max_file_size`,
`max_files`, `scan_timeout`, `scan_secrets` and `use_git` are forwarded to
every repository scan.

### `code.gitlab`
Group (with subgroups) or `projects:` list on gitlab.com or self-managed;
clone or API mode; also CI/CD variable names (masked flag), group service
accounts, group/project access tokens, project bots and GitLab Duo enablement.
Token: PAT with `read_api` + `read_repository`.
Live API records cannot choose internal offline paths or dispatch fields. Code
findings retain the scanned Git tree/commit identity in
`metadata.source_snapshot`, and API mode pins tree pagination to an immutable
commit before downloading files.
`clone_max_bytes` and `clone_timeout_seconds` have the same defaults and
incomplete-scan semantics as `code.github`. GitLab project details are queried
for size statistics when the listing omits them. If no usable estimate is
available, the connector falls back to sampled API mode without launching Git.
A size estimate cannot bound actual checkout bytes; enforce a writable disk
quota on the worker.

Options: `group` (env `GITLAB_GROUP`) or `projects`; `token` (env
`GITLAB_TOKEN`); `api_url` (env `GITLAB_API_URL`), `mode`, `include_archived`,
`max_projects`. The same filesystem scanner options as `code.github` are
forwarded to every project scan.

## Identity

### `identity.okta`
`/api/v1/apps` (+ `/grants`, `/tokens` for OIDC apps). Reports OAuth apps that
match AI SaaS signatures or hold privileged scopes, and service apps
(`application_type: service` / `client_credentials` / token-exchange).
Token: SSWS API token (`token`, env `OKTA_API_TOKEN`) or OAuth bearer
(`bearer`, env `OKTA_ACCESS_TOKEN`) with `okta.apps.read`; `bearer` wins when
both are set. Options: `include_inactive`, `fetch_tokens`.

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
Offline exports may contain individual token records or per-user objects such
as `{"user":"user@example.com","tokens":[...]}`. The latter retains user
attribution whether supplied as one object or inside an array.

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
lifetime and algorithm hygiene are flagged. Optional `jwks_url` verification
fetches a bounded JWKS through the shared HTTPS client and accepts only RS256,
ES256, EdDSA and PS256 by default. `allowed_algorithms` may narrow that list.
`expected_issuer` binds verification to an operator-supplied exact issuer; the
unverified token's issuer does not choose or authorize a key source. The JWKS URL
is configured by the operator, so legitimate providers may host keys separately.
Audience and historical-token expiry are not authorization checks here. Read
`metadata.verified` as signature evidence, not permission to act.

CLI equivalents: `--jwks-url`, `--expected-issuer`, and repeatable
`--jwt-algorithm`. The latter two require `--jwks-url`.

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

Options: `format`, `min_events`, `llm_hosts_only`, `max_records`,
`correlation_bindings`, and `label` (or `gateway_name` when the entry has no
label), which names the gateway on findings: it becomes the provider and the
account of callers without a tenant/account scope.

## Low-code

### `lowcode.power-platform`
BAP admin API (environments), Power Automate admin flows, Power Apps admin
apps (AI connector references: `shared_openai`, `shared_azureopenai`,
`shared_aibuilder`, `shared_microsoftcopilotstudio`…), Dataverse `bots` +
`botcomponents` (Copilot Studio agents: generative answers, actions, knowledge,
authentication mode, publish state). Auth: Entra app registered as a Power
Platform application user / tenant admin. Environment enumeration follows
`nextLink`; app enumeration uses the documented AdminApps 2024-10-01 API at
`api.powerplatform.com` with a separate `https://api.powerplatform.com/.default`
token audience. A denied child request or failed continuation marks coverage
incomplete while retaining findings from other environments. Before relying on
live coverage, verify the application's Power Platform roles and known apps
in a read-only tenant canary.

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
steps (→ code-exec), models. Live pagination is bounded by `max_pages`
(default 1000). Make scans one `team_id`, or every team of an
`organization_id` when `team_id` is unset.

## SaaS

### `saas.slack`
`users.list` (bots), `admin.apps.approved.list` / `restricted` / `requests`
(scopes, pending requests), `team.integrationLogs` (who installed what).
`team.info` must return an authenticated workspace identity. If `team_id` is
configured, it must match exactly before inventory calls begin. Missing/null
collection arrays and malformed pagination are incomplete coverage. Later
network failures retain already collected observations; provider error text is
not copied into diagnostics. Complete live acceptance generally requires an
appropriately scoped administrative audit token, not an ordinary bot token.
Findings use the immutable workspace ID as `account`; the display name is stored
in `metadata.workspace_name`. An offline export without a team record requires
an explicit `team_id`. Conflicting envelopes or record-level workspace IDs make
the scan incomplete and prevent attribution. Update inventory account bindings
and collect a fresh comparison baseline when upgrading from name-based IDs.

### `saas.microsoft-teams`
Graph app catalog (custom apps with bot definitions and RSC permissions) and
installed apps per team (capped by `max_teams`).
Malformed app IDs, conflicting expanded identities and malformed nested
definitions or permissions make collection incomplete. An installation ID is
not a fallback catalog app ID. Valid neighboring records remain available.

### `saas.github-apps`
Org installations with permissions and repository selection (AI reviewers,
coding agents), Copilot billing/seat settings, fine-grained PATs approved for
the org.

### `saas.atlassian` · `saas.notion` · `saas.zoom`
UPM user-installed apps (Jira/Confluence) and Notion bot users. Zoom's
Marketplace list API returns approved public apps and account-created apps
(`type=public` and `type=account_created`), including app scopes when supplied.
See [Zoom's Marketplace List apps API](https://developers.zoom.us/docs/api/marketplace/).
Approval or account creation does not establish that any individual installed
or used the app; for that question, obtain a separate tenant activity or
installation export. Notion rejects a missing/repeated pagination cursor and
caps live pages (`max_pages`, at most 1000); either condition makes the scan
incomplete. Zoom likewise marks denied, invalid, or truncated pages incomplete.

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
limits discovery without loading all projects first; `max_pages` (default 1000)
bounds every paginated call; resource lists stop at 500 pages and audit-log
queries at 50 pages regardless.

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
Options: `profile`, `config_file`, `auth`, `tenancy` (default: from the
profile or the principal signer), `region` (session region for
`instance_principal`; config auth uses the profile's region), `regions`,
`compartments`, `max_pages` (default 1000).
Function inspection retrieves application and function details, combines
inherited configuration with function overrides, and supports both legacy image
fields and `source_details.image`. Denied or invalid detail reads mark coverage
incomplete while preserving available resource evidence. Audit credentials need
the corresponding application/function read permissions; list-only access is
insufficient to inspect configuration.

## Least privilege

All connectors are read-only. Prefer dedicated audit credentials:

| Connector | Minimum |
|---|---|
| GitHub | fine-grained PAT: contents/metadata read (`secrets:read` optional) |
| GitLab | PAT `read_api`, `read_repository` |
| Okta | API token from a read-only admin, or OAuth `okta.apps.read` |
| Entra / Teams / Power Platform | app permissions `Application.Read.All`, `DelegatedPermissionGrant.Read.All`, `Directory.Read.All`, `AppCatalog.Read.All`, `Team.ReadBasic.All`, `TeamsAppInstallation.ReadForTeam.All`; Power Platform admin application user |
| Google Workspace | DWD scopes `admin.directory.user.readonly`, `admin.directory.user.security` |
| AWS | `SecurityAudit` managed policy + `bedrock:List*/Get*`, `bedrock-agentcore:List*/Get*`, `cloudtrail:LookupEvents`; ECS additionally needs `ecs:ListClusters`, `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:ListServices`, `ecs:DescribeServices`, `ecs:ListTaskDefinitionFamilies`, `ecs:DescribeTaskDefinition` |
| GCP | `roles/viewer` + `roles/iam.securityReviewer` (+ `roles/logging.privateLogViewer` for audit logs) |
| Azure | `Reader` on subscriptions (+ `Cognitive Services OpenAI User`/`Azure AI User` to list Foundry agents; a narrowly scoped custom permission `Microsoft.Web/sites/config/list/Action` when sensitive app settings are needed) |
| OCI | policy `Allow group audit to read all-resources in tenancy` |

The Azure app-settings permission exposes security-sensitive configuration;
only grant it for the app resources being audited. Do not grant Website
Contributor solely for this read operation. See Microsoft's
[permission definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/web-and-mobile).
