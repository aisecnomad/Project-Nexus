# Cloud connectors

Cloud connectors discover AI agents, managed AI services, LLM deployments,
and IAM roles with AI-related permissions across major cloud providers.

!!! info "Live and offline"
    Cloud connectors support live SDK collection (requires optional cloud
    extras) and offline record dump analysis.

    From a reviewed checkout, install cloud extras with `pip install ".[cloud]"`.
    For deployment, follow the [hash-locked install](../getting-started/install.md).

All cloud connectors need the matching extra (`aws`, `gcp`, `azure` or `oci`)
for live mode, or a JSONL record dump for offline mode. They use read-only
list/describe/get calls only.

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

## `cloud.aws`
Bedrock Agents (action groups, knowledge bases, aliases, collaborators,
guardrails, memory), Flows, AgentCore (runtimes, gateways = MCP, memories,
browsers, code interpreters, workload identities), model invocation logging
state, Lambda (env names, plaintext keys, layers, images, tags), ECS task
definitions referenced by running tasks and service deployments, plus latest
registered definitions, SageMaker endpoints (LLM containers), Step Functions with Bedrock
states, Q Business, Lex, Secrets Manager / SSM names, IAM principals with LLM
actions (via `get_account_authorization_details`), CloudTrail LLM callers.
Bedrock agents whose action-group functions set `requireConfirmation: ENABLED`
record `metadata.approval_gate` (`every-action` when every enabled action group
other than the user-input group defines functions and each one requires
confirmation, else `some-actions`); see [autonomy tiers](../concepts/autonomy.md).
Options: `profile`, `role_arn`, `regions` (`all`), `services`, `cloudtrail_days`,
`max_ecs_api_calls` (default 2000 per region). Without `regions`, only six
default regions are scanned (`us-east-1`, `us-west-2`, `eu-west-1`,
`eu-central-1`, `ap-southeast-1`, `ap-northeast-1`). The report then carries a
notice that names them and says other regions were not scanned; the notice does
not mark the scan incomplete. Set `regions` to a list, or `regions: all` for
every enabled region, to choose the scope. ECS uses exact task-definition ARNs
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
The collector reports this coverage gap as an informational notice when
CloudTrail collection is enabled. The notice does not mark the scan incomplete:
no returned callers still does not establish absence of runtime activity. A
failed or denied `LookupEvents` call does mark it incomplete.

Lambda `Environment.Error` is unknown environment coverage, not an empty set of
variables. The `environment_coverage` marker survives sanitized exports and replay;
other valid function evidence is retained while completeness fails.

IAM findings are policy evidence, not effective authorization. `Allow/NotAction`
is inspected against representative AI operations and resource service scope,
with potential actions and explicit limitations recorded. Conditions, denies,
policy boundaries, unsupported resource semantics and the full action universe
are not evaluated; partial semantics make coverage incomplete. A principal whose
policies carry any of these limits produces one warning that names it and the
limits (`policy_limitations` on its finding), and the scan exits 3. Accounts that
use conditions, denies or permissions boundaries widely therefore exit 3 by
design: review the listed principals rather than treating the scan as empty.
S3/IAM-only wildcards do not independently produce LLM grants. Effective access
also depends on applicable policies outside this collector's view.

Role trust policies are parsed, not searched as text. A service principal
(`Principal.Service`) or OIDC provider (`Principal.Federated`) is trusted only
through an `Allow` statement whose `Action` includes `sts:AssumeRole`,
`sts:AssumeRoleWithWebIdentity` or `sts:AssumeRoleWithSAML` (IAM wildcards, any
case). `Deny`, `NotAction` and `NotPrincipal` statements, and service names in a
`Sid` or `Condition`, never establish trust; conditions are not evaluated. A
trusted Bedrock or AgentCore principal tags the role `agent-execution-role`. The
document may be an object, JSON text or URL-encoded JSON; a malformed one is
reported as unknown trust (`malformed-trust-policy`) and makes the scan incomplete.

AWS clients ignore configured endpoint URL overrides and use bundled SDK models;
external model paths (`AWS_DATA_PATH`, user SDK model directories) cannot replace
service endpoint rules, including after role assumption. This does not replace
worker egress controls or establish the trustworthiness of installed SDK packages.

## `cloud.gcp`
Service Usage (AI APIs enabled), Vertex AI reasoning engines (Agent Engine)
and endpoints per location, Dialogflow CX agents, Discovery Engine /
Agentspace engines, Cloud Run services, Cloud Functions, project IAM bindings,
service accounts (user-managed keys), API keys restricted to Gemini, Secret
Manager names, optional Cloud Audit Log callers (`audit_days`). Auth: ADC via
`google-auth` or `access_token`. Owner-only and Editor-only IAM principals are
retained as privileged access findings even without an AI-specific role. A grant
shows access, not observed agent execution.
Vertex AI and Dialogflow CX are queried per location. Without `locations`, only
seven default locations are queried (`us-central1`, `us-east4`, `us-west1`,
`europe-west1`, `europe-west4`, `asia-southeast1`, `asia-northeast1`); the report
carries one notice that names them and says other locations were not scanned. The
notice does not mark the scan incomplete. Set `locations` to a list to choose the
scope; there is no `all` option. Dialogflow CX uses the global host for the
`global` location and `<location>-dialogflow.googleapis.com` for regional ones;
Discovery Engine uses `discoveryengine.googleapis.com` for `global` and
`us-` / `eu-discoveryengine.googleapis.com` for the `us` and `eu` multi-regions.
Cloud Run discovery enumerates project locations and then lists services in each
concrete region (`run.locations.list` and `run.services.list` permissions).
Unreachable locations reported by GCP make the scan incomplete. `max_projects`
limits discovery without loading all projects first; `max_pages` (default and
maximum 1000) bounds every paginated call; resource lists stop at 500 pages and audit-log
queries at 50 pages regardless.
Discovery Engine lists the engines of each collection in `discovery_collections`
(default `default_collection`). An engine whose `appType` is `APP_TYPE_INTRANET`
(a Gemini Enterprise or Agentspace app) is reported as an agent, like chat
engines; its metadata records `app_type`, `associated_agent_registry` and
`subscription_tier` when Google returns them. Reasoning engines record
`effective_identity` (the identity the engine runs as) when the API returns it.
Agent Registry counts as an AI API in the enabled-APIs finding.

### Agent Registry and Gemini Enterprise catalogs

Two opt-in catalogs turn Google's agent listings into
[registry records](../inventory.md#vendor-registries-as-inventory-sources). Both
are off by default; while both are off, collection, call order and findings stay
as described above.

- `agent_registry: true` reads Google Agent Registry
  (`agentregistry.googleapis.com`) in every scanned project that has the API
  enabled: the registry locations from `locations.list` (or the
  `agent_registry_locations` you set), then the agents, MCP servers and
  endpoints of each location (`pageSize` 100). `agent_registry_version` selects
  `v1` (default) or `v1alpha`. `v1alpha` is experimental: it also lists skills
  and publishers, and Google may change it without notice. Other versions are
  refused (there is no `v1beta`).
- `gemini_enterprise: true` reads the agents of Gemini Enterprise apps: for each
  listed engine whose `appType` is `APP_TYPE_INTRANET` or whose solution type is
  chat, the Discovery Engine `v1alpha` assistants of the engine and the agents of
  each assistant (`pageSize` 1000). Google documents that listing as the agents
  *created by the caller*: it is caller-scoped, and an agent missing from it may
  still exist. Search and recommendation engines are not asked.

Either option also records the project number (from the project listing, or one
`projects.get` call for a configured project) so names that carry the number
compare with names that carry the id, and records whether each Vertex AI
reasoning-engine and Dialogflow CX agent listing completed.

| Record kind | Finding kind | Registry | Status |
| --- | --- | --- | --- |
| `agent-registry-agent` | `agent` | `google-agent-registry` | `registered` |
| `agent-registry-mcp-server` | `mcp-server` | `google-agent-registry` | `registered` |
| `agent-registry-endpoint` | `cloud-resource` | `google-agent-registry` | `registered` |
| `agent-registry-skill` (`v1alpha`) | `agent-config` | `google-agent-registry` | `STATE_ACTIVE` is `registered`; draft and creating `draft`; disabled `blocked`; deprecated, decommissioned and deleting `deprecated`; others `unknown` |
| `gemini-enterprise-agent` | `agent` | `gemini-enterprise` | `ENABLED` is `approved`; `PRIVATE` with a rejection reason `rejected`; other `PRIVATE`, `CONFIGURED`, `CREATING` and `DEPLOYING` `draft`; `DISABLED` and `SUSPENDED` `blocked`; failed and unrecognized states `unknown` |

The registry id of an Agent Registry record is
`projects/<project-id>/locations/<location>`; that of a Gemini Enterprise record
is its engine, `projects/<project-id>/locations/<location>/collections/<collection>/engines/<engine>`.
A project number in either name is replaced by the project id from the same scan;
when the scan does not know the number, the name keeps it and that registry's
listing is never complete. Name these ids in
[`trusted_registries`](../inventory.md#trusting-a-registry).

Agent Registry has no approval workflow: its records carry `approval_mode: none`
and approve nothing unless the trusted registry entry sets
`allow_registered_only`. Gemini Enterprise records carry `approval_mode: manual`
(an administrator enables agents for the app) and `listing_scope: caller`, so
they are never a complete listing: an observed agent is never reported
`observed-not-registered` against Gemini Enterprise.

**Bindings.** A record binds only to an exact resource:

- a reasoning engine named by an Agent Registry `RuntimeReference`
  (`//aiplatform.googleapis.com/projects/.../reasoningEngines/<id>`) or by a
  Gemini Enterprise ADK agent (`provisionedReasoningEngine.reasoningEngine`);
- a Dialogflow CX agent named by a `RuntimeReference`
  (`//dialogflow.googleapis.com/...`) or by a Gemini Enterprise Dialogflow agent.

When the scan observed that resource (comparing the project number and the
project id), the binding carries the observed finding's exact resource, project
and location. Its coverage is `in-scope` only when this scan's Vertex AI (or
Dialogflow CX) listing for that project and location completed, `unknown` when
that listing was incomplete or the project number is unknown, and `out-of-scope`
otherwise (a location outside `locations`, a project not scanned or without the
API). Other runtime references (a GKE deployment, for example) bind nothing. A
runtime identity that equals a reasoning engine's `effective_identity`, or an
interface URL that equals a Cloud Run service URI, is recorded in
`metadata.registry_join_hints`: a hint, never a binding or an approval.

**Complete listings.** An Agent Registry record is `listing_complete` only when
the project's registry locations were enumerated (not set with
`agent_registry_locations`), that enumeration and every location's agents, MCP
servers and endpoints (and skills with `v1alpha`) listings completed, and every
runtime reference of the project's records names a project the scan can
resolve. Only then can an observed agent, Dialogflow CX agent, chat engine or
Gemini Enterprise app in that project be reported `observed-not-registered`.
Agent Registry does not list Gemini Enterprise apps themselves, so expect that
status on them.

**Catalog presence.** Agent Registry agents and Gemini Enterprise agents carry
`metadata.catalog_presence`: `agent_registry` is `present`, `absent` or
`unknown`, and `gemini_enterprise` is `present` or `unknown`. A Gemini Enterprise
agent and an Agent Registry agent are the same agent when they bind the same
reasoning engine or Dialogflow agent, or share an exact agent card or interface
URL (lowercase scheme and host, default port, userinfo, query and fragment
removed). `absent` needs a complete Agent Registry listing of the engine's
`associatedAgentRegistry` (else of the agent's project) and resolvable names on
both sides. Gemini Enterprise listings are caller-scoped, so absence from them
is never reported.

**Fail closed.** Every listing writes a `registry-coverage` record (export only,
never a finding) that says whether it completed. A denied or failed request, an
invalid page, unreachable locations, an invalid or repeated page token or the
page cap makes that listing incomplete and the scan incomplete (exit 3); the
items already read are kept. Engine, assistant and location names from responses
become request paths only after validation (an engine in another project,
location or collection is skipped with a warning). A record that analysis cannot
read, including a malformed coverage record or an unsupported `_kind`, makes
every binding's coverage `unknown`, every listing incomplete and every presence
`unknown` for that scan.

**What is kept.** Items are reduced when collected, so a record dump replays what
live analysis saw. An agent card becomes a summary (name, URL, version, protocol
version, skill ids, capability flags, security scheme names and types, and counts
of security requirements and signatures); interface URLs lose userinfo, query and
fragment; icons, starter prompts, assistant instructions and authorization values
are dropped (`auth_config` records only whether the app passes user tokens to the
agent and how many tool grants it has). An agent card that declares no security
scheme tags the record `no-auth-declared`; a card that cannot be read
(`agent_card_status` `invalid` or `too-large`, over 64 KiB) makes the scan
incomplete. URLs taken from responses are never fetched.

**Permissions.** Read access to Agent Registry locations, agents, MCP servers and
endpoints (and skills and publishers with `v1alpha`), to Discovery Engine
engines, assistants and agents, and `resourcemanager.projects.get`. Grant
Google's predefined viewer roles for Agent Registry and Discovery Engine, or a
custom role with these list permissions; verify the role names in your
organization. The catalogs were built from Google's published API discovery
documents and synthetic fixtures; they have not been validated against a live
project.

## `cloud.azure`
Azure Resource Graph inventory across subscriptions, then: OpenAI/AI Services
accounts + deployments + diagnostic settings, AI Foundry accounts/projects
(+ agents via the project endpoint), hub-based ML workspaces, Bot Service,
Logic Apps (AI connectors / agent loops; `metadata.trigger_types` lists the
trigger types, such as `Recurrence`), Web & Function app settings,
Container Apps, user-assigned identities, role assignments with AI roles.
Auth: `DefaultAzureCredential` or `access_token` (+ `foundry_token`).
App settings are read by default (`include_app_settings: true`) with a POST to
`<site>/config/appsettings/list`. That call returns plaintext setting values and
needs `Microsoft.Web/sites/config/list/action`, a Contributor-class permission
that Reader and the usual discovery roles lack. Values are held in memory for
analysis only: findings keep setting names and redacted previews, and dumps
redact every value. A denied call is one warning per web app that names the
permission, and it marks the scan incomplete because those apps were not
inspected; the rest of the scan continues. Set `include_app_settings: false` to
skip the call and the permission; web and function apps are then not inspected
for credentials.
Resource Graph, ARM and Foundry collections follow pagination. A denied or failed
diagnostic-settings request is reported as unknown; only a successful empty
response supports a missing-diagnostics finding.
Identifiers taken from ARM responses become request paths, so they are checked
first: a listed subscription without a GUID `subscriptionId` is not scanned, and a
Resource Graph resource whose `id` is not a plain ARM path (`/`-separated
segments without `.` or `..` segments, `?`, `#`, `%`, `\`, whitespace or control
characters) is skipped. Both are reported and make the scan incomplete; the
other subscriptions and resources are still collected.
Foundry agent discovery targets the classic Agent Service contract:
`GET <project-endpoint>/assistants?api-version=v1`. Newer `/agents` API families
require their own contract and are not implied by this support. Missing, denied
or malformed collections remain incomplete; pagination must finish before
absence can be inferred.

## `cloud.oci`
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
SDK objects become records through `oci.util.to_dict`, or through the model's
declared fields when the SDK cannot be imported; an object that cannot be
converted is skipped with a warning and makes the scan incomplete.

## Scaling

Cloud collection issues its detail calls one at a time: Lambda tags per
function, SageMaker, Step Functions and OCI details per resource, GCP keys per
service account. Large estates can exceed the connector deadline, and an
overrun marks the scan incomplete. Raise `connector_timeout_seconds` for such
scans, and bound the work with scope options (`regions`, `locations`,
`projects`, `subscriptions`, `compartments`, `services`) or split the estate
into several connector entries.

## Offline record kinds
Offline exports are JSONL files with one record per line. Each record's `_kind`
selects how it is analyzed; produce exports with `--dump-records` from a live
run rather than writing records by hand.

| Connector | Accepted `_kind` values |
| --- | --- |
| `cloud.aws` | `account`, `bedrock-agent`, `bedrock-knowledge-base`, `bedrock-flow`, `bedrock-logging`, `bedrock-guardrail`, `bedrock-custom-model`, `agentcore-runtime`, `agentcore-gateway`, `agentcore-memory`, `agentcore-browser`, `agentcore-code-interpreter`, `agentcore-workload-identity`, `lambda`, `ecs-task-definition`, `sagemaker-endpoint`, `state-machine`, `qbusiness-application`, `lex-bot`, `secret-name`, `ssm-parameter`, `iam-principal`, `cloudtrail-event` |
| `cloud.gcp` | `project`, `reasoning-engine`, `vertex-endpoint`, `dialogflow-agent`, `discovery-engine`, `cloud-run-service`, `cloud-function`, `iam-policy`, `service-account`, `api-key`, `secret-name`, `audit-event`, and with the opt-in catalogs `project-number`, `registry-coverage`, `agent-registry-agent`, `agent-registry-mcp-server`, `agent-registry-endpoint`, `agent-registry-skill`, `agent-registry-publisher`, `gemini-enterprise-agent` |
| `cloud.azure` | `resource`, `deployment`, `diagnostics`, `foundry-agent`, `logicapp-definition`, `appsettings`, `role-assignment` |
| `cloud.oci` | `tenancy`, `genai-agent`, `genai-agent-endpoint`, `genai-knowledge-base`, `genai-endpoint`, `genai-cluster`, `genai-custom-model`, `oda-instance`, `model-deployment`, `function`, `container-instance`, `secret-name`, `policy`, `dynamic-group` |

All four connectors apply the same record contract. A record with a missing,
unsupported or non-string `_kind`, or with fields that do not fit its kind, is
reported as a warning and makes the scan incomplete; the remaining records are
still analyzed. Envelope records (`account`, `tenancy`) and related records
(Azure deployments and diagnostic settings, OCI agent endpoints) are resolved
before findings are emitted. CloudTrail events become one gateway-caller
finding per principal, and Cloud Audit Log events one per principal and
project, with event counts and the first and last event time.

Synthetic sample exports for all four connectors are kept in
`tests/fixtures/cloud/` (`<provider>_records.jsonl`, plus
`gcp_extended_records.jsonl` and `oci_extended_records.jsonl` for the remaining
GCP and OCI kinds). `gcp_registry_records.jsonl` holds an Agent Registry
(`v1alpha`) and Gemini Enterprise estate with registered, shadow and
out-of-scope agents, and `gcp_registry_empty.jsonl` a complete, empty Agent
Registry listing. Both were written from Google's API discovery documents and
were not validated against a live project.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
