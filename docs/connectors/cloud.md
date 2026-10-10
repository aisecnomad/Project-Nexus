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
Opt-in: AWS Agent Registry and AgentCore registry records
([below](#aws-agent-registry-and-agentcore-registry-records)).
Options: `profile`, `role_arn`, `regions` (`all`), `services` (default: every
service except `registry`), `cloudtrail_days`, `max_ecs_api_calls` (default 2000
per region), `max_registry_records`, `registry_arns`. Without `regions`, only six
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

### AWS Agent Registry and AgentCore registry records

Registry collection is opt-in: add `registry` to `services`. The default is
every service except `registry`, so a configuration without it makes no
registry API call, needs no new permission and reports no registry finding.
With it, the connector reads, in every scanned region and after the other
services, both registry namespaces through their control-plane APIs
(`ListRegistries`, `GetRegistry`, `ListRegistryRecords`, `GetRegistryRecord`):

- AWS Agent Registry (`agent-registry-control`, registry type
  `aws-agent-registry`); and
- AgentCore registries (`bedrock-agentcore-control`, registry type
  `aws-agentcore-registry`).

The control plane lists records of every status, so pending, draft, rejected
and deprecated records are reported too. Each record becomes one finding whose
resource is the record ARN and whose resource type (`agent-registry-record` or
`agentcore-registry-record`) does not change with the record's status or type,
so its identity stays stable while the record moves through review. The
finding carries `metadata.registry_record` (the
[record contract](../inventory.md#record-contract)), evidence of weight 0.5
(a record is a declaration, not proof that the agent runs), and the vendor
fields `record_status`, `record_type`, `record_version`, `registry_arn`,
`created_by_auto_detection`, `provenance` and `registry_auto_approval`.

| Vendor value | Contract value |
| --- | --- |
| `status` `APPROVED`, `PENDING_APPROVAL`, `DRAFT`, `REJECTED`, `DEPRECATED` | `approved`, `pending`, `draft`, `rejected`, `deprecated`; anything else (`CREATING`, `UPDATING`, the failed states) is `unknown` |
| `recordType` or `descriptorType` `MCP` or `GATEWAY`, `AGENT`, `A2A`, `SKILL` or `AGENT_SKILLS`, `CUSTOM` | `mcp` (an MCP server finding), `agent` and `a2a` (agent), `agent-skills` (agent configuration), `custom` (cloud resource). An unrecognized type is `custom` and makes the scan incomplete. |
| The registry's `approvalConfiguration` at scan time | `approval_mode: auto` when Agent Registry `autoApprovalRules` holds any rule (such as `APPROVE_ALL`) or AgentCore `autoApproval` is true, whatever else the configuration holds (a true value of an unexpected type counts too); `manual` when the rules are empty or absent, or `autoApproval` is false or absent, and the configuration holds no other setting; `unknown` when the registry details were denied or carry no approval configuration, and when the configuration has a shape or a setting this release does not recognize, which also makes the scan incomplete |
| Provenance `sourceId` with relation `DETECTED_FROM`, on a record the registry created by auto-detection (`createdByAutoDetection: true`) | One binding to that exact ARN, as the runtime or gateway finding carries it. Its coverage is `in-scope` only when the `agentcore` service ran in that region for the scanned account in the same scan without a warning; otherwise `out-of-scope`. Records without such provenance have no binding. Provenance on a record created through the API is kept in `metadata.provenance` but binds nothing. A relation other than `DETECTED_FROM`, or none, binds nothing and makes the scan incomplete. |

Auto-approval is not human review. A record approved by an auto-approval rule
says so in its evidence (`approved automatically by a registry rule, not
reviewed by a person`) and approves nothing through
[`trusted_registries`](../inventory.md#trusting-a-registry) unless the trusted
entry sets `allow_auto_approved: true`.

`approval_mode` describes the registry's approval configuration when the scan
reads it, not how each record was approved: the APIs do not say. A record
approved while an auto-approval rule was on reports `manual` after the rule is
removed. Trust a registry without `allow_auto_approved` only when it has never
auto-approved records, or set `allow_auto_approved` deliberately.

Provenance is not only written by the registry. `CreateRegistryRecord` and
`UpdateRegistryRecord` accept it from the caller, so the connector binds only
the records the registry created by auto-detection; a record created through
the API names its source as the publisher's assertion and approves no runtime
or gateway. An update can still change the provenance of an auto-detected
record, so trusting a registry means trusting everyone who can create, update
or approve its records.

A record's `listing_complete` is true only when its registry's record listing
finished in this scan without a denial, a failed or truncated page, a skipped
malformed record or the `max_registry_records` cap (default 1000 records per
region and registry namespace). Reaching the cap, a denied or throttled call,
an unsupported region, an SDK without the service and a malformed response all
mark the scan incomplete (exit 3); records already read are kept. A record
whose details (`GetRegistryRecord`) failed is still reported from its listing
summary, with its descriptors unknown and the scan incomplete. Denied listings
use the `cloud.aws: <operation> collection failed (access denied (<code>))`
diagnostic the canary runner reads.

Descriptors are untrusted inline documents of up to 100 KiB. They are parsed as
strict JSON during collection and reduced to a bounded, sanitized summary
(`metadata.descriptor`): MCP server name, version, remote URLs, package
identifiers and tool names; A2A card name, URL, protocol version, interfaces
(URL, protocol binding and version of each of up to 10 `supportedInterfaces`
of a 1.0 card or `additionalInterfaces` of a 0.3 card; a 1.0 card's URL and
protocol version are its first interface's), version, skills, capability and
security scheme names; schema versions; and each descriptor source URL with its
credential provider ARN, grant type, scopes or IAM role. The raw `data` and
`inlineContent` documents, authorizer settings and OAuth `customParameters` are
never exported or reported, and no descriptor URL becomes a finding resource.
A document that is oversized, not strict JSON or of the wrong shape makes the
scan incomplete. An A2A card without security schemes or security
requirements is tagged `no-auth-declared`; MCP remotes go through the same
transport checks as configured MCP servers (`mcp-insecure-transport`).

`registry_arns` lists exact Agent Registry ARNs
(`arn:aws:agent-registry:<region>:<account>:registry/<id>`) of registries,
usually in other accounts, to read through the discovery API
(`ListDiscoverableRegistryRecords`, `BatchGetDiscoverableRegistryRecord`). It
needs `registry` in `services`. The discovery API returns approved records
only, so these records carry `registry_coverage: approved-only`, never set
`listing_complete`, have no bindings, and have `approval_mode: unknown`
because another account's approval configuration cannot be read. Their
account is the registry's account, which is not an unresolved identity. A
registry the control plane already listed in the same scan is not read again.
A registry that uses a JWT authorizer rejects AWS credentials on the discovery
API, which marks the scan incomplete. Per-record batch errors report only their
error codes. The connector never calls `SearchDiscoverableRegistryRecords`,
`InvokeRegistryMcp` or any write operation.

Registry exports replay with the same identities; a replayed record that was
listed incompletely, lacks its details, had an invalid descriptor, or carries
an approval configuration or provenance relation this release does not
recognize makes the replay incomplete again. The registry responses in the
tests and in `aws_registry_records.jsonl` are synthetic, modeled on the
installed SDK models; they were not validated against a live account.

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
| `cloud.aws` | `account`, `bedrock-agent`, `bedrock-knowledge-base`, `bedrock-flow`, `bedrock-logging`, `bedrock-guardrail`, `bedrock-custom-model`, `agentcore-runtime`, `agentcore-gateway`, `agentcore-memory`, `agentcore-browser`, `agentcore-code-interpreter`, `agentcore-workload-identity`, `agent-registry`, `agent-registry-record`, `agent-registry-discoverable-record`, `agentcore-registry`, `agentcore-registry-record`, `lambda`, `ecs-task-definition`, `sagemaker-endpoint`, `state-machine`, `qbusiness-application`, `lex-bot`, `secret-name`, `ssm-parameter`, `iam-principal`, `cloudtrail-event` |
| `cloud.gcp` | `project`, `reasoning-engine`, `vertex-endpoint`, `dialogflow-agent`, `discovery-engine`, `cloud-run-service`, `cloud-function`, `iam-policy`, `service-account`, `api-key`, `secret-name`, `audit-event` |
| `cloud.azure` | `resource`, `deployment`, `diagnostics`, `foundry-agent`, `logicapp-definition`, `appsettings`, `role-assignment` |
| `cloud.oci` | `tenancy`, `genai-agent`, `genai-agent-endpoint`, `genai-knowledge-base`, `genai-endpoint`, `genai-cluster`, `genai-custom-model`, `oda-instance`, `model-deployment`, `function`, `container-instance`, `secret-name`, `policy`, `dynamic-group` |

All four connectors apply the same record contract. A record with a missing,
unsupported or non-string `_kind`, or with fields that do not fit its kind, is
reported as a warning and makes the scan incomplete; the remaining records are
still analyzed. Envelope records (`account`, `tenancy`) and related records
(Azure deployments and diagnostic settings, OCI agent endpoints, AWS registry
containers) are resolved before findings are emitted. CloudTrail events become one gateway-caller
finding per principal, and Cloud Audit Log events one per principal and
project, with event counts and the first and last event time.

Synthetic sample exports for all four connectors are kept in
`tests/fixtures/cloud/` (`<provider>_records.jsonl`, plus
`gcp_extended_records.jsonl` and `oci_extended_records.jsonl` for the remaining
GCP and OCI kinds, and `aws_registry_records.jsonl` for AWS registry records).


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
