# Sanctioned inventory and shadow reconciliation

ShadowScan calls a finding **shadow** when nothing in the sanctioned inventory
claims it. Without an inventory every finding has `shadow: null` and the
report is a plain discovery; with one, the risk model adds +25 for unregistered
agents, −10 for registered ones, and registered findings inherit the owner
recorded on their card. The inventory is the files described below, plus the
approved records of any vendor registry you explicitly
[trust](#trusting-a-registry).

## Formats

### Agent Capability Cards (one YAML per agent)

A Capability Card is not an A2A Agent Card. You write a Capability Card
(`agent-card.yaml`) to sanction what ShadowScan finds. An agent publishes an
[A2A Agent Card](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)
(`/.well-known/agent-card.json`) to advertise its interfaces and skills to
other agents; ShadowScan discovers those cards in code
([`code.filesystem`](connectors/code.md)) or fetches the ones you list
([`endpoint.mcp`](connectors/endpoint.md#a2a-agent-card-probe)) and reports
each as a finding. A discovered A2A card, signed or not, never registers or
approves a finding; bind it with a Capability Card like any other agent.

The bundled example is [`agent-card.yaml`](https://github.com/aisecnomad/Project-Nexus/blob/main/agent-card.yaml). ShadowScan reads
`schema_version`, `metadata.agent_id`, `metadata.name`, `metadata.owner_team` / `owner`,
`metadata.classification`, `autonomy_profile.level`, and a `discovery:` block required for automatic registration:

```yaml
schema_version: 2                              # autonomy_profile.level uses the L0-L5 scale
metadata:
  agent_id: "ops-provisioning-04"
  version: "2.4.1"
  owner_team: "Platform-Engineering"
  classification: "Internal-Restricted"
autonomy_profile:
  level: 3                                     # declared level: L3 Semi-Autonomous / Agentic Workflow
# ... identity_and_delegation, capability_surface, security_controls, risk_scoring ...
discovery:
  resources:                                   # glob patterns against finding.resource
    - "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT1"
    - "arn:aws:iam::123456789012:role/AmazonBedrockExecutionRoleForAgents_ops"
    - "github:acme/infra-agents/*"
    - "cloudtrail:arn:aws:sts::123456789012:assumed-role/ops-agent-role/*"
  names: ["ops provisioning agent", "ops-agent"] # suggestions only; never automatic approval
  frameworks: [cloud.aws-bedrock-agents]        # informational
  surfaces: [cloud, code, gateway]              # enforced if supplied
  # providers: [aws]                          # optional exact provider constraint
  # accounts: ["123456789012"]                 # optional exact tenant/account constraint
  # regions: [us-east-1]                     # optional exact region constraint
  # discriminators: [bedrock-agent]          # optional exact observation-type constraint
```

Standalone `[cite_start]` / `[cite: n]` export markers are ignored only in the
leading document preamble. Markers inside resource patterns are rejected so
that removing one cannot silently broaden an approval.

### Card schema version and declared autonomy

`schema_version` is a top-level integer. A card without it is version 1.

- **Version 2** declares `autonomy_profile.level`, an integer from 0 (L0
  Chatbot) to 5 (L5 Fully Autonomous) on the scale in
  [autonomy tiers](concepts/autonomy.md). An omitted or null level is
  undeclared. A level outside 0 to 5 (including a string or a boolean) or an
  `autonomy_profile` that is not a mapping makes the card invalid, and the
  inventory fails to load.
- **Version 1** cards used `autonomy_profile.level` on an undefined scale, so
  their level is ignored and counts as undeclared. `shadowscan inventory check`
  prints `autonomy_profile.level ignored: card has no schema_version 2`, and a
  scan records the same advisory warning under `engine.inventory`; neither
  makes a scan incomplete.
- Any other `schema_version` (0, 3, `"2"`, …) is invalid.

A finding matched to an entry with a declared level records `declared` and
`declared_source` in `metadata.autonomy`. A declared level below the observed
floor adds the tag `autonomy-understated` (risk weight 10); one above the
observed ceiling adds a `declared-above-ceiling` note to the autonomy basis.
Matching and approval do not depend on the level.

**Migration from version 1:** add `schema_version: 2` and set
`autonomy_profile.level` on the new scale; do not carry over an old number
without reviewing it against the scale's definitions. Until then the card
keeps registering its resources and its level is ignored with the warning
above.

### Simple list

```yaml
agents:
  - id: claims-assistant
    name: Claims Assistant
    owner: claims-it
    resources: ["ocid1.genaiagent.oc1.us-chicago-1.agent1"]
    names: [claims bot]
    autonomy_level: 3          # optional declared level, 0-5
```

### CSV

```
agent_id,name,owner,resources,names,autonomy_level
hr-helper,HR Helper,erin@acme.com,power-platform:bot:bot-1|okta:app:0oa9x,HR bot|hr assistant,2
```

Simple entries and CSV rows declare a level with `autonomy_level` (an integer
from 0 to 5; a blank CSV cell is undeclared). They have no schema version: the
field exists only on the current scale.

Pass any mix with `--inventory` (repeatable) or `inventory:` in the config;
directories are searched recursively. Symbolic links are never followed: a
directory or glob that skips one records a warning naming it (`engine.inventory`
in scan reports, stderr for `inventory check`). A glob that matches no files is
an error, like a missing path, rather than an empty inventory.

YAML and JSON list fields (`resources`, `names`, `surfaces`, `providers`,
`accounts`, `regions`, `discriminators`, `frameworks`, `tags`) must be arrays of nonempty strings. Quote
numeric account IDs. Optional lists may be omitted or empty; scalar strings
are rejected rather than interpreted character by character. CSV retains
pipe-separated lists. Malformed entries, duplicate keys, unknown simple-inventory
or discovery fields and inconsistent CSV columns fail validation before scanning.

## Matching and approval

Automatic registration requires exactly one matching `discovery.resources`
pattern (or `resources` in the simple format). Resource matching is case-sensitive.
Optional `surfaces`, `providers`, `accounts`, `regions` and `discriminators` lists are
enforced; a finding without a required scope cannot match. Several findings can
share one resource, such as a repository's agent project and its coding-agent
configuration. An entry without `discriminators` approves all of them;
`discriminators` limits it to the findings whose `identity_discriminator` (the
stable observation type in the JSON report, such as `project` or
`coding-agent-config:coding-agent.claude-code`) it lists. A missing resource or one whose
resource, provider, account or region contains `[REDACTED]` cannot be
automatically approved by any pattern; supply a stable nonsecret identity for
registration. Prefer exact
immutable IDs and narrowly scoped patterns; a broad glob is an explicit broad
approval. Region-scoped resources can share a short ID across regions; generated
cards bind a region when available. Review existing cards with short cloud IDs
and add explicit `regions` before using them to approve a single region.

Names, aliases, and agent-ID similarities produce `registry_suggestions` only.
They never confer registered status, inherit an owner, or reduce risk. An
explicit resource mismatch cannot fall through to name-based approval. Multiple
matching inventory entries require review and leave the resource unregistered.

A gateway finding's resource (for example `principal:svc-ops`) is a caller name
the log producer supplied, often the caller itself. When its identity assurance
is `operator-asserted` or `unverified` (generic and access-log exports, shared or
missing names), a matching card still registers it, but the finding carries
`metadata.registry_match_assurance` and the `registry-identity-unverified` tag:
the registration is only as trustworthy as the log's caller field. Review such
registrations before treating the agent as sanctioned.

### Inventory placement and wildcard warnings

An inventory is an approval list, so whoever can edit it can approve findings.
When an inventory file or directory (resolved with `realpath`), or a file it
loads, lies inside a local path that the same run scans with `code.filesystem`
(including `shadowscan code PATH`) or inside the offline clone directory
(`input`) of a `code.github` or `code.gitlab` entry, the scan records the warning
`inventory <name> is inside scanned path <path>; scanned content could alter approvals`.
It also warns once per run for each entry whose resources include a broad
pattern. A nonempty run of stars, such as `*` or `**`, matches every resource
string; approvals still respect surface, provider, account, region and observation
discriminator constraints. Patterns such as `?*` and `*?` are reported as
near-universal across sampled resource shapes, which is advisory evidence rather
than proof of universal matching: `?` requires at least one character. Inventory
list members are trimmed when loaded; the warning classifier does not further
normalize the resulting glob. These warnings do not make a scan incomplete or
change the exit code: a local
`shadowscan code . --inventory agent-card.yaml` is legitimate. They appear under
the `engine.inventory` entry of the report's `stats` (the table output always
shows them), and a fixed-text log line points to them. In CI, keep the
inventory outside the checkout that a pull request can change, as
`examples/github-action-code-scan.yml` does.

**Migration:** cards that previously matched by name need explicit resource
bindings. The bundled `agent-card.yaml` contains example bindings for offline AWS
fixtures; replace them with your reviewed identities before production use.

`shadowscan inventory check inventory/` validates the files and lists what was
loaded: each entry's agent id, name, owner, explicit resource patterns (or
`none (suggestions only)` when the entry can only produce suggestions) and
source file. It warns about skipped symbolic links and about version 1 cards
whose autonomy level is ignored. It does not display scope restrictions or simulate matching; run
a scan against the inventory to see which findings an entry approves.

## Vendor registries as inventory sources

Organizations also keep agents in vendor registries, such as an AWS Agent
Registry or Microsoft Agent 365. A connector that reads one emits one finding
per registry record. A record is a declaration: it shows that someone
registered the agent, not that the agent runs. Its evidence (signal
`registry:<type>`, confidence group `registry-record`) has weight 0.5, and a
second registry listing never raises the confidence.

### Record contract

Each record finding carries `metadata.registry_record`:

```json
{
  "schema": "shadowscan.registry-record/v1",
  "registry": "aws-agent-registry",
  "registry_id": "arn:aws:agent-registry:us-east-1:123456789012:registry/abcd1234abcd",
  "record_id": "rec-123",
  "status": "approved",
  "descriptor_type": "agent",
  "bindings": [
    {"resource": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-a1",
     "provider": "aws", "account": "123456789012", "region": "us-east-1",
     "coverage": "in-scope"}
  ],
  "publisher": "platform-team",
  "updated_at": "2026-09-01T00:00:00Z",
  "listing_complete": true,
  "approval_mode": "manual",
  "listing_scope": "registry"
}
```

| Field | Meaning |
|---|---|
| `schema` | `shadowscan.registry-record/v1`. Any other value is malformed. |
| `registry` | Registry type: `aws-agent-registry`, `aws-agentcore-registry`, `microsoft-agent-365`, `entra-agent-registry`, `google-agent-registry`, `gemini-enterprise`, `mcp-registry` or `a2a-card`. |
| `registry_id` | Exact identity of this registry instance, such as its ARN. Empty when the connector could not establish it; such a record can never be trusted. |
| `record_id` | The record's nonempty id in that registry. |
| `status` | `approved`, `registered`, `pending`, `draft`, `rejected`, `deprecated`, `blocked` or `unknown`. Connectors map vendor statuses onto this set and anything unrecognized onto `unknown`. `registered` means the registry lists the record but has no approval workflow (a Google Agent Registry entry, for example). |
| `descriptor_type` | `agent`, `mcp`, `a2a`, `custom`, `agent-skills` or `package`. |
| `bindings` | Up to 64 deployed objects the record describes, each by the exact `resource` of its finding, with optional `provider`, `account`, `region` and `coverage`. |
| `publisher` | Optional: who published the record. |
| `updated_at` | Optional timestamp. |
| `listing_complete` | Optional, default false. True only when the connector listed every record of this registry without truncation or denial. |
| `approval_mode` | Optional, default `unknown`. `auto` when the registry approves every record without a person, `manual` when a person approves records, `none` when the registry has no approval workflow. |
| `listing_scope` | Optional, default `registry`. `caller` when the listing shows only what the scanning identity can see; such a listing is never treated as complete, whatever `listing_complete` says. |

A binding's `coverage` is `in-scope` only when the emitting connector collected
that resource type for the binding's account and region in the same run;
otherwise it is `out-of-scope` or `unknown` (the default). A binding whose
resource, provider, account or region is empty, padded with whitespace or
contains `[REDACTED]` stays in the record but can neither match nor approve.

A record that breaks the contract (an unknown field, schema, registry type,
status or descriptor type, more than 64 bindings, a non-string identity) is
malformed. It takes no part in reconciliation or approval, and the scan records
`malformed registry record metadata on N finding(s)` under `engine.registries`
and is incomplete (exit 3).

Only a built-in connector written to read vendor registries may emit records:
its class declares the `emits_registry_records`
[engine hook](architecture.md#engine-hooks) and lists the registry types it
reads in `registry_record_types`. A record of a type the connector does not
list is removed with the note
`the connector does not declare that registry type`, so a connector for one
vendor cannot speak for another vendor's registry. The engine removes
`registry_record` from every other connector's findings and notes
`registry record metadata ignored on N finding(s)` in that connector's stats,
so metadata copied from an export or a repository cannot claim an approval. A
third-party plugin cannot emit records even when it declares the hook (the
reason given is `only built-in connectors may emit registry records`): an
approved record of a trusted registry approves findings of every connector.

### Trusting a registry

A vendor approval is not organisational sanction. Registry records change
`shadow` only for the registry instances listed in
[`options.trusted_registries`](getting-started/configuration.md#trusted-vendor-registries),
each by type and exact id. A whole registry type cannot be trusted.

```yaml
options:
  trusted_registries:
    - registry: aws-agent-registry
      id: arn:aws:agent-registry:us-east-1:123456789012:registry/abcd1234abcd
      allow_auto_approved: false      # default
      allow_registered_only: false    # default
```

In a trusted registry, a record approves when its status is `approved` and its
`approval_mode` is `manual`: the registry shows that a person approved it. Two
optional per-registry switches widen that:

- `allow_auto_approved: true` also accepts approved records whose approval no
  person is known to have made: `approval_mode: auto` (the registry approves
  every record without a person) and `approval_mode: unknown` (the connector
  could not establish how the registry approves records). Auto-approval is not
  human review.
- `allow_registered_only: true` also accepts `registered` records of a registry
  without an approval workflow.

Records these rules decline are counted in an advisory `engine.inventory`
warning (`trusted registry <type> <id>: N auto-approved ... record(s) were not
treated as sanctioned`). Records of the deprecated `entra-agent-registry` source
never approve, and the configuration refuses to trust that type.

A record whose `approval_mode` is `unknown` and whose status is `approved` does
not approve by default: the warning counts it as `approved without a known
reviewer`. Set `allow_auto_approved` on the entry only when you know who
approves records in that registry.

Each record that approves:

- registers its own record finding as `<registry>:<record_id>` (for example
  `registry_match: aws-agent-registry:rec-123`); and
- becomes one inventory entry per usable binding. The entry approves exactly
  the bound resource, with glob characters escaped (a binding to `agent-*`
  approves only the literal `agent-*`, never `agent-x`). The binding's provider,
  account and region become the entry's scope constraints, the record's
  `publisher` its owner and `trusted-registry:<registry_id>` its source. It has
  no names, so it produces no suggestions.

These entries are matched together with the inventory files under the
[same rules](#matching-and-approval): exactly one match, case-sensitive, scope
enforced, no approval of redacted or unresolved identities, and never by name.
When a card and a trusted record, or two trusted records, approve the same
finding, the approval is ambiguous: the finding stays shadow with
`registry_match_reason: ambiguous-resource-approval`. Approve each object in one
place. Several bindings of one record that all cover a finding (the same
resource with and without a region, say) are one approval, not an ambiguity.
Records with any other status never approve, and neither does any record
of a registry instance that is not listed, whatever its status.

With `trusted_registries` set, a report has an inventory even without inventory
files: `inventory_present` is true, every finding gets `shadow: true` or
`false`, and `inventory_size` counts the file entries plus the approved records
of trusted registries (one each, whatever their bindings). A trusted registry
that produced no records in the scan (its
connector did not run or failed, or the id does not match what the connector
reports) gets the advisory warning
`trusted registry <type> <id> produced no records; its approvals were not applied`
under `engine.inventory`; an id longer than 16 characters is shortened to its
last 16. The warning does not make the scan incomplete.

Nothing is cached. Every scan rebuilds the approvals from that scan's records,
so a record that is revoked, rejected or deleted, or a registry removed from
`trusted_registries`, stops approving on the next scan.

Records replayed from an offline export (a connector's `input`) are treated
like live records: the engine cannot tell an export of a trusted registry from
a forged one, and an approved record in it approves the resources it binds.
Offline exports are untrusted input, so before trusting a registry whose
records you replay, keep its exports where only operators can write them, or
scan that registry live.

### Example: Google Agent Registry and Gemini Enterprise

The `cloud.gcp` connector reads both catalogs when you opt in
([details](connectors/cloud.md#agent-registry-and-gemini-enterprise-catalogs)):

```yaml
connectors:
  - name: cloud.gcp
    projects: [acme-ml]
    locations: [us-central1]
    agent_registry: true          # Agent Registry agents, MCP servers, endpoints
    gemini_enterprise: true       # agents of Gemini Enterprise apps (caller-scoped)
options:
  trusted_registries:
    # An administrator enables Gemini Enterprise agents: ENABLED records are approved.
    - registry: gemini-enterprise
      id: projects/acme-ml/locations/global/collections/default_collection/engines/acme-assist
```

An `ENABLED` agent of that app approves exactly the reasoning engine or
Dialogflow CX agent it is bound to; a `PRIVATE`, draft, disabled or suspended
agent approves nothing. Agent Registry has no approval workflow, so its
`registered` records approve only with `allow_registered_only: true` on an entry
such as `{registry: google-agent-registry, id: projects/acme-ml/locations/global}`;
listing an agent there is not a review. Trust one of the two for a given agent:
two trusted records approving the same engine are ambiguous and leave it shadow.

### Trusting AWS registries

`cloud.aws` with `registry` in `services` emits records of both AWS registry
namespaces (see the
[cloud guide](connectors/cloud.md#aws-agent-registry-and-agentcore-registry-records)).
The registry id is the registry ARN exactly:

```yaml
connectors:
  - name: cloud.aws
    account_id: "123456789012"
    regions: [us-east-1]
    services: [agentcore, registry]
options:
  trusted_registries:
    # Agent Registry without an auto-approval rule, now or before: a person
    # approves its records.
    - registry: aws-agent-registry
      id: arn:aws:agent-registry:us-east-1:123456789012:registry/abcd1234abcd
    # AgentCore registry with autoApproval: its records were not reviewed by a
    # person, so they approve only because this entry says so.
    - registry: aws-agentcore-registry
      id: arn:aws:bedrock-agentcore:us-east-1:123456789012:registry/efgh5678efgh
      allow_auto_approved: true
```

An approved Agent Registry record that the registry created by auto-detection
(`createdByAutoDetection: true`) from an AgentCore runtime or gateway binds that
exact ARN, so the runtime's finding is registered when its account and region
match. Provenance is also writable: `CreateRegistryRecord` and
`UpdateRegistryRecord` accept it from the caller. A record created through the
API therefore binds nothing, whatever source it names, and an update can change
the provenance of an auto-detected record, so trusting a registry means trusting
everyone who can create, update or approve its records. AgentCore registry
records, and records read from another account's registry through
`registry_arns`, carry no provenance: trusting them registers only the record
findings themselves. Records read through `registry_arns` have
`approval_mode: unknown`, so they approve only when that registry's entry sets
`allow_auto_approved`; it then accepts every approved record in it, however it
was approved.

`approval_mode` reflects the registry's approval configuration when the scan
reads it, not how each record was approved. A record approved while an
auto-approval rule was on reports `manual` once the rule is removed, so trust a
registry without `allow_auto_approved` only when it has never auto-approved
records. A configuration the connector does not recognize gives
`approval_mode: unknown` and makes the scan incomplete.

### Microsoft Agent 365

`identity.entra` with `include_agent_registry: true` reports each package of the
tenant's Agent 365 catalog as a `microsoft-agent-365` record whose registry id
is the connector's `tenant_id`. Trust the tenant by that id:

```yaml
connectors:
  - name: identity.entra
    tenant_id: 00000000-0000-0000-0000-000000000000
    include_agent_registry: true
    include_agent_identities: true   # makes agent identity bindings in scope
options:
  trusted_registries:
    - registry: microsoft-agent-365
      id: 00000000-0000-0000-0000-000000000000
```

An approved package then approves its own record and the objects it binds: the
agent identity (`entra:sp:<agentIdentityId>`), only when that id is a listed
agent identity, and the app registration (`entra:app:<appId>`), only for an
organization's own package. A package never binds any other service principal,
and a Microsoft or partner package never binds an app registration of the
tenant, whatever ids it declares. Blocked, pending, rejected, draft and unknown
packages approve nothing.
Only an organization's own package whose request a person approved has
`approval_mode: manual`; an approved Microsoft or partner package has
`approval_mode: unknown` and approves nothing unless the tenant's entry sets
`allow_auto_approved`, which then approves its record and a listed agent
identity it names. Trust the
tenant only when the packages allowed in its catalog are ones your organization
has decided to sanction. Without `tenant_id` the records have an empty registry
id and cannot be trusted; with it, a pre-issued `access_token` must carry that
tenant in its `tid` claim. A delegated scan's listing is caller-scoped, so it
never marks findings `observed-not-registered` or `registered-not-observed`. The
[identity connector guide](connectors/identity.md#microsoft-agent-365-packages-opt-in)
lists the status rules and binding coverage.

## Registry reconciliation statuses

Whether or not a registry is trusted, the engine compares its records with the
observed findings (findings without a `registry_record`) and writes
`metadata.registry_reconciliation`. A binding matches an observed finding only
when the resources are equal and the binding's provider, account and region,
where set, are equal too. Names never match.

| Status | Set on | When |
|---|---|---|
| `registered-and-observed` | record and observed finding | A usable binding matches the observed finding. The record lists the matched finding ids in `observed`; the observed finding lists the record finding ids in `records` and the registries (`registry`, `registry_id`) in `registries`. |
| `registered-not-observed` | record | Every usable binding has coverage `in-scope` and none matched: the scan collected where the agent should be and did not find it. |
| `not-comparable` | record | No usable binding (`reason: no-usable-binding`), or no match and at least one binding outside the collected scope (`reason: binding-not-in-scope`). |
| `observed-not-registered` | observed finding | An agent, workflow, bot or MCP server with an exact resource, provider and account, in the scope of an identified registry (the providers and accounts of its bindings) whose records all report `listing_complete: true`, that no registry matched. It is shadow with respect to the `registries` listed. |

A match in any registry wins over absence from another. A finding outside every
registry's scope, one whose identity is redacted or unresolved, and one in the
scope only of registries without a complete listing get no status: absence from
a partial listing proves nothing. The lists hold at most 50 entries. When
`min_confidence` drops a finding, links to it are removed and statuses stay as
computed.

Statuses are informational: they do not change `shadow`, approval or risk.

## Approved MCP registries

An organisation's approved MCP catalog is configured separately, as a pinned
snapshot in [`options.mcp_registries`](getting-started/configuration.md#mcp-registry-snapshots)
with `approved: true`. It is not an inventory source: it never approves a
finding or changes `shadow`, `registry_match` or `inventory_size`. It adds the
`mcp-not-in-approved-registry` governance factor to MCP configurations with an
enabled server it does not list by what the client fetches or connects to,
including any server whose package or endpoint cannot be identified; see
[MCP registry provenance](connectors/code.md#mcp-registry-provenance). The
`mcp-registry` record type above is for registry connectors that emit
`registry_record` metadata, not for these snapshots.

## From shadow to registered

```
shadowscan scan -c shadowscan.yaml --format json -o today.json
shadowscan inventory stubs today.json -o inventory/pending/ --min-risk medium
```

`inventory stubs` writes one capability-card skeleton per shadow finding (agent,
mcp-server, workflow, bot-app, agent-config by default): the discovered
resource goes into `discovery.resources` with literal glob characters escaped,
and the finding's `identity_discriminator` into `discovery.discriminators`, so
the generated card approves only that finding, even where other findings share
its resource. A redacted resource or scope leaves `discovery.resources` empty
pending an identity review. Generated cards also bind the finding's region when
present. The finding's names go into `discovery.names` as review suggestions,
detected capabilities into `capability_surface`, the risk score into
`risk_scoring`, and the owner (when known) into `owner_team`. Stubs are
`schema_version: 2` cards whose `autonomy_profile.level` is the finding's
observed autonomy floor, the lowest level its evidence proves; set it to the
level the agent is approved for. A finding kind without autonomy (for example
`oauth-grant`) gets no level. Review, complete
and move the card into the inventory directory; on the next scan the finding is
registered and its risk drops.

Cards generated by earlier versions bind only the resource: one such card
approves every finding on its resource, and two such cards for one resource
leave both findings unregistered as ambiguous. Regenerate them from a current
report or add `discriminators`.

Track drift between runs with `shadowscan diff last.json today.json`: new
findings, risk-level changes and resolved findings from complete, comparable
scans. Missing findings from incomplete or differently scoped scans remain
unknown. Gateway callers keep their finding IDs between runs only when both
scans set `SHADOWSCAN_IDENTITY_KEY`; otherwise diff lists them as not
comparable. See [comparison semantics](scanning.md#comparing-reports).

Generated stub files use mode 0600 in a 0700 output directory. Deliberate wildcard
approvals remain supported in manually reviewed inventory entries. Do not remove
the escaping in a generated resource binding unless a broader approval is intended.
