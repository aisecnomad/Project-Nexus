# Agent governance proposals

Status: proposal, drafted 2026-10-10. This page expands six roadmap ideas into
scoped items. It is intent, not a contract, and nothing here is implemented
unless an item says so. [ROADMAP.md](https://github.com/aisecnomad/Project-Nexus/blob/main/ROADMAP.md)
carries the one-line summary of each item.

The six items are:

1. [Registry integrations](#1-registry-integrations-reg): AWS AgentCore
   Registry, Microsoft Agent 365, Gemini Enterprise, the official MCP Registry
   and A2A Agent Cards.
2. [Scheduled drift detection](#2-scheduled-drift-detection-drift) for a
   weekly enterprise CI run.
3. [Autonomy tiers](#3-autonomy-tiers-tier) L1 to L5.
4. An [enterprise inventory dashboard](#4-enterprise-inventory-dashboard-dash).
5. [Threat mapping](#5-threat-mapping-threat): OWASP, MITRE ATLAS and MAESTRO.
6. [Control mapping](#6-control-mapping-ctrl): ISO/IEC 42001, NIST AI RMF, the
   EU AI Act and AIUC-1.

## Recommended sequence

The ideas depend on each other. Tiers and corrected threat references change
what drift reports and what the dashboard shows, so they come first. The
dashboard comes last because it consumes everything else; a small first
version can ship early from data that already exists.

| Phase | Items | Why this order |
|-------|-------|----------------|
| 1. Foundations | THREAT-0, TIER-1, DASH-0 | THREAT-0 corrects references the scanner already publishes. Tiers are a new finding attribute that drift, the dashboard and control mapping all read. DASH-0 needs only `merge` output. |
| 2. Change detection | DRIFT-0 to DRIFT-4, REG-1, REG-4 | Weekly drift is the enterprise ask, and live connectors cannot be compared today. REG-1 extends the existing `cloud.aws` AgentCore code; REG-4 enriches MCP findings that already exist. |
| 3. Coverage | REG-2, REG-3, REG-5, THREAT-1 to THREAT-3, CTRL-0 to CTRL-2 | The Microsoft and Google registry APIs are newer and still moving. Control mapping reuses the THREAT-1 catalog engine. |
| 4. Fleet view | DASH-1 to DASH-3 | Trends need comparable drift history from phase 2. |

Sizes in this page are relative: S is days, M is one to two weeks and L is
several weeks of focused work, each including tests, fixtures and
documentation.

## Rules for every item

These restate [AGENTS.md](https://github.com/aisecnomad/Project-Nexus/blob/main/AGENTS.md)
for the new work. Each item's acceptance criteria assume them.

- **Declared is not observed.** A registry record, a Capability Card or a
  framework mapping is a claim. Findings keep claims and observations apart,
  and an observation never inherits confidence from a claim.
- **Fail closed.** A denied registry API, a truncated page, an unknown API
  version, an over-limit response or a catalog whose digest does not match
  makes the scan incomplete (exit 3). Missing data is never shown as zero.
- **No new trust paths.** Approval in a vendor registry does not give a
  finding sanctioned status by default. Names and aliases never do, as today.
- **References, not verdicts.** Threat and control mappings say a finding is
  relevant to an entry. ShadowScan never reports a system as compliant,
  certified, or attacked.
- **Offline first.** Every connector ships `collect()` and `analyze()`, offline
  fixtures under `tests/fixtures/`, a guide under `docs/connectors/`, a summary
  in `docs/connectors.md` and a regenerated `docs/connectors/reference.md`.
  Live calls use the shared HTTP client and keep its HTTPS, origin and
  private-address controls.
- **Redaction.** Registry records hold endpoint URLs, auth configuration,
  OAuth client IDs and headers. They are sanitized before they reach a finding,
  an export or a log.
- **Identity and rollout changes** update `CHANGELOG.md` (Unreleased) and
  `docs/production.md`.
- **Licensing.** Catalogs store framework identifiers and rationale in the
  project's own words. They do not copy control text from ISO/IEC 42001
  (copyrighted) or from any source whose licence has not been checked.

## 1. Registry integrations (REG)

### Problem

Enterprises now keep agents in vendor registries: the catalog an organization
says exists. ShadowScan finds what is actually deployed, configured or
running. The useful product is the difference between the two: agents running
outside every registry, and registry entries whose agents no longer exist or
changed.

### What exists

- `cloud.aws` lists Bedrock Agents and AgentCore runtimes, gateways, memories,
  browsers, code interpreters and workload identities (`_AGENTCORE_LISTS` in
  `shadowscan/connectors/cloud/aws.py`).
- `cloud.azure` discovers Foundry agents through the classic Agent Service
  contract. `lowcode.power_platform` covers Copilot Studio.
- `cloud.gcp` covers Vertex AI Agent Engine and Agentspace engines.
  Agentspace is the earlier name of Gemini Enterprise.
- The code connectors parse A2A Agent Cards (`agent-card.json`, and
  `agent.json` under `.well-known/`) in `semantic_config.py`, and MCP
  configurations.
- `shadowscan/registry.py` reconciles findings with a sanctioned inventory
  built from Capability Cards, lists or CSV. Only an exact resource pattern
  approves a finding.

None of these read a vendor registry.

### Design: three uses of a registry record

1. **Discovery evidence.** A record becomes a finding of kind `agent` or
   `mcp-server` with evidence type `registry-record`. Its weight reflects a
   declaration: the record proves someone registered the agent, not that it
   runs.
2. **Reconciliation.** Records are matched to observed findings by exact
   identity (ARN, Entra object ID, Google resource name or endpoint URL),
   never by display name. Each record and finding gets one status:
   - `registered-and-observed`
   - `registered-not-observed`, only when the observed scan covered the
     record's account, region and service; otherwise `not-comparable`
   - `observed-not-registered`, shadow with respect to that registry
3. **Optional inventory source.** An operator may list a registry under
   `inventory.trusted_registries`. Only then can an approved record make a
   finding sanctioned, and only through an exact resource binding. Draft,
   pending, rejected and deprecated records never approve anything. A revoked
   approval makes the finding shadow on the next scan.

**Implemented core.** The record contract, the reconciliation statuses and the
optional inventory source exist now, with the option named
`options.trusted_registries` and trust given per registry instance (type and
exact id), never per type. See
[vendor registries as inventory sources](../inventory.md#vendor-registries-as-inventory-sources).
The registry connectors below (REG-1 to REG-5) are still proposals.

Recommendation: vendor registries become services inside the existing
connectors (`cloud.aws`, `identity.entra` or a Graph sibling, `cloud.gcp`). They
reuse the credential handling, account scope, pagination limits and offline
export paths those connectors already have. A new `registry` surface would
duplicate that code and change the documented surface count. The MCP Registry
is a public catalog, not a tenant, so it is an enrichment source rather than
a connector.

### REG-1 AWS AgentCore Registry (M)

At research time the AgentCore Registry stores records of descriptor type
`MCP`, `A2A`, `CUSTOM` and `AGENT_SKILLS` behind an approval workflow. It has
two API families:

- Control plane: `ListRegistries` and `ListRegistryRecords`
  (`bedrock-agentcore-control`), which filter by name, status and descriptor
  type.
- Consumer: `ListDiscoverableRegistryRecords`,
  `BatchGetDiscoverableRegistryRecord` and `SearchDiscoverableRegistryRecords`
  in the newer `agent-registry` namespace. These return only records whose
  latest revision is approved, and summaries omit descriptors.

Scope:

- Use the control-plane listing so pending and rejected records are visible.
  If the audit role holds only consumer permissions, record the coverage as
  `approved-only`. Drift then treats that scan as not comparable with a full
  one.
- Support both namespaces, because registries created under the older
  `bedrock-agentcore` namespace do not expose the newer APIs.
- Add the read-only IAM actions to the documented audit policy.
- Correlate record descriptors (endpoints, runtime and gateway ARNs) with the
  existing `agentcore-runtime` and `agentcore-gateway` findings.

### REG-2 Microsoft Agent 365 (M to L)

Microsoft moved its agent registry from Entra to Agent 365 in the Microsoft
365 admin center during 2026. The Entra `agentRegistry` Graph beta resource
(agent card manifests, collections, instances) is marked deprecated in favour
of Agent 365 APIs. At research time the documented listing is Graph
`GET /copilot/admin/catalog/packages` plus a per-package details call,
with `CopilotPackages.Read.All` and the AI Administrator role. Seeing Entra
Agent ID details needs the Agent ID Administrator role.

Scope:

- Implement against the Agent 365 API. Accept the deprecated Entra registry
  only as an offline export, for tenants that saved one.
- Add Entra Agent ID `agentIdentity` objects to the Entra collection so agent
  identities correlate with registry packages.
- Correlate packages with `lowcode.power_platform` (Copilot Studio) and
  `cloud.azure` (Foundry) findings.
- Design spike first: `identity.entra` authenticates app-only with client
  credentials. Confirm that an application permission is enough without a
  directory role, and whether the endpoint is generally available or still in
  preview. A connector that needs a delegated admin session is a different
  operational model and needs its own production guidance.

### REG-3 Google Gemini Enterprise (L)

Google has two catalogs:

- The Google Cloud Agent Registry, which manages `Agent`, `McpServer`,
  `Endpoint`, `Skill` and `Publisher` resources (`gcloud alpha agent-registry`).
- Gemini Enterprise app agents, registered under
  `.../engines/ENGINE_ID/assistants/default_assistant/agents` in the Discovery
  Engine `v1alpha` API.

An agent registered directly through Discovery Engine may be missing from the
Agent Registry. The connector reads both and reports divergence as a finding
attribute rather than choosing one.

Scope:

- Pin each API version. An unknown or retired version makes the scan
  incomplete. Mark the service experimental while the APIs are alpha or beta.
- Correlate with the existing Agentspace engine and Agent Engine findings in
  `cloud.gcp`.
- Confirm the exact list methods in a design spike. At research time the
  published reference showed the resource model but not every list method.

### REG-4 Official MCP Registry (M)

The official registry at `registry.modelcontextprotocol.io` publishes metadata
about MCP servers. Server names live in namespaces that the registry verifies
(GitHub-based `io.github.<owner>/...`, or reverse DNS verified through DNS or
HTTP). The REST API uses cursor pagination and a `search` parameter. Secondary
sources report a `v0.1` API frozen since October 2025; confirm against the
live registry before implementation.

It is a public catalog of unverified claims, not a tenant inventory. Two uses:

1. **Provenance enrichment.** For each MCP server found by `code.mcp_config` or
   `endpoint.mcp`, record whether the package or remote URL is published, under
   which verified namespace, whether the configured version exists, and
   whether the entry is deprecated. Tags such as `mcp-unpublished` and
   `mcp-registry-deprecated` are review hints. A published server is not a safe
   server, so publication never lowers risk.
2. **Enterprise allowlist.** Many organizations run a private registry that
   implements the same API (a subregistry, or Azure API Center). An operator
   can name it as the approved MCP catalog. A configured server missing from it
   gets the governance factor `mcp-not-in-approved-registry`.

Scope:

- Offline by default. The operator fetches a snapshot, pins its SHA-256 in the
  scan configuration, and the scanner reads only that file. A digest mismatch
  makes the scan incomplete. A live fetch is opt-in, keeps the HTTPS and
  private-address controls, and caps pages and bytes. Hitting a cap makes the
  scan incomplete.
- No network calls during scans of untrusted repositories unless the operator
  opted in.
- Name similarity to published servers (possible typosquats) is a review hint
  with no risk weight until the evaluation corpus measures its precision.

### REG-5 A2A Agent Cards (M)

At research time there is no official central A2A registry. Discovery resolves
an Agent Card at `/.well-known/agent-card.json` (A2A 0.2 clients probe
`/.well-known/agent.json`). An IETF individual draft proposes DNS-SD discovery
for A2A; it is not an adopted standard.

Scope:

- Normalize A2A records from REG-1 to REG-3 into one A2A card model. All three
  registries can hold A2A entries.
- Add an opt-in `a2a.cards` probe of operator-listed base URLs only. It does
  not crawl or browse DNS-SD. It requires HTTPS, refuses cross-origin
  redirects, refuses private addresses unless `allow_private_origin` is set, and
  caps response size.
- Verify card signatures when the card carries one, and record
  `signature: verified | invalid | absent`. An invalid signature is a tag, not
  a dropped finding.
- Score card signals: no security scheme declared, plaintext `http://`
  interfaces, and skills that declare write or execution actions.
- Documentation must separate ShadowScan's Agent Capability Card
  (`agent-card.yaml`, the sanctioned-inventory format) from the A2A Agent Card.
  The two names collide.

### Acceptance criteria

- Offline fixtures per registry for a complete listing, a complete empty
  listing, a denied call, a truncated page and a malformed record. Denied and
  truncated cases exit 3. Per-connector coverage stays at or above 75%.
- Tests prove that a registry record never sets `shadow: false` unless its
  registry is listed in `trusted_registries` and the binding is an exact
  resource identity.
- `registered-not-observed` appears only when the observed scan's scope covers
  the record. Tests cover the out-of-scope case.
- Synthetic credentials in record auth configuration and endpoint URLs never
  reach findings, exports or logs.

## 2. Scheduled drift detection (DRIFT)

### Problem

Security teams want a scheduled job, typically weekly, that answers what
changed in the agent estate. That means new agents, removed agents, expanded
tools or permissions, higher autonomy and lost owners. The job must fail loudly
when it cannot see, rather than report "no change".

### What exists

- `shadowscan diff baseline.json current.json --fail-on-new` exits 2 on new
  findings or a higher risk level, and 3 when the comparison is incomplete
  (`shadowscan/comparison.py`). Findings missing from an incomplete comparison
  are `unknown`, never `resolved`.
- Only `code.filesystem`, offline exports from built-in connectors, and
  `gateway.logs` keyed with `SHADOWSCAN_IDENTITY_KEY` attest a comparable
  collection scope.
- **A comparison involving a live API connector always exits 3**
  ([CI integration](../operations/ci.md#exit-code-handling)). The cloud and
  SaaS tenants that matter most to enterprises cannot gate on drift today.
- Live scans can write record exports with a manifest, and fleet reports keep
  a derived scope fingerprint.
- `examples/github-action-code-scan.yml` already runs weekly, but it uploads
  SARIF; it does not compare against a baseline.

### Proposed

**DRIFT-0 Record, replay, compare (S).** Check and document an interim path:
collect live with a record export, replay each export through its manifest
filename, and diff the replays. This works only if replays of built-in exports
attest scope as the CI guide says. The live run must itself be complete
(`summary.complete` and `exported: true`). A replay attests the export's
contents, not the tenant's completeness, and the guide must say so.

**DRIFT-1 Attested scope for live connectors (L).** This is the main
engineering work. Each built-in live connector records:

- the tenant or account the API reports for the caller (for example STS
  `GetCallerIdentity` or the Graph organization), not the configured value
- the regions, services and API operations requested and enumerated, with
  each operation's outcome
- pagination completion
- scanner and signature digests

These go into `collection_scope`. A denied, throttled or truncated operation
makes the scan incomplete. Two scans compare only when their scope digests
match. Third-party plugins stay non-comparable.

**DRIFT-2 Drift classes (M).** Label each changed field with a class so
operators gate on what they care about:

| Class | Examples |
|-------|----------|
| `inventory` | New agent, removed agent (complete comparisons only) |
| `capability` | Tool added, permission or scope widened, MCP tool definition hash changed |
| `autonomy` | Tier floor or ceiling rose, approval gate removed (needs TIER-1) |
| `governance` | Owner lost, became shadow, registry approval revoked |
| `coverage` | Connector coverage or scope changed; never resolves findings |

Add `--fail-on-drift inventory,capability,autonomy,governance`. Today's
`--fail-on-new` keeps its meaning. This item absorbs the existing roadmap entry
for stronger comparison of MCP tool-definition changes.

**DRIFT-3 Baseline lifecycle (S to M).** A baseline is a reviewed artifact:

- stored outside the scanned repositories, in a private baseline repository or
  a protected artifact store
- referenced by SHA-256 in the workflow, with `diff` refusing a mismatch
- updated by a pull request to the baseline repository with code-owner review,
  never by the scheduled job itself
- expired after a configured age (for example 35 days); an expired baseline
  makes the comparison incomplete
- regenerated after scanner upgrades that change the identity schema, which
  `diff` already refuses to compare

**DRIFT-4 Weekly workflow template (S).** Add `examples/github-action-drift.yml`
and a Kubernetes CronJob variant:

- `schedule` once a week at an off-peak minute, plus `workflow_dispatch`. No
  `pull_request` trigger.
- Every action pinned by full commit SHA, and `persist-credentials: false` on
  checkout.
- Top-level `permissions: contents: read`. `id-token: write` only on the
  collection job, for OIDC federation into read-only cloud roles. No long-lived
  cloud keys.
- A GitHub environment limited to the default branch, and cloud trust
  policies that pin the OIDC subject to that environment, so forks and other
  branches cannot assume the cloud roles.
- `concurrency` to stop overlapping runs, a job timeout and a scan deadline.
- Reports uploaded as artifacts with short retention. The job summary shows
  counts per drift class only.
- Exit 2 opens or updates one issue in a private repository with counts and
  the run link. Exit 3 opens a separate coverage issue. Findings, tenant
  identifiers and exports never go into issues, summaries or logs.

### Acceptance criteria

- Mocked-transport fixtures for two identical complete live scans compare with
  no drift and exit 0. A scope change exits 3, a denied API exits 3, and a new
  agent exits 2.
- Each drift class has a fixture pair and a test.
- The workflow template passes the repository's action-pinning and
  credential-persistence checks.
- `docs/operations/ci.md`, `docs/production.md` and `CHANGELOG.md` describe the
  new comparison semantics.

## 3. Autonomy tiers (TIER)

### Problem

"Agent" covers everything from an FAQ bot to a scheduled coding agent that
merges its own changes. Risk owners need one label that says how much an AI
system can do without a person, and how sure the scanner is about that label.

### What exists

- Capabilities `autonomous`, `tool-use`, `code-exec`, `multi-agent` and others,
  set by many connectors. Posture tags such as
  `posture-permissions-bypassed` and `mcp-auto-approve`. The `autonomous`
  capability already adds a risk weight of 10.
- Capability Cards carry `autonomy_profile.level` as an integer with no
  defined scale. `card_stub_for` in `shadowscan/registry.py` writes 4, 3 or 2
  from capabilities.

### Taxonomy

**Superseded.** The maintainer chose a six-level scale: L0 Chatbot, L1
Copilot, L2 Supervised, L3 Semi-Autonomous / Agentic Workflow, L4 High
Autonomy, L5 Fully Autonomous, declared as `autonomy_profile.level` (0 to 5)
behind card `schema_version: 2`. TIER-1 implements it; see
[autonomy tiers](../concepts/autonomy.md). The table below is the original
proposal.

| Tier | Name | Who chooses the next step | Who starts it | Side effects |
|------|------|---------------------------|---------------|--------------|
| L1 | Chatbot | A person | A person | None. It answers. |
| L2 | Copilot | A person | A person | Proposed to a person, who approves each one, or read-only tools |
| L3 | Agentic workflow | A developer-defined path | A person or an event | Fixed steps; the model fills steps but does not choose the path |
| L4 | Semi-autonomous agent | The model, in a loop | A person or an event | Some actions need approval, or the action scope is bounded |
| L5 | Fully autonomous agent | The model | An event, a schedule or the agent itself | No per-action approval |

Examples: a chat-completion app with no tools is L1. An IDE assistant in its
default ask mode is L2. A Power Automate flow with an AI step is L3. A Bedrock
Agent with return of control on writes is L4. A scheduled coding agent with
`bypassPermissions`, or a ServiceNow agent marked autonomous, is L5.

### Classification is an interval

A scanner can prove that a capability exists. It usually cannot prove that one
is absent. A single tier would either overstate certainty or default to a low
tier, which fails open. Each finding therefore gets:

- `autonomy.floor`: the lowest tier the evidence proves
- `autonomy.ceiling`: the highest tier that positive evidence has not ruled out
- `autonomy.oversight`: `gated`, `bypassed` or `unknown`
- `autonomy.initiation`: `human`, `event`, `schedule` or `unknown`
- `autonomy.basis`: the evidence and rules that set each bound

Rules:

- The floor rises only on evidence. Tool definitions give at least L2. A fixed
  workflow with a model step gives at least L3. A model-driven tool loop (an
  agent factory, a Bedrock or Foundry agent) gives at least L4. An event or
  schedule trigger, a model-driven loop and bypassed approval together give L5.
- The ceiling falls only on positive evidence of restriction. A complete
  source analysis with no tools caps it at L1. A verified approval gate on
  every write tool caps it at L4. With no such evidence the ceiling is L5.
- `metadata.potential_capabilities` (imports and dependencies only) never
  raises the floor.
- Gates and policies read the ceiling. Reports show both bounds.
- A Capability Card's declared tier is compared with the interval. Declared
  below the floor adds the governance tag `autonomy-understated`. Declared
  above the ceiling is informational.
- The tier is not part of finding identity. Changes appear in `diff`
  `changed_fields` and feed the DRIFT `autonomy` class.

### Scope

- **TIER-1 (M):** the interval model, per-surface rule tables in a new concepts
  page, and evaluation corpus cases for each tier on each surface.
- **Card scale:** define `autonomy_profile.level` as 1 to 5 using this table,
  behind a card schema version. Cards without the version produce a warning
  and count as undeclared, so an older 1 to 4 scale is not misread.
  `card_stub_for` writes the floor.
- **Risk:** add an `autonomy` group to `risk_weights` with zero defaults, to
  avoid double counting the existing `autonomous` weight. Change defaults only
  after the evaluation corpus shows a benefit, with a changelog entry.
- **Crosswalk:** compare the tiers with the AWS Agentic AI Security Scoping
  Matrix and record the result. Do not claim alignment before that comparison.

### Acceptance criteria

- A property test shows that no finding gets a ceiling below L5 without
  recorded restriction evidence.
- Corpus cases per tier and surface pass with the expected floor and ceiling.
- Card stubs round-trip, and unversioned cards warn.

## 4. Enterprise inventory dashboard (DASH)

### Constraint

The roadmap does not plan a hosted scanning service. The dashboard is
therefore a static, self-contained HTML file built from reports the operator
already holds: no server, no outbound requests and no external assets, like
the existing HTML report. Teams that want a live dashboard feed the JSON or
CycloneDX output into their own BI or SIEM tools (DASH-3).

### What exists

- `shadowscan/reporters/html.py` produces a self-contained report with
  filters and evidence drill-down.
- `shadowscan merge` combines reports from many machines or scans and records
  `metadata.merged_from`. The result is incomplete when any source is.
- `--format cyclonedx` produces an AI-BOM, and `diff` produces drift.

### Proposed

- **DASH-0 (S):** `shadowscan dashboard fleet.json [--baseline old.json] -o
  dashboard.html`. The overview shows counts by surface, provider, account and
  owner; shadow, sanctioned and no-inventory status; risk distribution; and
  unowned agents. The **coverage panel comes first**: completeness per source
  and connector, last-scanned time and staleness. A cell for a source that was
  not collected reads "not collected", never 0.
- **DASH-1 (M):** trends from a directory of dated fleet reports. Weekly drift
  is computed only between comparable pairs; non-comparable gaps show as breaks
  in the series, not zeros.
- **DASH-2 (M):** views by autonomy tier against shadow status (shadow L4 and
  L5 agents are the priority quadrant), by registry reconciliation status, and
  by threat and control reference.
- **DASH-3 (S):** a documented, versioned `inventory.json` for BI and SIEM
  tools, with no credential fields.

### Security and scale

- The dashboard holds resource IDs, owners and accounts, so it inherits report
  confidentiality and the private file modes used for other outputs.
- All data is HTML-escaped and embedded as JSON. A strict Content Security
  Policy is set, and nothing is evaluated.
- A size budget and paging keep a fleet of 10,000 sources usable. A benchmark
  covers 100,000 findings.
- An incomplete fleet shows a banner and the command exits 3.

### Acceptance criteria

- Snapshot tests per view, and XSS tests with hostile titles, owners and
  resource names.
- Coverage tests: a failed source never renders as an empty or zero row.
- The core tables are readable with JavaScript disabled, and the controls work
  from the keyboard.

## 5. Threat mapping (THREAT)

### What exists

`shadowscan/compliance.py` maps nine tags to OWASP LLM, `OWASP-ASI` and MITRE
ATLAS identifiers. The HTML report shows them under "Compliance", SARIF
results carry them as tags, and JSON findings carry them as
`metadata.compliance`.

### Problems found while drafting

- **The identifiers name no edition, and several do not match the current
  lists.** In the OWASP Top 10 for LLM Applications 2025, LLM07 is System
  Prompt Leakage, yet `exposed-llm-server` and `unauthenticated-mcp` map to
  `OWASP-LLM-07`. In the OWASP Top 10 for Agentic Applications (December
  2025), ASI08 is Cascading Failures and ASI05 is Unexpected Code Execution.
  Yet `cluster-admin`, `privileged-pod`, `code-exec` and `saas-actions` map to
  `OWASP-ASI-08`, and `unauthenticated-mcp` maps to `OWASP-ASI-05`. ASI02 (Tool
  Misuse and Exploitation), ASI03 (Identity and Privilege Abuse) and ASI05 look
  closer for those tags. `hardcoded-credential` maps to supply-chain entries
  (`OWASP-LLM-03`, `OWASP-ASI-04`) where Sensitive Information Disclosure
  (LLM02) or ASI03 may fit better.
- OWASP and ATLAS are threat taxonomies, but the output labels them
  "Compliance".
- Only tags are mapped. Kinds, capabilities and autonomy are not.

### Proposed

- **THREAT-0 (S, do first).** Re-map against pinned editions and use
  edition-qualified identifiers such as `owasp-llm-2025:LLM06`,
  `owasp-asi-2026:ASI03` and `mitre-atlas:AML.T0051`, with the ATLAS release in
  catalog metadata. Rename the output to `metadata.threats`. ShadowScan is
  unreleased, so a rename with a changelog entry costs less now than an alias
  kept indefinitely. Add a regression test per mapping.
- **THREAT-1 (M).** Move mappings into data files (for example
  `shadowscan/mappings/threats/*.yaml`). Each catalog records framework,
  edition, source URL, licence and retrieval date. Each rule maps tags,
  capabilities, kinds, tier or posture to entries, with a rationale. A
  validator rejects unknown tags and entries, like
  `python -m shadowscan.signatures.validate`, and runs in `make check`. A
  generated reference page lists every rule.
- **THREAT-2 (S).** MAESTRO layer attribution. MAESTRO is the Cloud Security
  Alliance's agentic threat-modelling framework, organized in seven layers:
  foundation models, data operations, agent frameworks, deployment and
  infrastructure, evaluation and observability, security and compliance, and
  the agent ecosystem. The mapping says where in the stack a finding sits; it
  is not a threat ID. For example, an unsafe model serialization sits in layer
  1, an MCP configuration in layer 3, a privileged pod in layer 4, and
  disabled model-invocation logging in layer 5. Check the layer names against
  CSA's publication before shipping.
- **THREAT-3 (M).** Extend ATLAS coverage to the agent-specific techniques in
  the pinned release, only where a finding supplies a precondition. The output
  reads "enables" or "relevant to", never "observed attack" or "vulnerable".

### Acceptance criteria

- Every rule has a fixture finding and a test.
- Catalog validation runs in `make check`.
- SARIF tags and JSON identifiers are edition-qualified.

## 6. Control mapping (CTRL)

### Frameworks

| Framework | What ShadowScan can evidence | Notes |
|-----------|-------------------------------|-------|
| NIST AI RMF 1.0 and the Generative AI Profile (NIST AI 600-1) | GOVERN 1.6 calls for mechanisms to inventory AI systems, which is ShadowScan's core output. Ownership, monitoring cadence and risk evidence support other subcategories. | US government publications |
| ISO/IEC 42001:2023 | Annex A resource documentation (A.4) and AI system life cycle (A.6) evidence | Copyrighted: identifiers and own-words rationale only |
| EU AI Act, Regulation (EU) 2024/1689 | Evidence relevant to deployer obligations (Art. 26), record keeping (Art. 12), human oversight (Art. 14) and transparency (Art. 50) | Amended by the AI Omnibus. Secondary sources report Annex III high-risk obligations moved to 2 December 2027; verify against the Official Journal before publishing dates. |
| AIUC-1 | Evidence for its data and privacy, security, safety, reliability, accountability and society domains | Versioned quarterly; pin the version and check the licence before referencing control IDs |

ShadowScan cannot decide whether a system is high-risk under the EU AI Act,
because that depends on intended use. It reports evidence relevant to an
article, and goes further only when a Capability Card declares the risk
class.

### Proposed

- **CTRL-0 Evidence model (M).** Mappings attach to evidence ShadowScan
  produces: inventory completeness, ownership, shadow status, autonomy tier and
  oversight, logging configuration, credential hygiene and drift cadence. For
  each control the output lists the relevant findings and scan facts, the
  scope and completeness behind them, and gaps such as unowned agents. There
  is no pass or fail and no score.
- **CTRL-1 Catalogs (M).** Use the THREAT-1 engine. Where a published
  crosswalk exists (NIST publishes AI RMF crosswalks to other standards, and
  CSA published an AIUC-1 to OWASP agentic crosswalk), cite it rather than
  inventing one.
- **CTRL-2 Output (S).** A controls section in the Markdown and HTML reports,
  and a CSV for GRC tools.
- **CTRL-3 Declared facts (S).** Capability Card fields for facts the scanner
  cannot observe: EU AI Act risk class, intended purpose, oversight measures
  and AIUC-1 certification reference. Reports label them as declared.

### Review status

Mappings written by the single maintainer are author mappings. Reports and
docs label them "author mapping, not independently reviewed" until an
independent reviewer signs off, in line with AGENTS.md.

### Acceptance criteria

- Every mapping has a rationale and a test.
- No output contains "compliant", "certified" or a compliance score.
- An incomplete scan marks the control report incomplete and exits 3.

## Open questions for the maintainer

1. Registry services inside existing connectors (recommended), or a new
   `registry` surface?
2. Should `trusted_registries` exist at all, or should vendor approval stay
   reconciliation-only? The recommendation is opt-in per registry with exact
   binding.
3. Redefine `autonomy_profile.level` behind a card schema version
   (recommended), or add a new `autonomy_profile.tier` field?
4. Should autonomy risk weights start at zero (recommended)?
5. Rename `metadata.compliance` to `metadata.threats` and `metadata.controls`
   before the first release (recommended), or keep an alias?
6. Agent 365: is a preview API or a delegated admin session acceptable for a
   built-in connector?
7. Licensing: may catalogs reference ISO/IEC 42001 and AIUC-1 control
   identifiers?

## Sources

These were consulted on 2026-10-10. Vendor APIs in this space change quickly,
so each REG item starts with a spike that confirms them.

- AWS: [ListRegistryRecords API](https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_ListRegistryRecords.html),
  [Browse approved records](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-browse-records.html),
  [Search registry records](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-search-records.html),
  [Agentic AI Security Scoping Matrix](https://aws.amazon.com/ai/security/agentic-ai-scoping-matrix/)
- Microsoft: [Agent 365 Graph API for the agent registry](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/graph-api),
  [Agent Registry in the Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-registry?view=o365-worldwide),
  [Entra Agent ID APIs in Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-beta)
- Google: [Agent Registry overview](https://docs.cloud.google.com/agent-registry/overview),
  [Register and manage A2A agents in Gemini Enterprise](https://docs.cloud.google.com/gemini/enterprise/docs/register-and-manage-an-a2a-agent),
  [Agent Platform API reference](https://docs.cloud.google.com/gemini-enterprise-agent-platform/reference/rest)
- MCP: [Official MCP Registry](https://registry.modelcontextprotocol.io/)
- A2A: [A2A project](https://github.com/a2aproject/A2A),
  [draft-zhao-a2a-dns-sd-00](https://datatracker.ietf.org/doc/draft-zhao-a2a-dns-sd/)
- OWASP: [Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/),
  [Top 10 for Agentic Applications](https://genai.owasp.org/)
- MITRE: [ATLAS](https://atlas.mitre.org/)
- Cloud Security Alliance: [AIUC-1 and OWASP agentic crosswalk](https://labs.cloudsecurityalliance.org/research/csa-research-note-aiuc1-owasp-agentic-crosswalk-20260804-csa/)
- NIST: [AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- EU: [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
