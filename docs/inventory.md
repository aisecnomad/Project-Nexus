# Sanctioned inventory and shadow reconciliation

ShadowScan calls a finding **shadow** when nothing in the sanctioned inventory
claims it. Without an inventory every finding has `shadow: null` and the
report is a plain discovery; with one, the risk model adds +25 for unregistered
agents, −10 for registered ones, and registered findings inherit the owner
recorded on their card.

## Formats

### Agent Capability Cards (one YAML per agent)

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
