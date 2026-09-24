# Sanctioned inventory and shadow reconciliation

ShadowScan calls a finding **shadow** when nothing in the sanctioned inventory
claims it. Without an inventory every finding has `shadow: null` and the
report is a plain discovery; with one, the risk model adds +25 for unregistered
agents, −10 for registered ones, and registered findings inherit the owner
recorded on their card.

## Formats

### Agent Capability Cards (one YAML per agent)

The bundled example is [`agent-card.yaml`](../agent-card.yaml). ShadowScan reads
`metadata.agent_id`, `metadata.name`, `metadata.owner_team` / `owner`,
`metadata.classification`, and a `discovery:` block required for automatic registration:

```yaml
metadata:
  agent_id: "ops-provisioning-04"
  version: "2.4.1"
  owner_team: "Platform-Engineering"
  classification: "Internal-Restricted"
# ... autonomy_profile, identity_and_delegation, capability_surface, security_controls, risk_scoring ...
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
```

Standalone `[cite_start]` / `[cite: n]` export markers are ignored only in the
leading document preamble. Markers inside resource patterns are rejected so
that removing one cannot silently broaden an approval.

### Simple list

```yaml
agents:
  - id: claims-assistant
    name: Claims Assistant
    owner: claims-it
    resources: ["ocid1.genaiagent.oc1.us-chicago-1.agent1"]
    names: [claims bot]
```

### CSV

```
agent_id,name,owner,resources,names
hr-helper,HR Helper,erin@acme.com,power-platform:bot:bot-1|okta:app:0oa9x,HR bot|hr assistant
```

Pass any mix with `--inventory` (repeatable) or `inventory:` in the config;
directories are searched recursively.

YAML and JSON list fields (`resources`, `names`, `surfaces`, `providers`,
`accounts`, `regions`, `frameworks`, `tags`) must be arrays of nonempty strings. Quote
numeric account IDs. Optional lists may be omitted or empty; scalar strings
are rejected rather than interpreted character by character. CSV retains
pipe-separated lists. Malformed entries, duplicate keys, unknown simple-inventory
or discovery fields and inconsistent CSV columns fail validation before scanning.

## Matching and approval

Automatic registration requires exactly one matching `discovery.resources`
pattern (or `resources` in the simple format). Resource matching is case-sensitive.
Optional `surfaces`, `providers`, `accounts`, and `regions` lists are enforced; a finding
without a required scope cannot match. A missing resource or one whose
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

**Migration:** cards that previously matched by name need explicit resource
bindings. The bundled `agent-card.yaml` contains example bindings for offline AWS
fixtures; replace them with your reviewed identities before production use.

`shadowscan inventory check inventory/` lists what was loaded and how each
entry can match.

## From shadow to registered

```
shadowscan scan -c shadowscan.yaml --format json -o today.json
shadowscan inventory stubs today.json -o inventory/pending/ --min-risk medium
```

`inventory stubs` writes one capability-card skeleton per shadow finding (agent,
mcp-server, workflow, bot-app, agent-config by default): the discovered
resource goes into `discovery.resources` with literal glob characters escaped
so the generated card approves only that exact resource. A redacted resource or
scope leaves `discovery.resources` empty pending an identity review. Generated
cards also bind the finding's region when present. Detected capabilities go into
`capability_surface`, the risk score into `risk_scoring`, and the owner (when
known) into `owner_team`. Review, complete and move the card into the inventory
directory; on the next scan the finding is registered and its risk drops.

Track drift between runs with `shadowscan diff last.json today.json`: new
findings, risk-level changes and resolved findings from complete, comparable
scans. Missing findings from incomplete or differently scoped scans remain
unknown. See [comparison semantics](scanning.md#comparing-reports).

Generated stub files use mode 0600 in a 0700 output directory. Deliberate wildcard
approvals remain supported in manually reviewed inventory entries. Do not remove
the escaping in a generated resource binding unless a broader approval is intended.
