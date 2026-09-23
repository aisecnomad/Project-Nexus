# Sanctioned inventory and shadow reconciliation

ShadowScan calls a finding **shadow** when nothing in the sanctioned inventory
claims it. Without an inventory every finding has `shadow: null` and the
report is a plain discovery; with one, the risk model adds +25 for unregistered
agents, −10 for registered ones, and registered findings inherit the owner
recorded on their card.

## Formats

### Agent Capability Cards (one YAML per agent)

The format used by this repository (the `Agent Card` file at the repo root). ShadowScan reads
`metadata.agent_id`, `metadata.name`, `metadata.owner_team` / `owner`,
`metadata.classification`, and an optional `discovery:` block:

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
  names: ["ops provisioning agent", "ops-agent"] # aliases matched as whole words in titles / name fields
  frameworks: [cloud.aws-bedrock-agents]        # informational
  surfaces: [cloud, code, gateway]              # informational
```

`[cite_start]` / `[cite: n]` markers left by document exports are ignored.

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

## Matching rules (in order)

1. **Resource pattern** — `discovery.resources` globs against `finding.resource`
   (case-insensitive). Resource ids are stable and documented per connector:
   ARNs, `projects/…/reasoningEngines/…`, ARM ids, OCIDs, `okta:app:<id>`,
   `entra:sp:<objectId>`, `github:<org>/<repo>/<path>`, `slack:app:<id>`,
   `power-platform:bot:<botid>`, `salesforce:genai-planner:<id>`,
   `servicenow:sn_aia_agent:<sys_id>`, `n8n:workflow:<id>`, `cloudtrail:<principal arn>`, `jwt:<hash>`…
2. **Agent id** — `metadata.agent_id` appears as the tail of the resource id
   (`…/ops-provisioning-04`, `…:ops-provisioning-04`) or in a name field of the
   finding's metadata (`agent_name`, `name`, `names`, `display_name`,
   `agent_definitions[].name`, …). This is how a Bedrock agent, the Terraform
   that creates it and the IAM role named after it all resolve to one card
   without listing every ARN.
3. **Name / alias** — the card's `name` and `discovery.names` matched as whole
   words against the finding title, resource and name fields.

`shadowscan inventory check inventory/` lists what was loaded and how each
entry can match.

## From shadow to registered

```
shadowscan scan -c shadowscan.yaml --format json -o today.json
shadowscan inventory stubs today.json -o inventory/pending/ --min-risk medium
```

`inventory stubs` writes one capability-card skeleton per shadow finding (agent,
mcp-server, workflow, bot-app, agent-config by default): the discovered
resource goes into `discovery.resources`, detected capabilities into
`capability_surface`, the risk score into `risk_scoring`, and the owner (when
known) into `owner_team`. Review, complete and move the card into the inventory
directory; on the next scan the finding is registered and its risk drops.

Track drift between runs with `shadowscan diff last.json today.json`: new
findings, resolved findings and risk-level changes.
