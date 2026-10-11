# Autonomy tiers

"Agent" covers everything from an FAQ bot to a scheduled coding agent that
changes code without asking. ShadowScan labels each applicable finding with how
much it can do without a person, on a six-step scale, and with how sure the
evidence makes that label.

## Scale

| Level | Name (`machine name`) | Who decides, who starts it, who approves side effects |
|-------|----------------------|--------------------------------------------------------|
| L0 | Chatbot (`chatbot`) | Answers only. No tools or actions. A person starts every exchange. |
| L1 | Copilot (`copilot`) | Assists a person inside their session: drafts, suggests, retrieves with read-only tools. The person performs or confirms every action. |
| L2 | Supervised (`supervised`) | Runs tool actions with side effects, but a person approves each side-effecting action. A person starts it. |
| L3 | Semi-Autonomous / Agentic Workflow (`semi-autonomous`) | Multi-step execution (a developer-defined workflow, or a model-driven loop with bounded scope) where approval happens at checkpoints, not per action. May be event-triggered. |
| L4 | High Autonomy (`high-autonomy`) | The model plans and acts in a loop with write or execution capabilities and no per-action approval; people supervise by exception. |
| L5 | Fully Autonomous (`fully-autonomous`) | Starts itself (event, schedule or another agent), acts with no approval gates and with write, execute or delegated capabilities; people only monitor. |

## An interval, not a single level

A scanner can prove that a capability exists. It can rarely prove that one is
absent. A single level would either overstate certainty or fall back to a low
level, which fails open. Each applicable finding therefore carries an interval
in `metadata.autonomy`:

```json
"autonomy": {
  "schema": "shadowscan.autonomy/v1",
  "floor": 3, "floor_label": "L3 Semi-Autonomous / Agentic Workflow",
  "ceiling": 5, "ceiling_label": "L5 Fully Autonomous",
  "oversight": "unknown",
  "initiation": "schedule",
  "basis": [
    {"bound": "floor", "rule": "ai-system", "value": 0},
    {"bound": "floor", "rule": "tool-access", "value": 1},
    {"bound": "floor", "rule": "agentic-execution", "value": 3},
    {"bound": "ceiling", "rule": "no-restriction-evidence", "value": 5},
    {"bound": "oversight", "rule": "no-oversight-evidence", "value": "unknown"},
    {"bound": "initiation", "rule": "schedule-trigger", "value": "schedule"}
  ],
  "declared": 2,
  "declared_source": "lead-qualifier"
}
```

- `floor`: the lowest level the finding's evidence proves. It rises only on
  evidence.
- `ceiling`: the highest level that positive evidence has not ruled out. It
  is 5 unless the finding records positive restriction evidence. Absence of a
  capability or a tag is never restriction evidence: unknown never counts as
  low.
- `oversight`: `bypassed` (some evidence says actions run without approval),
  `gated` (some evidence says a person approves some or all actions) or
  `unknown`.
- `initiation`: `schedule`, `event`, `human` or `unknown`.
- `basis`: every rule that fired, as `{bound, rule, value}`, sorted by bound
  and rule order, at most 32 entries. Rule ids come from the closed set below.
  The basis never holds evidence text, resource names or credentials: a floor
  or ceiling value is a level and an oversight or initiation value is one of
  the values above, and `shadowscan merge` refuses a source block that breaks
  this. The finding's capabilities, tags and evidence show what each rule read.
- `declared` and `declared_source`: only when the finding matched an inventory
  entry that declares a level; see [Declared and observed levels](#declared-and-observed-levels).

Gates and policies should read the ceiling rather than the floor; reports show
both bounds. Only a recorded approval setting lowers the ceiling (to L2), and
such a setting describes configuration the scan read, not a given run: flags,
settings in scopes the scan did not read, or an offline export that misstates
them can let an agent do more. Treat an L2 ceiling as configuration evidence,
not proof, and an L5 ceiling as "not ruled out". The interval is not part of
finding identity, so a change in autonomy keeps the finding id.

The classification is a pure function of the finding
(`shadowscan.autonomy.classify`). The engine computes it after merging and
correlation, on every run, so incrementally cached findings are classified like
fresh ones, and any `metadata.autonomy` a plugin or an earlier pass wrote is
replaced. It reads static configuration and collected records: a level states
what the evidence allows, not what a deployed agent did, and it has not been
validated against a live tenant.

### Applicable kinds

`agent`, `framework-usage`, `agent-config`, `mcp-server`, `workflow`,
`bot-app`, `gateway-caller`, `ai-app`, `runtime-process` and `cloud-resource`.

Autonomy is not a property of `secret`, `token`, `oauth-grant`,
`service-identity`, `iam-grant`, `infra`, `local-model` or `network-contact`
findings: they enable an AI system rather than act. They carry no
`metadata.autonomy`; the correlated agent finding (`metadata.related`) carries
it.

## Rules

### Floor (the highest rule that fires)

| Rule | Level | Fires when |
|------|-------|------------|
| `ai-system` | 0 | The finding's kind is applicable. |
| `tool-access` | 1 | Capability `tool-use`, `rag`, `browsing`, `data-access` or `memory`. |
| `side-effect-tools` | 2 | Capability `saas-actions`, `code-exec` or `delegated-identity`, or tag `write-access`. |
| `agentic-execution` | 3 | Kind `workflow`; capability `multi-agent`; or a model-driven loop: kind `agent` with `tool-use`, unless a person approves every side-effecting action (the loop is then Supervised by definition). |
| `unapproved-side-effects` | 4 | Approval-bypass evidence (below) and capability `saas-actions`, `code-exec`, `delegated-identity` or `data-access`. |
| `self-initiated` | 5 | The L4 conditions and initiation `schedule` or `event`. |

`metadata.potential_capabilities` (features supported only by imports or
dependencies) are not capabilities and never raise the floor.

### Approval-bypass evidence

- Tag `posture-permissions-bypassed`: Claude Code
  `permissions.defaultMode: bypassPermissions`, Codex
  `approval_policy = "never"`, Goose `GOOSE_MODE: auto`.
- Tag `mcp-auto-approve`, or an enabled server in `metadata.servers` whose
  `auto_approve` is `true` or a nonempty tool list (`autoApprove`,
  `alwaysAllow`). A disabled server runs nothing.
- A Claude Code allow rule for every shell command (`posture-unrestricted-shell`
  from `permissions.allow`). OpenClaw `capabilities.shell_access` grants shell
  access and says nothing about approval, so it is not bypass evidence.
- The `autonomous` capability, when it records a run without per-action
  approval; see the next section.

### What the `autonomous` capability means at each site

Connectors set `autonomous` for different reasons. ShadowScan reads it as
approval-bypass evidence only where it means that no person approves each step.
A trigger, a schedule or an around-the-clock cadence means that no person
starts the run; that is initiation evidence and does not show that a flow lacks
an approval step.

| Site | Meaning | Used as |
|------|---------|---------|
| Agent settings posture (Claude Code, Codex, Goose bypass modes) | Tool calls run without approval | Approval bypass |
| AutoGen `human_input_mode="NEVER"` (code) | The agent never asks a person | Approval bypass |
| Model-selected tool dispatch loops (code) | Each tool the model picks runs and feeds back without approval | Approval bypass |
| Signature `heuristic.autonomy` (code: `human_in_the_loop=False`, `--dangerously-skip-permissions`, `autoApprove` and similar) | Code disables an approval gate | Approval bypass, even next to a trigger |
| Other signature capabilities (agent-loop idioms, autonomous agent frameworks, coding agents) | The signature author's claim that it runs without a person | Approval bypass, unless a trigger explains the capability |
| ServiceNow AI agent `autonomous` flag, or `agent_type` exactly `autonomous` | The agent is configured to act without a person | Approval bypass |
| n8n, Make, Zapier, Workato schedule, webhook and app triggers | A schedule or an event starts the flow (tags `scheduled`, `event-triggered`). A trigger a person operates (an n8n manual, chat, form or evaluation trigger; a Make on-demand scenario; a Workato Workbot command; a Zapier Chrome extension push or Interfaces form) records neither | Initiation only |
| Power Automate recurrence | A schedule starts the flow (tag `scheduled`) | Initiation only |
| Salesforce flow `TriggerType` | A schedule or a record or platform event starts the flow (`metadata.trigger_type`) | Initiation only |
| ServiceNow use case and trigger records | A record or application event (tag `event-triggered`) or a schedule (tag `scheduled`) starts the use case. A use case without a trigger runs from a conversation and records neither | Initiation only |
| Azure Logic App recurrence | A schedule starts the flow (`metadata.trigger_types`) | Initiation only |
| GCP Cloud Function `eventTrigger` | An event starts the function (`metadata.trigger`) | Initiation only |
| Gateway caller active around the clock | Cadence of an unattended caller (tag `always-on`) | Initiation only |
| AWS Step Functions state machine with LLM steps | An unattended workflow definition | Neither: the kind `workflow` already sets L3 |
| Signature `heuristic.scheduled-agent` | Code wired to a scheduler, queue or webhook | Explains the capability; not initiation evidence (it cannot tell a schedule from an event) |

So `autonomous` counts as approval bypass when the finding carries
`heuristic.autonomy` evidence, or when it is not a `workflow` and carries no
trigger evidence (trigger tags, trigger metadata or `heuristic.scheduled-agent`
evidence). When a trigger explains the capability, the scanner cannot tell from
the finding whether another site also set it; it counts the capability as
initiation evidence, and the ceiling stays open.

### Ceiling

| Rule | Ceiling | Fires when |
|------|---------|------------|
| `no-restriction-evidence` | 5 | No positive restriction evidence. |
| `per-action-approval` | 2 | `metadata.approval_gate.scope` is `every-action` and there is no approval-bypass evidence. |
| `conflicting-evidence` | the floor, or 5 | The floor rules exceed a lowered ceiling (the ceiling becomes the floor), or every-action gating sits next to approval-bypass evidence (the gating rules nothing out). |
| `declared-above-ceiling` | unchanged | Note: a matched inventory entry declares a level above the ceiling. |

Partial gating (`approval_gate.scope: some-actions`, or tag `asks-user`)
makes oversight `gated` but does not lower the ceiling: only evidence that
rules a level out lowers it. The tag `asks-user` (a Bedrock agent's user-input
action group) shows a person at some steps, not approval of each action. An
MCP configuration without auto-approval is not gating evidence either: the
client may still approve tools some other way. Lifecycle tags (`disabled`,
`inactive`, `suspended`) do not change any bound.

### Oversight and initiation

| Rule | Value | Fires when |
|------|-------|------------|
| `approval-bypassed` | `bypassed` | Any approval-bypass evidence. |
| `approval-gated` | `gated` | Otherwise, any `approval_gate` or tag `asks-user`. |
| `no-oversight-evidence` | `unknown` | Otherwise. |
| `schedule-trigger` | `schedule` | Tag `scheduled` or `always-on`; Salesforce `trigger_type: Scheduled`; workflow `trigger_types` `Recurrence` or `SlidingWindow`. |
| `event-trigger` | `event` | Tag `event-triggered`; Salesforce `trigger_type` `RecordAfterSave`, `RecordBeforeSave`, `RecordBeforeDelete` or `PlatformEvent`; workflow `trigger_types` `ApiConnection`, `ApiConnectionWebhook`, `OpenApiConnection`, `OpenApiConnectionWebhook` or `HttpWebhook`; a function `trigger` naming an event type. |
| `interactive-client` | `human` | An endpoint editor extension, browser extension or command found in shell history (`resource_type` `ide-extension`, `browser-extension`, `cli-usage`), with no trigger evidence. |
| `no-initiation-evidence` | `unknown` | Otherwise. A configured client (`agent-config`) can also run unattended, for example a personal agent gateway or a CI job, so it is not person-started evidence. |

## Approval gating evidence

Connectors record positive approval gating as `metadata.approval_gate`:
`{"scope": "every-action" | "some-actions", "settings": [...]}`. Nothing is
recorded without a setting; an unset option is not evidence.

| Source | `every-action` | `some-actions` |
|--------|----------------|----------------|
| Claude Code settings (`code.filesystem`, `endpoint.inventory`) | `permissions.defaultMode` `default` or `plan` | `acceptEdits`; a nonempty `permissions.allow` list in any settings file the finding reports; and, only next to another setting, a sandbox that auto-allows Bash or a `PreToolUse` or `PermissionRequest` hook |
| Codex `config.toml` | `approval_policy = "untrusted"` (a profile counts only when the top level is also `untrusted`) | `on-request`, `on-failure`, or an `untrusted` profile over another default |
| Goose `config.yaml` | `GOOSE_MODE: approve` | `GOOSE_MODE: smart_approve` |
| Bedrock agent action groups (`cloud.aws`) | Every enabled action group other than the user-input group defines functions, and each function sets `requireConfirmation: ENABLED` | Some functions require confirmation |

A coding-agent finding is `every-action` only when every recorded setting is
and no posture issue (`posture-permissions-bypassed`,
`posture-unrestricted-shell`) lets an action run unapproved. Settings are
combined across the files the finding reports, so allow rules in
`.claude/settings.local.json` make a `default` mode in `.claude/settings.json`
partial. A Claude Code sandbox with `sandbox.enabled` and
`autoAllowBashIfSandboxed` not `false` (the default is `true`) runs Bash
commands without a prompt, and a `PreToolUse` or `PermissionRequest` hook can
allow a call; each is a `some-actions` setting that makes the gate partial but
records no gate on its own, because it configures no approval. A
`permissions.allow` value that is not a list counts as allow rules, and a
`permissions`, `sandbox` or `hooks` value that is not a mapping makes the gate
partial in the same way. Codex
`on-request` lets the model decide when to ask, so it gates only some actions.
A settings file says how an agent is configured, not how a given run was
started: command-line flags (for example `--dangerously-skip-permissions`) and
settings in scopes the scan did not read can override it. A Bedrock code
interpreter or OpenAPI-schema action group has no per-function setting this
reader verifies, so it leaves the gate partial, and a function entry that is
not an object leaves it partial and marks the scan incomplete. A settings file
of the client that could not be read (invalid syntax, a symbolic link the scan
does not follow, a file over the size limit or one that cannot be decoded; a
problem with one MCP server entry in a file that parsed does not count) adds a
`settings-file = unreadable` entry: it records no gate on its own and keeps a
gate from the client's other settings at `some-actions`, because the unread
file could loosen it. Endpoint replay that drops a malformed approval or
posture entry, or skips a malformed settings record, also keeps the gate at
`some-actions`.

## Per-surface evidence

| Surface | Evidence that raises the floor | Evidence that gates or restricts | Initiation evidence |
|---------|-------------------------------|----------------------------------|---------------------|
| Code | Capabilities from verified source analysis and signatures; agent kind with `tool-use`; posture bypass tags; MCP auto-approval; `heuristic.autonomy` | Coding-agent `approval_gate` | `heuristic.scheduled-agent` explains `autonomous` only |
| Endpoint | Configured clients' signature capabilities; posture bypass tags; MCP auto-approval | Coding-agent `approval_gate` | Editor and browser extensions, shell history: `human` |
| Runtime | Capabilities of the observed product | None | None |
| Low-code | Workflow kind (L3); agents with tool records (a ServiceNow agent carries `tool-use` only with tool records, and `saas-actions` only when a tool is not a retrieval); `saas-actions`; ServiceNow autonomous agents | None | Schedule and event tags (a trigger a person operates records neither), Salesforce `trigger_type`, Power Automate recurrence |
| SaaS | Bot and app capabilities; tag `write-access` | None | None |
| Cloud | Agent resources with tools; action groups and code interpreters (`code-exec`); workflows (Step Functions, Logic Apps); `multi-agent` collaborators | Bedrock `requireConfirmation`; `asks-user` (partial) | Logic App `trigger_types`, Cloud Function `trigger` |
| Gateway | Tool-use and multi-agent request shapes | None | Tag `always-on` |
| Identity, network | Not applicable: grants, identities, tokens and network contacts carry no autonomy | | |

## Declared and observed levels

An inventory entry can declare the level the agent is approved for:

- An Agent Capability Card with top-level `schema_version: 2` declares
  `autonomy_profile.level`, an integer from 0 to 5 on this scale. A missing or
  null level is undeclared. Any other value, an `autonomy_profile` that is not
  a mapping, or a `schema_version` other than 1 or 2 makes the card invalid.
- A card without `schema_version`, or with `schema_version: 1`, used an
  undefined scale: its `autonomy_profile.level` is ignored and counts as
  undeclared. `shadowscan inventory check` prints
  `autonomy_profile.level ignored: card has no schema_version 2`, and scans
  record the same advisory warning under `engine.inventory`; it does not make
  the scan incomplete.
- Simple YAML or JSON entries accept `autonomy_level` (0 to 5), and CSV files an
  `autonomy_level` column (a blank cell is undeclared).

When a finding matches an entry that declares a level, `metadata.autonomy`
records `declared` and `declared_source` (the entry's agent id):

- declared below the floor adds the tag `autonomy-understated` (risk weight
  10: the declared level is below what the evidence proves);
- declared above the ceiling adds the basis note `declared-above-ceiling`
  only;
- otherwise the declaration is consistent with the evidence.

`shadowscan inventory stubs` writes `schema_version: 2` cards whose
`autonomy_profile.level` is the finding's observed floor (from a well-formed
`metadata.autonomy` in the report, else recomputed). The floor is a lower
bound: review it and set the level the agent is approved for. A finding kind
without autonomy gets a card without a level. See
[the inventory guide](../inventory.md).

## Risk

`options.risk_weights.autonomy` weighs the observed floor, with keys `L0` to
`L5` and default 0 for every level. A nonzero weight adds the factor
`autonomy:L<n>` ("observed autonomy floor L<n> <label>"); a zero weight adds
nothing. Unknown keys are rejected. The defaults are zero because the
`autonomous` capability and the approval-bypass tags already score the
evidence behind a high floor. The factor is computed from the finding, not
read from `metadata.autonomy`, and counts toward `danger_score`. See
[risk scoring](risk.md).

## Merged reports

`shadowscan merge` classifies each merged finding again from its merged
capabilities, tags, evidence and metadata, together with the widest oversight
and initiation any source's block records, so the combination rules apply
across sources: approval bypassed in one source, a side-effecting capability
and a schedule trigger recorded by another give floor L5
(`unapproved-side-effects`, `self-initiated`), as they would in one scan. It
then widens the interval so it admits at least what every source's block
admits: the highest floor and the highest ceiling, oversight `bypassed` over
`unknown` over `gated`, and initiation `schedule` over `event` over `unknown`
over `human`. A widened bound keeps the basis rules of the source block that
set it. Approval-bypass evidence that only a later source recorded therefore
raises the merged interval, and an approval gate that only one source recorded
cannot lower it below another source's block. A declared level applies only
while the merged finding is registered (sources with an inventory matched it
to one agent and none found it unregistered; see
[fleet merge](../scanning.md#fleet-merge)). The lowest level any source
declares for that agent is kept, whatever the order of the sources, and is
compared with the merged interval again (`autonomy-understated`,
`declared-above-ceiling`). A merged finding that a source left unregistered,
or that sources matched to different agents (ambiguous), carries no declared
level. Risk keeps the highest source score and is not rescored, so its factors
can still include `tag:autonomy-understated` from a source whose own match
was registered. A source whose autonomy block is malformed
is rejected ("rescan before merging"). Findings from reports written before
this field existed are classified from the merged finding alone.
[`shadowscan dashboard`](../operations/dashboard.md) reads a single report
the same way, so one report shows the tiers it would show among others.

## Limits

- The classification reads collected configuration and records. It does not
  observe a run, and flags or settings outside the scanned scope can change
  what an agent does.
- The rules and fixtures are author-written and synthetic. They have not been
  validated against live tenants, and a comparison with other autonomy
  frameworks (for example the AWS Agentic AI Security Scoping Matrix) has not
  been made.
