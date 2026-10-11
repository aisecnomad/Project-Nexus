# Low-code connectors

Low-code connectors discover AI agents, bots, and automation workflows on
citizen-developer platforms like Power Platform, Salesforce, ServiceNow,
and workflow automation tools.

!!! info "Live and offline"
    All low-code connectors support both live API collection and offline
    export analysis.

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

## `lowcode.power-platform`
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

## `lowcode.salesforce`
SOQL/Tooling: `BotDefinition`/`BotVersion` (Einstein bots & Agentforce
agents), `GenAiPlannerDefinition`/`GenAiPluginDefinition`/`GenAiFunctionDefinition`
(topics, actions, Apex/Flow targets), `GenAiPromptTemplate`, `FlowDefinitionView`
with AI hints, `ConnectedApplication` + `OauthToken` (user-authorised apps,
aggregated). Auth: `access_token` or client-credentials connected app. A flow
whose `TriggerType` is `Scheduled`, `RecordAfterSave`, `RecordBeforeSave`,
`RecordBeforeDelete` or `PlatformEvent` carries `autonomous` as initiation
evidence, with the value in `metadata.trigger_type`.

## `lowcode.servicenow`
Table API: `sn_aia_agent`, `sn_aia_tool`, `sn_aia_usecase`, `sn_aia_trigger`,
`sys_hub_flow` (AI hints), `oauth_entity`. Auth: basic or bearer. Live
collection reads each table in windows of 500 rows (`sysparm_offset` 0, 500,
1000, ...). ACLs remove rows after `sysparm_limit` is applied, so a window can
come back short or even empty before the end of the table: collection stops
only when the windows cover the table's `X-Total-Count`, the number of rows the
query matches before that filtering. A response without a valid `X-Total-Count`
cannot prove where the table ends: an empty page then ends the table with a
warning and the scan is incomplete. `max_pages` bounds each table, and reaching
it is incomplete. An AI agent carries `tool-use` only when the export holds its
`sn_aia_tool` records, and `saas-actions` only when one of them is not a
retrieval tool; the `autonomous` capability needs the agent's `autonomous`
flag or an `agent_type` of exactly `autonomous`. A use case or its
`sn_aia_trigger` records add `scheduled` for a scheduled trigger and
`event-triggered` for a record or application trigger; a use case without a
trigger, which runs from a conversation, adds neither.

## `lowcode.n8n` · `lowcode.make` · `lowcode.zapier` · `lowcode.workato`
Workflows/scenarios/zaps/recipes with AI or agent steps (n8n LangChain nodes,
Make AI modules and AI Agents, Zapier AI/Agents from account exports, Workato
GenAI/agentic providers); triggers, code steps (→ code-exec), models. A
schedule trigger adds the `scheduled` tag and a webhook, polled or chained
trigger the `event-triggered` tag, each with the `autonomous` capability as
initiation evidence (see [autonomy tiers](../concepts/autonomy.md)). A trigger
a person operates adds neither: an n8n manual, chat, form or evaluation
trigger, a Make scenario scheduled on demand, a Workato Workbot command, or a
Zapier Chrome extension push or Interfaces form. n8n classifies its trigger
nodes by type, Make reads `scheduling.type` and webhook modules, Workato the
provider of the recipe's trigger line, and Zapier the first step's app. A
Zapier export record needs an `id`, `title`,
`name` or `Zap` field; any other object is reported as an unsupported record
and makes the scan incomplete. A CSV row whose cells are all blank is skipped
without a diagnostic.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
