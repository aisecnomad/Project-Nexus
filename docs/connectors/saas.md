# SaaS connectors

SaaS connectors discover bots, apps, integrations, and AI-related marketplace
installations across collaboration and productivity platforms.

!!! info "Live and offline"
    SaaS connectors support live API collection and offline JSON/CSV export
    analysis (including CASB inventory exports via `saas.generic`).

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

## `saas.slack`
`users.list` (bots), `admin.apps.approved.list` / `restricted` / `requests`
(scopes, pending requests), `team.integrationLogs` (who installed what).
`team.info` must return an authenticated workspace identity. If `team_id` is
configured, it must match exactly before inventory calls begin. Missing/null
collection arrays and malformed pagination are incomplete coverage. Later
network failures retain already collected observations; provider error text is
not copied into diagnostics. Complete live acceptance generally requires an
appropriately scoped administrative audit token, not an ordinary bot token.

## `saas.microsoft-teams`
Graph app catalog (custom apps with bot definitions and RSC permissions) and
installed apps per team (capped by `max_teams`).

## `saas.github-apps`
Org installations with permissions and repository selection (AI reviewers,
coding agents), Copilot billing/seat settings, fine-grained PATs approved for
the org. An installation is reported when it matches an AI signature or has an
AI-like name; write access alone does not make an app an agent. Set
`include_unrecognized_apps: true` to also report other write-capable apps,
tagged `unrecognized-app` and capped at possible confidence. `workflows` or
`actions` write access implies `code-exec`; contents and pull-request writes
are SaaS write actions.

## `saas.atlassian`
UPM user-installed apps for Jira and Confluence.

## `saas.notion`
Notion bot users. A missing or repeated pagination cursor, or reaching the live
page cap (`max_pages`, at most 1000), makes the scan incomplete.

## `saas.zoom`
The Marketplace list API returns approved public apps and account-created apps
(`type=public` and `type=account_created`), including app scopes when supplied.
See [Zoom's Marketplace List apps API](https://developers.zoom.us/docs/api/marketplace/).
Approval or account creation does not establish that any individual installed
or used the app; obtain a separate tenant activity or installation export to
check that. Denied, invalid, or truncated pages make the scan incomplete.

## `saas.generic`
Any CSV/JSON app inventory (Google Marketplace, HubSpot, CASB discovered-apps
exports…). Map columns with `fields:`; findings are produced for AI matches
and privileged/data scopes (`keep_all: true` to emit everything). Records without an app name are skipped and counted (fully blank rows are
ignored), and an export where no record maps to a name makes the scan incomplete
instead of looking empty.

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
