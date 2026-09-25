# SaaS connectors

SaaS connectors discover bots, apps, integrations, and AI-related marketplace
installations across collaboration and productivity platforms.

!!! info "Live and offline"
    SaaS connectors support live API collection and offline JSON/CSV export
    analysis (including CASB inventory exports via `saas.generic`).

### `saas.slack`
`users.list` (bots), `admin.apps.approved.list` / `restricted` / `requests`
(scopes, pending requests), `team.integrationLogs` (who installed what).
`team.info` must return an authenticated workspace identity. If `team_id` is
configured, it must match exactly before inventory calls begin. Missing/null
collection arrays and malformed pagination are incomplete coverage. Later
network failures retain already collected observations; provider error text is
not copied into diagnostics. Complete live acceptance generally requires an
appropriately scoped administrative audit token, not an ordinary bot token.

### `saas.microsoft-teams`
Graph app catalog (custom apps with bot definitions and RSC permissions) and
installed apps per team (capped by `max_teams`).

### `saas.github-apps`
Org installations with permissions and repository selection (AI reviewers,
coding agents), Copilot billing/seat settings, fine-grained PATs approved for
the org.

### `saas.atlassian` · `saas.notion` · `saas.zoom`
UPM user-installed apps (Jira/Confluence) and Notion bot users. Zoom's
Marketplace list API returns approved public apps and account-created apps
(`type=public` and `type=account_created`), including app scopes when supplied.
See [Zoom's Marketplace List apps API](https://developers.zoom.us/docs/api/marketplace/).
Approval or account creation does not establish that any individual installed
or used the app; for that question, obtain a separate tenant activity or
installation export. Notion rejects a missing/repeated pagination cursor and
caps live pages (`max_pages`, at most 1000); either condition makes the scan
incomplete. Zoom likewise marks denied, invalid, or truncated pages incomplete.

### `saas.generic`
Any CSV/JSON app inventory (Google Marketplace, HubSpot, CASB discovered-apps
exports…). Map columns with `fields:`; findings are produced for AI matches
and privileged/data scopes (`keep_all: true` to emit everything).


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
