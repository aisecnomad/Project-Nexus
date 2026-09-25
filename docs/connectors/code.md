# Code connectors

Code connectors scan source repositories for AI agent frameworks, LLM SDK
usage, MCP configurations, coding-agent configs, and infrastructure-as-code
that provisions agent resources.

!!! info "Live and offline"
    `code.filesystem` scans a local checkout and has no live API mode.
    `code.github` and `code.gitlab` collect live through the provider API
    (clone or API mode); their offline `input` is a directory of clones, not
    an export file. For code connectors `--dump-records` records repository
    listings and scan roots only, so those records are not replayable.

### `code.filesystem`
Scans a directory tree. Project roots are detected from manifests
(`package.json`, `pyproject.toml`, `go.mod`, `pom.xml`, …); each root yields one
finding summarising frameworks, model providers, capabilities, models and
evidence. Extra findings: MCP configs (`.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `claude_desktop_config.json`, Codex `config.toml`,
Continue, Kiro, Amazon Q…), coding-agent configs (`CLAUDE.md`, `.claude/agents`,
`.github/agents/*.agent.md`, `.cursor/rules`, `AGENTS.md`, `GEMINI.md`…),
A2A agent cards, M365 declarative agents, LangGraph/CrewAI manifests, exported
low-code flows, IaC (Terraform, CloudFormation, ARM/Bicep, wrangler) and
container files, `.env`/CI secret references, provider credentials (redacted).

Python and common JavaScript/TypeScript constructors are resolved against imports,
including aliases, namespaces and ordinary CommonJS bindings. Generic loops,
subprocess calls and repeated weak idioms cannot independently establish an agent.
Confidence groups cap repeated observations of the same technology. Unsupported
dynamic imports, re-exports and uncertain bindings remain usage evidence. Other
languages use lexical signatures and require matching framework import/dependency
corroboration before agent classification; uncorroborated lexical framework code
is capped at 0.6 confidence. These are static candidate classifications, not proof
that code ran or that a deployment is autonomous.

Agent filenames select structural discovery checks. Empty/invalid LangGraph,
A2A, M365 and CrewAI manifests yield incomplete coverage instead of confirmed
agents. JSON/YAML descriptions are not executed or treated as source; low-code
matching projects operational fields only. These predicates are not complete
versioned vendor schema validators.
Owner comes from `CODEOWNERS` and configured inventory. Git author/history
enrichment is disabled by default; `use_git: true` explicitly enables it for
reviewed local metadata. The metadata command must support `--no-lazy-fetch`;
unsupported Git versions or failed history reads mark the scan incomplete.
Metadata reads cannot initiate a transport, fetch missing objects or use hooks.

Options: `path`/`paths`, `root_ids`, `exclude`, `max_file_size`, `max_files`,
`max_notebook_size`, `max_ast_nodes`, `scan_secrets`, `strict_coverage`, `include_tests`, `use_git`, `label`. When using labeled `paths`, supply unique
`root_ids` aligned with those paths for IDs that survive moving checkouts.
Unread oversized source files and symlinks leaving the root make a scan incomplete
by default; `strict_coverage` promotes their diagnostics to errors. Declared
oversize skip globs remain visible omissions.

Configuration files are parsed as JSONC where their format allows comments.
A syntax error in a file that is not coding-agent settings only skips its
structured checks, with a warning; `.claude`, `.codex` and `.gemini` settings
and `strict_coverage` keep such an error incomplete. A notebook larger than
`max_file_size` because of saved outputs is analyzed by its code cells up to
`max_notebook_size` (default 20 MiB); its outputs are then not scanned for
credentials. A Python module over `max_ast_nodes` (default 50000) keeps its
lexical evidence without import-bound analysis: a warning in test code, an error
elsewhere.

A CrewAI `agents.yaml` or `langgraph.json` inside a reported project is folded
into that project's finding and listed under `metadata.manifests`. MCP server
capabilities are derived from the tool names the server registers
(`metadata.mcp_tools`, for example `write_file` implies `data-access`).

### `code.github`
Enumerates an organisation, a user or an explicit `repos:` list, fetches
content by shallow clone (default) or the contents API (`mode: api`, bounded
file sample) and runs the filesystem scanner. Adds CI secret/variable *names*
matching LLM providers. Token: fine-grained PAT or GitHub App token with
`contents:read`, `metadata:read`; `secrets:read` for secret names. Offline
input: a directory of clones. Code findings retain the scanned Git tree/commit
identity in `metadata.source_snapshot`; API blob bytes are checked against their
enumerated Git object IDs.
An offline input with no clone directories is incomplete.
An explicit `repos:` response whose repository identity does not match the
requested name is incomplete, and that response is not scanned.
Live API records cannot choose local scan paths. `use_git` has the same explicit
opt-in policy as `code.filesystem`; cloning retains its separate HTTPS policy.

### `code.gitlab`
Group (with subgroups) or `projects:` list on gitlab.com or self-managed;
clone or API mode; also CI/CD variable names (masked flag), group service
accounts, group/project access tokens, project bots and GitLab Duo enablement.
Token: PAT with `read_api` + `read_repository`.
Live API records cannot choose internal offline paths or dispatch fields. Code
findings retain the scanned Git tree/commit identity in
`metadata.source_snapshot`, and API mode pins tree pagination to an immutable
commit before downloading files.
Missing, malformed or mismatched details for an explicitly named project, and an offline
input with no clone directories, make the scan incomplete.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
