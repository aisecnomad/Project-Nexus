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
(`package.json`, `pyproject.toml`, `go.mod`, `pom.xml`, a `setup.py` that builds a
package, …); each root yields one
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
oversize skip globs remain visible omissions. Each root is opened once, and every
file (including `CODEOWNERS`) is read relative to it without following a link in
any path component. A directory replaced by a link while the scan runs therefore
fails the reads below it, which makes the scan incomplete, instead of redirecting
them outside the root. Like reading a file by its path, this needs only search
permission on the directories above a file, so a checkout below a traverse-only
directory, such as a mode `0711` home directory, can be scanned. A root that
cannot be opened this way is reported, by its `label` when one is set, as `could
not open the scan root safely (<reason>)`, with a reason such as `permission
denied`, `not found` or `a path component is a link or not a directory`; nothing
below it is scanned and the scan is incomplete. Findings describe
one consistent state of the tree only when the checkout does not change during
the scan.

Configuration files are parsed as JSONC where their format allows comments.
A syntax error in a file that is not coding-agent settings only skips its
structured checks, with a warning; `.claude`, `.codex` and `.gemini` settings
and `strict_coverage` keep such an error incomplete. A notebook larger than
`max_file_size` because of saved outputs is analyzed by its code cells up to
`max_notebook_size` (default 20 MiB); its outputs are then not scanned for
credentials, which leaves coverage incomplete unless `scan_secrets` is off.
Import-bound analysis is skipped for a Python module none of whose imports can
resolve to a signature: no import, and no attribute of an imported module, forms
an import statement that a signature's import pattern could match. Such a module
cannot contribute import-bound evidence, so its size or nesting depth never makes
the scan incomplete. Deciding this takes time linear in the module and at most
4,096 distinct import statement matches, 512 of them for attributes; a module
that needs more, which ordinary code does not, is treated like one that imports
a signature's library. Any other Python module over `max_ast_nodes` (default
50000) keeps its lexical evidence without import-bound analysis: a warning in
test code, an error elsewhere. Malformed YAML front matter in an agent
definition, including a YAML value PyYAML cannot construct (an impossible date,
an integer over 4,300 digits), is reported as `invalid agent definition YAML`;
the definition is still listed by its file name.

A CrewAI `agents.yaml` or `langgraph.json` inside a reported project is folded
into that project's finding and listed under `metadata.manifests`. MCP server
capabilities are derived from the tool names the server registers
(`metadata.mcp_tools`, for example `write_file` implies `data-access`).

Gemini CLI's `httpUrl` (Streamable HTTP) is read as an MCP endpoint, like
`url`, `serverUrl` and `endpoint`; an entry with more than one of them is
ambiguous. A header or env value that is only a shell-style variable reference
(`Bearer $TOKEN`) is not an inline credential, nor is a credential-file path
argument (`GOOGLE_APPLICATION_CREDENTIALS=/app/key.json`) or an argument that
repeats such a reference; both stay redacted. A GitHub Actions workflow is not
itself an MCP document: servers passed as a JSON object in a step input (for
example `run-gemini-cli` `settings` or `claude-code-action` `mcp_config`) are
reported from that workflow, and an embedded object that cannot be parsed
makes the scan incomplete.

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
An org or user listing entry whose `full_name` is not a plain `owner/name`
(letters, digits, `.`, `_` and `-`, never a `.` or `..` segment) is an error
that makes the scan incomplete; that repository is never requested or cloned.
The listing is read to the end, in `full_name` order, before the first repository
is cloned or scanned, so a push during the scan cannot move an unlisted
repository out of it. A listing that fails part-way, or exceeds `max_repos`,
still has the repositories already listed scanned and makes the scan incomplete.
A clone populates no submodule and runs no Git LFS smudge filter: a repository
whose tree holds a submodule (a gitlink entry), or whose files include LFS
pointer files, is reported as `submodules in <repo> are not cloned` or
`Git LFS pointer files in <repo> are not resolved` and makes the scan
incomplete, as does a clone that could not be inspected for either. API mode
reports submodules and LFS pointer files the same way.
Live API records cannot choose local scan paths. `use_git` has the same explicit
opt-in policy as `code.filesystem`; cloning retains its separate HTTPS policy.
`clone_max_bytes` (default 256 MiB) first checks the provider's repository
size estimate. During an eligible clone, it also measures the clone directory
(including `.git`) and stops Git and its transport processes if the observed
logical or allocated size exceeds the cap. It measures again after Git exits,
before scanning. A size limit, unreadable clone directory, or more than 100,000
entries triggers incomplete sampled API fallback; partial clone files are
removed. Directory symlinks are not followed during measurement. Checks occur
between Git writes, so brief overshoot is possible, and this is not a network
transfer limit. Use a dedicated filesystem/container disk quota to enforce a
strict disk ceiling; `clone_timeout_seconds` (default 120) bounds clone time.
Cloning requires Git 2.32 or newer (older versions ignore the environment
settings that confine a clone); with an older or unidentifiable Git the
connector uses sampled API mode and the scan is incomplete.

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
A group listing entry whose project `id` is not a positive integer is an error
that makes the scan incomplete; that project is skipped before any request is
made for it, and the other projects in the listing are still scanned.
The group listing is ordered by project `id`, read to the end before the first
project is cloned, and compared with the `X-Total` / `X-Total-Pages` totals GitLab
reports (it omits them for very large groups); a mismatch makes the scan
incomplete. Submodules and LFS pointer files are reported as for GitHub.
GitLab clones use the same observed `clone_max_bytes` and timeout behavior as
GitHub clones above. GitLab's reported size is a preflight estimate in bytes;
it does not replace a filesystem/container disk quota.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
