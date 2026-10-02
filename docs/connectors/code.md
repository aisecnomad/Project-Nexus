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

A list of products is not use of them. A data or prose file (YAML, JSON, TOML, INI,
XML, CSV, text, Markdown) that names four or more different products through
domains or environment-variable names, and holds no import, dependency, code,
file-name, image, IaC, model or credential evidence, is a *catalog*: a proxy
blocklist, an egress allowlist, a vendor policy, a copy of the signature packs.
Its mentions establish a technology only when the same signature also has an
import, a dependency or specific code evidence elsewhere in the project, like an
ambiguous pattern. A project with nothing else yields no finding for them, and
a coding-agent product named only in a catalog yields no `agent-config` finding.
When a project has no evidence except mention-only data files, and one of them
is a catalog, all of them count as one catalog, because nothing in the project
uses what they name. A project finding that remains lists the discounted files
under `metadata.catalog_mentions` (`files`, at most 20, and `min_signatures`).
Source code that lists providers is multi-provider code, and files that declare
what a project builds or runs with (dotenv files, Compose files, Helm
`values.yaml`, CI workflows, dependency manifests, IaC) are never catalogs; a
data file naming one to three products is configuration. The threshold of four is
a judgement from the bundled corpora and fixtures: their multi-provider
configurations name at most four products and are dotenv files, while blocklists
and vendor policies name six to ten and the signature packs seven to
thirty-six per file. A real routing table kept in a plain data file that names
four or more providers, with no other evidence, is therefore not reported.

Ordinary Spring `ChatClient` and LangChain4j `AiServices` construction, and
standalone Java tool declarations, remain framework usage. Recognized explicit
agent factories and supported concrete tool registration can establish agents.
For Spring typed-field registrations, the registered class must have matching
`@Tool` methods in the same project; unrelated or test-only tool declarations
do not establish production capabilities.
For supported import-bound constructors, empty or disabled tool/delegation
options do not establish those workload capabilities; unresolved dynamic
configuration remains potential evidence. Review capability assertions as well
as binary presence when validating a detection change.

Agent filenames select structural discovery checks. Empty/invalid LangGraph,
A2A, M365 and CrewAI manifests yield incomplete coverage instead of strong
agent findings. JSON/YAML descriptions are not executed or treated as source; low-code
matching projects operational fields only. These predicates are not complete
versioned vendor schema validators.
Owner comes from `CODEOWNERS` and configured inventory. Git author/history
enrichment is disabled by default; `use_git: true` explicitly enables it for
reviewed local metadata. The metadata command must support `--no-lazy-fetch`;
unsupported Git versions or failed history reads mark the scan incomplete.
Metadata reads cannot initiate a transport, fetch missing objects or use hooks.

Submodule declarations are inspected without running Git. Missing, empty or
unsafe declared module directories make coverage incomplete. Clone collection
and local `use_git: true` also inventory committed gitlinks using the hardened
metadata path. No submodule is initialized or fetched; see the detailed
[coverage policy](../scanning.md#coverage-policy) for scope and limitations.

Options: `path`/`paths`, `root_ids`, `exclude`, `default_excludes`, `max_file_size`, `max_files`,
`max_notebook_size`, `max_ast_nodes`, `scan_secrets`, `strict_coverage`, `include_tests`, `use_git`, `label`. When using labeled `paths`, supply unique
`root_ids` aligned with those paths for IDs that survive moving checkouts.

`paths`, `exclude` and `oversize_skip_globs` must be lists of non-empty strings.
A bare string, such as the YAML scalar `exclude: "vendor/*"`, is a configuration
error (the message names the option, not the value) rather than being read
one character at a time; on the command line repeat `--exclude`, or give
`--set 'exclude=["vendor/*"]'`.

The walk skips a built-in list of directory names at any depth. `exclude` only
adds to it; `default_excludes: false` (`--no-default-excludes`) turns the list
off. Most names are tool metadata, caches, virtualenvs, dependency trees and IDE
state that never hold a project's own source, and are skipped without comment:
`.git`, `.hg`, `.svn`, `node_modules`, `bower_components`, `.yarn`,
`.pnpm-store`, `Pods`, `.venv`, `venv`, `.virtualenv`, `site-packages`,
`__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`, `.nox`,
`.cache`, `.coverage`, `.dart_tool`, `.gradle`, `.terraform`, `.serverless`,
`.next`, `.nuxt`, `.svelte-kit`, `.turbo`, `.parcel-cache`, `.idea` and `.vs`.
The remaining names are build output or vendored code by convention, but
projects also keep first-party code there (scripts in `bin/`, an agent under
`vendor/` or `build/`): `bin`, `build`, `dist`, `out`, `target`, `obj`,
`coverage`, `vendor`, `third_party`, `thirdparty` and `external`. When the walk
skips one of these that holds at least one file, the scan records the warning
`default-excluded directories not scanned: bin (2), vendor (1); set
default_excludes: false to scan them` (the count is directories with that name,
and a name listed in `exclude` is not repeated there). It is a warning, not
incomplete coverage, because the exclusion is a documented default. With
`default_excludes: false` only the explicit `exclude` entries apply, so
dependency trees such as `node_modules` and virtualenvs are scanned too (add
them to `exclude` unless that is intended); version-control metadata (`.git`,
`.hg`, `.svn`) is never scanned, since its index and objects are binary. The
same option is accepted by `code.github` and `code.gitlab` and forwarded to the
scan of each checkout.
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

The directory walk keeps its own stack, so how deep a tree nests is not limited
by Python's recursion limit (on Python 3.11 the standard walk fails at about a
thousand levels and would discard every finding). A Python file more than 128
directories deep cannot have its imports checked against local packages, and is
reported as `file analysis incomplete (ImportProvenanceError)` for that file
alone.

A file or directory name that is not valid UTF-8 appears in findings and
diagnostics with each undecodable byte written as a `\xNN` escape (for example
`agent-\xff.py`), so every report format can carry it; the file is still read
under its real name. Two names that differ only in such bytes, or a name that
contains the literal text `\xff`, are indistinguishable in a report.

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
test code, an error elsewhere.

An absolute import is read as repository code rather than the SDK of the same
name when the scan root, the project root, its `src` directory or the importing
file's directory holds a module `name.py`, a package directory with an
`__init__.py`, or a directory without one that contains Python source (a
bounded look: 256 entries and 8 levels; a larger or deeper directory, or a link
inside it, is reported as `file analysis incomplete (ImportProvenanceError)`).
An empty directory, or one of data files, does not count: Python ignores it in
favour of the installed package, so it does not hide that SDK's imports.

A Python source the running interpreter cannot parse (syntax newer than it, such
as a PEP 695 `type` statement on Python 3.11, or a notebook's `!pip` and `%magic`
lines) has no import binding either: it keeps its lexical evidence, so an agent
can show as framework usage, and the scan records the warning `import-bound
analysis skipped (source did not parse); lexical evidence retained` without
becoming incomplete.

Malformed YAML front matter in an agent
definition, including a YAML value PyYAML cannot construct (an impossible date,
an integer over 4,300 digits), is reported as `invalid agent definition YAML`;
the definition is still listed by its file name.

A CrewAI `agents.yaml` or `langgraph.json` inside a reported project is folded
into that project's finding and listed under `metadata.manifests`. MCP server
capabilities are derived from the tool names the server registers
(`metadata.mcp_tools`, for example `write_file` implies `data-access`).

An MCP server entry that declares itself disabled (`disabled: true` or
`enabled: false`) is still reported. The flag is client-specific (Cline and Roo
honour it, Claude Code's `.mcp.json` does not) and the repository sets it, so
honouring it would let a repository hide a server. The finding lists the server
with `disabled: true` in `metadata.servers`, keeps its endpoints, environment
names and capabilities as evidence, and carries the tag `declared-disabled` (not
`disabled`, which would lower the risk score); `metadata.disabled` is `true`
when no server is left enabled. `metadata.server_count` counts the servers that
are not declared disabled and `metadata.disabled_server_count` the others. An
entry with no command, URL or package is not a server, whatever its flag.

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
GitLab clones use the same observed `clone_max_bytes` and timeout behavior as
GitHub clones above. GitLab's reported size is a preflight estimate in bytes;
it does not replace a filesystem/container disk quota.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
