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

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

## `code.filesystem`
Scans a directory tree. Project roots are detected from manifests
(`package.json`, `pyproject.toml`, `go.mod`, `pom.xml`, a `setup.py` that builds a
package, …); each root yields one
finding summarizing frameworks, model providers, capabilities, models and
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
dynamic imports, re-exports and uncertain bindings remain usage evidence.
Supported Go LangChain agent constructors require the imported agent-package
receiver, with local shadowing excluded. For Microsoft.Extensions.AI, a
standalone function declaration is tool context; supported automatic invocation
with concrete nonempty tools and a response call can establish an agent.
Tool-mode type and alias names must remain unshadowed to prove automatic invocation.
These bounded checks do not resolve arbitrary types or cross-file bindings.
Other languages, and framework code patterns from custom signature packs in any
language, use lexical signatures and require matching framework import/dependency
corroboration before agent classification; uncorroborated lexical framework code
is capped at 0.6 confidence. These are static candidate classifications, not proof
that code ran or that a deployment is autonomous.

Python and JavaScript/TypeScript execution capabilities are attributed to supported
registered tool bodies, direct local helpers, and recognized model-selected
dispatch. Unused tools, unrelated helpers and turn-loop cleanup remain zero-weight
context (`metadata.contextual_capabilities`); unresolved dynamic registration stays
potential evidence. Literal dead branches are excluded only for supported source
shapes, including synchronous Python comprehensions with literal empty
iterables or false filters. Calls evaluated before those clauses remain evidence.
This bounded static analysis does not prove runtime reachability or follow
tools across arbitrary aliases or files. Rescans can therefore lower a candidate's
capabilities and score without a source change; see [scanning](../scanning.md) and
[production migration notes](../production.md).

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
`values.yaml`, CI pipelines such as GitHub workflows, `.gitlab-ci.yml`,
`azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.circleci/` and
`.buildkite/`, Spring `application*` and `bootstrap*` configuration, dependency
manifests, IaC) are never catalogs. Neither is a configuration document: a
Kubernetes-style resource (`apiVersion` and `kind`, also in a multi-document
stream), an ECS task definition, or a data file that assigns a variable it
names under an `env`, `environment`, `variables` or `secrets` key (as a key, or
as the `name` or `key` of an item). A data file naming one to three products is
configuration. The threshold of four is a judgement from the bundled corpora and
fixtures: their multi-provider configurations name at most four products and are
dotenv files, while blocklists and vendor policies name six to ten and the
signature packs seven to thirty-six per file. A real routing table kept in a
plain data file that names four or more providers by base URL, with no other
evidence, therefore yields no finding; whenever a project's only evidence is in
catalogs, the scan names those files in a note (a warning that does not make the
scan incomplete) so the discount is never silent.

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

This option-aware handling includes Google ADK, Strands, AutoGen, LlamaIndex
and Semantic Kernel constructors. Explicit tool/plugin lists establish tool-use;
an SDK's feature list alone does not. Empty or unknown `sub_agents`, `handoffs`,
team participants and tools do not establish their corresponding capabilities.
ADK parent/sub-agent configuration needs an explicit child, while standalone
Strands swarms, AutoGen teams and LlamaIndex workflows need at least two explicit
participants to establish multi-agent configuration. String-only handoff targets
remain potential evidence because the target may be a human. A tool retriever,
workbench, directory loader or external kernel can provide tools dynamically;
their unknown contents stay potential, and tool retrieval alone is not document
RAG. A Semantic Kernel function-choice override also stays potential because it
can disable invocation. These conservative checks do not resolve runtime options
or object relationships across files. Independent tool/code execution evidence
is retained even when another constructor has empty options.

Legacy AutoGen `code_execution_config={}` explicitly enables default execution;
`False` disables it. Planning vocabulary, a limit such as `max_steps`, or the
option name `sub_agents` alone no longer adds autonomous capability. Supported
model-selection/dispatch loops and explicit autonomous settings remain evidence.
Contracts checked against the primary references:
[ADK LlmAgent](https://github.com/google/adk-python/blob/main/src/google/adk/agents/llm_agent.py),
[ADK BaseAgent](https://github.com/google/adk-python/blob/main/src/google/adk/agents/base_agent.py),
[Strands Agent](https://strandsagents.com/docs/api/python/strands.agent.agent/),
[Strands Swarm](https://strandsagents.com/docs/api/python/strands.multiagent.swarm/),
[AutoGen AssistantAgent](https://microsoft.github.io/autogen/stable/_modules/autogen_agentchat/agents/_assistant_agent.html),
[AutoGen ConversableAgent](https://microsoft.github.io/autogen/0.2/docs/reference/agentchat/conversable_agent/),
[LlamaIndex agents](https://developers.llamaindex.ai/python/framework-api-reference/agent/),
[LlamaIndex AgentWorkflow](https://github.com/run-llama/llama_index/blob/main/llama-index-core/llama_index/core/agent/workflow/multi_agent_workflow.py),
and [Semantic Kernel ChatCompletionAgent](https://learn.microsoft.com/en-us/python/api/semantic-kernel/semantic_kernel.agents.chat_completion.chat_completion_agent.chatcompletionagent).

Agent filenames select structural discovery checks. Empty/invalid LangGraph,
A2A, M365 and CrewAI manifests yield incomplete coverage instead of strong
agent findings. An A2A card that names its agent and declares an endpoint,
skills or capabilities but misses other required fields still gets its own
`protocol.a2a` framework-usage finding, tagged `incomplete-agent-card` with
the errors in `metadata.card_errors`, never an agent finding; the errors also
keep the scan incomplete. JSON/YAML descriptions are not
executed or treated as source; low-code
matching projects operational fields only. These predicates are not complete
versioned vendor schema validators.
Owner comes from `CODEOWNERS` and configured inventory. Git author/history
enrichment is disabled by default; `use_git: true` explicitly enables it for
reviewed local metadata. The metadata command must support `--no-lazy-fetch`;
unsupported Git versions or failed history reads mark the scan incomplete.
Metadata reads cannot initiate a transport, fetch missing objects or use hooks.
Local metadata must be self-contained: config includes, internal links and
alternate/common metadata directories are rejected. Local `config` and
`config.worktree` reads are bounded to 1 MiB; unsupported section syntax,
encodings, continuations or multiline values make coverage incomplete before
Git runs. Use immutable checkouts; preflight does not sandbox Git.

Submodule declarations are inspected without running Git. Missing, empty or
unsafe declared module directories make coverage incomplete. Clone collection
and local `use_git: true` also inventory committed gitlinks using the hardened
metadata path. No submodule is initialized or fetched; see the detailed
[coverage policy](../scanning.md#coverage-policy) for scope and limitations.

Options: `path`/`paths`, `root_ids`, `exclude`, `default_excludes`, `max_file_size`, `max_files`, `max_entries`,
`max_notebook_size`, `max_ast_nodes`, `scan_secrets`, `strict_coverage`, `include_tests`, `use_git`, `label`. When using labeled `paths`, supply unique
`root_ids` aligned with those paths for IDs that survive moving checkouts.

`max_entries` defaults to 1,000,000 filesystem entries inspected during
enumeration. It counts directories, skipped files and entries revisited by
coverage probes, and is independent of the existing `max_files` limit on
files and symbolic links. Reaching either limit makes coverage incomplete
(exit 3). Enumeration checks connector cancellation and deadlines even when
every entry is excluded or the tree holds only directories. `code.github`
and `code.gitlab` forward this option to each checkout scan.

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
by default, as do binary content (a NUL byte) in an analyzable file, non-regular
entries named like configuration files, and directory nesting deeper than the
walker supports; `strict_coverage` promotes their diagnostics to errors. Declared
oversize skip globs remain visible omissions, and directories skipped by the
default excludes (`build`, `vendor`, `external`, …) are listed in one warning per
root that does not affect completeness. See the coverage policy in
[scanning](../scanning.md#coverage-policy). Each root is opened once, and every
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
A file the scanner reads that is a Git LFS pointer (a checkout or offline clone
made without git-lfs) is not the content it stands for: it is reported as
`Git LFS pointer file, not the content it stands for; coverage incomplete` (an
error under `strict_coverage`) and not analyzed. A pointer in place of a file
the scanner never reads, such as an image or a model, is not a gap.
Import-bound analysis is skipped for a Python module none of whose imports can
resolve to a signature: no import, and no attribute of an imported module, forms
an import statement that a signature's import pattern could match. Such a module
cannot contribute import-bound evidence, so its size or nesting depth never makes
the scan incomplete. Deciding this takes time linear in the module and at most
4,096 distinct import statement matches, 512 of them for attributes; a module
that needs more, which ordinary code does not, is treated like one that imports
a signature's library. Any other Python module over `max_ast_nodes` (default
50000) keeps its lexical evidence without import-bound analysis: a warning in
test code, an error elsewhere. A call into a signature's library is analyzed
from its first 8,192 characters in Python, JavaScript and TypeScript alike. A
longer JavaScript or TypeScript call (a Genkit flow body, an agent with long
instructions) keeps its construction evidence, as does the rest of the file's
import-bound evidence, but an option past that point is unread: the scan
records `import-bound call at line N analyzed from its first 8192
characters; options after them were not read, so coverage is incomplete` and
is incomplete (exit 3), a warning in test code as for the other binder limits.

An absolute import is read as repository code rather than the SDK of the same
name when the scan root, the project root, its `src` directory or the importing
file's directory holds a module `name.py`, a package directory with an
`__init__.py`, or a directory without one that contains Python source (a
bounded look: 256 entries and 8 levels; a larger or deeper directory, or a link
inside it, is reported as `file analysis incomplete (ImportProvenanceError)`).
An empty directory, or one of data files, does not count: Python ignores it in
favour of the installed package, so it does not hide that SDK's imports.

A notebook's IPython magic (`%pip`, `%%time`) and shell (`!pip`) lines are read
as inert expressions, as IPython rewrites them, so they do not keep the import
binder from the notebook. Jupyter runs code cells one at a time, so each cell is
lexed on its own, and a cell that still does not parse (a `%%bash` cell, an
unfinished scratch cell) is left out of import binding on its own: the warning
`import-bound analysis skipped for notebook cell N, which does not parse;
lexical evidence retained` names it, and the other cells are bound as usual. A
string left open in one cell no longer masks the cells after it.

A Python source the running interpreter cannot parse (syntax newer than it,
such as a PEP 695 `type` statement on Python 3.11) has no import binding: its
framework patterns are kept as lexical evidence, which counts toward an agent
only when the same library is imported or declared as a dependency, as in a
language without a binder, and the scan records the warning `import-bound
analysis skipped (source did not parse); lexical evidence retained` without
becoming incomplete. The same lexical evidence stands in for a notebook cell
that does not parse, and when a binder budget is exhausted; that scan is
incomplete.

Malformed YAML front matter in an agent
definition, including a YAML value PyYAML cannot construct (an impossible date,
an integer over 4,300 digits), is reported as `invalid agent definition YAML`;
the definition is still listed by its file name.

A CrewAI `agents.yaml` or `langgraph.json` inside a reported project is folded
into that project's finding and listed under `metadata.manifests`. MCP server
capabilities are derived from the tool names the server registers
(`metadata.mcp_tools`, for example `write_file` implies `data-access`).
Python registrations require supported stable MCP imports and receivers;
JavaScript registrations use filtered lexical forms. Comments and example
strings do not establish registrations. Exceeding the per-file or project
name limit makes coverage incomplete, and named tools cannot suppress
separate execution-sink evidence. Empty, explicitly disabled or unverified
provider tool options do not establish configured tool-use; supported
import-bound requests and linked enabled dispatch provide that evidence.

An MCP server entry that declares itself disabled (`disabled: true` or
`enabled: false`) is still reported. The flag is client-specific (Cline and Roo
honor it, Claude Code's `.mcp.json` does not) and the repository sets it, so
honoring it would let a repository hide a server. The finding lists the server
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

## `code.github`
Enumerates an organization, a user or an explicit `repos:` list, fetches
content by shallow clone (default) or the contents API (`mode: api`, bounded
file sample) and runs the filesystem scanner. Adds CI secret/variable *names*
matching LLM providers. Token: a fine-grained PAT or GitHub App token with
read-only Contents and Metadata, plus Secrets, Variables, Codespaces secrets and
Dependabot secrets (each repository is asked for the names in all four; a denied
one adds `repository metadata HTTP 403; coverage unknown` and makes the scan
incomplete; see the [connector reference](../connectors.md#codegithub)). Use a
variable of its own for the token rather than a shared `GITHUB_TOKEN`. Offline
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
A clone populates no submodule (reported by the filesystem scan of the checkout;
see the [coverage policy](../scanning.md#coverage-policy)) and runs no Git LFS
smudge filter: a repository whose files include LFS pointer files is reported as
`Git LFS pointer files in <repo> are not resolved` and makes the scan incomplete
(an error under `strict_coverage`), as does a clone that could not be checked for
them. API mode reports LFS pointer files the same way.
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
connector uses sampled API mode and the scan is incomplete. (The gitlink
inventory of a clone needs Git 2.45; with 2.32 to 2.44 a clone is scanned but
reports that submodule coverage is unknown.)

## `code.gitlab`
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
incomplete. LFS pointer files are reported as for GitHub.
GitLab clones use the same observed `clone_max_bytes` and timeout behavior as
GitHub clones above. GitLab's reported size is a preflight estimate in bytes;
it does not replace a filesystem/container disk quota.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
