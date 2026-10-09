# Connectors

## Modes and shared collection rules

Most connectors have a **live** mode (API credentials) and an **offline** mode
(`input:` pointing at an export). `gateway.logs` reads supplied logs and
`identity.jwt` reads supplied tokens. Live runs can persist sanitized records with
`--dump-records DIR` / `options.dump_records` for offline re-analysis. Exports are
written atomically with mode 0600 in a 0700 directory and JWT inputs are never
exported. Every connector instance has a collision-resistant export filename,
including repeated connector names or labels that normalize to the same text. Redaction
removes sensitive values, so an export is not a lossless copy of the API response.
Exports must satisfy strict JSON and the same encoded byte limits as replay.
A rejected replacement marks the scan incomplete, preserves an existing file,
and leaves that instance unexported in the current manifest. Check the manifest
before replaying a path from an earlier run. A complete zero-record export is an
explicit empty record envelope. See [migration guidance](production.md#october-9-scan-evidence-corrections-unreleased).
Live HTTP endpoints require HTTPS; redirects and pagination cannot send credentials
to another origin. Denied access, collection failures, pagination limits and
oversized or slow responses (see
[resource limits](production.md#resource-limits-and-incomplete-scans)) make
the scan incomplete rather than producing a clean result.
TLS verification cannot be disabled and `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` are
ignored, so a private endpoint admitted with `--allow-private-origin` behind
internal PKI fails verification (and the scan is incomplete) unless the connector
offers an explicit CA option. Only `identity.jwt` does today (`ca_bundle`, JWKS
endpoint); other connectors trust the default CA store.

### Offline input limits

Offline file and directory inputs use shared safety limits: 10,000 files,
32 MiB per file and 256 MiB total per connector by default. JSONL, CSV and gateway
text logs stream line by line, with a 4 MiB line cap; gzip gateway logs are bounded
by expanded size. Override `max_input_files`, `max_input_file_bytes` or
`max_input_bytes` in the connector config when a trusted export needs larger
limits. The existing hard ceilings remain 64 MiB per file and 512 MiB total.
Any skipped symlink or input-limit hit marks the connector incomplete, and so
does any file in an offline input directory without one of the connector's
export suffixes (a `README.md`, `.DS_Store` or rotated log): remove it or point
`input` at the export file.

The offline inventories (`endpoint.host`, `endpoint.mcp`, `endpoint.ollama`,
`endpoint.models`, `endpoint.ebpf`, `gateway.otel`, `cloud.kubernetes` and
`cloud.openshift`) are **offline-only**. See the
[Kubernetes and OpenShift guide](connectors/kubernetes.md) for workload exports
and the [endpoint guide](connectors/endpoint.md) for MCP, OTLP, Ollama,
model-artifact metadata, and eBPF exports. These connectors do not perform live
probes or local host filesystem discovery, and their findings carry no device
name, so lifecycle links do not apply to them.
Model metadata is not parsed from GGUF/safetensors files, and MCP fingerprints
have no rug-pull baseline. When no `input` is set, `endpoint.inventory` reads a
fixed list of local user-scope locations and `runtime.processes` reads `/proc`
on Linux; the engine links the two for the same tool on the same device (see
the [endpoint](connectors/endpoint.md) and [runtime](connectors/runtime.md)
guides).
These three keys are declared once on `BaseConnector.shared_config_keys` and
apply to every connector that reads an export file, so `shadowscan connectors`
lists them after each connector's own keys. `code.filesystem`, `code.github` and
`code.gitlab` scan checkouts instead of exports: they are bounded by `max_files`, `max_entries`,
`max_repos` and `max_projects` and do not advertise the export limits. They
ignore those three keys, but a value supplied for one must still be a positive
integer or the entry fails validation.

### Live pagination limits

Connectors that page through a live API accept `max_pages`, a positive integer
(default 1000; larger values are capped at 1000). Zero, a negative or fractional
number, a boolean or non-numeric text is a configuration error, never a silent
one-page scan; reaching the page bound marks coverage incomplete. The other
integer limits (`max_lambda`, `max_ecs_api_calls`, `max_projects`,
`min_events`, `max_teams`, `max_records`, `max_users`,
`max_app_role_lookups`) follow the same rule, and the look-back windows
`cloudtrail_days` and `audit_days` are non-negative integers, where 0 switches
the lookup off: `cloudtrail_days: 0.5` is an error, not a disabled lookup.

See [scan state and runtime correlation](scanning.md) for incremental scans,
gateway workload bindings and completion semantics.

### Configuration reference

The [configuration reference](connectors/reference.md) lists the keys every
built-in connector accepts; it is generated from the connector classes and the
configuration parser, and the `shadowscan connectors` listing shows the same
descriptions. A configuration key that a built-in connector does not read is rejected when
the YAML file or `--set` option is parsed (`connector 'identity.okta' does not
accept 'fetch_tokenz'`), so a typo cannot silently disable an option. Keys
starting with an underscore are reserved for the engine. Third-party plugins
are not imported while parsing, so their keys are not checked at that point.

## Third-party plugin execution

Plugins still require an explicit allowlist in `options.plugins` or
`--allow-plugin NAME`. The default `options.plugin_execution: thread` retains
existing behavior. For reviewed plugins that can block inside an SDK or native
extension, select a dedicated spawned process per connector:

```yaml
options:
  plugins: [platform.example]
  plugin_execution: process
  connector_timeout_seconds: 120
connectors:
  - name: platform.example
```

The equivalent CLI override is `--plugin-execution process`. Built-in connectors
continue to use the existing thread backend. A plugin is imported only inside
its child process, and its original completion deadline includes import,
collection, result serialization and transfer. The worker exits with
`os._exit` as soon as its result is sent: plugin `atexit` handlers do not run,
and lingering non-daemon threads cannot delay or discard the result. The parent accepts only bounded
JSON results (16 MiB maximum), validates their model and statistics, and discards
results on timeout, crash, serialization failure or malformed output. As in the
JSON report, values JSON cannot represent (such as `datetime`, sets and bytes)
are converted with `str()` and then sanitized by the parent; NaN and infinity
still fail closed. These
failures mark the scan incomplete (exit 3); they never fall back to threads.
Each terminated worker frees capacity for queued connectors. Termination uses
SIGTERM and, if needed, SIGKILL with at most 0.5 seconds of waiting at each step;
the parent retains a separate deadline guard with two seconds for cleanup.
A worker does not depend on that cleanup: its watchdog thread exits it two
seconds after the deadline, or as soon as the scanner process exits for any
reason, including the job-deadline watchdog's immediate exit, SIGTERM or SIGKILL.
A `KeyboardInterrupt` during collection kills running workers before it
propagates. The watchdog is a Python thread, so native code that holds the
interpreter lock indefinitely still needs external supervision.

This is **lifecycle isolation, not a security sandbox**. A child retains the
scanner's operating-system privileges and environment, including credentials.
Sibling connector configurations are not passed to it. Record exports go only
to the private export directory the scanner prepared (expanded, symlink-free,
owned, mode 0700); the worker never derives that path again. Descendant subprocesses
and external side effects are not rolled back by worker termination; plugins
that launch other programs need external process-group/container supervision.
A cache or record export published before termination may remain on disk; the
failed connector's manifest entry is explicitly incomplete and not exported.
Do not consume such artifacts as accepted results.

The backend uses `spawn` on supported POSIX platforms (Linux and macOS); embedding
applications must call the scanner behind Python's usual
`if __name__ == "__main__":` guard. Plugin configuration and supplied signature
objects must be serializable by Python's spawn machinery. Workers are daemonic,
so a plugin cannot start its own `multiprocessing.Process` children. Choose the
thread backend or an external supervised scanner process for such plugins.
Neither backend enforces CPU/memory quotas or prevents deliberate malicious
filesystem or network activity.

## Validation maturity and evidence status

The unreleased attribution corrections distinguish individual network
connections, hosted-agent execution from management traffic, and a bounded
subset of Python re-exports. See the [network](connectors/network.md),
[gateway](connectors/gateway.md) and [code](connectors/code.md) guides, plus the
[migration notes](production.md#unreleased-attribution-migration). Regression
coverage for these cases does not change the field-evaluation or live-acceptance
status below.

For the October 1 code-collection and capability corrections, review the
[migration notes](production.md#october-1-discovery-review-migration) and
[source coverage policy](scanning.md#coverage-policy). Added regression tests
do not raise a connector's live-acceptance or field-evaluation status.

Connector availability is not production acceptance. This summary describes
published evidence, not private tenant work or guarantees for a deployment.
The release status was refreshed on 2026-10-09 against the published 0.1.2
release; the field and tenant evidence remains subject to the limits below.
Unreleased changes require a new final-revision review and acceptance evidence.

| Scope | Evidence published in this repository | Status supported by that evidence |
|---|---|---|
| `code.filesystem` | Regression corpora plus a frozen 42-file public-source corpus labeled by two separate AI reviewers. The final result followed feedback and is not a fresh held-out field estimate. | Regression-tested; field precision and recall are unestablished. |
| `cloud.aws`, `saas.slack` | Offline replay, stubbed API/SDK tests, and a read-only canary runner for exact tenant scopes. | Canary-capable; no live tenant acceptance is recorded. |
| Other built-in connectors | Per-connector unit, fixture, and mocked-provider coverage at varying depth; no connector-specific live acceptance receipts are published. | Regression-tested; live acceptance is unestablished. |
| Cross-connector field accuracy | No fresh, independently sampled and human-double-labeled representative holdout is published. The bundled AI-labeled corpus does not satisfy this requirement. | Not field-evaluated. |
| Published 0.1.2 | [Release and wheel evidence](https://github.com/aisecnomad/Project-Nexus/releases/tag/v0.1.2), plus a [non-author approval on the release source tree](https://github.com/aisecnomad/Project-Nexus/pull/160#pullrequestreview-5459628229). | Published alpha; this does not approve a later candidate or establish field accuracy. |

Use these labels literally:

- **Regression-tested** means fixed fixtures and stubs passed in CI. It establishes behavior for those cases, not tenant coverage or field accuracy.
- **Canary-capable** means a live-test runner exists. Its presence and an offline `REPLAY_PASS` do not establish live acceptance.
- **Live-accepted** requires fresh, exact-scope evidence for both a complete collection and a separately credentialed permission-denied case. No live acceptance receipt is published in this snapshot.
- **Field-evaluated** requires a new human-labeled holdout sampled and frozen before scanner results are examined, with acceptance policy set in advance. The bundled corpus is a regression resource, not field evidence.

Before using a connector for a production decision, check the [assurance results](assurance-results.md), [field-evaluation procedure](evaluation.md#build-a-genuinely-held-out-field-set), [canary evidence rules](canaries.md#what-counts-as-evidence), and [rollout acceptance gate](production.md#rollout-acceptance). A passing replay or test suite must never be reported as a live tenant pass.

## Connector entry keys

Every entry under `connectors:` in a scan configuration accepts these keys in
addition to the connector's own options:

- `name` (required): the connector, for example `identity.okta`. A bare string
  entry is shorthand for `{name: ...}`.
- `enabled`: `true` (default) or `false` to keep the entry but skip it on this
  run. Environment-backed strings such as `"false"`, `"no"`, `"off"` or `"0"` are
  accepted; any other value fails validation. A disabled entry is not a valid
  `--only` selector.
- `label`: a name for this entry. Give each repeated connector a distinct
  label; nothing else tells the entries apart. It is the entry's id in
  `--only`, progress and `dump_records` file names, and it is passed to the
  connector as the `label` key:
  `code.filesystem` prefixes resource ids with it and `gateway.logs` records it
  as the gateway name.
- `config`: an optional nested mapping merged into the top-level keys, for
  configurations that keep credentials apart from entry metadata. A nested
  key replaces a top-level key of the same name.
- `input`: the offline export path; each connector's offline format is listed
  below and by `shadowscan connectors`.

## Connector entry guide

Use the same six checks for each entry:

- **Modes:** the shared modes above and the surface guide's `Live and offline`
  or `Log-based` note.
- **Collects:** the APIs, resources or export formats described in the entry.
- **Permissions / least privilege:** the [permission table](#least-privilege).
- **Options:** names, types and descriptions are in the
  [generated configuration reference](connectors/reference.md); entries call
  out operational details.
- **Fail-closed behavior:** shared limits above and connector-specific
  incomplete conditions in the entry.
- **Does not establish:** consult
  [validation maturity and evidence status](#validation-maturity-and-evidence-status).

## Code

### `code.filesystem`
Scans a directory tree. Project roots are detected from manifests
(`package.json`, `pyproject.toml`, `go.mod`, `pom.xml`, a `setup.py` that builds a
package, …); by default each root yields one
finding summarizing frameworks, model providers, capabilities, models and
evidence. Extra findings: MCP configs (`.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `claude_desktop_config.json`, Codex `config.toml`,
Continue, Kiro, Amazon Q…), coding-agent configs (`CLAUDE.md`, `.claude/agents`,
`.github/agents/*.agent.md`, `.cursor/rules`, `AGENTS.md`, `GEMINI.md`…),
A2A agent cards, M365 declarative agents, LangGraph/CrewAI manifests, exported
low-code flows, IaC (Terraform, CloudFormation, ARM/Bicep, wrangler) and
container files, `.env`/CI secret references, provider credentials (redacted).

Supported Go SDK import aliases are resolved before source evidence is
excerpted; reports remain confidential. Ordinary Rust multiline strings and
supported JSX in `.js`, `.mjs` and `.cjs` can be analyzed without false lexical
incompleteness. Ambiguous or unterminated source still marks the scan incomplete.

Opt-in `agent_granularity: source` gives supported uniquely named Python
constructions separate inventory resources and constructor-specific evidence.
Other source remains project evidence, with unsupported identity limits visible.
Literal control and Unicode separators preserve Python constructor and local
tool coordinates, including execution capabilities. This is static source
inventory, not runtime instance discovery. The default
`project` mode preserves existing identities; see the
[source guide](connectors/code.md#separate-source-identities) and
[migration notes](production.md#unreleased-review-migration). GitHub and GitLab
forward the same option to their checkout scans.

`package.json` npm aliases (`"runtime": "npm:@langchain/langgraph@^1"`) are
attributed to the target package, not the local alias name. Malformed alias
targets mark coverage incomplete while valid neighboring dependencies remain
available. Dependency presence establishes usage evidence only; aliased import
names are not resolved across manifests into source construction evidence.

Python and common JavaScript/TypeScript constructors are resolved against imports,
including aliases, namespaces and ordinary CommonJS bindings. Generic loops,
subprocess calls and repeated weak idioms cannot independently establish an agent.
Confidence groups cap repeated observations of the same technology. Unsupported
dynamic imports, re-exports and uncertain bindings remain usage evidence. Narrow
Go and C# proofs additionally require imported receivers and supported tool flows;
C# automatic tool modes require an unshadowed SDK type or alias. Other
languages, and framework code patterns from custom signature packs in any
language, use lexical signatures and require matching framework import/dependency
corroboration before agent classification; uncorroborated lexical framework code
is capped at 0.6 confidence. These are static candidate classifications, not proof
that code ran or that a deployment is autonomous.

Supported Python and JavaScript/TypeScript tool registrations and model-selected
dispatch establish execution capabilities. Unused or unrelated execution code
remains zero-weight `metadata.contextual_capabilities`; unresolved registration is
potential evidence. Only supported literal dead branches are excluded. This
bounded attribution does not establish runtime reachability. Rescans can reduce
candidate scores without source changes; see the [code guide](connectors/code.md)
and [migration notes](production.md).

Supported constructor options, including ADK, Strands, AutoGen, LlamaIndex and
Semantic Kernel, separate configured capabilities from framework availability.
Empty/unknown tool and delegation collections stay potential; planning vocabulary
and limit names alone do not imply autonomy. See the [code connector guide](connectors/code.md)
for supported options, primary SDK contracts and dynamic-configuration limits.

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

A CrewAI `agents.yaml` or `langgraph.json` inside a reported project is folded
into that project's finding (`metadata.manifests`). MCP server capabilities come
from the tool names the server registers outside tests (`metadata.mcp_tools`);
comments and string examples do not establish registrations, and enum-based
names count only the referenced members. Exceeding the per-file or project name
limit makes coverage incomplete. Static registration evidence does not prove
the server executed those tools. A server without recognized tools keeps the
capabilities its code implies.

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

Options: `path`/`paths`, `root_ids`, `exclude`, `default_excludes`, `max_file_size`, `max_files`, `max_entries`,
`max_notebook_size`, `max_ast_nodes`, `scan_timeout`, `scan_secrets`,
`strict_coverage`, `include_tests`, `use_git`, `label`. When using labeled `paths`,
supply unique `root_ids` aligned with those paths for IDs that survive moving
checkouts. `account`, `owner` and `provider` set the corresponding finding
fields. A configured `owner` is recorded on every finding and takes precedence
over CODEOWNERS and inventory attribution; leave it unset to attribute by
CODEOWNERS, then the git author when `use_git` is on, then the inventory.
`include` limits local filesystem collection to named relative paths below each root;
such a scan always runs in full, without the incremental cache.
Endpoint profile discovery uses it and reports unsafe or unreadable known locations as
incomplete while still scanning the others.
`metadata` is a mapping merged into every finding's metadata. The walk skips a
built-in list of directory names (`bin`, `build`, `dist`, `vendor`,
`node_modules`, virtualenvs, caches, ...); a skipped non-empty `bin`, `build`,
`dist`, `out`, `target`, `obj`, `coverage`, `vendor`, `third_party`,
`thirdparty` or `external` directory is reported as a warning, and
`default_excludes: false` (`--no-default-excludes`) scans them. The full list
and the quiet/disclosed split are in [connectors/code.md](connectors/code.md).
`oversize_skip_globs` replaces the default list of case-insensitive file-name
globs. The defaults cover lockfiles, minified bundles, source maps, images,
fonts, archives and compiled artifacts, and a glob with `/` matches the relative
path. A file over `max_file_size` that matches one is skipped with a warning
and the scan stays complete, even under `strict_coverage`. Any other oversize
analyzable file makes coverage incomplete.

Each root is opened once, and every file, including `CODEOWNERS`, is read
relative to it without following a link in any path component. A root that
cannot be opened this way is reported as
`could not open the scan root safely (<reason>)` and makes the scan
incomplete. A Python module none of whose imports can resolve to a signature
skips import-bound analysis at any size; any other module over
`max_ast_nodes` keeps its lexical evidence (a warning in test code, an error
elsewhere). See the [code connector guide](connectors/code.md) for details.

### `code.github`
Enumerates an organization, a user or an explicit `repos:` list, fetches
content by shallow clone (default) or the contents API (`mode: api`, bounded
file sample) and runs the filesystem scanner. Adds CI secret/variable *names*
matching LLM providers. Token: a fine-grained PAT or GitHub App token with
read-only **Contents** and **Metadata** (the clone or API snapshot) and the four
repository permissions listed below (CI credential names); a classic PAT needs the
`repo` scope. Offline
input: a directory of clones. Code findings retain the scanned Git tree/commit
identity in `metadata.source_snapshot`; API blob bytes are checked against their
enumerated Git object IDs.
An offline clone directory containing no repositories makes the scan incomplete;
verify the export or select an intended nonempty directory.
An explicit `repos:` response with a missing or mismatched repository identity
also makes coverage incomplete; the connector will not scan a different repo
as a substitute for the requested one. An org or user listing entry whose
`full_name` is not a plain `owner/name` is an error that makes the scan
incomplete; that repository is never requested or cloned.
The listing is read to the end, in `full_name` order, before the first
repository is cloned or scanned. A push during the scan therefore cannot move a
repository that was not listed yet out of the listing, which an
activity-ordered, lazily paged listing allowed. If the listing fails part-way
(or exceeds `max_repos`) the repositories already listed are still scanned and
the scan is incomplete.
Live API records cannot choose local scan paths. `use_git` has the same explicit
opt-in policy as `code.filesystem`; cloning retains its separate HTTPS policy.
`clone_max_bytes` (default 256 MiB) checks GitHub's reported repository size
before cloning and samples the local checkout, including `.git`, while Git runs.
The clone is stopped when observed size exceeds the cap or cannot be measured,
and checked again after Git exits. `clone_timeout_seconds` (default 120) bounds
each clone.
A clone populates no submodule (see the
[coverage policy](scanning.md#coverage-policy)) and runs no Git LFS smudge
filter: a repository with LFS pointer files (small text files that open with
`version https://git-lfs.github.com/spec/v1`) holds the pointers, not the large
files, so such a repository makes the scan incomplete (an error under
`strict_coverage`), as does a clone that could not be checked for them. API mode
reports LFS pointer files the same way.
An oversized repository or missing/malformed size estimate falls back to sampled
API mode without launching Git and marks coverage incomplete. A failed clone or
Git being unavailable for explicit `mode: clone` also marks the scan incomplete.
A clone also makes Git verify every object it receives (`transfer.fsckObjects`,
`fetch.fsckObjects`), so a repository with malformed objects fails to clone and
is scanned through the incomplete API fallback. A clone URL or API link that
contains whitespace or control characters is refused outright rather than
cleaned up, and an API tree path with a `.git` component (any case) aborts that
repository's API snapshot.
Cloning requires Git 2.32 or newer: the protections that keep a clone on its
origin and out of local configuration are passed through `GIT_CONFIG_COUNT` and
`GIT_CONFIG_GLOBAL`, which older versions ignore without an error. With an older
or unidentifiable Git (`git --version` is read once per process) the connector
uses sampled API mode and the scan is incomplete. The submodule inventory of a
clone uses the hardened metadata path, which needs Git 2.45; with Git 2.32 to
2.44 a clone is scanned but reports
`could not inventory gitlinks safely; submodule coverage unknown`.
The provider's size is an estimate, and polling can overshoot between samples.
Neither check limits network transfer or guarantees a hard disk ceiling. Run
remote scans with a host/container wall-clock limit and a writable disk quota.

Options: `org` (env `GITHUB_ORG`), `user` or `repos`; `token` (env
`GITHUB_TOKEN`, falling back to `github_token` / env `GH_TOKEN`); `api_url`,
`mode`, `include_archived`, `include_forks`, `max_repos`, `clone_depth`,
`topics`. The filesystem scanner options `exclude`, `max_file_size`,
`max_files`, `max_entries`, `scan_timeout`, `scan_secrets` and `use_git` are forwarded to
every repository scan. `repos` and `topics` must be lists of non-empty strings,
and `max_repos` and `clone_depth` whole numbers; anything else (including a bare
string such as `--set topics=llm`, which would be read as single characters)
stops the connector with an error that names the option, and the scan exits 3.
With `--set`, write `a,b` or a JSON list such as `'["a"]'`.

**Token permissions for CI credential names.** For every repository it reaches,
the connector also lists the *names* (never the values) of four credential
collections. Each needs its own read-only repository permission:

| Endpoint (under `/repos/{owner}/{repo}/`) | Fine-grained / App permission (read) |
|---|---|
| `actions/secrets` | Secrets |
| `actions/variables` | Variables |
| `codespaces/secrets` | Codespaces secrets |
| `dependabot/secrets` | Dependabot secrets |

A token with only Contents and Metadata is denied all four, and each denial adds
the warning `code.github: repository metadata HTTP 403; coverage unknown` (the
status of the response: 403 for a missing permission, 404 where the feature is
not available on the repository). Four identical warnings per repository, an
incomplete scan and exit 3 are therefore the expected outcome of a token that
lacks those permissions; the code findings themselves are unaffected. The
warning does not say which endpoint was denied. There is no option to skip these
endpoints: grant the four permissions, or accept an incomplete scan.

**Use a dedicated token variable.** `token` defaults to the environment variable
`GITHUB_TOKEN` (then `GH_TOKEN`), and so does `saas.github-apps`, which needs an
organization-admin token. `code.github` clones and parses untrusted repository
content with its token in the process, so give each connector its own variable
(for example `token: ${GITHUB_CODE_TOKEN}` here and `token: ${GITHUB_APPS_TOKEN}`
for `saas.github-apps`) and never export the admin token as `GITHUB_TOKEN` where
code scans run. The rule that code scans and live credentialed connectors need
separate scans (`allow_credential_mixing`) keeps the two out of one scan; it does
not narrow what a shared token can do.

### `code.gitlab`
Group (with subgroups) or `projects:` list on gitlab.com or self-managed;
clone or API mode; also CI/CD variable names (masked flag), group service
accounts, group/project access tokens, project bots and GitLab Duo enablement.
Token: PAT with `read_api` + `read_repository`.
Live API records cannot choose internal offline paths or dispatch fields. Code
findings retain the scanned Git tree/commit identity in
`metadata.source_snapshot`, and API mode pins tree pagination to an immutable
commit before downloading files.
`clone_max_bytes` and `clone_timeout_seconds` have the same defaults, sampled
checkout measurement and incomplete-scan semantics as `code.github`. GitLab
project details are queried for size statistics when the listing omits them.
Without a usable estimate, the connector falls back to sampled API mode
without launching Git.
A missing, malformed or mismatched response for an explicitly named project
marks coverage incomplete; an empty offline clone directory is also incomplete. Check the
configured project names and export before treating an empty result as clean.
A group listing entry whose project `id` is not a positive integer is an
error that makes the scan incomplete; that project is skipped before any
request is made for it, and the other projects are still scanned.
As for `code.github`, the group listing (ordered by project `id`) is read to the
end before the first project is cloned. It is also compared with the totals
GitLab reports (`X-Total`, `X-Total-Pages`; GitLab omits them for very large
groups): entries that do not add up make coverage incomplete.
Polling cannot provide a hard disk or network-transfer limit; enforce a writable
disk quota on the worker.

Options: `group` (env `GITLAB_GROUP`) or `projects`; `token` (env
`GITLAB_TOKEN`); `api_url` (env `GITLAB_API_URL`), `mode`, `include_archived`,
`max_projects`. The same filesystem scanner options as `code.github` are
forwarded to every project scan. `projects` must be a list of non-empty strings
(numeric project ids may be written unquoted) and `max_projects` a whole number;
other values stop the connector with an error that names the option (exit 3).

## Identity

### `identity.okta`
`/api/v1/apps` (+ `/grants`, `/tokens` for OIDC apps). Reports OAuth apps that
match AI SaaS signatures or hold privileged scopes, and service apps
(`application_type: service` / `client_credentials` / token-exchange).
Token: SSWS API token (`token`, env `OKTA_API_TOKEN`) or OAuth bearer
(`bearer`, env `OKTA_ACCESS_TOKEN`) with `okta.apps.read`; `bearer` wins when
both are set. Options: `include_inactive`, `fetch_tokens`. A 429 is retried
after the window named by Okta's `X-Rate-Limit-Reset` header (bounded to 120 s
per wait); exhausted retries mark the scan incomplete.
Live collection also needs `org_url` (`https://<org>.okta.com`, env
`OKTA_ORG_URL`).

### `identity.entra`
Microsoft Graph: service principals, delegated `oauth2PermissionGrants`,
app-only `appRoleAssignments` (role ids resolved to the names their resource
defines, such as `Mail.ReadWrite`), tenant app registrations, managed identities. First-party
Microsoft SPs are skipped unless they match AI signatures (Copilot).
Permissions (application): `Application.Read.All`, `DelegatedPermissionGrant.Read.All`,
`Directory.Read.All`. Or pass `access_token`.
Offline grants or role assignments with unresolved service-principal identity make
coverage incomplete. Their permission evidence remains available for investigation
and cannot establish an approved registry binding. A service principal exported
with conflicting records is reported the same way, keeping AI evidence from up to
16 of its snapshots (64 evidence items) without choosing one snapshot's identity.

Client credentials: `tenant_id`, `client_id` and `client_secret` (env
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`).
`include_first_party: true` also reports Microsoft first-party service
principals that match no AI signature; Copilot ones are always kept.
`max_app_role_lookups` caps the per-service-principal `appRoleAssignments`
calls (default 2000). Reaching the cap leaves app-only permissions partial and
the scan incomplete.

### `identity.google-workspace`
Admin SDK `users/{id}/tokens` for every user, aggregated per OAuth client:
"Fireflies has Gmail + Calendar for 214 users". Auth: service account with
domain-wide delegation impersonating an admin (`service_account_file` +
`admin_email`; scopes `admin.directory.user.readonly`,
`admin.directory.user.security`, `admin.directory.customer.readonly`) or an
`access_token` with those scopes. Live collection first resolves the authenticated
customer through the read-only Admin SDK `customers.get` endpoint, including when
the customer has no users. A configured concrete `customer` must match that ID;
user email domains and the alias `my_customer` do not establish tenant identity.
For service-account authentication, the signed assertion audience and token
exchange are fixed to `https://oauth2.googleapis.com/token`; a `token_uri` in
the key document cannot redirect the credential exchange.
Offline exports may contain individual token records or per-user objects such
as `{"user":"user@example.com","tokens":[...]}`. The latter retains user
attribution whether supplied as one object or inside an array. Set `customer` to
the verified immutable customer ID for offline analysis. Missing, conflicting or
unverifiable scope makes collection incomplete; retained observations cannot be
approved or merged with observations from another unresolved connector instance.
Google Workspace inventory bindings must include the matching customer in
`discovery.accounts`. Regenerate older cards whose account list is empty.
`max_users` caps the users enumerated (default 10000); reaching it makes the
scan incomplete. Live user suspension flags, when present, must be boolean. A
malformed flag makes coverage incomplete while valid neighboring users remain
eligible for collection.

### `identity.auth0`
Management API `clients` and `client-grants`: M2M applications, their
audiences and scopes, AI-named apps. Auth: M2M client for the Management API
(`read:clients`, `read:client_grants`) or `token`.
Options: `domain` (tenant domain such as `acme.eu.auth0.com`, env
`AUTH0_DOMAIN`) and the M2M application's `client_id` and `client_secret` (env
`AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`).

Client grants whose parent client is unavailable remain distinct unresolved
observations and make coverage incomplete. An inventory card cannot approve
an unresolved identity.

### `identity.jwt`
Decodes tokens (never stored) and classifies the holder as `human`, `service`,
`workload`, `delegated`, `agent` or `delegated-agent` using issuer-specific
conventions (Entra `idtyp=app`, Okta `cid == sub`, Auth0 `gty`, Google service
accounts, Cognito, Keycloak, SPIFFE) plus RFC 8693 `act` chains and
agent-related claims. GitHub Actions, Kubernetes service-account and GitLab CI
job tokens are `workload` identities. An agent-related claim counts only with a
meaningful value: `bot: false`, `purpose: ""` or `tools: []` do not make an
agent. Scopes/roles are classified by the policy signatures;
lifetime and algorithm hygiene are flagged. Optional `jwks_url` verification
fetches a bounded JWKS through the shared HTTPS client and accepts only RS256,
ES256, EdDSA and PS256 by default. `allowed_algorithms` may narrow that list.
`expected_issuer` binds verification to an operator-supplied exact issuer; the
unverified token's issuer does not choose or authorize a key source. The JWKS URL
is configured by the operator, so legitimate providers may host keys separately.
Audience and historical-token expiry are not authorization checks here. Read
`metadata.verified` as signature evidence, not permission to act.
A token analyzed without `jwks_url`, or whose verification failed, carries
`metadata.signature_verified: false`, the `signature-unverified` tag and a
`jwt:signature` evidence item: its issuer family, identity type and privileged
scopes come from unauthenticated claims and can be forged. The marker does not
change confidence or risk. For a JWKS endpoint behind a private CA, set
`ca_bundle` to a PEM file; it replaces the default CA store for that fetch and
certificate verification stays on.

Tokens come from `input` (one token per line, or JSON) or from the `tokens`
list in the connector entry. Keep live tokens out of committed configuration.

CLI equivalents: `--jwks-url`, `--expected-issuer`, and repeatable
`--jwt-algorithm`. The latter two require `--jwks-url`.

## Gateway

### `gateway.logs`
Auto-detects the schema per record: `litellm`, `portkey`, `kong`, `cloudflare`,
`helicone`, `langfuse`, `bedrock` (model invocation logs, CloudWatch export or
S3), `azure-openai` (diagnostic `RequestResponse`/`Audit`), `vertex` (Cloud
Audit Logs), `openai-usage`, `anthropic-usage`, `access-log` (nginx/envoy/ALB
combined or JSON, keeps only LLM/agent hosts and paths by default) or
`generic`. Each caller (API key, principal, service, user, user agent or IP)
becomes a finding with models, providers, frameworks (user agent
fingerprints), tool-use ratio, tool-call responses, temporal shape (24×7 /
night / weekend → `always-on`), volume, tokens, cost, errors. A gateway finding
for an anonymous, shared or user-agent/IP fallback caller cannot establish
the identity of a code workload in cross-layer correlation. Aggregate provider
usage exports count requests from provider counters; aggregate buckets are
not individual timestamped transaction events. Log fields for environment
and caller identity are evidence from the supplied export; assess the
producer and delivery chain before treating them as verified production facts.

A caller is titled **Agentic caller** when at least one agent indicator
holds: requests carried tool definitions or responses invoked tools; a user
agent belongs to a coding agent or agent framework; requests attempted a supported
hosted-agent invocation (Bedrock `InvokeAgent` or AgentCore runtimes, Assistants
runs, Vertex AI Agent Engine, Dialogflow CX sessions; tag `agent-runtime-api`);
requests reached an MCP endpoint (`/mcp`, or `/sse` and `/messages` on a
host a signature identifies as an MCP server; tag `mcp-client`); or corroborated
round-the-clock activity. Cadence remains a weak hint: three or more model calls
at distinct times at most 30 seconds apart can add `agent-loop`, but that tag
alone does not promote the caller to an agent. A batch script or chat front end
can have the same timing pattern. Read `metadata.agent_behaviour` before acting
on the label. A caller whose
requests mostly carry a browser user agent is never counted as a loop.
Invocation evidence binds method, provider and operation within the same event.
Management/list/poll/cancel requests cannot supply it, and an invocation attempt
does not by itself establish success or the `tool-use` capability.
Calling a model API is LLM use: the domains
and names of AI SaaS apps (`*.openai.com`, `*.anthropic.com`) do not make a
caller agentic. A product name matched in a key alias or a user name is a
hint, never an agent indicator, and a host counts only through the one
service it belongs to (its highest-weight signature), so browsing
`chatgpt.com` is AI use while traffic to `api2.cursor.sh` is a coding agent.

Options: `format`, `min_events`, `llm_hosts_only`, `max_records`,
`correlation_bindings`, and `label` (or `gateway_name` when the entry has no
label), which names the gateway on findings: it becomes the provider and the
account of callers without a tenant/account scope.

Static assets and health probes are recognized from the request path alone,
never its query string, and their count is reported as a scan note. In
`key=value` text lines, quoted values honor `\"` and `\\` escapes; a line that
repeats a key or leaves a quote open is malformed and makes the scan incomplete.

## Low-code

### `lowcode.power-platform`
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
Options: `tenant_id`, `client_id` and `client_secret` (env `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`; the client must be a Power Platform
application user). `environments` restricts live collection to the listed
environments, matched by name or display name. `include_bots` defaults to
true; `false` skips the Dataverse query for Copilot Studio agents.

### `lowcode.salesforce`
SOQL/Tooling: `BotDefinition`/`BotVersion` (Einstein bots & Agentforce
agents), `GenAiPlannerDefinition`/`GenAiPluginDefinition`/`GenAiFunctionDefinition`
(topics, actions, Apex/Flow targets), `GenAiPromptTemplate`, `FlowDefinitionView`
with AI hints, `ConnectedApplication` + `OauthToken` (user-authorised apps,
aggregated). Auth: `access_token` or client-credentials connected app.
Options: `instance_url` (`https://<org>.my.salesforce.com`, env
`SFDC_INSTANCE_URL`), `access_token` (env `SFDC_ACCESS_TOKEN`) or the connected
app's `client_id` and `client_secret` (env `SFDC_CLIENT_ID`,
`SFDC_CLIENT_SECRET`), `api_version` (default `v62.0`) and `max_pages` (per
query, at most 1000).

### `lowcode.servicenow`
Table API: `sn_aia_agent`, `sn_aia_tool`, `sn_aia_usecase`, `sn_aia_trigger`,
`sys_hub_flow` (AI hints), `oauth_entity`. Auth: basic or bearer.

Options: `instance` (env `SNOW_INSTANCE`), `username` and `password` (env
`SNOW_USERNAME`, `SNOW_PASSWORD`) or `token` (env `SNOW_TOKEN`) for a bearer
token instead of basic auth; `max_pages` (per table, at most 1000); `input`
for an offline JSON export of the table records.

Tools and triggers with unresolved agent/usecase references remain visible
as unresolved observations, make coverage incomplete and cannot inherit
registry approval from an unrelated parent.

### `lowcode.n8n`
n8n workflows with AI or agent steps, including LangChain nodes; triggers
(schedule/webhook → autonomous), code steps (→ code-exec) and models. Live
pagination is bounded by `max_pages` (default and maximum 1000). A workflow
needs a nonempty provider ID for a usable resource identity. Exported blueprints
without an ID retain detected AI evidence under an unresolved identity, make
collection incomplete and cannot be approved by a registry card. Authentication
uses `api_key`, sent as `X-N8N-API-KEY` (env `N8N_API_KEY`), against `api_url`
(env `N8N_API_URL`, for example `https://n8n.example.com/api/v1`).

### `lowcode.make`
Make scenarios with AI modules and AI Agents; triggers (schedule/webhook →
autonomous), code steps (→ code-exec) and models. Live pagination is bounded by
`max_pages` (default and maximum 1000). Make scans one `team_id`, or every team
of an `organization_id` when `team_id` is unset.

### `lowcode.zapier`
Zapier zaps and AI/Agents from account exports; triggers (schedule/webhook →
autonomous), code steps (→ code-exec) and models. Live pagination is bounded by
`max_pages` (default and maximum 1000). Wholly blank text rows are skipped only
with a recognized identity column (`title`, `name`, `Title`, `Zap`, `id`, or
`Id`); unknown schemas are incomplete.

### `lowcode.workato`
Workato recipes with GenAI/agentic providers; triggers (schedule/webhook →
autonomous), code steps (→ code-exec), and models. Live pagination is bounded by
`max_pages` (default and maximum 1000).

## SaaS

### `saas.slack`
`users.list` (bots), `admin.apps.approved.list` / `restricted` / `requests`
(scopes, pending requests), `team.integrationLogs` (who installed what).
`team.info` must return an authenticated workspace identity. If `team_id` is
configured, it must match exactly before inventory calls begin. Missing/null
collection arrays and malformed pagination are incomplete coverage. Later
network failures retain already collected observations; provider error text is
not copied into diagnostics. Complete live acceptance generally requires an
appropriately scoped administrative audit token, not an ordinary bot token.
Findings use the immutable workspace ID as `account`; the display name is stored
in `metadata.workspace_name`. An offline export without a team record requires
an explicit `team_id`. Conflicting or malformed workspace envelopes make the
scan incomplete and prevent attribution. A record that names another or an
invalid workspace ID (for example a Slack Connect bot) is skipped and counted,
and the scan is incomplete; the workspace's other records are still reported.
Update inventory account bindings
and collect a fresh comparison baseline when upgrading from name-based IDs.

### `saas.microsoft-teams`
Graph app catalog (custom apps with bot definitions and RSC permissions) and
installed apps per team (capped by `max_teams`).
Malformed app IDs, conflicting expanded identities and malformed nested
definitions or permissions make collection incomplete. An installation ID is
not a fallback catalog app ID. Valid neighboring records remain available.
Options: `tenant_id`, `client_id` and `client_secret` (env `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`) or `access_token` (env
`GRAPH_ACCESS_TOKEN`). `include_store: true` also lists store apps in the
catalog; installed apps are always inspected.

### `saas.github-apps`
Org installations with permissions and repository selection (AI reviewers,
coding agents), Copilot billing/seat settings, fine-grained PATs approved for
the org. An installation is reported when its slug or its words match an AI
signature or an AI-like name; `include_unrecognized_apps: true` also reports
other write-capable apps, tagged `unrecognized-app` at possible confidence.
`token` (env `GITHUB_TOKEN`) must be an organization-admin token. Name a variable
of its own for it (for example `token: ${GITHUB_APPS_TOKEN}`) rather than relying
on `GITHUB_TOKEN`, which `code.github` reads by default for a token that clones
untrusted repositories; the rule that code scans and live connectors run
separately does not narrow a shared token's scope.

### `saas.atlassian`
UPM user-installed apps for Jira and Confluence. Provider error envelopes make
collection incomplete even when they include empty record arrays; valid
observations from other pages and products remain available. The same rule applies to
offline exports. Options: `site`
(`https://<org>.atlassian.net`, env `ATLASSIAN_SITE`), a site admin `email` and
`api_token` (env `ATLASSIAN_EMAIL`, `ATLASSIAN_API_TOKEN`), and `products`
(`jira`, `confluence`; default both).

### `saas.notion`
Notion bot users. A missing or repeated pagination cursor, or reaching the live
page cap (`max_pages`, at most 1000), makes the scan incomplete. Provider error
envelopes make collection incomplete even when they include empty record arrays;
valid observations from other pages remain available. The same rule applies to
offline exports. Options: `token` (env
`NOTION_TOKEN`), an internal integration secret whose integration has the
*read user information* capability for `GET /v1/users`; `max_pages`; `input`
for an offline `/v1/users` export.

### `saas.zoom`
The Marketplace list API returns approved public apps and account-created apps
(`type=public` and `type=account_created`), including app scopes when supplied.
See [Zoom's Marketplace List apps API](https://developers.zoom.us/docs/api/marketplace/).
Approval or account creation does not establish that any individual installed
or used the app; obtain a separate tenant activity or installation export to
check that. Denied, invalid or truncated pages make the scan incomplete.
Options: `account_id`, `client_id` and `client_secret` (env `ZOOM_ACCOUNT_ID`,
`ZOOM_CLIENT_ID`, `ZOOM_CLIENT_SECRET`) for a Server-to-Server OAuth app, or
`access_token` (env `ZOOM_ACCESS_TOKEN`).

### `saas.generic`
Any CSV/JSON app inventory (Google Marketplace, HubSpot, CASB discovered-apps
exports…). Map columns with `fields:`; findings are produced for AI matches
and privileged/data scopes (`keep_all: true` to emit everything). Records
without a usable string app name make coverage incomplete while valid
neighboring records remain available. A partial export cannot resolve an
earlier finding merely because that row lost its name.
`platform` (default `saas`) names the export's source, for example
`google-marketplace`, `hubspot` or `defender-mcas`. It prefixes finding titles
and resource IDs and sets the provider, so keep it stable between scans.

## Cloud

All cloud connectors need the matching extra (`aws`, `gcp`, `azure` or `oci`)
for live mode, or a JSONL record dump for offline mode. They use read-only
list/describe/get calls only.

Cloud record exports withhold every environment value of a function, app or
container. Those values are ordinary configuration rather than credentials, so
they are not also removed from sibling fields such as ARNs; values under
sensitive names and recognizable credential formats are removed everywhere.
Findings record environment variable names only.

Instance and workload credentials are used only when the scan-wide
`options.allow_instance_credentials` is true (default false). These are EC2 or
ECS roles, Azure managed identity, GCP metadata Application Default
Credentials, and OCI instance or resource principals. The engine replaces an
`allow_instance_credentials` value in a connector entry with the scan-wide
value; see [Production](production.md).

### `cloud.aws`
Bedrock Agents (action groups, knowledge bases, aliases, collaborators,
guardrails, memory), Flows, AgentCore (runtimes, gateways = MCP, memories,
browsers, code interpreters, workload identities), model invocation logging
state, Lambda (env names, plaintext keys, layers, images, tags), ECS task
definitions referenced by running tasks and service deployments, plus latest
registered definitions, SageMaker endpoints (LLM containers), Step Functions with Bedrock
states, Q Business, Lex, Secrets Manager / SSM names, IAM principals with LLM
actions (via `get_account_authorization_details`), CloudTrail LLM callers.
Options: `profile`, `role_arn`, `regions` (`all`), `services`, `cloudtrail_days`,
`max_ecs_api_calls` (default 2000 per region). ECS uses exact task-definition ARNs
for deployed references, including referenced inactive revisions. Findings
separate running-task/service references from registered-only definitions; a
reference does not establish successful AI execution. Exhausted API budgets or
partial/denied responses mark coverage incomplete. Account identity is resolved
before collection emits account metadata. Live `account_id` is an expected
12-digit account, verified through STS even when explicitly configured;
mismatches stop collection. AWS SDK clients use finite connection/read timeouts
and retry attempts. `max_lambda` limits streamed enumeration.
Offline exports resolve their account from `account` records wherever they
appear. Several different or invalid `account` records, or a resource ARN from
another account (CloudTrail callers excepted), leave short resource identities
unresolved and the scan incomplete; generated ARNs for Bedrock logging, Q
Business, Lex and SSM parameters take the resolved account or none. Such
findings cannot be approved by an inventory card.
IAM analysis includes both local and AWS-managed attached policies. Unresolved
attachments make collection incomplete. CloudTrail LookupEvents only supplies
management events: `InvokeAgent` / `InvokeInlineAgent` data events require a
separately configured trail or event data store and an export to `gateway.logs`.
The collector reports this coverage gap when CloudTrail collection is enabled.

Lambda `Environment.Error` is unknown environment coverage, not an empty set of
variables. The `environment_coverage` marker survives sanitized exports and replay;
other valid function evidence is retained while completeness fails.

IAM findings are policy evidence, not effective authorization. `Allow/NotAction`
is inspected against representative AI operations and resource service scope,
with potential actions and explicit limitations recorded. Conditions, denies,
policy boundaries, unsupported resource semantics and the full action universe
are not evaluated; partial semantics make coverage incomplete. S3/IAM-only
wildcards do not independently produce LLM grants. Effective access also depends
on applicable policies outside this collector's view.

Role trust policies are parsed, not searched as text. A service principal
(`Principal.Service`) or OIDC provider (`Principal.Federated`) is trusted only
through an `Allow` statement whose `Action` includes `sts:AssumeRole`,
`sts:AssumeRoleWithWebIdentity` or `sts:AssumeRoleWithSAML` (IAM wildcards, any
case). `Deny`, `NotAction` and `NotPrincipal` statements, and service names in a
`Sid` or `Condition`, never establish trust; conditions are not evaluated. A
trusted Bedrock or AgentCore principal tags the role `agent-execution-role`. The
document may be an object, JSON text or URL-encoded JSON; a malformed one is
reported as unknown trust (`malformed-trust-policy`) and makes the scan incomplete.

AWS clients ignore configured endpoint URL overrides and use bundled SDK models;
external model paths (`AWS_DATA_PATH`, user SDK model directories) cannot replace
service endpoint rules, including after role assumption. This does not replace
worker egress controls or establish the trustworthiness of installed SDK packages.

### `cloud.gcp`
Service Usage (AI APIs enabled), Vertex AI reasoning engines (Agent Engine)
and endpoints per location, Dialogflow CX agents, Discovery Engine /
Agentspace engines, Cloud Run services, Cloud Functions, project IAM bindings,
service accounts (user-managed keys), API keys restricted to Gemini, Secret
Manager names, optional Cloud Audit Log callers (`audit_days`). Auth: ADC via
`google-auth` or `access_token`. Owner-only and Editor-only IAM principals are
retained as privileged access findings even without an AI-specific role. A grant
shows potential access, not observed agent execution. Project IAM collection
requests policy version 3 and preserves each conditional binding. Conditions
must be evaluated separately before asserting effective access; degraded
`_withcond_` exports are retained with incomplete diagnostics.
Cloud Run discovery enumerates project locations and then lists services in each
concrete region (`run.locations.list` and `run.services.list` permissions).
Unreachable locations reported by GCP make the scan incomplete. `max_projects`
limits discovery without loading all projects first; `max_pages` (default and
maximum 1000) bounds every paginated call; resource lists stop at 500 pages and audit-log
queries at 50 pages regardless.
`locations` lists the Vertex AI and Dialogflow locations to query (default
`us-central1`, `us-east4`, `us-west1`, `europe-west1`, `europe-west4`,
`asia-southeast1`, `asia-northeast1`). `credentials_file` names an explicit
Google credentials file (env `GOOGLE_APPLICATION_CREDENTIALS`); otherwise the
local gcloud Application Default Credentials are used.

### `cloud.azure`
Azure Resource Graph inventory across subscriptions, then: OpenAI/AI Services
accounts + deployments + diagnostic settings, AI Foundry accounts/projects
(+ agents via the project endpoint), hub-based ML workspaces, Bot Service,
Logic Apps (AI connectors / agent loops), Web & Function app settings,
Container Apps, user-assigned identities, role assignments with AI roles.
Auth: `DefaultAzureCredential` or `access_token` (+ `foundry_token`).
Resource Graph, ARM and Foundry collections follow pagination. A denied or failed
diagnostic-settings request is reported as unknown; only a successful empty
response supports a missing-diagnostics finding.
Foundry agent discovery targets the classic Agent Service contract:
`GET <project-endpoint>/assistants?api-version=v1`. Newer `/agents` API families
require their own contract and are not implied by this support. Missing, denied
or malformed collections remain incomplete; pagination must finish before
absence can be inferred.
`subscriptions` lists the subscription IDs to scan (default: every visible
subscription). `include_app_settings` (default true) reads Web and Function
app settings, recording names and checking values for credentials; `false`
skips them.

### `cloud.oci`
Generative AI Agents (agents, endpoints, tools, knowledge bases), Digital
Assistant, GenAI endpoints/clusters/custom models, Data Science model
deployments, Functions, Container Instances, Vault secret names, IAM policies
granting `generative-ai*`, dynamic groups. Auth: `~/.oci/config` profile,
instance or resource principal.
Options: `profile`, `config_file`, `auth`, `tenancy` (default: from the
profile or the principal signer), `region` (session region for
`instance_principal`; config auth uses the profile's region), `regions`,
`compartments`, `max_pages` (default and maximum 1000).
Function inspection retrieves application and function details, combines
inherited configuration with function overrides, and supports both legacy image
fields and `source_details.image`. Denied or invalid detail reads mark coverage
incomplete while preserving available resource evidence. Audit credentials need
the corresponding application/function read permissions; list-only access is
insufficient to inspect configuration.
SDK objects become records through `oci.util.to_dict`, or through the model's
declared fields when the SDK cannot be imported; an object that cannot be
converted is skipped with a warning and makes the scan incomplete.

## Endpoint

### `endpoint.inventory`
Inventories AI tools on developer workstations from a fixed list of
documented user-scope locations below each home directory: client and
coding-agent configurations with their MCP servers (Claude Desktop, Claude
Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex, Kiro, Amazon Q, LM
Studio, Continue, Goose, Cline, Roo Code, Aider, OpenClaw, Copilot CLI), AI
editor extensions, AI browser extensions (matched by product name), local
model stores (Ollama, LM Studio, Hugging Face, GPT4All, Jan) and, with
`shell_history: true`, AI command-line tools named in shell history (tool
names and counts only). MCP server findings carry the static server risks
and agent configurations carry the posture checks described in
[risk](concepts/risk.md). Every location is opened without following
symbolic links; a link, an unreadable location, an oversized file or an
exhausted `max_entries` budget makes the scan incomplete.

Options: `path` or `paths` (home directories; default the scanning
account's home), `label` (device name; default the host name),
`shell_history`, `max_entries`. Offline, `input` replays exported records or
reads osquery `vscode_extensions`, `chrome_extensions` and `firefox_addons`
results. See the [endpoint guide](connectors/endpoint.md).

## Network

### `network.logs`
Reports, per client address, the AI services contacted in DNS, TLS and flow
telemetry: Zeek `dns.log`, `ssl.log` and `conn.log` (TSV or JSON), Route 53
Resolver query logs, VPC Flow Logs, and generic JSON or CSV DNS and SNI
records. Host names match a signature's exact domain or declared wildcard,
never a substring. Non-AI TLS names are retained as negative attribution evidence.
A flow is attributed by its connection identity to an AI TLS server name, or
through unambiguous DNS answers in the same input. Conflicting identities and
explicit non-AI TLS evidence prevent fallback attribution. Coding-agent, MCP and hosted-agent services
are tagged `agent-service`; runs of connections to a model API seconds apart
are tagged `agent-loop`. Malformed or unrecognized records make the scan
incomplete. VPC `SKIPDATA` and invalid or contradictory logging statuses also
make coverage incomplete; `NODATA` is a valid no-traffic observation.

Options: `format` (`zeek`, `route53`, `vpc-flow`, `generic`; default auto),
`label` (network name; default `network`), `max_records`. See the
[network guide](connectors/network.md).

## Runtime

### `runtime.processes`
Reports AI tools seen running, per host, user and tool: coding-agent CLIs
(also as npm packages or Python modules), AI desktop apps matched by
executable and install path, MCP servers launched through `npx`, `uvx`,
`uv tool run`, `pipx run` or `node`, local model servers and agent dev
servers. Command lines never enter a finding or a `--dump-records` export:
only the tool, the executable's base name and an MCP package name are kept.
Offline, `input` reads osquery `processes` results, Defender
`DeviceProcessEvents`, CrowdStrike process events or any JSON/CSV with a
command line or executable; live mode reads `/proc` on Linux. The engine
links these findings to endpoint findings for the same tool on the same
device (`metadata.lifecycle`, tag `observed-running`) without changing
scores.

Options: `label` (host name for records without one), `max_processes` (live
mode bound). See the [runtime guide](connectors/runtime.md).

## Least privilege

All connectors are read-only. Prefer dedicated audit credentials:

| Connector | Minimum |
|---|---|
| GitHub | fine-grained PAT: contents/metadata read; `secrets:read` for Actions secret names, plus `variables:read`, Codespaces `secrets:read` and Dependabot `secrets:read` for the other credential-name listings (each optional; a denied listing marks coverage incomplete) |
| GitLab | PAT `read_api`, `read_repository` |
| Okta | API token from a read-only admin, or OAuth `okta.apps.read` |
| Slack | token with `users:read`; the `admin.apps.*` lists and `team.integrationLogs` need an org admin user token (`admin.apps:read`, `admin`) |
| ServiceNow | basic or bearer credentials with read access to the `sn_aia_*`, `sys_hub_flow` and `oauth_entity` tables through the Table API |
| Notion | internal integration token with the *read user information* capability (`GET /v1/users`) |
| Zoom | Server-to-Server OAuth app with `marketplace:read:list_apps:admin` |
| Atlassian | site admin basic auth with an API token for the Universal Plugin Manager listing |
| Auth0 | Management API v2 token with `read:clients`, `read:client_grants` |
| Entra / Teams / Power Platform | app permissions `Application.Read.All`, `DelegatedPermissionGrant.Read.All`, `Directory.Read.All`, `AppCatalog.Read.All`, `Team.ReadBasic.All`, `TeamsAppInstallation.ReadForTeam.All`; Power Platform admin application user |
| Google Workspace | DWD scopes `admin.directory.user.readonly`, `admin.directory.user.security`, `admin.directory.customer.readonly` |
| AWS | `SecurityAudit` managed policy + `bedrock:List*/Get*`, `bedrock-agentcore:List*/Get*`, `cloudtrail:LookupEvents`; ECS additionally needs `ecs:ListClusters`, `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:ListServices`, `ecs:DescribeServices`, `ecs:ListTaskDefinitionFamilies`, `ecs:DescribeTaskDefinition` |
| GCP | `roles/viewer` + `roles/iam.securityReviewer` (+ `roles/logging.privateLogViewer` for audit logs) |
| Azure | `Reader` on subscriptions (+ `Cognitive Services OpenAI User`/`Azure AI User` to list Foundry agents; a narrowly scoped custom permission `Microsoft.Web/sites/config/list/Action` when sensitive app settings are needed) |
| OCI | policy `Allow group audit to read all-resources in tenancy` |
| Endpoint | read access to the inventoried home directories; run as that user, or as an account that can read every listed home on a shared host. Nothing is written |
| Network | read access to the exported logs; the connector needs no sensor or cloud credentials |
| Runtime | offline: read access to the process export; live: an account that can read `/proc/<pid>/cmdline` of the processes to inventory. Nothing is written |

The Azure app-settings permission exposes security-sensitive configuration;
only grant it for the app resources being audited. Do not grant Website
Contributor solely for this read operation. See Microsoft's
[permission definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/web-and-mobile).
