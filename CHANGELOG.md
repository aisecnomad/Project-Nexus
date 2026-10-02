# Changelog

## 0.1.1 — Unreleased

### October 1 review remediation

An AI-assisted audit of the unreleased candidate (not independent human review)
found places where a scan could finish `complete` while skipping content or
persisting credential-shaped text. These changes close the confirmed gaps; each
has a regression test.

- **Silent coverage gaps now mark the scan incomplete.** A source or config file
  with a NUL byte in its first 8 KiB and no byte-order mark (UTF-8/16/32 files
  with a byte-order mark are now decoded instead; other invalid UTF-8 is still
  decoded with replacement characters), a FIFO, socket or device named like a
  config file, a directory named like an MCP configuration file (`.mcp.json/`),
  a directory tree nested too deeply for the Python 3.11 walker, any file
  without a supported export suffix in a connector's offline input directory (a
  rotated `access.log.1`, a `.bak` or `.zst` copy, a `README.md`),
  `saas.generic` rows without a resolvable name, wrong-schema `saas.generic` and
  `lowcode.zapier` objects, and negative or absurd gateway token and cost values
  each produce a specific incomplete diagnostic. A symlinked card inside an
  inventory directory stops setup instead of being skipped. A recognised binary
  artifact (executable, archive, image, PDF or SQLite database, by its header)
  stays a quiet skip when it has no file extension, when only a directory-wide
  signature glob such as `.cursor/rules/**` selected it, or when it is a `.ts`
  MPEG transport-stream video segment; unrecognised binary content is a gap.
- **Disclosure without failure.** Code scans list default-excluded directory
  names (`build`, `vendor`, `external`, ...) once per root, and default-scope AWS
  and GCP scans name the regions or locations that were not scanned. Both are
  notices that do not mark the scan incomplete. Reports list disabled or
  `--only`-excluded connectors in `collection_scope.not_run`. The AWS CloudTrail
  management-events notice no longer forces exit 3.
- **Credential redaction.** Newly withheld: values of the `--passphrase`,
  `--pat` and `--auth` options (withheld as a `--password` value is, so a
  lowercase word after a space stays; in an argv list the value after these
  options and `--pass`, `--pwd` or `--password` is always withheld); whole
  armored PGP private key blocks, including one after a credential name; every
  cookie in a `Cookie` header; compact headers and passwords without a space
  (`x-api-key:S`, `password:S`); unquoted values containing `;`; values in
  escaped-quote JSON; the URL query keys `auth`, `pwd` and `pat`; Fireworks
  `fw_` keys; and provider tokens next to non-Latin text. Sets and bytes are
  traversed. Some text is over-redacted: `ffmpeg -pass 1` loses its pass
  number, `NAME=S;rest` loses the text after `;`, and `Authorization:` loses
  its scheme name. A quadratic JWT pattern that could stall a scan for minutes
  was replaced by a linear one. The unkeyed SHA-256 `credential:sha256:` digest
  is unchanged; see `docs/production.md`.
- **Gateway attribution.** Access-log hosts are read only from the trailing
  unquoted `host=` token, so a user agent or path cannot hide or forge LLM
  traffic. Generic vendor hosts (`api.cloudflare.com`, `huggingface.co`) are
  hints rather than LLM-usage evidence, except Cloudflare Workers AI inference
  paths (`/accounts/<id>/ai/run/`, `/accounts/<id>/ai/v1/`), which stay LLM
  traffic. PyPI `swarm` no longer maps to OpenAI Swarm. Scope names are matched by bare name across providers, so names that
  are routine on another provider no longer match `policy.privileged-scopes`:
  OIDC `offline_access`, Salesforce `full`, `web` and `refresh_token`, GitLab
  `api`, GitHub `workflow` and Slack `admin`. Findings that held only these
  scopes lose that risk factor and can drop a risk level.
  `identity.jwt` ignores empty or false agent claims, labels GitHub Actions,
  GitLab CI and Kubernetes service-account tokens `workload` (a Kubernetes
  service-account subject or claims make a `workload` for any issuer, including
  GKE), counts a GitHub Actions `actor` or `triggering_actor` as an agent hint
  only when it names an AI agent or product, and marks tokens scanned without a
  JWKS (`signature_verified: false`). Gateway registry matches on
  operator-asserted or unverified caller names carry
  `metadata.registry_match_assurance` and the `registry-identity-unverified` tag.
- **Engine and reports.** A connector or third-party plugin raising
  `SystemExit` or another `BaseException` other than `KeyboardInterrupt`, while
  it is imported, its class is verified, an engine hook runs or it collects, is
  an incomplete connector (exit 3 with a report), not a process exit. Only the
  exception type is reported. `KeyboardInterrupt` still ends the scan. Incomplete CSV
  reports start with a `SCAN-INCOMPLETE` status row. Saved CSV and HTML render
  terminal control characters visibly. `shadowscan diff --fail-on-new` exits 2 on
  new or higher-risk findings. Exit codes 1 and the usage-error 2 are documented.
- **HTTP client.** Okta `X-Rate-Limit-Reset` is honored, retries stop at the
  connector deadline, a response body must also finish before that deadline
  (in addition to the read deadline below), and `identity.jwt` accepts an
  explicit `ca_bundle` for private PKI (verification stays on; a relative path
  resolves beside the configuration file).
- Dialogflow CX and Discovery Engine use their regional endpoints. ServiceNow
  collection pages until an empty page. A weekly scheduled `pip-audit` workflow
  was added. The Anthropic signature recognises `sk-ant-oat01-` OAuth tokens.
  Unquoted Cursor `globs: **/*.ts` no longer causes a false exit 3,
  and `host_of` strips URL userinfo and handles IPv6 literals.

### October 1 discovery review corrections

- Code collection identifies declared submodules whose source has not been
  materialized and reports incomplete coverage instead of a complete empty
  result. Remote clone collection also checks the Git tree for submodule
  entries. Submodule URLs are never fetched automatically.
- Ordinary Spring AI `ChatClient` and LangChain4j `AiServices` construction,
  and standalone Java tool declarations, no longer establish an agent or
  tool-use capability. Explicit agent construction and bounded, concrete tool
  registration remain evidence.
- Import-bound source calls distinguish configured workload capabilities from
  features merely offered by their framework. Empty tool/handoff collections
  and disabled delegation no longer add those capabilities or their risk
  factors. Review changed findings and rebuild enforcement baselines.
- Authored evaluation cases now check capability labels as well as kind and
  product attribution. The frozen independent corpus and its labels are
  unchanged; these regressions do not establish fresh field accuracy, live
  tenant acceptance or independent human review.

### October 1 code.filesystem coverage and precision

- A coding-agent instruction document that links to another one in the same
  project with the same test classification (`CLAUDE.md` to `AGENTS.md`) no
  longer marks the scan incomplete. The target is scanned at its real path and
  the alias-only file name is not reported as a second agent. Links across
  projects or into and out of test paths, and directory links, stay gaps.
- Credential policy: a real-format credential under a test, fixture or
  `cassettes/` path stays a `secret` finding and now follows the project
  test-code policy: half weight, lower confidence and risk, and the
  `test-code-only` tag unless `include_tests` is set. Recorded cassettes
  capture real traffic, so such keys are downweighted, never dropped.
- A coding-agent configuration finding now needs more than an environment-variable
  or display-name mention such as `GOOSE_PROVIDER`. Config files, instruction
  documents, dependencies and code patterns such as a workflow step still
  establish it. In test paths only config files and instruction documents count
  unless `include_tests` is set.
- MCP parsing skips `*.lock.yml` and `*.lock.yaml` files (compiled agentic
  workflows) and cookiecutter `{{...}}` template paths, which no longer raise an
  invalid-MCP error. Other GitHub Actions workflows are still parsed for MCP
  servers passed as JSON step inputs (see the field scan follow-up below).
- Not changed: signatures, risk scoring and inventory labeling. Oversize
  recorded fixtures (`cassettes/`, test data) stay coverage gaps, because they
  can hold real credentials; skipping them unread is an operator decision
  through `oversize_skip_globs` (for example `*/cassettes/*`). Examples,
  templates and benchmarks are not discounted like tests, because the bundled
  corpora label their agents as real. Evidence is offline regression tests and
  corpora only; it is not a measured field precision.

### October 1 field scan follow-up

Fixes for defects found by scanning five public agent repositories (see
`archive/reviews/field-scan-2026-10-01.md`); each has a regression test.

- The JSX lexer no longer marks valid TSX incomplete. It skips explicit type
  arguments on elements (`<Select<Option> ...>`, `<Form<{ email: string }>>`),
  comments between attributes (a comment just before `>` no longer makes the
  tag self-closing), and treats `<Text>(...)</Text>` as an element
  unless the parenthesized group is followed by `=>` or a return type. In the
  field scan this removed 139 false incomplete files; unbalanced tags still
  fail closed.
- Gemini CLI's `httpUrl` is an MCP endpoint alias. Such extension manifests no
  longer make the scan incomplete, and their remote servers are reported. A
  header or env value that is only a shell-style reference (`Bearer $TOKEN`) is
  not an inline credential.
- GitHub Actions workflows that pass MCP settings to an agent action no longer
  fail strict YAML parsing on the `on:` key. Servers embedded as JSON step inputs
  are reported as MCP findings; unparseable embedded settings stay incomplete.
- `GOOGLE_GENAI_USE_VERTEXAI` no longer attributes the Google Agent Development
  Kit. It remains Vertex AI provider evidence.
- Exported workflows under test or fixture paths follow the project test-code
  policy: half weight and the `test-code-only` tag unless `include_tests` is set.
- A `setup.py` marks a project root only when it references setuptools,
  distutils or scikit-build, or calls `setup(...)`. Ordinary modules named
  `setup.py` no longer split a package into a separate project; an unreadable
  file keeps the previous behavior.
- An MCP argument assigning a file path to a credential-file variable
  (`GOOGLE_APPLICATION_CREDENTIALS=/app/key.json`), or one whose only redacted
  part repeats a variable reference from `env` (`-v ${KEY_FILE}:/app/key.json`),
  is still redacted but no longer marks the server as carrying an inline secret.
  Literal values remain inline secrets.

### Completeness, report safety and credential policy (2026-09-28)

Behavior changes to review before upgrading (see
[production](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#completeness-report-and-credential-changes)):

- **Credential policy:** the scan-wide `options.allow_instance_credentials`
  now replaces `allow_instance_credentials` in every connector entry. Only
  `cloud.*` entries were replaced before, so a third-party connector's own
  entry could grant it instance-credential approval. The scan-wide value
  still goes to every `cloud.*` connector, plugins included, and now also to
  any plugin that declares the cloud surface or documents the key in
  `config_keys`; with the default `false` this only denies. Built-in
  connectors behave as before.
- **New incomplete scans (exit 3):**
  - A shared HTTP response body must arrive within twice the client timeout
    (60 seconds by default), not only within the 30-second per-read timeout.
    A slower body, for example from a slow-drip server, is aborted (`HTTP
    response exceeds the read deadline`) and the connector's collection is
    incomplete, never truncated.
  - `code.filesystem` opens each scan root once and reads every file, and
    `CODEOWNERS`, relative to it without following a link in any path
    component; before, only the final component was protected. A directory
    replaced by a link during the scan fails the reads below it
    (`file could not be read`). A root that cannot be opened this way is
    reported, by its `label` when one is set, as
    `could not open the scan root safely (<reason>)`.
  - `code.gitlab` skips a group listing entry whose project `id` is not a
    positive integer (`group project listing entry has no valid numeric id;
    project skipped`) and scans the other projects. Such an id used to reach
    request paths, where it could send the token to another API endpoint,
    and a missing id aborted the whole listing.
  - `code.github` skips an org or user listing entry whose `full_name` is not
    a plain `owner/name` (`repository listing entry has no valid owner/name;
    repository skipped`). It used to reach request paths and the clone URL.
- **Changed diagnostics (these scans were already incomplete):**
  - A YAML value PyYAML cannot construct, such as an impossible date or an
    integer over 4,300 digits, is reported as malformed YAML: `invalid YAML`
    for conda environment files (was `manifest parsing failed (ValueError)`)
    and `invalid agent definition YAML` for agent front matter (was
    `file analysis incomplete (ValueError)`). The agent definition is now
    listed where it used to be dropped, which adds `agent_definitions`
    metadata and can raise the finding's risk score. Scan configuration and
    inventory files with such a value still fail at setup (exit 1), now with
    `ConfigValidationError` and `InventoryValidationError` instead of an
    unclassified `ValueError`.
  - A cancellation or connector deadline while `code.filesystem` builds a
    credential finding ends the connector, as it does everywhere else,
    instead of becoming that file's `credential analysis incomplete` error.
- **Scans that now complete:**
  - A Python module none of whose imports can resolve to a signature no
    longer makes a scan incomplete when it exceeds `max_ast_nodes` or the
    import binder's nesting limit: the binder, which could add no evidence
    there, is skipped. The check is linear in the module and matches at most
    4,096 distinct import statements; other modules keep the
    `import-bound analysis skipped (…); lexical evidence retained`
    diagnostic. A scan of installed libraries such as mypy, pip, requests and
    rich, which exited 3 because of `mypy/checker.py`, now completes.
  - Configuration, inventory, signature pack, `diff` report and offline
    export files below a traverse-only directory (mode `0711`) now open:
    directories are opened for traversal only (`O_PATH` on Linux), not for
    reading.
  - An unrendered Helm, Jinja or Go-template YAML file, whose placeholders
    read as mapping keys (`image: {{ .Values.image }}`) or whose conditional
    branches repeat a field, no longer reports `structured parsing incomplete
    (YAMLIntegrityError)`. Such a file is not YAML until rendered, so its
    excerpts use lexical redaction, as for any template the YAML parser
    rejects. Plain YAML with duplicate or non-finite data still fails closed.
- **Report redaction** withholds more credential forms, in excerpts and in
  structured connector metadata. Expect more `[REDACTED]` markers:
  - string literals passed to credential constructors, helpers and factories
    (`AzureKeyCredential("…")`, `HTTPBasicAuth("user", "…")`,
    `Credentials.basic`, `setBearerToken`, `WithAPIKey`, `cohere.Client`),
    including Rust `::new("…")`, C# target-typed `new("…")`, calls down a
    builder chain (`builder().apiKey("…")`, `.header("x-api-key", "…")`) and
    `auth=("user", "…")` tuples;
  - literal defaults of credentials read from the environment
    (`process.env.OPENAI_API_KEY || "…"`, `?? "…"`, `or "…"`, `?: "…"`,
    `${OPENAI_API_KEY:-…}`);
  - credential command-line options: `--api-key`, `--token`, `--password`,
    `--key` and `--pwd`, also in argv lists; `curl -u` and
    `-H "X-Api-Key:…"`; `-p` after `docker login`, other registry logins and
    `az`, `oc` or `cf` logins; `sshpass -p`; MySQL `-p…`; a literal echoed
    into `--password-stdin`; and `dotnet user-secrets set NAME VALUE`;
  - Dockerfile `ENV`, `setx`, `setenv`, C `#define`, PowerShell and TOML
    quoted keys assigned with `=`, and R `<-`;
  - XML key/name attributes, element names and name/value records, read as
    .NET settings by their last `:`, `__` or `.` segment as well as whole
    (`<add key="OpenAI:Secret" value="…"/>`, `- name: AzureOpenAI__Key`). In
    structured metadata the value is also removed from the record's other
    fields;
  - an opaque-looking value under a name whose last word, ignoring trailing
    digits, names a credential (`openaiKey`, `key`, `KEY1`), and a lone
    opaque value on the unindented line after a sensitive key;
  - more token prefixes: Google `ya29.`, `1//0` and `GOCSPX-`; Slack `xapp-`
    and `xoxe`; the GitLab `glrt-` family; `npm_`, `pypi-` and `dop_v1_`;
    and Stripe, SendGrid, Databricks, Shopify, Atlassian, Linear, Notion,
    Postman, Doppler, Supabase, Grafana, Sentry, Vault and Terraform Cloud
    tokens. `Ocp-Apim-Subscription-Key` and names ending in
    `subscriptionKey` are credentials.

  A C# `new AzureKeyCredential("<key>")`, a Java `builder().apiKey("<key>")`
  or a web.config `<appSettings>` key used to reach the reports of a complete
  scan; regenerate such reports and rotate the keys they show. Endpoint URLs,
  model names, variable names and references, placeholders and ordinary
  values (`<add key="CacheKey" value="users"/>`) stay visible. SECURITY.md
  lists the forms that are still not withheld, among them a space or comment
  before a call's parenthesis, redundant parentheses, C# interpolated and
  multi-line triple-quoted strings, one-letter options, a query parameter
  outside a URL and an unquoted value that reads as an identifier.
- **Redaction fixes:** a YAML parent key such as `openai:` no longer takes
  the next line as its value, which leaked a nested `api_key: <value>`. A
  `Bearer`/`Basic` scheme before a line break no longer drops a line from
  the excerpt, and a marker inside an unquoted value no longer gains a `]`
  each time a report sanitizes it again. Redaction is linear on hostile
  layouts that used to time out, exhaust the redaction budget or hang the
  scan without marking it incomplete: long runs of unfinished annotations,
  minified lines with thousands of sensitive keys, and long unquoted values
  after `key=`. Expressions nested more than 100 brackets deep are withheld
  through the end of the excerpt, and an unquoted word holding more than 16
  command-line options is withheld from its 17th option on.
- **Finding identity:** IDs are computed from sanitized resource fields, so
  an ID changes only where such a field held a value that is now withheld.
  These redaction rules leave the findings and IDs of the demo, the sample
  repository and every evaluation corpus unchanged; the classification
  corrections of September 27 below can still change findings. The redaction
  policy token changed, so findings verified clean under the old rules are
  sanitized again. Report sanitization takes about 28% longer (11 s to 14 s
  for 19 MB of library source).
- **Reports:**
  - CSV also inserts the `'` marker after a `,`, `;`, tab, `|` or line break
    inside a value when a formula could start there (OWASP CSV injection), so
    a report opened with another delimiter cannot create a formula cell.
    Leading no-break spaces and double quotes no longer hide a trigger.
    Consumers that strip only a leading `'` must strip these markers too, or
    read `json`.
  - Markdown writes `@` as `[@]` in untrusted text, like the existing
    `hxxp://` and `www[.]` defanging, so a pasted report no longer
    @-mentions users or teams or links e-mail addresses. Code spans stay
    verbatim.
- **Plugins and embedders:**
  - `shadowscan.utils.text.sanitize_record` is removed; call
    `shadowscan.utils.redaction.sanitize`.
  - `HttpClient.paginate_cursor` is removed; paginate explicitly. The Slack
    and Notion connectors keep their own cursor pagination.
  - The engine no longer names connectors. Per-root incremental caching, the
    instance-credential approval and the per-run gateway identity key are
    hooks a connector class declares (`cache_roots_separately`,
    `inherits_instance_credentials_approval`, `uses_run_identity_key`; see
    `docs/architecture.md`). Offline export parsing moved from
    `BaseConnector` to `shadowscan/connectors/offline.py` with
    `BaseConnector` names unchanged, and duplicate-finding metadata merging
    to `shadowscan.connectors.common.merge_duplicate_metadata`.
  - `shadowscan.utils.redaction` is split into `redaction_*` modules with the
    same public API and rule names. Patch rules through
    `shadowscan.utils.redaction`, never through a `redaction_*` module;
    `policy_token()` covers every module.
  - `SignatureIndex.signals_of_type(kind)` returns the (signature, signal)
    pairs of one signal type in pack order.

Development:

- ruff enforces line length (E501, 110 columns) outside `tests/` and
  loop-variable capture in closures (B023) everywhere. mypy requires
  annotated definitions (`disallow_untyped_defs`) and reports unused
  `type: ignore` comments (`warn_unused_ignores`). Only `regex`, `boto3`,
  `botocore` and `oci`, which ship neither stubs nor a `py.typed` marker, may
  be imported untyped.
- Unit tests live in files named after the module or feature they exercise,
  not the review round that added them; test bodies are unchanged.
- The evaluation, benchmark, canary and acceptance tools resolve the temporary
  directories they create before handing paths to the scanner, so they pass on
  macOS, where `/var` and `/tmp` are links into `/private`. The symbolic-link
  checks on untrusted input are unchanged.
- `docs/testing.md` describes the development environment, the offline suite
  and every `make` gate CI runs. `docs/maintainer-onboarding.md` is a reviewer
  and co-maintainer checklist, and `GOVERNANCE.md` has reviewer,
  co-maintainer and offboarding sections.
- `code.github` and `code.gitlab` share one implementation
  (`shadowscan/connectors/code/remote.py`), and the four cloud connectors
  share one offline-record dispatcher and audit-caller aggregator. New
  offline exports cover every GCP and OCI record kind, raising line coverage
  of `cloud/gcp.py` from 78% to 99% and of `cloud/oci.py` from 88% to 99%.
  The scanning commands share one option decorator; options, defaults and
  help are unchanged.
- Consistency tests check that documents describing CSV markers name every
  separator the reporter marks, and that the documented HTTP read deadline
  matches the client.
- Documentation: ADR-003 has a dated amendment recording the implemented
  confidence and risk formulas, and `docs/concepts/risk.md` matches the
  code. The cloud connector guide lists each connector's offline `_kind`
  values, and the architecture guide the engine hooks.

### September 28 repository hygiene

- The DCO check accepts Dependabot's app-authored commits with GitHub's fixed
  `support@github.com` sign-off, and only that pairing; every other commit
  still needs a sign-off matching its author or committer.
- CodeQL, Scorecard and the operator example workflow use `github/codeql-action`
  4.38.2 in every step, and Dependabot groups GitHub Actions updates so
  sub-actions of one repository move together instead of failing analysis with
  mixed versions.
- The development toolchain moves to ruff 0.16.9 with the regenerated hash
  lock and the matching pre-commit revision.

### September 27 review follow-up

- Opaque values nested under a sensitive credential container are now remembered
  before that container is redacted. Repeated values in sibling report fields
  and optional record exports are redacted too; descriptive provider and status
  fields remain available. Report and export regressions cover the boundary.
- GitHub and GitLab clones now check observed local checkout size during the
  clone and after Git exits, in addition to the provider size preflight. A
  measurement failure or exceeded cap stops the Git process group and leaves
  the scan incomplete with sampled API fallback. Sampling may overshoot and
  does not limit network bytes; use a worker disk quota for a hard ceiling.
- The evaluation runner supports explicit checks for expected and forbidden
  finding kinds, product signatures and model providers, with counts separated
  from the one-target binary accuracy result. Selected authored cases now
  guard against attribution noise; they do not establish field accuracy.
- Contributor and governance guidance now describes the configured pull-request
  approval and required-status rules, with dated observations of their changing
  enforcement state. The dated assurance report identifies its historical corpus
  count separately from the current corpus.

### September 27 review corrections

- Offline exports, approval inventories, imported reports, repository manifests,
  notebooks, agent/MCP configuration and other scanned JSON, JSONC and YAML
  reject duplicate or non-finite data. Rejected input makes collection
  incomplete instead of establishing absence; valid neighboring evidence is
  still retained.
- Structured projections reject conflicting schema aliases; CSV headers reject
  case-folded collisions; and conflicting provider records for the same logical
  Teams, Slack, Entra, Power Platform or Salesforce identity are quarantined
  without discarding valid neighbors. Azure pagination likewise refuses
  disagreeing continuation aliases.
- Generic graph and flow construction no longer establishes an agent by itself.
  Disabled, empty or schema-only tool options do not establish model-directed
  action execution. Source capabilities require corresponding evidence rather
  than inheriting every feature of an imported framework.
- CI exposes a single `CI gate` covering documentation, every supported Python
  version, the container checks, and DCO on pull requests. The repository ruleset
  must require that check; workflow code alone does not configure branch rules.
- Size-scaled source matching gives files near a 256 KiB budget boundary the
  next bounded time slice, avoiding scheduler-sensitive false incompleteness
  without weakening the fail-closed timeout behavior.
- The Python distribution is now `project-nexus-shadowscan` to distinguish it
  from the unrelated PyPI package. The `shadowscan` command, import namespace,
  entry-point group and report schemas retain their names. No package is
  published or namespace reserved by this change.
- Built-in connector options now use one fail-closed schema for YAML and
  programmatic configuration. Boolean aliases are normalized explicitly,
  ambiguous values and unknown/reserved built-in keys are rejected, later
  mutations and nested risk policy are revalidated before collection, and
  plugin-owned configuration stays schema-opaque while still rejecting cycles,
  excessive nesting and non-finite values.
  Configured inventory is reloaded on every run so the first execution cannot
  reuse an approval snapshot captured during engine construction.
- Shared JSON input rejects duplicate keys and non-finite values. JSON and
  SARIF publication refuses `NaN`/infinities. HTML/CSV sent to a terminal makes
  control and bidirectional-formatting characters visible, while explicit
  output files retain their serialized values. Reporter boundaries sanitize
  copied diagnostics, tolerate malformed related-finding metadata and preserve
  valid SARIF paths without treating provider resources as source locations.
- Incremental cache work now observes connector cancellation/deadlines, refuses
  `.git` indirection for Git-aware reuse, binds fingerprints to runtime/parser/
  Git versions, bounds tree traversal, and applies TTL, aggregate size/count,
  deterministic eviction and stale-pending/orphan-lock cleanup policies. Startup
  maintenance has a fixed two-second monotonic budget and disables reuse for the
  run when it expires. Lock acquisition verifies pathname identity after `flock`
  so cleanup cannot split one cache slot across stale and replacement lock inodes.
- Google Workspace domain-wide delegation strictly parses service-account JSON
  and pins both the signed assertion audience and token exchange to Google's
  HTTPS token endpoint; a key file cannot redirect the assertion.
- CI core/development tooling is now exact-versioned and SHA-256 hash-locked on
  Linux and macOS. All runtime, build, CI and documentation locks are audited.
  Pre-commit repositories use immutable commit SHAs and their additional type
  stubs are exact-pinned. Supported Python is explicitly 3.11 through 3.13.
- Release evidence now refuses a dirty checkout, builds from a clean archive,
  and assembles the exact attested wheel and bundles as a non-publishing
  `release-publication-input-<SHA>` artifact. The runtime SBOM remains a Python
  dependency SBOM, not a container/operating-system SBOM; no hermetic apt or
  package-index publication claim is made.
- Regenerate discovery baselines after adopting these classification and
  capability corrections. Fresh human-labeled holdouts, live tenant acceptance,
  independent release review and hosted artifact attestations remain separate
  release requirements; regression results do not supply that evidence.

### Self-graded audit follow-up

Fixes from an internal, AI-assisted grading pass over the repository; each
has a regression test.

- The registry's inventory scope-matching no longer hardcodes a single
  `google-workspace` string check to decide whether a card must list
  `accounts` before a resource pattern can approve a finding. The same
  requirement is now driven by
  `shadowscan.utils.identity.PROVIDERS_REQUIRING_CARD_ACCOUNT_SCOPE`, a single
  extensible set instead of a hand-patched exception repeated at three call
  sites (`Inventory.match`, `Inventory._scope_matches`, `card_stub_for`).
  Behavior for existing providers (AWS, Google Workspace, and every other
  built-in connector) is unchanged; adding the next provider that needs this
  protection is now a one-line addition to that set.
- `cloud.gcp` and `cloud.oci` test coverage now exercises the Cloud Function
  plaintext-secret handler, the Vertex endpoint and Discovery Engine
  handlers, the Cloud Audit Logs pagination edge cases (empty-token
  termination, repeated-token detection, invalid responses, transport
  failures), the instance-credential transport's redirect refusal and
  30-second timeout bound, and the three OCI GenAI resource handlers
  (dedicated endpoint, dedicated cluster, knowledge base) that had none.
  Both connectors were previously below the project's 75% per-connector
  coverage floor.
- `tests/test_repository_consistency.py`'s connector-count check now fails
  loudly (matching its signature-count sibling) if no doc states the count
  in bold, instead of silently matching zero times forever; README now
  states it (`**27 connectors**`).
- `docs/connectors/cloud.md` (the per-surface page reachable from the site
  nav) no longer omits the GCP pagination/audit-log page-cap sentence that
  `docs/connectors.md` documents; a regression test checks the two stay in
  sync on this point.
- `utils.output._require_private_pipe` now requires a named pipe's mode to
  be exactly `0600`, matching its own error message and the CHANGELOG's
  "Report output safety" description, instead of accepting any mode with no
  group/other bits (e.g. `0700`).
- `SetupError` now redacts its own message through the same sanitizer used
  for scan diagnostics, instead of relying on every call site to have
  hand-built a credential-free message; existing call sites that already do
  so are unaffected since sanitization is idempotent.

### Field-review follow-up

Fixes from the review of the field-review series; each has a regression test.

- A structured configuration the parsers refuse for nesting depth or XML
  entity expansion keeps the scan incomplete (exit 3) again. The series had
  reported it as a syntax warning outside coding-agent settings, so such a file
  hid its workflow evidence behind a complete scan.
- JSONC stripping is linear again: an unterminated string full of escaped
  quotes made it quadratic, so one small file could exhaust the scan deadline.
- The import-statement cache keeps only statements up to 256 characters,
  within 4 MiB of statement text, instead of any statement up to 65,536
  entries. Module names come from scanned code and the index lives for the
  process.
- GitHub Apps match their slug's words as well as the slug, so
  `amazon-q-developer`, `ellipsis-dev`, `mentatbot` and `factory-droid` are
  recognised again instead of dropping out of complete scans.
- `boto3.client(service_name="bedrock-agent-runtime")` and the AgentCore
  clients corroborate `invoke_agent` like the positional form.
- An MCP server keeps the capabilities its code implies when no tools were
  recognised, so a FastMCP shell tool registered with `@mcp.tool(description=...)`
  is `code-exec` again. Tools registered only in tests imply no capabilities.
- MCP enum tool names are found in one pass instead of one text search per enum.
- Documentation: the GitHub Apps rollout note lists the risk changes, the code
  and GitHub Apps connector options are documented, and the evaluation guide
  runs the field-review corpus.

### Report output safety

- A report path that already exists as a character device, such as
  `-o /dev/null`, is now written in place. Previously the report writer renamed
  a private temporary file over it, which, when run as root, replaced the
  system's `/dev/null` with a regular file. An existing named pipe is written
  in place only when the current user owns it with mode 0600 and a reader
  already has it open; otherwise the write fails at once instead of waiting.
  Sockets, directories, block devices and other non-regular paths are refused.
  Regular files are still replaced atomically with mode 0600, and symlinks are
  still refused. This covers `--output` for scans, the canary runner and the
  acceptance verifier, and the inventory stub and record-export manifest
  writers.

### Repository hygiene

- Every documentation page is reachable from the site navigation: the ADRs,
  the tenant canary guide and the 2026-09-24 assurance results were built but
  unlisted. A consistency test now fails on any page missing from the nav.
- Ruff enforces six more rules (`B007`, `B008`, `B034`, `C416`, `E741`,
  `SIM113`) after fixing their few violations: unused loop variables, a
  hand-maintained counter, a redundant comprehension and ambiguous `l` names.

### Type checking and lint coverage

- `mypy` runs with `warn_return_any` and `warn_unreachable`, and ruff's `B904`
  and `UP028` rules are enabled. The sites they reported are fixed at the
  source: untrusted API rows are typed as such so their guards are reachable,
  the AWS manual pagination path no longer runs inside an exception handler,
  and a GitLab variable shadow that hid a dead branch is renamed. The
  `pip install -e ".[dev]"` suite skips the two boto3-only tests without the
  AWS extra.

### Field review of public repositories (2026-09-25)

Behavior changes to review before upgrading (see
[production](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#field-review-changes)):

- **Finding identity:** a CrewAI `agents.yaml` or `langgraph.json` inside a
  reported project is folded into that project's finding (listed under
  `metadata.manifests`) instead of a second agent finding. `diff` reports the
  former manifest findings as resolved. A2A cards and M365 declarative agents
  stay separate findings.
- **GitHub Apps:** an installation needs an AI signature or an AI-like name,
  whatever its permissions, so read-only apps with an AI-like name are now
  reported as well. Apps with neither, such as Renovate or Dependabot, are no
  longer reported unless `include_unrecognized_apps: true`, which caps them at
  possible confidence. A separate word "bot" in the slug (`changeset-bot`)
  still counts as an AI-like name. Only `workflows` or `actions` write access
  implies `code-exec`, so an app with only `contents` or `pull_requests` write
  access loses it and can drop a risk level (critical to high for the Claude
  app).
- **Scan completeness:** a syntax error in a configuration file that is not
  coding-agent settings (`.claude`, `.codex`, `.gemini`) is a warning; lexical
  checks still read the file. `strict_coverage` keeps it incomplete.

Fewer false incomplete scans:

- Structured configuration accepts JSONC (VS Code settings, dev containers,
  tsconfig) through a shared, faster lenient loader (`shadowscan.utils.jsonc`).
- A Python module over the AST budget keeps its lexical evidence and is reported
  as partially analyzed: a warning in test code, an error elsewhere. New
  `max_ast_nodes` option (default 50000).
- Notebooks whose saved outputs exceed `max_file_size` have their code cells
  analyzed up to `max_notebook_size` (default 20 MiB) instead of being skipped.
  Their outputs are not scanned for credentials at that size, which leaves the
  scan incomplete unless `scan_secrets` is off.

Precision and recall:

- Code signals accept `ambiguous: true` for identifiers common outside the
  product. Such matches count only with an import, dependency or specific code
  pattern of the same signature in the project. Applied to `ClientSession(`
  (aiohttp), `AgentCard(`/`AgentSkill(`/`DefaultRequestHandler(` (A2A),
  `invoke_agent(`/`invoke_flow(` (Bedrock Agents), `create_agent(model=`,
  `AgentsClient(`, `OpenApiTool(` (Azure AI Foundry), `CopilotClient(`
  (Copilot Studio) and `Exa(`/`GoogleSearch(`/`WebSearch` (web search tools).
- The cap on uncorroborated lexical evidence in languages without the import
  binder applies to every signature category, not only frameworks.
- On a host shared with another product and not named for MCP
  (`api.githubcopilot.com`), the URL path decides: `/mcp` or `/sse` is MCP.
- Provider tool loops are recognized with raw-response, streaming and
  helper-function requests.
- MCP server capabilities come from the tool names the server registers
  (`metadata.mcp_tools`). Test-path evidence adds no capability unless the
  project is only tests, and vendor-neutral idioms add none to an MCP server.
- Findings with only supporting technology are titled `AI tooling`.
- New `tools/evaluation/field_review_corpus.json` (8 synthetic cases) in
  `make evaluate`.

Performance:

- Regex signal passes select candidate patterns with one scan over their
  required literals instead of a per-pattern check, synthesized import
  statements are matched once per index, and unresolved imports skip a code
  pass whose results were discarded. Findings are unchanged.

Development:

- `pip install -e ".[dev]"` runs the whole suite: boto3 tests skip without the
  AWS extra, and the dev extra includes setuptools and wheel.
- Internal AI-assisted review logs move from `docs/` to `archive/reviews/`.

### Coverage and release verification follow-up

- Mark unread oversized source and configuration files and outward or unresolved
  symlinks as incomplete even without `strict_coverage`; the flag elevates the
  diagnostic from a warning to an error. Declared generated-file omissions in
  `oversize_skip_globs` remain visible warnings.
- Treat in-root directory symlinks, and file links to excluded or otherwise
  unread targets, as incomplete instead of assuming alias content was scanned.
  Links whose own names are never read (lockfiles, generated bundles, images)
  and source aliases analyzed in the same project with the same test
  classification stay complete.
- Treat malformed or mismatched explicit GitHub/GitLab repository responses and empty GitHub/GitLab
  offline clone inputs as incomplete scans instead of complete empty results.
- Compute the signature-set digest once per incremental scan run instead of
  reserializing it for every input snapshot; changes between runs still invalidate
  the cache.
- Accept GitHub's actual workflow-run path in the release evidence gate and
  require successful exact-commit CI and CodeQL before building a candidate.

### Scanner boundaries and acceptance consistency

- Redact the value of any call whose first argument, or `key=`/`name=`
  argument, is a literal credential key (`os.getenv("API_KEY", "...")`,
  `settings.get("password", ...)`) before publishing source evidence. The
  bounded lexer reads `#` and `//` as text when a comment reading cannot close
  a call, so prose such as `(#123)`, Python floor division and JavaScript private
  fields pass through unchanged. A credential call whose value cannot be
  bounded withholds the excerpt and marks the scan incomplete.
- Keep repository-connector exception logging free of raw exception payloads.
- Bind Google Workspace observations and registry approvals to an immutable
  customer identity. Unresolved identities remain visible for investigation but
  cannot establish approval or complete collection. **Operator action:** grant
  the audit identity `admin.directory.customer.readonly` before live
  collection; `customer` must be `my_customer` or a concrete `C…` ID (a domain
  is rejected at startup); offline scans need the verified `customer` or stay
  incomplete. Unresolved findings keep stable IDs per input or admin account.
- Preserve unresolved Entra permission evidence. Grants or role assignments
  whose service principal is missing, and principals exported with conflicting
  records, become `unresolved-principal` findings that report no type,
  publisher or first-party status.
- Reject contradictory AWS account envelopes: several or invalid `account`
  records, or a resource ARN from another account, leave short identities
  unresolved and the scan incomplete. An offline `account_id` that disagrees
  with the export's account record no longer silently wins.
- Require usable identity for n8n workflow observations; blueprints without an
  ID, including YAML exports, keep their evidence under an unresolved identity.
- Remove the duplicate lexical agent-promotion path. Provider dispatch findings
  must pass source-semantic provenance checks and the configured test-code policy.
  Python single dispatch is recognized whether its result is kept, discarded or
  returned. JavaScript recognition stays deliberately narrow (a small, complete
  top-level program): JS/TS files that the lexical path promoted, such as a
  dispatch inside a function or code without semicolons, now report
  `framework-usage`. Review their findings before relying on agent counts.
- Share source-overlap validation between the holdout acceptance tools so repeated
  examples cannot inflate sample counts or statistical confidence.
- These changes require fresh finding baselines and acceptance evidence. Offline
  regressions do not establish independent human review or live tenant acceptance.

### Markdown report safety

- Defang bare HTTP(S) and `www.` URLs in untrusted report text so copied Markdown
  does not automatically turn attacker-controlled values into clickable links.

### Supported-platform preflight

- Every `shadowscan` command now fails closed, with a clear error, on a host
  that cannot enforce the documented path confinement (Windows, or a platform
  without `O_NOFOLLOW`); `--help` and `--version` still work everywhere.
  `shadowscan.utils.platform.require_supported_platform()` performs the same
  check for embedding callers. `redact` in `shadowscan.utils.text` stays as
  a documented compatibility alias. `sanitize_record` was removed later in
  this release; call `shadowscan.utils.redaction.sanitize`.

### Community policy consistency

- Add a documentation issue form, keep detection reports and private security
  reports on their existing routes, and document safe vulnerability report inputs.
- Hash-lock the documentation toolchain, align local hooks with CI tool versions,
  and scope CodeQL and stale-triage write permissions to their jobs.
- Validate workflow and issue-form safety policies. Label synchronization creates
  or updates declared labels without deleting labels; inactive issues and pull
  requests remain open for maintainer review.
- `tests/test_repository_consistency.py` (run by `make policy`) fails CI when a
  relative Markdown link or heading anchor is broken, a community file is
  missing, `CITATION.cff` disagrees with `pyproject.toml`, the CI matrix
  differs from the classifiers, the Makefile or pre-commit hooks drift from the
  CI gates, the docs toolchain is installed outside its lock, CodeQL steps are
  pinned to different releases, or a documented signature, signal or connector
  count is stale. The CI docs job now installs from `requirements-docs.lock`;
  the install guide states that CI validates Python 3.13; the detection quality
  report asks for the signature involved and a sanitization acknowledgement;
  README's community table links the detection form, maintainers, roadmap,
  changelog and citation.
- A verified repository hygiene audit fixed the drift it found. Pre-commit: the
  secret hook used `types: [python, yaml]`, an AND filter that selected no file,
  so it had never run; it now uses `types_or`, recognises current OpenAI and
  Anthropic key formats and excludes the tests that hold synthetic tokens;
  `check-yaml` skips `mkdocs.yml`, whitespace fixers skip fixtures and the
  digest-bound retained licences, and `detect-private-key` skips the redaction
  tests, so `pre-commit run --all-files` passes. The `pre-commit` dependency
  closure is pinned in `requirements-ci-constraints.txt`. Documentation: the
  production guide, constraints header and contributor guide state that Linux
  x86_64 is the only validated target, that Python 3.11 to 3.13 are all
  covered, that Windows is unsupported by design, and that the `main` ruleset's
  enforcement has changed during 2026-09 and must be checked live; the quick
  start no longer mixes a live code connector with credentialed tenant
  connectors in one configuration; the replay example uses the exported
  filename; the risk table, GitLab per-file cap (512,000 bytes), default
  `max_file_size`, evaluation corpora count and code connector modes match the
  code; two hardening logs no longer describe same-author passes as independent
  reviews and the two remaining 2026-09-24 review documents carry the internal
  work-log banner. Packaging: PEP 639 `license = "Apache-2.0"` with
  `license-files`, and the `Operating System :: POSIX :: Linux` classifier
  replaces `OS Independent`. Examples: the consumer workflow pins
  `upload-sarif` to a commit rather than a tag object and grants `actions:
  read` for private repositories. HTML report: sorting and evidence drill-down
  are real buttons reachable by keyboard with `aria-expanded`/`aria-sort`, the
  filters have accessible names, the result count is a live region, an `info`
  tile is shown, and pill and light-scheme colours meet WCAG AA contrast. The
  bug report form asks for the full commit SHA and describes exit codes
  accurately; the CSV reporter's formula-quoting is documented in README.

### Private holdout and CLI job deadline gates

- Reject bundled corpora and AI annotation ledgers from holdout acceptance;
  validate the human-review declaration used for the actual evaluation and read
  acceptance policies and annotations with bounded, symlink-free file access.
- Add optional `--job-deadline-seconds` / `options.job_deadline_seconds` for CLI
  scans. The cancellable process watchdog exits `3` when setup, scanning or output
  exceeds the deadline; external process supervision remains required.
- Start an explicit CLI deadline before reading JWTs from stdin, so an open,
  silent input pipe cannot hold the process past its configured deadline.

### Follow-up trust-boundary review (2026-09-24)

- Reject duplicate fields and nonfinite numbers in provider API JSON before
  interpreting collection, pagination or signing-key data.
- Mark offline Slack cursors and AWS truncation markers incomplete, retaining
  observed records while refusing a clean result for uncollected pages.
- Require intact, unambiguous code identities and recognized caller assurance
  before attaching runtime activity; clear stale derived observations.
- Sanitize imported findings before publishing report comparisons and require
  explicit, matching connector completion evidence before resolving findings.
- Render terminal control characters visibly in untrusted CLI display values.
- Bound evaluation corpus reads, reject the reserved aggregate family name,
  and bind annotation checks to the exact corpus snapshot being evaluated.

### Control-assurance fixes (2026-09-24)

- Redact long sensitive assignment keys before source evidence enters JSON or SARIF; bind Power Platform Dataverse token audiences and destinations to validated organization origins.
- Preserve valid neighboring provider records while marking provider errors, malformed Slack responses, missing collections and invalid pagination incomplete.
- Reduce generic-code false positives, recognize OpenAI Responses function dispatch, and fail closed on ambiguous source masking.
- Bound remote clone time, preflight provider repository size, avoid cloning when a usable size estimate is unavailable, terminate clone descendants on cancellation, remove partial checkouts and mark API fallbacks incomplete.
- Add a frozen holdout acceptance gate, tenant canary procedure, safer contributor guidance and a GitHub Action example. Field accuracy still needs independent review and live canaries.

### Scanner assurance and release evidence (2026-09-25)

- Preserve observed ServiceNow native agents if optional name or OAuth
  signature matching times out, mark coverage incomplete, and skip repeated
  matching for remaining records.
- Keep YAML manifest artifact matching within its existing one-second shared
  deadline during parallel scans, while allowing a chunk the manifest pattern
  budget; exhausted deadlines still make coverage incomplete.
- Recognize import-bound OpenAI Responses API function loops only when the
  model-selected call is dispatched and its result returns in the next request
  with matching call identity. Unreachable literal branches and locally
  shadowed execution names no longer establish provider tool loops.
- The offline acceptance verifier excludes previously evaluated source snapshots,
  validates the evaluator's known-gap report, and supports frozen per-kind
  sample and error limits. Its operator declarations still require independent
  human review and real tenant validation before rollout.
- The release candidate workflow binds a successful exact-commit main CI run
  to a wheel, hash-locked runtime and build dependencies, SBOM and retained
  provenance. The reviewed container base and consumer CI example are pinned;
  the workflow does not publish a package or authorize deployment.

### Detection precision, coverage policy and risk explainability

Behavior changes (review before upgrading an enforcement gate):

- Oversize files and symbolic links leaving the scan root are skipped with a
  warning instead of making the scan incomplete. `strict_coverage: true` /
  `--strict-coverage` restores the previous fail-closed behavior. Links that stay
  inside the scan root no longer affect coverage in either mode.
- Evidence found only in test or fixture code no longer establishes an agent
  (half weight, `test-code-only` tag); `include_tests` / `--include-tests` opts out.
- Project findings built only from evidence already reported by an MCP config,
  agent manifest, exported workflow, IaC or credential finding are no longer
  emitted as duplicates.
- Signature-level capabilities are narrower: LangGraph no longer implies memory,
  the OpenAI Agents SDK implies multi-agent only with hand-offs, and Bedrock
  AgentCore memory, code interpreter and browser come from their own resources.

Fixes and additions:

- The Python/JavaScript import binder counts only calls into modules that a
  signature describes. Ordinary large files (e.g. psf/requests' test suite) no
  longer fail with `source binding call limit exceeded`; diagnostics now include
  the scanner's own limit message.
- Provider SDK requests that pass tools (`tools=`, `toolConfig=`) record
  import-bound tool-use capability and provider attribution. The agent verdict
  still requires the model-selected dispatch and feedback loop, which is now
  recognized for Anthropic `messages.create` as well as OpenAI chat
  completions, including process or code execution sinks fed with the model's
  tool input, collected `tool_result` lists and dispatch inside `if` branches.
  Anthropic, OpenAI, Bedrock Converse and Gemini tool-call shapes are matched
  when written as dict keys or compared strings; loop checks accept `!=` as
  well as `==`.
- Shell, process and dynamic-code sinks count as code execution when the same
  file invokes a model, framework or tool-calling protocol.
- Model providers are attributed through LangChain, LlamaIndex and Vercel AI SDK
  integration packages and n8n model nodes (18 providers), and through model IDs
  declared in IaC. IaC projects with wildcard IAM statements are tagged
  `wildcard-permissions`.
- Placeholder credentials (repeated characters, marker words such as `EXAMPLE`,
  very low character diversity) are ignored; Azure OpenAI keys are recognized by
  their standard variable name. MCP inline-secret evidence names its location.
- Risk factors always add up to the score (explicit `confidence-scaling` and
  `bounds` factors). New `risk.danger_score` excludes governance factors;
  `options.risk_basis` (`combined` | `danger`) and validated `options.risk_weights`
  configure the model.
- Tests that need optional cloud SDKs or Git 2.45+ skip cleanly; the container
  base moves to Debian 13 (Git 2.47) and the build fails if Git is older than 2.45.

### Quality, precision and governance pass (2026-09-24)

#### Security

- Third-party connectors are verified when loaded: the class must be a concrete `BaseConnector` subclass whose `name` equals its entry-point name and is not a built-in name or namespace; violations fail closed with `PluginRegistryError`, and `plugin_registry_errors()` returns structured, credential-free diagnostics that the CLI now prints.
- The container build installs the build backend from the hash-locked `requirements-build.lock` with `--no-build-isolation`, pins the base image by digest (refreshed by a Dependabot `docker` entry), and admits only source, packaging and signature files into the build context.
- `Finding.from_dict` rejects malformed report shapes (non-object metadata, non-string list items, non-boolean `shadow`, evidence or risk factors without string identifiers) at the import boundary instead of failing later inside a scan.
- The two diverged copies of the `O_NOFOLLOW`/`dir_fd` offline-file open sequence are replaced by one confined helper in `shadowscan.utils.files`, with tests that both callers refuse symlinked components and special files and enforce their byte limits.

#### Detection

- Signature packs grow to 211 signatures and 912 signals (local inference, guardrails, Chinese-market providers, 2025 agent SDKs, more AI SaaS identity apps). The OpenAI secret regex is shape-specific and no longer claims Langfuse, LiteLLM or OpenRouter keys; dictionary-word display names match only with product context; two vendor misattributions are corrected; code idioms shared by competing frameworks move to heuristic signatures; the Azure OpenAI model pattern requires Azure context; `langchain-text-splitters` is a non-agent utility signature; and LangChain keeps prefix matching for every partner package through the new `exclude_names` / `exclude_prefixes` dependency fields.
- The signature validator enforces ecosystem, language and capability vocabularies, per-signal uniqueness, positive weights, non-empty-match patterns, balanced globs, id-namespace-to-category mapping and cross-signature duplicate regex detection. Custom packs that violate these rules now fail to load.
- Placeholder-looking provider keys (`REPLACE_ME`, `<your-key>`, repeated or sequential characters) become low-weight `example-credential` evidence instead of high-risk secret findings; the check is applied per matched key across filesystem, `.env`, MCP, cloud and blob scans.
- A repository whose only LLM signal is a credential no longer receives a derivative LLM-usage finding; vendor-neutral heuristics cannot create an `agent` finding without a framework, provider, platform, protocol or cloud-service match; projects observed only through environment-variable or display names are tagged `env-names-only`, weighted at half and capped at confidence 0.8.
- MCP filesystem and database servers carry a new `data-access` capability and browser servers carry `browsing`; gateway callers are titled `Agentic caller` only with a non-temporal indicator, and round-the-clock activity alone keeps the informational `always-on` tag.
- When a project's only technology anchors are environment-variable or display names, vendor-neutral heuristics contribute no evidence, indicators or capabilities; a dependency, import, code or file anchor restores their weight.
- Regression cases for each rule join `tools/evaluation/corpus.json`.
- `tools/evaluation/realistic_corpus.json` adds 31 multi-file cases written to resemble real repositories and naive-scanner false positives; the evaluator gains a `known_gap` flag and a `max_secret_findings` assertion, CI runs all three corpora, and docs/evaluation.md states what each corpus does and does not measure. Semantic Kernel C# projects now promote to agents, and a function defined as `create_agent()` no longer matches the LangChain call pattern.

#### Correctness

- SARIF output never emits a `physicalLocation.region` without `startLine` (line-less snippets move to the location's property bag), rule names are restricted to `[A-Za-z0-9_]`, invocation timestamps are ISO 8601 UTC or omitted, and null-valued keys are dropped; `render_sarif()` is validated against the vendored SARIF 2.1.0 JSON schema in the test suite.
- Risk scoring is total over malformed metadata: a non-numeric secret count or a non-object MCP server entry no longer aborts the scan, and the confidence-scaling factor never carries a positive weight.
- `shadowscan connectors` renders configuration keys with real styling instead of literal `[bold]` markup and prints plugin registry diagnostics; scans log the same diagnostics at WARNING.
- Setup failures print actionable, credential-free messages (`inventory path not found: …`, `signature directory not found: …`, a malformed pack named by file and document, an unknown connector key with a suggestion) through the new `shadowscan.errors.SetupError` contract; every other exception stays masked. Connector-level configuration keys now fail closed against each built-in connector's declared keys, YAML syntax errors report line and column without echoing source, and the deprecated `options.connector_timeout` alias logs a one-time deprecation warning.
- `shadowscan signatures test` reports an invalid pack as a click error and, in auto mode, also consults dependency signals across every ecosystem.

#### Performance and maintainability

- The filesystem scanner stops its walk cooperatively before the connector deadline, records one error naming examined and remaining files, and returns the findings collected so far; the engine keeps them and reports the scan incomplete instead of discarding everything.
- Domain, regex-signal and file-glob matching are prefiltered by required literals with engine-consistent case folding and batched deadline bookkeeping; equivalence tests assert identical results and the repository self-scan runs about twice as fast. The per-file budget scales with file size, files over `max_file_size` that match the new `oversize_skip_globs` key (lockfiles, minified bundles, source maps, images, fonts, archives, compiled artifacts) are skipped with a warning while other oversize files remain errors, and incremental fingerprints track oversize files by metadata instead of aborting.
- The gateway log normaliser is split into `shadowscan/connectors/gateway/normalise.py` with one small function per export format behind a registry; goldens generated from the previous code replay byte-for-byte under `tests/fixtures/gateway_golden/`.

- `Engine.run` is decomposed into named seams (`_prepare_run`, `_ConnectorRunner`, `_Supervisor`, `_ExportLedger`, `_postprocess`, `_write_manifest`) with identical ordering, thread-safety and deadline semantics.
- Signature packs are parsed once per `Engine` instead of twice, inventory is loaded once, and `Finding.sanitize()` skips objects unchanged since the last pass under the current redaction policy, so redaction runs once per finding instead of seven times while every call site keeps its defence in depth. Rendering 5,000 findings to JSON drops from about 18 s to under 2 s; sanitization semantics are unchanged.
- `Signal.compiled` is a lazy property; the scanner-source digest used by comparison and incremental caching is one shared helper; helpers with no callers are removed from the connector base, `utils.text`, `utils.safe_yaml` and the identity connectors.

#### Tests and tooling

- The suite collects on a core-only install (optional SDKs are imported with `importorskip`), deadline tests no longer depend on host speed, byte-identical duplicate tests are collapsed, and index-less `Engine()` constructions in tests reuse the session signature index.
- Every configuration key a connector reads is declared in its `config_keys`, shared offline-limit keys are surfaced through one `BaseConnector` list, `enabled` and `label` are documented, and a test parses each connector module so an undeclared key cannot reappear.

#### Governance and documentation

- `CONTRIBUTING.md` documents the actual single-maintainer, self-merge process with automated checks and requires independent human review before any tagged release; `docs/production.md` gives operators the commands to verify ruleset and review state themselves.
- The three 2026-09-24 review documents are relabelled as internal AI-assisted hardening logs under `docs/hardening-logs/`; the package classifier drops from Beta to Alpha; README gains a Project status section and corrected claims; SECURITY.md states that no versions are released yet.

### Production acceptance fixes (2026-09-25)

- Redact opaque credentials assigned through indexed Python/JavaScript targets
  before capturing source evidence, and escape terminal control characters in
  verbose reports.
- Bind Slack findings to immutable workspace IDs; preserve workspace names only
  as display metadata. Legacy offline exports need a team envelope or explicit
  `team_id`. Refresh Slack comparison baselines after this identity correction.
- Reject Teams records with missing or malformed resource identity, retaining
  valid neighboring observations while reporting incomplete coverage.
- Distinguish repository-local Python modules from third-party agent SDKs and
  recognize supported provider-driven tool loops through structural source
  evidence. Static construction still does not establish runtime execution.
- Add deployment evidence validation and a manually invoked release-evidence
  workflow. Neither tool creates human review, live tenant results, a published
  release, or a production acceptance claim from offline tests.

### Production review round 2 (2026-09-24)

- Stop treating every environment value of a cloud inventory record as a credential to remove from sibling fields: a benign setting such as `STAGE=prod` or `WORKERS=4` no longer redacts ARNs, account IDs and names out of SageMaker findings and `--dump-records` exports, which also restores stable finding IDs when an export is re-analysed offline. Environment values remain withheld in exports, and values under sensitive names or in recognizable credential formats are still removed everywhere. SageMaker findings now record environment variable names only, like Lambda findings.
- Snapshot Bedrock agent DRAFT details instead of storing the agent record inside itself; the previous self-reference collapsed to a redaction marker in record exports and marked every re-analysed agent incomplete. Older exports with the collapsed entry are read without a coverage warning.
- Identify potential grants from IAM `NotAction` allow statements against a representative AI-action list, recorded with a `notaction-partially-evaluated` limitation (the wildcard treatment first described here was superseded before it shipped), and treat `sagemaker:*` as an LLM invoke grant during live collection, matching the offline analysis.
- Report OCI custom (fine-tuned) models by `type: CUSTOM` / base model reference instead of a vendor test that excluded every real custom model.
- A `bedrock-logging` export record without a `loggingConfig` key, or carrying an error body, is unknown coverage rather than a "logging DISABLED" finding.
- Show the configuration policy reason when scan setup is rejected (for example the code-scan and live-credential separation rule) instead of a generic message; the rule's message now names `--allow-credential-mixing`.
- Sort Entra delegated scopes so `permissions` are reproducible across runs.
- JWT classification: `client_name`, `app_displayname` and `azp_name` count as agent hints only when their value matches an AI product or agent name signature (every Entra v1 delegated token carries `app_displayname`, so ordinary user tokens were reported as agents); a user-subject token with an RFC 8693 actor and agent claims is `delegated-agent`, never weaker than the same token without `act`; nested claim values are sanitized before truncation so no token prefix is persisted.
- Entra service-principal findings use the scanned tenant as `account` (the publisher tenant is kept as `metadata.owner_tenant`); Google Workspace accepts the Admin SDK `tokenList` envelope and URL-encodes user keys; Atlassian validates `products`; Make pagination isolates invalid pages.
- n8n, Make, Workato and Notion exports containing a provider error body are incomplete coverage instead of an empty inventory; one malformed record in Teams, n8n, Make, Zapier, Workato, Notion, generic SaaS or live Slack lists is skipped with a warning instead of aborting the connector.
- Gateway: response-side tool calls count when inspected requests carried no tool definitions (LiteLLM with body logging off), Bedrock Converse `toolUse`/`stopReason` are recognised, activity buckets use UTC, `llm_hosts_only` keeps requests to known LLM hosts on unlisted paths, Vertex and Portkey/Helicone detection use structural fields, a token in a user or principal field is sanitized before the label is shortened, LiteLLM rows without key material are `service` callers rather than pseudonymised credentials, `identity.arn` wins over the `identity` object, prose `message` wrappers keep the structured event, retained labels and samples are bounded, and a caller's first model/provider/host label survives an exhausted detail budget. Opaque credential labels skip display-name matching.
- Code connectors: cooperative cancellation now stops the tree walk instead of being recorded as one error per remaining file; credential detection runs first and in its own isolation, so a content pass that exceeds its regex budget, a structured file that exceeds the sanitizer budget (excerpts withheld) or notebook outputs and markdown cells no longer hide a real key; one unsafe tree path in API mode skips that file rather than the repository; agent definitions (50 per project) and retained agent manifests (200) are bounded with an incomplete-scan error; directory exclusion names no longer skip files of the same name; `Containerfile` is parsed like a Dockerfile; per-repository diagnostics share the 1000-entry cap; Git author fields use NUL separators with a validated timestamp; Ruby `=begin` blocks scan in linear time; a Python 3.12 tokenizer error mid-file marks the file ambiguous instead of silently masking the remainder; multi-line structured secrets keep excerpt line numbers aligned.
- Environment-style credential names in text (`AZURE_OPENAI_KEY`, `DATABRICKS_TOKEN`, `MODAL_TOKEN_SECRET`, `LITELLM_MASTER_KEY`, ...) have their assigned values redacted in source excerpts, evidence and URL queries (indexed targets such as `os.environ["DATABRICKS_TOKEN"]` included); record field names keep their narrower sensitivity so provider inventories are not over-redacted. A connector's other findings survive one finding that exceeds the sanitizer's output budget.
- Tests that assert successful Git history enrichment skip with a clear reason when the local Git lacks `--no-lazy-fetch` (2.45+) instead of failing; CI enables pip caching and mypy checks untyped function bodies.

### Detection and collection assurance (2026-09-24)

- Require corroborating AI evidence and bind constructors to imported frameworks; resolve common Python and JavaScript/TypeScript aliases. Generic loops and subprocess calls cannot establish confirmed agents.
- Validate agent manifests and operational configuration; descriptions and empty files cannot establish agent presence.
- Preserve unknown Lambda coverage, identify potential IAM NotAction grants with explicit analysis limits, validate Slack workspace scope and report missing n8n definitions as incomplete.
- Add a frozen negative-heavy public corpus with separate AI labeling passes, provenance and annotation checks in CI. This is not field accuracy.
- Add read-only AWS and Slack tenant canaries with explicit controls, scope and coverage assertions, permission-denied tests and private reports. Offline replay does not establish live acceptance.

Live tenant acceptance remains a deployment gate. Neither offline tests nor static findings prove a production tenant was scanned.

### Final reconciliation after PR #33 (2026-09-24)

- Fence incremental cache and record publication against timed-out connectors, and refuse to reuse an Engine while a prior abandoned worker still runs. A separate process deadline remains necessary for blocked SDK or plugin calls.
- Redact short configured credentials in diagnostics. Bound gateway caller/detail/interval state and repository-wide CODEOWNERS work, and avoid excessive work on Go source ranges.
- Keep untrusted SDK diagnostics out of application logs, redact opaque API/Foundry/GitHub token fields and the `GH_TOKEN` fallback, and restrict Kubernetes JWT classification to documented claim shapes.
- Preserve the newer webhook, HTTP header, imported finding, CSP, SARIF, GCP and Azure safeguards from the consolidated candidate.
- Fix the example code-scanning workflow for repositories without an inventory directory and for fork pull requests.
- Record immutable commit/tree identities on GitHub and GitLab code findings, and reject downloaded blob bytes that do not match the enumerated Git object ID.

Package version: 0.1.1. No release tag or published artifact is implied by this
entry. Tenant canaries and container runtime acceptance are still required.

### Security

- Withhold the credential-bearing path of webhook capability URLs (Slack, Discord, Teams, Zapier, Make, IFTTT, Telegram, n8n) in evidence, reports and record exports; `webhookUrl`/`webhookUri`/`webhookId`/`hookUrl`, `AccountKey`, `SharedAccessKey` and `sas_token` fields are sensitive.
- Apply the Keycloak service-account rule to Keycloak issuers only; a `preferred_username` starting with `service-account-` no longer relabels tokens from other issuers.
- Match the Kubernetes JWT claim namespace on the exact `kubernetes.io` prefix.
- Validate headers before requests can echo credential-bearing invalid values; redact additional provider formats and escaped credentials before source excerpts are shortened.
- Redact opaque Azure app settings and OCI Function configuration in record exports. Reject malformed numeric fields in imported findings and restrict HTML scripts to the shipped script's SHA-256 hash.
- Redact multiline YAML credentials before evidence excerpts, and pin GitLab API tree pagination to an immutable commit.
- Route GCP token refresh through bounded response and redirect policy.
- Classify JWT issuer families by parsed hostname labels rather than substring matches.

- Separate repository scanning from live tenant credentials by default; mixing requires explicit `allow_credential_mixing` approval.
- Cloud instance-metadata credentials require `allow_instance_credentials` opt-in; connector settings cannot silently override the global policy.
- Checkouts disable persisted GitHub credentials, and the Docker build context permits only source and packaging inputs.
- Core and cloud runtime dependencies are version- and hash-locked for the documented Linux/Python deployment targets.

### Reliability

- Render inventory, signature and connector text literally in CLI tables: Rich markup in an approval card no longer crashes `inventory check` or restyles the review screen.
- Retry GitHub 403 rate-limit responses (`X-RateLimit-Remaining: 0` or `Retry-After`) but not plain permission denials; all HTTP backoff is jittered and capped at 120 seconds.
- SARIF artifact URIs are percent-encoded, made root-relative only on path boundaries, absolute outside the scan root, and each rule reports its most severe result.
- Preserve valid cloud, identity and SaaS records after individual collection/analysis failures. GCP service-account key coverage now distinguishes unknown inventory from observed zero keys.
- Normalize scalar cloud scope options and reject unknown AWS service selections instead of reporting an empty successful scan.
- Bound diagnostic streams, gateway detail cardinality and numeric aggregates; isolate failures without losing later valid records.
- Deduplicate repeated source observations without dropping distinct custom signal capabilities. Preserve caller scan budgets and bound concurrent manifest matching by both CPU and wall time.
- Add a default 120-second connector deadline with incomplete-scan reporting. This is a soft thread deadline; host job timeouts remain necessary for blocked SDK/plugin calls.
- Protect incremental cache slots with nonblocking POSIX advisory locks. Contention or missing platform locking falls back to full scans without unsafe cache reuse or saves.
- Preserve the required CodeQL check name `analyze` and test hash-locked runtime installation in the Python 3.11/3.12 CI matrix.

### Operations

- Reuse bounded inventory patterns and per-analysis JWKS documents; index source newlines, avoid unnecessary JSONC parsing and reuse OCI clients within one collection session.
- Consolidate additional verified fixes from PR #31 on top of the PR #30 candidate; preserve PR #30's credential isolation, default deadlines and release gates.
- Explain how to select and verify the final reviewed full commit SHA; avoid an install example that silently falls behind later candidate fixes.
- Raise the development Ruff requirement to 0.16.8 and validate wheel installations against the runtime lock.
- Correct README commands, formatting and discovery claims; document the active required checks and independent-review merge gate.
- Document dependency lock maintenance, soft deadline limits, rollout evidence and remaining tenant/container acceptance.
- Clarify that finding confidence is heuristic, that static signals and resource existence need runtime corroboration, and that field precision/recall require a held-out local corpus before risk-gate enforcement.

## Earlier hardening notes — 2026-09-24

The following summarizes the reconciled pre-release implementation.

### Security


- Escaped, multiline and nested sensitive mapping values are redacted before source evidence is emitted; TLS verification rejects all falsy effective settings.
- Live AWS account attribution is checked through STS even with a configured expected account.
- Report imports reject ambiguous JSON, unsafe file paths and invalid security attributes before generating inventory stubs.
- GitHub/GitLab API downloads use enumerated immutable blob IDs; links, submodules and malformed Base64 produce incomplete coverage.
- Accountless short AWS IDs cannot approve a registry entry; their scans report incomplete coverage until an account is supplied.
- Filesystem scans reject symlinked root paths and report skipped in-scope symbolic links as incomplete coverage.
- Injected HTTP sessions cannot retain origin-specific adapters that bypass destination checks; default buffered responses have a decoded-byte limit.
- Scan configuration rejects missing required environment values, duplicate authored YAML keys, invalid gate settings, and unsupported top-level options.
- Finding identity no longer includes `kind`; promotion from framework-usage to agent preserves merge/diff/incremental identity.
- Shared HTTP client bounds JSON response bodies by default.
- Injected `requests.Session` objects still receive the destination-policy adapter.
- Missing `${ENV}` expansions for required secrets fail closed instead of becoming empty strings.
- Full Apache-2.0 LICENSE text and NOTICE.

### Reliability
- Identity/low-code pagination retains valid neighbors and partial observations, rejects provider failures, and recognizes documented Google empty-list envelopes.
- GCP Cloud Run lists concrete locations; unreachable regions are incomplete. Azure ARM pages preserve observations while incomplete diagnostic collections remain unknown.
- AWS and OCI SDK clients use finite transport/retry bounds; AWS Lambda and GCP project limits stop enumeration early.
- Relative inventory globs and work directories resolve beside their configuration file.
- A later Azure Resource Graph page failure retains already observed resources and reports incomplete coverage; GCP caller attribution is scoped by project.
- Concurrent connector completion order no longer determines merged finding ownership or metadata.
- CLI documents exit 3 (incomplete), exit 2 (`--fail-on` on a complete scan), and Click's separate usage-error path.

### Operations
- Repeated gateway headers reuse bounded per-scan classification summaries; regex contention retries retain their original CPU and input deadlines.
- Docker build context uses an explicit input allowlist, Actions checkout drops persisted credentials, and both CI matrix jobs finish independently.
- Incremental fingerprints ignore literal excluded source directories while retaining CODEOWNERS inputs; project-root attribution scales with active ancestors in wide monorepos.
- Disposable non-root worker image (`Dockerfile`).
- CI runs lint, audit, test, and package checks in each Python matrix job, with a concurrency group.
- Example GitHub Action and README use commit-pinned install examples and document incomplete-scan gating.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Finding IDs for promoted resources change with these commits. Rebuild comparison baselines and incremental state when upgrading from an earlier revision.
- Install from a reviewed tag/SHA. Do not follow `main`.

### Known limits
- Connector deadlines are cooperative; blocked SDK/plugin calls still need host process timeouts.
- SDK timeouts and retry limits do not establish a universal deadline for authentication chains or whole scans; workers still require a host deadline.
- Incremental cache writes are atomic and protected by per-slot advisory locks on POSIX. Unsupported platforms and contention use full scans.
