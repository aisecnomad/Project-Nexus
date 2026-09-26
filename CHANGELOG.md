# Changelog

## 0.1.1 — Unreleased

### Production readiness review fixes (2026-09-25)

Detection

- Add a `bound_only` code-signal flag: such patterns are ignored lexically and
  count only as calls bound to an import of the signature's library. The MCP
  `ClientSession(` constructor uses it, so `aiohttp.ClientSession(` is no longer
  MCP evidence while an import-bound `mcp.ClientSession(` still is.
- Fall back to lexical evidence, with a warning, when the scanner's interpreter
  cannot parse a source file (for example PEP 695 syntax on Python 3.11) instead
  of silently dropping its agent evidence.
- Recognize MCP configurations by structure: a nested `mcp.servers` block (VS
  Code settings, TOML `[mcp.servers.*]`) or a dedicated MCP file name. OpenAPI,
  Docker and proxy documents with a `servers` member are not tool servers.
- Emit coding-agent configuration findings only from configuration files,
  dependencies, imports, workflow actions, source code, editor or agent
  settings directories (`.vscode/`, `.cursor/`, `.github/` and similar) or
  variables declared in a Dockerfile, compose, workflow or `.env` file; vendor
  hostnames and variable names quoted inside data files (an egress allowlist, a vendor inventory, the
  scanner's own signature packs) no longer configure Cursor, Windsurf, Goose,
  Copilot, Claude Code or Cody.
- Gateway callers: a direct request to a provider API is LLM use, not an
  "agentic" caller. Traffic to an AI SaaS product (claude.ai, chatgpt.com,
  otter.ai) still names that product but no longer makes the caller an agent;
  where a provider signature also matches the host, only the provider is
  attributed. OAuth-app signatures no longer apply to user names, and
  `llm_hosts_only` keeps inference endpoints (`/v1/chat/completions`
  and similar) on any host but generic paths such as `/sse` only on known LLM
  hosts. One observed host counts once even when a
  signal lists it both exactly and as a wildcard.
- Low-code: a bare "agent" or "assistant" in a flow or record name is not an AI
  hint, while qualified names ("AI agent", "chatbot", "RAG", "autonomous
  agent") still are. A zap is an agent when it is a Zapier agent object or runs
  a Zapier Agents step, or when an AI-agent title comes with a real AI step; a
  title alone never invents an AI step. n8n manual, chat and form triggers are
  not autonomous.
- Product names that are also first names or common words need context:
  Olivia, Jamie, Piper, Devin, Kaia and Ema match only with their product
  qualifier (`Olivia by Paradox`, `Devin AI`), and Cursor, Warp, Zed, Drift,
  Gong, Clay, Apollo, Fathom, Codex, Sweep and similar words match an app
  named exactly that or a qualified form (`cursor.com`, `Fathom AI`). A person
  named Devin, a cursor-pagination Lambda, `Apollo GraphQL`, "qualified leads"
  or an "All Hands meeting" no longer names an AI product.
- Generic loop words (`while True:`, `for step in range(`, `scratchpad`,
  `supervisor`, `handoff`, `max_steps=`) add weak context only; they no
  longer mark a finding `autonomous` or count as agent indicators.
  Agent-specific idioms (`max_turns=`, `agent_loop`, `stop_reason ==
  "tool_use"`) still do.
- A GitHub App with pull-request write access is write access, not code
  execution; `contents` or `workflows` write still is.
- MCP server capabilities come from the server's own name and arguments,
  matched as whole words: the launcher (`docker run`, `npx`, `uvx`) and path
  arguments no longer count, so a Postgres server started with Docker is
  database access rather than code execution, and `executor` or `laws` in a
  package name no longer reads as `exec` or `aws`.
- Risk: capability and provider weights are capped, and findings that only
  establish framework or SDK use stay below the critical band reserved for
  agents and credentials. Every adjustment, including the 0-100 bound, is a
  listed factor, so a finding's factors always sum to its score; non-numeric
  connector counts score as zero instead of failing the assessment.

Robustness

- Large ordinary source files complete: the import binder accepts 400k AST
  nodes, shadow-checks and records calls only for imports a signature
  recognizes (at most 4,096 calls and 2 MiB of call text), and computes
  JavaScript line numbers from a newline index. Per-pattern regex caps and
  per-file and default matching budgets scale with input size (up to the
  validated 60-second maximum). Co-occurrence heuristics (`playwright ...
  agent`, `child_process ... tool`) look at most 500 characters ahead, so they
  stay linear on minified lines; one alternation of the domain expressions rules
  out dotted source tokens (`obj.prop`) before per-signature checks. A minified
  bundle with hundreds of credential-like keys on one line is sanitized in
  linear time. On a 319-file sample of real 100 KB-1 MiB JavaScript, TypeScript
  and Python files, no file now times out; files whose lexical structure cannot
  be resolved (some minified bundles, and Python 3.12 f-string syntax when the
  scanner runs on Python 3.11) are still reported as incomplete.
- `exclude` names apply without an accompanying glob; cooperative cancellation
  stops the file walk instead of being recorded once per file; a killed clone's
  partial checkout is removed before the API fallback; a worker that finished
  inside its deadline is never reported as timed out.
- One malformed or oversized record costs only itself in the cloud, low-code and
  automation connectors (`MatchTimeoutError` is isolated per record). Azure list
  failures are reported once. CloudTrail LookupEvents still marks runtime
  visibility incomplete by design; set `cloudtrail_days: 0` for an inventory
  scan that can complete.
- Gateway text logs: envoy's default access-log format is parsed. A logfmt key
  must start a whitespace-separated field, so `[timestamp] level=info ...` and
  other prefixed logfmt lines still parse, while a query string inside a
  request line (`GET /x?key=abc`) can no longer become a silently discarded
  record. A line starting with `[` that is neither envoy, JSON nor logfmt is
  reported.
- Salesforce metadata XML with DTD or entity declarations is rejected before
  parsing, as Maven POMs already were. `--incremental` together with record
  dumps logs why cached results are not reused.
- Built-in directory excludes (`build`, `dist`, `vendor`...) no longer skip
  regular files with those names, such as an extensionless `script/build`.
- Salesforce flows, bots, planners, templates and connected apps, and
  ServiceNow agents and use cases, isolate a failing record like the other
  low-code connectors. A manifest pattern timeout is a manifest diagnostic.
- HTTP requests and retry back-off honour the connector deadline: a timed-out
  worker issues no further requests, and the stop signal is not a
  `RuntimeError`, so per-endpoint error handlers cannot absorb it.
- OAuth token responses without an access token fail closed; the device
  authorization grant is not a machine-only grant; scalar `products` and
  `environments` settings are one item, not characters; Slack `first_seen` is
  the earliest enable event; hostnames of URLs with userinfo or IPv6 literals
  parse correctly.

Redaction

- Well-known credential names (`JWT_SECRET`, `SESSION_SECRET`, `VAULT_TOKEN`,
  `NPM_TOKEN`, `CI_JOB_TOKEN`, `SECRET_KEY_BASE`, `X-Amz-Security-Token`,
  `passphrase`) are always redacted. Generic names (`*_SECRET`, `*_TOKEN`,
  `*_PASS`, `*_PWD`, `auth`) are redacted when the value looks like a
  credential, so `auth: none`, `eos_token: "</s>"`, OCI's `auth: config`,
  `pwd = os.getcwd()` and integer counts stay readable and cannot erase a
  file's evidence context. `max_tokens`, `token_count` and similar
  descriptive names are unaffected.
- Command-line flags quoted in evidence text (`mysql --password ...`,
  `--mysql-pwd '...'`, `--db-pass ...`, `--api-key ...`) have their values
  redacted under the same rules as assignments; `--auth none`,
  `--password-stdin` and `--max-tokens 4096` stay readable.

Operations

- `--set` keeps identifiers with leading zeros (`tenant_id=0123`) as strings.
- Generated inventory stubs list readable names instead of Python reprs.
- The worker image is based on Debian trixie (Git 2.47) and fails the build on a
  Git older than 2.45; tests of history enrichment skip on older Git, and tests
  that configure live AWS or OCI SDK clients skip without the SDKs, so
  `pip install -e ".[dev]"` followed by `pytest` works on a stock Ubuntu 24.04
  host. CI installs the locked cloud SDKs and runs them all.
- 19 byte-identical duplicate tests were removed; regression tests are named
  by feature.

### Detection and collection assurance (2026-09-24)

- Require corroborating AI evidence and bound source constructors to imported
  frameworks; resolve common Python and JavaScript/TypeScript aliases. Repeated
  generic loops and subprocess calls cannot establish confirmed agents.
- Validate agent manifests and project operational configuration fields before
  matching signatures. Descriptions and empty configuration files cannot prove
  an agent exists.
- Preserve unknown Lambda environment coverage, recognize potential IAM
  `NotAction` grants with policy limitations, and validate Slack collection
  schemas and workspace scope. Preserve observed Slack records on later network
  failures and report missing n8n workflow definitions as incomplete.
- Add a frozen, negative-heavy public corpus with separate AI labeling passes,
  source provenance and annotation-integrity checks in CI. This does not establish
  independently measured production accuracy.
- Add read-only AWS and Slack tenant canaries with explicit known controls,
  scope and coverage assertions, permission-denied controls, and private reports.
  Offline replay and unavailable credentials cannot produce live acceptance.

Live tenant acceptance remains a deployment gate. Neither these changes nor an
offline test result constitute evidence that a production tenant was scanned.

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
