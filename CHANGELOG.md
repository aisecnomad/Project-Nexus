# Changelog

## 0.1.1 — Unreleased

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
- Signature packs are parsed once per `Engine` instead of twice, inventory is loaded once, and `Finding.sanitize()` skips objects unchanged since the last pass under the current redaction policy, so redaction runs once per finding instead of seven times while every call site keeps its defence in depth.
- `Signal.compiled` is a lazy property; the scanner-source digest used by comparison and incremental caching is one shared helper; helpers with no callers are removed from the connector base, `utils.text`, `utils.safe_yaml` and the identity connectors.

#### Tests and tooling

- The suite collects on a core-only install (optional SDKs are imported with `importorskip`), git-dependent tests skip with a reason on hosts older than Git 2.45, deadline tests no longer depend on host speed, byte-identical duplicate tests are collapsed, and index-less `Engine()` constructions in tests reuse the session signature index.
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
- Evaluate IAM `NotAction` allow statements (everything not listed is granted) and treat `sagemaker:*` as an LLM invoke grant during live collection, matching the offline analysis.
- Report OCI custom (fine-tuned) models by `type: CUSTOM` / base model reference instead of a vendor test that excluded every real custom model.
- A `bedrock-logging` export record without a `loggingConfig` key, or carrying an error body, is unknown coverage rather than a "logging DISABLED" finding.
- Verify unchanged findings by digest instead of re-running the full credential sanitizer on every engine stage and reporter; rendering 5,000 findings to JSON drops from about 18 s to under 2 s, and sanitization semantics are unchanged (any later mutation is re-sanitized in full).
- Load signature packs once per CLI invocation instead of twice (a reused `Engine` still reloads packs between runs).
- Show the configuration policy reason when scan setup is rejected (for example the code-scan and live-credential separation rule) instead of a generic message; the rule's message now names `--allow-credential-mixing`.
- Render `shadowscan connectors` config keys with real styling instead of literal `[bold]`/`[dim]` markup.
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
