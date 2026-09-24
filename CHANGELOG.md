# Changelog

## Unreleased — 2026-09-24, production review round 2

### Security
- Configured HTTP header values are validated before a request is built; a credential with a trailing newline no longer reaches a library error message. The Okta `SSWS` scheme and `repr()`-escaped known values are redacted like `Bearer` values.
- Secret excerpts are redacted before truncation, and the text sanitizer now recognises every credential format the secret signatures detect (Groq, xAI, NVIDIA, Perplexity, Replicate, Cerebras, Together, E2B, LangSmith, Pinecone, Tavily, Firecrawl, Dify, Langfuse, LiteLLM).
- Azure App Service settings and OCI Function configuration are exported under an env-style key so record dumps redact every value; the Salesforce `OauthToken` query no longer selects token values.
- Self-contained HTML reports declare a Content-Security-Policy that forbids network access, navigation and form submission.

### Reliability
- Opt-in `options.connector_timeout` / `--connector-timeout` abandons a connector that exceeds its deadline; the scan is reported incomplete instead of blocking the job.
- Azure: a failed per-resource detail call, transport error, Private Link or unrecognised Foundry endpoint is incomplete coverage for that resource instead of discarding the whole subscription inventory. Foundry projects inherit their account's subscription and location.
- List-typed connector settings (`regions`, `services`, `locations`, `projects`, `subscriptions`, `compartments`) accept a bare string as one value; `--set services=lambda` previously scanned nothing and reported completion. Unknown AWS services are rejected.
- Salesforce continuation failures and ServiceNow repeated or unbounded pages keep the records already collected and mark coverage incomplete. GitHub fine-grained PAT inventory is optional coverage.
- Gateway: linear access-log/logfmt parsing, finite-number hygiene (NaN/Infinity), fractional epoch timestamps, bounded per-caller distributions and observation buckets, and one diagnostic for a corrupt JSON export instead of one per line.
- Identity: Okta and Auth0 isolate malformed records; JWT analysis isolates hostile claims and fetches each JWKS once per run; Okta optional lookups no longer abort the inventory.
- Code: git author bytes that are not UTF-8 no longer abort a project; every emit phase is isolated; duplicate manifest/text observations count once; `scan_timeout` above 2 seconds is honoured; manifest regexes honour the per-file budget with a 1 s per-pattern ceiling; clone temp directories tolerate a symlinked temp root; CODEOWNERS budgets are per lookup and cheap for non-matching anchored rules.
- Report output no longer depends on the hash seed (set-ordered permissions).

### Performance
- Findings are sanitized once per state change instead of about seven times end to end; the signature index is loaded once per first run; signature patterns compile once; line numbers use a newline index; inventory name patterns and gateway user-agent matches are cached; plain JSON files skip the JSONC comment stripper.
- AWS clients use explicit connect/read timeouts with standard retries; OCI clients are cached per region with explicit timeouts; azure-identity token requests use short timeouts.

### Migration
- SSM parameter findings now use the real `...:parameter/<name>` ARN and GitLab group-scoped findings carry the plain group path; rebuild comparison baselines for those.
- Azure `appsettings` and OCI `function` record dumps now use an `environment` key; older dumps with `settings` / `config` still analyse.

## Unreleased — 2026-09-24

Production-hardening changes merged after 0.1.0. The package version is still
0.1.0; these changes have not been published as a 0.1.1 release.

### Security
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
- A later Azure Resource Graph page failure retains already observed resources and reports incomplete coverage; GCP caller attribution is scoped by project.
- Concurrent connector completion order no longer determines merged finding ownership or metadata.
- CLI documents exit 3 (incomplete), exit 2 (`--fail-on` on a complete scan), and Click's separate usage-error path.

### Operations
- Incremental fingerprints ignore literal excluded source directories while retaining CODEOWNERS inputs; project-root attribution scales with active ancestors in wide monorepos.
- Disposable non-root worker image (`Dockerfile`).
- CI runs lint, audit, test, and package checks in each Python matrix job, with a concurrency group.
- Example GitHub Action and README use commit-pinned install examples and document incomplete-scan gating.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Finding IDs for promoted resources change with these commits. Rebuild comparison baselines and incremental state when upgrading from an earlier revision.
- Install from a reviewed tag/SHA. Do not follow `main`.

### Known limits
- Without `options.connector_timeout`, a blocked cloud SDK call can keep a scan running until the host job timeout; with it, the abandoned thread still holds its SDK call until that call returns.
- AWS assume-role, GCP and Azure credentials are minted once per scan and are not refreshed; a scan longer than the token lifetime reports the later calls as incomplete coverage.
- Incremental cache writes are atomic and validated by fingerprint, but concurrent scanner processes do not acquire an exclusive state lock.
