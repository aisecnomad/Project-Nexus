# Changelog

## 0.1.1 — Unreleased

### Production review round 2 (2026-09-24)

#### Security
- Configured HTTP header values are validated before a request is built; a credential with a trailing newline no longer reaches a library error message. The Okta `SSWS` scheme and `repr()`-escaped known values are redacted like `Bearer` values.
- Secret excerpts are redacted before truncation, and the text sanitizer now recognises every credential format the secret signatures detect (Groq, xAI, NVIDIA, Perplexity, Replicate, Cerebras, Together, E2B, LangSmith, Pinecone, Tavily, Firecrawl, Dify, Langfuse, LiteLLM).
- Azure App Service settings and OCI Function configuration are exported under an env-style key so record dumps redact every value.
- Self-contained HTML reports declare a Content-Security-Policy that forbids network access, navigation and form submission.

#### Reliability
- Azure: a failed per-resource detail call, transport error, Private Link or unrecognised Foundry endpoint is incomplete coverage for that resource instead of discarding the whole subscription inventory. Foundry projects inherit their account's subscription and location.
- List-typed connector settings (`regions`, `services`, `locations`, `projects`, `subscriptions`, `compartments`) accept a bare string as one value; `--set services=lambda` previously scanned nothing and reported completion. Unknown AWS services are rejected.
- GitHub fine-grained PAT inventory is optional coverage.
- Gateway: linear access-log/logfmt parsing, finite-number hygiene (NaN/Infinity), fractional epoch timestamps, bounded per-caller distributions and observation buckets, and one diagnostic for a corrupt JSON export instead of one per line.
- Identity: Okta and Auth0 isolate malformed records; JWT analysis isolates hostile claims and fetches each JWKS once per run; Okta optional lookups no longer abort the inventory.
- Code: git author bytes that are not UTF-8 no longer abort a project; every emit phase is isolated; duplicate manifest/text observations count once; `scan_timeout` above 2 seconds is honoured; manifest regexes honour the per-file budget; clone temp directories tolerate a symlinked temp root; CODEOWNERS budgets are per lookup and cheap for non-matching anchored rules.
- Report output no longer depends on the hash seed (set-ordered permissions).
- The CLI exits without joining a timed-out connector worker so a blocked SDK call cannot hold the job open after the report is written.

#### Performance
- Findings are sanitized once per state change instead of about seven times end to end; the signature index is loaded once per first run; signature patterns compile once; line numbers use a newline index; inventory name patterns are cached; plain JSON files skip the JSONC comment stripper; OCI clients are cached per region.

#### Migration
- SSM parameter findings now use the real `...:parameter/<name>` ARN and GitLab group-scoped findings carry the plain group path; rebuild comparison baselines for those.
- Azure `appsettings` and OCI `function` record dumps now use an `environment` key; older dumps with `settings` / `config` still analyse.


Package version: 0.1.1. No release tag or published artifact is implied by this
entry. Tenant canaries and container runtime acceptance are still required.

### Security

- Redact multiline YAML credentials before evidence excerpts, and pin GitLab API tree pagination to an immutable commit.
- Route GCP token refresh through bounded response and redirect policy.
- Classify JWT issuer families by parsed hostname labels rather than substring matches.

- Separate repository scanning from live tenant credentials by default; mixing requires explicit `allow_credential_mixing` approval.
- Cloud instance-metadata credentials require `allow_instance_credentials` opt-in; connector settings cannot silently override the global policy.
- Checkouts disable persisted GitHub credentials, and the Docker build context permits only source and packaging inputs.
- Core and cloud runtime dependencies are version- and hash-locked for the documented Linux/Python deployment targets.

### Reliability

- Add a default 120-second connector deadline with incomplete-scan reporting. This is a soft thread deadline; host job timeouts remain necessary for blocked SDK/plugin calls.
- Protect incremental cache slots with nonblocking POSIX advisory locks. Contention or missing platform locking falls back to full scans without unsafe cache reuse or saves.
- Preserve the required CodeQL check name `analyze` and test hash-locked runtime installation in the Python 3.11/3.12 CI matrix.

### Operations

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
