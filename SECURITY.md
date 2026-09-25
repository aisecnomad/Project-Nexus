# Security

ShadowScan handles audit credentials and security findings. Protect configuration,
environment variables, record dumps, incremental state and reports as sensitive
data. Redaction reduces accidental disclosure; it does not make reports public.

## Trust boundary

The operator workstation or CI runner, scanner configuration and installed Python
packages are trusted. Third-party connector execution requires an exact-name
allowlist in `options.plugins` or repeatable `--allow-plugin`. Listing connectors
does not import plugin code. The allowlist is not a sandbox: an approved plugin
runs with scanner privileges. Built-in connector names cannot be replaced.

Remote responses, scanned repositories and offline exports are untrusted inputs.
Review signature packs before installation. Built-in signature IDs are reserved
unless `options.allow_signature_override` / `--allow-signature-override` explicitly
permits replacement. Directory walks do not follow signature/inventory symlinks.

Use dedicated read-only audit credentials and narrowly scoped inventory approvals.

## Implemented controls and limits

* Shared `HttpClient` requests require HTTPS without embedded credentials.
  Redirects and pagination stay on the configured origin. By default, private,
  loopback, link-local, metadata and other non-global addresses are rejected.
  The HTTPS adapter checks the addresses at connection time and connects directly
  to the checked address, retaining hostname TLS verification. A trusted private
  API requires `options.allow_private_origin: true` or `--allow-private-origin`.
  This exception does not relax origin or TLS checks. HTTP proxies, including
  environment proxy settings, are unsupported by this transport.
* Default shared HTTP responses and JSON/pagination helpers are limited to 16 MiB
  of decoded bytes; oversized and malformed collection responses fail collection.
  Explicit raw streaming callers are responsible for bounded reads and closure.
  Injected Requests sessions have their adapters replaced by destination policy.
  GitLab source-file downloads have a stricter 512 KiB per-file cap.
* Configured header values are validated before any request is built; a value
  with control characters (typically a secret file's trailing newline) fails
  without being echoed. The Okta `SSWS` scheme is redacted like `Bearer` and
  `Basic`, and known configuration values are also redacted in their
  `repr()`-escaped spelling, which library errors use.
* Connector warning/error log events contain fixed summaries, never diagnostic
  payloads or exception arguments. Bounded, sanitized diagnostic details remain
  in the scan report; treat reports as sensitive operational artifacts because
  arbitrary upstream text can contain data beyond recognized secret formats.
  Opaque `api_token`, `foundry_token`, and `github_token` values, including the
  `GH_TOKEN` fallback, are sensitive.
* `options.connector_timeout_seconds` / `--connector-timeout-seconds` defaults
  to a 120-second cooperative completion deadline. Late connector results are
  discarded and coverage is incomplete. Legacy `connector_timeout` /
  `--connector-timeout` remain compatibility aliases; legacy YAML null uses the
  default. Python cannot forcibly interrupt blocked threads: calls may outlive
  `Engine.run()`. The CLI writes an incomplete report and exits without joining
  an abandoned worker once timeout handling returns. A filesystem replacement
  already in progress can finish after the timeout report; a cache or record
  file from a timed-out connector is unaccepted even if it exists. Record export
  manifests mark these entries `exported: false`. Embedded callers still need a
  process supervisor; worker concurrency remains bounded. Enforce an external
  process or job deadline when a hard runtime limit is needed.
* Azure App Service settings and OCI Function configuration are exported under
  `environment`, so record dumps redact every value; Salesforce token
  values are never requested.
* Cloud SDKs and Git use separate transports. Network egress rules remain needed
  for those paths. URL preflight checks alone do not pin Git's later DNS lookup.
  Custom non-Requests transport doubles remain trusted extension/test mechanisms.
* JWT classification remains unverified by default. Optional `jwks_url` signature
  verification uses the shared transport with a bounded JWKS body and key count.
  Only allowlisted asymmetric algorithms and unambiguous eligible public keys
  are accepted. Symmetric and private keys are rejected. `allowed_algorithms`
  can narrow the supported set; `expected_issuer` validates an operator-supplied
  exact issuer. An unverified issuer does not select a JWKS source. Expiry and
  audience are not authorization checks: historical tokens are valid analysis
  inputs. `metadata.verified` never grants permission to act.
* Offline exports use bounded reads without following symlinks, including
  intermediate path components. YAML construction bounds nodes, aliases, depth,
  merge expansion and expanded content before Python objects are constructed.
  Sanitization bounds expanded structure and total replacement work. Ownership
  patterns use bounded matching instead of backtracking regexes. Limit hits and
  malformed inputs make coverage incomplete while retaining valid neighboring
  findings. These are resource safeguards, not process isolation or a universal
  deadline across every external SDK call.
* Git history enrichment is disabled by default. Explicit `use_git: true`
  uses metadata-only commands with lazy fetching and every transport disabled;
  unsupported Git behavior or failed metadata reads makes coverage incomplete.
  Clone calls have a separate HTTPS-only policy: credentials stay scoped to the
  approved origin and redirects are disabled. Hooks and inherited Git overrides
  are suppressed. Unsafe branch values are dropped with incomplete diagnostics.
  Remote repository data cannot select an internal offline filesystem path.
  Keep Git patched and use disposable workers for untrusted inputs.
* Reports and generated inventory stubs are written atomically with mode 0600.
  Dump directories must be private (0700); record files use 0600 and unique
  per-instance filenames. An export manifest records provenance/completion without
  raw connector configuration. JWT records are never exported. No `--dump-raw`
  option exists. Redaction handles recognized secrets and sensitive Python
  assignments, including annotated and multiline expressions, but arbitrary
  credentials and sensitive business data may remain.
* Generated inventory resource bindings escape literal glob characters. Manual
  wildcard approvals remain possible and require operator review. Surface,
  provider and account restrictions still apply; ambiguous matches do not approve.
* Configuration rejects missing or empty required environment substitutions,
  duplicate YAML keys, unknown top-level/options fields and invalid gate levels.
  Explicit `${VAR:-default}` fallbacks remain an operator policy decision.
* Incomplete scans exit 3 and set SARIF executionSuccessful=false. Only complete
  results qualify for incremental reuse. Comparisons infer resolution only for
  complete scans with matching collection, detection and finding-identity schemas.
  Explicit unmatched connector selections and unsupported/error exports fail
  visibly. Incremental input roots and ancestor symlinks are ineligible for reuse;
  pre/post hashing is not an atomic filesystem snapshot. Keep inputs immutable
  while scanning. Runtime telemetry attribution does not prove that a particular
  dependency executed.

See [deployment and migration](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md),
[scan semantics](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/scanning.md),
and [connector permissions](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/connectors.md).

## Supported versions

No version has been released. There is no tag, published package or signed
artifact; the `0.1.1` version string in `pyproject.toml` names an unreleased
candidate. Only the current `main` branch receives fixes, and fixes land there
without a backport. Report issues against the full commit SHA of `main` or of
the pinned revision you deployed, not against a version number.

## Reporting

Use a private GitHub security advisory or contact the maintainer privately.
Do not include credentials, private exports or exploit details in public issues.
