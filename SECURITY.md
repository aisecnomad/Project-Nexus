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
* Cloud SDKs and Git use separate transports. Network egress rules remain needed
  for those paths. URL preflight checks alone do not pin Git's later DNS lookup.
  Custom injected HTTP sessions/adapters are trusted extension/test mechanisms.
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
* Git clone/history calls suppress inherited Git configuration overrides and
  hooks. Clone credentials stay scoped to the approved HTTPS origin and redirects
  are disabled. Unsafe branch values are dropped with incomplete diagnostics.
  Repository contents are inspected, not intentionally executed. Keep Git itself
  patched and run scanners in disposable workers when scanning untrusted inputs.
* Reports and generated inventory stubs are written atomically with mode 0600.
  Dump directories must be private (0700); record files use 0600 and unique
  per-instance filenames. An export manifest records provenance/completion without
  raw connector configuration. JWT records are never exported. No `--dump-raw`
  option exists. Redaction handles recognized secrets and annotated source
  assignments, but arbitrary credentials and sensitive business data may remain.
* Generated inventory resource bindings escape literal glob characters. Manual
  wildcard approvals remain possible and require operator review. Surface,
  provider and account restrictions still apply; ambiguous matches do not approve.
* Incomplete scans exit 3 and set SARIF executionSuccessful=false. Only complete
  results qualify for incremental reuse. Comparisons infer resolution only for
  complete scans with matching collection and detection scope. Runtime telemetry
  attribution does not prove that a particular dependency executed.

See [deployment and migration](docs/production.md), [scan semantics](docs/scanning.md),
and [connector permissions](docs/connectors.md).

## Reporting

Use a private GitHub security advisory or contact the maintainer privately.
Do not include credentials, private exports or exploit details in public issues.
