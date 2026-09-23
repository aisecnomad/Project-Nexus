# Security

ShadowScan handles audit credentials and security findings. Protect configuration,
environment variables, record dumps, incremental state and reports as sensitive
data. Redaction reduces accidental disclosure; it does not make reports public.

## Trust boundary

The operator workstation or CI runner, scanner configuration, installed Python
packages and plugins are trusted. Review signature packs before installing them:
they control detection and contain regular expressions. Remote responses, scanned
repositories and offline exports are untrusted inputs.

Use dedicated read-only audit credentials and narrowly scoped inventory approvals.
Only install reviewed `shadowscan.connectors` plugins. Plugins execute Python with
the scanner's privileges; reserving built-in connector names is not a sandbox.

## Implemented controls and limits

* Shared `HttpClient` requests require HTTPS without embedded credentials.
  Redirects and pagination links stay on the configured origin. This is an
  origin check, not a network address filter: private and loopback destinations
  are not blocked. Configure only trusted endpoints and use network egress
  controls where necessary. Cloud SDKs and PyJWT have their own transports.
* JWT classification decodes without verification by default. Optional
  `jwks_url` verification uses PyJWT directly and checks a signature against the
  configured keys. It does not validate the expected issuer or audience, and
  expiry checking is disabled for analysis of historical tokens. The algorithm
  comes from the token header; there is no operator algorithm allowlist or
  issuer-to-JWKS binding. Treat `metadata.verified` as signature evidence only,
  never as an authorization decision. Configure a trusted JWKS endpoint.
* JSON/YAML/CSV exports and gateway/JWT files use bounded reads without following
  symlinks, including intermediate path components. Platforms without the secure
  file-open primitives fail collection explicitly. Malformed data marks a scan
  incomplete while valid neighboring records remain visible. Local repository
  traversal has separate file and symlink checks.
* Git clones use argument arrays, validate repository URLs against the approved
  host, scope credentials to that origin and disable HTTP redirects. Configured
  branch names are passed as argument values; there is no conservative branch
  alphabet validator. Repository contents are inspected, not executed.
* `--dump-records` writes sanitized connector records with private permissions;
  JWT records are excluded. No `--dump-raw` option exists. Reports and cache
  entries also redact recognized secrets. Unknown credential formats and
  sensitive business data can remain, so restrict access to all outputs.
* Built-in connector names cannot be replaced by plugin entry points. Additional
  plugin names remain supported and must be trusted as executable code.
* Regex matching and offline input processing have resource limits. These are
  safeguards, not process isolation or a universal whole-scan time limit.
* Incomplete scans exit 3 and mark SARIF execution unsuccessful. Only complete
  results are eligible for incremental reuse. Report comparisons infer resolution
  only for complete scans with matching collection and detection scope.

See [scan behavior and migration](docs/scanning.md) for limits, comparison
semantics and runtime attribution assumptions.

## Reporting

Use a private GitHub security advisory or contact the maintainer privately.
Do not include credentials, private exports or exploit details in public issues.
