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
  of decoded bytes, and each body must arrive within twice the client timeout
  (60 seconds by default). Oversized, slow and malformed collection responses
  fail collection, which marks the scan incomplete; a partial body is never
  analyzed.
  Explicit raw streaming callers are responsible for bounded reads and closure.
  Injected Requests sessions have their adapters replaced by destination policy.
  GitLab source-file downloads have a stricter 512 KB (512,000 bytes) per-file cap.
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
  An existing character device given as the output path (such as `/dev/null`)
  is written in place, and an existing named pipe only when the current user
  owns it with mode 0600; other non-regular paths are refused.
  Dump directories must be private (0700); record files use 0600 and unique
  per-instance filenames. An export manifest records provenance/completion without
  raw connector configuration. JWT records are never exported. No `--dump-raw`
  option exists.
* Report evidence is redacted before it is shortened. Redaction withholds
  recognized token formats (provider prefixes such as `sk-`, `ghp_`, `glpat-`,
  `glrt-`, `xoxb-`, `xapp-`, `AIza`, `ya29.`, `npm_`, `pypi-` and `dop_v1_`),
  JWTs, PEM private keys, URL userinfo and credential query or webhook path
  segments. A token or JWT is withheld behind a JSON-escaped line break or tab
  (`\n`, `\t`), a percent escape (`%3D`) or an underscore, and the prefixes no
  ordinary word contains (`sk-proj-`, `ghp_`, `AKIA`, `eyJ` and similar) also
  behind a digit; a word that merely ends in a prefix's text (`risk-`, `disk-`)
  stays. URL userinfo is withheld whole when the password holds a raw `/`, `?`
  or `#` (`postgres://u:Pass#word@host`). It also withholds values that their
  context names as credentials:
  assignments, including annotated, multiline and R (`<-`) expressions;
  mappings, YAML block scalars, properties and INI entries; `getenv`-style
  calls; name/value records such as Kubernetes `env` lists; XML elements and
  `key`/`value` attributes; Dockerfile `ENV NAME value`, `setx`, `setenv` and
  C `#define`; command-line options such as `--api-key`, `--token`,
  `--password`, `curl -u user:secret`, `-H "X-Api-Key:value"`, `-p` after
  `docker login` and other registry or cloud logins (`az`, `az acr`, `oc`,
  `cf`), `sshpass -p`, MySQL's `-pVALUE` and a literal echoed into
  `--password-stdin`; literal defaults of credentials read from the
  environment (`process.env.OPENAI_API_KEY || "..."`, `?? "..."`,
  `or "..."`, `?: "..."`, `${OPENAI_API_KEY:-...}`); and string literals,
  including Python f-strings without replacement fields and backtick
  strings, passed to credential constructors and helpers such as
  `AzureKeyCredential("...")`, Rust's `AzureKeyCredential::new("...")`, C#'s
  target-typed `AzureKeyCredential credential = new("...")`,
  `HTTPBasicAuth("user", "...")`, `Credentials.basic("user", "...")`,
  `auth=("user", "...")` and `setBearerToken("...")`, including methods down a
  builder chain (`builder().apiKey("...")`). XML key/name attributes, element
  names and name/value records are read as settings: a hierarchical .NET name
  counts by its last `:`, `__` or `.` segment as well as whole
  (`<add key="OpenAI:Secret" value="..."/>`, `- name: AzureOpenAI__Token`,
  `<entry key="openai.token">`). A key/name attribute names the element's
  value attributes, `<value>` child and content, and the element's own name
  decides its content as well (`<token key="openai.token" value="">...</token>`).
  A literal that looks like an opaque key is also withheld from a name whose
  last word, ignoring trailing digits, names a credential: in assignments
  (`openaiKey = "..."`, `key = "..."`, `KEY1=...`, YAML `openaiKey: ...`),
  settings (`<add key="AzureOpenAI:Key" value="..."/>`,
  `<OpenAIKey>...</OpenAIKey>`, `{name: OpenAIKey, value: ...}`), options
  (`--key ...`, also in an argv list) and `dotnet user-secrets set NAME
  VALUE`; ordinary values under such names (`<add key="CacheKey"
  value="users"/>`, `cacheKey: users-by-id`) stay. It is also withheld from a
  lone unindented line after a sensitive key such as `token:`. Variable
  references (`$VAR`, `${{ secrets.X }}`), environment variable names and
  placeholders stay visible. Structured name/value records that connectors
  pass to the sanitizer read their name as a setting too, in either field
  order (`{"name": "OpenAI:Secret", "value": "..."}`, and an opaque value under
  `OpenAIKey`); an environment-style name there (`PAGE_TOKEN`) withholds only
  an opaque value. The rules added for settings, options, numbered names and
  YAML values run after the earlier rules, on their output, so they only
  withhold more.
* Redaction cannot withhold a credential that nothing names or shapes as one,
  so treat reports as confidential. These forms can remain: an unprefixed
  literal passed to an ordinary function or nested in another call inside a
  credential constructor (`AzureKeyCredential(str("..."))`); a literal in a
  credential call written in a form the call rules do not read: after a space
  or comment before the parenthesis (`AzureKeyCredential ("...")`, since
  prose writes a space there), inside redundant parentheses
  (`AzureKeyCredential(("..."))`), as a C# interpolated string (`$"..."`) or
  as a triple-quoted string spanning lines; a credential query parameter
  outside a URL with a scheme (`?sig=...`); a word-like or short value under
  a name that is not itself sensitive (an unquoted value made only of
  capitalized words, digits and underscores reads as an identifier, so
  `KEY1=Gh4Hj9Kl8Zx2Qw` and `openaiKey: Zx9Kq2Lm8Np4` stay); a lowercase word
  after a space-separated option or as a fallback default; an option this
  list does not name, including a one-letter option (`-k ...`) and an option
  glued to the value before it (`--key=...--password "..."`); a positional
  argument of any other command; the part of an unquoted option value after a
  bracket, brace or comma; a literal fallback of a name that is not a
  credential's, even inside a credential constructor
  (`new AzureKeyCredential(Environment.GetEnvironmentVariable("K") ?? "...")`);
  URL userinfo that cannot be delimited: a password holding raw whitespace,
  quotes or angle brackets, one holding both a raw `@` and a raw `/`, `?` or
  `#`, a token without a colon that holds one of those
  (`https://tok?en@host`), or a numeric password followed by one
  (`https://user:12345?x@host`, which reads as a port); a token glued to a
  letter (`apisk-proj-...`) or, for a shorter prefix, a digit; a value named
  only by a comment (`x = "..."  # openai key`); a name/value
  record in text whose value field comes before its name
  (`{"value": "...", "name": "Password"}`, `- value: ...` above
  `name: DB_PASSWORD`); the part of a quoted record value after a `}` inside
  it under a name sensitive as a whole (`{"name": "Password", "value":
  "p}..."}`); a value split across concatenated strings; and sensitive
  business data.
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

Use a [private GitHub security advisory](https://github.com/aisecnomad/Project-Nexus/security/advisories/new).
Do not include credentials, private exports or exploit details in public issues.

### What to report privately

Report credential or private-data disclosure, redaction failures, unexpected
access outside the scan root or configured network origin, allowlist bypasses,
and malformed inputs that make incomplete coverage look complete. Reports about
CI or release-evidence integrity also belong in the private channel.

Ordinary false positives, missed integrations and incorrect attribution can use
the [detection report form](https://github.com/aisecnomad/Project-Nexus/issues/new?template=detection_report.yml)
when the reproduction is safe to publish. A trusted component being compromised
is outside the scanner's stated trust boundary; explain any demonstrated bypass
rather than assuming the scanner protects a compromised host.

### What to include

- The full scanner commit SHA, connector and collection mode. The unreleased
  package version alone does not identify the revision.
- A minimal synthetic reproduction or public repository and commit, with
  expected and observed behavior.
- The security impact, affected artifacts and who could access them.
- Any relevant sanitized diagnostics; do not attach real credentials, JWTs or
  live tenant exports.

### Response and disclosure

This volunteer project has one maintainer and cannot guarantee response times.
Use the advisory to coordinate reproduction, a fix and disclosure timing. Fixes
land on `main`; there is no released-version backport commitment. A confirmed
fix should include a regression test and any necessary rollout or migration
notes. Reporter credit and publication timing should be agreed in the advisory.
Only test repositories, accounts and tenants you are authorized to assess.
