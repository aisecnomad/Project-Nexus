# Deployment and migration

## Collection and aggregation follow-up (24 September 2026)

The follow-up review builds on the existing hardening described below. It does
not change the finding identity schema or declare a new release version.

- Shared HTTP responses default to a 16 MiB decoded-body limit, including raw
  non-streaming GET/POST, JSON and pagination calls. JSON callers may specify a
  smaller per-request `max_bytes`; trusted integrations may configure
  `HttpClient(max_response_bytes=...)`. Raw `stream=True` callers must bound reads
  themselves and close responses. Compressed bodies are checked after decoding.
  Errors, retries and redirects do not require buffering their response bodies.
- Collection envelopes must contain the expected array and valid continuation
  fields. An arbitrary HTTP 200 object no longer establishes an empty inventory.
  Google Directory may omit an empty repeated field only when its response
  identifies the expected collection kind and has no error or continuation.
- AWS preserves already collected pages after later request failures and marks
  coverage incomplete. AWS clients use 10-second connect and 30-second read
  timeouts with at most three attempts. OCI uses the same socket timeouts,
  at most three attempts and a 120-second retry budget. These settings are per
  request/retry operation, not a total connector deadline; retain worker job
  deadlines and resource limits.
- Malformed Azure Resource Graph responses are incomplete. GCP audit callers
  remain separated by resource project, including when the same principal
  accesses several projects.
- Parallel connector results are merged in configuration order, so network
  timing no longer chooses ownership or metadata precedence. Duplicate evidence
  cannot be appended repeatedly from a merged record. Gateway observation
  deduplication uses structural hashing while retaining distinct source records.
  Review configured connector precedence when sources disagree.
- Malformed, deeply nested cache JSON triggers a full scan. Cache files already
  use atomic replacement and fingerprint validation; concurrent writers can
  duplicate work or evict one another's cache hits without mixing their payloads.

Configuration migration: `${VAR}` now requires a nonempty value, including in
disabled connector declarations. Set required values or use `${VAR:-default}`
for a deliberate fallback; `${VAR:-}` explicitly permits an empty optional value.
Do not use empty fallbacks for required policy or credentials. Configuration
rejects unknown top-level/options fields, duplicate authored YAML keys, invalid
container types, invalid `fail_on` levels and nonpositive/nonintegral `parallel`.
YAML merge overrides remain supported. Error messages identify validation
problems without echoing configuration values. Review previously accepted
configuration before rollout; these errors now stop before collection.

## Earlier production review

This hardening change addresses all nine findings in the review of `main` at
`b13753df3199242c9e13cbfd04aefc18dd31a735`. It closes unsafe Git metadata execution,
Python credential redaction gaps and falsely complete export scans; corrects
Foundry and OCI collection; separates remote records from local paths; validates
every explicit scan selector; stabilizes finding identity; and preserves Google
Workspace user attribution. It retains the earlier bounded YAML, inventory,
output, HTTP, JWT and cloud hardening already merged on `main`.

Automated validation establishes implementation behavior. Production rollout
also requires the tenant canaries and operational checks below; a passing unit
suite does not establish complete coverage of a particular estate.

## Explicit security policy

```yaml
options:
  plugins: []
  allow_signature_override: false
  allow_private_origin: false
connectors:
  - name: identity.jwt
    input: ./tokens.json
    jwks_url: https://identity.example.com/keys
    expected_issuer: https://identity.example.com/
    allowed_algorithms: [RS256]
```

`plugins` contains exact connector names, not module paths or wildcard patterns.
Approved plugins still run trusted Python code. `shadowscan connectors` lists
installed plugin metadata without importing it. A plugin must be explicitly
allowed on each scan, even if a prior scan imported it.

Custom packs can add signatures by default. Replacing a built-in signature
requires explicit `allow_signature_override` approval. Enable private origins
only when the selected scan requires a trusted private HTTPS endpoint; keep
network-layer restrictions appropriate for that scan. Separate private-endpoint
scans from public collection when they need different trust policy.

All scan commands also expose `--allow-plugin`,
`--allow-signature-override/--deny-signature-override` and
`--allow-private-origin/--deny-private-origin`. Configured values are retained
unless explicitly overridden. Signature inspection commands expose the same
signature override opt-in. JWT CLI verification additionally accepts
`--expected-issuer` and repeatable `--jwt-algorithm`.

The shared HTTP transport enforces destination policy at connection time and
retains TLS hostname checks. HTTP proxies are unsupported; environment proxies
are ignored. Cloud SDK and Git transport behavior remains separate. Do not assume
that the shared client's policy controls every network connection in the process.

JWT verification is for analysis. The default scope is signature evidence;
configuring `expected_issuer` also binds the issuer. Neither mode authorizes a
request or substitutes for audience, expiry and application-policy validation in
an actual relying service.

## Git metadata policy

All code connectors default to `use_git: false`. Source inspection and
`CODEOWNERS` still work without invoking Git for history enrichment. For reviewed
local metadata, set the connector's `use_git: true` explicitly (a YAML boolean).
History enrichment requires Git 2.45 or later and a self-contained `.git`
directory; external gitfiles and symlinks are not accepted for enrichment.
Unsupported versions and failed metadata reads, including unavailable history
objects, make the scan incomplete while preserving code findings.

Metadata commands disable hooks, lazy fetching and every transport. Authenticated
cloning uses a separate HTTPS-only policy. Remote JSON fields such as
`_local_path` cannot select local scan roots or substitute for a verified offline
record. Use fresh disposable workers and immutable inputs; these controls do not
turn Git or the scanner into a process sandbox.

## Resource limits and incomplete scans

YAML parsing checks input size, composed nodes, alias count, nesting, expanded
nodes/content and merge work before object construction. Sanitization has a
separate expanded-structure and total-work budget, so valid YAML aliases cannot
cause unbounded report serialization. CODEOWNERS patterns use bounded iterative
matching with a per-root work budget.

A limit hit is a diagnostic and incomplete coverage, not proof of absence. Exit 3
must remain a failed gate in CI. Exit 2 means a complete scan exceeded the chosen
risk threshold. Hosted CI has a job timeout as an additional containment boundary;
there is no claim of a universal deadline for all vendor SDKs.

Saved provider errors and unsupported/malformed export records also make scans
incomplete. Valid neighbors remain available. Explicit empty inventories such
as `[]` remain valid; an authorization-error document is not an empty inventory.
Every `--only` value must match an enabled connector name or label, including
when another selector matches successfully.

Use disposable, resource-limited workers for untrusted repository scans. Keep
scanner state and output outside the repository under review. Avoid handing
production credentials to a job that executes repository-controlled build steps.

## Output and inventory migration

Reports and inventory stub files now use atomic 0600 writes. Inventory stub and
record-export directories are created as 0700; existing non-private directories
are rejected without changing their permissions. Use dedicated directories for
these outputs.

Dump filenames include the original connector configuration ordinal and a safe
label. Repeated names or normalization-colliding labels no longer overwrite each
other. Selecting a subset with `--only` retains the original ordinal. Use the
export manifest to locate each instance's file and completion status instead of
assuming a filename such as `cloud_aws.jsonl`. Exports remain sanitized and are
not lossless copies of upstream responses. JWTs are never included.

Generated resource patterns escape literal `*`, `?` and `[` characters. Review
previously generated cards for those characters and regenerate literal bindings
where necessary. Existing intentionally authored wildcard approvals remain valid.

## Finding identity and comparison migration

Finding IDs now separate stable source identity from inferred classification.
A service principal transitioning from delegated to application permissions
keeps its identity. Stable resource-type families separate different observation
types on the same resource; plugins can provide an explicit stable
`identity_discriminator` when needed. Never derive this discriminator from an
inferred kind, risk level or current permissions.

Reports declare `shadowscan.finding-identity/v2`. Rebuild comparison baselines
after this upgrade: legacy or mismatched schemas cannot establish resolution
and diff reports missing findings as unknown. Incremental cache format changes
force a full rescan; cached approval is never reused. Review any downstream
deduplication, SARIF alert history and ticket integrations that store old IDs.

Diffs now identify substantive changes in classification, permissions,
capabilities, technologies, risk score/factors, registration and ownership,
including changes within the same risk band. `changed_fields` identifies the
changed attributes. Timestamp and evidence ordering alone do not create changes.

Symlinked incremental roots or ancestor paths are ineligible for cache reuse.
Pre/post content hashes can detect ordinary concurrent edits but do not form an
atomic snapshot. Scan an immutable checkout/export to exclude changes that occur
and revert between those reads.

## Cloud collection changes

AWS resolves its account before emitting account metadata. ECS discovery follows
exact definition ARNs referenced by running tasks and service deployments,
including referenced inactive revisions, and retains the latest active registered
revision of each family as a separate evidence category. Stopped tasks and unused
historical revisions are outside this collection scope. A registered-only label
does not prove a definition is undeployed when discovery is incomplete.
The per-region `max_ecs_api_calls` limit defaults
to 2000; exceeding it or encountering denied/partial calls marks coverage
incomplete. Add the read permissions listed in [connectors.md](connectors.md).

GCP Owner/Editor-only principals remain visible as privileged access findings.
Neither broad role grants nor ECS deployment references establish that AI code
actually executed. Use trusted runtime telemetry for additional attribution.

Foundry collection uses the verified classic Agent Service `/assistants` route
with `api-version=v1` and validates its pagination envelope. Newer `/agents`
families are outside that contract. OCI Function collection now reads both
application and function details, merges inherited configuration with function
overrides, and treats denied detail access as incomplete. Ensure the audit
identity can read those details, not just enumerate summary records.

Google Workspace per-user token envelopes preserve the parent user in both
single-object and array forms. Regenerate earlier offline analyses affected by
lost user attribution before using their counts as governance evidence.

## Release verification

The CI workflow installs all cloud SDK extras and validates signatures, lint, typing, dependency advisories, tests
with a minimum 80% statement coverage, wheel creation, installed-wheel validation
outside the source checkout and offline SARIF output.
Focused regressions cover the review findings, private-address enforcement,
public-key verification, plugin policy, artifact permissions and replay integrity.
Dependabot checks Python and GitHub Actions dependencies weekly.

Automated and mocked provider-contract checks do not validate a tenant's actual
permissions, enabled services, data retention or export trust chain. Before an
operational rollout, run a read-only canary in each target tenant, inspect complete
coverage and account identity, verify expected known resources, and compare live
results with the retained export. These environment-specific checks require
access to those tenants and are not performed by offline CI.

## Rollout acceptance

Before broad deployment, retain evidence for each intended connector instance:

1. Run a read-only canary with the actual audit identity. Record the expected
   tenant/account, regions and collection scope, then verify known agents and
   at least one known permission/configuration signal appear.
2. Verify denied access, malformed exports and partially invalid selections
   cannot pass the gate. Require `summary.complete=true` and inspect all connector
   statistics for successful collection; do not infer coverage from finding
   count or an empty report alone.
3. Check sanitized artifacts with synthetic credentials and enforce private
   file/directory modes. Keep configuration, state and outputs outside scanned
   repositories and restrict access to retained reports.
4. Replay each exported instance using its manifest filename, checking account,
   resource identity and detection consistency. Sanitized exports are not
   lossless raw API backups; credential findings may differ after redaction.
5. Run a representative large scan in a resource-limited disposable worker.
   Set a job deadline, monitor incomplete/failed runs and provider throttling,
   and document how to restore access or rerun after a partial collection.
6. Pin the reviewed scanner commit and an approved dependency set for rollout.
   Establish a fresh comparison baseline, retain the prior pinned version for
   rollback, and keep rollback reports separate from the new identity schema.

These checks require operator-specific tenant access and operational decisions.
Until completed, describe deployment status as pending tenant acceptance.
