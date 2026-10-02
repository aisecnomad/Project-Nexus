# Deployment and migration

This is the rollout guide for the unreleased 0.1.1 candidate. It combines the
previous input, transport, identity and collection fixes with explicit credential
boundaries, connector deadlines, serialized incremental state and reproducible
runtime dependency installs. The package version is 0.1.1; a version string does
not establish that a tag, signed artifact or production acceptance exists.

Automated validation establishes implementation behavior. Production rollout
also requires the tenant canaries and container/operational checks below; a
passing unit suite does not establish complete coverage of a particular estate.

## September 27 migration and acceptance

The distribution metadata now names `project-nexus-shadowscan`. Install a wheel
from the reviewed revision into a fresh virtual environment; do not overlay it
on a previous `shadowscan` distribution, because both use the same Python import
and command paths. The CLI, Python imports, connector entry-point group and
report schemas retain the `shadowscan` name. This rename does not publish a
package or reserve the package-index namespace.

Offline exports, approval inventories, imported reports, dependency manifests,
notebooks and agent/MCP configuration with duplicate or non-finite data now fail
validation. Affected scans are incomplete while valid neighboring evidence is
retained. JSON readers and writers also reject `NaN`, infinities and exponent
overflow rather than accepting non-standard values. Obtain an unambiguous,
standards-compliant source and rerun collection; do not treat empty findings
from rejected input as evidence that an earlier finding resolved.
Conflicting schema aliases, case-folded CSV headers, pagination cursors and
multiple records for one provider identity also make coverage incomplete. The
scanner quarantines only the ambiguous identity where the format permits it and
continues to retain findings from unambiguous neighboring records.
Ordinary deterministic graph/flow construction and text generation without
enabled tool execution no longer establish agent behavior. Source capabilities
also stop inheriting unsupported features solely from framework membership.
Review changed kinds, capabilities and risk scores, then collect a fresh baseline
before using these reports in an enforcement decision.

Built-in connector options now apply the same schema to YAML-loaded and
programmatically constructed configurations. Connector option booleans accept
explicit case-insensitive true/false forms; the connector `enabled` field also
retains its documented aliases. Ambiguous values, unknown built-in keys and
reserved keys fail before collection. Plugin keys remain plugin-defined, while
cycles, excessive nesting and non-finite values still fail at the scanner
boundary. Mutable risk and deadline settings are revalidated before every run.
Configured inventory is reloaded for every run, including the first run after
engine construction, so an approval file changed between construction and
execution cannot supply a stale match.

When HTML or CSV is sent to stdout, terminal control and bidirectional-formatting
characters are rendered visibly; artifacts explicitly written with `-o` retain
their serialized data. Reporter boundaries sanitize copied diagnostics without
mutating in-memory scan state, ignore malformed related-finding metadata, preserve
valid SARIF source paths and reject non-finite JSON. Serialization failures stop
before stdout or an existing output file is changed; table output preflights
diagnostics before emitting its header. Continue to treat reports as sensitive:
these controls do not authorize publication of tenant or source data.

Incremental scans now bind cache fingerprints to Python/platform, parser/regex
and Git runtime versions. Git-aware reuse refuses `.git` indirection, and tree
hashing, Git metadata, cache reads and post-scan maintenance cooperate with
cancellation and connector deadlines. Startup maintenance has its own two-second
monotonic budget; exceeding it disables cache reuse for that run so collection
continues as a full scan. Enumeration is bounded by entries, depth, time and
bytes. Cache maintenance applies a 30-day TTL, 256-entry and 512 MiB aggregate
limits, deterministic oldest-access eviction and removal of stale pending and
orphan-lock files. Post-lock inode checks prevent cleanup from splitting a slot
across stale and replacement lock files. These are implementation defaults, not
evidence of field accuracy; rebuild the incremental state when changing rollout
baselines.

Google Workspace domain-wide delegation pins the signed assertion audience and
token exchange to `https://oauth2.googleapis.com/token`; a service-account
document's `token_uri` cannot redirect the credential exchange.

The `CI gate` job combines documentation, Linux Python 3.11–3.13 (including the
container checks in Python 3.13), macOS Python 3.11 and 3.13, and DCO for pull
requests. Core/development, runtime, build and documentation dependency sets are
hash-locked, and CI audits all four. Add `CI gate` to the live required checks
while retaining existing checks and independent approval. Verify the platform
setting before claiming it is enforced: a workflow cannot change a branch
ruleset by declaring a job.

The revised synthetic cases remain regression data. Freeze a fresh population,
human labels and acceptance policy using [the holdout procedure](evaluation.md#gate-a-frozen-holdout),
then run the [scope-specific evidence gate](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md).
For AWS or Slack deployments, retain complete and separately credentialed
permission-denied receipts from [approved tenant canaries](canaries.md).
Other connectors need their own acceptance evidence. The existing bundled
corpora, replays and mocked transports do not meet these live requirements.

After independent review, merge and successful exact-commit CI and CodeQL,
exercise the manual release-evidence workflow described below. Retain its
candidate, attestation and `release-publication-input-<SHA>` artifacts together.
The latter contains the exact attested wheel bytes and is an input to a possible
future OIDC trusted-publishing job; it does not publish anything or approve a
release. Evidence from an earlier main commit does not cover these source or
package changes, and local wheel checks do not establish GitHub-hosted provenance.

## September 25 migration and acceptance

Rebuild finding and comparison baselines after adopting the scanner-boundary
corrections. Google Workspace customer attribution, unresolved permission/workflow
identities, and semantic provider-dispatch classification can change finding IDs,
registry status or finding kinds. Review existing inventory bindings and retain the
previous pinned scanner and reports for rollback. Unresolved identity is evidence
for investigation, not a resource that can be approved through an inventory card.

For Google Workspace, add `admin.directory.customer.readonly` to the audit
identity's approved scopes before live collection. The read-only customer lookup
must establish a concrete customer ID, even for an empty tenant. Offline runs
require that verified ID in `customer`. Regenerate accountless Google Workspace
inventory cards with an explicit customer binding; an old globally scoped OAuth
client card no longer approves grants across tenants. Re-run tenant acceptance
after changing audit permissions. No live Google tenant validation is implied by
the mocked provider-contract tests.

Source excerpts now redact sensitive environment-call arguments, and repository
connector debug diagnostics omit raw exception payloads. Run the synthetic report
and log checks before distributing reports; redaction remains a defense in depth
control, not permission to publish private source or unrestricted tenant exports.
The sanitizer also propagates opaque secret values found in nested credential
objects or lists to sibling fields in the same finding or connector record export.
It leaves common credential descriptor labels intact so resource identity remains
useful; the containing credential field is still redacted. Recheck stored reports
and exports containing nested credential data before sharing or reusing them,
because earlier scanner versions could leave an identical value in an unrelated
description. Synthetic regressions exercise this path; no live tenant validation
is implied.

The two holdout acceptance paths share source-overlap checks. Copying or renaming
previously evaluated source does not create new independent observations; repeated
holdout sources cannot satisfy sample minima or tighten uncertainty estimates.
Freeze a fresh independently human-labeled sample and its policy before evaluation.
Neither these checks nor a passing regression suite supplies that human review or
real tenant canary evidence.

Slack findings now use the immutable workspace ID as `account`; workspace names
are display metadata. Update inventory account bindings and collect a fresh
Slack baseline after upgrading. An offline
export must include a valid team record or an explicit operator-supplied
`team_id`; conflicting workspace identities cannot establish attributed findings.
Teams records without valid app identity make collection incomplete while valid
neighboring observations remain available.

Code findings can change after this scanner update. A single OpenAI Responses
action requires an import-bound request and source-linked model-selected dispatch;
it supplies tool-use evidence without asserting repeated autonomous execution.
An iterative function loop additionally requires matching feedback to the next
request. Provider analysis rejects unrelated dispatch, unreachable literal branches
and locally shadowed execution calls. Reconcile a fresh code
baseline and review changed finding identities before using `--fail-on` as an
enforcement gate. Offline source tests establish these paths, not runtime use.

Use the [offline acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md) to check the
required evidence for the intended deployment scope. It checks artifact identity,
freshness and declared review/metric requirements. It does not authenticate
reviewers, prove that a supplied receipt came from a real tenant, or turn synthetic
tests into operational evidence. Keep receipts and human attestations in controlled
audit storage and review their origin. Unsupported live connectors still require
their own acceptance work; they cannot inherit an AWS or Slack result.

The manually invoked [release-evidence workflow](https://github.com/aisecnomad/Project-Nexus/blob/main/.github/workflows/release.yml)
requires successful main-branch CI and CodeQL runs for the exact selected commit.
It rejects modified, untracked and ignored checkout files, builds from a clean
`git archive`, checks the wheel, retains a runtime dependency SBOM and hashes,
and produces GitHub artifact provenance. It then assembles the candidate and
attestation bundles without rebuilding the wheel. It does not publish to PyPI,
create a release, or declare tenant acceptance. Review and retain its artifacts
before a separate maintainer publication decision.

After merge and successful push CI, dispatch **Release candidate evidence** on
`main` with `expected_commit` set to the full current main SHA, `ci_run_id`
set to that commit's successful CI run ID, and `codeql_run_id` set to its
successful CodeQL run ID. The workflow rejects stale commits, PR-only runs,
failed checks and other workflows. Retain `release-candidate-<SHA>`,
`release-attestations-<SHA>` and `release-publication-input-<SHA>` together;
hosted retention is 90 days. Verify the candidate's `SHA256SUMS` and GitHub
attestations before publication. A future publisher must use the wheel in that
publication-input artifact, not rebuild from a tag. Configure an environment-
protected PyPI trusted publisher and grant `id-token: write` only in that future,
isolated publication job. The current workflow deliberately has no package-index
permission or upload action.

The runtime SBOM covers locked Python core/cloud dependencies. It is not a
container or operating-system SBOM and does not cover the base image, Git,
CA certificates or other Debian packages. Generate and review a container/OS
SBOM for the exact deployed image digest as a separate release control.

## Install from a reviewed revision

Check out an audited full commit SHA before installation. README and example
workflow instructions require a full reviewed commit; a fixed example SHA would
fall behind new fixes. Record the exact revision with deployment evidence and
verify the checkout matches it before building. Do not use a floating branch or
a tag that has not been published.

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
git clone https://github.com/aisecnomad/Project-Nexus.git
cd Project-Nexus
git checkout --detach "$SHADOWSCAN_REVISION"
test "$(git rev-parse HEAD)" = "$SHADOWSCAN_REVISION"
```

The install commands below use the files in this checked out tree. Check that
`git status --porcelain` is empty and retain the commit SHA, CI links, dependency
lock and built wheel hash for each worker deployment.

The runtime lock covers the core scanner and all cloud SDK extras on CPython
3.11, 3.12 and 3.13, Linux x86_64. It contains exact versions and permitted
SHA-256 hashes; Linux CI checks installation and dependency consistency on all
three interpreters. Linux x86_64 is the only validated deployment target for
this full runtime/cloud lock. The macOS 3.11 and 3.13 CI jobs install
`requirements-ci.lock` and this runtime lock from the same published wheel
hashes and run the full test suite with the per-connector coverage floor, which
validates development use there; a macOS deployment still needs its own wheel,
container and acceptance evidence. Windows is not
supported at all, because the confined file reader
(`O_NOFOLLOW`, `O_DIRECTORY`, `dir_fd`) is unavailable there and the scanner
refuses to read any input rather than weaken that policy. The lock is not
universal for ARM or every future Python release either. Resolve and validate a
separate lock before deploying on another platform.

From the reviewed checkout, in a clean virtual environment:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python -m pip install --no-deps dist/project_nexus_shadowscan-0.1.1-*.whl
python -m pip check
python -m shadowscan.signatures.validate
shadowscan --help
```

The runtime lock deliberately includes all cloud extras, even for a code-only
worker. Development tools are not part of it; CI and `make install-dev` use
`requirements-ci.lock`, which hash-locks the core and development environment.
`requirements-ci-constraints.txt` is a reviewed version input for regenerating
that lock and is never installed by CI. The build backend is locked separately:
`requirements-build.lock` carries the exact `[build-system]` requirements from
`pyproject.toml` (setuptools and wheel) with the SHA-256 hash of every artifact
PyPI publishes for those releases. Install it under `--require-hashes` and build
with `--no-build-isolation`, as above; an isolated build would let pip resolve
the backend from the live index on a version pin alone. CI fails when the two
files disagree, so refresh them together. Build the
wheel in a controlled builder, retain its SHA-256, and install that reviewed
artifact into workers. Capture the builder image digest, Python/pip/build-backend
versions and wheel hash: matching runtime dependencies alone does not ensure
identical wheel bytes. Dependency hashes
prevent silent runtime artifact substitution; they do not establish that a
dependency is safe.

Regenerate intentionally in a clean Linux environment with Python 3.12 and
`pip-tools==7.5.3`, review the dependency diff and advisory results, and let every
CI matrix job verify the result:

```bash
pip-compile --extra cloud --generate-hashes --strip-extras \
  --no-emit-index-url --no-emit-trusted-host --no-annotate \
  --output-file requirements.lock pyproject.toml

uv pip compile pyproject.toml --extra dev --universal --generate-hashes \
  --no-emit-index-url --no-annotate --no-header \
  --constraint requirements-ci-constraints.txt \
  --constraint requirements.lock --constraint requirements-build.lock \
  --output-file requirements-ci.lock
```

The current CI lock records the reviewed `uv` version in its header. Use a
different resolver version only as an intentional toolchain change. Use
`--upgrade` only for an intentional dependency refresh. Preserve each lock's
supported-platform comment when regenerating. Do not bypass failed hash checks.

The Dockerfile installs the runtime and build locks under `--require-hashes`,
builds the package with `--no-build-isolation`, and runs as UID/GID 65532. Its
literal `FROM` pins the multi-arch `python:3.12-slim-trixie` image index. The
image build checks that Git is 2.45 or newer for history enrichment.
Review that exact digest and any Dependabot refresh before deployment:

```bash
docker build --tag shadowscan:reviewed .
```

Retain the reviewed base and built image digests. The build context is an
allowlist (`.dockerignore`) of package sources, signature data, packaging
inputs and the runtime/build locks. Distribution packages from `apt-get` and image
metadata remain mutable, so the Dockerfile does not promise byte-for-byte
reproducible images. There is no claim of a hermetic apt snapshot. CI
smoke-tests a non-root, read-only and network-isolated image; build and test the
deployment image, generate its container/OS SBOM, and validate resource limits
and output-directory permissions before rollout.

The [Kubernetes offline Job example](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/k8s-job.yaml) has a 20-minute
active deadline, a placeholder for a reviewed image digest, and a matching
NetworkPolicy that denies egress when enforced by the cluster CNI. Supply a
reviewed `/input` volume before running it. For live API collection, use a
separate Job and enforce a network path through an approved egress proxy; a
standard Kubernetes NetworkPolicy cannot filter destinations by DNS name.

Opt-in Git history enrichment requires Git 2.45+;
verify the distribution Git version if that feature is needed. Keep runtime
secrets out of the build context.

For record replay, read `exports/manifest.json` and use the `filename` for the
intended connector instance; export names are not a fixed `cloud_aws.jsonl`.

## Explicit security policy

```yaml
options:
  plugins: []
  allow_signature_override: false
  allow_private_origin: false
  allow_credential_mixing: false
  allow_instance_credentials: false
  connector_timeout_seconds: 120
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

Keep scans of repository content separate from jobs holding live cloud, identity,
SaaS or low-code credentials. By default, configuration rejects a selected code
connector alongside a selected live credentialed collector. A single remote code
connector can use its repository token; code plus offline exports is allowed.
`allow_credential_mixing: true` permits a reviewed exception, but does not isolate
the repository from credentials available in the worker. Use separate disposable
workers for untrusted repositories.

`allow_instance_credentials: false` disables implicit cloud instance-metadata
credential acquisition. Enabling it is a global opt-in; a connector-level value
cannot silently override that policy. The engine replaces the key in any
connector entry with the scan-wide value, and passes that value to every
`cloud.*` connector, plugins included, and to any plugin that declares the
cloud surface or documents the key in its `config_keys`. Before this release
only `cloud.*` entries were replaced, so review plugin entries that set their
own `allow_instance_credentials: true`: it no longer takes effect. Use
explicit audit credentials or approved workload credentials and inspect
account/tenant attribution before rollout.
These settings are credential-use policy, not a process or network sandbox.

Custom packs can add signatures by default. Replacing a built-in signature
requires explicit `allow_signature_override` approval. Enable private origins
only when the selected scan requires a trusted private HTTPS endpoint; keep
network-layer restrictions appropriate for that scan. Separate private-endpoint
scans from public collection when they need different trust policy.
Configuration rejects duplicate authored YAML keys and unknown top-level or
`options` fields. `${VAR}` must resolve to a nonempty value; use
`${VAR:-fallback}` only where an explicit fallback is appropriate. Invalid
`fail_on` thresholds or `parallel` values stop the scan before collection.
Environment references are validated in disabled connector declarations too;
remove unused placeholders or give intentionally optional values a fallback.
Relative inventory globs and `options.workdir`, like other configured paths,
resolve beside the configuration file, independent of the process directory.

The new policies also expose `--connector-timeout-seconds`,
`--allow-credential-mixing/--deny-credential-mixing` and
`--allow-instance-credentials/--deny-instance-credentials`.
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
Inject only trusted `requests.Session` implementations. Calls to the shared
client that explicitly request `stream=True` must read within a size limit and
close the response; the default buffered response path enforces a 16 MiB limit
and a whole-body [read deadline](#resource-limits-and-incomplete-scans).

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

Shared HTTP JSON responses are streamed and limited to 16 MiB of decoded
content by default. Each response body must also arrive within twice the
client timeout (60 seconds by default). The 30-second client timeout bounds
each connection attempt and each socket read, so without the deadline a server
that sends a byte just inside every timeout could hold a worker until the
connector deadline abandoned it. A body still being read at the deadline is
aborted (`HTTP response exceeds the read deadline`) and the connector's
collection is incomplete (exit 3); a partial body is never analyzed. The
deadline follows the client's timeout, not a `timeout` passed with one
request, and applies to each response separately:
`connector_timeout_seconds` still bounds a connector's whole collection.
Pagination rejects missing or malformed collection arrays and records an
incomplete scan when a response exceeds its limit. Review unusually large
provider pages against their API contract before raising a per-client or
per-request limit. GitLab file downloads remain capped at 512 KB (512,000
bytes) per file.

YAML parsing checks input size, composed nodes, alias count, nesting, expanded
nodes/content and merge work before object construction. Sanitization has a
separate expanded-structure and total-work budget, so valid YAML aliases cannot
cause unbounded report serialization. CODEOWNERS patterns use bounded iterative
matching with a per-lookup work budget.

YAML manifest artifact matching uses a shared one-second deadline and gives
each bounded line chunk no more than the remaining manifest pattern budget.
Concurrent collection can take over the signature matcher’s separate 100 ms
ceiling while still remaining inside that manifest deadline and any active
per-input scan deadline. Exhausting either deadline marks the code scan
incomplete (exit 3).

A limit hit is a diagnostic and incomplete coverage, not proof of absence. Exit 3
must remain a failed gate in CI. Exit 2 means a complete scan exceeded the chosen
risk threshold. `connector_timeout_seconds` defaults to 120 seconds and must be a strictly positive
finite number. It starts when the connector worker begins, and split filesystem
roots share that connector's deadline. The engine stops accepting a connector's
results after the deadline and records incomplete coverage. Python
worker threads cannot safely be killed: a blocked SDK call can continue after
that soft deadline. The CLI normally exits after emitting an incomplete report,
but a filesystem replacement already in progress can finish after the timeout
report. Such cache or record artifacts are unaccepted even if present; timed-out
record exports are `exported: false` in the manifest. Use a fresh state and
export directory after a timeout to avoid reusing a late cache or orphan export.
Embedded callers must supervise their process and
cannot reuse an Engine with an active abandoned worker. Also enforce a host/job
wall-clock deadline and terminate the disposable worker when it expires.
SDK connect/read limits and bounded retries reduce blocking; none guarantees a
universal hard deadline for the whole scan.

For CLI scans, `--job-deadline-seconds 600` or
`options.job_deadline_seconds: 600` also arms a process watchdog covering plugin
discovery, engine setup, collection and report output. The explicit CLI option
starts during option processing, before command preparation, including connector
metadata discovery for `run` and stdin reads for `jwt`. A YAML-only deadline starts
after the configuration has been read and validated. Use an external supervisor
to bound process startup, Click argument parsing and YAML preflight. The value
must be positive and finite; omission or YAML `null` leaves it disabled. Expiry
terminates the scanner with exit `3`, without guaranteeing a final report or
cleanup. A blocked output stream cannot delay that exit. Completed CLI
invocations disarm their watchdog. `Engine` embedding does not arm it: the host
application owns process supervision. Keep the external job deadline and process
group/container cleanup to reap child processes and bound native code that holds
the interpreter lock indefinitely.

Code scans follow a documented coverage policy. Links whose own names are never
read, source-file links whose real targets are analyzed in the same project
with the same test classification, and coding-agent instruction-document links
to another instruction document under the same condition, are skipped because
nothing at the alias path is lost (see [scan semantics](scanning.md) for the
exact rule). Directory
links, configuration aliases, links into excluded or unread content, links
leaving the root, oversized files the scanner would
inspect and files it analyzes by name but cannot read as text (a NUL byte
outside a UTF-8, UTF-16 or UTF-32 file with a byte-order mark) make the scan
incomplete (exit 3) by default, with a warning naming the omission.
`strict_coverage: true` (`--strict-coverage`) records those
conditions as errors; explicit `oversize_skip_globs` remain declared omissions
in both modes. Raise `max_file_size` or add `exclude` patterns for known data files.
A non-empty `bin`, `build`, `dist`, `out`, `target`, `obj`, `coverage`, `vendor`,
`third_party`, `thirdparty` or `external` directory that the walk skips by default
is listed in one warning per scan root (the scan stays complete); set
`default_excludes: false` (`--no-default-excludes`) to scan them. Evidence found
only in test or fixture paths has half weight and cannot promote a project to an
agent unless `include_tests: true` (`--include-tests`) is set, and a project
finding whose evidence is already reported by an MCP configuration, agent
manifest, exported workflow, IaC or credential finding is not emitted again.
Recognisable placeholder credentials (repeated characters, marker words such as
`EXAMPLE`, very low character diversity) are no longer reported. A
real-format credential in a test, fixture or `cassettes/` path is still a
`secret` finding, at half weight and tagged `test-code-only` unless
`include_tests: true` is set. Risk factors
always sum to the reported score; `risk.danger_score` excludes the governance
factors and `options.risk_basis: danger` bases `level` and `--fail-on` on it.
Review [scan state and runtime correlation](scanning.md) and the changelog
before raising an enforcement gate on a scanner upgrade.

A ServiceNow agent remains a native finding if optional display-name or OAuth
signature matching times out before the agents are emitted. The connector marks
coverage incomplete and skips repeated matching; exit 3 remains mandatory.
OAuth findings whose classification could not finish are omitted, and native
findings must not be interpreted as fully enriched.

Saved provider errors and unsupported/malformed export records also make scans
incomplete. Valid neighbors remain available. Explicit empty inventories such
as `[]` remain valid; an authorization-error document is not an empty inventory.
Identity and low-code collectors retain available records when enrichment or a
later page fails. Auth0 offset pagination has a finite page budget and detects
repeated pages. Okta grants and optional tokens both follow pagination.
Zoom's Marketplace listing enumerates approved public and account-created apps;
its results do not prove a per-user installation. A denied or incomplete
Marketplace category marks the scan incomplete.
Google Workspace accepts omitted empty arrays only in identified native users
and token-list envelopes; an arbitrary empty object is incomplete coverage.
Every `--only` value must match an enabled connector name or label, including
when another selector matches successfully.

Use disposable, resource-limited workers for untrusted repository scans. Keep
scanner state and output outside the repository under review. Avoid handing
production credentials to a job that executes repository-controlled build steps.
For GitHub/GitLab remote repository scans, preflight estimates and process-group
cancellation reduce ordinary runaway clone cost. `clone_max_bytes` also stops a
clone when observed checkout use, including `.git`, exceeds the configured cap.
It checks during the clone and after Git exits; a failed measurement or excessive
entry count also stops Git, removes the partial checkout and makes collection
incomplete while retaining the sampled API fallback. Periodic checks can
overshoot the threshold, and the cap does not limit network transfer bytes or
guarantee a hard writable disk ceiling. Give each disposable worker an
operating-system/container writable disk quota, memory and process limits, a
separate job wall-clock deadline and a cleanup policy for abandoned workspaces.
A worker's soft connector timeout is not a hard kill for every child process.
A local checkout example, such as
`examples/github-action-code-scan.yml`, does not exercise the remote clone path.

## Output and inventory migration

Reports and inventory stub files now use atomic 0600 writes. An existing
character device given as the report path, such as `/dev/null`, is written in
place instead of being replaced. An existing named pipe is written in place only
when you own it with mode 0600 and a reader already has it open. Sockets,
directories and other non-regular paths are refused. Inventory stub and
record-export directories are created as 0700; existing non-private directories
are rejected without changing their permissions. Use dedicated directories for
these outputs.

The Markdown reporter defangs bare HTTP(S) and `www.` strings and writes `@` as
`[@]` in untrusted text fields, so repository names, owners, diagnostics and
evidence descriptions do not become links, @-mentions or e-mail links when
reports are pasted into a ticket, pull request or wiki. Code spans keep
identifiers verbatim. The CSV reporter inserts a literal `'` at the start of a
value, and after each `,`, `;`, tab, `|` or line break inside it, where the
text that follows begins with `=`, `+`, `-` or `@` (also after whitespace,
including no-break spaces, or double quotes) or with a tab or carriage
return; a value that begins with a line feed is marked too. Other tabs and
line breaks inside a value are left alone. A report opened with another
delimiter therefore cannot create a formula cell. Strip every marker when
consuming CSV programmatically, or consume `json`.

Dump filenames include the original connector configuration ordinal and a safe
label. Repeated names or normalization-colliding labels no longer overwrite each
other. Selecting a subset with `--only` retains the original ordinal. Use the
export manifest to locate each instance's file and completion status instead of
assuming a filename such as `cloud_aws.jsonl`. Exports remain sanitized and are
not lossless copies of upstream responses. JWTs are never included.

Generated resource patterns escape literal `*`, `?` and `[` characters. Review
previously generated cards for those characters and regenerate literal bindings
where necessary. Existing intentionally authored wildcard approvals remain valid.
Resources or identity scopes whose identifiers were redacted cannot establish
an exact approval: assign a stable nonsecret resource, provider, account and
region identity before registering them. A report display value containing
`[REDACTED]` is not an authority to approve every object that renders to the
same value.
AWS findings with only a short resource ID also require an account ID from
the connector configuration or a trusted account export record. Without one,
the scan is incomplete and a registry card cannot approve the finding. Check
that distinct offline exports carry their own account scope before combining
them into an inventory baseline.
Generated cards now include `discovery.regions` when a region is known; review
older cards with short resource IDs (for example a Bedrock agent ID without its
ARN) and add explicit region constraints to avoid approving another region.

For a labeled `code.filesystem` connector using `paths`, each root gets its own
resource ID under the shared label, even if the list later contains just one
path. Without `root_ids`, the suffix is `root-<SHA256 of canonical path>` and
changes when a checkout moves. Set unique `root_ids` in the same order as
`paths` to emit `root-id-<id>` suffixes that remain stable across CI workers;
reorder the two lists together. Inventory entries using the old shared label
will no longer approve these roots. Regenerate cards from a complete scan and
approve each root separately. A scalar `path` retains its prior resource ID,
so another option for stable identities is one connector per repository with
its own explicit label.

## Field review changes

A field review of public repositories changed what some scans report. Compare a
pinned baseline with a candidate before enforcing policy on the new output:

- **Folded manifests.** A CrewAI `agents.yaml` or `langgraph.json` inside a
  reported project no longer produces its own `agent-manifest` finding; it is
  listed under the project finding's `metadata.manifests`. `diff` shows those
  finding IDs as resolved. Inventory entries that bound a manifest path should
  bind the project resource instead. A2A cards and M365 declarative agents are
  unchanged.
- **GitHub Apps.** Installations without an AI signature or AI-like name are no
  longer reported. Set `include_unrecognized_apps: true` to keep reviewing them,
  at possible confidence with the `unrecognized-app` tag. Read-only apps with an
  AI-like name are now reported. `contents` or `pull_requests` write access no
  longer implies `code-exec`, so such apps can drop a risk level (the Claude app
  from critical to high); check `--fail-on` thresholds against a baseline.
- **Completeness.** Syntax errors in ordinary configuration files and Python
  test modules over `max_ast_nodes` produce warnings instead of incomplete
  scans; the file is still read lexically. Enable `strict_coverage` to keep
  treating them as incomplete. A file the parsers refuse for nesting depth or
  XML entity expansion stays incomplete, since its content is unknown rather
  than malformed. Notebooks whose outputs exceed `max_file_size`
  now contribute their code-cell evidence; their outputs are not scanned for
  credentials at that size, so the scan stays incomplete unless `scan_secrets`
  is off. Raise `max_file_size` to scan the outputs too.
- **Capabilities.** Test-only evidence and vendor-neutral idioms in MCP tool
  servers no longer add capabilities; MCP server capabilities come from their
  registered tools. Risk scores of affected findings change accordingly.

## Completeness, report and credential changes

The 2026-09-28 changes alter completeness, report text and credential policy.
Compare a pinned baseline with a candidate before enforcing policy on the new
output:

- **Newly incomplete (exit 3).** A shared HTTP response body that misses the
  [read deadline](#resource-limits-and-incomplete-scans); a `code.filesystem`
  root that cannot be opened safely, or a directory replaced by a link during
  the scan (see
  [finding identity](#finding-identity-and-comparison-migration)); a
  `code.gitlab` group listing entry without a positive integer project `id`;
  and a `code.github` listing entry whose `full_name` is not a plain
  `owner/name`.
- **Changed diagnostics, still incomplete.** A YAML value PyYAML cannot
  construct, such as an impossible date or an integer over 4,300 digits,
  already made a scan incomplete; it is now reported as malformed YAML
  (`invalid YAML`, `invalid agent definition YAML`), and the agent definition
  is now listed where it used to be dropped, which can raise that finding's
  risk score. Scan configuration and inventory files with such a value still
  fail at setup (exit 1), now with `ConfigValidationError` or
  `InventoryValidationError`. A cancellation or connector deadline while a
  credential finding is built now ends that connector instead of being
  recorded as one file's error; the scan was and is incomplete.
- **Newly complete.** A Python module whose imports cannot resolve to any
  signature is complete at any size or nesting depth, because the import
  binder, which could add no evidence there, is skipped for it.
  `mypy/checker.py` (52,729 AST nodes) used to make ordinary library trees
  exit 3. A module that imports a library a signature describes keeps the
  `max_ast_nodes` diagnostic: a warning in tests, an error elsewhere.
  Configuration, inventory, signature pack, report and offline input files
  below a traverse-only directory (mode `0711`) now open, since directories
  are opened for traversal only.
  An unrendered Helm, Jinja or Go-template YAML file, such as a chart
  template with `image: {{ .Values.image }}`, no longer reports
  `structured parsing incomplete`: it is not YAML until rendered, so its
  excerpts use lexical redaction. Plain YAML with duplicate or non-finite
  data still makes the scan incomplete.
- **Reports.** CSV reports also carry `'` markers after a `,`, `;`, tab, `|`
  or line break inside a value, not only at its start (see
  [output migration](#output-and-inventory-migration)). Consumers that strip
  only a leading marker must strip these too, or read `json`. Markdown writes
  `@` as `[@]` in untrusted text, including owner e-mail addresses.
- **Redaction.** Report excerpts and structured connector metadata withhold
  more credential forms: literals passed to credential constructors and
  builder chains, literal fallbacks of credential environment variables,
  credential command-line options, .NET and XML settings, and opaque values
  under credential-like names ([changelog](changelog.md) lists them). This is
  a credential-policy change without configuration changes; scores and
  evaluation results are unchanged. Expect more `[REDACTED]` markers, for
  example on every literal after the first in a multi-argument credential
  constructor (such as a client ID), on opaque-looking values under names
  such as `cacheKey` or `nextPageToken`, and on a capitalized literal
  fallback after a credential name. Reports produced before this release may
  show such values although the scan exited 0, for example a web.config
  `<appSettings>` key beside an Azure OpenAI endpoint, a C#
  `new AzureKeyCredential("…")` or a `--key` command line. Regenerate earlier
  reports that covered .NET or XML configuration, SDK client code or such
  command lines, and rotate any key they show. The
  [security policy](security.md) lists the forms still not withheld; keep
  treating reports as confidential.
- **Redaction limits.** Redaction is linear in its input, so minified bundles
  and long runs of unfinished annotations no longer exhaust the redaction
  budget or time out, and a long unquoted value after `key=` no longer hangs
  a scan. Expressions nested more than 100 brackets deep are withheld through
  the end of the excerpt, and an unquoted word holding more than 16
  command-line options from its 17th option on. In structured metadata the
  added rules run as a second pass over the first pass's output. That pass
  refuses a value the earlier rules accepted, with a sanitization limit
  (exit 3), only when removing a credential it found from the value's other
  fields would exceed the replacement work budget or grow a text past the
  size limit. Report sanitization takes about 28% longer.
- **Finding identity.** IDs are computed from sanitized resource fields, so
  an ID changes only where such a field held a value that is now withheld;
  the demo, sample repository and evaluation corpora keep their IDs. The
  redaction policy token changed, so findings verified clean under the old
  rules are sanitized again automatically.
- **Plugins and embedders.** `shadowscan.utils.text.sanitize_record` and
  `HttpClient.paginate_cursor` are removed: call
  `shadowscan.utils.redaction.sanitize`, and paginate explicitly. Patch
  redaction rules only through `shadowscan.utils.redaction`. A plugin that
  declares the cloud surface or documents `allow_instance_credentials`
  receives the scan-wide approval (see
  [explicit security policy](#explicit-security-policy)), and engine
  behavior that differs by connector is a class hook (see
  [architecture](architecture.md#engine-hooks)).

## October field scan changes

These corrections change what some scans report. Compare a pinned baseline with
a candidate before enforcing policy on the new output:

- **Completeness.** TSX files with typed elements, comments between JSX
  attributes or element text starting with `(` no longer make scans incomplete.
  Previously incomplete React repositories can now complete and become usable
  `diff` baselines.
- **New MCP findings.** Gemini `httpUrl` servers and MCP servers embedded in
  GitHub Actions step inputs are new `mcp-server` findings. `diff` shows them as
  new; review their risk before using `--fail-on`.
- **Attribution.** Findings whose only Google ADK evidence was
  `GOOGLE_GENAI_USE_VERTEXAI` lose `framework.google-adk` and its `multi-agent`
  potential capability. `diff` reports them as changed; titles change too.
- **Fixture workflows.** Exported workflows under test or fixture paths gain the
  `test-code-only` tag, lower confidence and a lower risk score.
- **Project roots.** Modules named `setup.py` that do not build a package no
  longer create a project. Findings for such directories disappear from `diff`
  as resolved and their evidence joins the enclosing project's finding.
- **Credential files.** MCP servers whose only inline-secret evidence was a
  credential-file path argument or a repeated variable reference lose the
  `inline-secrets` tag and its risk factor.
- **Test-path credentials.** `secret` findings under test, fixture or
  `cassettes/` paths gain the `test-code-only` tag, lower confidence and a lower
  risk score unless `include_tests` is set; they are still reported.
- **Coding-agent configuration.** A product named only by an environment
  variable or display name (such as `GOOSE_PROVIDER` in a test matrix) no longer
  yields an `agent-config` finding; `diff` shows such findings as resolved.
  Instruction-document aliases (`CLAUDE.md` linking to `AGENTS.md` in the same
  project) no longer make a scan incomplete.
- **MCP parsing.** Compiled agentic-workflow lock files (`*.lock.yml`) and
  cookiecutter `{{...}}` template paths are not parsed as MCP configuration and
  no longer make a scan incomplete.

## October 2 review changes

These fixes came from an AI-assisted review of the October 1 candidate; neither
the review nor the fixes had a second-person review. Several of them turn a
result that used to look complete into an incomplete one, so run a candidate
scan next to the pinned baseline and read the differences before you enforce
policy on the new output.

New incomplete (exit 3) and configuration-error outcomes:

- **Unreadable analyzable files.** A file that `code.filesystem` analyzes by
  name and that still contains a NUL byte in its first 8 KiB (a binary `.plist`
  or `.xml`, a UTF-16 file without a byte-order mark, a stray NUL in source or
  Markdown) is a coverage gap named `binary or undecodable content in
  analyzable file`. Fix the file or add it to `exclude`. UTF-8, UTF-16 and
  UTF-32 files with a byte-order mark, and Python sources with a PEP 263 coding
  cookie, are now decoded and analyzed, so dependency lists, `.env` files and
  sources that used to read as empty can add findings.
- **List options.** A bare string for `exclude` or `paths` (`exclude:
  "vendor/*"`, `--set exclude=vendor/*`) is a configuration error. It used to be
  split into characters, which excluded the whole tree and reported a complete,
  empty scan. Use a list, or repeat `shadowscan code --exclude`.
- **Signature packs and inventories.** A custom signature pack directory that
  contributes no `.yaml`/`.yml` pack (empty, other file types, only symbolic
  links) and an inventory glob that matches no file now fail at setup (exit 1).
- **Connectors and plugins.** A connector or plugin that calls `sys.exit()` is
  a failed connector and the scan is incomplete; it no longer ends the process
  with the plugin's status and no report.
- **Exports.** Gateway logfmt lines that repeat a key or leave a quote open,
  gateway records whose timestamp no supported format parses, `saas.generic` and
  `lowcode.zapier` rows with no name (blank rows, footers; map the column with
  `fields.name`, or call it `title`/`name` for Zapier), Slack Connect bots from
  partner workspaces, OCI policy statements over 8192 characters, and
  Power Platform records that cannot be analysed are skipped with a warning and
  make the scan incomplete. The remaining records are still reported.
- **ServiceNow paging.** A short page no longer proves that a table ended.
  Collection stops at an empty page, so a small `max_pages` makes any non-empty
  table incomplete. Keep the default (1000) or size it above rows/500 + 1.
- **Report comparison.** `diff` treats a report whose `summary` counts do not
  match its `findings` array as incomparable (missing findings are unknown,
  exit 3) instead of counting them as resolved.

Changed results to review before you compare against a baseline:

- **Disabled MCP servers.** A server entry that declares `disabled: true` or
  `enabled: false` is reported, tagged `declared-disabled`, with `disabled: true`
  in `metadata.servers`; `server_count` still counts only the others. The flag
  is client-specific and comes from the repository, so honoring it let a
  repository hide a server. `diff` shows a configuration whose only entries are
  disabled as a new finding.
- **Newly visible evidence.** NuGet `PackageReference` items in
  `Directory.Build.props`, `*.targets` and shared `*.props` files, and imports
  of an SDK whose name a repository shares with an empty or data-only
  directory, now produce dependency and provider evidence.
- **Gateway logs.** Only the request path decides whether a request is a static
  asset or health probe, and a probe name must be the last segment: `/healthz/ready`
  and `?_=.js` requests are classified by the normal LLM route and host rules.
  Provider attribution follows the URL authority (`https://api.openai.com@evil.example/`
  names `evil.example`). Microsecond, nanosecond, Go and RFC 2822 timestamps
  are now parsed, which changes first/last-seen and activity analysis.
- **Entra.** Permission names in findings may change from a raw GUID to the
  label of the resource that defines the role. The "conflicting role labels"
  warning appears only when a conflicting label is needed for a grant, so
  exports in which different resources reuse a role id are no longer incomplete.
- **JWT.** Without `jwks_url`, every token finding carries
  `metadata.verified: false`; confidence and risk are unchanged.

New warnings (the scan stays complete):

- Default-excluded directories: one warning per scan root names the non-empty
  `bin`, `build`, `dist`, `out`, `target`, `obj`, `coverage`, `vendor`,
  `third_party`, `thirdparty` and `external` directories the walk skipped.
  Set `default_excludes: false` (`shadowscan code --no-default-excludes`) to
  scan them. That option also stops skipping dependency trees and virtualenvs
  (`node_modules`, `.venv`, `site-packages`), so pair it with `exclude:
  [node_modules, .venv]`. Version-control metadata (`.git`, `.hg`, `.svn`) is
  always excluded. Pipelines that fail on any warning must pass the option or
  tolerate the warning.
- Inventory placement: a scan warns, under the new `engine.inventory` entry of
  `stats`, when an inventory or a file it loads is inside a path scanned in the
  same run, and for each `*`-only resource pattern. Keep the inventory outside
  the checkout that a pull request can change. Report consumers that list
  `stats[].connector` will see the new entry name.
- Python that does not parse (syntax newer than the runtime, a notebook with
  shell or magic lines) keeps its lexical evidence and adds a warning.
- Gateway scans note how many static-asset and probe requests were not counted.
  Tooling that fails on any warning should key on `incomplete` or the exit code.

Operational notes:

- With a Kubernetes ConfigMap mount, pass the resolved file path as the
  scan configuration; links are deliberately not followed.
- `XDG_STATE_HOME` is ignored when it is empty or relative.
- Remove an `actions/cache` step that restores `--incremental` state. The
  fingerprint includes file identity, so a fresh checkout never reused it.
- Maintainers: `main` push CI runs are no longer cancelled by the next push,
  so expect more concurrent CI minutes on busy days. A new connector family
  directory or nested connector package must be listed in `CONNECTOR_FAMILIES`
  in `tools/coverage_gate.py`, or the coverage gate fails.

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

This candidate preserves the v2 algorithm (`ss-` plus the first 16 SHA-256 hex
characters). Corrected JWT issuer labels can change provider-derived IDs for
previously misclassified tokens; review those deltas when updating a baseline.

Diffs now identify substantive changes in classification, permissions,
capabilities, technologies, risk score/factors, registration and ownership,
including changes within the same risk band. `changed_fields` identifies the
changed attributes. Timestamp and evidence ordering alone do not create changes.
`diff` and `inventory stubs` accept regular JSON report files up to 64 MiB,
without input or ancestor symlinks. Duplicate keys, non-finite numbers, invalid
finding fields and excessive nesting fail validation. All records are checked
before stub generation writes files; this does not make multiple file writes
transactional if a later filesystem operation fails.

GitHub and GitLab API source downloads use immutable blob IDs returned by tree
enumeration and verify each downloaded file against its Git object ID before
scanning it. GitHub API findings include the tree SHA; GitLab API findings
include the commit SHA resolved before pagination. Clone-mode findings include
the checked-out commit and tree SHAs. These appear in each code finding's
`metadata.source_snapshot`, alongside the provider, capture method and validated
branch name when available. Missing or malformed snapshot identities and blob
mismatches mark the scan incomplete; valid neighboring files remain usable.
Symlinks and submodules are skipped with incomplete coverage. Provider settings,
CI variable names and other metadata collected separately are not part of the
source snapshot.

Symlinked incremental roots or ancestor paths are ineligible for cache reuse.
Filesystem scans reject selected roots whose paths traverse a symbolic link.
They then open each root once and read every file, including `CODEOWNERS`,
relative to it without following a link in any path component. A scan needs
read and search permission on the root and the directories below it, but on
Linux and macOS only search permission on the directories above it (they are
opened with `O_PATH` on Linux; on macOS the root is opened in one call with
`O_NOFOLLOW_ANY`), so a checkout below a traverse-only directory such as a
mode `0711` home directory is scanned completely. A root that cannot be opened
this way is reported, by its `label` when one is set, as
`could not open the scan root safely (<reason>)`, for example
`permission denied`, and makes the scan incomplete. Source links encountered
during a walk are skipped and mark coverage incomplete. A directory replaced
by a link while the scan runs fails the reads below it and also marks
coverage incomplete, so content outside the root is never analyzed. Review
or explicitly exclude such paths before accepting a completeness gate.
Pre/post content hashes can detect ordinary concurrent edits but do not form an
atomic snapshot. Scan an immutable checkout/export to exclude changes that occur
and revert between those reads.
Incremental state uses nonblocking advisory `flock` per cache slot
(`<sha256>.lock`): shared for reading and exclusive for publication, as well as
atomic writes and current-input fingerprint checks.
Keep state in a dedicated private directory outside the scanned repository. A
busy read lock causes a cache miss; a busy write lock skips that publication.
Incremental state needs POSIX advisory locking (`fcntl`); platforms without it are ones the confined file reader already refuses, so no scan runs there. Symlinked, non-owner or non-private lock files are
rejected. Use local filesystems with working advisory locks; a lock is not a
distributed coordination service or a security boundary against another process
with the same user ID.

## Cloud collection changes

AWS verifies the live account through STS before emitting account metadata,
including when `account_id` is configured. For live scans, that setting is an
expected account and a mismatch stops collection. AWS and OCI SDK clients have
explicit 10-second connect and 30-second read timeouts with at most three
attempts. These bounds do not replace the overall worker deadline. AWS Lambda
and GCP project limits stop enumeration without materializing the full inventory.
ECS discovery follows
exact definition ARNs referenced by running tasks and service deployments,
including referenced inactive revisions, and retains the latest active registered
revision of each family as a separate evidence category. Stopped tasks and unused
historical revisions are outside this collection scope. A registered-only label
does not prove a definition is undeployed when discovery is incomplete.
Late AWS list-page failures retain earlier observations, mark coverage incomplete,
and cap pagination; a missing collection field is not an empty inventory.
The per-region `max_ecs_api_calls` limit defaults
to 2000; exceeding it or encountering denied/partial calls marks coverage
incomplete. Add the read permissions listed in [connectors.md](connectors.md).

GCP Owner/Editor-only principals remain visible as privileged access findings.
Neither broad role grants nor ECS deployment references establish that AI code
actually executed. Use trusted runtime telemetry for additional attribution.
GCP audit caller findings keep events from separate projects distinct, including
when the service account principal is the same. Azure Resource Graph failures on
later pages preserve earlier observations and mark collection incomplete.
Cloud Run discovers concrete regions using the locations API before listing
services; the v2 services endpoint does not accept a `-` location. Unreachable
regions in GCP list responses make coverage incomplete while retaining reachable
observations. The audit identity must have `run.locations.list` and
`run.services.list` for this discovery path. Azure ARM inventory pages also retain
observations after later failures; diagnostic-setting coverage remains unknown
unless every page was collected successfully.

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

### Merge gate and review status

Ruleset
[23913372, Require CI and CodeQL](https://github.com/aisecnomad/Project-Nexus/rules/23913372)
is configured to require `test (3.11)`, `test (3.12)` and `analyze`, an
up-to-date branch, and one approving review from a reviewer with write access,
alongside `Protect main`. Add the new aggregate `CI gate` to that required-check
list without removing the existing checks or approval rule. Its enforcement
state has changed more than once during 2026-09: the 2026-09-24 review recorded
it disabled; on 2026-09-25 (13:10 UTC) a merge attempted without an approving
review was refused with "Repository rule violations found", so it was enforced
at that moment; and on 2026-09-27 (10:40 UTC) both rulesets were read back with
`enforcement: disabled`, so nothing was enforced on `main` at that time. Treat
no observation as permanent; only the live commands below describe the current
state. Keep the CodeQL job's displayed name `analyze` consistent with the
required check.

Whatever the ruleset's state, the history is unchanged: the repository has a
single maintainer, and no change merged to `main` through 2026-09-25 (including
#62, #65 and #42) carries an approving review from a second person. A repository
administrator can bypass or reconfigure rules, so a merged pull request, the
version string and the internal AI-assisted hardening logs are not evidence of
independent review. The review and merge policy is in
[CONTRIBUTING.md](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#review-and-merge-policy).

Rulesets, branch protection and pull request approvals are repository settings
that can change at any time, so an
operator who needs an independently reviewed revision must inspect the live
state when selecting the commit and retain the output with the deployment
evidence:

```bash
# Rules currently enforced on main; an empty list means nothing is enforced
gh api repos/aisecnomad/Project-Nexus/rules/branches/main
# The ruleset itself, including its enforcement state
gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 --jq '{name, enforcement, rules: [.rules[].type]}'
# Classic branch protection; HTTP 404 means none is configured
gh api repos/aisecnomad/Project-Nexus/branches/main/protection
# Who authored, reviewed and merged the pull request that introduced a change
gh pr view <number> --repo aisecnomad/Project-Nexus --json author,mergedBy,reviews
```

An approving review counts only when it comes from a person with write access,
other than the author, and covers the final revision of the pull request. A
successful workflow run or Copilot review does not supply that approval. A
single maintainer cannot approve their own PR: recruit a second eligible human
reviewer rather than weakening the rules to self-merge. Recheck the live ruleset
and pull request status at release time.

The CI workflow installs hash-locked runtime, build and core/development
dependency sets and validates signatures, lint, typing, dependency advisories
(including the documentation lock), tests with a minimum 80% statement coverage,
wheel creation, installed-wheel validation outside the source checkout and
offline SARIF output. All three Linux matrix jobs
(Python 3.11, 3.12 and 3.13) enforce a 75% statement-coverage floor for each
built-in connector module, so a well-tested engine cannot conceal an untested
provider. Coverage proves execution of code paths in tests; it does not prove
provider compatibility or complete tenant inventory. The aggregate `CI gate`
requires every Linux and macOS matrix job and documentation to succeed; it also
requires DCO on pull requests. It fails if a required prerequisite fails, is
cancelled or is unexpectedly skipped. Verify that the live ruleset requires
`CI gate` before treating the full matrix as an enforced merge gate. The Linux
Python 3.13 job also
builds the Docker image and checks its non-root UID, signature assets and
network-isolated scan with a read-only root filesystem and resource limits.
Focused regressions cover the review findings, private-address enforcement,
public-key verification, plugin policy, artifact permissions and replay integrity.
Dependabot checks Python, GitHub Actions and Docker base-image dependencies weekly.

Automated and mocked provider-contract checks do not validate a tenant's actual
permissions, enabled services, data retention or export trust chain. Before an
operational rollout, run a read-only canary in each target tenant, inspect complete
coverage and account identity, verify expected known resources, and compare live
results with the retained export. These environment-specific checks require
access to those tenants and are not performed by offline CI.

The [synthetic evaluation](evaluation.md) guards against known classification
regressions. It does not measure field precision, recall or the calibration of
the heuristic confidence score. Before turning on `--fail-on` for an estate,
label a representative held-out set from that estate, include inactive configs,
commented/string-only source, disabled integrations and genuinely executing
agents, and review errors by connector and severity. For code-filesystem cases,
run the acceptance command with a separately reviewed, SHA-256-frozen policy:

```bash
python -m tools.evaluation.accept \
  --corpus /restricted/holdout.json \
  --policy /restricted/acceptance-policy.json \
  --annotations /restricted/holdout-annotations.json \
  --output /restricted/acceptance-result.json
```

The gate rejects synthetic/public samples and requires a frozen, SHA-256-bound
two-reviewer ledger plus predeclared sample floors and Wilson lower bounds per
family. Both acceptance paths reject repeated nonblank source contents or pinned
locations across holdout cases, including renamed and partially overlapping
multi-file samples. Repeated files inside one case are one sampling unit; blank
package scaffolding alone does not duplicate an otherwise distinct case, but
repeated all-blank cases are rejected. Previously evaluated source exclusion
remains strict for every file. Ledger declarations do not authenticate reviewer independence or prove
tenant completeness. Set a documented acceptable false-alert
and miss rate for each high-impact workflow; keep human triage while those
acceptance metrics are measured.

## Rollout acceptance

Before broad deployment, retain evidence for each intended connector instance.
The [canary proof packet](evaluation.md#read-only-tenant-canary-procedure) lists
the concrete status, denominator, control and reviewer artifacts:

1. Run a read-only canary with the actual audit identity. Record the expected
   tenant/account, regions and collection scope, then verify known agents and
   at least one known permission/configuration signal appear.
2. Verify denied access, malformed exports and partially invalid selections
   cannot pass the gate. Require `summary.complete=true` and inspect all connector
   statistics for successful collection; do not infer coverage from finding
   count or an empty report alone.
3. Check sanitized artifacts with synthetic credentials and enforce private
   file/directory modes. Keep configuration, state and outputs outside scanned
   repositories and restrict access to retained reports. Regenerate retained
   reports after an upgrade that withholds more, such as the
   [2026-09-28 redaction changes](#completeness-report-and-credential-changes).
4. Replay each exported instance using its manifest filename, checking account,
   resource identity and detection consistency. Sanitized exports are not
   lossless raw API backups; credential findings may differ after redaction.
5. Run a representative large scan in a resource-limited disposable worker.
   Set a job deadline, monitor incomplete/failed runs and provider throttling,
   and document how to restore access or rerun after a partial collection.
6. Pin the reviewed scanner commit, wheel/image digest and approved dependency lock for rollout.
   Establish a fresh comparison baseline, retain the prior pinned version for
   rollback, and keep rollback reports separate from the new identity schema.
7. Measure precision and recall on a held-out, representative set of your own
   code and tenant records. Record the labeled corpus, per-connector confusion
   matrix, severity thresholds, reviewer decisions and accepted failure budget
   before treating findings as an automated policy decision.

These checks require operator-specific tenant access and operational decisions.
Until completed, describe deployment status as pending tenant and container acceptance.

## Consolidated candidate compatibility

The consolidated candidate preserves the PR #30 runtime policies and reconciles
verified additional fixes with PR #31, which merged during that work. The
canonical deadline setting is `options.connector_timeout_seconds` /
`--connector-timeout-seconds` (default 120). Legacy `options.connector_timeout`
and `--connector-timeout` remain deprecated compatibility aliases. Configure only
one YAML key; supplying both is rejected. Legacy YAML `connector_timeout: null`
uses the 120-second default rather than disabling it.
Workers are not replaced after all capacity is occupied by blocked calls; the
remaining queue is reported incomplete. `Engine.run()` returns control to library
callers; the CLI exits after reporting abandoned workers. Continue to enforce
the disposable worker's external job deadline for blocked output or filesystem
replacement still in progress after the report.

New Azure App Service settings and OCI Function exports store configuration under
`environment`, which redacts every value even when a credential has an unusual
name. Analyzers still accept older `settings` / `config` exports. GCP service-account
exports include `key_coverage`; denied or malformed key listings carry an unknown
count rather than an observed zero. Consumers must preserve that distinction.

Corrected SSM parameter ARNs and nested GitLab group account paths can change the
identity of affected findings. Duplicate source observations no longer inflate
confidence. Review changed classifications and rebuild comparison baselines when
adopting this candidate; the collection-scope digest already prevents automatic
resolution across different scanner implementations.

Offline export diagnostics are capped at 20 detailed messages plus a suppression
message per file; context-generated errors and warnings are separately capped at
1,000 plus a suppression message per connector. Suppression never clears incomplete
coverage, and later valid records continue to be analyzed. Gateway detail caps
also mark missing detail incomplete while preserving supported aggregate totals.
Application logs contain fixed warning/error summaries. Inspect the bounded,
sanitized connector diagnostics in the report for details, and retain reports
under the same access controls as inventory data.

JWKS documents are fetched lazily and cached only within a JWT analysis. Tokens
with rejected algorithms do not trigger a lookup, and each token is still checked
against its expected issuer and allowed keys. This is signature evidence, not an
authorization or token-acceptance decision. Key rotation during the same analysis
requires a new scan.

See the [consolidated hardening log](https://github.com/aisecnomad/Project-Nexus/blob/main/archive/reviews/consolidated-review-2026-09-24.md)
for the maintainer's verification notes and implementation choices. It is an
internal, AI-assisted work log, not an independent review.

The [round 2 production review](https://github.com/aisecnomad/Project-Nexus/blob/main/archive/reviews/production-review-2026-09-24-round2.md), also an
internal AI-assisted work log rather than an independent review, records
the later verified corrections to export sanitization, Bedrock/IAM/OCI collection,
JWT classification, gateway detection and report rendering performance.
