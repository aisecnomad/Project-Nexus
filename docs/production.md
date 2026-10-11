# Deployment and migration

This is the rollout guide for version 0.1.2. It covers reviewed
revisions, installation, validation, rollout, operation and migration.

Automated validation establishes implementation behavior. Production rollout
also requires the tenant canaries and container/operational checks below; a
passing unit suite does not establish complete coverage of a particular estate.

## Unreleased attribution migration

This section covers the Python re-export and governance observation changes.
For network connection attribution and hosted-agent invocation, see
[October 9 scan evidence corrections](#october-9-scan-evidence-corrections-unreleased).

- Supported local Python re-exports can expose agent construction previously
  reported only as framework usage. This remains static integration evidence,
  not proof of deployment or execution; see the [source guide](connectors/code.md).
  Rerun affected source scans before comparing totals. A re-export source or
  chain budget, or a connector deadline that leaves a queued root-level
  consumer's import binding unanalyzed, marks the scan incomplete; ordinary
  local modules, however large, do not. A consumer left unbound keeps its
  lexical import and code evidence.
- A scheduled governance audit can verify visible controls while reporting
  bypass settings as unknown. Do not use that partial observation as the complete
  ruleset evidence required for release or rollout. See the
  [merge-policy procedure](operations/merge-policy.md).

The scanner-source fingerprint changes with these fixes. Preserve earlier
reports as historical observations and rebuild comparison baselines under the
new reviewed revision; do not interpret incomparable findings as resolved.

Before using the changed source classifications for enforcement, commission a
fresh holdout using the [frozen field-evaluation procedure](evaluation.md#build-a-genuinely-held-out-field-set).
Include modular agent code: import-only re-exports, cycles, shadowed bindings
and executable shims. Freeze repository/family sampling and acceptance
thresholds before showing scanner results to reviewers. These new authored
regressions must be excluded from that holdout.

The [acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md)
supports static code, AWS and Slack. A code change cannot substitute for human
labels, approved tenant credentials or live acceptance receipts.

## Unreleased review migration

After upgrading to the review corrections, rescan source and regenerate retained
reports. Python `try` and `match` alternatives no longer transfer their last
visited binding to another path. Supported literal unreachable alternatives
remain excluded; uncertain branches retain usage evidence. A lower agent
classification is not evidence that a deployed agent stopped executing.
Guarded optional imports (`except ImportError: pass`, or a handler ending in
`sys.exit()`) again keep their SDK binding, so rescans can restore agent
classifications and tool-use capabilities that the first review correction
lowered. A notebook cell that stops (`raise SystemExit`, `sys.exit()`) no longer
hides constructions in later cells, so such notebooks can rise to agent.
Python literals containing control or Unicode separators no longer shift AST
coordinates; rescans can restore registered-tool execution capabilities that
were previously lost in either project or source inventory mode.

For separate source inventory bindings, explicitly select
`agent_granularity: source` on `code.filesystem`, `code.github` or `code.gitlab`.
The supported subset is import-proved Python constructors assigned to a unique
simple name in a straight-line module, class or function scope in a `.py` file. Each supported binding
uses its source file and qualified binding as a separate resource identity;
unrelated line insertions do not change it. Renaming a file or binding changes
the identity. Dynamic, repeated, control-flow-dependent and unnamed constructions
retain project evidence and expose identity limitations; this option does not
enumerate deployed instances, split notebooks or follow every source language.
Execution capabilities of a tool that such a construction, a registration, a
dispatch loop or other code that obtains the function (a computed tools value,
`bind_tools`, a wrapper, method or local decorator) can also reach stay on the
project finding as well as on each named source finding; approving a named
binding does not hide them.

Review generated inventory stubs for each source finding. A project resource
approval does not approve a separate source resource; a broad inventory glob
can intentionally match both and must be reviewed for that scope. Keep previous
reports and establish a fresh baseline after changing granularity or scanner
revision. Source identity and source-analysis changes alter the collection
fingerprint, so incomparable observations cannot establish resolution.

Supported AWS CLI positional credential settings are now sanitized in command
text and argument arrays, including unlisted global options, other letter cases,
PowerShell and cmd continuations, commented or prefixed source argv and an
executable passed separately from its argument list. Regenerate old reports,
exports and cached evidence under the reviewed revision; changing the scanner
cannot erase already retained copies. Continue to protect audit artifacts and
follow the credential handling policy in [SECURITY.md](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md).
The additive JSON `inventory_present` field distinguishes an explicitly supplied
empty inventory from a scan without inventory reconciliation. CSV now retains
the entire sanitized permission list, including permissions beyond position 30.

The scheduled governance audit can pass its visible-policy checks while its
retained observation reports partial assurance. Inspect `unknown_fields` and
`complete_readback_verified`; an omitted bypass list is never evidence of no
bypass actors. Complete administrator readback remains required by the strict
verification and release paths. After deployment, retain an actual scheduled or
dispatched audit run and both ruleset observations, then verify a fresh complete
administrator readback against the reviewed policy. Synthetic workflow tests
do not establish the deployed token's response or assurance.

Before enabling enforcement, commission a fresh blinded holdout that includes
exception handling, pattern matching, multiple constructions per project,
ambiguous bindings and registered versus unregistered source agents. Freeze
sampling, labels and acceptance thresholds before showing results to reviewers;
exclude the new authored regression fixtures. Follow
[rollout acceptance](#rollout-acceptance) for complete and permission-denied
tenant canaries. The [acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md)
supports static code, AWS and Slack; passing those scopes does not grant
acceptance to other connectors. Human labels and live receipts remain pending
until operators supply them.

Use this operator sequence; dated candidate notes remain under
[Candidate change history](#candidate-change-history) and describe differences
between candidate builds, not between releases.

## Review before deployment

The model-identifier pass leaves coverage incomplete (exit 3) when a file
exceeds its 400-literal analysis limit. Only literals that carry a vendor stem
(model-id candidates) count; ordinary strings never reach the limit. Findings
from the analyzed prefix remain available; review the unread content
separately before using an incomplete result for an assurance decision.
Catalog assignment and data-file reference limits likewise mark coverage
incomplete when unread content could change the configuration classification.
A truncated reference list is reported only when the project discounts a data
file as a catalog that an unread reference could have named; otherwise the
unread references change nothing and the scan stays complete.

Text decoding examines every bounded window before accepting replacement
characters. A plain-text prefix does not exempt a binary body from incomplete
coverage. Python and notebook inputs remain strict UTF-8 inputs when they
carry a UTF-8 byte-order mark; invalid bytes leave a coverage gap (exit 3).

Before selecting a revision, verify its final-head review record and the live
merge rules. A versioned policy, merged pull request or passing CI does not
establish independent human review. The [merge gate and review status](#merge-gate-and-review-status)
section records the available evidence and commands for checking current
enforcement. Independent human review is required before any tagged release.

Release tags are annotated; personal tag signatures are optional. Verify the
downloaded wheel's digest and GitHub provenance as described in the
[publishing runbook](operations/publishing.md#per-release). Workflow
attestations identify the artifact's origin and do not replace the review
record or deployment acceptance evidence.

## Contents

1. [Review before deployment](#review-before-deployment)
2. [Pin and install a reviewed revision](#install-from-a-reviewed-revision)
3. [Validate security policy, Git metadata and resource limits](#explicit-security-policy)
4. [Roll out with tenant acceptance evidence](#rollout-acceptance)
5. [Operate within collection and resource limits](#resource-limits-and-incomplete-scans)
6. [Upgrade and migrate identities](#credential-evidence-identity-migration)
7. [Candidate change history](#candidate-change-history)

## Install from a reviewed revision

The scheduled dependency and governance audit checks both live merge rulesets
against the versioned desired policy. Its GitHub token is read-only: a green
job establishes that the visible managed fields match, but its retained
observation can still report partial assurance because GitHub withholds bypass
settings. Read `complete_readback_verified` and `unknown_fields` in each
observation; never interpret an omitted bypass list as empty. A failed or
unavailable read does not establish protection. Repository administrators must apply the
[reviewed ruleset updates](operations/merge-policy.md) and verify fresh API
readback. The audit neither changes settings nor substitutes for independent
human review or tenant acceptance.

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
hashes and run the full test suite, which validates development use there;
the coverage floors are enforced on Linux Python 3.11. A macOS deployment still
needs its own wheel,
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
python -m pip install --no-deps dist/nexusshadowscan-0.1.2-*.whl
python -m pip check
python -m shadowscan.signatures.validate
python -m shadowscan.mappings.validate
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

The Dockerfile installs both locks under `--require-hashes`: the runtime lock
into the virtual environment the runtime stage copies, and the build lock into
a separate build environment. That environment builds the package wheel with
`--no-build-isolation` and is not copied. The image runs as UID/GID 65532. Both
stages pin the same multi-arch `chainguard/wolfi-base:latest` image index by
its literal digest; Python 3.12 and Git are Wolfi packages, and pip stays in
the build stage. Both stages also pin Wolfi's `python-3.12` to one package
revision for now; see
[October 2 integration of #134](#october-2-integration-of-134-and-hygiene-review).
Because apk reads the live Wolfi repository, this image is not byte-for-byte
reproducible. Retain the built image by immutable digest for repeatable
deployment. Reproducible rebuilds additionally require an immutable package
repository snapshot and a validated reproducible build process; a rebuild
cadence alone does not supply either. Keep both `FROM` digests and Python package
pins identical across the build and runtime stages.
The image build checks that Git is 2.45 or newer for history enrichment.
Review that exact digest and any Dependabot refresh before deployment:

```bash
docker build --tag shadowscan:reviewed .
```

Retain the reviewed base and built image digests. The build context is an
allowlist (`.dockerignore`) of package sources, signature and mapping data,
packaging inputs and the runtime/build locks. Distribution packages from `apk`
and image metadata remain mutable, so the Dockerfile does not promise byte-for-byte
reproducible images. There is no claim of a hermetic package snapshot. CI
smoke-tests a non-root, read-only and network-isolated image; build and test the
deployment image, generate its container/OS SBOM, and validate resource limits
and output-directory permissions before rollout.

Docker Hub rate-limits anonymous pulls by source address, and hosted CI runners
share their egress addresses. CI's container job therefore adds Google's Docker
Hub pull-through cache, `https://mirror.gcr.io`, to the runner's Docker daemon
`registry-mirrors` setting, fails unless the restarted daemon reports it, and
pulls the base image by the digest in the Dockerfile's `FROM` lines before the
build. A digest pull is content-verified, so the mirror cannot change the base
image, and the daemon falls back to Docker Hub when the mirror fails. A builder
elsewhere that hits the limit can set the same daemon mirror or authenticate to
Docker Hub; the digest pin keeps the base image identical either way.

The [Kubernetes offline Job example](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/k8s-job.yaml) has a 20-minute
active deadline, a placeholder for a reviewed image digest, and a matching
NetworkPolicy that denies egress when enforced by the cluster CNI. Supply a
reviewed `/input` volume before running it. For live API collection, use a
separate Job and enforce a network path through an approved transparent egress
gateway or firewall that filters by name; a standard Kubernetes NetworkPolicy
cannot filter destinations by DNS name, and ShadowScan's HTTP client ignores
proxy environment variables and rejects an explicit proxy. See [operational controls](operations/operational-controls.md).

Opt-in Git history enrichment requires Git 2.45+;
verify the distribution Git version if that feature is needed. Cloning requires
Git 2.32 or newer; with an older or unidentifiable Git the scan uses sampled API mode
and is incomplete. The gitlink inventory of a clone additionally needs Git 2.45; with
Git 2.32 to 2.44 a clone is scanned but reports `could not inventory gitlinks safely;
submodule coverage unknown`. Keep runtime secrets out of the build context.

For record replay, read `exports/manifest.json` and use the `filename` for the
intended connector instance; export names are not a fixed `cloud_aws.jsonl`.

## Explicit security policy

```yaml
options:
  plugins: []
  plugin_execution: thread
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

Use `options.plugin_execution: process` or `--plugin-execution process` to run
approved third-party connectors in dedicated spawned workers. Built-in
connectors keep their existing thread execution; the default for plugins also
remains `thread`. Plugin import and execution happen in the child. The original
connector deadline includes worker startup and result transfer, and the worker
exits as soon as its result is sent (plugin `atexit` handlers do not run); expired results
are discarded, and termination escalates from TERM to KILL with bounded cleanup.
A parent supervision guard allows up to two additional seconds for cleanup.
Workers also exit by themselves two seconds after the deadline, or as soon as
the scanner process exits (job-deadline watchdog, signals), and a
`KeyboardInterrupt` during collection kills them at once. Worker crashes, invalid result schemas and output above the 16 MiB JSON
transport limit make the scan incomplete. There is no automatic thread fallback.

Process mode is lifecycle isolation, not a security sandbox. Workers inherit the
scanner's privileges and environment, and killing one does not undo remote
changes, completed cache/export writes, or terminate its independently spawned
descendants. Continue to use an external job deadline and disposable workers
with appropriately restricted credentials and filesystem/network access.
Embedded Python entry points must use the usual `if __name__ == "__main__"`
guard for spawning. Plugin workers are daemonic and cannot themselves start
`multiprocessing.Process` children. See [connectors](connectors.md) for the
plugin execution contract.

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
Relative inventory globs and `options.workdir`, like other configured paths
(including `identity.jwt` `ca_bundle`), resolve beside the configuration file,
independent of the process directory.

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
retains TLS hostname checks. A well-known NAT64 address (`64:ff9b::/96`, what
a DNS64 resolver returns on an IPv6-only runner) is judged by the IPv4 address
it embeds; the local-use prefix `64:ff9b:1::/48` is always refused. HTTP proxies are unsupported; environment proxies
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
Metadata preflight also rejects common-directory and alternate-object
indirections, local `include`/`includeIf` configuration sections, internal links
and special files. Local `config` and `config.worktree` use confined reads with
a 1 MiB limit and a conservative UTF-8, single-line configuration grammar.
Ordinary sections, quoted or deprecated dotted subsections, comments and
single-line values work; unsupported section syntax, continuations and multiline
values make coverage incomplete before Git starts. Inputs must remain immutable
while Git runs; preflight is not a filesystem snapshot or process sandbox.
Unsupported versions and failed metadata reads, including unavailable history
objects, make the scan incomplete while preserving code findings.

Incremental scans with `use_git: true` run the same bounded preflight before
Git fingerprinting and cache reuse, within the connector deadline. Unsafe
metadata disables reuse; the full scan retains source findings and reports
incomplete coverage. Updating the scanner invalidates previous cache entries
through its source digest.

Metadata commands disable hooks, lazy fetching and every transport. Authenticated
cloning uses a separate HTTPS-only policy. Remote JSON fields such as
`_local_path` cannot select local scan roots or substitute for a verified offline
record. Use fresh disposable workers and immutable inputs; these controls do not
turn Git or the scanner into a process sandbox.

## Resource limits and incomplete scans

Record dumps are JSONL and obey offline replay's 4 MiB encoded-byte line limit,
including the newline. Each connector export also obeys the smaller of its
`max_input_file_bytes` and `max_input_bytes` limits: 32 MiB by default. The hard
file ceiling stays 64 MiB. Export-size and strict-JSON serialization rejections
make the scan incomplete while preserving valid original records for analysis.
Sanitizer safety-limit rejections skip the unsafe record and make the scan
incomplete. Any of these rejections aborts dump publication and preserves a
prior file; the manifest marks the new export `exported: false`.
A partial dump is not complete evidence. Use smaller collection scopes or raise the
configured file/total limits within their hard ceilings when appropriate.
The line limit is fixed, so a single oversize record requires an upstream
export with bounded records rather than a larger file limit.

Shared HTTP JSON responses are streamed and limited to 16 MiB of decoded
content by default. Each network attempt has a response-acquisition budget of
twice the client timeout (60 seconds by default), covering connection, request
transmission, status line and headers. TCP candidates and TLS handshakes share
the remaining acquisition time. The active socket is interrupted on expiry;
the watchdog is cancelled and joined before the response can leave its checked-out
connection. System DNS is synchronous and cannot be forcibly cancelled: late
resolution is rejected before connection, but needs a process/job supervisor
for a hard time limit.

Each response body has a separate budget of twice the client timeout.
The 30-second client timeout also bounds individual socket reads, so without
these budgets a server sending a byte just inside every timeout could hold a
worker until the connector deadline abandoned it. A body still being read at the deadline is
aborted (`HTTP response exceeds the read deadline`) and the connector's
collection is incomplete (exit 3); a partial body is never analyzed. The
budgets follow the client's timeout, not a `timeout` passed with one
request. Retries and redirects each get a fresh acquisition budget:
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

`code.filesystem` reserves incomplete coverage (exit 3) for content it would
have read. Since the model-identifier and corroboration changes of the next
release, the remaining lockfile names and generated files (`*.log`, `*.har`,
`*.snap`) joined the default `oversize_skip_globs`, so such a file over
`max_file_size` is skipped with a warning and leaves the scan complete. Change
logs are deliberately not on that list: a name glob such as `CHANGELOG*` would
also match source files (`history_store.py`, `changes.ts`) that a scanned
repository names freely. With `scan_secrets: false`, an oversize documentation
file (`.md`, `.txt`, a `CHANGELOG.md` included) and, without `include_tests`,
an oversize file under a test or fixture path (a recorded cassette) are skipped
with a warning; with credential detection on (the default) they are read for
credentials below the limit and stay a coverage gap above it, so no planted key
is lost to an exit 0. A repository with a change log over `max_file_size`
therefore still exits 3 under the default settings; raise `max_file_size`, or
review the file and list its path in `oversize_skip_globs` (the setting
replaces the default list, so keep the defaults beside it). `strict_coverage`
keeps every skip outside the globs a gap. See the [coverage policy](scanning.md#large-and-generated-files).

The code scanner's IaC wildcard-action and agent front-matter patterns run on
the bounded regex engine under the same per-input matching budget as the
signature patterns, so a planted file costs at most that budget and is
reported as an incomplete file rather than holding the connector. The crawler
user-agent discount tokenizes only lines naming `mozilla/`, in linear time, so
a planted file of escaped quotes cannot hold the connector either. Symbolic
links count toward `max_files` together with regular files. A checkout with
more links than the remaining `max_files` budget needs a larger `max_files` or
an `exclude` entry for the link directories. The walk lists a root's entries
before it scans them in priority order; listing, including the checks of file
and directory links, stops after half of the time in which a file can still
start, with the error `connector deadline: listing stopped after N entries`,
so the listed files are still scanned and their findings kept. The link-check
error `connector deadline reached while checking symbolic links` remains as a
backstop at the deadline margin. The scan is incomplete (exit 3). A root that
starts when no file can start any more, such as a late repository of an
organization scan, lists nothing (`after 0 entries`), so it cannot run the
connector past its deadline and discard the findings of the roots scanned
before it. A tree whose listing alone takes more than that half is reported
incomplete even when the former interleaved walk would have finished in time;
raise `connector_timeout_seconds` for such a tree.

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
worker threads (the default backend) cannot safely be killed: a blocked SDK call can continue after
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
terminates the scanner with exit `3`, without guaranteeing a final report. It first
stops in-flight `git clone` process groups and deletes their temporary checkouts (best
effort, bounded to a few seconds); SIGTERM, SIGINT and SIGHUP do the same before the
scanner exits. SIGKILL and OOM kills cannot, so keep the external job deadline and
process-group or container cleanup. A blocked output stream cannot delay that exit. Completed CLI
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
inspect and files it analyzes by name but cannot read as text (binary content
with dense NUL bytes, mostly invalid UTF-8, or UTF-16 or UTF-32 without a byte-order mark; a few stray NUL
bytes or invalid bytes in otherwise valid text do not count) make the scan
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

## Release verification

### Merge gate and review status

The [versioned policy and activation procedure](operations/merge-policy.md)
retain the existing required checks and add `CI gate`, bind them to GitHub
Actions, and require fresh non-author approval with no bypass actors. Use
`python -m tools.governance_check RULESET_JSON` on a fresh API snapshot before
relying on enforcement. Neither the policy file nor this checker updates live
repository administration settings.

Ruleset
[23913372, Require CI and CodeQL](https://github.com/aisecnomad/Project-Nexus/rules/23913372)
is configured to require `test (3.11)`, `test (3.12)` and `analyze`, an
up-to-date branch, and one approving review from a reviewer with write access,
alongside `Protect main`. Add the new aggregate `CI gate` to that required-check
list without removing the existing checks or approval rule. Its enforcement
state has changed more than once during 2026-09: the 2026-09-24 review recorded
it disabled; on 2026-09-25 (13:10 UTC) a merge attempted without an approving
review was refused with "Repository rule violations found", so it was enforced
at that moment; on 2026-09-27 (10:40 UTC), and again on 2026-10-01 during the
discovery review, both rulesets were read back with `enforcement: disabled`.
The October 1 branch response also reported `protected: false`. During the
October 2 hygiene review, both rulesets were read back as `enforcement: active`
and the branch response reported `protected: true`. `Require CI and CodeQL`
retained one required approval, stale-review dismissal, strict checks and no
bypass actors; its required checks still omitted `CI gate`. `Protect main`
separately retained administrator and integration bypass actors. Treat no
observation as permanent; only the live commands below describe the current
state. Keep the CodeQL job's displayed name `analyze` consistent with the
required check.

Both rulesets were read back active on 2026-10-01 (updated 17:30 UTC).
`Require CI and CodeQL` requires one approving review of the final revision
with stale reviews dismissed, the strict required checks `test (3.11)`,
`test (3.12)` and `analyze`, CodeQL alert gating and signed commits, and lists
no bypass actors; `CI gate` is not yet among its required checks. `Protect
main` adds linear history and deletion protection and still names bypass
actors. At 08:05 UTC on 2026-10-02 both rulesets read back as
`enforcement: disabled` again (last updated 04:28 UTC), and
`GET /repos/aisecnomad/Project-Nexus/rules/branches/main` returned no active
rules, so nothing enforced review, CI or linear history on `main` at that time.
At 19:08 UTC on 2026-10-02 both again read back as `enforcement: disabled`
(last updated 18:39 UTC) with no active rules on `main`. The committed
snapshots in
[`.github/rulesets/observed/`](https://github.com/aisecnomad/Project-Nexus/tree/main/.github/rulesets/observed)
record the 04:28 UTC state.
On 2026-10-03 (19:06 UTC), both rulesets read back active again. The review/CI
ruleset still omitted `CI gate` and application bindings on its three required
checks, and still had `require_last_push_approval` and
`required_review_thread_resolution` disabled. `Protect main` retained four
bypass actors. These observations do not meet the versioned desired policy;
the weekly read-only audit will fail until matching administrator updates are
applied and verified with a complete API response. If GitHub withholds bypass
actors from the read-only workflow token, it will remain failed with unknown
assurance and an administrator must obtain the full readback.
On 2026-10-04, both rulesets read back as `enforcement: disabled` again,
and the `main` branch response reported `protected: false`. The available
GitHub connector exposes no administration-write operation; restoring the
reviewed policy and verifying exact readback requires an administrator.
On 2026-10-06 (23:50 UTC; both last updated at 20:16 UTC), both rulesets
read back `enforcement: active` in complete responses that included
`bypass_actors`, the `main` branch response reported `protected: true`, and
the classic branch-protection endpoint answered HTTP 404 `Branch not
protected`. `Require CI and CodeQL` requires one approving review with stale
reviews dismissed, the strict checks `test (3.11)`, `test (3.12)` and
`analyze`, CodeQL and code-quality gating and signed commits, and lists no
bypass actors; it still omits `CI gate`, the checks' application binding,
last-push approval and review-thread resolution. `Protect main` requires no
approval, adds linear history and deletion protection, and still lists the
administrator role and three integrations as `always` bypass actors. The
weekly audit keeps failing until the reviewed payloads are applied.

Classic branch protection is not readable through the app
integration. Read and retain the current configuration before changing it,
and compare it against the [versioned merge policy](operations/merge-policy.md):
`python -m tools.governance_check <snapshot.json>` reports every difference
with a fixed diagnostic code. The policy file is not applied automatically and
does not describe the live state; a repository administrator applies it under
**Settings → Rules → Rulesets**.

Do not claim that the full merge gate is enforced until readback confirms
`CI gate` is required. If the API connection lacks administration access, use
an authorized administrator session rather than weakening the rules.

Whatever the ruleset's state, the history is unchanged: the repository has a
single maintainer, and no change merged to `main` through 2026-10-02 (including
#42, #62, #65 and #123 to #133) carries an approving review from a second person;
the only approvals on merged pull requests are the maintainer's own, on two
Dependabot updates. A repository
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

The offline rules helper can prepare a reviewed PUT body from a fresh full
ruleset response. Use an administrator identity able to see `bypass_actors`;
GitHub can omit that field for identities without ruleset write access. Read
the default branch first and confirm it is `main`:

```bash
gh api repos/aisecnomad/Project-Nexus --jq .default_branch
gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 > /secure/main-rules-before.json
python -m tools.release.rules prepare --input /secure/main-rules-before.json \
  --output /secure/main-rules-update.json --repository aisecnomad/Project-Nexus \
  --default-branch main
# Review the generated body before this administrator operation.
gh api --method PUT repos/aisecnomad/Project-Nexus/rulesets/23913372 \
  --input /secure/main-rules-update.json
gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 > /secure/main-rules-after.json
python -m tools.release.rules verify --input /secure/main-rules-after.json \
  --output /secure/merge-rule-verification.json --repository aisecnomad/Project-Nexus \
  --default-branch main
```

Preparation activates the same ruleset and tightens it to the versioned minimum
policy: all four required checks are bound to the GitHub Actions app, final-push
approval and review-thread resolution are required, deletion is blocked and
CodeQL errors remain blocking. It retains additional checks and stronger rules,
pins an unbound required check and refuses a conflicting nonempty app binding.
It also refuses missing independent approval or stale-review dismissal,
ambiguous branch scopes, nonempty or unavailable bypass lists and malformed
settings. Generate the body from current settings rather than from an older
snapshot, so that later administrator changes are not overwritten, and compare
it with the [versioned merge policy](operations/merge-policy.md). The verifier
checks a supplied settings snapshot against the same minimum policy as the
governance checker. The release workflow obtains its snapshot
directly from GitHub; an offline receipt cannot authenticate its own API origin,
establish historical enforcement or prove an actual human approved the final PR.

The [two-ruleset payload helper](https://github.com/aisecnomad/Project-Nexus/tree/main/tools/governance)
additionally prepares `Protect main` and `Require CI and CodeQL` together,
removing bypass actors from both. The observed snapshots and proposed PUT
bodies are in [.github/rulesets](https://github.com/aisecnomad/Project-Nexus/tree/main/.github/rulesets).
The committed observed snapshots capture disabled rulesets. Refresh
those observations and regenerate the bodies before applying them; the files
are preparation, not evidence of active enforcement. After administrator PUTs,
compare each fresh full API response against its exact approved body:

```bash
python -m tools.governance.rulesets plan --ruleset-id 23892853 \
  --input /secure/protect-main-before.json --output /secure/protect-main-update.json
python -m tools.governance.rulesets plan --ruleset-id 23913372 \
  --input /secure/main-rules-before.json --output /secure/main-rules-update.json
# Apply each reviewed body to its matching ruleset through an administrator.
python -m tools.governance.rulesets verify --ruleset-id 23892853 \
  --input /secure/protect-main-after.json --expected /secure/protect-main-update.json
python -m tools.governance.rulesets verify --ruleset-id 23913372 \
  --input /secure/main-rules-after.json --expected /secure/main-rules-update.json
```

An approving review counts only when it comes from a person with write access,
other than the author, and covers the final revision of the pull request. A
successful workflow run or Copilot review does not supply that approval. A
single maintainer cannot approve their own PR: recruit a second eligible human
reviewer rather than weakening the rules to self-merge. Recheck the live ruleset
and pull request status at release time.

The CI workflow installs hash-locked runtime, build and core/development
dependency sets and validates signatures, lint, typing, dependency advisories
(including the documentation lock), tests, wheel creation, installed-wheel
validation outside the source checkout and offline SARIF output. The Linux
Python 3.11 job traces coverage and enforces a minimum of 80% overall and 75%
for each module under `shadowscan/connectors/`, both counting statements and
branches, so a well-tested engine cannot conceal an untested provider; the
other jobs run the same tests untraced. Coverage proves execution of code paths in tests; it does not prove
provider compatibility or complete tenant inventory. The aggregate `CI gate`
requires every Linux and macOS matrix job, documentation and container security to succeed; it also
requires DCO on every pull-request commit, including merge commits that can
introduce authored conflict resolutions. It fails if a required prerequisite fails, is
cancelled or is unexpectedly skipped. Verify that the live ruleset requires
`CI gate` before treating the full matrix as an enforced merge gate. The dedicated
container job builds one Docker image and checks its non-root UID, signature assets
and network-isolated scan with a read-only root filesystem and resource limits.
It also requires the expat that the image's Python uses to parse every XML file
read from a repository to be 2.8.5 or newer, and the build fails if any file
keeps a setuid or setgid bit.
It inventories that exact local image with a CycloneDX SBOM and blocks HIGH or
CRITICAL OS and Python vulnerabilities, including unfixed findings, and lists each
blocking finding in the job log. It records
the image ID, source revision, pinned scanner and fresh vulnerability database
identities; scanner errors also block the gate.
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

## Credential evidence identity migration

Code and cloud credential evidence now carries `credential:hmac-sha256:`
pseudonyms made with a domain-separated HMAC and a private key. A report reader
cannot check guessed low-entropy credentials against a public hash. Each Engine
scan supplies one random key shared by its workers, so identical credentials
within that scan have identical pseudonyms. Without an operator key, another
scan produces different credential pseudonyms. Direct calls to the library's
`credential_id()` or `redact()` outside an Engine use an ephemeral process key.

For stable credential correlation between scans, provide the existing
`SHADOWSCAN_IDENTITY_KEY` through a private secret environment: at least 32
random secret bytes, explicitly encoded as `hex:<value>` or `base64:<value>`.
Ambiguous bare encodings, including ordinary 64-character hex keys, now fail
before collection; prefix an existing hex key with `hex:` to preserve its bytes.
Use the same key for the scans being compared. The key also governs gateway
pseudonyms, so rotating it changes gateway identities too. Keep the key out of
configuration files, logs, command-line arguments and shared reports. No key is
generated into persistent storage automatically, and scan reports/export/cache
files never contain it.

The report's `collection_scope.credential_identity_schema` is
`shadowscan.credential-identity/v1`; `credential_identity_scope` is `run` or
`keyed`. Resource-based finding IDs still identify the same source observation;
the credential pseudonym in its evidence has the key's scope. Without a stable
key, incremental scanning does not persist results containing credential
pseudonyms, while clean inputs remain cacheable. With a stable key those
results may be reused. Cache format 4 and private key commitments invalidate
older entries or entries generated under a different key. Key rotation also
changes the collection-scope fingerprint, so `diff` cannot claim resolution
across that change; establish a fresh baseline.

Regenerate reports and baselines made with previous candidate builds. Their
`credential:sha256:` values cannot be converted to the new pseudonyms without
rescanning the source credentials. Restrict or delete the old copies and
rotate exposed low-entropy credentials if their digests were disclosed.
Existing gateway correlation mappings using private `credential:sha256:` exact
bindings remain compatible. Those legacy binding values are private and never
enter gateway reports; gateway public identities retain their existing domain
and behavior. Reports still contain sensitive audit evidence and business data.

Synthetic code/cloud, cache, comparison, gateway-binding and publication
regressions validate these behaviors. They do not establish independent human
review or live tenant acceptance.

## Unreleased changes

Incremental scans preserve exact Git filenames, including whitespace. Agent
classification continues to require semantic verification or corroboration of
lexical source matches even for signatures with an agent-indicator flag.

`shadowscan code PATH --diff-base REF` scans only the files committed since the
merge base with `REF`, plus dependency manifests, `.env*` files and coding-agent
settings files. Use it for
pull-request feedback, not as an inventory: its report is not comparable, so a
pipeline that keeps the last report as its `shadowscan diff` baseline sees
earlier findings as unknown, never resolved, and `--incremental` does not reuse
it. Uncommitted, untracked and submodule changes are not scanned. Keep a full
scan of the default branch as the comparison baseline. The option needs Git
2.45 or later; when the diff cannot be computed the connector warns and scans
the whole tree.

An unexpected connector failure, and an unexpected failure while scanning one
`code.github` or `code.gitlab` repository, reports the exception text only when
ShadowScan code raised it; those messages are fixed or already sanitized. An
exception raised inside a third-party SDK or plugin reports only its type
(`code.github: acme/app: RuntimeError`), because its text can echo request data
or opaque credentials that redaction does not recognize. The scan is still
incomplete (exit 3). Alerting keyed on SDK exception text should key on the
connector name and exception type.

Plugin approvals can pin the import target (`--allow-plugin
name=module:Class`); a pin binds the import path, not a version or file hash,
so keep installing plugins from reviewed, hash-pinned requirements. Give JWTs
and connector credentials through files, stdin or `${ENV_VAR}` references:
the CLI warns, but still runs, when they arrive as arguments. Incremental
cache entries are authenticated only when a stable identity key is
configured; without one, keep the state directory writable only by the
scanner account.

## Candidate change history

These notes record unreleased corrections and earlier candidate changes.
Read them when you have baselines, reports or inventories produced
by an earlier candidate build; a deployment that starts from a reviewed
revision and a fresh baseline does not need them.

### October 10 drift classes and baseline lifecycle (unreleased)

This candidate adds drift classes, baseline pinning and expiry to
`shadowscan diff`, and the weekly [drift templates](operations/drift.md). It
does not change the published 0.1.2 artifact, create a release, or establish
live tenant acceptance. The class rules and fixtures are synthetic and
author-written.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Comparison fields | `diff` also compares `metadata.autonomy` floor, ceiling, oversight and initiation, `metadata.tool_definition_sha256` and `metadata.registry_reconciliation.status`. A finding whose only difference is one of these is now `changed`. Finding identity and the scope fingerprint are unchanged. | Expect `changed` entries that earlier builds did not report, for example an MCP tool whose definition changed. Consumers that count `changed` should not treat the increase as a regression in the scanner. |
| Report import | Reading a report for `diff`, `merge` or `inventory stubs` rejects (exit 1) a finding whose `metadata` is not an object, or whose value at one of those paths is malformed. | Regenerate edited or hand-built reports; reports this scanner wrote are unaffected. |
| JSON output | Each change carries `drift`; the document carries `drift_summary`, `adverse` and `baseline` (`sha256`, `pinned`, `age_days`). Existing keys and `changed_fields` names are unchanged. | Consumers that require an exact key set must accept the new keys. |
| Gating | `--fail-on-drift CLASSES` exits 2 on adverse drift in a listed class. An incomplete comparison still exits 3, and `coverage` never yields 2. `--fail-on-new` is unchanged. | Start with `inventory,capability,autonomy,governance`, and review which changes the [class table](operations/drift.md#drift-classes) treats as adverse before gating on it. |
| Baseline lifecycle | `--baseline-sha256` refuses (exit 1) a baseline whose raw bytes differ from the pinned digest. `--max-baseline-age-days` makes an expired or undatable baseline, or one that started after the current scan, incomplete (exit 3). | Store baselines in a private baseline repository, accept drift by reviewed pull request, and pin `sha256sum baseline.json`. Disable line-ending conversion for the baseline file. A replayed report is dated by the replay, not by the collection. |
| Mitigating tags | Removing `disabled`, `inactive`, `suspended`, `expired`, `asks-user`, a `*-code-only` or `docs-only` scope tag, `pending-request`, `managed-secret` or `mcp-registry-published` is adverse capability drift; adding one is not. | Expect exit 2 from `--fail-on-drift capability` when an agent is enabled again or an app is restored, and none when one is disabled. |
| Fleet start time | A fleet's `started_at` is the earliest source start compared as instants. Any source without a valid timezone-aware start makes it `null` instead of the merge time. | A fleet baseline with an undated source makes `--max-baseline-age-days` exit 3. Regenerate its sources, or merge only dated reports. |

A pinned digest shows only that the baseline file is the reviewed one. The
drift classes record what changed between two reports. They do not prove that
a change is malicious or benign, and they are not a measured detector.

### October 10 fleet shadow status and triage budget corrections (unreleased)

This source candidate corrects fleet merging and bounds LLM triage. It does not
change the published 0.1.2 artifact or create a release. Select and review a
new full commit SHA before deploying it.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Fleet merge | A merged finding is `shadow: true` only when a source found it unregistered, `false` when a source matched it to its inventory, and `null` when no source that reported it had an inventory. Earlier candidates reported every finding of inventory-less sources as shadow. The merged report carries `inventory_present`; a non-boolean value in a source is refused. | Re-merge fleet reports built from scans without an inventory before alerting on `shadow: true` or comparing shadow counts. Supply an inventory to the source scans when registration status is required. |
| Registration claims | A scan without an inventory or trusted registries now clears the `shadow`, `registry_match` and match metadata a connector or plugin set, instead of passing them through. A merge reads `shadow` and `registry_match` only from sources whose `inventory_present` is true, treats `shadow: false` without a match as unassessed, and makes a finding that sources matched to different agents ambiguous (`shadow: true`, `registry_match_reason: ambiguous-resource-approval`) instead of keeping the first source's match. | Expect `shadow: null` where only inventory-less sources claimed a registration, and `shadow: true` for findings that different source inventories registered to different agents; give each object one agent id across the fleet's inventories. |
| LLM triage | One triage run is limited by `options.llm_triage.budget_seconds` (default 300) and stops after three consecutive failed requests; findings it does not reach are recorded as `status: skipped`. Under a CLI job deadline, triage ends 10% of the deadline before it (5 to 60 s) or is skipped, so it no longer uses up the time reserved for writing the report. A reply longer than 16 KiB is refused unread (`status: unparseable`; the response body is capped at 64 KiB), and an unexpected request error is recorded as `status: failed`. | Raise `budget_seconds` together with `max_findings` if later findings are now skipped. Triage remains advisory and never changes risk, shadow status, completeness or `--fail-on`. |
| Container CI | The CI container job pulls the Dockerfile's digest-pinned base image through the `mirror.gcr.io` Docker Hub cache. | None for deployments: the image content is fixed by the digest. See [the worker image notes](#install-from-a-reviewed-revision). |

### October 10 threat and control references (unreleased)

This source candidate changes the report schema. It does not change the
published 0.1.2 artifact, create a release, or establish independent review of
the mappings. Select and review a new full commit SHA before deploying it.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Report schema | `metadata.compliance` is removed. Findings carry `metadata.threats` (OWASP LLM and Agentic 2026, MITRE ATLAS 2026.09, MAESTRO layers) and `metadata.controls` (NIST AI RMF 1.0, ISO/IEC 42001:2023, EU AI Act, AIUC-1), as edition-qualified references such as `owasp-llm-2026:LLM03`. Several earlier references named the wrong entry. Disclosure and unsecured-credential references need an exposure tag; a credential in a managed secret store or an encrypted CI secret is referenced only as an identity. SARIF rule tags and properties, HTML, Markdown and CycloneDX output change accordingly. | Switch SIEM, ticketing and dashboard consumers from `metadata.compliance` to the new keys and their prefixes. Do not translate old identifiers one to one; several were wrong. The references are evidence references and author mappings, not compliance determinations or reviewed control assessments. |

Finding identity, risk scores and `diff` change detection are unchanged: the
references are derived at export and never read back, so a baseline from an
earlier candidate compares without reporting the rename as drift. Validate the
packaged catalogs with `python -m shadowscan.mappings.validate` after
installing a candidate; see [threat and control mappings](concepts/mappings.md).

### October 10 vendor registry records and trusted registries (unreleased)

This candidate adds the vendor
[registry record contract, reconciliation statuses and trusted registries](inventory.md#vendor-registries-as-inventory-sources).
No built-in connector reads a vendor registry yet, so existing scans emit no
records. It does not change the published 0.1.2 artifact, create a release, or
establish live tenant acceptance; the tests use synthetic records.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Inventory source | `options.trusted_registries` (empty by default) lets approved records of the listed registry instances approve findings by exact resource. Shadow status changes only when it is configured. | Before trusting a registry, confirm who can approve records in it: its approval becomes organisational sanction for every resource it binds. Keep the setting in reviewed configuration outside scanned checkouts. |
| Report fields | `metadata.registry_reconciliation` on records and on the observed findings they match or that a complete listing omits. With trusted registries alone, `inventory_present` is true and findings get `shadow: true` or `false`; `inventory_size` counts the approved records of trusted registries. | Consumers that read metadata must tolerate the new key. Rebaseline reports when you first set `trusted_registries`: `shadow` and `registry_match` change. |
| Confidence threshold | Registry record findings (confidence 0.5) are kept whatever `min_confidence` is. Earlier candidates dropped every record above a 0.5 threshold while the approvals those records conferred stayed in force. | Expect record findings in reports filtered above 0.5; filter them by `resource_type` downstream if needed, not by confidence. |
| Completeness | Malformed `registry_record` metadata makes the scan incomplete (`engine.registries`, exit 3). A trusted registry without records in the scan is an advisory `engine.inventory` warning. | Treat exit 3 as unknown coverage. Resolve the advisory warning before relying on that registry's approvals. |
| Connectors and plugins | Records count only from built-in connectors that declare the `emits_registry_records` hook; `registry_record` from any other connector, including a plugin that declares the hook, is dropped with a stats warning. | Third-party connectors cannot emit records. |
| Offline replays | Records replayed from an offline export (a connector with `input`) still reconcile but no longer approve: earlier candidates counted them like live records, so a forged export line could sanction any runtime it bound. The engine records which findings a job with `input` produced; a record also read live in the same scan counts as replayed. A trusted entry accepts them only with `allow_offline_records: true`, and a replayed record that would otherwise approve is counted in an advisory `engine.inventory` warning (`N offline-replayed ... record(s) were not treated as sanctioned`). | Expect `shadow: true` and a lower `inventory_size` for findings approved only through replayed records. Set `allow_offline_records` only for a registry whose exports only operators can write; otherwise scan it live. |
| Approval rules | A card and a trusted record approving the same finding are ambiguous and leave it shadow, the record finding itself included (earlier candidates registered a record finding before inventory matching, so a card approving it as well was ignored); bindings of one record that cover the same finding are one approval. A record finding is registered under the same fail-closed identity rules as any finding, so one with a redacted resource stays shadow. A revoked, rejected or deleted record stops approving on the next scan. | Approve each object in one place: remove card bindings that duplicate trusted registry bindings. |
| Reconciliation statuses | Only `approved`, `registered` and `pending` records register what they bind. A `draft`, `rejected`, `deprecated`, `blocked` or `unknown` record is `not-comparable` (`reason: record-status`) and no longer makes the agent it binds `registered-and-observed`, so with a complete listing that agent is `observed-not-registered` and the `registry-gap` control rule applies. AWS registries report absence only for AgentCore runtimes and gateways, the only resources their records bind: a Bedrock agent in the same account is no longer `observed-not-registered`. | Rebaseline reports that consume `registry_reconciliation`: agents bound only by rejected, deprecated or draft records change status, and Bedrock agents lose a status they should not have had. |
| Approval policy | Only approved records with `approval_mode: manual` approve by default; auto-approved records and approved records whose approval mode is unknown approve only with `allow_auto_approved`, and registered-only records only with `allow_registered_only`, on the trusted entry; caller-scoped listings are never complete; `entra-agent-registry` cannot be trusted; a connector keeps only records of the registry types it declares. | Leave both switches off unless a person reviews records in that registry by other means: auto-approval and registration are not human review. |

### October 10 MCP registry provenance and approved MCP catalogs (unreleased)

This candidate adds [MCP registry snapshots](getting-started/configuration.md#mcp-registry-snapshots)
and [MCP registry provenance](connectors/code.md#mcp-registry-provenance). It
is opt-in: without `options.mcp_registries` reports, scores and collection
scope fingerprints are unchanged. It does not change the published 0.1.2
artifact, create a release, or establish live tenant acceptance; the tests use
a synthetic snapshot shaped like the live API.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Configuration | `options.mcp_registries` lists up to 16 snapshots, each with an `id`, a `snapshot` path and the `sha256` of the file; `approved: true` marks an approved MCP catalog. | Produce snapshots with `shadowscan mcp-registry snapshot` where direct HTTPS egress to the registry is allowed: the shared HTTP client refuses proxies. Review a snapshot before pinning it, keep it and the configuration outside scanned checkouts, and pin the printed SHA-256; a new snapshot needs a new pin. |
| Completeness | A snapshot that is missing, a symbolic link, changed, larger than 256 MiB, not strict JSON, not `complete`, of another schema or API version, or that has an invalid entry (structure, name, version, status or latest flag) is not used and the scan is incomplete (`engine.mcp-registry`, exit 3). A package or remote URL no configured server could match (templated, with user information, unparseable, on another package registry) is not indexed and does not reject the snapshot. | Treat exit 3 as unknown coverage. The `mcp-unpublished` tag and the governance factor are withheld while a registry that could list the server failed to load. |
| Report fields | MCP servers carry `registry` entries, and a server that sets a working directory or environment file carries `launch_context` (the field names, never their values); `mcp-server` findings carry `metadata.mcp_registry` and the review tags `mcp-registry-published`, `mcp-unpublished`, `mcp-registry-deprecated`, `mcp-registry-deleted`, `mcp-registry-version-unpublished` and `mcp-registry-outdated` with zero-weight evidence. CycloneDX MCP services gain `shadowscan:mcp:registry-*` properties. Finding identity is unchanged. | Consumers that read metadata or tags must tolerate the new values. Publication says who published a server, not that it is safe: review a published server like any other. |
| Identity | A server is matched only by what its client fetches or connects to: a command by its launched package, a URL by itself, a `server.json` manifest by every package and remote it declares; one identity, no fallback to another field. A launch with a source-changing option or environment variable (`--registry`, index flags, `--with`, `--pip-args`, `--entrypoint`, an unknown option; `npm_*`, `NODE_*` other than `NODE_ENV`, `BUN_*`, `YARN_*`, `UV_*`, `PIP_*`, `PYTHON*` other than output settings, `DOCKER_*`, `CONTAINERS_*`, `PATH`, `HOME`, `USERPROFILE`, `APPDATA`, `XDG_*`, `TMPDIR`, `LD_*`, `SSL_*`), a launcher named by a relative or UNC path, a `cwd` or `envFile` field, a `docker run` mount, working directory, `--env-file` or `-e` of such a variable, a `cmd /c` line or batch-file arguments with `%VAR%` or `!VAR!`, an npm alias or Git/URL/file source, a URL with user information, or both a command and a URL (whatever the transport) has no identity (`mcp-registry-unidentified`, `metadata.mcp_registry.unidentified`). A package several names of a registry list is approved only by a version that lists it, other than as deleted. A manifest's own name gives hints only. A repository `.npmrc`, `bunfig.toml`, `.yarnrc.yml`, `uv.toml` or `pip.conf` is not read. | Expect servers launched through such options, and Windows forms (`npx.cmd`, `cmd /c npx`, now recognized), to change matches. Containerized servers that mount a directory, and servers with a `cwd` or `envFile`, become unidentified and count against an approved catalog: a mount or working directory can replace what runs. Keep launchers on the PATH or at an absolute path, and set registries in operator-owned configuration, not in the server entry. A catalog package with a non-public `registryBaseUrl` approves no launch: list it without one to approve the name wherever clients resolve it. |
| Risk | The registry tags weigh 0. Only an approved registry scores: `mcp-not-in-approved-registry` (15, a governance factor excluded from `danger_score`) applies when every approved registry loaded and an enabled server is absent from all of them by its identity, listed only as deleted, or has no identity. | Expect higher scores for MCP configurations outside the approved catalog once one is configured, including servers launched from a local or relative path, a shell command, a source-changing launcher option or environment variable, a working directory, environment file or container mount; rebaseline risk-level gates. `mcp-insecure-transport` also applies to an `http://` URL whose authority holds a backslash or user information. |
| Comparison | With the option set, the collection scope fingerprint covers each registry's id, pin and approval flag. | Rebaseline `diff` comparisons when you configure or change snapshots; earlier baselines become not comparable. |
| Resources | Each scan loads every pinned snapshot. A full official listing (about 145,000 versions in October 2026, roughly 50 MB) takes a few seconds and a few hundred MiB of memory. | Size scan runners for the snapshots you pin; an organisation's own catalog is usually much smaller. |

### October 10 Google Agent Registry and Gemini Enterprise catalogs (unreleased)

This candidate lets `cloud.gcp` read Google Agent Registry and Gemini
Enterprise agents as [registry records](connectors/cloud.md#agent-registry-and-gemini-enterprise-catalogs).
Both catalogs are opt-in. It does not change the published 0.1.2 artifact,
create a release, or establish live tenant acceptance: the fixtures are
synthetic, written from Google's API discovery documents, and were not
validated against a live project.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Rollout | `agent_registry` and `gemini_enterprise` default to false; with both off and `discovery_collections` unset, `cloud.gcp` makes no new API calls, and findings change only as listed under finding identity and kinds below. Either option adds one `projects.get` call per configured project. `agent_registry_version: v1alpha` and the Gemini Enterprise assistants API are Google pre-GA (`v1alpha`) surfaces and may change without notice. | Enable one catalog in one project first and read the `cloud.gcp` warnings. Grant read access to Agent Registry and Discovery Engine assistants and agents; verify the role names in your organization. |
| Completeness | Every catalog listing records whether it completed. A denied, truncated or malformed listing makes the scan incomplete (exit 3), and so does replaying the record dump of such a scan. Such an Agent Registry listing makes that registry's listing incomplete, so it never yields `observed-not-registered`; such a Vertex AI or Dialogflow CX listing makes the coverage of bindings into it `unknown`, so no record bound there is `registered-not-observed`. Items read before the failure keep their records and still reconcile through their bindings. `agent_registry_locations` skips location enumeration, so that project's Agent Registry never yields `observed-not-registered`; neither does an Agent Registry with a record whose runtime reference names another project's resource, or names Vertex AI or Dialogflow in a form the scan cannot read (the latter also makes the scan incomplete). An unreadable record (including a publisher not named in the project and location it was listed in), anything else that makes an offline replay incomplete (such as an invalid JSON line or a provider error record that the loader drops), or a registry record or publisher whose name carries the number of a project other than the one it was listed in voids every completeness claim of the scan: no binding is in scope, no listing is complete and nothing is reported absent. | Treat exit 3 as unknown coverage. Leave `agent_registry_locations` unset where you need `observed-not-registered`. |
| Caller-scoped listing | Google documents the Gemini Enterprise agents list as the agents created by the caller. Its records are `listing_scope: caller` and never complete: absence from Gemini Enterprise is never reported, and no observed agent becomes `observed-not-registered` because of it. | Do not read a missing Gemini Enterprise agent as proof that none exists; scan with an identity that sees the app's agents. |
| Approval policy | Agent Registry has no approval workflow: its records are `registered` (`approval_mode: none`) and approve only with `allow_registered_only` on a trusted entry. Gemini Enterprise `ENABLED` agents are `approved` (`approval_mode: manual`) and, when the engine is trusted, approve exactly the reasoning engine or Dialogflow CX agent they bind in the app's own project. A record's reference to another project's engine or agent binds and approves nothing, even in a trusted registry; it is a `cross-project-reference` join hint. | Trust a registry by its exact id (`projects/<project-id>/locations/<location>` or the engine name). Trust one catalog per agent: two trusted records approving one engine are ambiguous and leave it shadow. An app or registry approves no runtime in another project: sanction such runtimes in the inventory or through a registry of their own project. |
| Finding identity and kinds | New record findings have their own identities. Discovery Engine engines keep their kinds: chat engines are `agent`, other engines, including Gemini Enterprise app engines (`appType: APP_TYPE_INTRANET`) of a search solution type, `cloud-resource`, which is never reconciled. Engines and reasoning engines gain optional metadata. Agent Registry counts as an AI API, so a project whose only AI API is Agent Registry gains an enabled-APIs finding. With a complete Agent Registry listing, observed reasoning engines, Dialogflow CX agents and chat engines in its own project that no record binds become `observed-not-registered`. Records bind only reasoning engines and Dialogflow CX agents, so a chat engine is never `registered-and-observed` through a record. | Expect a new enabled-APIs finding in projects whose only AI API is Agent Registry. Before treating an `observed-not-registered` chat engine as unregistered, check the reconciliation of the Dialogflow CX agent behind it. |
| Credential policy | Items are reduced when collected: no raw agent card, no interface URL userinfo or query, no icon, prompt, assistant instruction or authorization value reaches findings, warnings or record dumps. URLs from responses are never fetched with the scan credential. | Regenerate GCP record dumps with this build before replaying them; older dumps carry no catalog records. |

### October 10 AWS registry records in cloud.aws (unreleased)

This candidate lets `cloud.aws` read
[AWS Agent Registry and AgentCore registry records](connectors/cloud.md#aws-agent-registry-and-agentcore-registry-records)
as vendor registry records. It does not change the published 0.1.2 artifact,
create a release, or establish live tenant acceptance: the registry responses
and fixtures are synthetic, modeled on the installed SDK models, and were not
validated against a live account.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Rollout | New `services` value `registry`, off by default: `services` now defaults to every service except `registry`. Configurations that omit `services`, or list services without `registry`, make the same API calls and report the same findings as before. | Nothing changes until you add `registry`. Add it in a reviewed configuration change, and only after granting the permissions below. |
| Credential policy | With `registry`, the scan identity needs `agent-registry:ListRegistries`, `agent-registry:GetRegistry`, `agent-registry:ListRegistryRecords` and `agent-registry:GetRegistryRecord` (AgentCore registries use the existing `bedrock-agentcore:List*/Get*`); `registry_arns` adds `agent-registry:ListDiscoverableRegistryRecords` and `agent-registry:GetDiscoverableRegistryRecord` on the listed registries. A missing permission is a denial that makes the scan incomplete (exit 3). | Grant only these read actions; do not grant `agent-registry:InvokeRegistryMcp` or `Search*`. Expect exit 3 until every scanned region and registry is readable. |
| Finding identity | One finding per registry record: resource = record ARN, resource type `agent-registry-record` or `agentcore-registry-record`, stable across status changes. Records from `registry_arns` keep the registry's account instead of being marked `identity_unresolved`. | Re-baseline when you enable `registry`: the record findings are new, and reconciliation can add `registry_reconciliation` to existing AgentCore runtime and gateway findings of the scanned account (`registered-and-observed` for runtimes and gateways an approved, pending or registered record binds, `observed-not-registered` for the other runtimes and gateways when a registry's listing is complete). |
| Approval semantics | Records carry `approval_mode` from the registry's auto-approval settings when the scan reads them, not from how each record was approved (`auto` whenever an auto-approval setting is on, even beside a setting this release does not know; `unknown` when the registry details were denied, always for `registry_arns` records, and for an unrecognized configuration, which also makes the scan incomplete). An auto-approved record, and an approved record whose approval mode is `unknown`, approves through `trusted_registries` only with `allow_auto_approved: true`; by default only `manual` approvals count. Only the `DETECTED_FROM` provenance of a record the registry created by auto-detection binds a runtime or gateway, and not while that record is still a `DRAFT` nobody submitted: provenance written through `CreateRegistryRecord` or `UpdateRegistryRecord` on a record created through the API binds nothing, and an unrecognized relation makes the scan incomplete. A binding is in scope only when the region's AgentCore collection recorded no warning or error and every runtime and gateway finding there could be reported. | Auto-approval is not human review. Leave `allow_auto_approved` off unless a person reviews that registry's records by other means, and trust a registry without it only if the registry has never auto-approved records: a record approved while a rule was on reports `manual` after the rule is removed, and one a person approved before a rule was added reports `auto` (its evidence says only that the registry currently approves records). Expect the runtime or gateway behind an auto-detected draft to read `observed-not-registered` when its registry's listing is complete. Trusting a registry means trusting everyone who can create, update or approve its records, since an update can change an auto-detected record's provenance. Trust a registry whose approval mode is unknown only when you know who approves its records. |
| Limits and exports | New `max_registry_records` (default 1000 per region and namespace); reaching it is incomplete. Exports keep only a sanitized descriptor summary (card capability and security scheme names redacted and cut to 64 characters), never raw descriptor documents or OAuth `customParameters`. Registry records carry `_listing_complete` and `_detail`, and each listing writes an `aws-registry-coverage` record, so a live gap that left no record behind (a denied listing or `GetRegistry`, an unsupported region, a missing SDK service, a used-up cap) replays as incomplete. | Raise the cap for large registries rather than accepting a partial listing. Regenerate exports to replay registry records: registry records without the coverage markers replay as incomplete (exit 3). |

### October 10 Microsoft Agent 365, Entra Agent ID and delegated Graph auth (unreleased)

This candidate lets `identity.entra` read the Microsoft Agent 365 package
catalog as a vendor registry, report Entra Agent ID agent identities and
authenticate as a signed-in user. Both collections are off by default, so
existing configurations collect what they did before. It does not change the
published 0.1.2 artifact, create a release, or establish live tenant
acceptance: the fixtures and Graph payloads in the tests are synthetic, modeled
on Microsoft's Graph reference pages, and were not validated against a live
tenant. See the [identity connector guide](connectors/identity.md#identityentra).

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Opt-in collection | `include_agent_registry` lists Agent 365 packages (`CopilotPackages.Read.All`; `agent_registry_api` `v1.0` or `beta`; detail calls capped by `max_package_lookups`). `include_agent_identities` lists agent identities from the Graph beta API. The new permissions are needed only when the switches are on. | Grant the permission before enabling a switch: a denied or unlicensed catalog makes the scan incomplete (exit 3), never empty. Beta API changes surface as malformed records and incomplete scans. |
| Finding identity | New resources `entra:copilot-package:<id>` (`copilot-package`), `entra:agent-registry-instance:<id>` and `entra:agent-registry-card:<id>` (offline only). A standalone agent identity is `entra:sp:<id>` with the same finding id as its service principal. Agent identities, and service principals and app registrations a package names, are reported even without AI signals, so enabling a switch can add findings for existing principals. | Rebaseline when you enable a switch: new findings are expected, and existing service principal findings gain the `entra-agent-identity` tag and agent identity metadata. |
| Registry records | Packages are `microsoft-agent-365` records with registry id `tenant_id`; deprecated agent registry records are `entra-agent-registry` and never approve. Only an organization's own package whose approval request was approved is `approved` with `approval_mode: manual`. An organization's own package (`custom`, `shared`, `lob`) with no request, such as an agent a user shared, is `registered` and approves in a trusted tenant only with `allow_registered_only`; `allow_auto_approved` does not accept it. Approved Microsoft and partner packages have `approval_mode: unknown` and approve in a trusted tenant only with `allow_auto_approved`. A package whose detail call failed, was throttled or was beyond `max_package_lookups` is `unknown` and binds nothing, since `requestStatus` comes from the details. A package binds `entra:sp:<agentIdentityId>` only for a listed agent identity, and `entra:app:<appId>` only for an organization's own package, so a vendor package cannot approve a tenant app registration or an ordinary service principal. A binding is `in-scope` only when no record of the export was rejected as malformed. | Trust a tenant (`trusted_registries`, registry `microsoft-agent-365`, id `tenant_id`) only when the packages allowed in its catalog are ones your organization sanctions. Set `tenant_id`: without it the records cannot be trusted. Set `allow_registered_only` only if unrequested organization packages, including ones users shared, are sanctioned in that tenant: no person approved them. |
| Credential policy | `auth_mode: delegated` reads a signed-in user's Graph token from the environment variable named by `delegated_token_env` (default `GRAPH_DELEGATED_TOKEN`); no configuration key holds the token. The tenant, Microsoft Graph audience (`aud` `https://graph.microsoft.com`, with or without a trailing slash, or `00000003-0000-0000-c000-000000000000`) and delegated claims are checked before any request; the token is never refreshed, logged, exported or reported, and app-only credentials are never used as a fallback. With `include_agent_registry` and `tenant_id`, a pre-issued app-only `access_token` (or `GRAPH_ACCESS_TOKEN`) must be a JWT whose `tid` is `tenant_id`; otherwise the connector is skipped. With either opt-in collection, a pre-issued token whose claims decode must have a Graph audience (otherwise the connector is skipped), and a token that is not app-only (`scp`, or no `idtyp: app`) or cannot be decoded gives caller-scoped listings and an incomplete scan with a fixed warning that names `auth_mode: delegated`. | Decide which operator signs in and with which role; a delegated scan sees only what that user may see. Do not put the token in configuration through `${VAR}`. Set the variable only for the scan: process-mode plugin workers inherit the environment. Expect exit 3 when the token expires during a long scan. With a pre-issued token and `include_agent_registry`, set `tenant_id` to the tenant ID the token was issued for, and clear stale `GRAPH_ACCESS_TOKEN` values. Pass a signed-in user's token through `auth_mode: delegated`, not `access_token`; request a token for Microsoft Graph, not another resource. |
| Comparison | Delegated package listings are caller-scoped and never complete, and their bindings have `unknown` coverage, so they produce no `observed-not-registered` or `registered-not-observed` statuses. A delegated scan with `include_agent_registry` or `include_agent_identities` always warns once and exits 3, even when the user sees nothing. Delegated and app-only scans cover different scopes. | Do not compare delegated and app-only scans for drift; keep `auth_mode` fixed for a baseline. Do not gate on a delegated scan's exit code: it is always 3 with an opt-in collection; use an app-only scan for gating. |
| Replay attribution | The coverage marker of a live collection records the tenant its credential is bound to (`tenantId`: the checked `tid` of a pre-issued or delegated token, or `tenant_id` for client credentials). A replay whose `tenant_id` differs from it is incomplete and its records get an empty registry id, so no trusted entry approves another tenant's packages. A caller-scoped export replays as incomplete too. An older export without `tenantId` replays as before, attributed to the configured `tenant_id`. | Replay an export with the `tenant_id` it was collected with. Re-collect older exports to record their tenant before trusting their records. |

### October 10 A2A Agent Card probe (unreleased)

This candidate adds an opt-in live probe to `endpoint.mcp` and a shared A2A
Agent Card projection. It does not change the published 0.1.2 artifact, create
a release, or establish live tenant acceptance: the cards, keys and HTTP
exchanges in the tests are synthetic, modeled on the A2A specification, and
were not checked against a live agent.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Egress | `endpoint.mcp` fetches the A2A Agent Cards listed in `agent_card_urls` (HTTPS only, same-origin redirects, 1 MiB, at most `max_agent_cards`, default 100) and, when set, the JWKS at `agent_card_jwks_url`. Private and loopback agents need `options.allow_private_origin`; `ca_bundle` trusts a private CA. Without `agent_card_urls` the connector is unchanged. | Allow egress only to the listed agent hosts and the JWKS host. Keep `allow_private_origin` off unless a configuration targets internal agents on purpose. |
| Findings | One `a2a-agent-card` finding per fetched card (`provider` `a2a`, identity `a2a-card`, resource the card URL without query). Every fetch, HTTP, JSON, size or card-validation failure is an error and the scan is incomplete (exit 3). | Treat exit 3 as unknown coverage of that agent. |
| Card projection | `code.filesystem` and the probe share `metadata.agent_card`: A2A 1.0 `supportedInterfaces` now supply `url` and `protocol_version` (earlier 1.x cards had `url: null`), interfaces are listed, and `signature` records `absent`, `present-unverified`, `verified` or `invalid`. Projected strings are bounded (200 characters; the description 300). An interface URL with user information or a backslash before its host is left out: HTTP clients can read another host from it. | Consumers that read `agent_card` must tolerate the new `interfaces`, `signature` and `signature_detail` keys. A card whose only interface carries user information has `url: null`. |
| Risk | New tags `a2a-plaintext-interface` (10; an `http://` or `ws://` interface to a host not known to be loopback, one with a backslash or user information before its host included) and `a2a-card-signature-invalid` (10), with threat references (ASI07; AML.T0118.001; ASI04). Existing card files with an `http://` interface or a malformed `signatures` entry score higher. | Rebaseline risk-level gates that cover A2A card findings. |
| Signatures | Verified only against `agent_card_jwks_url`, over the RFC 8785 canonical card without `signatures`: as served, without any empty string, array or object (the A2A Python SDK's form), or without empty members other than REQUIRED and `optional` A2A 1.0 fields (the specification's section 8.4.1 example). A verified card is projected and tagged as the form its signature covers, so empty values added after signing (an empty `securitySchemes` entry) change neither `security_schemes` nor `no-auth-declared`. Keys or key URLs named by a card are never used. A card holding an integer beyond 2^53, or signed by a signer that also drops `false` or `0` defaults and served with them, reports `invalid`. | Sign with the A2A SDK or the specification's rules. Do not read `verified` as approval: an A2A card never registers or approves a finding. |
| Protocol versions | A card declaring a `protocolVersion` other than 0.x or 1.x, on the card or an interface, is reported with a warning that makes the scan incomplete (exit 3), in `endpoint.mcp` and `code.filesystem`. | Treat exit 3 as cards read with field assumptions that may not hold. |
| Configuration | A job that sets both `input` and `agent_card_urls` is refused when the connector is built (exit 3); a replay never probes. | Keep replay jobs (`input`, optionally `agent_card_jwks_url`) separate from probe jobs. |
| Exports | `--dump-records` card records also withhold the userinfo of scheme-less `user:password@host:port` addresses. A replayed card that lost one reports its signature `present-unverified`. | None; live verification reads the card as served. |

### October 10 autonomy tiers and card schema version 2 (unreleased)

This candidate adds the [autonomy tiers](concepts/autonomy.md). It does not
change the published 0.1.2 artifact, create a release, or establish live tenant
acceptance. The classification rules and fixtures are synthetic and
author-written.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Report fields | Applicable findings carry `metadata.autonomy` (`shadowscan.autonomy/v1`: floor, ceiling, oversight, initiation, basis, and the declared level when an inventory entry sets one). Finding identity is unchanged. | Consumers that read metadata must tolerate the new key. Gate on the ceiling, not the floor, which is a lower bound. An L2 ceiling rests on recorded approval settings: configuration evidence, not proof of how a run behaves. |
| Capability Cards | Top-level `schema_version`; version 2 declares `autonomy_profile.level` (0 to 5). An out-of-range level, a non-mapping `autonomy_profile` or an unknown `schema_version` now fails inventory validation. Version 1 levels are ignored with an advisory warning. | Run `shadowscan inventory check` on every inventory before deploying. Review each card's level against the new scale before adding `schema_version: 2`; never copy an old number unreviewed. |
| Risk | Tag `autonomy-understated` (weight 10) when a declared level is below the observed floor. New `risk_weights.autonomy` group, zero by default. Other default weights are unchanged. | Expect higher scores only for registered findings whose declared level is understated; rebaseline risk-level gates that cover them. |
| Connector metadata | Coding-agent settings (code and endpoint) and Bedrock action-group confirmation record `metadata.approval_gate`; Azure Logic Apps record `metadata.trigger_types`. Claude Code allow rules in any settings file, a sandbox that auto-allows Bash and `PreToolUse` or `PermissionRequest` hooks make the gate partial. Endpoint replays keep only approval entries the settings reader could have written for that record; they drop any other entry and are incomplete. | Regenerate endpoint exports to include approval entries; older exports replay without them and keep the ceiling at L5. |
| Fleet merge | `merge` classifies each merged finding again and widens the interval to admit what every source's block admits (highest floor and ceiling, `bypassed` over `unknown` over `gated`); it refuses a source with a malformed block. | Rescan sources that the merge refuses. Findings from older reports are classified from the merged finding alone. |
| Fleet merge combinations and declared levels | The merged finding is classified with the widest oversight and initiation any source recorded, so the combination rules apply across sources: approval bypassed in one source and a schedule trigger in another now give floor L5 (`self-initiated`) instead of L4. A registered finding keeps the lowest level any source declares for its agent, so `autonomy-understated` no longer depends on the order of the reports; sources that matched different agents leave it ambiguous with no declared level. | Expect higher merged floors where sources recorded complementary evidence, and the understated tag in every argument order. Rebaseline gates on merged floors. |
| Inventory stubs | Stubs are `schema_version: 2` cards declaring the observed floor. | Review the generated level and set the approved one before moving a stub into the inventory. |

### October 10 attested live collection scope (unreleased)

This candidate lets live `cloud.aws`, `cloud.azure`, `cloud.gcp` and
`identity.entra` scans attest their
[collection scope](scanning.md#live-collection-scope), so `shadowscan diff` can
resolve findings between two complete live scans. It does not change the
published 0.1.2 artifact, create a release, or establish live tenant
acceptance: the provider responses in the tests are mocked and synthetic, and
nothing was validated against a live account, tenant, project or subscription.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Rollout | `collection_scope` is computed after collection. A complete live scan by one of the four connectors whose provider confirmed the principal is now comparable; before, every live comparison exited 3. Other live connectors, plugins and timed-out jobs are unchanged: never attested. | Live scans taken before this candidate carry no attested scope: collect a new baseline with the reviewed revision before gating on `diff`. Pin that revision: any scanner change changes every fingerprint. |
| Collection scope | The fingerprint covers each live entry's verified principal, non-secret requested options as resolved, partitions (regions, projects and locations, subscriptions) and every enumeration with its outcome. Detail calls, counts, identifiers and timestamps are excluded. Changing options, enabling an API in a configured GCP project, adding a service or region, or a region enabled under `regions: all` changes the fingerprint. `collection_scope.live` publishes each live record outside the fingerprint. | Expect exit 3 (`scope differs`) after any scope change and re-baseline deliberately. Read `collection_scope.live` to see which listing was denied, throttled or truncated. Do not pass connector-specific secrets through non-credential option names: a value the sanitizer would change fails closed (`configuration contains private comparison values`). |
| Credential policy | `identity.entra` reads `GET /organization` (`Organization.Read.All` or `Directory.Read.All` for application tokens, `User.Read` delegated); `cloud.azure` reads `GET /subscriptions/{id}` for configured subscriptions (covered by `Reader`). AWS and GCP use calls they already made. A denied verification is an advisory warning, the scan still completes, and its scope is not attested (`live principal could not be verified`). A reported tenant other than a GUID `tenant_id`, or another subscription than a configured one, stops the scan (exit 3). | Grant the organization read only where you need comparable drift. Set `tenant_id` to the tenant ID and `subscriptions` to the exact subscription IDs the credentials are meant for. |
| Finding identity | Unchanged. | None. |

What attestation proves: which principal, partitions and listings a scan
enumerated successfully, and with which options. It does not prove that the
account or tenant has no agents outside the enumerated APIs, services, regions,
locations or projects, that the credentials could read every object (a listing
returns only what they may see), or that another identity would see the same.
Delegated `identity.entra` scans, and those whose `access_token` is not a
decodable app-only token, are never attested, for that reason.
Without `projects`, `cloud.gcp` attests the discovered project set, as
`cloud.azure` does for listed subscriptions: a project the credentials lose
access to, or a new one, changes the scope (exit 3) instead of resolving
findings. Set `projects` or `subscriptions` for a stable drift gate. Comparing replays of record exports remains
possible; stage every replay at the same absolute `input` path and label, and
replay only exports whose `manifest.json` shows a complete run, because an
export is published even when its live run was incomplete
([record export replay](scanning.md#record-export-replay)).

### October 9 change-scoped scans, path context and new ecosystems (unreleased)

These `code.filesystem` changes move confidence, risk and kind, and add or
remove findings, against baselines from an earlier build. The default risk
weights changed (three new tags). Rescan and rebaseline before comparing;
`shadowscan diff` otherwise reports the differences as changed, new or
resolved findings.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Diff-scoped scans | `--diff-base REF` scans committed changes since the merge base plus dependency manifests and `.env*` files; the report is not comparable and never cached. | Keep a full scan of the default branch as the comparison baseline. Do not gate inventory or resolution on a diff-scoped report. |
| Path context | Evidence in documentation or example directories inside a project has half weight, generated files (`*_pb2.py`, `*_pb2_grpc.py`, `*.generated.*`) 0.4. A project with no other evidence is tagged `docs-only`, `example-code-only` or `generated-code-only`, capped at 0.85, 0.85 or 0.7 confidence and scored 8, 8 or 10 lower. A directory that is itself a project root, or one named `codegen` or `generated`, is not discounted. | Review findings whose risk dropped below a `--fail-on` threshold. A custom risk policy that sets these tags overrides the defaults; set `include_tests: true` to scan these paths at full weight. |
| Corroboration | A project whose evidence spans a library and a code signal, or three signal types, gains a synthetic `corroboration:cross-signal` item (0.10 or 0.15). | Expect higher confidence and likelihood on such projects, and findings that now pass `min_confidence`. |
| Deny-list files | A mention-only data file whose name spells `blocklist`, `denylist` or `blacklist` as one word or two (`ai-blocklist.yaml`, `deny_list.json`) is a catalog whatever it names. Allowlists, egress policies and firewall or WAF rule sets (`firewall-rules.json`, `default-deny.yaml`) are configuration. | A project evidenced only by such a file has no finding; the scan note names the file. |
| Signatures | New languages (`c`, `cpp`, `elixir`, `r`, `lua`), `conda` dependency signals and eleven new signatures, listed in `CHANGELOG.md`. Elixir and R signatures have no dependency signals. | New products appear in reports. Re-run your own signature packs through `python -m shadowscan.signatures.validate`: `hex` and `cran` are not ecosystems. |

These cases are authored regressions and a 130-case author-written benchmark.
They do not establish independent review, live tenant acceptance or measured
field precision.

### October 9 scan evidence corrections (unreleased)

This source candidate includes corrections reviewed from the existing discovery,
redaction/replay and lexer work. It does not change the published 0.1.2 artifact,
create a release, or establish live tenant acceptance. Select and review a new
full commit SHA before deploying it.

| Area | Changed behavior | Migration check |
| --- | --- | --- |
| Source reports | Supported Go SDK aliases are resolved before credential redaction and source excerpting; embedded carriage returns no longer shift LF-based excerpts. | Regenerate affected reports and restrict older reports as confidential. Dynamic calls and arbitrary credential encodings still need operator review. |
| VPC flow coverage | `SKIPDATA`, invalid or contradictory statuses mark collection incomplete; `NODATA` remains a valid no-traffic record. | Pipelines must preserve exit 3 as unknown coverage and obtain complete input before accepting absence of findings. |
| Network attribution | Connection-specific TLS evidence is retained before totals are combined; contradictory and non-AI observations cannot borrow AI attribution. | Rebaseline traffic totals and investigate reduced attributed counts; previous totals may include unrelated connections. |
| Gateway activity | Invocation evidence requires a supported operation and provider, with its method from the same event. | Rebaseline agent indicators and capabilities. A management request, missing method or invocation attempt alone cannot establish successful execution or tool use. |
| Source coverage | Valid Rust multiline strings, C raw strings (`cr"..."`) and `\x`/`\u{...}` character escapes, and supported JSX in JavaScript files can finish lexical analysis. A `<` right after another `<` (`mask<<shift`) is part of a shift and never opens a JSX element. | Re-scan prior incomplete repositories. Newly analyzed code can add findings; unresolved, unterminated or ambiguous syntax stays incomplete (exit 3). |
| Record exports | Strict JSON and encoded line/file/aggregate byte limits match replay; empty complete exports contain an empty record envelope. | Check the current manifest before replay. A rejected replacement retains the previous file but reports `exported: false` and `filename: null`; that file is not this run's accepted export. |

Treat these as behavior changes when comparing old reports. Record scanner and
signature fingerprints, exact configuration and input scope alongside new
baselines. For oversized exports, narrow the collection scope or deliberately
adjust the configured file/aggregate limits within their hard ceilings; the
encoded JSONL line limit remains 4 MiB including its newline. Sanitization
safety-limit failures remain incomplete even when other records are analyzable.

The [reviewer packet](operations/reviewer-packet.md) lists paired controls for
these changes. Before enforcement, obtain a fresh human-labeled holdout using
the [repository-level procedure](evaluation.md#repository-level-field-acceptance)
and exact-scope authorized [tenant canaries](canaries.md). The existing automated
acceptance gate supports only local-code, AWS and Slack deployments; other
connector families need their own approved validation. No fixture, mock, AI
review or reused benchmark can be relabeled as that evidence.

### October 8 discovery classification and lifecycle corrections (unreleased)

Regenerate reports and comparison baselines with the reviewed candidate.
Supported SDK credential argument recognition is applied before evidence
publication; redaction remains defense in depth, and reports remain confidential.

Source classification becomes more conservative for standalone .NET tool
definitions, unrelated Go receivers, and provably unreachable Python
comprehension clauses. Supported .NET automatic invocation and Go agent
constructors retain import-bound positive evidence. These are static candidate
classifications and do not establish deployed execution. Unknown dynamic
bindings remain potential or framework-usage evidence.
Microsoft.Extensions.AI `UseFunctionInvocation()` middleware remains an agent
indicator with tool use when import or dependency evidence corroborates it, so
projects that configure a client with this middleware and register it through
dependency injection keep their agent classification. An explicitly
constructed `FunctionInvokingChatClient` is proven only within one file and
scope; when it is registered through dependency injection or held in fields,
the project is reported as framework usage, where `AIFunctionFactory.Create`
previously made it an agent. Expect such projects to move from agent to
framework usage in regenerated baselines. The per-file proof also accepts
target-typed `new()` options and clients. C# files that never name
`Microsoft.Extensions.AI` skip the tool-loop proof and cannot exhaust its token
budget.
C# tool-mode expressions whose type or alias name is locally shadowed also
remain unproven; a lookalike `Auto` member cannot establish automatic invocation.

Lifecycle links now require the same complete device value, compared after
trimming and case normalization. Standardize endpoint and runtime exports on
the same canonical immutable device identifier or full hostname. A short name
does not implicitly alias a FQDN, and different DNS suffixes remain distinct.
Repeat correlation clears derived endpoint activity tags when their process
observations disappear; native runtime observations remain intact. Confidence
and risk are unchanged by these links.

Use the [repository-level acceptance procedure](evaluation.md#repository-level-field-acceptance)
for full repositories that exceed the bounded evaluation runner's limits.
New authored regression cases are development evidence. Independent human
annotation and authorized provider-specific tenant acceptance still require
their own evidence and cannot be inferred from a passing CI run.

### October 9 endpoint and fleet completeness corrections

Endpoint discovery marks the report incomplete (exit 3) if any known
configuration location cannot be inspected safely; the other locations are
still scanned and reported. Missing locations remain normal; symbolic links,
non-regular objects and denied access are coverage failures. A linked
directory that holds none of the locations (a stow-folded `~/.config`) is
passed over without being followed. A scan of the user's own profile whose
`%APPDATA%` is redirected outside it (folder redirection) is incomplete, since
the Windows client configuration there is not read. In any `code.filesystem`
scan with `include`, a file link whose target is not selected is a coverage
gap rather than covered by a target the walk never reads. Instruction checks
reuse the original confined file snapshot and mark inspection beyond 512 KiB
incomplete.

Rescan endpoint baselines produced by an earlier candidate. Windows locations
now come from the profile's own `AppData/Roaming`: a mounted Windows profile
scanned with `--home` gains its Claude Desktop and VS Code findings, and a
scan that ran with `APPDATA` set loses the operator's configuration it had
attributed to the target. The command covers every `endpoint.inventory`
configuration file and uses the same include list for every profile, so the
collection scope fingerprint changes once and then stays stable as clients
come and go; empty profiles are comparable in fleet diffs. `--incremental` is
ignored for endpoint scans, and for every `code.filesystem` scan with
`include`, because fingerprinting would read the whole profile. Hidden HTML
comments longer than 4,000 bytes, or never closed where Markdown passes them
through as HTML, now add the `hidden-instructions` tag, and emoji joiners and
subdivision flags no longer add `invisible-text`, so `shadowscan diff` can
show those findings as changed.

Fleet inputs must preserve completion statistics, matching summary counts and
valid collection fingerprints. Combining an incomplete or truncated report
with a healthy one does not restore completeness. When duplicate observations
have different assessments, the highest source risk is retained, and a shadow
observation remains shadow. Source risk policies are not silently replaced by
the merging workstation's defaults. A finding id that another report uses for
a finding with another identity is refused (exit 1) instead of merged, and
sources are named by their path below the reports' common directory. Machines
that share a host name and home path, such as clones of one VM image, still
produce the same identities: give each a distinct `--label`. Rescan to replace
baselines produced by an earlier candidate; these safeguards do not establish
field validation.

### October 8 classification and risk follow-ups

Re-scan before comparing risk to reports from an earlier candidate. Three
things change what a report says without any repository change. A project
whose executable code constructs and serves an MCP server keeps its kind but
carries the `mcp-server` capability and an "MCP server in" title, as described
under "October 8 MCP server capability and model id attribution"; its resource
and identity are unchanged, so `shadowscan diff` reports it as changed, not new.
Coding-agent configuration findings now carry the tags `hidden-instructions`
(20), `remote-code-fetch` (15) and `invisible-text` (10) when the instruction
files they report contain hidden comment content, fetch-and-execute or
decode-and-execute pipelines, or invisible characters; the evidence names the
file and line only. A bare `mlflow` dependency no longer produces a
`provider.databricks` finding, so such findings resolve on re-scan; that is a
detection correction, not remediation. Spring AI services that register tools
on an injected `ChatClient.Builder` chain become `agent` findings. The new
`shadowscan endpoint` and `shadowscan merge` commands add collection and
aggregation paths; the existing CycloneDX AI-BOM semantics are retained. None of this is
field-validated: the changes were driven by an author-written benchmark
(`archive/reviews/head-to-head-2026-10-08.md`) and are covered by regression
tests and evaluation cases only.

### Real-world benchmark follow-ups (unreleased, after 0.1.2)

Re-scan before comparing finding counts, confidence or exit codes with earlier
reports. The changes below came from running ShadowScan on 326 public
repositories (`tools/benchmark/realworld`). They make fewer scans incomplete
(exit 3), remove false evidence, and add some evidence that earlier builds
missed, so a repository can gain or lose findings without any change to it.
Finding IDs are unchanged: no identity field is touched, and a finding's title
is not part of its identity.

- **Credential titles.** A `secret` finding whose only matches are the generic
  credential rules (an assigned `PASSWORD`, `ACCESS_TOKEN`, `CLIENT_SECRET`,
  `CREDENTIAL` or `*_API_KEY` value, a GitHub or AWS key) is titled
  `Hard-coded credential in <file>` and gains the tag `unattributed-credential`.
  Before, every secret finding was titled `LLM provider credential in <file>`,
  including a mail password, although nothing tied it to a provider. A finding
  with an attributed provider keeps the old title and no new tag. Dashboards or
  filters keyed on the old title for unattributed credentials should key on
  `kind: secret` and the absence of `model_providers`. Detection, weight and
  risk are unchanged.
- **Fewer incomplete scans.** Each of these used to end a scan with exit 3 and
  is now read exactly:
  - source lexing: ordinary strings that span lines in Rust, PHP and F#; PHP 8
    attributes (`#[...]`, which are code, not comments; in PHP before 8 a `#[` line is a
    comment, so a file with `#[` is lexed both ways and only what both readings mask
    stays masked; when only the PHP 7 reading leaves a string open at the end of the
    file it is not used, and when only the PHP 8 reading does the scan stays incomplete);
    PHP here-documents whose closing marker is followed by code on its line
    (`EOT)]`, allowed since PHP 7.3); F# type variables
    (`'T`) and primed names; C# verbatim strings that open with an escaped
    quote (`@"""x"" y"`); JSX in `.js`, `.mjs` and `.cjs` files, tried when the
    plain walk is ambiguous and used only if it reads the whole file cleanly
    (an element must follow punctuation or a reserved word that cannot be a name,
    such as `return`; after `yield`, `await`, `of` or a keyword cut out of a longer
    name such as `a<ZWNJ>typeof`, all names in a script, and in a file with a left
    shift such as `mask<<shift>limit`, the scan stays incomplete);
    the TypeScript non-null assertion before a division (`idle! / step`); and
    Qt Linguist translations and Tiled tilesets named `.ts` or `.tsx`, which are
    XML: only a file that opens with an XML declaration or a document type
    declaration and parses as well-formed XML with a `TS` or `tileset` root is
    masked whole. A construct that is
    still ambiguous (a string left open, Ruby strings that span lines, heredoc
    interpolation) stays incomplete.
  - file contents: text that is not valid UTF-8 and holds no NUL byte, and
    large UTF-8 text with a few stray NUL bytes (names are matched without them,
    as bash removes them from a script; a source file is lexed with and without
    them and is incomplete when the readings differ), are analyzed instead of skipped
    (see [scan semantics](scanning.md)); each adds a warning that leaves the
    scan complete (one warning per kind; `strict_coverage` makes each noted file a gap, and a
    `CODEOWNERS` file with replaced bytes is an error). Dense NUL content, text mixed with other control characters
    and UTF-16 or UTF-32 without a byte-order mark are still coverage gaps.
  - agent definitions: a description with `: ` in a plain value is read after
    quoting, as coding agents read it (see the [code connector](connectors/code.md)).
  - JavaScript and TypeScript: the check that drops an SDK binding shadowed by a
    method parameter was quadratic in the size of the file and could exceed the
    0.1 s pattern budget on a 22 KB source, which discarded all analysis of that
    file (`file analysis incomplete (TimeoutError)`). It now looks only at the
    text around each use of the name and gives the same answer.
  Because files that used to be skipped are now analyzed, a repository can gain
  findings, including credentials, that earlier builds could not see.
- **Less false evidence.** The `mcp.<vendor>.<tld>` host form of `protocol.mcp`
  now ends in a country-code domain (except two-letter codes that are common file
  extensions or property names, such as `py`, `md`, `rs`, `pl`, `ps`, `id` and `in`)
  or one of a list of generic top-level domains (`host`, `info`, `page`, `live` and
  other property or method names are left out), so a dotted identifier such as the
  translation key `mcp.translator.translatekey` is no longer an MCP endpoint while
  `mcp.example.de` still is. A `protocol.mcp` candidate followed by a call, an index,
  an underscore or an assignment (`MCP.LOGGER.info("x")`, `mcp.client.is_connected()`,
  `mcp.session.page = 2`) is code, and in a source file a candidate counts only where
  a string or a URL starts with it or an `/mcp` or `/sse` path follows it, so the
  property read `y = mcp.result.no` is not an endpoint. A
  host on a line of a hosts file, ad-block list, resolver configuration or
  Clash/Surge-style rule list (`0.0.0.0 chatgpt.com`, `||api.openai.com^`,
  `address=/api.openai.com/0.0.0.0`, `DOMAIN-SUFFIX,openai.com,PROXY`) routes or
  blocks the host and no longer counts as use of it; the same host elsewhere
  still counts (the filter applies to documents that are not source files, so a `host, port = ...`
  assignment or a `||` continuation line in code is unaffected). Strings in Rust, PHP and F# that span lines are no longer read
  as code, which removes the framework names that appeared inside them.
- **New evidence.** `protocol.mcp` matches the JSON-RPC method names an SDK-free
  server or client dispatches on (`tools/list`, `tools/call`, `resources/list`,
  `resources/read`, `prompts/list`, `prompts/get`,
  `notifications/initialized`) at a `case`, a comparison, a `method:` field or
  the start of a line, never inside a comment or a string, at weight 0.75. In
  languages without an import binder (Go, Rust and others), such a match
  establishes `protocol.mcp` only with an MCP import or dependency in the
  project, like any lexical-only match; without one the scan names the file in
  a note instead of reporting a finding.
  `coding-agent.claude-code` gains `.claude/launch.json`, `.claude/rules/*.md`,
  `.claude/output-styles/*.md` and the `.claude-plugin/plugin.json` and
  `marketplace.json` manifests, at weight 0.8.

### October 8 MCP server capability and model id attribution

Re-scan code and compare risk scores before replacing a baseline or relying
on a `--fail-on` threshold. Findings for projects that expose an MCP server
(`FastMCP(`, `new McpServer(`, `server.NewMCPServer(`, `.AddMcpServer(`,
`McpServer.sync(`, the server transports) now carry the `mcp-server`
capability, which scores 5 risk points like `tool-use`, so their default risk
rises by 5 without any repository change; a custom `risk_weights.capabilities`
table may set `mcp-server` explicitly, and the default-weight digest pinned in
the tests changed with it. The project finding of an implemented server is
retitled on re-scan from `LLM usage in <dir>: ...` to `MCP server in <dir>:
...` (finding identity and ids are unchanged; the title is prose), so a
dashboard or filter keyed on `LLM usage in` titles sees those findings move
to the new title. A project that only uses an MCP client next to an HTTP or
socket server class constructed as `Server(` keeps its `LLM usage in` title
and `tool-use` alone. Model-id attribution also moved: path-like strings
such as `gpt-4-turbo-docs.md`, `command-line` or `claude-code-action` no
longer attribute OpenAI, Cohere or Anthropic, LiteLLM-style routes
(`bedrock/`, `vertex_ai/`, `openrouter/`, `ollama/`...) attribute the routed
provider, `AnthropicBedrock(` and `AnthropicVertex(` attribute the platform
instead of Anthropic, and `provider.openai-compatible` is reported only next
to a `base_url` override, so provider lists and confidence may differ from an
earlier candidate's report. Finding IDs are unchanged. These are detection
corrections, not evidence of change in the scanned repositories.

### October 8 corroboration rules: findings that disappear or shrink

Review `shadowscan diff` output before accepting a baseline from this
candidate: whole project findings can disappear, and others lose frameworks
or providers, without any repository change. Four kinds of evidence no longer
establish a technology on their own: a lexical code pattern whose signature
has no import, dependency, file-name, image, IaC, model, bound-call,
configuration or mention of weight 0.3 or more anywhere in the project; a
signature known only from mentions below weight 0.3 (`huggingface.co` in a
comment); a host, variable, display name, model id or CI image under a test
path while `include_tests` is off; and a container image that runs a CI job
(`.github/workflows/`, `.gitlab-ci.yml` and the like), which also no longer
produces an `infra` finding. The evidence is kept, but such a signature moves
from `frameworks[]` or `model_providers[]` to `metadata.potential_frameworks`
or `metadata.potential_providers`, adds no capability and does not title the
finding. A project whose only evidence is of these kinds yields no project
finding; the scan instead records a warning, "evidence not reported because
nothing in the project establishes a technology on its own", that names up to
five of its files. That warning does not mark the scan incomplete, so the exit
code does not change. Finding IDs are unchanged, so `diff` reports these
findings as resolved and the shrunk ones as changed, and policy filters or
`--fail-on` thresholds keyed on `frameworks[]` or `model_providers[]` stop
matching them. Before accepting the baseline, take every finding that `diff`
reports as resolved, or that lost a framework or provider. Find its project in
the new report's `metadata.potential_*` lists and in the warnings that name
files. Open those files and decide whether the project really uses the
product, for example a vendored SDK without a manifest entry or an
integration test that is in scope. Keep a finding you confirm under manual
review, or re-scan with `include_tests: true` when test code is in scope.
Record the rest as detection corrections, not remediation. These rules come
from the author-written benchmark and its regression cases; they are not
field-validated.

### October 7 distribution rename and PyPI publication

The distribution is renamed from `project-nexus-shadowscan` to
`NexusShadowScan`, the name it is published under on PyPI; the wheel file is
`nexusshadowscan-<version>-py3-none-any.whl`. The CLI, Python imports,
connector entry-point group and report schemas keep the `shadowscan` name, so
configurations, reports and baselines need no change. Install into a fresh
virtual environment rather than over an earlier `project-nexus-shadowscan` or
`shadowscan` distribution, because they share the import package and command.
Update any pipeline that globs the old wheel name, and any container inventory
check that looks for `pkg:pypi/project-nexus-shadowscan`; it is now
`pkg:pypi/nexusshadowscan`.

The release-evidence workflow gains a `publish` input (default `none`); the
[publishing runbook](operations/publishing.md) describes the upload path and
its gates. The workflow's wheel-count checks also
now fail when an artifact holds more than one wheel; before, `set -e` ignored
the failed count in an `a && b` list and only the file check could stop the
job.

### October 6 benchmark follow-ups

Re-scan before comparing risk with earlier reports. MCP configuration
findings gain `mcp-unpinned-package` (+10), `mcp-broad-filesystem` (+10) and
`mcp-shell-command` (+5), and coding-agent configuration findings gain posture
tags read from the agent's own settings: `posture-permissions-bypassed` (+15),
`posture-unrestricted-shell` (+10), `posture-unsandboxed` (+10),
`posture-exposed-gateway` (+15) and `posture-unauthenticated-gateway` (+15).
Each server record in `metadata.servers` lists its `risks`, and
`metadata.posture` names the client, setting, enumerated value and file. A
finding can therefore rise a level without any repository change. Override a
weight with `options.risk_weights.tags` if your policy differs. The new
evidence has weight 0, so confidence and finding identity are unchanged.
OpenClaw state directories (`.openclaw/openclaw.json` and workspace files)
are now attributed to a new `coding-agent.openclaw` signature, so findings that
previously fell under a generic instruction-file signature may change their
framework list; finding IDs depend on the resource and discriminator, and the
discriminator of a coding-agent configuration includes its signature id. A
coding agent's own configuration file now belongs to that agent's signature
alone: `platform.openclaw` still matches a bare `openclaw.json`,
`clawdbot.json` or `moltbot.json` and OpenClaw code, but no longer adds a
second framework-usage finding for a file in the state directory.
An MCP server reached through `ws://`, an upper-case `HTTP://` scheme, or a
URL that client parsers read as plaintext despite embedded tabs, newlines or
leading control characters now gains the `mcp-plain-http` factor (+10), as
`http://` servers already did: the factor parses the scheme as the
`mcp-insecure-transport` tag does, so every tagged server is scored.

The new `endpoint.inventory` connector reports findings on the `endpoint`
surface with new kinds (`ai-app` and `local-model` at base weight 5, plus
`agent-config` and `mcp-server`). Reports, dashboards and `--surface` filters
that enumerate surfaces or kinds should add them; `network-contact` (5) and
`runtime-process` (10) are reserved for the network and runtime connectors.
Endpoint resource ids have the form
`endpoint:<device>:<home>:<category>:<key>`, so a finding keeps its identity
across scans of the same device and home. The connector reads home
directories of the account running it; on a shared host, scope `paths` to the
homes you are authorized to inventory, and leave `shell_history` off unless
your policy allows it (only tool names and counts are kept).

Gateway caller titles change on re-scan. Callers whose only agent indicator
was the domain or name of an AI SaaS app (any `api.openai.com` or
`api.anthropic.com` caller, or a key named after the vendor) are now
"LLM caller" instead of "Agentic caller". Callers that invoke hosted agent
runtimes, reach MCP endpoints or show agent-loop cadence gain the tags
`agent-runtime-api`, `mcp-client` or `agent-loop` and
`metadata.agent_behaviour`. Finding IDs are unchanged; dashboards that count
agentic callers by title will see a different number.

The new `network.logs` connector reports `network-contact` findings on the
`network` surface, with resource ids `network:<label>:<client>:<signature>`.
A client address names a device or a NAT gateway; give each sensor or VPC a
distinct `label` so the same private address in two networks stays two
findings, and join findings to DHCP or VPN records before assigning owners.

`runtime.processes` reports `runtime-process` findings with resource ids
`runtime:<host>:<user>:<tool>`, and `endpoint.inventory` findings for the same
tool on the same device gain `metadata.lifecycle` and the tag
`observed-running`. A tool links through its signature, through its tool id
(Claude Desktop, Kiro and LM Studio have no signature), or, for an MCP
configuration, through a running server's package. Neither changes risk. Keep
endpoint `label` values equal to the host names that process exports report,
or the two will not link. A process list is a point in time: absence does not
show that a tool is unused. A live `/proc` scan of a container's own `/proc`,
or under a `hidepid` setting that hides processes from the scanning account,
cannot see every process and is marked incomplete (see the runtime guide for
which settings do).

`--format cyclonedx` replaces the earlier candidate's CycloneDX exporter with
a different document: agents, configurations, apps, callers and processes are
`application` components instead of `machine-learning-model` components (MCP
and Ollama inventories stay `services`, model stores stay models), the new
`shadowscan:heuristic-risk` properties carry the risk the earlier exporter
never published, the per-tag `shadowscan:tag:<tag>` properties are one
`shadowscan:tags` list, and `secret` and `token` findings are no longer
components. Regenerate BOMs and update
their consumers; `docs/operations/ai-bom.md` lists the changes. Its
composition is `incomplete` for an incomplete scan, and the exit code is
unchanged. `options.llm_triage` is off
by default. Enabling it sends finding summaries to a third-party or
self-hosted model endpoint, so treat it as a data-egress decision: review
`docs/operations/llm-triage.md`, prefer a `base_url` you operate, and do not
enable it for scans whose finding titles must stay in your environment.

### Incomplete A2A cards, OpenClaw state files and short `sk-` keys

Re-scan before comparing finding counts with earlier reports; these changes
add findings and evidence that earlier candidate builds did not report. Exit
codes and existing finding IDs are unchanged, except as noted for Moltbot
state files.

- An A2A card that names its agent and declares an endpoint, skills or
  capabilities, but misses other required fields, gets its own
  `protocol.a2a` framework-usage finding tagged `incomplete-agent-card`, with
  the errors in `metadata.card_errors`. It never becomes an agent finding,
  and its validation errors still mark the scan incomplete (exit 3); the
  report now also shows which file holds the card. Completing the card turns
  the same finding ID into the agent finding.
- `config.json` in an OpenClaw state directory (`.openclaw/`, `.clawdbot/` or
  `.moltbot/`) and `.moltbot/moltbot.json` join the `coding-agent.openclaw`
  configuration finding with the other state files. A `.moltbot/moltbot.json`
  previously produced a separate `platform.openclaw` framework-usage finding;
  `diff` against an older baseline reports that finding removed and the agent
  configuration added.
- `heuristic.unattributed-api-key` reports `sk-` keys of 20 to 31 characters
  after the prefix when they look random (see the
  [signature conventions](signatures.md#conventions)), at its usual weight 0.4.
  Such keys were missed in SDK calls, JSON and YAML configuration and
  `Authorization` headers, so `--fail-on` gates may now fail on a repository
  that holds one. A key that the generic credential rule already reported
  (an `*_API_KEY=` assignment) keeps that finding and its weight.

### Offline endpoint and runtime inventory limits

The `endpoint.host`, `endpoint.mcp`, `endpoint.ollama`, `endpoint.models` and
`endpoint.ebpf` connectors and `gateway.otel` analyze offline exports. They do
not make live API calls, probe endpoint URLs, discover host configuration
files, or read model directories (`endpoint.inventory` reads its fixed list of
local locations). The one exception is opt-in: `endpoint.mcp` fetches the A2A
Agent Cards listed in `agent_card_urls` (see
[A2A Agent Card probe egress](#a2a-agent-card-probe-egress)). Kubernetes and OpenShift inventories are also
offline-only; do not provide kubeconfig material, Secret values, service-account
tokens, environment values, or image pull credentials in an export.

`endpoint.models` consumes metadata produced elsewhere; it does not parse GGUF or
safetensors files. MCP tool fingerprints are not compared with a saved baseline,
so rug-pull detection is not implemented. Findings from these offline inventories
carry no device name, so lifecycle links do not apply to them. Treat their output as bounded inventory evidence, not
live execution or deployment attestation.

#### A2A Agent Card probe egress

`endpoint.mcp` with `agent_card_urls` makes HTTPS GET requests from the scan
worker to each listed agent origin (the card path, and the legacy
`/.well-known/agent.json` after a 404), and to `agent_card_jwks_url` when it is
set and a fetched card is signed. It sends no credentials beyond any query a
listed URL itself carries, follows redirects only on the same origin, uses no
proxy, reads at most 1 MiB per card and never fetches a URL declared inside a
card. Allow egress to exactly those hosts.

- Agents on private or loopback addresses are refused unless
  `options.allow_private_origin: true`, which applies to every connector in the
  scan. Prefer a separate configuration for internal agents.
- `ca_bundle` on `endpoint.mcp` trusts a private CA for the card and JWKS
  endpoints; verification stays on, and a relative path resolves beside the
  configuration file.
- `verified` means a signature checks out against the keys you configured at
  scan time. It is not an approval, does not register the agent, and does not
  check key expiry or revocation beyond what that key set contains. Serve the
  JWKS from an endpoint only your key owners can change.
- A probe failure is an error and exit 3; never read a failed agent as absent.
  Collection-scope fingerprints mark these live scans non-comparable, so `diff`
  never resolves an earlier card finding from a probe.

### October 3 source capability attribution migration

Re-scan code with this candidate before comparing its risk to earlier reports.
Unused tool declarations, unregistered SDK execution tools and unrelated shell
helpers now remain zero-weight contextual evidence instead of granting an
agent execution authority. Their features are retained as contextual/potential
metadata. Existing findings may lose capabilities, confidence or risk without
any repository change; that is a detection correction, not proof of remediation.
Supported literal registrations, local unshadowed tool helpers and connected
MCP/provider execution remain source observations. Dynamic implementations
remain potential and require source review or independently attributed runtime
evidence. Constant-dead JavaScript/TypeScript constructions may likewise become
framework usage instead of agents. No field-accuracy or execution attestation
is implied by these static corrections. Discarded callbacks supplied to unknown
JavaScript factories, shadowed local helpers, unrelated MCP member receivers,
unreachable Python statements and deferred lambdas in compound callees remain
contextual. Supported import-bound async execute callbacks and directly invoked
Python lambdas retain connected source evidence.

### October 3 review remediation

HTTP retry warnings, errors and optional-request warnings now identify only
the HTTPS origin and status. Request paths, userinfo, queries and fragments are
omitted; malformed URL diagnostics use fixed messages. Update any operational
parsers that expected a path in an HTTP error. Treat historical logs as sensitive
when reviewing or sharing them. Collection policy and incomplete-scan exit
semantics remain unchanged. Transport and response-body errors also discard
opaque upstream payloads, request/response objects and original exception
chains; controlled TLS, connection and timeout categories remain available.

Supported ADK, Strands, AutoGen, LlamaIndex and Semantic Kernel constructors now
receive capability checks specific to their configuration. Empty or unresolved
tool and participant collections no longer establish those capabilities solely
because the SDK supports them. A dynamic tool retriever does not establish
document RAG; weak planning vocabulary does not establish autonomous execution.
Findings can retain the same identity while their capabilities, confidence or
risk decrease. Rescan and inspect those differences before replacing an
existing baseline; these changes do not establish that a deployed agent stopped
using tools. See the [code connector guide](connectors/code.md) for the supported
static patterns and remaining inference limits. Strands literal tool names
and file paths count as configured tools; literal participant or handoff
strings do not establish another agent.

Git submodule inventory preserves its fail-closed result and now reports a
bounded category for preflight, subprocess or tree-parsing failure. Numeric OS
errors may be retained, but raw paths, arguments and subprocess stderr are not.
The observed macOS/Python 3.11 test failure passed on an unchanged rerun at
`c232e28c34571ea87b0ca2925a84e86fed0b3645`; its root cause remains unconfirmed. Additional
diagnostic assertions and fast-exit subprocess tests aid investigation without
relaxing confinement, Git version or deadline requirements. Require the full
CI matrix to pass on the selected revision.

The [merge-policy runbook](operations/merge-policy.md) now prepares both
rulesets from fresh snapshots and verifies exact persisted readback. Conflicting
check-provider bindings require administrator review instead of silent
replacement. The available repository integration cannot apply administration
writes; versioned payloads are not evidence of active enforcement. Human review,
a fresh human-labeled holdout and scope-specific live tenant receipts remain
required evidence. Existing [acceptance tooling](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md)
checks supplied evidence; synthetic regression results cannot replace it.

### October 2 integration of #134 and hygiene review

Earlier candidate builds tagged every SARIF rule `security`, set
`security-severity` from the heuristic level (critical 9.5, high 7.5, medium
5.0, low 2.5, info 1.0) and reported critical and high findings at level
`error`. Reports from this revision carry no security severity: GitHub code
scanning shows ShadowScan alerts as Warning or Note rather than as security
alerts rated Critical to Low, and a filter on the `security` tag no longer
matches them. Rule IDs and `partialFingerprints` are unchanged, so existing
alerts keep their identity and history.

A code-scanning merge-protection rule whose security-alert threshold was met
by ShadowScan alerts no longer blocks on them, and neither does an alerts
threshold of Errors; Errors and warnings still blocks on critical, high and
medium findings. Do not restore blocking by lowering a threshold. Follow
[Severity is not an enforcement signal](severity.md) and gate on the exit code
only after the acceptance steps it lists. A consumer that sorted results by
SARIF level should read the result property `risk_level` or the rule property
`shadowscan/heuristic-risk` instead.

`code.filesystem` now stops at setup (exit 1) on a boolean, fractional or
non-numeric `max_file_size` or `max_files` and on a boolean, non-finite or
out-of-range `scan_timeout`. Such values used to be coerced: `max_file_size:
true` skipped every file larger than one byte and reported the scan
incomplete. Correct the value and rescan instead of comparing against reports
it produced; numbers and numeric text are accepted as before.

The worker image's `/opt/venv` no longer contains `setuptools`, `wheel` or
`packaging`, which only the build needs. An image that extends the worker and
imports them must install them from its own hash-locked requirements.

Both worker image stages pin Wolfi's `python-3.12` and `python-3.12-base` to
`3.12.15-r0`. Revision `3.12.15-r1`, published on 2026-10-02, has no SHA-224,
which pip uses for its cache keys, so every pip install in the build fails on
it. While the pin holds, a rebuild keeps that interpreter revision and does not
receive later Wolfi Python fixes. The container gate still scans it and fails
on HIGH or CRITICAL findings, and the build fails if the revision is no longer
available. Drop the pin once a newer revision passes
`python3.12 -c "import hashlib; hashlib.sha224"`.

### October 2 integrity and capability corrections

Collect a fresh baseline before enforcing these changes. Empty, disabled or
unresolved provider tool options no longer establish tool-use; safely bound
Python literal collections still do. MCP comments and string examples no longer
establish registrations, supported decorator options do, and independent
execution-sink evidence remains visible. Review capability and risk-score
changes rather than carrying forward the previous classification.

Conditional GCP IAM bindings retain their conditions and count as potential
access. Degraded conditional-role exports, unresolved Auth0 grants and
ServiceNow tools or triggers, and SaaS rows missing usable names make coverage
incomplete. Unresolved children cannot approve a parent in the registry. Fix
the export or association before using a scan to resolve earlier findings.

Malformed UTF-8 and malformed BOM-declared text now produce a fixed coverage
gap instead of being analyzed with replacement characters. Git metadata
enrichment rejects common-directory and alternate-object indirections, local
configuration includes, internal links and special files; use an immutable,
self-contained checkout with supported single-line configuration if you opt
in. Supported mixed interpolated credential strings with opaque static
material are now withheld. Regenerate old reports and review changed finding
identities; sanitization still does not make a report public data.

### October 2 integration review: redaction and source decoding

Reports withhold more than earlier candidate builds did: a JSON string that
starts with a credential and an escaped value (`{"log": "password: \"S\""}`),
the rest of a double-quoted option or `auth=` password after an escaped quote
(`--password "a\"S"`), the rest of a braced ODBC password (`Pwd={a;S}`), the
value after `bearer =>`, `=~` or `==`, the credential on the line after a `;`
and an escaped line break in JSON-escaped text, and the userinfo, credential
query fields and webhook path of a URL inside another URL's text
(`redis://:S@a,redis://:S@b`, `?next=https://u:secret@b`). Reports generated
by an earlier candidate build can contain those values: regenerate them,
restrict or delete the old copies, and rotate any credential they show.
Expect extra `[REDACTED]` markers where such shapes occur; finding IDs built
from sanitized text can change with them, so compare a fresh baseline.

A Python source whose PEP 263 coding cookie names a codec that does not read
ASCII as ASCII is now the coverage gap `binary or undecodable content in
analyzable file` (exit 3). That covers `utf-16-le` or `utf-32` without a
byte-order mark, `utf-7`, `hz`, EBCDIC code pages such as `cp037`, and also
`shift_jis_2004`, `shift_jisx0213` and `cp864`, which read `\`, `~` or `%` as
other characters. Such a file used to be decoded into other characters and
silently not analyzed. Fix the cookie, or add the file to `exclude`.

### October 2 integration review: gateway, low-code and cloud connectors

Re-run `gateway.logs` over combined-format access logs before comparing
gateway callers with an earlier baseline. A host token that a client could have
written (quoted, as in `host="api.example.com"`, or followed by another quoted
field) is still not used, but when it alone would have made a request LLM
traffic the scan is now incomplete (exit 3) instead of complete without that
traffic. Put the host in the log format as an unquoted token after the last
quoted field (nginx: `... "$http_user_agent" host=$host`), or export JSON
logs, to attribute such requests. Fields that were taken from inside a value or
quoted text of a text log (a `?model=` query, an `&host=` argument) no longer
are, and a line truncated inside a quoted field is malformed (incomplete).

`lowcode.servicenow` now pages each table until its 500-row windows cover the
response's `X-Total-Count`, so a window that ACLs emptied no longer ends the
table early with a complete scan. A table whose responses carry no valid
`X-Total-Count` (a proxy that strips the header, `sysparm_no_count`) cannot
prove where it ends: the scan is incomplete with a warning naming the table.
Pass the header through to the scanner; `max_pages` still needs to exceed the
table's `X-Total-Count`/500.

Check connector configurations for numeric options before upgrading:
`max_lambda`, `max_ecs_api_calls` (`cloud.aws`), `max_projects` (`cloud.gcp`),
`min_events` (`gateway.logs`) and `max_teams` (`saas.microsoft-teams`) must be
positive integers, and `cloudtrail_days` (`cloud.aws`) and `audit_days`
(`cloud.gcp`) non-negative integers, as `max_pages` already must be. A boolean,
a fraction or non-numeric text now stops that connector with a configuration
error (exit 3) instead of being truncated: `cloudtrail_days: 0.5` used to
switch the CloudTrail lookup off without a diagnostic and `max_lambda: true`
became 1. Integral values such as `7.0` or `"7"` are still accepted.

`cloud.azure` no longer sends a request whose path comes from an unchecked
response identifier. A listed subscription without a GUID id, or a Resource
Graph resource whose id is not a plain ARM path, is skipped with a warning and
the scan is incomplete. ARM does not return such identifiers; a scan that
reports one points at a proxy or a response that should be investigated.
Configured `subscriptions` keep their existing validation.
### October 2 integration review: code connectors

Re-run code scans before updating baselines. Kubernetes manifests, ECS task
definitions, CI pipelines and other files that assign provider variables to a
service or job are configuration again: repositories that reported nothing
because such a file named four or more products now report LLM usage. A data
file that only lists products is still discounted; when a project's only
evidence is in such files, the scan adds a note (a warning that does not make
the scan incomplete) naming them. Review the named files: a provider routing
file that configures four or more providers by base URL cannot be told from a
vendor list by its shape.

A `.gitmodules` file with a run of more than 32 blanks is refused before it is
parsed and makes the scan incomplete (submodule coverage unknown). Such a file
used to stall the scanner process beyond every deadline.

A JavaScript or TypeScript call longer than 8192 characters (a Genkit flow, an
agent with long instructions) is now analyzed from its first 8192 characters,
and the file's other import-bound evidence is kept: such files used to lose all
of it. The scan is still incomplete (exit 3) as before, because options past
that point are unread; the error now reads `import-bound call at line N
analyzed from its first 8192 characters; options after them were not read, so
coverage is incomplete` instead of `source binding call text limit exceeded`.
Update any alert or triage rule that matches the old text.

Notebooks that install packages with `%pip` or `!pip`, and Python files the
scanner's interpreter cannot parse, can now report an agent where they reported
LLM usage: their framework patterns count as lexical evidence when the same
library is imported or declared. Notebook cells are now read one at a time, so
a notebook with an unfinished scratch cell, which used to report nothing, can
report findings, with a warning that names the cell that does not parse.
Review such changed classifications before updating baselines.

Local scans and offline clone directories now make the scan incomplete when a
file the scanner reads is a Git LFS pointer. Check out such repositories with
git-lfs installed (`git lfs pull`) before scanning, or the scan stays
incomplete (exit 3).

These fixes come from an AI-assisted review and have offline regression tests
only; they are not independent human review or field precision evidence.

### October 2 production review migration

Review framework attribution in projects using npm dependency aliases before
replacing enforcement baselines: the registry target now supplies dependency
identity. This identifies a declared dependency, not runtime execution or
cross-file resolution of imports through the alias. Malformed alias targets
make source coverage incomplete (exit 3).

CSV inventory approvals preserve embedded line separators in quoted resource
and scope fields. Review previously generated reports if an inventory used such
fields: a value that previously lost its separator is now a different identity
and no longer confers the same approval. Ordinary single-line inventories are
unaffected.

Malformed evidence in imported reports is rejected before correlation or risk
processing; malformed incremental cache entries are ignored and fully rescanned.
Notion and Atlassian provider error envelopes and malformed Google Workspace user
suspension flags now produce incomplete collection rather than a complete empty
result. Valid neighboring Google Workspace users remain eligible for collection.
Resolve the reported input or provider failure before accepting the scan.

The connector coverage gate now rejects a report that does not name every
module under `shadowscan/connectors/` in the checkout, and malformed counts
(exit 2). Generate its JSON from a full coverage run; a selected-test report is
not evidence for all connectors. The 75% per-module floor over statements and
branches is unchanged. Wheel validation uses private temporary storage and
cleans it up after success or failure.

These changes have offline regression coverage. They do not replace independent
human review, a fresh labeled holdout or authorized tenant acceptance checks.

### October 2 hygiene review migration

Re-run scans and compare MCP tool/capability labels before updating enforcement
baselines: inert examples and unreferenced enum members no longer count as
registered tools. Live GCP, Azure, OCI and Slack records keep collector-assigned
classification and scope when response fields share those names. Invalid
discovered GCP project identifiers are skipped with incomplete coverage.

Gateway records with timestamps outside the representable UTC range now fail
before updating caller state. A malformed record still makes coverage incomplete,
while valid neighboring observations remain available for review.

Tenant-canary verification now groups records and findings by exact resource
identity before checking controls and reads record dumps incrementally under
the existing size cap. The declared scope and acceptance selectors still apply;
this optimization does not establish a tenant-scale latency or memory SLO.

Re-render retained sensitive reports where possible: diagnostic sanitization
now preserves context across errors, warnings and skip reasons, and JSON
statistics are checked together. Continue treating reports as sensitive; no
redaction rule recognizes every possible secret or private datum.

CI and `make check` enforce the bounded secret-pattern gate over every tracked
file. The October 3 follow-up replaces directory and placeholder exemptions
with `tools/secret_allowlist.json`: each synthetic fixture or documentation
example is approved by exact repository path, credential family and matched-text
SHA-256, with a review reason. Private-key BEGIN markers additionally bind the
whole file's bytes so an approval cannot cover another key body. The gate rejects
new credential-shaped values, malformed entries and stale approvals, including
during partial hooks. Review changes to these approvals with the fixture itself;
do not add live credentials to the manifest. The evaluation path contract rejects ambiguous case/Unicode names,
file/directory collisions and components over 255 UTF-8 bytes. Correct such
layouts before re-running a private holdout; do not silently rename its samples
after freezing the acceptance policy.

These checks are offline regression evidence. They do not establish independent
human approval, a representative field accuracy measurement or live tenant
acceptance. Verify the current required-check configuration under
[release verification](#release-verification) before merging or deploying.

### October 2 review remediation

Collect a fresh baseline after upgrading: dependency examples confined to Gradle
or Dockerfile comments no longer establish framework usage, while active
declarations and credentials inside comments are still reported. Do not read the
disappearance of a comment-only finding as a remediation.

The new regression cases are authored from observed defects. They do not replace
the [fresh human-reviewed holdout](evaluation.md#build-a-genuinely-held-out-field-set),
independent review of the final candidate, or [live tenant canaries](canaries.md).
Run the existing [scope-specific acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md)
on real evidence for the intended population and tenant scopes. Record unmet
requirements as unmet; do not substitute offline replays or AI-generated labels.

### October 2 detection and assurance migration

Name/value credential redaction now reuses line bounds and first-content
positions. Long lines containing repeated record names previously caused
quadratic prefix scans and copies; those queries now perform linear character
work. Credential withholding and record/list boundaries are unchanged. Existing
matching budgets still fail closed, and timing regressions remain checks of the
implementation rather than tenant throughput guarantees.

JavaScript/TypeScript calls exceeding the bounded semantic-analysis budget now
make the scan incomplete (exit 3). This includes long constructor arguments;
an unchanged framework-usage finding is no longer evidence that agent analysis
completed. Review the diagnostic and source, then provide an analyzable input
or explicitly narrow the intended scope before using the result as a gate.
Neighboring findings remain available for investigation.

Binary-looking `.ts` files also make source coverage incomplete. Packet bytes
cannot distinguish a video segment from TypeScript containing a padded comment.
Review the affected paths and explicitly exclude verified media directories
with the connector's `exclude` policy when they are outside the intended source
scope. Recognized binary assets selected only by a directory-wide configuration
glob keep their existing treatment.

Failed incremental cache-decision hooks now mark connector coverage incomplete;
built-in validation diagnostics remain available, while plugin hook failures
expose only exception types.

Zapier ignores wholly blank text rows only when a recognized identity column
is present. Unknown JSON keys or CSV headers make coverage incomplete; existing
padding rows under valid Zapier headers remain accepted.

Generic Genkit initialization and standalone flow/tool declarations are
framework evidence. Supported explicit agent definitions and concrete model
calls using registered tools establish stronger configured behavior. Review
changed kinds, capabilities and risk scores, then collect a fresh comparison
baseline. Tool registration must resolve to a direct module-level initializer
or a standalone call with an explicit statement boundary; dynamic bindings and
uncertain boundaries remain supporting framework evidence. The added examples
are authored regressions; obtain fresh
human-reviewed evidence using the
[holdout procedure](evaluation.md#build-a-genuinely-held-out-field-set).

The shared HTTPS client now bounds response acquisition, including status and
headers, separately from body delivery. Cancellation closes the active socket
before that connection can be reused. System DNS resolution cannot be forcibly
interrupted in a Python worker thread; a result arriving after the acquisition
budget is rejected before connection. External SDK calls retain their own
transports. Keep a process/job supervisor for a hard end-to-end execution limit.

The aggregate `CI gate` also requires container security checks for the exact
built image. CI retains the image identity, OS/Python SBOM and vulnerability
result; HIGH/CRITICAL vulnerabilities, scanner errors and unavailable database
updates fail the gate. These results depend on the database at scan time.
Record the deployed image digest and rescan that exact image before deployment;
an earlier source commit or Docker tag does not identify its bytes. apk still
reads the live Wolfi repository, so independently rebuilding the source does
not produce a guaranteed identical image.

The first October 2 container scan found HIGH-severity Debian advisories,
including advisories without a recorded stable-package fix. The worker build
now upgrades base packages from the enabled Debian archives before installing
Git and certificates. This applies available fixes; it does not establish that
the resulting image is vulnerability-free. Retain the rebuilt image's actual
scan, and keep the candidate blocked while HIGH/CRITICAL findings remain.
Do not remove unfixed findings from the gate to turn it green.

A later October 2 base-image refresh moved the worker to Python 3.12.15. Its
bundled expat 2.8.5 carries the fixes for the expat denial-of-service and
memory-safety advisories that affect the 2.8.3 copy in the previous image; the
image scan reports Debian's `libexpat1`, which only `git-http-push` loads, and
cannot see Python's own copy. The build now also removes setuid and setgid bits
(`mount`, `su`, `passwd` and others). Neither change removes the unfixed Debian
findings that still block the container gate.

The worker image then moved from `python:3.12-slim-trixie` to Chainguard's
Wolfi base. On Debian the gate could not pass without exempting findings: the
55 unfixed HIGH entries (16 advisories in 22 packages) sat in packages the
worker never executes, such as util-linux, ncurses, Perl and systemd libraries,
and in `libcurl3t64-gnutls`, which Git's HTTPS transport needs and which had no
trixie fix. Wolfi installs none of the unused packages and carries current
fixes, so the gate stays strict and passes on the scanned image. Python, its
expat and Git are now packages the image scan inventories; the official Python
image built the interpreter outside the package manager, where the scan could
not see it. Rebuild and rescan deployment images: the base distribution, the
package names in the image inventory (`pkg:apk/wolfi/...`) and the virtual
environment path (`/opt/venv`) changed. The CLI, entry point, non-root UID and
mount points are unchanged.

The release-evidence workflow now verifies active merge protections before
building a candidate. Use the settings preparation and readback commands in
[merge gate and review status](#merge-gate-and-review-status) to restore the
existing ruleset without dropping checks, approvals or bypass restrictions.
Neither merging this source change nor a prepared JSON patch changes GitHub
settings. The release check fails if the API identity cannot expose bypass
actors; it does not infer an empty list from an omitted field. Do not grant
write credentials to the build job to suppress that failure.

Complete AWS/Slack and separately credentialed permission-denied
[tenant canaries](canaries.md) in the authorized deployment scope. For other
connectors, retain connector-specific live evidence. Bind those receipts and a
fresh human-reviewed holdout to this exact source/signature revision with the
[acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md).
Independent human review of the final revision remains required before release.
Offline replay and the new CI checks cannot supply these attestations.

### October 2 repository hygiene

Agentforce metadata that declares XML entities or attribute defaults is no
longer parsed, so a previously complete scan can become incomplete (exit 3):
remove the declarations, or exclude the file if it is not deployed metadata.
Embedders that imported the non-strict `bounded_safe_load_all` must switch to
`strict_bounded_safe_load_all`.

### October 1 scan integrity remediation

Rollout effects of the remediation listed in the changelog. Re-run any baseline
collected before this revision: some scans that previously finished complete now
finish incomplete because the earlier result hid a gap.

- **More exit 3 on real estates.** Expect new incomplete diagnostics for files
  with source or config names that hold a NUL byte, any file without a
  supported export suffix in a connector's offline input directory (rotated
  logs, a `README.md`, `.DS_Store`), unnamed `saas.generic` rows and negative
  gateway usage. Fix the input (exclude the path, remove the extra files or point
  `input` at the export file, supply rotated logs by name, map the name column)
  rather than ignoring exit 3. Do not read a finding that disappeared before this
  revision as resolved; compare only complete scans of the same scope.
- **Notices are not completeness.** The default-exclude notice and the AWS/GCP
  default-region notice are warnings that leave the scan complete. Scope a scan to
  an excluded directory as its own root, or set `regions` (AWS) or `locations`
  (GCP), to cover it. Review the
  notices before treating a clean report as estate-wide.
- **New report fields.** `collection_scope.not_run`, finding metadata
  `registry_match_assurance` and tag `registry-identity-unverified`, and
  `signature_verified` on JWT findings are additive. A gateway finding approved
  only by an operator-asserted caller name is still registered; treat that match
  as unverified until the caller binding is authenticated.
- **CSV consumers.** An incomplete CSV report has a first data row with
  `id=SCAN-INCOMPLETE`, `kind=scan-status` and the unfinished connectors in the
  `connector` column. Skip or alert on it; exit code 3 remains the primary signal.
- **Redaction.** Reports withhold more than before: `--passphrase`, `--pat`
  and `--auth` option values, whole PGP private key blocks (earlier reports
  could show a block's body when its first line followed a name such as
  `private_key:`), every cookie in a `Cookie` header, compact `x-api-key:S` and
  `password:S` values, unquoted values containing `;`, escaped-quote JSON values, the
  URL query keys `auth`, `pwd` and `pat`, Fireworks `fw_` keys and provider
  tokens next to non-Latin text. Reports generated before this revision can
  contain those values: regenerate them, restrict or delete the old copies, and
  rotate any key, PGP private key or session cookie they show. Expect extra
  `[REDACTED]` markers (`ffmpeg -pass 1`, the text after `;` in `NAME=S;rest`,
  the scheme after `Authorization:`). Finding IDs built from sanitized
  resource fields can change where those fields held such values.
- **Credential digest migration.** Previous candidate builds emitted public
  `credential:sha256:` digests in code/cloud evidence. The October 3 change
  replaces new credential evidence with private-key HMAC pseudonyms. Resource
  finding IDs and private gateway exact bindings stay compatible; credential
  evidence, incremental caches and comparison baselines need the migration
  described in [Credential evidence identity migration](#credential-evidence-identity-migration).
- **Lower risk for routine scope names.** OIDC `offline_access`, Salesforce
  `full`, `web` and `refresh_token`, GitLab `api`, GitHub `workflow` and Slack
  `admin` no longer match `policy.privileged-scopes`, because scopes are
  matched by bare name across providers. Findings that held only these scopes
  lose that risk factor and can drop a risk level. GitLab `api` and GitHub
  `workflow` remain powerful on their own providers: review those grants by
  hand rather than relying on the risk level.
- **Private CA.** Set `ca_bundle` on `identity.jwt` to a PEM file to scan an
  endpoint behind internal PKI; TLS verification stays on and the bundle replaces
  the default store. A relative path resolves beside the configuration file.
  Other connectors do not accept it yet.
- **Known limits.** The default 120 s connector deadline cannot finish a roughly
  20,000-file repository or a 30 MiB gateway log (raise
  `connector_timeout_seconds`); gateway finding IDs are scan-local unless
  `SHADOWSCAN_IDENTITY_KEY` is set, so `diff` of gateway findings between
  unkeyed runs is not stable; logfmt gateway lines still use last-key-wins
  for `host`.

### October 1 review migration

Collect a fresh baseline after adopting the review corrections. Named Python
direct-reference dependencies now use their declared package identity, and
Python source analysis excludes provably unreachable local statements and loop
bodies. Findings may appear or disappear, or change framework attribution;
inspect those differences before using a comparison to enforce policy. The
analysis remains bounded and does not prove runtime or interprocedural behavior.

Opt-in Git enrichment now limits combined command output to 16 KiB, author and
email fields to 1,024 characters each, and timestamps to 64 characters. Exceeded
limits, malformed metadata, cancellation and deadlines retain source findings
while making coverage incomplete. Re-run affected repositories with reviewed
metadata or with history enrichment disabled; an incomplete scan cannot establish
resolution of earlier findings.

Credential redaction recognizes more constructor, environment fallback, record,
command and query forms. The redaction policy token changes automatically with
these rules. Regenerate persisted reports, exports and incremental baselines
before sharing or reusing them, because an older artifact can contain values
now withheld. Reports remain sensitive: ambiguous comment-only credential hints
and arbitrary computed expressions do not establish safe public disclosure.

Production acceptance policies may now freeze aggregate and per-kind
`min_precision_lower95`, `min_recall_lower95` and `min_specificity_lower95`
thresholds together. Successful decisions expose the recomputed 95% Wilson lower endpoints;
the revised example also sets per-kind sample floors. Existing point-estimate
policies retain their behavior. Freeze confidence thresholds before collecting
new independently human-labeled holdout evidence, rather than tuning a policy to
a previously observed result. A small perfect sample need not pass these gates.

The [versioned merge policy](operations/merge-policy.md) and offline snapshot
checker prepare the requested review and CI enforcement. They cannot activate
live settings through the connected GitHub App. Administrator activation,
independent human approval and approved tenant acceptance remain outstanding.

### October 1 discovery review migration

Review finding kinds, capabilities and risk scores before replacing an existing
baseline. Ordinary Java chat-client construction and standalone tool declarations
are framework evidence; they do not by themselves establish an agent. Explicit
agent factories and supported concrete tool-registration patterns remain evidence
of construction or configuration, never proof of runtime execution.

Supported import-bound constructors in OpenAI Agents SDK, CrewAI, Pydantic AI,
LangGraph and LangChain no longer inherit a framework's advertised features as
configured workload capabilities. Empty tool/handoff collections and disabled
delegation do not contribute those capabilities or their risk factors. Unknown
features can remain potential capabilities in metadata; review the supporting
source before relying on a capability label for enforcement.

Submodule declarations whose source is missing or empty make source coverage
incomplete (exit 3). Clone collection also checks the immutable Git tree for
submodule entries. The scanner does not initialize submodules or contact their
URLs. Supply the intended source in a separately reviewed checkout or explicitly
exclude it from the declared scan scope; do not interpret an incomplete result
as an absence of agents. See [coverage policy](scanning.md#coverage-policy) for
the collection modes and limitations.

The new kind and capability examples are authored regressions. Keep the frozen
AI-labeled corpus unchanged and obtain fresh human-reviewed field evidence using
the [holdout procedure](evaluation.md#build-a-genuinely-held-out-field-set).
Include ordinary Java chat applications, explicit empty/disabled capabilities,
positive tool/delegation controls and incomplete source checkouts in the sampling
plan. Predeclare kind, product and capability labels before revealing scanner
results. AWS/Slack live acceptance still requires the authorized complete and
permission-denied [tenant canaries](canaries.md); other deployment scopes require
their own connector-specific evidence.

### September 27 migration and acceptance

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

HTML and CSV reports, whether sent to stdout or written with `-o`, render
terminal control and bidirectional-formatting characters visibly (tab and line
breaks remain data in CSV; tab and line feed in HTML), so `cat` or `less` on a
saved report cannot execute escape sequences taken from a scanned log. Output
sent to stdout also renders zero-width characters, the byte-order mark and
Unicode tag characters visibly, and a lone surrogate (which no encoder accepts,
and which a name read from an export can hold) is written as the escape text
`\ud800` in every format. Reporter boundaries sanitize copied diagnostics without
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

The `CI gate` job combines documentation, Linux Python 3.11–3.13, a dedicated
container security job, macOS Python 3.11 and 3.13, and DCO for pull
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
The latter contains the exact attested wheel bytes, which the workflow's
publish job uploads to PyPI only when the maintainer dispatches it with
`publish` set and approves its protected environment; retaining it approves
nothing. Evidence from an earlier main commit does not cover these source or
package changes, and local wheel checks do not establish GitHub-hosted provenance.

### September 25 migration and acceptance

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
attestation bundles without rebuilding the wheel. With the default
`publish: none` it uploads nothing; it never creates a GitHub release or
declares tenant acceptance. Review and retain its artifacts before a separate
maintainer publication decision.

After merge and successful push CI, dispatch **Release candidate evidence** on
`main` with `expected_commit` set to the full current main SHA, `ci_run_id`
set to that commit's successful CI run ID, `codeql_run_id` set to its
successful CodeQL run ID, and `ruleset_readback` set to an administrator's
`gh api repos/aisecnomad/Project-Nexus/rulesets/23913372` output taken just
before dispatch. The workflow rejects stale commits, PR-only runs, failed
checks and other workflows. GitHub withholds `bypass_actors` from the
workflow's read-only token, so the build job accepts the readback only when it
matches the job's own read in every other field, `updated_at` included, and
records in the evidence that `bypass_actors` came from that readback. Retain `release-candidate-<SHA>`,
`release-attestations-<SHA>` and `release-publication-input-<SHA>` together;
hosted retention is 90 days. Verify the candidate's `SHA256SUMS` and GitHub
attestations before publication. Publication uploads the wheel in that
publication-input artifact and never rebuilds from a tag: the isolated
`publish` job holds `id-token: write` as its only permission, waits for approval
in the protected `testpypi` or `pypi` environment, checks out nothing, and uses
PyPI trusted publishing, so no package-index token exists to leak. A `pypi`
upload also requires the maintainer's tag `v<version>` on the reviewed commit.
The one-time setup and per-release steps are in the
[publishing runbook](operations/publishing.md).

The runtime SBOM covers locked Python core/cloud dependencies. It is not a
container or operating-system SBOM and does not cover the base image, Git,
CA certificates or other Wolfi packages. Generate and review a container/OS
SBOM for the exact deployed image digest as a separate release control.

### Output and inventory migration

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

### Field review changes

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

### Completeness, report and credential changes

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

### October 1 review changes

These changes follow the 2026-10-01 repository review. Several change exit codes
or what scans report, so compare a pinned baseline with a candidate before
enforcing policy on the new output:

- **Exit codes.** Command-line usage errors (an unknown option or command, an
  invalid value such as `--min-confidence 1.5`, a missing path or
  configuration file) exit 1, like configuration and setup errors, instead of
  2. Exit 2 now only means a complete scan reached `--fail-on`, and exit 3 an
  incomplete scan or comparison. Fail CI on every non-zero exit: a script that
  treats only 2 and 3 as failures passes a scan that never ran.
- **Gateway identity.** Gateway finding IDs stay scan-local by default, and
  `diff` lists them under `not_comparable` (exit 3) instead of reporting them as
  new. To compare gateway callers across scans, inject the same
  `SHADOWSCAN_IDENTITY_KEY` (at least 32 bytes, explicitly `hex:<value>` or
  `base64:<value>`, for example `hex:` followed by `openssl rand -hex 32`) from
  a secret store into every comparable scan. Ambiguous unprefixed encodings
  stop the scan and require one of those prefixes.
  Findings then carry `identity_scope: keyed` and keep their IDs, and gateway
  inputs join the collection scope through a keyed digest. Treat the key as a
  secret: anyone who holds it can link reports and test guesses of short labels
  or keys against them. It is read only from the environment and is never
  written to reports, record exports, incremental state or git child
  processes. An invalid value stops the command with exit 1 before collection,
  findings recorded under one key never resolve against another, and rotating
  the key requires a fresh baseline.
- **Confidence.** Outside the code surface, repeated evidence of one signal
  counts once, so some identity, gateway, low-code, SaaS and cloud findings
  report lower confidence or a lower likelihood band. n8n, Make and Zapier
  findings now score their model and step-name evidence before they are
  finalized, so their confidence can rise: the demo's Zapier "Support agent"
  moves from 0.8 (`likely`) to 0.901 (`confirmed`). Re-check `--min-confidence`
  thresholds against a candidate run.
- **Inventory.** Cards accept `discovery.discriminators`, enforced like
  `regions`. `inventory stubs` writes each finding's discriminator, so findings
  that share a resource (a repository's agent project and its coding-agent
  configuration) are each registered by their own card. Cards generated
  earlier still approve every finding on their resource: regenerate them or
  add `discriminators`. Stub `names` are now plain strings.
- **AWS trust policies.** `cloud.aws` parses role trust policies instead of
  matching substrings. `Deny`, `NotAction` and `NotPrincipal` statements, and
  service names that appear only in a `Sid` or `Condition`, no longer tag a
  role `agent-execution-role`. A malformed trust policy is reported as unknown
  trust (`malformed-trust-policy`) and makes the scan incomplete.
- **Paging limits.** Every connector validates `max_pages` the same way: 0,
  negative, fractional, boolean and non-numeric values are configuration
  errors, and values above 1000 are capped at 1000. Fix such configurations
  before upgrading.
- **OCI exports.** `cloud.oci` converts SDK models with `oci.util.to_dict`, or
  through their declared fields when the SDK is absent. An object that cannot
  be converted is skipped and makes the scan incomplete instead of silently
  losing fields.
- **Detection.** Vercel AI SDK `generateText`/`streamText` calls that loop over
  tools past the first step (`stopWhen`, including AI SDK 7 `isStepCount`, or
  `maxSteps` above 1) are agents. Custom-pack `framework` code patterns now
  take effect in Python and JavaScript. Detection-rule files (ShadowScan
  signature packs, Semgrep, Sigma and gitleaks rules) are treated as data and
  listed in `metadata.detection_rule_files`, so a rescan can close findings
  that came only from such files.
- **Threshold filtering.** With `--min-confidence`, `related` links and
  `runtime_activity` references to findings below the threshold are removed.
  The runtime observations themselves remain.
- **Redaction.** Report excerpts withhold the API key passed positionally to
  well-known LLM SDK calls whose names carry no credential word: Semantic
  Kernel's .NET Azure OpenAI and OpenAI connectors, go-openai's
  `openai.DefaultConfig`, `DefaultAzureConfig` and `NewClient`,
  `new OpenAiService(...)` and `new GoogleGenerativeAI(...)` (see SECURITY.md
  for the remaining gaps). Earlier reports of such code could show the key:
  regenerate them and rotate any key they show. A long run of blanks before a
  character the Python 3.11 tokenizer cannot read no longer makes redaction
  quadratic and the scan incomplete, and on Python 3.12 and later a
  non-ASCII character after a lone carriage return, or a lone surrogate, no
  longer makes a file's analysis incomplete.

### October field scan changes

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

### October 2 review changes

These fixes came from an AI-assisted review of the October 1 candidate; neither
the review nor the fixes had a second-person review. Several of them turn a
result that used to look complete into an incomplete one, so run a candidate
scan next to the pinned baseline and read the differences before you enforce
policy on the new output.

New incomplete (exit 3) and configuration-error outcomes:

- **Unreadable analyzable files.** A file that `code.filesystem` analyzes by
  name and that still contains a NUL byte in its first 8 KiB (a binary `.plist`
  or `.xml`, a UTF-16 file without a byte-order mark) is a coverage gap named `binary or undecodable content in
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

Remote collection changes to review:

- **Listings.** Repositories are now listed in a fixed order before any is
  cloned. Over `max_repos` or `max_projects` the covered subset changes from the
  most recently active N to the first N by name (GitHub) or id (GitLab); the scan
  is incomplete either way. A bare string for `topics`, `repos` or `projects`, or
  a non-integer cap, is an error (exit 3) where it used to scan nothing.
- **Git.** Cloning needs Git 2.32 or newer, and the gitlink inventory of a clone
  needs 2.45: with 2.32 to 2.44 a clone is scanned but every repository reports
  `could not inventory gitlinks safely`, and with older or unidentifiable Git the
  connector uses sampled API mode. Both end incomplete. Clones that hold Git LFS
  pointer files are incomplete, and a repository with malformed objects at its tip
  is refused by `fsckObjects` and scanned through the sampled API fallback.
- **Termination.** SIGINT, SIGTERM, SIGHUP and the job deadline now stop live
  clones and delete their checkouts. Keep the external deadline and container or
  process-group cleanup for SIGKILL and out-of-memory kills.
- **Destinations.** `168.63.129.16` and `fec0::/10` are refused like the other
  metadata and private destinations unless `allow_private_origin` is set, and a
  URL with whitespace or control characters is an error rather than a cleaned
  value; a base URL with a stray trailing space now fails.
- **GitHub token.** Grant Secrets, Variables, Codespaces secrets and Dependabot
  secrets (read) beside Contents and Metadata, or each repository adds four
  identical `HTTP 403` warnings and the scan exits 3. Use distinct token
  variables for `code.github` and `saas.github-apps`; the credential-mixing guard
  separates scans, not token scope.

Label, precision and risk-policy changes to review:

- **`likelihood` value.** `findings[].likelihood` and the CSV `likelihood` column
  report `strong` where earlier output said `confirmed`. Dashboards, `jq` filters,
  SIEM rules and ticket automation that count or filter on `confirmed` must accept
  `strong`; accept both while old reports are in circulation. `diff` reads
  baselines written before the rename (the label is not compared and `confirmed`
  parses as `strong`), so no baseline needs regenerating. Use `confidence`, a
  number, for thresholds: `strong` does not mean verified.
- **List-only repositories.** Findings disappear for repositories that only list
  vendors (blocklists, allowlists, vendor policies, vendored signature or
  inventory data). A bare data file that names four or more providers and is the
  only evidence is no longer reported; keep its name a manifest name or add a
  signature with a `file` signal if you rely on it.
- **Plugin authors.** Evidence weights must be finite numbers in [0, 1]. A
  violation fails the connector and the scan is incomplete.
- **`risk_weights`.** A typo in a `capabilities` or `providers` key now fails the
  scan setup (exit 1) instead of being ignored. Provider ids are checked when the
  engine is built, after custom signature packs load. Check existing
  configurations for keys that never matched anything, and dry-run a change.
- **Scores.** Findings at five points of the score grid (raw 45 at confidence
  0.25, 75 at 0.15, 85 at 0.25, 125 at 0.17 and 125 at 0.21) score one higher.
  `diff` against an older baseline reports the changed `risk.score` and factor
  weight for those findings only, and a level change for the one that crosses from
  medium to high.

Redaction and lexing changes to review:

- **Redaction policy.** Credential operators, token boundaries, URL userinfo,
  record-field names, unknown value types and private-key blocks are redacted
  more completely (see the changelog). Reports can hold a little more
  `[REDACTED]` than before: comparisons with a sensitive name, `creds` and
  `db_pass`, record fields named for a credential word, and arrow functions whose
  parameter is named for a credential, which keep the arrow but lose the body.
  No finding, detection or exit code changes. The policy digest changes with the
  rules, so verified-clean digests cached on findings are recomputed, and
  `scanner_source_sha256` changes, so artifacts from an older build are not
  comparable (as for any release).
- **Earlier dumps.** `--dump-records` files written by an earlier version keep
  their older, less redacted content. Regenerate them with this version before
  you share them; a dump written now holds `[REDACTED]` for the newly covered
  field names, and offline re-analysis of it sees the marker.
- **Lexer.** Code that was hidden is now scanned when it followed a
  keyword-named property (`o.of / 1; ...`), a comment ended by a bare CR,
  U+2028 or U+2029, a JSX attribute string ending in a backslash, or a PHP
  comment closed by `?>`; expect new findings in such files. New incomplete
  (exit 3) cases are a `/` directly after `await` or `yield`, a regular
  expression after `}` that holds a quote, backtick or slash, and a JSX file
  that exhausts its look-ahead allowance (`file analysis incomplete
  (MatchTimeoutError: JavaScript lexical analysis look-ahead budget exceeded)`;
  hostile or machine-generated input, not configurable). Projects that vendor
  `emoji-regex` or similar generated tables stop reporting
  `incomplete source lexical analysis` for them.

### Real-world robustness migration (unreleased)

- **Crawler user-agent domains.** The provider-domain discount applies only
  inside a complete quoted crawler UA value. A separate endpoint on the
  same line, or another occurrence of that host later in the file, remains
  evidence. A user-agent marker elsewhere on a line cannot suppress it.
- **Input defects remain incomplete.** A checkout's own malformed content —
  invalid TOML/JSON (cookiecutter templates, fixtures), invalid structured
  configuration or agent-manifest syntax, an MCP configuration whose servers
  value is not an object or array — is now a per-file `input defect:` warning
  that preserves partial findings while keeping the scan incomplete (exit 3).
  `strict_coverage: true` promotes that diagnostic to an error; it is not
  needed to enforce incomplete coverage. There is no completeness exemption
  for malformed templates or fixtures. Integrity and ambiguity failures (duplicate keys, conflicting
  MCP dialects, YAML resource limits, undecodable analyzable files,
  unscanned symlink targets) are unchanged and still fail closed.
- **Flow exports with agent nodes are agents.** `code.filesystem` now emits
  `kind: agent` for an exported flow whose nodes include a verified agent
  node (n8n `.agent`/`agentTool`/`openAiAssistant`, Dify
  `agent_mode: enabled`), titled `Exported agent workflow (…)`; chains
  without an agent node stay `kind: workflow`. Finding identity does not
  change (`resource_type` stays `workflow-export`), so diffs resolve across
  the upgrade, but kind-based dashboards and `--fail-on` policies see such
  findings move from `workflow` to `agent`, and metadata gains
  `agent_flow`.
- **Lexer.** Brace-less JSX elements as attribute values
  (`description=<div>…</div>`, `title=<span>…</span>`, self-closing
  `icon=<Plus/>`) are now lexed completely, and JSX is tried in plain
  `.js`/`.mjs`/`.cjs` files when the plain walk is ambiguous (closing tags
  after expressions no longer read as ambiguous regex-vs-division; see the
  real-world benchmark follow-ups for when it is not used); repositories that reported
  `incomplete source lexical analysis` for such files scan complete and may
  gain findings there. A `<` right after another `<` (`mask<<shift`) is
  part of a shift and never opens an element, so the code after it stays
  visible and a file it leaves ambiguous stays incomplete.
- **Credential pass on large files.** The per-execution regex allowance
  scales linearly with input size inside the per-file wall budget, so
  keyword-dense megabyte files no longer record
  `credential detection incomplete (MatchTimeoutError)`. The ReDoS bar is
  size-relative: allowed work is proportional to input length, and
  `signatures.validate` rejects secret patterns slower than the allowance.
- **Deadline degradation is deterministic.** The walk scans manifests, MCP
  and coding-agent configuration, flow exports and IaC before source files
  (largest last), and the deadline diagnostic names the exact remainder.
  Order-sensitive truncated lists (example credentials, detection-rule
  files) may list different members than an earlier release.
- **Triage scans are always incomplete.** `triage: true` discloses the
  skipped stages per root and exits 3 by design; never compare a triage
  report against a full baseline (the configuration is part of the
  comparison fingerprint, so `diff` refuses to resolve across the modes).

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

### Finding identity and comparison migration

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
Symlinks and submodules are skipped with incomplete coverage in both modes: API mode
skips them, and a clone reports submodules (gitlinks) through the filesystem scan of the
checkout. Git LFS pointer files, which neither mode resolves, also make the scan
incomplete. Provider settings,
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

Confined regular-file reads use `O_NOFOLLOW_ANY` on macOS too, both for full
paths and paths relative to an open scan root. The kernel rejects links in any
component in the same lookup; the scanner does not call `realpath` to turn a
rejected link into an accepted input. This also avoids opening every ancestor
for reading. Nonblocking opens and `fstat` still reject FIFOs and other special
files. On other supported POSIX platforms the component-by-component confined
walk remains in use. Signature-pack directory enumeration fails if a subtree
cannot be read or the entry budget is exceeded, including directory-only
trees; correct those inputs before accepting the policy.

Source-checkout enumeration is bounded separately by `max_entries` (default
1,000,000). It counts every inspected directory entry, including skipped names
and coverage probes, before retaining it in memory. The existing `max_files`
limit keeps its file-and-link semantics. Reaching either entry or file limit
retains findings from source already assessed and marks coverage incomplete.
Cancellation and the connector deadline also make coverage incomplete;
directory-only and fully excluded trees check both during enumeration.
`code.github` and `code.gitlab` forward
`max_entries` to each checkout. Increase the entry limit explicitly when
a reviewed scan scope needs it, and retain operating-system memory limits.

Incremental fingerprints include the entry count of coverage probes inside
default-excluded directories, as well as whether those probes find a file.
Changing only descendants of an excluded directory can therefore invalidate
the cache when finding its contents requires more entries. A previously complete
cached scan cannot mask new `max_entries` exhaustion. These probes share the
fingerprint's entry, cancellation and deadline budgets. Earlier candidate
cache entries miss automatically after this scanner-source change; no manual
state migration is needed.

Incremental state uses nonblocking advisory `flock` per cache slot
(`<sha256>.lock`): shared for reading and exclusive for publication, as well as
atomic writes and current-input fingerprint checks.
Keep state in a dedicated private directory outside the scanned repository. A
busy read lock causes a cache miss; a busy write lock skips that publication.
Incremental state needs POSIX advisory locking (`fcntl`); platforms without it are ones the confined file reader already refuses, so no scan runs there. Symlinked, non-owner or non-private lock files are
rejected. Use local filesystems with working advisory locks; a lock is not a
distributed coordination service or a security boundary against another process
with the same user ID.

### Cloud collection changes

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
and cap pagination; a missing collection field is not an empty inventory. A
malformed AWS or GCP record (a function without an ARN, a service without a
config name) skips that record with a warning and incomplete coverage; the
remaining resources, services and regions are still collected. AWS diagnostics
for a failed SDK call name the operation and the provider's error code, never
the provider's message text.
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

### Consolidated candidate compatibility

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
