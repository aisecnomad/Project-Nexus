# Scan state and runtime correlation

## Coverage policy

A code scan is *complete* when every file it was asked to assess was assessed.
Two situations are deliberately outside a repository's own content:

* **Symbolic links** are never followed. A link whose target resolves inside the
  scan root loses nothing (the target is scanned at its real path) and is
  skipped silently. A link that leaves the root, or cannot be resolved, is
  skipped with a warning.
* **Oversize files** (`max_file_size`, default 1 MiB, e.g. recorded HTTP
  cassettes) are skipped with a warning.

With `strict_coverage: true` (`--strict-coverage`) both become errors and the
scan is incomplete (exit code 3). Use strict mode for enforcement gates, and
raise `max_file_size` or add `exclude` patterns for known data files.

Analysis limits are reported with their reason, for example
`file analysis incomplete (MatchTimeoutError: source binding call limit exceeded)`.
The import binder only counts calls into modules that a signature describes,
so large ordinary files (test suites, HTTP clients) no longer hit the limit.

## Test and fixture code

Library test suites often construct agents to exercise integrations. Evidence
found only under test or fixture paths (`tests/`, `fixtures/`, `cassettes/`,
`__mocks__/`, `test_*.py`, `*_test.go`, `*.spec.ts`, …) has half weight and cannot
promote a project to an *agent*; a project whose evidence is entirely test code
is tagged `test-code-only`. Set `include_tests: true` (`--include-tests`) to
treat test code like any other source. Credentials are still reported from test
paths unless they are recognisable placeholders (repeated characters, marker
words such as `EXAMPLE`, or very low character diversity).

## Incremental scans

Incremental mode reuses a completed connector result when SHA-256 content hashes
of its inputs, connector options, signature definitions and scanner implementation
are unchanged. Inventory approval, risk scoring and runtime correlation always
run again. New, edited and deleted files invalidate the affected repository.

```bash
shadowscan code ./repo-a ./repo-b --incremental
shadowscan run cloud.aws --input ./exports/aws.jsonl --incremental
shadowscan scan -c shadowscan.yaml --no-incremental
```

Equivalent YAML:

```yaml
options:
  incremental: true
  state_dir: ../private-scan-state
connectors:
  - name: code.filesystem
    paths: [./repo-a, ./repo-b]
  - name: cloud.aws
    input: ./exports/aws.jsonl
```

Each `code.filesystem.paths` root is a separate cache unit. Offline local directory
inputs to `code.github` / `code.gitlab` and static exports to the four `cloud.*`
connectors are also eligible. Live remote repositories, live cloud APIs, gateway
logs, identity, SaaS inputs and third-party connectors are collected anew: unchanged configuration cannot
establish that remote state is unchanged. Hashing still reads eligible inputs;
the saving is avoiding repeated parsing and signature evaluation.

When a shared `label` is set for multiple `code.filesystem.paths`, add
`root_ids: [repo-a, repo-b]` in the same order as `paths`. This keeps each root's
finding identity stable when the checkout location or list length changes.
Without `root_ids`, the canonical local path determines a distinct root suffix.
Using a scalar `path` with its own connector `label` preserves the older ID.

The default state location is `$XDG_STATE_HOME/shadowscan`, or
`~/.local/state/shadowscan`. `--state-dir` overrides it; YAML relative paths are
resolved against the configuration file. Keep the directory outside every scan
input. State uses a private 0700 directory and atomic 0600 JSON files containing
sanitized, unscored findings, not source content or raw credentials. Protect the
state as local security data; a checksum detects corruption, not a malicious user
who controls the scanner account. Remove the state directory to clear it.

Incomplete scans are never cached. Corrupt, incompatible or unsafe state and
symlink-bearing eligible inputs cause a full scan. Hashing has conservative limits:
512 MiB total, 200,000 entries, 30 seconds per snapshot, and 64 MiB per file (code
files are further capped by `max_file_size`, default 1,000,000 bytes). Exceeding a
limit falls back to normal scanning. Git replacement refs, grafts or externally
overridden history also disable reuse; HEAD and shallow boundaries are tracked.
Symlinked roots and ancestor path components are also ineligible for reuse.
Input changes detected between hashing and collection make the result
incomplete and require a rerun. `--dump-records` disables cache reuse to ensure the
requested export is actually collected. JSON connector statistics expose `cached`;
the private cache fingerprint stays in the access-restricted state directory.
Cached connectors examine zero objects during analysis.
Pre/post hashes do not form an atomic snapshot: inputs must remain immutable
throughout the scan to exclude changes that occur and revert between reads.

## Offline input limits

Offline connectors skip symlinks and bound directory walks and file parsing. The
defaults are 10,000 files, 32 MiB per file, and 256 MiB total per connector input.
JSONL, CSV and gateway text logs are streamed; individual lines are capped at
4 MiB. Gzip gateway logs are limited by expanded size as well as compressed file
size. JSON and YAML documents are parsed only after their file and aggregate byte
limits pass.

Set `max_input_files`, `max_input_file_bytes` or `max_input_bytes` on a connector
to change these limits. Gateway scans also honor `max_records` (default 5,000,000)
while analyzing streamed events. If any limit is reached, ShadowScan retains the
findings already collected and marks the connector incomplete; check the warnings
and rerun with an appropriate limit to claim full coverage. The existing hard
ceilings remain 200,000 directory entries, 64 MiB per file and 512 MiB total.
`options.min_confidence` must be a finite number from 0 through 1, inclusive.

YAML also has structural limits before object construction: 100,000 composed or
expanded nodes, 1,000 aliases, depth 64 and 64 MiB of expanded scalar content.
Recursive aliases and excessive merge expansion are rejected. Sanitization uses
separate structure and work budgets; rejected records mark collection incomplete
while valid neighboring records remain available. CODEOWNERS matching has a
bounded per-lookup work budget; an exhausted lookup marks the root's ownership
coverage incomplete.

Record dumps use a private directory and distinct filenames per configured
connector instance. `manifest.json` maps configuration ordinals to committed
export files and records each instance's completion status. Use only entries
marked `exported: true`; a failed attempt may leave an older file in place.
`gateway.logs` does not export source records through `--dump-records`: provider
key IDs and arbitrary log payloads can be sensitive even when a generic field
sanitizer does not recognize them. Its manifest entry has `exported: false`;
gateway findings and scan completion are unaffected.
See [deployment and migration](production.md) for explicit plugin, signature
override and private-endpoint policies, output changes and rollout checks.

## Connector deadlines and parallelism

`options.connector_timeout_seconds` (or `--connector-timeout-seconds`) sets a
positive, finite completion deadline for each connector, defaulting to 120 seconds.
It starts when the connector worker begins; split filesystem roots share that
connector's deadline. Legacy `options.connector_timeout` and `--connector-timeout`
are deprecated compatibility aliases. Configure only one YAML key; supplying
both is rejected. Legacy YAML `connector_timeout: null` uses the 120-second
default; it does not disable the deadline.

On expiry, the engine discards that connector's results, records incomplete
coverage and the reason, retains other completed connectors' findings, and
returns an incomplete scan (CLI exit 3). Cancellation is cooperative: Python
cannot forcibly interrupt a thread blocked in a vendor SDK or plugin call. Such
a call may outlive `Engine.run()`; once timeout handling returns, the CLI writes
the incomplete report and exits without joining the abandoned thread. A worker
already publishing a cache or record artifact can delay timeout handling while
its filesystem replacement finishes. Embedded callers must supervise their
process, and a reusable Engine refuses another scan while an abandoned worker
remains active. No replacement
workers are created beyond the configured parallelism; if all slots remain
occupied by timed-out calls, queued connectors are skipped with incomplete
coverage. Enforce an external process or CI job deadline for a hard runtime limit.

`options.parallel` (default 4) is the maximum number of worker threads. Additional
workers can improve throughput when connectors wait on network APIs. Offline
exports and repository scans also perform CPU-intensive parsing and matching;
extra threads can add contention. The offline example uses two workers as a
starting point; measure representative workloads before increasing parallelism.

## Link code to gateway activity

A static dependency alone cannot establish runtime use. Configure a binding
between a specific code `resource` and gateway caller from your own inventory:

```yaml
connectors:
  - name: code.filesystem
    path: ./ops-agent
    label: github:acme/ops-agent
  - name: gateway.logs
    input: ./gateway.jsonl
    correlation_bindings:
      - code_resource: github:acme/ops-agent
        caller: principal:svc-ops
        scope: {tenant: tenant-a}
```

An example generic gateway record:

```json
{"service":"svc-ops","tenant_id":"tenant-a","user_agent":"langchain/0.3","model":"gpt-4o","timestamp":"2026-09-22T10:00:00Z","environment":"production"}
```

In this example, `service` and `environment` are assertions made by the export.
An operator should verify that the log producer supplies a trustworthy workload
identity and deployment label before using the result as production evidence.

`scope` is required. It must exactly match all detected canonical `tenant`,
`account`, `project` and `workspace` fields. Use `{}` only for an unscoped export.
Names, shared providers, shared frameworks and pre-existing `related` links do
not establish workload identity. User-agent/IP address, anonymous, and shared
gateway or workspace fallback callers cannot be bound to a code resource,
even when the string is an exact match. A duplicated code resource across
distinct accounts, providers or connectors is ambiguous and remains unknown.
The gateway must also identify an LLM transaction by model or compatible
endpoint/host. Access logs with a path require a recognized LLM/API route;
a framework user agent or model field on `/favicon.ico` does not qualify as
execution evidence.

API-key callers use a private, connector-local `credential:hmac-sha256:<64 hex
digits>` report identifier. A public SHA-256 fingerprint of a short key or key
ID is recoverable by guessing it offline. An operator can still configure an
exact `api-key:credential:sha256:...` binding computed privately from the raw
key, which the connector checks in memory without writing that public digest to
findings. Keep binding configuration private: publishing a public digest of a
guessable key would itself disclose the key. The exported HMAC is scan-local
and cannot be pasted into a future binding. Other caller names changed by
credential redaction remain `unverified` for runtime attribution. Do not put
raw API keys into bindings.

If a gateway scope label overlaps a credential or uses an opaque scope prefix,
the report contains a `scope:hmac-sha256:…` value instead. The connector uses
an ephemeral private key so these values preserve distinct tenant groups within
one connector instance without exposing short labels to offline guessing. They
change across independent scans and cannot serve as cross-run identifiers or
correlation binding values. Gateway source IDs always use a private scan-local
key because configuration can include short labels or bindings even if no
accepted event uses that scope. The configured gateway label itself is written
to findings; do not put secrets in labels. The engine shares that key across gateway
jobs in one report, so duplicate sources retain one identity, and creates a new
key for each scan. Direct connector instances use independent keys. Redacted scope scans are
marked incomplete; gateway exports are noncomparable across independent runs.
Resolve the scope/credential overlap before interpreting a report comparison
as evidence that a finding was resolved.

Code findings with frameworks gain `metadata.runtime_activity`:

| Field | Meaning |
|---|---|
| `status: observed` | The bound gateway export contains timestamped, LLM-classified requests bearing a matching framework fingerprint. |
| `status: unobserved` | Linked telemetry exists but contains no matching framework fingerprint within the export window. |
| `status: unknown` | No eligible binding, ambiguous code identity, or missing matching-event timestamps. |
| `window`, `last_seen`, `events` | Time bounds and counts of matching timestamped events. |
| `production_observed` | At least one matching event carries `prod`/`production` in `environment` or `deployment_environment` (including event metadata). This is a label in the supplied data, not independently established deployment state. |
| `production_label_verified` | `false`: ShadowScan cannot establish the origin or accuracy of deployment labels in imported logs. |
| `sources` | Gateway finding IDs, export provenance, scope, identity and environment assurance, and per-observation details. |

Timestamp, framework and production label must belong to the same event. A caller
named `prod-agent` is insufficient. Generic service or principal fields carry
`operator-asserted` identity assurance. A recognized provider field can carry
`provider-authenticated-field` assurance when it originates from a trusted
provider export, but ShadowScan does not cryptographically verify that provenance.
Framework fingerprints in user agents can be spoofed. Inspect the source
assurance and validate the export's trust chain before claiming an identified
workload is executing in production. Missing logs do not prove inactivity, and
old events do not establish current execution. Correlation does not increase
static confidence or reduce risk.

Gateway finding IDs include the canonical input path and relevant connector
configuration (label, format, filters and bindings). This changes IDs from older
reports. Repeating an identical configured source within one connector instance
is idempotent for nonredacted principal/service callers; API-key callers and
redacted scopes use connector-local HMAC IDs. Gateway exports are noncomparable
across independent scans to avoid claiming that a missing scan-local ID is a
resolved finding. Distinct exports retain
separate provenance. Overlapping exports count observations from each source,
so aggregate counts are not guaranteed to represent unique requests.

OpenAI organization usage exports with `data[].results[]` are supported.
`metadata.events` counts requests and `metadata.records` counts exported rows;
`usage_intervals` preserves bucket boundaries and counts. A bucket is not a
per-request timestamp: it cannot establish hourly continuous activity or confirm
timestamped framework execution for runtime correlation.

## Comparing reports

`shadowscan diff baseline.json current.json` reports new findings and substantive
changes, including permissions, classification, ownership, registration and risk
score/factors within the same risk band. Each changed item includes
`changed_fields`. Missing findings count as resolved only when both reports
completed, declare the same supported finding-identity schema and have the same
`collection_scope` fingerprint. This opaque digest covers
selected source paths, connector settings, filters, confidence threshold,
signatures and scanner implementation. File contents and inventory approvals
are excluded so real removals and approval changes can be compared. A public
digest does not hide guessable paths or labels; keep these settings nonsecret.
Credential-bearing configurations omit the digest, and gateway exports cannot
attest comparable scope because private caller/scope identities may change
between scans.

Incomplete scans, changed scope, older reports without provenance, live provider
collections and third-party connectors cannot establish equivalent coverage.
Their missing findings are reported as `unknown`, and diff exits 3. New and
changed findings remain visible. Currently only local repositories and offline
exports from built-in connectors can attest comparable scope; live account and
permission coverage require additional provider-specific provenance.

Finding IDs do not depend on inferred kind. Stable resource-type families (or an
explicit plugin `identity_discriminator`) separate distinct observations on a
resource. Regenerate comparison baselines after upgrading from legacy IDs;
cross-schema comparisons retain missing findings as unknown. Incompatible cache
entries cause a full rescan.

## Completion and migration

| CLI exit | Meaning |
|---|---|
| `0` | Scan completed and the configured risk threshold was not reached. |
| `2` | Completed scan reached `--fail-on` (Click also uses 2 for invocation errors). |
| `3` | Collection or analysis was incomplete, including empty or partly invalid connector selection. |

`--min-confidence` and YAML `options.min_confidence` accept finite values in
`[0, 1]`; invalid thresholds stop the scan instead of silently clearing the gate.

Incomplete results preserve valid findings, set `summary.complete` to false and
SARIF `invocations[].executionSuccessful` to false, and include diagnostics.
Failed or denied live collection for an enabled source marks coverage incomplete;
review per-connector diagnostics and rerun after restoring access.
Malformed files are isolated, so one bad manifest cannot suppress neighboring
findings. Regex matches have time budgets; exhausted budgets mark the scan
incomplete. Configure `code.filesystem.scan_timeout` in seconds to adjust the
shared per-file regex budget (default 2 seconds); manifest parsers additionally
cap each pattern at one second within that budget.

Denied or failed API requests and exhausted pagination mark collection incomplete.
Offline exports require valid objects or arrays of objects; scalar records,
invalid envelopes and malformed rows are errors. Use `[]` in JSON/YAML or
`{"records": []}` in JSONL for an explicitly empty inventory; an empty file does
not establish successful collection. Valid neighboring records are retained.
Export files are capped at 64 MiB each, 512 MiB total and 200,000 filesystem
entries; symlinks and special files are rejected. Gateway gzip input is bounded
before and after decompression. These limits also apply to custom gateway and
JWT loaders.

Cloud offline inputs use ShadowScan's normalized record format, including a
recognized `_kind` discriminator (see `tests/fixtures/cloud/`). Arbitrary raw
provider responses need conversion to that format. Missing or unsupported
record kinds and malformed resource identifiers make collection incomplete;
they are never treated as a successfully scanned empty inventory.

Existing inventory entries that rely on names alone must add reviewed `resources`
bindings. Names now offer review suggestions without approving a finding or
reducing risk. Surface, provider and account restrictions are enforced; multiple
matching approvals remain ambiguous. See [inventory](inventory.md).

Signature files are validated before use and in CI. Unknown fields (including
`severity`), malformed regexes, duplicate definitions and invalid weights fail
validation. Severity is computed centrally by the risk engine rather than set in
a signature. See [signature authoring](signatures.md).
