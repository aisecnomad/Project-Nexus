# Scan state and runtime correlation

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
Input changes detected between hashing and collection make the result
incomplete and require a rerun. `--dump-records` disables cache reuse to ensure the
requested export is actually collected. JSON connector statistics expose `cached`
and `cache_key`; cached connectors examine zero objects during analysis.

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

API-key callers use a stable `credential:sha256:<64 hex digits>` identifier.
Copy the full caller resource from the gateway report (for example
`api-key:credential:sha256:...` or `litellm-key:credential:sha256:...`); do not put
raw API keys into bindings.

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
reports. Repeating an identical configured source is idempotent; distinct exports
retain separate provenance. Overlapping exports count observations from each
source, so aggregate counts are not guaranteed to represent unique requests.

OpenAI organization usage exports with `data[].results[]` are supported.
`metadata.events` counts requests and `metadata.records` counts exported rows;
`usage_intervals` preserves bucket boundaries and counts. A bucket is not a
per-request timestamp: it cannot establish hourly continuous activity or confirm
timestamped framework execution for runtime correlation.

## Comparing reports

`shadowscan diff baseline.json current.json` reports new findings and risk-level
changes. Missing findings count as resolved only when both reports completed
and have the same `collection_scope` fingerprint. This opaque digest covers
selected source paths, connector settings, filters, confidence threshold,
signatures and scanner implementation. File contents and inventory approvals
are excluded so real removals and approval changes can be compared.

Incomplete scans, changed scope, older reports without provenance, live provider
collections and third-party connectors cannot establish equivalent coverage.
Their missing findings are reported as `unknown`, and diff exits 3. New and
changed findings remain visible. Currently only local repositories and offline
exports from built-in connectors can attest comparable scope; live account and
permission coverage require additional provider-specific provenance.

## Completion and migration

| CLI exit | Meaning |
|---|---|
| `0` | Scan completed and the configured risk threshold was not reached. |
| `2` | Completed scan reached `--fail-on` (Click also uses 2 for invocation errors). |
| `3` | Collection or analysis was incomplete, including empty connector selection. |

`--min-confidence` and YAML `options.min_confidence` accept finite values in
`[0, 1]`; invalid thresholds stop the scan instead of silently clearing the gate.

Incomplete results preserve valid findings, set `summary.complete` to false and
SARIF `invocations[].executionSuccessful` to false, and include diagnostics.
Failed or denied live collection for an enabled source marks coverage incomplete;
review per-connector diagnostics and rerun after restoring access.
Malformed files are isolated, so one bad manifest cannot suppress neighboring
findings. Regex matches have time budgets; exhausted budgets mark the scan
incomplete. Configure `code.filesystem.scan_timeout` in seconds to adjust the
shared per-file regex budget (default 2 seconds).

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
