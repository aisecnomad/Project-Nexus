# Changelog

## Unreleased — 2026-09-24

Hardening changes following the 0.1.0 review. Package metadata remains at 0.1.0;
this entry does not announce a 0.1.1 release or completed production acceptance.

### Security

- Accountless short AWS IDs cannot approve registry entries; missing account
  scope makes the scan incomplete.
- Filesystem roots and in-scope source links cannot bypass symlink confinement;
  rejected or skipped links make coverage incomplete.
- Origin-specific injected HTTP adapters cannot bypass destination enforcement.
- Finding identity separates stable resource identity from inferred classification;
  promotion from framework usage to agent preserves merge and comparison identity.
- Shared HTTP responses and JSON/pagination helpers default to a 16 MiB decoded
  body limit. Injected Requests sessions receive the destination-policy adapter.
- Required `${ENV}` substitutions reject missing or empty values. Configuration
  rejects duplicate authored YAML keys and invalid security-gate options.
- Live AWS account labels must match verified STS identity before collection.
- Full Apache-2.0 license text and project notice are included.

### Reliability

- Successful AWS inventory pages survive later collection failures, which mark
  coverage incomplete. AWS and OCI clients have explicit socket timeouts and
  bounded retries. These are not total connector deadlines; use worker deadlines.
- Shared HTTP pagination rejects invalid collection envelopes and continuation
  values. Incomplete scans exit 3; complete scans that exceed the
  configured `--fail-on` threshold exit 2.
- Parallel connector results merge in configuration order. Evidence deduplication
  is idempotent, and gateway observation deduplication uses structural hashing.
- Later Azure Resource Graph page failures retain observed resources. GCP caller
  attribution remains scoped by project. Boolean and integer metadata remain
  distinct during deterministic aggregation.
- AWS Lambda and GCP project limits stop discovery without loading the entire
  inventory first. Truncation continues to mark coverage incomplete.
- Gateway analysis reuses bounded successful user-agent classifications. Regex
  contention retries share the original CPU and input wall-clock budgets.
- Malformed incremental state triggers a full scan. Cache writes use atomic
  replacement and fingerprint validation; concurrent writers can duplicate work
  or evict cache hits. There is no exclusive cache lock.

### Operations

- Incremental fingerprints skip literal excluded source directories while
  retaining CODEOWNERS inputs; project attribution scales with active ancestors.
- A disposable non-root Docker worker is available for core and offline scanning.
  Its build checks installed signatures and the CLI outside the source directory.
  Live cloud SDK extras require a separately prepared image.
- CI checks signatures, lint, typing, dependencies, coverage, wheel installation
  and offline scanning in a Python 3.11/3.12 matrix. These remain steps within one
  job, with a concurrency group and a job timeout. CodeQL runs separately.
- Both Python matrix jobs finish independently, and checkout credentials are
  removed after checkout.
- Example installation commands pin a reviewed commit; update the pin only after
  reviewing a replacement. Incomplete scans must remain failed CI gates.
- Production guidance covers credential separation, egress controls, tenant
  canaries, private reports and rollback. Tenant acceptance remains required.

### Migration

- Rebuild baselines when the `shadowscan.finding-identity/v2` schema differs from
  an earlier report. Package version alone does not establish schema compatibility.
- Review configuration for the stricter validation before rollout. Explicit
  `${VAR:-default}` fallbacks remain supported, including empty optional defaults.
- Deploy an approved commit and dependency set, retaining the previous version
  for rollback.
