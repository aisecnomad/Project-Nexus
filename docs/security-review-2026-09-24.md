# Project Nexus: software and security review

Review date: 24 September 2026. Baseline: `f2c667fba4f09a070acb5d76a4e7eca63961a6f7`
on `main`, including PR #18's production fixes and PR #20's README changes.

## Assessment

ShadowScan has substantive security controls and an extensive regression suite.
This review reproduced remaining collection-integrity, configuration and
aggregation defects, and implements the fixes below. No confirmed critical
vulnerability was identified in this review. This is a source and local test
assessment, not certification of tenant coverage or production readiness.

The important risk is unreliable security evidence: a malformed response can
look like an empty successful inventory, a configuration mistake can remove a
requested constraint, and aggregation can change attribution or confidence.
Those failures matter even when the scanner does not modify external systems.

## Findings and implemented changes

Severity is a contextual engineering assessment, not a CVSS calculation.

| ID | Severity | Confirmed behavior at baseline | Implemented change |
| --- | --- | --- | --- |
| R1 | Medium | HTTP JSON and ordinary response consumers could buffer unbounded bodies; compressed/chunked responses were not capped by default. | Default 16 MiB decoded-body budget, bounded GET/POST/JSON/pagination reads, closure on failures, and no buffering of rejected/retry/redirect bodies. |
| R2 | Medium | Missing/wrong collection arrays in successful pagination responses could become empty inventories; Azure Resource Graph and Google token responses also accepted unknown objects. | Validate collection envelopes and continuation types, fail collection visibly, and narrowly accept identified Google empty-list responses. |
| R3 | Medium | Missing environment variables expanded to empty strings; unknown/duplicate configuration fields and invalid risk levels could silently remove intended policy. | Fail before collection; validate schema and gates; reject duplicate authored keys; preserve explicit defaults and ordinary YAML merge overrides. |
| R4 | Medium | Later AWS pagination failures could discard all earlier records; Azure later failures also discarded buffered rows. | Preserve collected evidence, mark incomplete, and bound repeated/manual AWS pagination. |
| R5 | Medium | GCP audit events for one principal across projects were combined under the first project's attribution. | Partition callers by resource project and principal; preserve separate identities/counts. |
| R6 | Medium | Merge code appended repeated evidence without updating its deduplication set; parallel completion order chose conflicting owner/metadata values. | Prevent repeated evidence from inflating confidence; merge results in configured connector order. |
| R7 | Low | Gateway source/observation deduplication repeatedly compared nested dictionaries against growing lists; deeply nested corrupt cache JSON prevented normal cache-miss fallback. | Structural hashing preserves distinct source provenance; malformed cache JSON triggers a full scan. |

Additional hardening:

- Injected `requests.Session` instances no longer retain longer-prefix adapters
  that override the shared destination-enforcing adapter. This protects an
  integration boundary; injected transports were already trusted extensions.
- AWS and OCI explicitly configure connect/read timeouts and finite retries.
  AWS STS uses the same settings. This does not create a universal connector
  wall-clock deadline or govern every credential-provider transport.
- Malformed rate-limit headers cannot bypass response closure or expose header
  content through integer/date parsing errors.
- Replaced the abbreviated license notice with the full canonical Apache-2.0
  license text from https://www.apache.org/licenses/LICENSE-2.0.txt.

The main changed modules are [HTTP](../shadowscan/utils/http.py),
[configuration](../shadowscan/config.py), [engine](../shadowscan/engine.py),
[incremental cache](../shadowscan/incremental.py),
[AWS](../shadowscan/connectors/cloud/aws.py),
[Azure](../shadowscan/connectors/cloud/azure.py),
[GCP](../shadowscan/connectors/cloud/gcp.py),
[OCI](../shadowscan/connectors/cloud/oci.py), and
[Google Workspace](../shadowscan/connectors/identity/google_workspace.py).

## Optimization and design decisions

Gateway observation deduplication now uses a hash set instead of repeated linear
searches through nested records. A local illustrative helper benchmark with
8,000 observations and 4,000 unique records produced identical output in about
0.032 seconds versus 0.639 seconds previously. This measures that operation,
not end-to-end scan performance; workload and hardware affect results.

Cache storage already uses unique temporary files, atomic replacement and
content fingerprints. A six-writer concurrency regression verified that readers
receive complete matching payloads. No exclusive lock was added: it would not
fix a demonstrated corruption defect. Concurrent runs can still duplicate work
or evict one another's cache hits. Inputs should remain immutable during scans.

Hand-authored inventory wildcard approvals remain supported because they are
documented operator policy. Generated literal bindings remain escaped. Blanket
approval is an operational choice requiring review, not a newly forbidden syntax.

## Validation

Local validation used Python 3.12.14 in a fresh virtual environment with all
cloud/development extras and upgraded packaging tools, matching the CI install
procedure. Results for the combined patch:

| Check | Result |
| --- | --- |
| Full pytest suite | 1,228 passed, no skips or failures; 205 seconds |
| Statement coverage | 86.28%, above the existing 80% gate |
| Ruff | Passed |
| mypy | Passed for 69 source files; fresh cache used |
| Signature validation | 178 signatures / 790 signals passed |
| Isolated `pip-audit` | No known vulnerabilities in the resolved environment |
| Wheel build | Passed |
| Installed wheel outside checkout | Signature validation and CLI help passed |
| Offline SARIF scan | Complete; 101 findings; zero errors |
| Patch whitespace | Passed |

The dependency result applies to the resolved versions, not every historical
version allowed by the package's broad dependency ranges. Local execution
covered Python 3.12; the repository's hosted matrix additionally covers 3.11.

New regressions cover compressed and chunked HTTP bodies, strict pagination,
configuration policy, cloud partial failures and project attribution, Google
empty-list contracts, merge idempotence, deterministic ordering and cache
concurrency. Provider calls use test doubles, real SDK objects where useful,
and local HTTP/TLS test fixtures; they do not contact production tenants.

## Open pull requests

At the reviewed remote refs, PR #17 (`c6e536f`) and PR #19 (`1ccb494`) merge cleanly
with the reviewed `main`. PR #19 contains six additive operational files; it is
not a complete implementation of its changelog. In particular, its 0.1.1,
universal connector-deadline, cache-locking and split-CI claims must be reconciled
with code before release. This review retains package version 0.1.0.

PR #8 (`99ae381`) has conflicts in identity JWT, Git, HTTP, JWKS and their tests.
Current `main` already contains stronger overlapping changes. Audit unique work
before treating it as superseded; do not choose the older branch wholesale when
resolving conflicts. No existing PR was merged or closed by this review.

GitHub reports `main` as protected. Specific required-check and reviewer rules
were not independently inspected. Installation examples pin an older commit;
refresh release pins only to the final reviewed and accepted implementation.

## Deployment limits and migration

Read [deployment and migration](production.md) before upgrading configurations.
Strict validation is deliberately incompatible with silently ignored malformed
configuration. Existing valid explicit configuration remains supported.

Before production acceptance, exercise each intended connector in its actual
tenant using read-only credentials, verify known-resource coverage, test denied
access and export replay, enforce worker deadlines/egress/resource limits, and
pin a reviewed dependency set. Cloud SDK/Git transports remain separate from the
shared HTTP policy. Redacted reports remain sensitive. Raw `stream=True` callers
are responsible for bounded reads and response closure.

Google's omitted-empty-list compatibility follows its official
[Directory users sample](https://developers.google.com/apps-script/advanced/admin-sdk-directory#list_all_users)
and [token-list response contract](https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list).
Unrecognized objects still cannot establish empty inventory coverage.
