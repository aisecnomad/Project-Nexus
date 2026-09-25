# Software and security hardening log, 24 September 2026

> **Internal, AI-assisted hardening log. Not an independent review.**
> This document was produced by the project's single maintainer with AI
> assistance on 2026-09-24 while hardening the code it describes. The author of
> the changes also wrote this assessment; no second person or third party has
> verified its findings, its regression claims or its disposition, and it must
> not be cited as an external security or production review. An independent
> review would need to cover, at minimum: the trust boundary and HTTP transport
> policy in `shadowscan/utils/http.py`; credential redaction in findings,
> reports and record dumps; the fail-closed and incomplete-coverage semantics in
> the engine and every connector; the cloud, identity and low-code collectors
> against real tenant permissions rather than mocked responses; the dependency
> lock, wheel build and container process; and the repository and CI settings
> that this log takes as given. See [CONTRIBUTING.md](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md)
> for the review policy and [deployment and migration](../../docs/production.md) for
> the current rollout guide.

Review date: 24 September 2026. Initial baseline:
`f2c667fba4f09a070acb5d76a4e7eca63961a6f7`. Follow-up baseline:
`c4f03cc2e4d99a39f1b8188b02ef220bc4011901`, including merged PRs #19, #21 and #22.

## Follow-up findings

PR #23's initial hosted Python 3.11 checks passed tests, coverage, lint, typing,
dependency audit and wheel validation. The subsequent offline scan exited 3
after two gateway records encountered `MatchTimeoutError`; Python 3.12 was
cancelled by the matrix's fail-fast behavior. The independent AI code-scanning
service failed before analysis with `The requested model is not supported`.
That service failure is not a reported code vulnerability or a successful scan.

The updated branch integrates current `main` and its bounded public HTTP readers
with PR #23's strict envelopes, bounded ordinary response reads, session policy
and explicit Google empty-list handling. Merge regressions check both interfaces.

New verified issues and changes:

| Issue | Impact | Change |
| --- | --- | --- |
| Repeated gateway user-agent matching and regex timeout accounting under thread contention | Normal exported records can be marked incomplete even when the expression itself is cheap. | Cache bounded successful framework classifications and retry only qualifying contention timeouts within the original CPU and wall-clock budgets. |
| Cloud limits applied after enumeration | `max_lambda` and `max_projects` still allow unnecessary upstream enumeration and memory use. | Stream collection and stop at the configured cap; preserve incomplete status when coverage is limited. |
| Live AWS configured account bypasses STS resolution | Actual caller credentials can be attributed to a different configured account. | Verify live STS identity and reject a mismatching configured account before collection. Offline labels retain their existing role. |
| Release documentation asserts absent controls | Operators could rely on nonexistent total deadlines, cache locks, split CI or a released 0.1.1. | Correct the changelog to an accurate Unreleased entry and document actual worker/runtime limits. |

CI now retains both Python matrix results after one fails and does not persist
checkout credentials. Docker build-context and quick-start changes are reviewed
as source; container execution is not claimed where no Docker daemon is available.

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

The main changed modules are [HTTP](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/utils/http.py),
[configuration](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/config.py), [engine](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/engine.py),
[incremental cache](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/incremental.py),
[AWS](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/connectors/cloud/aws.py),
[Azure](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/connectors/cloud/azure.py),
[GCP](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/connectors/cloud/gcp.py),
[OCI](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/connectors/cloud/oci.py), and
[Google Workspace](https://github.com/aisecnomad/Project-Nexus/blob/main/shadowscan/connectors/identity/google_workspace.py).

## Optimization and design decisions

Gateway observation deduplication now uses a hash set instead of repeated linear
searches through nested records. A local illustrative helper benchmark with
8,000 observations and 4,000 unique records produced identical output in about
0.032 seconds versus 0.639 seconds previously. This measures that operation,
not end-to-end scan performance; workload and hardware affect results.

The follow-up gateway optimization caches only successful, immutable framework
classifications within one analysis: at most 256 user agents, each at most 1,024
characters. A local 1,000-event illustrative workload reduced full user-agent
classification calls from 1,001 to 2, retained all 1,000 events, and ran in
0.532 seconds versus 0.670 seconds with this cache disabled. The call counts are
the repeatable optimization; those timings are not a throughput guarantee.

Regex contention retries share the original pattern CPU budget and input wall
deadline, with at most two retries. A real pathological expression is still
preempted without a retry. Successful matching is checked against both budgets;
failed or partial user-agent classifications are never cached.

Cache storage already uses unique temporary files, atomic replacement and
content fingerprints. A six-writer concurrency regression verified that readers
receive complete matching payloads. No exclusive lock was added: it would not
fix a demonstrated corruption defect. Concurrent runs can still duplicate work
or evict one another's cache hits. Inputs should remain immutable during scans.

Hand-authored inventory wildcard approvals remain supported because they are
documented operator policy. Generated literal bindings remain escaped. Blanket
approval is an operational choice requiring review, not a newly forbidden syntax.

## Initial validation

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

## Follow-up validation

The combined changes and `main` baseline `c4f03cc` were validated locally with
Python 3.12.14 and all development/cloud extras:

| Check | Result |
| --- | --- |
| Full pytest suite | 1,347 passed, no skips or failures |
| Statement coverage | 89.83%, above the 80% gate |
| Ruff and mypy | Passed; 69 source files checked by mypy |
| Signature validation | 178 signatures / 790 signals passed |
| Dependency audit | No known vulnerabilities in the resolved environment |
| Wheel build and installed-wheel checks outside checkout | Passed |
| Three offline scans, six parallel connectors | Each complete with 101 findings and zero errors |
| Same-author integration re-check | No blocking HTTP, identity, aggregation or cloud regression identified |
| Docker image execution | Not run; Docker/Podman unavailable |

Regressions reproduce scheduler contention using real regex execution and verify
that expensive expressions, cumulative CPU exhaustion and wall deadlines still
fail closed. Additional coverage checks cache bounds/isolation, AWS account
mismatch, lazy cloud enumeration, and both public HTTP reader interfaces.
Hosted Python 3.11/3.12 and CodeQL results remain separate checks on the published
commit; see the PR checks for their current state.

Before publication, a concurrent update merged the same `main` baseline into the
draft branch (`02616c5`). That history was preserved. Its additional two-line
HTTP `stream` type guard was retained, with five invalid-input regressions;
245 HTTP, pagination and JWT tests passed afterward, as did Ruff and mypy.
This final reconciliation changed no other production code from the full-suite
run above.

## Open pull requests and release controls

PR #19 has merged into `main`; its public response-reader changes are preserved.
This branch corrects its unsupported release claims and retains package version
0.1.0. PR #21 merged into `main` during this review as `c4f03cc`; its identity,
inventory, provider coverage, source parsing and Markdown rendering changes are
included through the updated baseline and tested together with this patch.
PR #17 updates the Ruff minimum. No existing PR was merged or closed by this
review.

The active [Protect main ruleset](https://github.com/aisecnomad/Project-Nexus/rules/23892853)
was independently inspected. It requires pull requests and blocks deletion and
non-fast-forward updates, but has no required status-check rule and requires
zero approving reviews. A protected-branch label therefore does not establish
that failed CI cannot be merged. Require both Python test jobs and an approving
review before using `main` as a release gate. This review does not change
repository administration settings.

Installation examples pin an older commit; refresh release pins only to the
final reviewed and accepted implementation. Live tenant acceptance, reviewed
dependency constraints and worker egress/deadline policies remain deployment
requirements.

## Deployment limits and migration

Read [deployment and migration](../../docs/production.md) before upgrading configurations.
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
