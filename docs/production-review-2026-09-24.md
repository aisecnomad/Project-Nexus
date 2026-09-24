# Production assurance review — 24 September 2026

Base reviewed: `5486827cb478dc476412a6758c5897dd92d9b7ca` (`main`, including PR #25).
Disposition: implementation hardened; production rollout remains subject to tenant acceptance and an enforced merge gate.

This review examined the current implementation rather than replaying the older
findings against `b13753d`. It preserved the intervening main-branch protections
and selectively recovered useful HTTP, cloud and performance changes from the
conflicting draft PR #23. It does not merge or close that older draft.

## Confirmed findings and implemented remediation

Severity is an engineering assessment for an audit scanner, not a CVSS score.
Regression inputs were synthetic; provider responses were mocked unless stated.

| Area | Severity / impact | Remediation and regression evidence |
|---|---|---|
| Source credential redaction | High: opaque credential tails from escaped/doubled quotes and nested mapping expressions entered evidence | Bounded lexical redaction consumes the complete sensitive mapping expression, preserves line counts and retains credential fingerprints. `test_mapping_credential_redaction.py` exercises full source scans as well as sanitizer boundaries. |
| AWS attribution | High: configured `account_id` bypassed live identity verification | Always resolve STS identity and require the configured expectation to match. `test_cloud_production_scope.py` covers mismatch, malformed STS results and matching identities. |
| Transport and pagination | High assurance impact: successful HTTP error documents or malformed continuation values could terminate collection as complete; falsy TLS settings bypassed an identity check | Validate effective TLS settings, collection envelopes and continuation types; never reflect provider error secrets. Preserve connection-time destination enforcement and the current injected-adapter guard. HTTP response-integrity and trust-boundary regressions cover these paths. |
| GCP coverage | Medium: Cloud Run used an unsupported wildcard region; unreachable regions were ignored | Discover concrete Cloud Run locations and flag unreachable regions while retaining available observations. `test_cloud_production_contracts.py` uses provider-faithful fixtures. |
| Partial collection | Medium: identity/ARM/low-code failures discarded earlier findings or stopped later collections | Retain observations and mark incompleteness, paginate Okta grants, bound Auth0/ServiceNow/Salesforce loops and reject repeated pages. Keep Azure diagnostic coverage unknown when pagination fails. |
| Low-code attribution | Medium: ServiceNow display labels could break parent/tool joins; malformed records could abort neighboring records | Join references by stable IDs, validate records and remove unused Salesforce token-value fields from collection queries. `test_lowcode_provider_coverage.py` covers these cases. |
| Repository API consistency | Medium: tree enumeration and mutable-branch file downloads could inspect different file versions | Request validated enumerated blob IDs, strictly decode GitHub Base64 and mark skipped links/submodules incomplete. `test_code_api_snapshot_integrity.py` preserves real file evidence while testing those boundaries. |
| Report/configuration imports | Medium: relative globs used the process directory; unbounded or ambiguous report imports could create partial inventory stubs | Resolve paths beside configuration, bound report reads to 64 MiB, reject unsafe paths/duplicate keys/invalid finding fields, and prevalidate every record before writes. `test_core_review_boundaries.py` verifies error behavior and no partial files on malformed input. |
| Resource use | Reliability: eager inventory enumeration and repeated header classification caused unnecessary work | Stream AWS Lambda/GCP project limits, bound AWS/OCI SDK timeouts/retries, cache successful gateway classifications with bounded entries/keys and retain original regex CPU/wall deadlines during contention retries. |

Google Workspace's documented empty users/token-list envelopes remain supported;
an arbitrary empty object does not establish coverage. Provider-specific failures
remain visible even when neighboring findings are retained. Existing account
scope, stable finding identity, deterministic merge, private output, plugin,
inventory and offline-input controls were preserved.

## Validation

The existing suite passed before implementation. Combined validation uses a
fresh Python 3.12 virtual environment installed with `.[all]`, without inherited
system packages. The installer was upgraded to match CI before the dependency
audit; the exact tested environment reported no known vulnerabilities.

Full-suite counts, coverage and hosted check outcomes are recorded in the pull
request for this change. Focused tests alone are not a release gate.

Ruff, mypy (70 source files), and signature validation (178 signatures / 790
signals) passed. Mypy retains the repository's existing untyped-function-body
limitations. The wheel built successfully and its CLI and bundled signatures
were verified outside the checkout. The offline SARIF demonstration completed
with 101 results and `executionSuccessful=true`. No tenant credentials were used.

Controlled performance comparison against the reviewed base, using the same
clean environment and 1,000 identical synthetic gateway events:

| Measurement | Base | Updated |
|---|---:|---:|
| Full user-agent classification calls | 1,001 | 2 |
| Preserved events | 1,000 | 1,000 |
| Findings / incomplete | 1 / false | 1 / false |
| One local elapsed time | 0.606 s | 0.437 s |

The call-count reduction is deterministic for this workload. These single local
timings are illustrative and are not a throughput SLA. Tests also cover cache
eviction, separate analyses, event-value isolation, failed classifications and
actual expensive regex preemption.

## Release and deployment gates

1. The active `Protect main` ruleset was read during this review. It requires a
   pull request but has zero required approvals and no required CI checks.
   A maintainer must require both CI matrix checks and an approving review;
   administration settings were not changed.
2. Run read-only canaries in every intended tenant: verify the expected account,
   known resources, required permissions, failed-access behavior and exported
   replay. Mocked tests do not establish complete estate coverage.
3. Pin the accepted revision and approved dependencies, validate the worker image
   and impose an overall job deadline. AWS/OCI SDK limits do not bound every
   authentication-provider operation or the whole scan. Docker/Podman were not
   available for container execution here.
4. Keep immutable scan inputs and private outputs. GitLab tree pagination still
   uses a branch reference: per-file blob immutability is not a commit-consistent
   whole-tree snapshot. Incremental pre/post hashes are not atomic snapshots.
5. Redaction remains heuristic across arbitrary source languages and encodings.
   Sanitized reports are still sensitive. Inventory-stub validation is complete
   before writes, but a multi-file write is not transactional on filesystem error.

Package version remains `0.1.0`; this review does not publish a release or certify
the deployment environment. See [production.md](production.md) for migration and
acceptance details. The older conflicting PR #23 should not be merged wholesale
over the newer protections retained here.

## Provider contracts checked

- [Cloud Run v2 services.list](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/list): concrete region requirement.
- [Cloud Run v1 locations.list](https://docs.cloud.google.com/run/docs/reference/rest/v1/projects.locations/list): project-visible region enumeration.
- [Cloud Functions v2 functions.list](https://docs.cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions/list): unreachable-region semantics.
- [Auth0 client grants](https://auth0.com/docs/api/management/v2/client-grants/get-client-grants): bounded offset pagination.
- [Okta application grants API](https://developer.okta.com/okta-sdk-java/25.0.0/apidocs/apidocs/com/okta/sdk/resource/api/ApplicationGrantsApi.html): paginated grants collection.
