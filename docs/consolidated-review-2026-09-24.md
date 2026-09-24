# Consolidated production review — 24 September 2026

## Scope and disposition

Review began with `main` at `78414f4795e0c7fc5f0fb3101f901c1f310c16fa`, the
four then-open hardening PRs, and the implementation at PR #30 head
`57d0725137931ea804f0bc3dbf091e3b360627b8`. PR #30 already integrates #26
and #29. This candidate builds on that head and selectively incorporates verified
changes from PR #31 (`5f263015a4f5ed46bc4b5a7385fe5903f35670dc`), together
with additional fixes found during integration and an independent code review.
While this review was in progress, PR #31 merged into `main` as
`3bb4870e73635da52c9fcaf05a2a8d81d1afadea`. The candidate was reconciled with
that updated base, retaining the reviewed controls and the integration decisions
below. This review did not merge or close the existing PRs.

PR #33 subsequently merged this candidate through `fb366e4` into `main` as
`755ad3d2dd8fe1c8aafae7d8fee59c3d1b44a8c5`, while final CodeQL findings were
being investigated. The follow-up is based on that new main and retains its
additional HTTP, webhook-redaction, SARIF and CLI corrections. It addresses
diagnostic logging, configured credential redaction and exact Kubernetes claim
classification as described below. The external merge was not performed by this
review.

The candidate materially improves security and production reliability. It remains
a release candidate: passing automated checks cannot establish actual tenant
coverage, operational acceptance, or field detection precision. Refer to
[production rollout](production.md) and [detection evaluation](evaluation.md).

## Confirmed findings and changes

Priority describes engineering impact, not a CVSS score. All credential examples
and provider responses used for regression testing were synthetic or mocked.

| Priority | Defect and impact | Implemented correction |
|---|---|---|
| High | Malformed HTTP headers could expose token values through library error messages. | Validate constructor, injected session, mutated session and per-request headers; diagnostics omit both header names and values. Catch authentication-handler `InvalidHeader` safely. |
| High | Credentials could survive source excerpt truncation or appear as escaped diagnostic values. | Redact before truncation, expand provider-format coverage, redact SSWS authorization and known credentials' escaped representations. |
| High | Application logging accepted upstream diagnostic payloads after heuristic redaction, which cannot recognize every opaque secret. | Log fixed summaries only; retain bounded, sanitized details in access-controlled report artifacts. |
| High | Opaque Atlassian API and Azure Foundry tokens were not recognized by credential field names; GitHub's fallback token bypassed resolved configuration. | Recognize those credential fields and track the fallback token for diagnostic redaction; remove configured short secrets from diagnostics. |
| High | Azure/OCI configuration exports retained opaque values under ordinary mapping keys. | Store live configuration as `environment`, applying value-wide redaction; continue reading legacy export keys. |
| Medium | Imported risk/evidence numeric fields accepted strings and non-finite values. | Validate numeric types/ranges at import; escape numeric HTML slots and authorize only the shipped JavaScript hash through CSP. |
| Medium | Scalar cloud scopes were iterated as characters; unknown AWS services could produce apparently complete empty scans. | Normalize string/list options and reject malformed values and service names. |
| Medium | Provider errors or malformed records discarded useful neighboring observations. | Isolate Azure detail/Foundry, GitHub inventory source, identity and SaaS record failures, retaining findings with incomplete coverage. |
| Medium | Denied/malformed GCP key inventory looked like observed zero keys. | Preserve unknown key count and explicit `key_coverage`; do not imply key absence. |
| Medium | Duplicate source observations inflated confidence; broad deduplication could erase distinct custom capabilities. | Deduplicate repeated passes of the same signature signal and location while retaining distinct signal objects. |
| Medium | Gateway parsers had expensive failing regex paths; non-finite values and aggregate overflow corrupted totals. | Use linear parsers, finite conversions and atomic overflow rejection; isolate per-caller analysis failures. |
| Medium | High-cardinality gateway detail and repeated malformed records consumed unbounded report/log space. | Bound distributions, observation/interval details and diagnostics; explicitly flag coverage loss while preserving supported totals and valid later records. |
| Medium | Manifest regex calls failed under contention or imposed hidden lower budgets. | Retain caller budgets, cumulative CPU/wall limits and bounded retries; materialize bounded YAML matches before caller work. |
| Low | CODEOWNERS budgets accumulated across unrelated files; Git metadata decoding could fail on non-UTF-8 author data. | Reset lookup budgets per file, retain owner cache, decode metadata safely and isolate emit phases. |
| Low | Repeated work increased scan overhead. | Index newlines, fast-path ordinary JSON, bound inventory pattern caching, reuse OCI clients per session, and fetch JWKS once per analysis after header validation. |

Also corrected AWS Lambda layer parsing, SSM parameter ARN construction, Foundry
project scope inheritance, nested GitLab group attribution and timestamp parsing.

Final CodeQL inspection also flagged broad `kubernetes.io/` matching. This
expression classified JWT claim names, not trusted issuer URLs or authorization.
Replaced broad claim-prefix inference with recognized Kubernetes service-account
claim names and a structured `kubernetes.io` object, rejecting arbitrary namespace
suffixes and URL lookalikes. Regression tests cover the supported forms and
unrecognized claims. No alert suppression or security-gate bypass was introduced.

## Deliberate integration decisions

- Retained PR #30's default 120-second cooperative deadline, cancellation-aware
  cache/export publication, bounded worker concurrency, credential isolation,
  immutable repository snapshots, source lexical classification and release gates.
- Accepted PR #31's `connector_timeout` / `--connector-timeout` names as
  compatibility aliases for canonical `connector_timeout_seconds` /
  `--connector-timeout-seconds`. Legacy YAML null uses the 120-second default.
  Retained bounded worker capacity without replacement-worker pools. PR #36
  subsequently adds a CLI-only process exit after reporting abandoned workers;
  the embedded Engine returns an incomplete result and refuses reuse while an
  abandoned worker remains active. Diagnostic/flush errors must not prevent
  that CLI exit. Blocking publication or output still requires an externally
  supervised disposable process.
- Did not introduce digest-gated finding sanitization or a process-wide text
  sanitization cache. Digesting nested objects before the sanitizer's resource
  checks can amplify alias graphs; caching also needs explicit redaction-policy
  invalidation. Regression tests preserve repeated sanitization under mutation.
- Retained the public `Signal.compiled` field for compatibility with existing
  callers; bounded matching remains the execution path.
- Retained PR #30's stricter report import validation and stronger existing
  Salesforce/ServiceNow pagination and coverage controls.
- Used a fixed script hash in HTML CSP instead of allowing arbitrary inline
  JavaScript. The report remains self-contained with working filter/sort code.

## Validation

Final verification results are recorded in the pull request, tied to its exact
head. The review includes full pytest coverage, per-connector coverage floors,
Ruff, mypy, signature validation, both evaluation corpora, dependency audit,
hash-checked runtime installation, wheel installation outside the checkout and
offline scans. CI additionally checks Python 3.11 and container execution.

The PR #30 baseline suite reproduced a concurrent Terraform manifest regex timeout
at the fixed 0.1-second call budget. The candidate addresses that actual failure
while retaining CPU and wall-clock safety limits.

The two checked-in evaluation sets contain 39 synthetic cases and five pinned
public-file cases. Their small, selected nature cannot establish field precision,
recall, calibration or a production SLO. No authenticated tenant inventory was
performed in this review.

## Merge and deployment gates

The live `Require CI and CodeQL` ruleset was active at the start of this review,
requiring `test (3.11)`, `test (3.12)`, `analyze`, an up-to-date branch and one
approving review. Both it and `Protect main` were disabled externally before the
final merge-verification request. This review did not change their enforcement.
The user subsequently authorized merging verified open PRs. Restore the intended
repository protections before production release; verification results are tied
to the exact merged source in the PR.

Before production deployment, complete tenant canaries, held-out detection
evaluation, approved image-digest selection and an enforced host/job deadline.
Check migration notes for corrected finding IDs, exported configuration keys,
and unknown key inventory. Keep the prior reviewed version for rollback.
