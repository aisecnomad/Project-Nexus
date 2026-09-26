# Scope-specific production evidence gate

`python -m tools.acceptance manifest.json --output decision.json` checks that a
reviewed deployment evidence packet is internally consistent with a policy chosen
before evaluation. It performs no provider calls, uses no credentials, executes
no sampled code and creates no deployment. It is repository assurance tooling,
not part of the installed `shadowscan` wheel.

| Exit / status | Meaning |
| --- | --- |
| `0 / EVIDENCE_CONSISTENT` | Declared evidence meets the configured checks for the named population/scopes. |
| `1 / EVIDENCE_REJECTED` | Missing, malformed, stale, mismatched or insufficient evidence. The private report contains a stable reason code. |
| `2 / EVIDENCE_OUTPUT_ERROR` | The decision could not be saved. |

A pass **does not certify production readiness**. The gate cannot authenticate a
reviewer's identity, establish human independence, prove a set was never used for
tuning, distinguish forged/stubbed transport from real transport, or prove that an
operator-recorded exit status/principal separation is accurate. Those are explicit
operator declarations requiring organizational review and access-controlled audit
storage. Hashes provide content binding, not signatures or trust. Neither bundled
replays nor synthetic unit-test receipts are live tenant evidence.

## Supported intended deployments

Every intended deployment must be named in `deployments`. Supported entries are:

- `code.filesystem`: a `scope.population` identifier matching
  `evaluation.population`. This covers the declared static-code sample population;
  it does not validate repository acquisition, remote connectors or runtime activity.
- `cloud.aws`: exact account, explicit regions and selected services, with one
  passing complete receipt and one passing permission-denied receipt.
- `saas.slack`: exact immutable workspace ID, with the same receipt pair.

Other connector names are rejected. An AWS/Slack pass cannot cover Teams, Azure,
GitHub, or any other connector by implication. AWS region/service lists must be
sorted and contain no duplicates. Canary receipt scope must match the manifest
exactly; generate the canary config with that same order. The tool does not inspect
a separate deployment configuration, so operators must ensure the declared scopes
match the intended rollout. Adding a connector or scope requires new evidence.

## Evaluation evidence

Start with a new, independently sampled and human-labeled holdout following
[`docs/evaluation.md`](../../docs/evaluation.md). The bundled AI-labeled corpus is a
regression set and does not qualify. Freeze the sampling and numerical acceptance
policy before freezing the holdout or inspecting scanner observations. Set
`human_reviewed` and `never_used_for_tuning` to `true` only when those statements
are accurate. Two reviewers' labels and any adjudication must be recorded in the
existing annotations schema with method
`independent-human-double-label-before-scan`; the corpus must be `adjudicated`.

Run the existing evaluation command on the exact reviewed scanner candidate:

```bash
python -m tools.evaluation.evaluate --corpus /secure/holdout.json \
  --annotations /secure/annotations.json --output /secure/evaluation.json
```

The manifest binds all three artifacts by SHA-256. Paths resolve relative to the
manifest, or may be absolute. The gate validates the actual corpus and annotation
bytes, checks report label provenance, recomputes metrics from individual results,
and requires current scanner source/signature fingerprints. Evaluation output has
no execution timestamp, so `evaluated_at` is explicitly an operator declaration.

The verifier rejects a holdout that repeats an exact file's bytes or recorded
repository/commit/path from the five bundled evaluated corpora: synthetic,
public, realistic multi-file, AI-labeled independent, and September 25 review.
Both this verifier and `tools.evaluation.accept` use the same source-overlap
validator. They reject repeated nonblank file contents and source locations
across holdout cases, including renamed copies and partial overlap between
multi-file cases. A case is one sampling unit: repeated files within that one
case do not add observations. Empty package scaffolding is allowed between
otherwise distinct holdout cases, but repeated entirely blank cases are rejected.
The prior-corpus exclusion remains strict even for empty files. These exact checks
do not establish statistical independence or detect near duplicates.
Repository names are compared without case;
commit and path remain exact. Declare **every additional previously evaluated
corpus** in optional `evaluation.prior_corpora`, as an array of the same
`{"path": ..., "sha256": ...}` references (at most 32). The verifier checks
their hashes and rejects reused source bytes/locations. It cannot discover an
omitted private corpus, near duplicates or a source previously shown to a
reviewer outside these records; check those during independent selection. The
family name `all` is reserved for aggregate metrics and is rejected before
the verifier summarizes results. The adjudicated holdout cannot use any
`known_gap` flag; its evaluator report must include an empty `known_gaps`
summary and must mark every case as `known_gap: false`.

The operator chooses `min_cases`, `min_positive_cases`, `min_negative_cases`,
`min_precision`, `min_recall`, and `min_specificity`. There are no automatic claims
that these thresholds are adequate for a particular risk appetite. The production
verifier requires `min_cases` of at least 20, and the human-labeled holdout must
contain positive and negative cases; the evaluator permits at most 500 cases.
The three-repository and two-negatives-per-positive rules apply to public or
AI-labeled evaluation corpora, not to the private human holdout. Review source
diversity and class balance explicitly, and choose stricter counts from the
deployment population and risk.
The gate compares **point estimates**, not confidence intervals or calibrated
probabilities. Review sample uncertainty, strata, coverage and operational budgets
outside this gate. A report with classification errors can meet operator-selected
metrics; structural assertion failures always fail the gate.

For an enforcement decision, specify optional `policy.per_kind` so strong aggregate
scores cannot conceal misses for an important target kind. Its keys must exactly
match the holdout's target finding kinds. Each kind requires positive and negative
sample minima (at least one each) and maximum false positive/negative counts.
For example, an agent-only policy can add:

```json
"per_kind": {
  "agent": {
    "min_positive_cases": 25,
    "min_negative_cases": 75,
    "max_false_positives": 0,
    "max_false_negatives": 0
  }
}
```

These counts are illustrative, not measured field performance. An existing
manifest without `per_kind` remains valid and uses its original aggregate
thresholds. The decision now includes per-kind confusion matrices even when
per-kind limits were not supplied, so reviewers can inspect what was covered.

## Tenant evidence

Follow [`docs/canaries.md`](../../docs/canaries.md) with approved existing controls
and audit identities. Retain the actual complete and separately credentialed
permission-denied command receipts and process exits. Both must be `LIVE_PASS`,
with current scanner/canary source and signature fingerprints, the exact intended
scope, fresh collection times and the correct expected completeness. Complete
receipts must contain observed positive and negative controls; AWS control ARNs
must belong to a selected account, region and supported service/resource family.

Each manifest receipt wrapper declares `process_exit_code: 0`,
`real_tenant_transport: true`, `separate_process: true` and an opaque `principal_ref`.
Use different audit references for the complete and restricted identities. These
references are not credentials and do not independently prove identity separation.
Do not include tokens, keys or other credential values in the manifest. Never mark
a replay or unit-test fixture as real tenant transport.

All receipt/evaluation/review timestamps require an explicit timezone. The existing
canary producer also permits date-only `ground_truth.reviewed_at`; those dates are
compared to the collection start's UTC calendar date. Policy and holdout freeze
timestamps must precede evaluation, review must follow evaluation and receipt
completion, and future timestamps are rejected. `max_age_hours` is operator-chosen
between 1 and 720 hours, measured from the current verification time. Rerun
acceptance when scanner sources, signatures, intended scope or permissions change.

## Manifest template

[`manifest.example.json`](manifest.example.json) is deliberately incomplete and
cannot pass. Replace timestamps, artifact paths/digests, population and thresholds
with reviewed values. Use `sha256sum` on the retained files to obtain their exact
digests. The template contains a code-only deployment; for a provider deployment,
add this structure (values below are placeholders, not evidence):

```json
{
  "connector": "saas.slack",
  "scope": {"team_id": "TWORKSPACE"},
  "complete": {
    "artifact": {"path": "slack-complete.json", "sha256": "REPLACE_WITH_SHA256"},
    "process_exit_code": 0,
    "real_tenant_transport": false,
    "principal_ref": "approved-audit-reference",
    "separate_process": false
  },
  "permission_denied": {
    "artifact": {"path": "slack-denied.json", "sha256": "REPLACE_WITH_SHA256"},
    "process_exit_code": 0,
    "real_tenant_transport": false,
    "principal_ref": "restricted-audit-reference",
    "separate_process": false
  }
}
```

AWS entries use `"connector": "cloud.aws"` and a scope such as
`{"account_id":"123456789012","regions":["us-east-1"],"services":["lambda"]}`.
The ID here is illustrative. Never run against a scope without authorization.

Input JSON is bounded to 2 MiB per file, 32 levels and 100,000 values; duplicate
keys, NaN/infinity, symlinks and unknown manifest fields are rejected. At most 32
intended scopes are accepted. The decision contains aggregate counts, metrics,
source fingerprints and limitations, without raw evidence, account/workspace IDs,
reviewer names, principal references or source text. Decisions use atomic private
`0600` output (an existing character device, or a named pipe you own with mode
`0600`, is written in place). Keep the manifest, evidence, policy, actual process logs and decision
in your existing controlled audit store; none is cryptographically authenticated
by this tool.
