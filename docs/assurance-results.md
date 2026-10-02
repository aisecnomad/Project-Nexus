# Detection and collection assurance: 2026-09-24

This change implements the five review recommendations: suppress generic-code
false positives and repeated-evidence inflation; require meaningful operational
configuration; resolve imported constructors and aliases; preserve incomplete
AWS/Slack collection; and recognize potential AI permissions expressed through
IAM `NotAction`. Additional tests cover n8n missing definitions, Slack workspace
identity and pagination, and AWS SDK endpoint-model overrides.

## Frozen independent corpus

Two separate AI reviewers labeled complete source files without scanner results,
scanner implementation or one another's labels. Their 42 decisions agreed:
12 agent positives and 30 negatives from 15 repositories in five languages.
Labels were frozen before evaluation. Full source provenance, licenses and
annotation reasons are retained in `tools/evaluation/`.

| Scanner observation | True positives | False positives | False negatives | True negatives |
| --- | ---: | ---: | ---: | ---: |
| Main at `3c619fa2511cee2eeaff80088ecfc087b9544067` | 11 | 3 | 1 | 27 |
| First implementation evaluation | 11 | 0 | 1 | 30 |
| Subsequent regression evaluation | 12 | 0 | 0 | 30 |

The first implementation result exposed a missed typed Pydantic constructor,
`Agent[Deps, Response](...)`. Supporting that syntax removed the remaining miss.
No independent case, source file or label was changed. The final result therefore
measures regression performance after feedback; it is **not a fresh held-out
accuracy estimate**. Selection is purposive, the sample is small, and reviewers
share AI-model capabilities. This is not human certification or field accuracy.

The corpus SHA-256 remains
`128cf2c972cb13b11bafe141d584b910828899d689d5a457135ad7746f98eff3`.
[Recorded reports](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/evaluation/results/README.md) preserve the initial
failures and subsequent observations. The first implementation was an uncommitted
intermediate tree, without a source fingerprint; that report records observations
but cannot identify an exact reproducible implementation. The final report hashes
the actual scanner sources, signatures and corpus. CI regenerates reports for the
reviewed commit rather than trusting these recorded results.

At the time of this 2026-09-24 review, the separate authored synthetic suite
passed 39 cases (16 positives, 23 negatives), and the earlier public-source
sample passed five. The currently committed `tools/evaluation/corpus.json` has
since grown to 77 authored synthetic cases (32 positives, 45 negatives); the
case count alone does not establish that the current scanner passes them. Check
the final commit's CI evaluation. One **synthetic** PHP fixture was corrected to
a negative: a bare `create_agent(...)` call with no framework binding cannot
establish AI-agent construction. This does not modify the frozen independent
labels. Do not combine these populations into a field score.

## Read-only canary validation

AWS and Slack runners support live collection, explicit account/workspace scope,
independently attested positive and benign controls, exact resource selectors,
complete-coverage assertions and separate permission-denied controls. They do not
provision resources, change permissions or invoke models. Receipts identify the
scanner source, signatures, scope, expectations and observations.

Offline replay and mocked SDK/HTTP tests validate control binding, malformed and
partial responses, permission failures, endpoint restrictions and receipt status.
Both example replay commands pass. Credential preflight without approved
credentials returns `LIVE_NOT_RUN` and cannot produce live acceptance.

**Live tenant canaries were not run.** Approved tenant credentials and independently
reviewed real resource controls were unavailable. Production acceptance still
requires the complete and restricted-identity runs in [canaries.md](canaries.md).
AWS and Slack acceptance does not validate other connector families or establish
estate-wide recall. Review the exact commit's CI results and complete tenant
acceptance before enabling enforcement.

## Reproduction

Use the commands in [evaluation.md](evaluation.md) and [canaries.md](canaries.md).
When this dated result was recorded, CI covered Python 3.11/3.12. The current
workflow covers Linux 3.11–3.13 and macOS 3.11/3.13 for lint, types, tests and
the overall 80% and per-connector 75% coverage floors. Linux additionally runs
the full runtime dependency audit, installed-wheel and container checks. It also
validates the annotation ledger and frozen corpus, and retains evaluation JSON
artifacts with each run.
Required checks apply to the final commit; recorded local reports do not replace
them.
