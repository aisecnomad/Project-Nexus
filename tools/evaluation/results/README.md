# Recorded evaluation observations

These JSON reports preserve the observations described in
[assurance-results.md](../../../docs/assurance-results.md).

- `independent-baseline.json`: main commit `3c619fa2511cee2eeaff80088ecfc087b9544067`, before these changes. The older evaluator did not emit annotation or implementation metadata; the corpus digest matches the separately validated frozen ledger.
- `independent-first-implementation.json`: the first patched evaluation, before fixing typed Pydantic construction. This was an uncommitted intermediate tree without a source hash, so it is observation history, not an exact reproducible scanner revision.
- `independent-regression.json`: subsequent result, with the actual scanner-source and signature hashes, on the same unchanged corpus and labels. This set has now informed implementation and is regression evidence.

Timing values are local diagnostics, not production SLOs. Rerun evaluation for
the exact commit under review and use that commit's CI artifacts for release
evidence. Successful replay and these source results do not establish live tenant
acceptance or representative field accuracy.
