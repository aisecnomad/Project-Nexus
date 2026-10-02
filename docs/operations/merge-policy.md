# Enforce and verify the merge policy

The versioned [ruleset policy](https://github.com/aisecnomad/Project-Nexus/blob/main/.github/rulesets/require-ci-and-review.json)
is a desired configuration, not evidence that GitHub is enforcing it. The
2026-10-02 follow-up readback found both rulesets active and `main` protected.
The review/CI ruleset required one approval and the existing strict checks,
but still omitted `CI gate`, check application bindings, last-push approval
and review-thread resolution. `Protect main` still listed bypass actors.
Check the live settings rather than treating this dated observation as permanent.

The policy retains the existing CodeQL, signature and status requirements and
adds the aggregate `CI gate`. Required checks are bound to the GitHub Actions
application observed on this repository's check runs (application ID 15368).
It requires an up-to-date branch, an approving review, dismissal of stale
reviews, approval of the latest push, resolved review threads, and no bypass
actors. It also blocks branch deletion and force pushes. Review the complete
JSON before applying it; preserve any stronger rules subsequently introduced by
the maintainers. A passing automated check is not an independent human review.

## Apply with repository administration access

From the reviewed checkout, use an administrator-authenticated GitHub CLI.
The current GitHub app integration provides ruleset reads and repository writes,
but does not provide ruleset administration writes. This repository never
enables a rule merely by adding a JSON file or workflow job.

```bash
# Retain current settings and derive a new payload that preserves stronger rules.
gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 > /restricted/ruleset-before.json
python -m tools.governance.rulesets plan --ruleset-id 23913372 \
  --input /restricted/ruleset-before.json --output /restricted/ruleset-update.json
python -m tools.governance_check /restricted/ruleset-update.json

# Review the generated policy diff before applying it to the same ruleset.
gh api --method PUT repos/aisecnomad/Project-Nexus/rulesets/23913372 \
  --input /restricted/ruleset-update.json

# Verify the persisted object and which rules actually apply to main.
gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 > /restricted/ruleset-after.json
python -m tools.governance.rulesets verify --ruleset-id 23913372 \
  --input /restricted/ruleset-after.json --expected /restricted/ruleset-update.json
gh api repos/aisecnomad/Project-Nexus/rules/branches/main
gh api repos/aisecnomad/Project-Nexus/branches/main/protection
```

Use a private directory you control for `/restricted`; the generated output
must be a new file. Retain snapshots beside the selected revision's review
and deployment evidence. Preparation refuses a conflicting existing check
application binding rather than replacing it, and preserves additional checks,
stronger review requirements and other rule types. Re-fetch if settings change
before applying the reviewed body; do not PUT a stale versioned example. The checker rejects
disabled/evaluation-only rules, bypass actors, missing or unbound checks,
non-strict status gates, and missing final-push review requirements. It reads
bounded unambiguous JSON without following symbolic links. Exit 0 describes
only that snapshot; it does not authenticate its origin, freshness, human
reviewer, or protection by other rulesets.

Also inspect `Protect main` (23892853), preserve any stricter history policy,
and review its bypass actors before enabling it. The active no-bypass review/CI
ruleset must remain independently enforced. Do not add a bypass actor or reduce
the approval requirement to make a maintainer-authored change mergeable.

## Verify a candidate before merge or deployment

Require a successful `CI gate` and `analyze` on the exact head commit. Have an
eligible reviewer who did not author or produce the change approve that head.
Any later push needs renewed review. Exercise the rule with an ordinary
unapproved pull request: GitHub must refuse its merge. This check does not
require weakening the rules or merging the probe.

Repository administration and independent reviewer availability remain
external prerequisites. Human-labeled holdouts and live tenant receipts are
separate acceptance evidence; see [evaluation](../evaluation.md),
[canaries](../canaries.md) and the
[production verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md).
