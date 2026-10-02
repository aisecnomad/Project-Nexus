# Enforce and verify the merge policy

The versioned [ruleset policy](https://github.com/aisecnomad/Project-Nexus/blob/main/.github/rulesets/require-ci-and-review.json)
is a desired configuration, not evidence that GitHub is enforcing it. Both
visible repository rulesets have been enabled and disabled several times since
2026-09; the dated readbacks are under
[merge gate and review status](../production.md#merge-gate-and-review-status),
and the most recent one found both disabled. Separate classic branch protection
was unavailable to the integration used for those reads. Check the live
settings rather than treating any dated observation as permanent.

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
# Retain and inspect current settings before changing them.
gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 > /restricted/ruleset-before.json
python -m tools.governance_check .github/rulesets/require-ci-and-review.json

# Apply the reviewed desired configuration to the existing review/CI ruleset.
gh api --method PUT repos/aisecnomad/Project-Nexus/rulesets/23913372 \
  --input .github/rulesets/require-ci-and-review.json

# Verify the persisted object and which rules actually apply to main.
gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 > /restricted/ruleset-after.json
python -m tools.governance_check /restricted/ruleset-after.json
gh api repos/aisecnomad/Project-Nexus/rules/branches/main
gh api repos/aisecnomad/Project-Nexus/branches/main/protection
```

Use a private directory you control for `/restricted`; retain snapshots beside
the selected revision's review and deployment evidence. The checker rejects
disabled/evaluation-only rules, bypass actors, missing or unbound checks,
non-strict status gates, and missing final-push review requirements. It reads
bounded unambiguous JSON without following symbolic links. Exit 0 describes
only that snapshot; it does not authenticate its origin, freshness, human
reviewer, or protection by other rulesets.

Also inspect `Protect main` (23892853), preserve any stricter history policy,
and review its bypass actors before enabling it. Enforce the no-bypass
review/CI ruleset in its own right: `Protect main` names bypass actors and does
not substitute for it. Do not add a bypass actor or reduce the approval
requirement to make a maintainer-authored change mergeable.

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
