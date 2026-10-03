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
enables a rule merely by adding a JSON file or workflow job. Use a private
directory you control for `/restricted` below and retain its files beside the
selected revision's review and deployment evidence.

Confirm that the default branch is `main`, then fetch both full ruleset objects.
The API identity must be able to read `bypass_actors`; an omitted field is not
evidence that no bypass exists. Prepare new payloads from those responses with
the existing helper. This preserves additional rules, extra checks and higher
approval counts introduced since the committed examples were prepared.

```bash
set -e
test "$(gh api repos/aisecnomad/Project-Nexus --jq .default_branch)" = main
for id in 23892853 23913372; do
  gh api "repos/aisecnomad/Project-Nexus/rulesets/$id" > "/restricted/$id-before.json"
  python -m tools.governance.rulesets plan --ruleset-id "$id" \
    --input "/restricted/$id-before.json" --output "/restricted/$id-update.json"
done
python -m tools.governance_check /restricted/23913372-update.json
```

Review both snapshots and generated payloads before the administrator applies
them. The helper activates both rulesets, removes bypass actors, strengthens
final-revision review and pins the required checks to GitHub Actions. A required
check already bound to a different application is rejected for explicit review;
it is not silently rebound. Output files must be new, so earlier reviewed bodies
cannot be overwritten accidentally. If settings change during review, fetch
fresh snapshots into new files and prepare and review them again. The committed
`.update.json` examples and historical `observed/` snapshots are not current API
evidence and must not replace this preparation.

```bash
set -e
# Administrator operations: apply only the two payloads just reviewed.
for id in 23892853 23913372; do
  gh api --method PUT "repos/aisecnomad/Project-Nexus/rulesets/$id" \
    --input "/restricted/$id-update.json" > "/restricted/$id-put-response.json"
  gh api "repos/aisecnomad/Project-Nexus/rulesets/$id" > "/restricted/$id-after.json"
  python -m tools.governance.rulesets verify --ruleset-id "$id" \
    --input "/restricted/$id-after.json" --expected "/restricted/$id-update.json"
done
python -m tools.governance_check /restricted/23913372-after.json
# Inspect the effective rules as well as the individual settings objects.
gh api repos/aisecnomad/Project-Nexus/rules/branches/main
gh api repos/aisecnomad/Project-Nexus/branches/main/protection
```

The two-ruleset verifier compares every managed field of each full readback to
its reviewed payload, including preserved rules outside the minimum policy.
GitHub may have persisted the first update if the second fails; inspect both
readbacks and complete the remaining update without weakening the active one.
An administrator-level classic branch-protection response and effective branch
rules must also be reviewed; an unavailable response is not evidence of an
unprotected branch or of successful enforcement.

The minimum-policy checker rejects
disabled/evaluation-only rules, bypass actors, missing or unbound checks,
non-strict status gates, and missing final-push review requirements. It reads
bounded unambiguous JSON without following symbolic links. Exit 0 describes
only that snapshot; it does not authenticate its origin, freshness, human
reviewer, or protection by other rulesets.

`Protect main` (23892853) retains its stricter history policy. Enforce the
review/CI ruleset (23913372) in its own right: the history policy is not a
substitute for required CI checks. Do not add a bypass actor or reduce the
approval requirement to make a maintainer-authored change mergeable.

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
