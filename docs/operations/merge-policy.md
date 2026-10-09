# Enforce and verify the merge policy

The versioned [ruleset policy](https://github.com/aisecnomad/Project-Nexus/blob/main/.github/rulesets/require-ci-and-review.json)
is a desired configuration, not evidence that GitHub is enforcing it. Both
visible repository rulesets have been enabled and disabled several times since
2026-09; the dated readbacks are under
[merge gate and review status](../production.md#merge-gate-and-review-status).
On 2026-10-03 (19:06 UTC), both read back active, but the review/CI ruleset still
omitted the aggregate gate, required-check application bindings, last-push
approval and resolved-review-thread requirements. `Protect main` retained four
bypass actors. Separate classic branch protection was unavailable to the
integration used for those reads. Check the live settings rather than treating
any dated observation as permanent. On 2026-10-04, both rulesets read back
disabled. On 2026-10-06 both read back active again with the same gaps as on
2026-10-03, and `Protect main` still listed four bypass actors. The available
GitHub connector has no administration-write operation; an administrator must
restore the reviewed settings and verify exact readback.

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

## Detect protection drift between commits

The weekly [dependency and governance audit](https://github.com/aisecnomad/Project-Nexus/blob/main/.github/workflows/audit.yml)
has a separate read-only job that fetches both current rulesets and compares
their repository identities and settings to the reviewed update payloads. It
also runs on manual dispatch from `main`. A disabled rule, missing aggregate
`CI gate`, wrong application binding, changed policy, malformed response or
denied read fails the audit. A withheld `bypass_actors` field is the only allowed
omission: visible controls are still checked, while bypass assurance remains
explicitly unknown. Review any drift before intentionally updating the
versioned policy, including stronger changes.

The `observe` command retains one machine-readable observation per ruleset and
writes a scoped result to the workflow summary. Both rulesets are checked even
if one fails. The workflow retains observation artifacts for 90 days, including
failed reads and policy mismatches. Its exit status measures the visible-control
check; a successful job with a partial observation does **not** establish that
the repository has no bypass actors.

Each retained observation records a UTC `input_identity.recorded_at` timestamp
and SHA-256 digests of the same bounded snapshot and expected-policy text used
for verification. Digests cover UTF-8 text after removal of an optional leading
byte-order mark; the command reads each input once and never retains its payload
in the observation. A denied API read leaves the snapshot digest null, even if
the failed command printed valid JSON. An unreadable or oversized input also
has no inspected-text digest. Retain independently fetched source snapshots in
restricted audit storage when later comparison is needed. These hashes bind
content; the local timestamp does not authenticate the response's origin or
establish that GitHub's settings were unchanged after the read.

| Observation `status` | What was checked | Required action |
|---|---|---|
| `complete` | Every managed setting, including the visible bypass list, matched the reviewed policy. | Retain the snapshot; review freshness, origin and other protections separately. |
| `partial` | All visible managed settings matched; only `bypass_actors` was withheld. | Obtain and strictly verify a complete administrator readback before relying on no-bypass assurance. |
| `failed` | API access, parsing, identity, required fields or policy comparison failed. | Resolve the failed read or investigate the policy difference; no matching-policy assurance is provided. |

Partial observations contain `complete_readback_verified: false`,
`unknown_fields: ["bypass_actors"]` and `administrator_readback_required: true`.
They never insert an empty bypass list into the API response. If GitHub returns
a bypass list, it must match the reviewed empty list; an unexpected actor or
malformed value fails. Only the explicit `observe` command accepts the one
withheld field. The `verify` and `plan` commands still require full snapshots.

The job uses only the workflow's read-only token and never applies settings or
supplies an administrator credential. If GitHub withholds part of the response,
an administrator must verify a full readback using the procedure above; neither
partial nor failed observation establishes that protection is absent. GitHub
documents that `bypass_actors` is returned only to a caller with write access to
the ruleset. A dispatched run on 2026-10-07 failed on that withheld field; the
scoped observation now preserves useful monitoring of visible controls without
claiming complete assurance. Do not equate a hidden bypass list with an empty
one. See the
[GitHub ruleset API documentation](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset).
The release-evidence workflow reads the ruleset with the same kind of token, so
its dispatch takes an administrator readback that must match the token's own
read in every other field; see the
[publishing runbook](publishing.md).
Adding this job does not enable protections or replace an independent human
review.

Repository administration and independent reviewer availability remain
external prerequisites. Human-labeled holdouts and live tenant receipts are
separate acceptance evidence; see [evaluation](../evaluation.md),
[canaries](../canaries.md) and the
[production verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md).
