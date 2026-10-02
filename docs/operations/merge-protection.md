# Restore and verify merge protection

The October 2, 2026 authenticated API review found both `Protect main`
(`23892853`) and `Require CI and CodeQL` (`23913372`) disabled. The branch
response reported `protected: false`. Those observations describe that review,
not a permanent state. This document and the checked-in definition do not change
GitHub settings.

## Reviewed definition

`.github/rulesets/require-ci-and-codeql.json` is an importable desired definition
for `Require CI and CodeQL`. It retains the October 2 ruleset's existing checks,
CodeQL alert thresholds, code-quality warnings, Copilot review settings, signed
commits and force-push restriction. It adds the aggregate `CI gate`, deletion
protection and linear history. Independent approval, stale-review dismissal,
approval of the latest push and conversation resolution are required. Bypass
actors are empty. GitHub does not let an author approve their own pull request;
Copilot review does not replace an eligible independent human reviewer.

| Control | Required value |
| --- | --- |
| Target and enforcement | Default branch, active, no exclusions |
| Required checks | `CI gate`, `analyze`, `test (3.11)`, `test (3.12)`, each bound to GitHub Actions |
| Branch freshness | Strict up-to-date checks, including branch creation |
| Independent approval | At least one; dismiss stale approvals and require latest-push approval |
| Remaining protections | Signed commits, no deletion/force push, linear history, resolved conversations |
| Existing analysis rules | CodeQL medium-or-higher security alerts and errors; code-quality warnings; Copilot review |
| Bypass actors | None |

The four required contexts bind to GitHub Actions with `integration_id: 15368`.
That application ID and `github-actions` slug were confirmed from check suite
`99944881545` for reviewed commit
`b01e9ef45b4b0b4da5a2beaa1038ce9f0df44171` on October 2. The downloaded ruleset
did not bind these contexts; the desired definition adds the binding so another
status-producing integration cannot satisfy the required names. Preserve the
bindings of additional checks. Verify the app identity against fresh check runs
when applying this definition to a different repository or GitHub installation.

Check the proposed definition locally:

```bash
python -m tools.governance --definition \
  --ruleset .github/rulesets/require-ci-and-codeql.json
```

Its successful output is explicitly `uninstalled_definition`. This is a policy
lint result, not evidence that GitHub enforces the definition.

## Administrator update of the existing ruleset

Use an authenticated GitHub CLI session with repository administration rights,
or edit the existing ruleset in repository Settings. No token belongs in this
repository or in a command argument. An independent eligible human reviewer must
be available before enabling the approval gate. Keep the gate enabled when a
reviewer is unavailable; do not bypass it to merge the maintainer's own work.

1. Download fresh details for **both** existing rulesets and retain the originals
   with restricted access. Do not overwrite the live configuration from an old
   export or the checked-in example.

   ```bash
   umask 077
   mkdir -p governance-evidence
   gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 \
     > governance-evidence/23913372-before.json
   gh api repos/aisecnomad/Project-Nexus/rulesets/23892853 \
     > governance-evidence/23892853-before.json
   gh api repos/aisecnomad/Project-Nexus/rules/branches/main \
     > governance-evidence/main-before.json
   ```

2. Prepare an update body from the **fresh** `23913372` response. Preserve every
   unrelated rule, stronger threshold, additional status check and its integration
   binding. The four required names must use the verified GitHub Actions binding.
   The following command only creates a local file:

   ```bash
   jq '{name, target, enforcement, bypass_actors, conditions, rules}' \
     governance-evidence/23913372-before.json \
     > governance-evidence/23913372-proposed.json
   ```

   Edit that file using the checked-in desired definition as the minimum. Set
   enforcement to `active`, clear bypass actors and branch exclusions, include
   `~DEFAULT_BRANCH`, add missing required checks and protections, bind all four
   required names to `integration_id: 15368`, and strengthen
   review settings to the table above. Preserve approval counts above one. The
   desired definition includes the deletion and linear-history protections from
   `Protect main`; do not remove or weaken either existing ruleset. Compare fresh
   rules from `23892853` too, retaining any additional or stronger protections
   it now contains. The local verifier checks this documented policy floor; it
   cannot prove arbitrary unrelated settings were preserved.

3. Validate and independently review the complete proposed diff:

   ```bash
   python -m tools.governance --definition \
     --ruleset governance-evidence/23913372-proposed.json
   jq -S '{name, target, enforcement, bypass_actors, conditions, rules}' \
     governance-evidence/23913372-before.json > governance-evidence/before-sorted.json
   jq -S . governance-evidence/23913372-proposed.json > governance-evidence/proposed-sorted.json
   diff -u governance-evidence/before-sorted.json governance-evidence/proposed-sorted.json
   ```

   A nonzero `diff` exit is expected for the reviewed changes. Confirm the source
   repository and ruleset ID in the original response. Download the ruleset again
   immediately before writing; if it changed during review, refresh the proposed
   body and repeat review. GitHub's ruleset update endpoint does not provide this
   workflow with an atomic compare-and-swap guarantee. Coordinate with other
   administrators to avoid overwriting simultaneous changes.

4. An authorized administrator can apply the reviewed body to the **existing**
   `23913372` ruleset. GitHub's documented update method is **PUT**, not PATCH:

   ```bash
   gh api --method PUT repos/aisecnomad/Project-Nexus/rulesets/23913372 \
     --input governance-evidence/23913372-proposed.json \
     > governance-evidence/23913372-update-response.json
   ```

   This is the only remotely modifying command on this page. It must follow
   review of the actual proposed body. Importing the checked-in JSON through the
   UI creates a separate ruleset; updating the existing rule is preferred.

5. Download fresh readbacks independently of the update response:

   ```bash
   gh api repos/aisecnomad/Project-Nexus/rulesets/23913372 \
     > governance-evidence/23913372-after.json
   python -m tools.governance --ruleset governance-evidence/23913372-after.json
   gh api repos/aisecnomad/Project-Nexus/rules/branches/main \
     > governance-evidence/main-after.json
   gh api repos/aisecnomad/Project-Nexus/branches/main \
     > governance-evidence/branch-after.json
   ```

   Check that the effective rules on `main` contain the intended status, review,
   signature and history protections and that the branch reports protection.
   Review any remaining active rulesets and their scope. Keep the timestamped
   authenticated readbacks and final human review with deployment evidence.

## Verifier scope and exit status

`python -m tools.governance --ruleset FILE` expects the detailed GitHub REST
response for repository ruleset `23913372`, including source identity and the
explicit bypass list. It rejects disabled/evaluate modes, another ruleset or
repository, missing default-branch scope, any exclusions or bypass actors,
weakened required controls, unbound or wrongly bound required checks and ambiguous
duplicate rules/check contexts. Stronger
settings and additional rules are accepted without mutation. Inputs are bounded,
reject duplicate JSON keys and symbolic links, and never execute source code.

Exit `0` means the supplied snapshot meets the policy floor; `1` means a policy
or ambiguous-JSON failure; `2` means unreadable or malformed input. The command
does not contact GitHub, authenticate the JSON, verify freshness, combine rulesets,
authenticate a human reviewer, or prove effective branch enforcement. A saved or
fabricated active JSON file can pass; only authenticated live readback and review
justify an enforcement claim. Run the snapshot check again when selecting a
release commit. Do not claim the October 2 disabled settings were repaired until
the administrator update and effective-branch readback have actually succeeded.

GitHub references: [ruleset REST API](https://docs.github.com/en/rest/repos/rules#update-a-repository-ruleset)
and [available rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).
