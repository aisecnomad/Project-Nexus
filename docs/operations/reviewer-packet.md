# External reviewer packet

This page is a reading list for someone who did not author the change under
review. Completing it is not an independent review and does not approve a
release. A merged pull request, a green CI check, an AI-assisted comment,
OpenSSF Scorecard results, or the files under `archive/reviews/` are not that
review. See [governance](../governance.md) and
[merge gate and review status](../production.md#merge-gate-and-review-status).

## What to treat as trusted vs untrusted

Trusted: the operator workstation or CI runner, scan configuration, and
installed Python packages.

Untrusted: remote API responses, scanned repositories, offline exports, and
third-party plugins. An allowlisted plugin runs with scanner privileges; it
is not a sandbox.

## Pin a revision before you start

```bash
git fetch origin
SHA="$(git rev-parse origin/main)"   # record this 40-character SHA
git checkout --detach "$SHA"
test "$(git rev-parse HEAD)" = "$SHA"
```

Do not review a moving `main` tip. If the author keeps merging, ask them to
stop and name one SHA. Operators who later deploy must pin that same SHA.

## What to read first

1. [AGENTS.md](https://github.com/aisecnomad/Project-Nexus/blob/main/AGENTS.md) — trust model and hard rules
2. [SECURITY.md](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md) — reporting and controls
3. [Architecture](../architecture.md) — engine, connectors, inventory
4. [Production deployment](../production.md) — install, rollout, merge-gate honesty
5. [Evaluation](../evaluation.md) — what the corpora do and do not prove
6. [Contributor review policy](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#review-and-merge-policy)
7. [Connector maturity and validation status](../connectors.md#validation-maturity-and-evidence-status) — check the published evidence level before treating a connector as production-accepted.
8. [Merge policy enforcement](merge-policy.md) — compare the versioned policy with live settings; a policy file does not activate repository rules.

## What to run

From a POSIX checkout, Python 3.11 to 3.13:

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[all]"
make check
python -m shadowscan.signatures.validate
python -m shadowscan.mappings.validate
shadowscan scan -c examples/shadowscan.offline.yaml --format json -o /tmp/shadowscan-offline.json
```

`make check` is the local stand-in for CI. An offline fixture scan is not
live tenant acceptance. Do not run live connectors against a production
tenant for a first review. Keep credentials and private exports out of the
review record.

## What not to trust

- Treat severity labels or `shadow: true` as proof of unauthorized execution.
- Treat confidence as a calibrated probability.
- Treat author-written evaluation corpora as field precision or recall.
- Treat `archive/reviews/` as an external audit.
- Treat the `0.1.2` version string as a published release.
- Treat GitHub Pages at <https://aisecnomad.github.io/Project-Nexus/> as the
  MkDocs site until Pages is switched to the Docs workflow artifact.

## Suggested review slices

Pick one. Reading every connector is a multi-day job.

| Slice | Start here | Ask |
|---|---|---|
| Engine and scan completeness | `shadowscan/engine.py`, [scan semantics](../scanning.md) | Can an incomplete collection look empty? |
| HTTP / origin controls | connector HTTP helpers, [security policy](../security.md) | SSRF, body budget, private-address default |
| Inventory binding | `shadowscan/registry.py`, [inventory](../inventory.md) | When is `shadow: true` wrong? |
| One live connector | `cloud.aws` or `identity.entra` plus its fixtures | Fail-closed on malformed pages? |
| Release path | `.github/workflows/release.yml`, [publishing runbook](publishing.md), [production](../production.md) | Can anything other than the approval-gated `publish` job upload a package, or upload anything but the attested wheel? Does anything push a tag? |

For the October 1 discovery corrections, include these paired checks:

- Ordinary Java chat construction versus explicit agent factories and supported
  concrete tool registration. A framework import is not sufficient evidence of
  either agency or a configured tool.
- Empty or disabled tool/delegation settings versus positive configured values,
  including another agent in the same project. A negative setting on one call
  must not erase independently supported capabilities elsewhere.
- A missing declared submodule versus a materialized source directory and an
  explicitly excluded path. Missing source must not look like a complete empty
  scan, and no submodule URL may be fetched automatically.
- Capability assertions in the authored evaluation corpus, separately from
  binary agent-presence metrics. These are regression checks; commission fresh
  blinded human labels before claiming field accuracy.

For the October 2 review corrections, also check:

- A long JavaScript constructor versus its short equivalent: exceeding the
  semantic budget must mark analysis incomplete and retain neighboring evidence.
- Empty Genkit initialization versus a concrete agent definition or supported
  registered-tool model call; check configured capabilities separately.
- Slow HTTPS status/header delivery versus a healthy response and connection
  reuse; cancellation must not close a socket already serving another request.
- Container evidence for the exact built image, including database freshness,
  OS/Python inventory and vulnerability failures. A smoke test alone is insufficient.
- Disabled, bypassed or incomplete merge rules versus verified active settings.
  A prepared settings patch is not evidence that the administrator applied it.

Record live ruleset enforcement independently of code review. The required
`CI gate`, existing checks and final-revision non-author approval must be
effective on `main`; their presence in workflow files alone is insufficient.

For the October 10 fleet, triage and container corrections, verify these
paired controls:

- A fleet merge of sources with `shadow: null`, `true` and `false` for the same
  finding, in every order, versus a source that claims registration without
  naming a match. Unassessed findings must stay `null`; a match must come from
  a source that names one.
- A triage run stopped by `budget_seconds`, the consecutive-failure breaker or
  the job-deadline reserve versus a healthy endpoint. Unreached findings are
  `skipped`, never `failed` or missing, and risk and completeness are unchanged.
- A CI runner whose Docker daemon reports the registry mirror versus one that
  does not; the build must not start behind an unreported mirror, and the base
  image must be pulled by the Dockerfile's digest.

For the October 9 scan evidence corrections, verify these paired controls:

- Supported SDK imports and aliases preserve credential redaction in every
  exported report; unrelated imports and ordinary values retain their meaning.
- Complete VPC flow data and no-traffic observations versus explicit collection
  loss or conflicting statuses. Known loss must produce incomplete coverage.
- Two different connections sharing an address and port retain their own TLS
  attribution, including non-AI observations and conflicting identities.
- Supported invocation operations versus management/list/poll/cancel requests;
  method and destination must come from the same event. Invocation evidence
  alone must not create a tool-use or successful-execution claim.
- Valid Rust multiline strings and JSX-in-JavaScript versus ambiguous or
  unterminated source and TypeScript generic syntax.
- Valid and empty export roundtrips versus strict JSON and byte-limit failures;
  a rejected replacement must preserve the prior file without accepting it as
  this run's export, while valid collected records remain analyzable.

These are authored regression controls. Keep the independent human holdout,
provider-specific live canaries and final-revision approval as separate evidence.

For the October 8 classification corrections, also review positive and
negative .NET/Go source classification, Python comprehension reachability and
exact device identity. Check that repeated lifecycle correlation removes derived
endpoint activity without erasing native runtime observations, and that sanitizer
safety rejections skip the unsafe record. Treat the new authored cases as
regressions. Use [repository-level field acceptance](../evaluation.md#repository-level-field-acceptance)
for fresh independently selected full repositories; obtain human labels and
authorized live tenant receipts before declaring those checks complete.

For the unreleased Python re-export and governance assurance changes, review
these paired cases:

- A supported Python import-only re-export versus a cycle, a shadowed binding
  or executable shim. Inspect the declared source-analysis limits and verify
  that scanned code is never imported or executed. A large ordinary local module
  or a consumer whose imports resolve through no shim must keep its complete
  result; a queued consumer's binding must not start inside the deadline
  margin, and a consumer left unbound must keep its lexical evidence.
- A complete governance readback versus a read-only response with withheld
  bypass settings. Visible-policy drift must fail the monitor; a partial result
  must identify unknown fields and must never satisfy full release verification.

Commission fresh blinded human labels and scoped live acceptance using the
[migration and acceptance guidance](../production.md#unreleased-attribution-migration);
the authored regression cases in this change are not a held-out field sample.

## Suggested deliverable

For the unreleased review corrections, verify these paired cases:

- Matching versus conflicting Python imports across exception and pattern-match
  alternatives, including handler aliases, guards and a no-match path. An
  uncertain branch must not establish a construction by visit order.
- Two supported named constructions in one approved project, with different
  tools. In source mode, only the exact approved resource should be registered,
  and neither construction should inherit the other's execution capabilities.
- A supplied inventory with zero entries versus no supplied inventory, and a
  permission list whose privileged entry comes after position 30. Reports must
  retain both reconciliation status and the complete permission evidence.
- A complete governance readback versus a read-only response with withheld
  bypass settings. Visible drift must fail the monitor, partial observations must
  identify unknown fields, and strict release verification must still fail an
  incomplete readback. Inspect retained observation provenance as well.

Use the [migration and acceptance procedure](../production.md#unreleased-review-migration)
to plan fresh human labels and scoped live canaries. The authored regression
fixtures do not constitute that independent evidence.

A concise review record could list the SHA reviewed, commands run, review slices
covered, findings and remaining limitations. This is a suggested record, not a
certification of independence or release approval.

## How to record a review

Use a GitHub pull request approval from an account that did not author the
commits, on the final head SHA. Quote that SHA in the review body. Do not
approve a later push without re-reading it.

Private vulnerabilities go to a
[security advisory](https://github.com/aisecnomad/Project-Nexus/security/advisories/new),
not a public issue. Conduct reports follow the
[code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md).
