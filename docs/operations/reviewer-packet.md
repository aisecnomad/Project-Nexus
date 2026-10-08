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

For the October 8 corrections, review supported SDK argument sanitization,
positive and negative .NET/Go source classification, Python comprehension
reachability, exact device identity, and encoded-byte export/replay limits.
Confirm that size/encoding omissions preserve valid analysis, sanitizer safety
rejections skip the unsafe record, and any rejection aborts dump publication.
Check that repeated lifecycle correlation removes derived endpoint
activity without erasing native runtime observations. Treat the new authored
cases as regressions. Use [repository-level field acceptance](../evaluation.md#repository-level-field-acceptance)
for fresh independently selected full repositories; obtain human labels and
authorized live tenant receipts before declaring those checks complete.

## Suggested deliverable

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
