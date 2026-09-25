# Contributing to ShadowScan

Thank you for your interest in making ShadowScan better. This guide covers
everything from setting up your environment to getting a PR merged.

## Code of conduct

Participation is governed by the [Code of conduct](CODE_OF_CONDUCT.md), including
its reporting and enforcement process. For usage questions, start with the
[Support guide](SUPPORT.md). Report vulnerabilities through the
[security policy](SECURITY.md#reporting), never through a public issue.

## Choose a contribution

- **Documentation:** fix a confusing step, add a synthetic example, or improve
  an explanation. No live tenant or cloud credentials are needed. Use the
  [documentation form](https://github.com/aisecnomad/Project-Nexus/issues/new?template=documentation.yml)
  or submit a focused pull request.
- **Detection quality:** provide a minimal positive or negative fixture with the
  expected outcome and why it is correct. A dependency name alone does not prove
  an agent is running.
- **Bugs:** use the [bug report form](https://github.com/aisecnomad/Project-Nexus/issues/new/choose)
  and include the full scanner commit, command, expected result and a sanitized
  reproducer. Search existing issues first; add evidence to an existing report
  where possible.
- **Connectors or architecture:** open a proposal before implementing a large
  change so maintainers can agree on scope, permissions and offline fixtures.
- **Review:** explain what you inspected and verified, including limits. Review
  from someone who did not author the change is especially valuable.

Browse [open issues](https://github.com/aisecnomad/Project-Nexus/issues) or propose
a small improvement if no suitable issue exists. You can ask for scope guidance
on the issue before starting; there is no expectation to build a large feature
as your first contribution.

## Getting started

Use Python 3.11 or newer and Git. Fork the repository on GitHub if you need a
branch you can push; clone your fork in that case. In a local checkout:

```bash
git clone https://github.com/aisecnomad/Project-Nexus.git
cd Project-Nexus
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\Activate.ps1
git switch -c fix/short-description
python -m pip install -e ".[all]"    # dev + cloud + docs extras
make install-hooks                   # pre-commit hooks (recommended)
```

Cloud extras (`pip install -e ".[cloud]"`) are optional. Offline fixtures cover
the cloud connectors; do not commit live tenant exports.

Run `make help` for a quick reference of all development commands.

## Run one test

After the development setup above, run one offline test from the repository root:

```bash
python -m pytest -q tests/unit/test_signatures.py::test_all_signatures_load_and_validate
```

This validates that the bundled signatures load successfully. It needs no cloud
credentials. When iterating on a change, replace the path and test name with the
relevant test; a single-test pass does not establish full-suite coverage.

Existing Make targets provide the next steps:

```bash
make test-fast       # full test suite without coverage, stop at first failure
make test            # full suite with the overall coverage floor
make coverage-gate   # connector coverage; run after make test
make check           # all local quality gates
```

To run the connector coverage check directly after the full coverage test run,
export a report and pass its filename explicitly:

```bash
python -m coverage json -o /tmp/shadowscan-coverage.json
python -m tools.coverage_gate /tmp/shadowscan-coverage.json
```

The gate requires the JSON report argument; running one test is not enough to
measure every connector. See [quality gates](#quality-gates) for CI requirements.

## Trust model

The operator workstation or CI runner, the scan configuration, and installed
Python packages are trusted. Remote API responses, scanned repositories, and
offline exports are untrusted. Third-party connectors are not a sandbox: an
approved plugin runs with scanner privileges.

## Quality gates

Run `make check` for the main local quality gates. CI is the authoritative
merge check and additionally builds and validates the installed wheel, exercises
SARIF output and the container, and runs CodeQL. The CI workflow defines the
exact supported Python matrix and dependency pins.

| Gate | Command | Requirement |
|------|---------|-------------|
| Lint | `ruff check shadowscan tests tools` | No errors |
| Types | `mypy shadowscan tools/evaluation tools/canaries tools/acceptance tools/release` | No errors |
| Tests | `pytest --cov --cov-fail-under=80` | ≥ 80% aggregate |
| Connectors | `make coverage-gate` (after tests) | ≥ 75% per connector |
| Signatures | `python -m shadowscan.signatures.validate` | All valid |
| Audit | `pip-audit` | No known vulnerabilities |
| Evaluation | `make evaluate` | All bundled corpora pass |

The same gates as individual commands:

```bash
python -m pip install -e ".[cloud,dev]"
python -m shadowscan.signatures.validate
ruff check shadowscan tests tools
mypy shadowscan tools/evaluation tools/canaries tools/acceptance tools/release
pip-audit --progress-spinner off
python -m pytest -q --cov=shadowscan --cov-fail-under=80
make coverage-gate
make evaluate
```

The cloud SDKs (`boto3`, `google-auth`, `azure-identity`, `oci`) are optional
extras for users, but the test suite is gated with them installed, so use
`".[cloud,dev]"` as shown above. CI installs the hash-locked
`requirements.lock`, which contains every cloud SDK. Offline fixtures cover the
cloud connectors; do not commit live tenant exports.

Do not commit private adjudicated evaluation corpora.

## Pull requests

1. Make one focused change on your branch. For a documentation-only change,
   check the affected links and run `mkdocs build --strict` if the site changes.
2. Run the checks relevant to your change, then the full gates before requesting
   review for code changes. Explain any check you could not run and why.
3. Push your branch to your fork and open a pull request against `main`. Link the
   related issue with `Fixes #123` only when the PR resolves it completely.
4. Explain the problem, the resulting behavior and the validation performed.
   Draft PRs are welcome when you want feedback before the implementation is done.
5. Address review feedback and rerun affected checks after updating the branch.
   If the PR received independent approval, request renewed review after
   changing the approved commit. The requirements below apply to the final commit.

- Target `main`. Do not push reviewed security changes directly.
- Keep findings fail-closed: a limit, malformed export, or denied API must mark
  the scan incomplete (exit 3) rather than look empty.
- Do not log raw credentials, JWTs, or unsanitized connector configuration.
- Pin GitHub Actions by full commit SHA. Do not leave `persist-credentials`
  enabled on checkouts that do not need to push.
- Update `CHANGELOG.md` under Unreleased and `docs/production.md` when a change
  affects rollout, finding identity, or credential policy.
- Include regression tests for bug fixes.
- Use the PR template checklist — it matches the CI gates.

When changing workflows or issue forms, run `make policy` to check action pins,
permissions, manual publishing boundaries, and issue-form structure and labels.

## Writing a connector

See [docs/architecture.md](docs/architecture.md) for the full connector
contract. In brief:

1. Create a module under `shadowscan/connectors/<surface>/`.
2. Implement `collect()` (live API) and `analyze()` (offline records → findings).
3. Register in `shadowscan/connectors/__init__.py`.
4. Add offline test fixtures under `tests/fixtures/`.
5. Achieve ≥ 75% statement coverage.
6. Document in `docs/connectors.md` with configuration keys, required API
   scopes, and offline export format.

## Writing signatures

Signatures are YAML. Add a pack directory with `--signatures` or the
`signatures:` config key. After changes:

```bash
python -m shadowscan.signatures.validate
make evaluate
```

See [docs/signatures.md](docs/signatures.md) for the schema and authoring guide.

## Review and merge policy

ShadowScan currently has a single maintainer. The maintainer reviews changes,
checks validation and is accountable for merges. CI and CodeQL must pass on the
current PR revision, conflicts must be resolved, and substantive review feedback
must be addressed. Prefer independent human review for routine changes; the
current single-maintainer process does not guarantee it. AI-assisted review is
advisory and is never an independent human approval.

Before merging, the maintainer checks:

- The PR targets `main`, conflicts are resolved, and current CI and CodeQL
  checks pass. This includes signature validation, lint, typing, dependency
  audit, coverage, detection evaluation, and package and smoke checks.
- The change respects the trust model, documents compatibility changes, and
  includes appropriate validation. An AI-assisted change must meet the same
  requirements as any other contribution.
- The review record describes what was checked and any remaining limitation.
  If an independent approval exists, it must cover the final commit; a later
  push requires renewed review before that approval can be relied on.

The historical review status is documented in
[merge gate and review status](docs/production.md#merge-gate-and-review-status).
Do not read a merged pull request, green check, AI review or version number as
evidence that a second person examined the change. Repository settings are
separate from this policy: inspect the
[live rules](https://github.com/aisecnomad/Project-Nexus/rules) and PR checks
before merging. Do not disable checks or review rules to make a merge possible,
and do not describe an unenforced requirement as an active platform gate.

**Independent human review is required before any tagged release.** The
reviewer must not have authored or produced the change. A review is recorded as
a GitHub pull request approval from an account other than the author's. Inspect
the review author, state and `commit_id` with
`gh api repos/aisecnomad/Project-Nexus/pulls/<number>/reviews`, and compare that
commit to the current PR head. When the project has a second reviewer, enable
the ruleset's required approval for routine changes instead of relying on
convention. Never manufacture an approval or treat an AI reviewer as that person.

For deployment, pin the full reviewed commit SHA and retain its review and
acceptance evidence. No tag exists yet; `0.1.1` names an unreleased candidate.
Independent review of a release does not itself establish live tenant acceptance.
See [governance](GOVERNANCE.md) for release and decision responsibilities.

## Security reports

Follow the [security reporting instructions](SECURITY.md#reporting) to submit a
private report. Do not include credentials, private exports, or exploit details
in public issues.

## Developer Certificate of Origin

By contributing to this project, you certify that you have the right to submit
the work under the Apache-2.0 license and that you agree to the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).

You can sign off your commits with `git commit -s`, which adds a
`Signed-off-by` line. This is not currently enforced but may be in the future.

## License

By contributing, you agree that your contributions will be licensed under the
Apache-2.0 license.
