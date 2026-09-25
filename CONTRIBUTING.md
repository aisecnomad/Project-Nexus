# Contributing to ShadowScan

Thank you for your interest in making ShadowScan better. This guide covers
everything from setting up your environment to getting a PR merged.

## Code of conduct

Be respectful, constructive, and professional. Security scanning tools protect
organizations; contributors should hold themselves to the same standard.

## Getting started

```bash
git clone https://github.com/aisecnomad/Project-Nexus.git
cd Project-Nexus
python -m pip install -e ".[all]"    # dev + cloud + docs extras
make install-hooks                   # pre-commit hooks (recommended)
```

Cloud extras (`pip install -e ".[cloud]"`) are optional. Offline fixtures cover
the cloud connectors; do not commit live tenant exports.

Run `make help` for a quick reference of all development commands.

## Trust model

The operator workstation or CI runner, the scan configuration, and installed
Python packages are trusted. Remote API responses, scanned repositories, and
offline exports are untrusted. Third-party connectors are not a sandbox: an
approved plugin runs with scanner privileges.

## Quality gates

Every PR must pass these checks (run locally with `make check`):

| Gate | Command | Requirement |
|------|---------|-------------|
| Lint | `ruff check shadowscan tests tools` | No errors |
| Types | `mypy shadowscan tools/evaluation tools/canaries tools/acceptance tools/release` | No errors |
| Tests | `pytest --cov --cov-fail-under=80` | ≥ 80% aggregate |
| Connectors | `python -m tools.coverage_gate` | ≥ 75% per connector |
| Signatures | `python -m shadowscan.signatures.validate` | All valid |
| Audit | `pip-audit` | No known vulnerabilities |
| Evaluation | `python -m tools.evaluation.evaluate` | No regressions |

The same gates as individual commands:

```bash
python -m pip install -e ".[cloud,dev]"
python -m shadowscan.signatures.validate
ruff check shadowscan tests tools
mypy shadowscan tools/evaluation tools/canaries tools/acceptance tools/release
pip-audit --progress-spinner off
python -m pytest -q --cov=shadowscan --cov-fail-under=80
```

The cloud SDKs (`boto3`, `google-auth`, `azure-identity`, `oci`) are optional
extras for users, but the test suite is gated with them installed, so use
`".[cloud,dev]"` as shown above. CI installs the hash-locked
`requirements.lock`, which contains every cloud SDK. Offline fixtures cover the
cloud connectors; do not commit live tenant exports.

Do not commit private adjudicated evaluation corpora.

## Pull requests

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

ShadowScan currently has a single maintainer. As of 2026-09-24 every pull
request in the repository's history was merged by that maintainer's own
account; apart from Dependabot updates, every commit was authored by that
account or, for the initial import, attributed to the AI assistant it used. No
change on `main` carries an approving review from a second person. Do not read
a merged pull request, a green check or a version number as evidence that
someone other than the author examined the change.

What every change receives before it is merged:

- the CI workflow: signature validation, lint, typing, dependency advisory
  audit, tests with an overall and a per-connector coverage floor, labeled
  detection-case evaluation, wheel build and installed-wheel checks, an offline
  SARIF scan and, on Python 3.12, the container smoke test;
- CodeQL analysis;
- weekly Dependabot update pull requests for Python and GitHub Actions
  dependencies (`.github/dependabot.yml`);
- AI-assisted code review where it is configured on the repository. This is a
  repository setting, not part of the checked-in workflows, and its output is
  advisory. Much of the hardening work was itself AI-assisted; the maintainer
  reads the result and is accountable for what is merged.

These checks establish implementation behaviour. They are not an independent
review, and none of them can be confirmed from a checkout: rulesets, branch
protection and pull request approvals are repository settings that can change
at any time. [docs/production.md](docs/production.md#merge-gate-and-review-status)
gives operators the commands to inspect the live state.

Independent human review is required before any tagged release. No tag exists
yet; the `0.1.1` version string names an unreleased candidate. For an operator
who needs an externally reviewed revision, that review is the bar: pin the full
commit SHA that was reviewed, keep the review record with the deployment
evidence, and do not infer review from a version number or a merged pull
request.

A second reviewer is recorded as a pull request approval from a GitHub account
other than the author's, submitted on the final commit of the branch
(`gh pr review <number> --repo aisecnomad/Project-Nexus --approve`). The
approval appears in the pull request's review list and in
`gh api repos/aisecnomad/Project-Nexus/pulls/<number>/reviews`; an approval
followed by a further push does not cover the pushed commits. The author of a
change cannot supply this approval, and a review is only independent when the
reviewer did not produce the change. When a second maintainer exists, enable
the ruleset's required approving review instead of relying on convention. Do
not weaken rulesets to self-merge, and do not describe a review gate that the
repository settings do not enforce.

## Security reports

Use a private GitHub security advisory. Do not include credentials, private
exports, or exploit details in public issues.

## Developer Certificate of Origin

By contributing to this project, you certify that you have the right to submit
the work under the Apache-2.0 license and that you agree to the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).

You can sign off your commits with `git commit -s`, which adds a
`Signed-off-by` line. This is not currently enforced but may be in the future.

## License

By contributing, you agree that your contributions will be licensed under the
Apache-2.0 license.
