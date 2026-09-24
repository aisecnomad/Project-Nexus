# Contributing to ShadowScan

## Trust model

The operator workstation or CI runner, the scan configuration, and installed
Python packages are trusted. Remote API responses, scanned repositories, and
offline exports are untrusted. Third-party connectors are not a sandbox: an
approved plugin runs with scanner privileges.

## Development

```bash
python -m pip install -e ".[cloud,dev]"
python -m shadowscan.signatures.validate
ruff check shadowscan tests tools
mypy shadowscan tools/evaluation
pip-audit --progress-spinner off
python -m pytest -q --cov=shadowscan --cov-fail-under=80
```

The cloud SDKs (`boto3`, `google-auth`, `azure-identity`, `oci`) are optional
extras for users, but the test suite requires them:
`tests/unit/test_oci_live_contracts.py` imports `oci` at module level, so
without the `cloud` extra pytest reports a collection error and stops before
running any test. The other tests that drive a real SDK client call
`pytest.importorskip` and would only skip, but that does not make a core-only
install (`".[dev]"`) able to run the suite; install `".[cloud,dev]"` as shown
above. CI installs the hash-locked `requirements.lock`, which contains every
cloud SDK. Offline fixtures cover the cloud connectors; do not commit live
tenant exports.

## Pull requests

- Target `main`. Do not push reviewed security changes directly.
- Keep findings fail-closed: a limit, malformed export, or denied API must mark
  the scan incomplete (exit 3) rather than look empty.
- Do not log raw credentials, JWTs, or unsanitized connector configuration.
- Pin GitHub Actions by full commit SHA. Do not leave `persist-credentials`
  enabled on checkouts that do not need to push.
- Update `CHANGELOG.md` under Unreleased and `docs/production.md` when a change
  affects rollout, finding identity, or credential policy.

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
