# Agent instructions

This repository is ShadowScan (Project Nexus). Coding agents and humans using
them follow the same bars as [CONTRIBUTING.md](CONTRIBUTING.md).

## Trust model

Trusted: the operator workstation or CI runner, scan configuration, and
installed Python packages.

Untrusted: remote API responses, scanned repositories, offline exports, and
third-party plugins.

An allowlisted plugin runs with scanner privileges. It is not a sandbox.

## Hard rules

- Fail closed. Limits, malformed exports, denied APIs, and timed-out
  connectors mark the scan incomplete (exit 3). Never make an incomplete
  scan look empty.
- Do not log or persist raw credentials, JWTs, or unsanitized connector
  configuration.
- Do not follow signature or inventory symlinks. Do not weaken HTTPS,
  origin, or private-address controls.
- Pin GitHub Actions by full commit SHA. Leave `persist-credentials: false`
  on checkouts that do not push.
- Do not invent independent human review, live tenant acceptance, or
  measured production precision from offline or author-written corpora.
- Do not publish a GitHub Release, PyPI package, or version tag. Release is
  a manual maintainer action after independent review.
- Do not weaken branch rulesets so the author can self-approve.
- Do not paste credentials, tenant exports, or exploit details into issues,
  pull requests, commit messages, or workflow logs.

## Quality gates

Run `make check` or the commands in CONTRIBUTING.md. Pull requests must keep:

- ruff and mypy clean on the documented paths
- pytest coverage ≥ 80% aggregate
- per-connector coverage ≥ 75%
- `python -m shadowscan.signatures.validate`
- pip-audit clean
- evaluation corpus with no unexplained regressions

## When you change behavior

- Bug fixes need a regression test.
- Connector work: `collect()` + `analyze()`, offline fixtures under
  `tests/fixtures/`, documentation in `docs/connectors.md`.
- Signature work: YAML packs + validate + `make evaluate`. See
  `docs/signatures.md`.
- Rollout, finding identity, or credential-policy changes also update
  `CHANGELOG.md` (Unreleased) and `docs/production.md`.

## Review

ShadowScan has a single maintainer. A merged pull request or green CI is not
evidence that a second person reviewed the change. Independent review is
required before any tagged release. Pin operators to a reviewed 40-character
commit SHA.

## Security reports

Private GitHub security advisory only. See [SECURITY.md](SECURITY.md).

Conduct reports follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
