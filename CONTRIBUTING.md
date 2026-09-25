# Contributing to ShadowScan

## Trust model

The operator workstation or CI runner, the scan configuration, and installed
Python packages are trusted. Remote API responses, scanned repositories, and
offline exports are untrusted. Third-party connectors are not a sandbox: an
approved plugin runs with scanner privileges.

## Development

```bash
python -m pip install -e ".[dev]"
python -m shadowscan.signatures.validate
ruff check shadowscan tests
mypy shadowscan
python -m pytest -q --cov=shadowscan --cov-fail-under=80
```

Cloud extras (`pip install -e ".[cloud]"`) are optional: the OCI contract tests
skip without the SDK, and offline fixtures cover the cloud connectors. Do not
commit live tenant exports. Tests of opt-in Git history enrichment skip on Git
older than 2.45; everything else runs on a stock Ubuntu 24.04 or macOS host.

## Pull requests

- Target `main`. Do not push reviewed security changes directly.
- Keep findings fail-closed: a limit, malformed export, or denied API must mark
  the scan incomplete (exit 3) rather than look empty.
- Do not log raw credentials, JWTs, or unsanitized connector configuration.
- Pin GitHub Actions by full commit SHA. Do not leave `persist-credentials`
  enabled on checkouts that do not need to push.
- Update `CHANGELOG.md` under Unreleased and `docs/production.md` when a change
  affects rollout, finding identity, or credential policy.

## Review gate

The author of a change cannot supply the required independent approving review.
Do not weaken repository rulesets to self-merge.

## Security reports

Use a private GitHub security advisory. Do not include credentials, private
exports, or exploit details in public issues.
