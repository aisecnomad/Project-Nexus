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
| Lint | `ruff check shadowscan tests` | No errors |
| Types | `mypy shadowscan` | No errors |
| Tests | `pytest --cov --cov-fail-under=80` | ≥ 80% aggregate |
| Connectors | `python -m tools.coverage_gate` | ≥ 75% per connector |
| Signatures | `python -m shadowscan.signatures.validate` | All valid |
| Audit | `pip-audit` | No known vulnerabilities |
| Evaluation | `python -m tools.evaluation.evaluate` | No regressions |

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

## Review gate

The author of a change cannot supply the required independent approving review.
Do not weaken repository rulesets to self-merge.

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
