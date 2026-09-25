# Contributing

Thank you for your interest in contributing to ShadowScan.

## Before you start

1. Read the [security policy](security.md) — ShadowScan handles audit
   credentials and security findings.
2. Check [existing issues](https://github.com/aisecnomad/Project-Nexus/issues)
   for related work.
3. For significant changes, open an issue first to discuss the approach.

## Development setup

```bash
git clone https://github.com/aisecnomad/Project-Nexus.git
cd Project-Nexus
python -m pip install -e ".[all]"   # dev + cloud extras
make install-hooks                  # pre-commit hooks
```

For a quick reference of all development commands:

```bash
make help
```

## Running quality gates

```bash
make check   # local lint, typing, audit, coverage and evaluation subset
```

CI also validates the review corpus, wheel and container, plus additional
typing and release checks. Use the hosted CI status for the full gate.

Or individually:

```bash
make lint        # ruff
make typecheck   # mypy
make test        # pytest with coverage
make signatures  # validate signature schemas
make audit       # pip-audit
make evaluate    # detection corpus evaluation
```

## Trust model

The operator workstation or CI runner, the scan configuration, and installed
Python packages are trusted. Remote API responses, scanned repositories, and
offline exports are untrusted. Third-party connectors are not a sandbox: an
approved plugin runs with scanner privileges.

## Pull request guidelines

- Target `main`. Do not push reviewed security changes directly.
- Keep findings fail-closed: a limit, malformed export, or denied API must
  mark the scan incomplete (exit 3) rather than look empty.
- Do not log raw credentials, JWTs, or unsanitized connector configuration.
- Pin GitHub Actions by full commit SHA.
- Update `CHANGELOG.md` under Unreleased and `docs/production.md` when a
  change affects rollout, finding identity, or credential policy.
- Include regression tests for any bug fix.
- Connector changes require per-connector coverage ≥ 75%.

## Review gate

The author of a change cannot supply the required independent approving
review. Do not weaken repository rulesets to self-merge.

## Writing a connector

Connectors implement two methods:

- `collect()` — live API collection
- `analyze()` — offline record analysis (records → findings)

Register through the `shadowscan.connectors` entry-point group. See
[architecture](architecture.md) for the full connector contract.

Each connector must:

- Handle API failures gracefully and mark coverage incomplete
- Support offline mode with JSON/CSV/log exports
- Include offline test fixtures (no live credentials in tests)
- Achieve ≥ 75% statement coverage
- Be documented in `docs/connectors.md`

## Writing signatures

Signatures are YAML. Add a pack directory with `--signatures` or the
`signatures:` config key. See [signatures](signatures.md) for the schema
and authoring guide.

After adding or modifying signatures:

```bash
python -m shadowscan.signatures.validate
make evaluate
```

## Security reports

Use a [private GitHub security advisory](https://github.com/aisecnomad/Project-Nexus/security/advisories/new).
Do not include credentials, private exports, or exploit details in public issues.

## License

By contributing, you agree that your contributions will be licensed under the
Apache-2.0 license.
