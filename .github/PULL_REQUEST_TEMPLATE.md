## Summary

<!-- What does this PR do? Link any related issues with "Closes #NNN". -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New connector or signature
- [ ] Enhancement (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation
- [ ] CI / tooling

## Checklist

### Required for all changes

- [ ] `make lint` and `make format-check` pass
- [ ] `make typecheck` passes
- [ ] `pytest -q --cov=shadowscan --cov-fail-under=80` passes
- [ ] `make audit` (`pip-audit`) reports no known vulnerabilities
- [ ] `python -m shadowscan.signatures.validate` passes
- [ ] `python -m shadowscan.mappings.validate` passes
- [ ] `make secrets` finds no hardcoded credentials
- [ ] `make policy` passes (when `.github/`, a top-level document or a docs page changed)
- [ ] Every commit carries a `Signed-off-by` trailer (`git commit -s`; see the DCO in `CONTRIBUTING.md`)
- [ ] No raw credentials, JWTs, or unsanitized configuration in logs or reports
- [ ] `CHANGELOG.md` updated under Unreleased (if user-facing)

### Required for connector changes

- [ ] Per-connector coverage ≥ 75% (`make coverage-gate` after the coverage test run)
- [ ] Offline fixtures added (no live credentials in tests)
- [ ] Connector handles API failures and marks coverage incomplete (exit 3)
- [ ] New connector registered in `shadowscan/connectors/__init__.py`
- [ ] `docs/connectors/reference.md` regenerated (`make connector-reference`) and least-privilege scopes documented in the connector guide
- [ ] `shadowscan connectors` listing verified

### Required for signature changes

- [ ] `python -m shadowscan.signatures.validate` passes
- [ ] Evaluation corpus updated and `make evaluate` passes (all bundled corpora)
- [ ] No false positives introduced on existing negative corpus entries

### Required for mapping changes

- [ ] `python -m shadowscan.mappings.validate` passes
- [ ] `docs/concepts/mappings-reference.md` regenerated (`make mapping-reference`)
- [ ] Each changed rule has a test in `tests/unit/test_mappings.py`

### Required for security-sensitive changes

- [ ] `docs/production.md` updated if rollout, finding identity, or credential policy changed
- [ ] `SECURITY.md` updated if trust boundary or controls changed
- [ ] Redaction tested with known credential formats
- [ ] No credential-bearing values in application log events (only fixed summaries)

## Verification

<!-- How did you verify this change? Paste CI link, test output, or scan results. -->

<!-- State the tested commit, targeted regressions, and any checks not run.
For detection changes include both positive and negative examples. Distinguish
synthetic regression evidence from an independent human-labeled holdout.
For live connector validation name the authorized scope and coverage gaps;
never include tenant identifiers, tokens, or private exports. -->

## Breaking changes

<!-- If this is a breaking change, describe the migration path. -->
