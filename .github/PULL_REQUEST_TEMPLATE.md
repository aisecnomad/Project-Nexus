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

- [ ] `ruff check shadowscan tests` passes
- [ ] `mypy shadowscan` passes
- [ ] `pytest -q --cov=shadowscan --cov-fail-under=80` passes
- [ ] No raw credentials, JWTs, or unsanitized configuration in logs or reports
- [ ] `CHANGELOG.md` updated under Unreleased (if user-facing)

### Required for connector changes

- [ ] Per-connector coverage ≥ 75% (`python -m tools.coverage_gate`)
- [ ] Offline fixtures added (no live credentials in tests)
- [ ] Connector handles API failures and marks coverage incomplete (exit 3)
- [ ] New connector registered in `shadowscan/connectors/__init__.py`
- [ ] `docs/connectors.md` updated with configuration keys and least-privilege scopes
- [ ] `shadowscan connectors` listing verified

### Required for signature changes

- [ ] `python -m shadowscan.signatures.validate` passes
- [ ] Evaluation corpus updated and `python -m tools.evaluation.evaluate` passes
- [ ] No false positives introduced on existing negative corpus entries

### Required for security-sensitive changes

- [ ] `docs/production.md` updated if rollout, finding identity, or credential policy changed
- [ ] `SECURITY.md` updated if trust boundary or controls changed
- [ ] Redaction tested with known credential formats
- [ ] No credential-bearing values in application log events (only fixed summaries)

## Verification

<!-- How did you verify this change? Paste CI link, test output, or scan results. -->

## Breaking changes

<!-- If this is a breaking change, describe the migration path. -->
