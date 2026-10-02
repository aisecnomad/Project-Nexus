# Release notes

What changed for people who install, configure or operate ShadowScan, one
section per release. [CHANGELOG.md](https://github.com/aisecnomad/Project-Nexus/blob/main/CHANGELOG.md)
is the detailed engineering log, recorded per change, and the
[deployment and migration guide](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md)
has the full upgrade steps.

## 0.1.1 — unreleased candidate

**Not released.** There is no tag, package or signed artifact, and no change
has had independent human review. Install a reviewed commit SHA as the
[README](https://github.com/aisecnomad/Project-Nexus/blob/main/README.md#install)
describes.

### Before you upgrade

- Install the `project-nexus-shadowscan` distribution into a fresh virtual
  environment. The command and Python imports stay `shadowscan`; the unrelated
  `shadowscan` package on PyPI is not this project.
- Rebuild comparison baselines. Finding IDs follow the v2 identity schema
  (sanitized resource fields, independent of `kind`), so older reports cannot
  resolve findings.
- Fail CI on any non-zero exit. Exit 1 means no scan result (invalid usage,
  configuration or setup), 2 a complete scan that reached `--fail-on`, and 3
  an incomplete scan.
- Fix `max_pages` values that are now rejected: 0, negative, fractional,
  boolean or non-numeric.
- Regenerate inventory cards made by `inventory stubs`, or add
  `discovery.discriminators`, so that each approves only its own finding.
- Regenerate earlier reports of Semantic Kernel, go-openai, openai-java or
  Google AI JavaScript code, and rotate any API key they show.

### What changes in scan results

- Gaps are reported, not hidden: limits, malformed or ambiguous exports,
  denied APIs, timeouts, oversize files and links leaving the scan root make a
  scan incomplete (exit 3).
- Evidence found only in tests or fixtures no longer establishes an agent
  unless `--include-tests` is set.
- Confidence counts correlated evidence once, so repeated matches of one
  signal no longer inflate it; some non-code findings report lower
  confidence.
- 215 signatures and 1,006 signals cover current agent SDKs, including Vercel
  AI SDK tool loops (AI SDK 7's `isStepCount`). Custom-pack framework patterns
  apply in every language, and detection-rule files (ShadowScan signature
  packs, Semgrep, Sigma, gitleaks) are treated as data.
- AWS roles are tagged `agent-execution-role` only when an `Allow` statement
  in their trust policy names a Bedrock service.
- `diff` reports gateway findings as not comparable unless every compared
  scan uses the same `SHADOWSCAN_IDENTITY_KEY`.
- SARIF results are warnings (critical, high, medium) or notes (low, info)
  that carry the heuristic level as `risk_level`. Rules no longer set
  `security-severity` or the `security` tag, so GitHub code scanning no longer
  rates ShadowScan alerts as security severities; the
  [severity guide](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/severity.md)
  explains why.

### Security and safety

- Reports are written atomically with owner-only permissions. HTML reports
  carry a strict Content-Security-Policy, CSV cells are neutralized against
  formula injection, and Markdown is defanged.
- Credential redaction covers more forms, including keys passed positionally
  to well-known LLM SDK calls. Known gaps are listed in
  [SECURITY.md](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md);
  treat reports as confidential.
- Scanned repositories are read without following links, git runs with
  hardened configuration, and live collection enforces HTTPS, origin and
  private-address controls.
- Third-party connectors run only when named in `options.plugins`, and
  repository scans stay separate from live tenant collection unless
  `allow_credential_mixing` is set.

### Known limitations

- Confidence is a heuristic evidence score, not a calibrated probability. The
  bundled corpora are author- or AI-labeled regression suites, not field
  precision or recall estimates.
- Live connectors are validated against recorded fixtures and optional
  read-only canaries, not against every tenant configuration.
- Python 3.11–3.13 on Linux and macOS are supported; Linux x86_64 is the
  validated deployment target.
