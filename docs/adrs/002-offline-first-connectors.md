# ADR-002: Offline-first connector design

**Status:** Accepted
**Date:** 2026-09-23

## Context

Security teams often cannot grant live API credentials to a new scanning tool
before evaluating it. CI jobs may not have network access to all platforms.
Analysts may receive SIEM exports or CASB inventories rather than direct API
access. A scanner that only works with live credentials cannot serve these
workflows.

## Decision

Every connector supports both **live** and **offline** modes:

- **Live mode**: the connector calls platform APIs directly using configured
  credentials. It writes sanitized records that can be replayed later.
- **Offline mode**: the connector reads a JSON, CSV, or log export and applies
  the same analysis logic. The `--input` flag or `input:` config key selects
  this mode.

The same `analyze()` method processes records regardless of their origin. The
`collect()` method is only called in live mode.

Record exports from `--dump-records` are sanitized: JWTs are never persisted,
known credential formats are redacted, and webhook URLs are truncated.

## Consequences

**Positive:**

- Teams can evaluate ShadowScan without granting credentials.
- CI jobs can scan offline exports from a SIEM or previous live run.
- The same detection logic is tested against offline fixtures in the test
  suite, without requiring live API credentials in CI.
- Record dumps enable reproducible analysis and incident investigation.

**Negative:**

- Offline exports may be stale or incomplete, leading to false negatives.
  Mitigated by marking offline scans with their provenance.
- Sanitized exports still contain security-sensitive inventory data. Reports
  and exports must be treated as sensitive artifacts.
