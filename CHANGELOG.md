# Changelog

## 0.1.1 — 2026-09-24

Production-hardening release addressing the 0.1.0 review.

### Security
- Finding identity no longer includes `kind`; promotion from framework-usage to agent preserves merge/diff/incremental identity.
- Shared HTTP client bounds JSON response bodies by default.
- Injected `requests.Session` objects still receive the destination-policy adapter.
- Missing `${ENV}` expansions for required secrets fail closed instead of becoming empty strings.
- Incremental cache takes an exclusive lock so concurrent scanners cannot clobber state.
- Full Apache-2.0 LICENSE text and NOTICE.

### Reliability
- Engine enforces a per-connector deadline; timeout is incomplete coverage (exit 3), not a hang.
- Cloud SDK clients set explicit connect/read timeouts where the vendor SDK allows it.
- CLI documents exit 3 (incomplete), exit 2 (`--fail-on` on a complete scan), and Click's separate usage-error path.

### Operations
- Disposable non-root worker image (`Dockerfile`).
- CI split into lint, audit, test, and package jobs with a concurrency group.
- Example GitHub Action and README pin a reviewed SHA and forbid `continue-on-error` on incomplete scans.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Finding IDs for promoted resources change. Re-run scans rather than comparing 0.1.0 incremental state against 0.1.1.
- Install from a reviewed tag/SHA. Do not follow `main`.
