# Changelog

## 0.1.1 — 2026-09-24

Production-hardening release addressing the 0.1.0 review and the follow-up
production-readiness review of `main`.

### Security
- Finding identity no longer includes `kind`; promotion from framework-usage to agent preserves merge/diff/incremental identity.
- Shared HTTP client bounds JSON response bodies by default.
- Injected `requests.Session` objects still receive the destination-policy adapter.
- Missing `${ENV}` expansions for required secrets fail closed instead of becoming empty strings.
- Incremental cache takes an exclusive lock so concurrent scanners cannot clobber state. Cache files are mode 0600.
- HTML reports escape attribute and text context (including `'`) and ship a restrictive CSP. Markdown reports flatten untrusted titles, resources and evidence so they cannot inject headings, HTML or broken code spans.
- Plugin metadata errors are logged instead of swallowed. Built-in name collisions are warned.
- Full Apache-2.0 LICENSE text and NOTICE.

### Reliability
- Engine enforces a per-connector deadline (default 300s, `--connector-timeout` / `options.connector_timeout`); timeout is incomplete coverage (exit 3), not a hang.
- Git clone of untrusted remotes is capped at 180s per repository.
- Cloud SDK clients set explicit connect/read timeouts where the vendor SDK allows it.
- CLI documents exit 3 (incomplete), exit 2 (`--fail-on` on a complete scan), and Click's separate usage-error path.

### Operations
- Disposable non-root worker image (`Dockerfile`).
- CI split into lint, audit, test, and package jobs with a concurrency group.
- Incremental scanner digest uses version + file metadata instead of hashing every installed source file.
- Example GitHub Action and README pin a reviewed SHA and forbid `continue-on-error` on incomplete scans.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Finding IDs for promoted resources change. Re-run scans rather than comparing 0.1.0 incremental state against 0.1.1.
- Configurations that relied on unset secret environment variables expanding to empty strings now fail at load.
- Install from a reviewed tag/SHA. Do not follow `main`.
