# Changelog

## 0.1.1 — 2026-09-24

Production-hardening release. Packaging from the 0.1.0 review (LICENSE, NOTICE, Dockerfile)
is on `main`; this release implements the remaining runtime controls those docs already described.

### Security
- Finding identity v2 does not include `kind`; promotion from framework-usage to agent keeps merge/diff/incremental identity.
- Shared HTTP client bounds JSON response bodies by default (16 MiB streamed).
- Bare `${VAR}` expansions fail closed when the variable is missing or empty. `${VAR:-default}` remains an explicit fallback.
- Incremental cache takes an exclusive lock and prunes growth so concurrent scanners cannot clobber state.
- Bare `*` / `**` inventory approvals are rejected. Scoped wildcards remain valid explicit approvals.
- Full Apache-2.0 LICENSE text and NOTICE.

### Reliability
- Engine enforces a per-connector deadline (default 300s); overrun is incomplete coverage (exit 3), not a hang.
- Cloud SDK clients set explicit connect/read timeouts where the vendor SDK allows it.
- Configuration rejects unknown fields, duplicate YAML keys, empty required env values, and invalid `fail_on` / `parallel`.

### Operations
- Disposable non-root worker image (`Dockerfile`).
- CI split into lint, audit, test, and package jobs with a concurrency group.
- Example GitHub Action pins Actions SHAs, forbids `continue-on-error` on incomplete scans, and requires a reviewed scanner SHA.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Rebuild comparison baselines after finding-identity v2. Do not compare 0.1.0 incremental state against 0.1.1.
- Install from a reviewed tag/SHA. Do not follow `main`.
- Inventory cards that used a bare `*` resource pattern will fail validation and must be scoped.
