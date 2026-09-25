# ADR-001: Surface-connector architecture

**Status:** Accepted
**Date:** 2026-09-23

## Context

AI agents can appear on many enterprise surfaces: source code, identity
providers, LLM gateways, low-code platforms, SaaS apps, and cloud accounts.
Each surface has its own discovery API, data model, and vocabulary. A monolithic
scanner would couple detection logic to specific API clients and make it
difficult to add new platforms without modifying the core engine.

## Decision

Organize the scanner around **surfaces** (code, identity, gateway, low-code,
SaaS, cloud) and **connectors** (one per platform within a surface). Each
connector implements two methods:

- `collect(settings, http_client) → records` — live API collection
- `analyze(records, signatures) → findings` — offline record analysis

Connectors register through the `shadowscan.connectors` entry-point group,
allowing third-party connectors without modifying the core package.

The core engine orchestrates connectors concurrently, aggregates findings into
a unified model, and applies risk scoring, inventory reconciliation, and
cross-surface correlation.

## Consequences

**Positive:**

- New platforms are added by writing a single connector module with test
  fixtures, without touching the engine or other connectors.
- Third-party connectors can be published as separate packages and registered
  through entry points.
- The connector contract is small and testable: two methods with clear
  input/output types.
- Per-connector coverage gates enforce quality across the growing surface area.

**Negative:**

- Shared behavior (pagination, error handling, credential redaction) must be
  extracted into base classes and utilities rather than being implicit.
- The connector allowlist is not a sandbox — an approved plugin runs with
  scanner privileges.
- Cross-connector correlation (linking a Terraform module to the cloud agent
  it provisions) requires explicit coordination through the engine.

**Risks:**

- With 32+ connectors maintained by a small team, coverage quality could
  diverge. Mitigated by the 75% per-connector coverage floor enforced in CI.
- Entry-point registration means third-party connectors are trusted code.
  Mitigated by requiring explicit `options.plugins` allowlisting.
