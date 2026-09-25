# ADR-003: Evidence-based confidence scoring

**Status:** Accepted
**Date:** 2026-09-23

## Context

Detecting AI agents from static signals (dependency declarations, import
statements, configuration files) produces many low-confidence matches. A
project that imports `openai` might be an agent, a utility library, or a
one-off experiment. Without distinguishing confidence levels, scan results
drown in noise and teams lose trust in the tool.

## Decision

Use a **noisy-OR** model for confidence and an **additive, explainable** model
for risk, kept separate:

- **Confidence** = P(agent | evidence). Computed as 1 − ∏(1 − wᵢ) where wᵢ
  is the weight of each independent evidence signal. Ranges from 0 to 1.
- **Risk** = sum of factor weights, scaled by confidence. Each factor
  (shadow status, credential exposure, capabilities, ownership) adds a
  documented weight to the score. The final risk score is
  `raw_risk × confidence`.

Both scores carry their contributing factors in the finding JSON, so every
score is auditable.

## Consequences

**Positive:**

- Low-confidence findings (a dependency import) are visually distinct from
  confirmed findings (a running Bedrock Agent).
- Risk scaling by confidence prevents low-confidence noise from triggering
  CI gates.
- Every score is explainable: the `risk.factors` and `evidence` arrays in
  the finding JSON show exactly what contributed.

**Negative:**

- Noisy-OR assumes evidence independence, which is not always true (an
  import and a configuration file for the same framework are correlated).
  Mitigated by grouping correlated evidence and using the strongest signal.
- Weight calibration is subjective. Mitigated by making weights overridable
  in custom signature packs and documenting the evaluation methodology.
