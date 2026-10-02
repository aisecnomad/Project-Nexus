# ADR-003: Evidence-based confidence scoring

**Status:** Accepted
**Date:** 2026-09-23
**Amended:** 2026-09-27 (see the amendment at the end)

## Context

Detecting AI agents from static signals (dependency declarations, import
statements, configuration files) produces many low-confidence matches. A
project that imports `openai` might be an agent, a utility library, or a
one-off experiment. Without distinguishing confidence levels, scan results
drown in noise and teams lose trust in the tool.

## Decision

Use a **noisy-OR** model for confidence and an **additive, explainable** model
for risk, kept separate:

- **Confidence** is a heuristic evidence score, computed as 1 − ∏(1 − wᵢ)
  after grouping correlated signals. It ranges from 0 to 1; it is not a
  calibrated P(agent | evidence) or proof of runtime execution.
- **Risk** = sum of factor weights, scaled by confidence. Each factor
  (shadow status, credential exposure, capabilities, ownership) adds a
  documented weight to the score. The final risk score is
  `raw_risk × confidence`.

Both scores carry their contributing factors in the finding JSON, so every
score is auditable.

## Consequences

**Positive:**

- Low-confidence findings (a dependency import) are visually distinct from
  strong findings (a running Bedrock Agent).
- Risk scaling reduces contributions from weak evidence. An operator still
  needs to validate false-positive behavior before choosing a CI threshold.
- Every score is explainable: the `risk.factors` and `evidence` arrays in
  the finding JSON show exactly what contributed.

**Negative:**

- Noisy-OR assumes evidence independence, which is not always true (an
  import and a configuration file for the same framework are correlated).
  Mitigated by grouping correlated evidence and using the strongest signal.
- Weight calibration is subjective. Mitigated by making weights overridable
  in custom signature packs and documenting the evaluation methodology.

## Amendment (2026-09-27)

The decision above stands as recorded. Two statements in it do not describe
the implementation. The code has scaled risk as below since the ADR's date
(2026-09-23), and has matched the rest of this amendment since shortly after:
per-group confidence since 2026-09-24, and the `bounds` factor and
`danger_score` since 2026-09-25. This amendment records the current model
instead of rewriting the decision.

- **Confidence is a heuristic evidence score, not P(agent | evidence).** It is
  the noisy-OR 1 − ∏(1 − wᵢ) of evidence weights clamped to [0, 1], rounded to
  three decimals. Evidence that shares a `confidence_group` attribute is
  correlated, so each group contributes only its strongest weight. The weights
  are authored in signature packs and connectors, not calibrated against
  observed outcomes, so the result is not a probability.
- **Risk is not `raw_risk × confidence`.** `shadowscan/risk.py` computes

  ```text
  raw   = sum of the factor weights
  scale = 0.6 + 0.4 × confidence        (confidence clamped to [0, 1])
  score = min(100, max(0, round(raw × scale)))
  ```

  The reduction appears as a `confidence-scaling` factor (never positive) and
  any 0/100 clamp as a `bounds` factor, so the listed factors always sum to
  the score. `danger_score` applies the same scale to the non-governance
  factors.

Rationale: the scale only ever lowers a score, and by at most 40%. Weak
evidence of a severe exposure therefore stays visible to `--fail-on` gates,
while strong evidence keeps its full score. For example, a shadow plaintext
credential with no owner (raw 90) found with confidence 0.3 scores 65 (high);
multiplying by confidence alone would give 27 (medium). Consequences listed
above that depend on scaling still hold in this weaker form: low confidence
reduces risk but cannot remove it.
