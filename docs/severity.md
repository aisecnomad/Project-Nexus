# Severity is not an enforcement signal

ShadowScan risk scores are author-chosen heuristics. They are not CVSS, not a calibrated probability, and not a vulnerability severity.

## What the number is

`RiskLevel.from_score` maps an additive factor sum (secret-shaped evidence, unmatched inventory, tool use, missing owner, and similar weights) scaled by confidence into critical / high / medium / low / info. Confidence is a noisy-OR of signature weights. Neither input was fitted to analyst dispositions or incident outcomes.

A score of 90 and a label of `CRITICAL` mean "the heuristic factors stacked." They do not mean a critical vulnerability, an actively executing agent, or an unauthorized deployment.

## What SARIF must not claim

GitHub code scanning treats a rule property named `security-severity` as a CVSS-like score (`>9.0` critical, `7.0–8.9` high). Emitting `9.5` for a heuristic agent-discovery hit makes a code-scanning UI render an unused import or an unmatched inventory card as a critical security alert.

SARIF output therefore:

- does not set `security-severity`
- records `shadowscan/heuristic-risk` and `shadowscan/score-basis=heuristic-not-cvss`
- uses SARIF level `warning` or `note`, not `error`, for discovery hits

Upload a SARIF report only as an analyst triage queue. Do not fail a release on `security-severity`.

## What `--fail-on` must not do

`--fail-on` compares the heuristic label. It is a local exit-code convenience for an analyst who already chose a threshold. It is not a production gate. An incomplete scan (exit 3) is a coverage failure, not a clean pass and not a confirmed finding.

## What would be required before enforcement

- A frozen human-labeled holdout, with the scanner forbidden from training on it, and a published confusion matrix.
- Severity either dropped or calibrated against analyst dispositions.
- Live tenant canary receipts for every connector used as a control.
- A second maintainer who can reject the author's change.

None of that is met by version `0.1.1`. The package is an unreleased alpha. Pin a reviewed commit SHA. Treat every report as confidential. Confirm each hit before registering, blocking, or telling anyone the estate is covered.
