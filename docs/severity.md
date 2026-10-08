# Severity is not an enforcement signal

ShadowScan risk scores are author-chosen heuristics. They are not CVSS, not a
calibrated probability, and not a vulnerability severity.

## What the number is

`RiskLevel.from_score` maps an additive factor sum (secret-shaped evidence,
unmatched inventory, tool use, missing owner, and similar weights) scaled by
confidence into critical / high / medium / low / info. Confidence is a noisy-OR
of grouped evidence weights. Neither input was fitted to analyst dispositions
or incident outcomes; [risk scoring](concepts/risk.md) lists the factors and
the score ranges.

A score of 90 and a label of `CRITICAL` mean "the heuristic factors stacked."
They do not mean a critical vulnerability, an actively executing agent, or an
unauthorized deployment.

## What SARIF must not claim

GitHub code scanning reads a rule property named `security-severity` on a rule
tagged `security` as a CVSS-like score (over 9.0 is critical, 7.0 to 8.9 high).
A value of `9.5` on a heuristic agent-discovery hit makes a code-scanning UI
show an unused import or an unmatched inventory card as a critical security
alert. Earlier candidate builds emitted exactly that.

SARIF output therefore:

- does not set `security-severity` and does not tag rules `security`
- records the heuristic level as the rule property `shadowscan/heuristic-risk`,
  with `shadowscan/score-basis` set to `heuristic-not-cvss`, and as the result
  property `risk_level`
- uses SARIF level `warning` (critical, high and medium) or `note` (low and
  info), never `error`, for discovery hits; `error` is kept for connector
  failures in the run's tool execution notifications
- links each rule's `helpUri` to this page

Upload a SARIF report only as an analyst triage queue. Do not fail a release on
a code-scanning severity derived from it.

## What `--fail-on` must not do

`--fail-on` compares the heuristic label. It is a local exit-code convenience
for an analyst who already chose a threshold. It is not a production gate. An
incomplete scan (exit 3) is a coverage failure, not a clean pass and not a
confirmed finding.

## What would be required before enforcement

- A [frozen human-labeled holdout](evaluation.md#gate-a-frozen-holdout), with
  the scanner forbidden from training on it, and a published confusion matrix.
- Severity either dropped or calibrated against analyst dispositions.
- [Live tenant canary receipts](canaries.md) for every connector used as a
  control.
- A second maintainer who can reject the author's change.

None of that is established by publishing `0.1.2`. The package remains
alpha. Pin a reviewed commit SHA. Treat every report as confidential. Confirm
each hit before registering, blocking, or telling anyone the estate is covered.
