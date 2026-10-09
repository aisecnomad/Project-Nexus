# Post-change holdout: findings

This is the pre-registered post-change measurement of [PROTOCOL.md §13](../PROTOCOL.md#13-post-change-holdout-pre-registered-before-its-draw).
The standard tables are in [REPORT.md](REPORT.md); this page states the
pre-registered targets, compares with the first run, and explains what the
numbers mean for ShadowScan.

**Read this first.**
- Labels come from two independent AI annotators and AI adjudicators, not
  from human reviewers.
- The harness lives in the ShadowScan repository, and the person who changed
  ShadowScan also ran the benchmark (see the protocol's conflict-of-interest
  section).
- The code reviews of the changes were AI reviews, not independent human review.
- Nothing here is a measured production precision.

## Setup

- 140 repositories drawn with seed `20261009`, disjoint from the first run's
  corpus, calibration set and purposive sets. Labels were frozen and pushed
  before any tool ran.
- Every tool of the first run ran at the same pinned version, with the same
  adapters, offline sandbox and 900 s timeout.
- ShadowScan ran at code-freeze commit `c30aaac` (see §13.5, deviation 5).
- Post-run blind adjudication reviewed all 111 repositories where any tool
  disagreed with a label. It changed no label and no assistant-artifact flag,
  so frozen and adjudicated results are identical.
- The decisions are in `../labels-holdout/adjudication-postrun.jsonl`.

## Pre-registered targets (ShadowScan, primary strict rule)

Under the strict rule, an incomplete or failed scan counts as a wrong answer.
The targets were stated before the draw and are reported as they came out.

| Target | Required | Holdout | Met |
|---|---|---|---|
| Incomplete scans | at most 5% | 26/140 = 18.6% | **no** |
| T1 (generative-AI use) MCC | at least 0.80 | 0.533 (95% CI 0.38–0.67) | **no** |
| T2 (AI agents) MCC | at least 0.75 | 0.352 (0.19–0.51) | **no** |
| T1 specificity | at least 0.97 | 0.857 (0.71–0.94) | **no** |

No target was met.

## Compared with the first run

The first run used the original corpus and the pre-change code. The holdout
is a different sample, so the difference is described, not tested
(§13.4).

| ShadowScan, strict rule | First run (183 repos, pre-change) | Holdout (140 repos, post-change) |
|---|---|---|
| Incomplete scans | 64/183 = 35.0% | 26/140 = 18.6% |
| T1 MCC | 0.172 | 0.533 |
| T2 MCC | 0.087 | 0.352 |
| T1 MCC, completed scans only | 0.809 | 0.848 |
| T2 MCC, completed scans only | 0.692 | 0.628 |

Incomplete scans halved, and the strict scores tripled or more. Most of that
gain comes from coverage: on the scans it completes, T1 accuracy barely
moved. Among completed scans, ShadowScan has the best T1 MCC of any tool
(0.848). Under the strict rule it ranks seventh of nine on T1 and last on
T2. Repeated scans were deterministic: 14 repeats, no verdict changed.

## What still makes scans incomplete (holdout)

Some repositories have more than one cause.

| Cause | Repositories | Notes |
|---|---|---|
| Source lexer gives up | 8 | mostly Ruby (`.rb` specs and libraries); also F#, Kotlin and bundled `yarn-*.cjs` releases |
| Missing submodules | 4 | real gaps: the code is not in the checkout |
| Structured parsing limits | 6 | a large OpenAPI YAML, ambiguous YAML, test snapshots read as MCP configuration |
| Binary or undecodable content | 3 | text with stray bytes in Markdown, YAML and PHP |
| Agent-definition limit (50) | 2 | large `.claude/agents` collections |
| Import-bound analysis truncated | 2 | calls deep in very long TypeScript files |
| Timeouts and the connector deadline | 3 | |
| Oversize files | 2 | |
| Other | 3 | invalid NuGet project XML, the MCP tool-name limit |

The in-sample work never stressed Ruby lexing or the fixed limits (50 agent
definitions, the 8,192-character window for import-bound calls). Those are
the clearest next fixes. Fixing them now would use the holdout to tune the
scanner, so a further claim needs a new holdout.

## The agentic rule

§13.3 made `metadata.agentic` ShadowScan's primary agent signal. The
original kind list (`agent`, `agent-config`, `bot-app`, `mcp-server`,
`workflow`) is kept as a secondary analysis.

On the holdout, the kind list scores better on T2:

| ShadowScan T2 MCC | `metadata.agentic` (primary) | kind list (secondary) |
|---|---|---|
| Strict rule | 0.352 | 0.447 |
| Completed scans only | 0.628 | 0.739 |

The new classification excludes cases that the labels count as agents. The
benchmark measured this rather than confirming it; how `metadata.agentic`
treats MCP clients, coding-agent plugins and agent definitions should be
revisited against the rubric.

## In-sample check (not a generalisation estimate)

ShadowScan also ran at the freeze commit on the original 183-repository
corpus. The fixes were derived from these repositories, so this measures
fit. Results are in [`../results-insample-postchange/`](../results-insample-postchange/).

- 16/183 = 8.7% of scans incomplete.
- T1 MCC 0.727 and T2 MCC 0.492 under the strict rule.
- On completed scans only, T1 MCC 0.907 and T2 MCC 0.660.

The gap between the in-sample and holdout results (8.7% against 18.6%
incomplete) is the expected cost of fitting fixes to a sample. It is why the
holdout, not the in-sample run, is the result to quote.
