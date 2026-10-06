# Post-change regression run

ShadowScan only, rerun on the same 900-case corpus (seed `20261006`, SHA-256
`b757b2ac2293dba05e961a11ef9f49abb66e97aea1ab5edb9d9ccb28d2319e63`) after the
October 6 benchmark follow-ups. [`COMPARISON.md`](COMPARISON.md) has the
before/after tables.

> **This is a regression check, not new evidence of accuracy.** The corpus,
> the first run, the fixes and this rerun were all written in ShadowScan's
> repository. The fixes were made after reading the first run's misses, and
> the agent-loop heuristic and the corpus's network "agent" families share an
> author and a definition of an agent loop. Improvements here show that the
> changes do what they were written to do on these templates. They do not
> show field accuracy, and they do not change the other tools' published
> results, which were not rerun.

## Configurations

- **`shadowscan`** is the published configuration, unchanged:
  `code.filesystem` on repositories and home directories, `gateway.logs` on
  network access logs. Its agent tier counts finding kinds only, as in the
  first run.
- **`shadowscan-dedicated`** uses the connectors added by the follow-ups:
  `endpoint.inventory` (default options, so shell history is not read) on home
  directories, and `gateway.logs` plus `network.logs` on network cases. Its
  agent tier also counts callers and contacts whose
  `metadata.agent_indicators` is positive.
- The comparison re-scores the stored reports of the first run with that
  metadata rule (`before, agent rule re-scored`), so a change in the rule is
  not credited to a change in code. `raw/shadowscan.jsonl.gz` in the published
  results holds those reports.

## What changed

- **Goose and Cline (same configuration):** 0/6 → 6/6 and 5/8 → 8/8 home
  directories found. Endpoint recall 0.70 → 0.75, no false alarms.
- **Dedicated endpoint connector:** endpoint recall 0.96 (0.92–0.98) with no
  false alarms on 120 clean home directories. It finds the AI browser
  extensions (11/11, which no tool found in the first run), the Copilot
  extension, Ollama and LM Studio model stores. The 7 remaining misses are the
  shell-history family: reading shell history is opt-in
  (`shell_history: true`) and this run keeps the default.
- **Gateway agent classification:** under the metadata rule, the first run
  called 17 of 45 LLM-only network cases agentic, because every caller to
  `*.openai.com` or `*.anthropic.com` inherited the ChatGPT and Claude SaaS
  app signatures' agent flag, and a user named Jules matched Google's Jules.
  After the fixes, 0 of 45 are, and agent recall is 0.99 (0.96–1.00). The one
  missed agent case is an OpenClaw window. This agent tier is the most circular
  number here (see above).
- **Disagreement kept, not tuned away:** 4 of 45 LLM-only endpoint cases are
  called agentic because the GitHub Copilot Chat extension is classified as
  agentic (it has an agent mode with tools and a terminal). The corpus labels
  the Copilot extension LLM-only. Neither label is wrong; the boundary is a
  choice.
- **Unchanged:** repository results (the 7 Terraform Bedrock agents are still
  found but not marked agentic), network detection recall and specificity,
  and 0 errors in 1,800 runs.

## Files

- `shadowscan.jsonl`, `shadowscan-dedicated.jsonl`: one line per case, as in
  the published results.
- `run-manifest.json`: corpus hash, platform and run summaries.
- `COMPARISON.md`: rendered by
  `python -m tools.benchmark.compare --before tools/benchmark/results --after DIR`,
  where `DIR` holds this run's rows and its `raw/` reports. The after-run raw
  reports are not committed; rerun the harness to regenerate them.

Reproduce with
`python -m tools.benchmark.run --corpus corpus.json --tool-root TOOLS --results DIR --tools shadowscan,shadowscan-dedicated`.
