# Real-world repository results

These results come from the 91-repository pinned corpus
([`realworld_corpus.json`](../realworld_corpus.json), SHA-256
`12d8cf8157ec9507d459562f5101ba134bbfe6a999e9690ba712862b7199065c`), run once
on 2026-10-08 after the corpus and every detection rule were committed.
[`REPORT.md`](REPORT.md) has every table: the confusion matrices with 95%
intervals, detection by stratum, evidence coverage, paired McNemar tests, the
post-hoc readings of ShadowScan's reports, and one row per repository.

> The repositories were chosen and labeled by the author of this harness,
> who had read ShadowScan's signature packs. The selection is stratified, not
> random, and no second person reviewed the labels. These numbers describe
> eight tools on these 91 checkouts; they are not field precision or recall,
> and they are not an independent evaluation. See the
> [harness README](../README.md#real-world-repository-corpus) for the label
> rules, the run modes and the limits.

## What the run shows

- **On real checkouts, coverage and precision pull apart.** The naive keyword
  control finds every one of the 64 positives and flags 14 of the 27
  negatives: AWS Copilot, Minecraft Bedrock, the MCP2515 CAN driver, the
  Gemini-protocol server, Weave Net and every list of AI names. cdxgen's AI
  inventory (92% recall, 37% specificity) and Cisco AI BOM (91%, 63%) sit
  near it: cdxgen's `prompt-config-file` heuristic fires on shell scripts in
  ripgrep, jq, fzf, bat and goose, and Cisco AI BOM inventories datasets,
  training runs and model artifacts in minGPT, Gymnasium, imbalanced-learn,
  bat and ripgrep by design. Agentic Radar and Cisco Skill Scanner never
  raise a false alarm and find 19% and 39% of the positives.
- **ShadowScan's detections were right and its completeness contract was the
  story.** Under the pre-registered rule, which follows ShadowScan's own
  fail-closed contract (exit 3 is an error, never a clean result), 47 of the
  91 scans ended incomplete and count as misses: recall 0.45, specificity
  0.96. Reading the stored reports instead, every one of the 64 positives
  holds findings, including all 35 incomplete positives and all 13
  configuration-only cases, and only three negatives do, all of them
  provider-key-shaped strings in test fixtures and documentation (AWS Copilot,
  Weave Net) or in Cursor rule templates (awesome-cursorrules). Ignoring
  reports whose only findings are secrets leaves one false alarm. Neither
  reading was pre-registered. The incompleteness came from text files over
  the 1 MB `max_file_size` (21 scans), lexical analysis that stopped on Rust,
  JavaScript and other sources (17), structured configuration that did not
  parse (13), notebooks whose import-bound analysis stopped (12), symbolic
  links with unavailable targets (11), binary content in analyzable paths
  (5), missing submodule checkouts (4), malformed MCP configurations (3) and
  one unreadable A2A card. Whether a skipped 2 MB CSV should make a
  repository scan "incomplete" is a product decision for the maintainers; the
  benchmark shows that on real repositories it happens to more than half.
- **Configuration-only agents separate the tools.** Of the 13 repositories
  whose agent evidence is only skills, coding-agent files, exports or IaC,
  ShadowScan reads 8 under the pre-registered rule (13 of 13 in the stored
  reports), Cisco AI BOM 12, cdxgen 11, AgentDiscover 5, agent-bom 4, Skill
  Scanner 3 and Agentic Radar 1. Skill Scanner found all 25 repositories with
  skill packages and nothing else, as its scope says.
- **Language reach is the other divider.** agent-bom found 24 of 25
  Python-first positives but 6 of 15 TypeScript, 1 of 8 Go, 0 of 2 Java and
  none of the Rust, Ruby, C# or export-only repositories; AgentDiscover's
  pattern is the same (25 of 25 Python, 7 of 15 TypeScript, 1 of 8 Go).
  Agentic Radar covers five Python frameworks and n8n, so the TypeScript,
  Java, Go and Rust positives are out of its reach by design.
- **Crashes are part of the result.** Agentic Radar's LangGraph and CrewAI
  parsers raised on ordinary Python in 44 repositories (34 positives, 10
  negatives), which the harness records as errors rather than misses; where a
  parser survived it mapped real graphs (179 agents in Pydantic AI, 135 in
  Microsoft Agent Framework, 32 nodes in GitLab's Duo Workflow service).
  Cisco AI BOM timed out at 900 s on five large repositories (Synapse, the
  GitLab AI Gateway, Pydantic AI, FastMCP, Microsoft Agent Framework) and
  took 74 s at the median. agent-bom crashed on SwarmKit.
- **Paired tests, pre-registered rule.** The keyword control (p = 0.002) and
  Cisco AI BOM (p = 0.003) are right where ShadowScan is wrong far more often
  than the reverse, because of the incomplete scans; ShadowScan beats Agentic
  Radar (p = 0.005); the other differences are not significant on 91 cases.

## Run notes

- Every tool ran on a copy of the checkout in fresh network and PID
  namespaces with an empty `HOME`, four cases at a time on a 4-core machine,
  with a 900 s timeout per invocation.
- The harness's timeout killed only the `unshare` process until the fix in
  `adapters._isolated`, which now kills the whole process group. That fix
  landed while this run was in progress, so the first two Cisco AI BOM
  timeouts (Synapse and the GitLab AI Gateway) left orphaned analyses running
  for up to 27 minutes beside later scans; they were killed by hand, and a
  reaper killed one more. Those orphans competed for CPU with the Cisco AI
  BOM scans that ran at the same time and may have slowed them. No recorded
  outcome changed: a timed-out case is an error either way.
- Cisco AI BOM ran without its LLM tier, cdxgen without dependency
  installation or Babel, Skill Scanner without its LLM analyzer, and no tool
  had network access.

## Limits

- Single-author, single-reviewer labels on a stratified selection; 64
  positives against 27 negatives, so specificity intervals are wide and the
  two `llm` cases carry little weight.
- One commit per repository, pinned on 2026-10-08.
- Binary scoring per repository, as in the synthetic benchmark; the
  evidence-coverage table is secondary and depends on each adapter's mapping.
- The post-hoc readings of ShadowScan's reports are exactly that: they were
  chosen after seeing that incompleteness dominated the pre-registered score.

## Files

- `<tool>.jsonl`: one line per repository with status (`ok`, `error`),
  detection, item count, agent-tier flag, seconds, a short note and the
  evidence counts. `shadowscan.jsonl` was written first, before any other
  tool ran.
- `run-manifest.json`: corpus hash, checkout manifest (files and bytes per
  repository), timeout, platform and each tool's run summary.
- `raw/<tool>.jsonl.gz`: the tools' own reports, kept for every tool except
  agent-bom, whose 39 MB of package inventories are regenerated by rerunning
  the harness. `raw/shadowscan.jsonl.gz` feeds the post-hoc table.

Regenerate the tables with
`python -m tools.benchmark.realworld report --results tools/benchmark/results-realworld --output tools/benchmark/results-realworld/REPORT.md`
from the repository root.
