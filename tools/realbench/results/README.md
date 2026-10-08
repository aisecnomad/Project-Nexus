# Real-world benchmark results: summary

The full tables are in [REPORT.md](REPORT.md). This page summarises what they
show and what they do not show. The design, conflicts of interest and limits
are in [PROTOCOL.md](../PROTOCOL.md).

> **Read this first.**
>
> - Labels are AI annotations, not human review. Two annotators, which
>   differed in model and search strategy, agreed on 179 of 183 three-class
>   labels (κ 0.96). A blind post-run adjudication of 158 repositories against
>   pooled tool evidence changed no label.
> - The corpus over-represents AI projects, so read precision through the
>   prevalence table in the report.
> - The harness lives in ShadowScan's repository.
> - Every tool ran offline. Cisco AI BOM therefore ran without its LLM tier,
>   and no tool sent repository content anywhere.

## Headline (primary population of 171 repositories, pre-registered strict rule)

| Tool | T1 MCC: generative-AI use | T2 MCC: agents | Scans incomplete or failed | Cited-file precision |
|---|---|---|---|---|
| Baseline: manifest dependencies | 0.67 | 0.64 | 0 | 1.00 |
| Cisco AI BOM | 0.65 | 0.63 | 3 timeouts | 0.32 |
| SafeDep vet | 0.64 | 0.62 | 6 | 0.76 |
| agentguard | 0.55 | **0.69** | 0 | 0.88 |
| Baseline: keyword grep | 0.53 | 0.58 | 0 | 0.32 |
| agent-bom | 0.53 | 0.54 | 1 | 0.28 |
| cdxgen (AI/MCP BOM) | 0.48 | 0.62 | 1 | 0.72 |
| AgentDiscover Scanner | 0.42 | 0.42 | 0 | 0.48 |
| ShadowScan | 0.17 | 0.09 | 64 incomplete | 0.72 |

## Findings

1. **No tool clearly beats a dependency-list baseline at finding generative-AI
   use.** Reading manifests for a fixed list of AI packages scored MCC 0.67,
   with one false alarm in 68 negatives. Cisco AI BOM (0.65) and vet (0.64)
   match it within the intervals. None of the three clears the others, and
   all three miss AI use that never appears in a manifest: raw HTTP calls,
   configuration, workflow exports and CI agents.
2. **Agent detection is best served by configuration-aware tools.** agentguard
   leads T2 (MCC 0.69, precision 0.93), mainly because it inventories MCP
   configuration, skills and instruction files. Every scanner misses
   between 25% and 69% of agents, most often hand-written tool loops (A2) and
   agent infrastructure (A5).
3. **Keyword grep finds almost everything and is wrong on most negatives.**
   It reaches recall 0.98, but specificity is 0.44. The hard negatives make
   the cost visible: OpenAI-branded reinforcement learning code, the Gemini
   protocol, AWS Copilot, Minecraft Bedrock, secret scanners with AI-key
   rules and AI-crawler blocklists.
4. **AI-BOM tools trade precision for coverage.** Cisco AI BOM and cdxgen
   both reach T1 recall 0.89. Only 32% and 72% of the files they cite hold
   AI evidence. cdxgen's AI mode labels ordinary shell scripts
   `prompt-config-file` and extracts "models" such as `str` from non-AI
   code.
5. **ShadowScan's detection is the strongest, and its coverage policy is the
   weakest.** On the 111 repositories it scanned to completion, it scored
   T1 recall 0.98, precision 0.86 and MCC 0.81, the best of any tool. On
   T2 it scored MCC 0.69, level with the best. But it marked 64 of 183 scans
   incomplete. Counted once per repository and cause (one scan can have
   several causes):
   - 26 for text files over its 1 MB default, mostly JSON and plain-text data;
   - 18 for source its lexer could not finish;
   - 11 for symbolic links it does not follow, all pointing inside the
     repository (2 of them dangling);
   - 10 for binary or non-UTF-8 content in files it treats as analyzable;
   - smaller counts for AI configuration it could not parse (6), missing
     submodule or Git LFS content (5), structured-data limits (5), deadlines
     (2) and other analysis limits (2).
   Under the pre-registered rule an incomplete scan without a finding cannot
   certify a repository clean and counts as wrong, which puts it last
   (MCC 0.17). Counting findings from incomplete scans, a rule added only
   as a secondary analysis, gives 0.64. Fail-closed reporting is a
   deliberate design choice, but on real repositories it currently costs
   more than it protects.
6. **Assistant files are common and handled inconsistently.** 53 of 183
   repositories carry AI coding-assistant files, and 12 carry nothing else.
   Tools flagged those 12 at rates from 8% (dependency baseline) to 100%
   (agentguard and cdxgen). The rubric treats these files as a separate
   policy question, not as AI use.
7. **The runs are deterministic.** A seeded 10% of repositories was run twice
   per tool. Across 162 repeat runs, there was one verdict flip (vet).

## What this does not show

- **Field precision for any estate.** The corpus over-represents AI
  projects. See the prevalence table in the report: at 5% prevalence, only
  vet, agentguard and the dependency baseline keep precision at 0.5 or
  above.
- **Online capability.** Cisco AI BOM's LLM classifier, agent-bom's
  vulnerability enrichment and AgentDiscover's live layers were not used.
- **Independent human judgment.** Treat ShadowScan's completed-scan lead with
  particular suspicion, since this repository built the harness. An
  independent human re-labelling of `corpus.json` is the most useful
  next step (see the [README](../README.md#independent-re-labelling)).
