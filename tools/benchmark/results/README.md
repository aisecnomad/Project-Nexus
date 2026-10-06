# Scored results

These results come from the 900-case pre-registered corpus (seed `20261006`,
SHA-256 `b757b2ac2293dba05e961a11ef9f49abb66e97aea1ab5edb9d9ccb28d2319e63`).
[`REPORT.md`](REPORT.md) has every table: coverage, per-surface confusion
matrices with 95% intervals, per-family detection, paired McNemar tests, and
two clearly labeled post-hoc analyses.

> The cases were written by ShadowScan's maintainers. These are results on
> synthetic inputs, not field accuracy, and not an independent evaluation. See
> the [harness README](../README.md) for the conflict of interest and limits.

## What the run shows

- **Coverage separates the tools more than accuracy does.** ShadowScan is the only tool here that reads all three input types; every other tool covers one or two. Across all 540 AI cases, ShadowScan flags 90% (87–92%), Cisco AI BOM 49%, and no other tool more than 33%.
- **Source repositories.** ShadowScan got all 300 cases right. Running without its LLM classifier, Cisco AI BOM found 86% of AI repositories. All 23 of its false alarms are dataset or classical-ML components it inventories by design; dropping those types (post hoc) leaves it with none. It missed Semantic Kernel (C#), Claude Agent SDK, Pydantic AI and Terraform Bedrock agents. agent-bom raised no false alarms but found none of the 41 TypeScript and JavaScript projects (56% recall overall). AgentDiscover flagged 35 of 120 clean repositories through a generic HTTP-client rule.
- **Developer home directories: no single tool covers them.** ShadowScan found 126 of 180 (70%) with no false alarms. It missed every LLM-only artifact (the Copilot extension, Ollama and LM Studio models, AI commands in shell history), plus Goose and three Cline installs. AI-Detector caught 34 of those 45 LLM-only cases. Together the two reach 163 of 180 with no false alarms. Among the other tools, Snyk Agent Scan was the most reliable on agent configs: 73% of agent cases, no false alarms.
- **No tool detected an AI browser extension**: 0 of 11 cases, for every tool.
- **Network logs.** ShadowScan detected all 180 AI windows with no false alarms. Shadow AI Detector came next with 83% recall and no false alarms; it missed OpenRouter, Bedrock InvokeAgent and sessions that only reached a remote MCP server. Open Shadow AI's catalog missed Azure OpenAI custom subdomains, private vLLM servers, loopback Ollama and Bedrock (57% recall).
- **AgentSonar flagged every network case, clean or not.** Its traffic-shape scores for ordinary SaaS traffic overlap with LLM traffic, and no cut-off separates them in this replay (post hoc). Its input here is synthetic flow statistics, not captured packets, so this says more about the replay than about AgentSonar on a real network.
- **Single-purpose tools are precise within their scope.** Claw-Hunter found all 19 OpenClaw homes and nothing else. Cisco MCP Scanner found all 19 Cursor and Windsurf configs, the only two clients it reads on Linux. Their low overall recall reflects scope, not error.
- **Every tool completed every case it supports**: 0 errors in 4,800 tool runs. The paired McNemar tests favor ShadowScan on every shared surface, but on a corpus its own maintainers wrote that is expected and is not evidence of field superiority.

## Limits

- The cases were written by ShadowScan's maintainers in ShadowScan's repository. Discount its perfect repository and network scores until someone without a stake reruns the benchmark with their own templates.
- Every case is small and synthetic. Real repositories, laptops and proxy logs are larger and messier, and include formats no template covers.
- Several tools ran below full capability: Cisco AI BOM without its LLM classifier, Open Shadow AI without its database and correlation, AgentDiscover without its live network, Kubernetes and cloud layers, and both MCP scanners without network access to the servers.
- Endpoint cases are file trees. Tools that also inspect running processes, installed packages, browser profiles or sockets lose those signals here.
- Network cases are rendered logs and flow records, not live traffic. Each tool gets only the fields its native format carries, so tools that read paths and user agents see more than a flow sensor does.
- The label boundary is a choice. Classical ML and data files count as no AI, which penalizes AI-BOM tools. A plain LLM call counts as AI, which favors broad matchers over agent-only tools.
- Scoring is binary per case. It does not grade attribution, severity, report quality or remediation guidance.
- Tool versions are pinned to commits from 2026-10-06, and most of these projects change every week.

## Files

- `<tool>.jsonl` has one line per case: surface, family, label, difficulty,
  the tool's status (`ok`, `error` or `n/a`), detection, item count, agent-tier
  flag, seconds and a short note. `shadowscan.jsonl` was committed before any
  third-party tool ran. A rerun of ShadowScan under the final harness matched
  it on all 900 detections, differing only in timings.
- `run-manifest.json` records the corpus hash, the platform and each tool's
  run summary.
- `raw/agentsonar.jsonl.gz` keeps AgentSonar's raw scores for the post-hoc
  cut-off sweep. Other tools' raw reports are regenerated by rerunning the
  harness.

Regenerate the tables with
`python -m tools.benchmark.report --results tools/benchmark/results --output REPORT.md`.
