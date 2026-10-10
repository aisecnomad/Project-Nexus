# Real-world shadow-AI discovery benchmark: results

> **Read this first.** These are results on public repositories at pinned commits, labeled by two model-based labelers (no human labeled the corpus) under `PROTOCOL.md`. They are not field precision or recall, not an independent review, and not production accuracy. Intervals are 95% Wilson (proportions) or a 2,000-sample bootstrap (F1). Small strata give wide intervals.

Manifest SHA-256 `4ebc1dc910ff684661193e76af402617053658eb2f5d83d1849ce82fd6d967bc`. Protocol v1 (`PROTOCOL.md`).

## Corpus

- Repositories: 41 (pinned commits). Labels after adjudication: agent 24, ambiguous 2, llm 5, none 10.
- Strata: ai-app 28, hard-negative 10, ordinary 3.
- Labeler agreement before adjudication: exact 0.83, Cohen's kappa 0.71 (agent / llm / none / ambiguous), kappa 0.77 (positive versus none).
- Disagreements, adjudicated from the cited evidence: rw-09-aider, rw-11-chatbot-ui, rw-32-fastapi, rw-35-private-gpt, rw-36-azure-search-openai-demo, rw-39-streamlit-llm-examples, rw-41-llms-from-scratch.

## Repo surface (the source tree)

| Tool | Supported | TP | FP | FN | TN | Errors | Recall [95% CI] | Specificity | Precision | F1 [95% CI] | Median s |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---|---:|
| agent-bom | 41 | 29 | 6 | 0 | 4 | 0 | 1.00 [0.88–1.00] | 0.40 | 0.83 | 0.91 [0.82–0.97] | 11.546 |
| agentdiscover | 41 | 21 | 5 | 8 | 5 | 0 | 0.72 [0.54–0.85] | 0.50 | 0.81 | 0.76 [0.62–0.88] | 7.58 |
| cisco-aibom | 41 | 25 | 3 | 4 | 7 | 5 | 0.86 [0.69–0.95] | 0.70 | 0.89 | 0.88 [0.77–0.95] | 83.432 |
| mcp-audit | 41 | 14 | 1 | 15 | 9 | 0 | 0.48 [0.31–0.66] | 0.90 | 0.93 | 0.64 [0.44–0.78] | 0.535 |
| safedep-vet | 41 | 9 | 0 | 20 | 10 | 0 | 0.31 [0.17–0.49] | 1.00 | 1.00 | 0.47 [0.26–0.65] | 0.223 |
| shadowscan-dedicated | 41 | 16 | 2 | 13 | 8 | 15 | 0.55 [0.38–0.72] | 0.80 | 0.89 | 0.68 [0.51–0.82] | 2.854 |
| shadowscan | 41 | 16 | 1 | 13 | 9 | 16 | 0.55 [0.38–0.72] | 0.90 | 0.94 | 0.70 [0.52–0.84] | 2.965 |

## Home-view surface (root read as $HOME)

| Tool | Supported | TP | FP | FN | TN | Errors | Recall [95% CI] | Specificity | Precision | F1 [95% CI] | Median s |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---|---:|
| agent-bom | 41 | 1 | 7 | 0 | 33 | 0 | 1.00 [0.21–1.00] | 0.82 | 0.12 | 0.22 [0.00–0.60] | 4.313 |
| agentdiscover | 41 | 1 | 26 | 0 | 14 | 0 | 1.00 [0.21–1.00] | 0.35 | 0.04 | 0.07 [0.00–0.23] | 7.251 |
| ai-detector | 41 | 0 | 3 | 1 | 37 | 0 | 0.00 [0.00–0.79] | 0.93 | 0.00 | 0.00 [0.00–0.00] | 3.2 |
| cisco-aibom | 41 | 0 | 30 | 1 | 10 | 5 | 0.00 [0.00–0.79] | 0.25 | 0.00 | 0.00 [0.00–0.00] | 86.087 |
| cisco-mcp-scanner | 41 | 0 | 0 | 1 | 40 | 0 | 0.00 [0.00–0.79] | 1.00 | — | 0.00 [0.00–0.00] | 5.17 |
| claw-hunter | 41 | 0 | 0 | 1 | 40 | 0 | 0.00 [0.00–0.79] | 1.00 | — | 0.00 [0.00–0.00] | 0.066 |
| mcp-audit | 41 | 0 | 0 | 1 | 40 | 0 | 0.00 [0.00–0.79] | 1.00 | — | 0.00 [0.00–0.00] | 0.557 |
| safedep-vet | 41 | 1 | 10 | 0 | 30 | 0 | 1.00 [0.21–1.00] | 0.75 | 0.09 | 0.17 [0.00–0.47] | 0.287 |
| shadow-mcp | 41 | 0 | 0 | 1 | 40 | 0 | 0.00 [0.00–0.79] | 1.00 | — | 0.00 [0.00–0.00] | 0.265 |
| shadowscan-dedicated | 41 | 1 | 0 | 0 | 40 | 0 | 1.00 [0.21–1.00] | 1.00 | 1.00 | 1.00 [0.00–1.00] | 1.653 |
| shadowscan | 41 | 0 | 18 | 1 | 22 | 17 | 0.00 [0.00–0.79] | 0.55 | 0.00 | 0.00 [0.00–0.00] | 3.02 |
| snyk-agent-scan | 41 | 1 | 0 | 0 | 40 | 0 | 1.00 [0.21–1.00] | 1.00 | 1.00 | 1.00 [0.00–1.00] | 1.327 |

## False positives by stratum (repo surface)

| Tool | AI apps detected | Hard negatives flagged | Ordinary repos flagged |
|---|---|---|---|
| agent-bom | 26/26 | 4/8 | 2/2 |
| agentdiscover | 19/26 | 4/8 | 1/2 |
| cisco-aibom | 23/26 | 3/8 | 0/2 |
| mcp-audit | 14/26 | 1/8 | 0/2 |
| safedep-vet | 9/26 | 0/8 | 0/2 |
| shadowscan-dedicated | 14/26 | 2/8 | 0/2 |
| shadowscan | 14/26 | 1/8 | 0/2 |

## Sensitivity: hard negatives excluded (repo surface)

| Tool | F1 (all scored) | F1 (hard negatives excluded) | Specificity (all) |
|---|---|---|---|
| agent-bom | 0.91 | 0.96 | 0.40 |
| agentdiscover | 0.76 | 0.83 | 0.50 |
| cisco-aibom | 0.88 | 0.92 | 0.70 |
| mcp-audit | 0.64 | 0.68 | 0.90 |
| safedep-vet | 0.47 | 0.50 | 1.00 |
| shadowscan-dedicated | 0.68 | 0.71 | 0.80 |
| shadowscan | 0.70 | 0.71 | 0.90 |

## Agent tier (repo surface)

| Tool | Recall on agent repos | False alarms on llm and none repos |
|---|---|---|
| agent-bom | 0.50 [0.31–0.69] | 0.27 [0.11–0.52] |
| agentdiscover | 0.71 [0.51–0.85] | 0.40 [0.20–0.64] |
| mcp-audit | 0.54 [0.35–0.72] | 0.13 [0.04–0.38] |
| safedep-vet | 0.38 [0.21–0.57] | 0.00 [0.00–0.20] |

## Paired comparison with ShadowScan (exact McNemar), repo surface

| Tool | n | ShadowScan only right | Tool only right | p |
|---|---:|---:|---:|---:|
| agent-bom | 39 | 5 | 13 | 0.096 |
| agentdiscover | 39 | 9 | 10 | 1 |
| cisco-aibom | 39 | 3 | 10 | 0.092 |
| mcp-audit | 39 | 12 | 10 | 0.83 |
| safedep-vet | 39 | 12 | 6 | 0.24 |
| shadowscan-dedicated | 39 | 1 | 0 | 1 |

## Paired comparison with ShadowScan (exact McNemar), endpoint surface

| Tool | n | ShadowScan only right | Tool only right | p |
|---|---:|---:|---:|---:|
| agent-bom | 41 | 5 | 17 | 0.017 |
| agentdiscover | 41 | 14 | 7 | 0.19 |
| ai-detector | 41 | 1 | 16 | 0.00027 |
| cisco-aibom | 41 | 13 | 1 | 0.0018 |
| cisco-mcp-scanner | 41 | 0 | 18 | 7.6e-06 |
| claw-hunter | 41 | 0 | 18 | 7.6e-06 |
| mcp-audit | 41 | 0 | 18 | 7.6e-06 |
| safedep-vet | 41 | 3 | 12 | 0.035 |
| shadow-mcp | 41 | 0 | 18 | 7.6e-06 |
| shadowscan-dedicated | 41 | 0 | 19 | 3.8e-06 |
| snyk-agent-scan | 41 | 0 | 19 | 3.8e-06 |

## Errors (crash, timeout, incomplete scan, unreadable output)

| Tool | Surface | Errors | Example note (sanitized) |
|---|---|---:|---|
| cisco-aibom | repo | 5 | exit 124: timeout after 300s |
| cisco-aibom | endpoint | 5 | exit 124: timeout after 300s |
| shadowscan-dedicated | repo | 16 | incomplete scan (exit 3) |
| shadowscan | repo | 17 | incomplete scan (exit 3) |
| shadowscan | endpoint | 17 | incomplete scan (exit 3) |

## Self-check: ShadowScan on this repository (descriptive, not scored)

Status `error`, detected `False`, items 0. This repository is not a corpus member, and it contains the signatures it searches for.

## Limits

- The corpus is small. Strata of 1 to 4 repositories cannot support rates; read them as examples.
- Labels come from model-based labelers following the protocol. No human labeled them, and adjudication is by the same pipeline. Treat labels as a reproducible reading of public code, not as ground truth.
- Repositories are at pinned commits. Results do not transfer to other commits or to private code.
- Network, identity, SaaS and cloud surfaces are not measured here (no public real-world data).
- Several tools were run in a reduced mode: Cisco AI BOM without its LLM classifier, AgentDiscover without layers 2 to 5, Snyk Agent Scan with no analysis upload (no network in the sandbox).

## Reproduce

```bash
bash tools/benchmark_realworld/install_tools.sh /opt/rwbench/tools
python -m tools.benchmark_realworld.run --manifest tools/benchmark_realworld/corpus.json --checkout-root /home/user --tool-root /opt/rwbench/tools --results tools/benchmark_realworld/results --raw /opt/rwbench/raw --self-check
python -m tools.benchmark_realworld.score --results tools/benchmark_realworld/results --manifest tools/benchmark_realworld/corpus.json
```
