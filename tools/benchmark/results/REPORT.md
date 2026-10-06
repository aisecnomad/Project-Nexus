# Shadow-AI discovery head-to-head: results

Corpus: 900 synthetic cases, SHA-256 `b757b2ac2293dba05e961a11ef9f49abb66e97aea1ab5edb9d9ccb28d2319e63` (seed 20261006). Python 3.13.16 on Linux-6.18.44-fc-v70-x86_64-with-glibc2.39.

**These are results on author-written synthetic cases, not field accuracy.** The corpus was written in the ShadowScan repository; see the README for the conflict of interest, the per-tool run modes and the limits. Intervals are 95% Wilson (proportions) or bootstrap (F1).

## Coverage: which surfaces each tool can be scored on

| Tool | repo | endpoint | network | Estate recall (unsupported = miss) |
|---|---|---|---|---|
| Project Nexus ShadowScan | ✓ | ✓ | ✓ | 0.90 (0.87–0.92) |
| Cisco AI BOM | ✓ | ✓ | — | 0.49 (0.45–0.53) |
| agent-bom | ✓ | ✓ | — | 0.29 (0.26–0.33) |
| AgentDiscover Scanner | ✓ | ✓ | — | 0.23 (0.20–0.27) |
| Snyk Agent Scan | — | ✓ | — | 0.18 (0.15–0.22) |
| Cisco MCP Scanner | — | ✓ | — | 0.04 (0.02–0.05) |
| Open Shadow AI | — | — | ✓ | 0.19 (0.16–0.23) |
| AgentSonar (Knostic) | — | — | ✓ | 0.33 (0.29–0.37) |
| Shadow AI Detector | — | — | ✓ | 0.28 (0.24–0.32) |
| Claw-Hunter (Backslash) | — | ✓ | — | 0.04 (0.02–0.05) |
| AI-Detector (shamo0) | — | ✓ | — | 0.13 (0.11–0.16) |

## Surface: repo

| Tool | n | TP | FP | FN | TN | Errors | Recall | Specificity | Precision | F1 | MCC | Agent recall | Median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 300 | 180 | 0 | 0 | 120 | 0 | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 (0.98–1.00) | 1.00 (1.00–1.00) | 1.00 | 0.95 (0.90–0.97) | 1.7 |
| Cisco AI BOM | 300 | 154 | 23 | 26 | 97 | 0 | 0.86 (0.80–0.90) | 0.81 (0.73–0.87) | 0.87 (0.81–0.91) | 0.86 (0.82–0.90) | 0.66 | 0.24 (0.17–0.32) | 36.1 |
| agent-bom | 300 | 101 | 0 | 79 | 120 | 0 | 0.56 (0.49–0.63) | 1.00 (0.97–1.00) | 1.00 (0.96–1.00) | 0.72 (0.65–0.78) | 0.58 | 0.05 (0.03–0.10) | 1.1 |
| AgentDiscover Scanner | 300 | 96 | 35 | 84 | 85 | 0 | 0.53 (0.46–0.60) | 0.71 (0.62–0.78) | 0.73 (0.65–0.80) | 0.62 (0.55–0.68) | 0.24 | 0.30 (0.23–0.38) | 2.2 |

Detection rate by family (positives: higher is better; `none` rows: lower is better).

| Family | Label | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner |
|---|---|---|---|---|---|
| cs-semantic-kernel | agent | 7/7 | 0/7 | 0/7 | 0/7 |
| go-langchaingo | agent | 4/4 | 4/4 | 2/4 | 0/4 |
| mcp-project-config | agent | 10/10 | 10/10 | 5/10 | 5/10 |
| n8n-ai-agent | agent | 10/10 | 10/10 | 0/10 | 0/10 |
| py-autogen | agent | 5/5 | 5/5 | 5/5 | 5/5 |
| py-claude-agent-sdk | agent | 7/7 | 0/7 | 0/7 | 0/7 |
| py-crewai | agent | 7/7 | 6/7 | 7/7 | 7/7 |
| py-google-adk | agent | 7/7 | 7/7 | 7/7 | 7/7 |
| py-langchain-agent | agent | 12/12 | 12/12 | 12/12 | 12/12 |
| py-langgraph | agent | 3/3 | 3/3 | 3/3 | 3/3 |
| py-llamaindex | agent | 8/8 | 8/8 | 8/8 | 8/8 |
| py-openai-agents | agent | 6/6 | 6/6 | 6/6 | 6/6 |
| py-pydantic-ai | agent | 4/4 | 0/4 | 4/4 | 0/4 |
| py-raw-tool-loop | agent | 9/9 | 9/9 | 9/9 | 9/9 |
| py-smolagents | agent | 6/6 | 6/6 | 6/6 | 0/6 |
| tf-bedrock-agent | agent | 7/7 | 0/7 | 7/7 | 0/7 |
| ts-langgraph | agent | 4/4 | 4/4 | 0/4 | 4/4 |
| ts-mastra | agent | 3/3 | 3/3 | 0/3 | 3/3 |
| ts-openai-agents | agent | 9/9 | 9/9 | 0/9 | 0/9 |
| ts-vercel-ai-tools | agent | 7/7 | 7/7 | 0/7 | 0/7 |
| js-fetch-anthropic | llm | 6/6 | 6/6 | 0/6 | 0/6 |
| py-anthropic-messages | llm | 2/2 | 2/2 | 2/2 | 2/2 |
| py-gemini | llm | 7/7 | 7/7 | 0/7 | 7/7 |
| py-litellm | llm | 9/9 | 9/9 | 9/9 | 9/9 |
| py-ollama | llm | 4/4 | 4/4 | 4/4 | 4/4 |
| py-openai-chat | llm | 5/5 | 5/5 | 5/5 | 5/5 |
| ts-openai-chat | llm | 4/4 | 4/4 | 0/4 | 0/4 |
| ts-vercel-ai-plain | llm | 8/8 | 8/8 | 0/8 | 0/8 |
| neg-call-center-api | none | 0/18 | 0/18 | 0/18 | 18/18 |
| neg-commented-out | none | 0/9 | 0/9 | 0/9 | 0/9 |
| neg-egress-blocklist | none | 0/10 | 0/10 | 0/10 | 0/10 |
| neg-gemini-exchange | none | 0/12 | 0/12 | 0/12 | 12/12 |
| neg-insurance-agents | none | 0/4 | 0/4 | 0/4 | 0/4 |
| neg-minecraft-bedrock | none | 0/2 | 0/2 | 0/2 | 0/2 |
| neg-modcoderpack | none | 0/11 | 11/11 | 0/11 | 0/11 |
| neg-monitoring-agent | none | 0/7 | 0/7 | 0/7 | 0/7 |
| neg-readme-prose | none | 0/7 | 0/7 | 0/7 | 0/7 |
| neg-rule-chatbot | none | 0/7 | 0/7 | 0/7 | 0/7 |
| neg-sklearn | none | 0/12 | 12/12 | 0/12 | 0/12 |
| neg-travel-agent | none | 0/5 | 0/5 | 0/5 | 5/5 |
| neg-user-agent | none | 0/10 | 0/10 | 0/10 | 0/10 |
| neg-webapp | none | 0/6 | 0/6 | 0/6 | 0/6 |

## Surface: endpoint

| Tool | n | TP | FP | FN | TN | Errors | Recall | Specificity | Precision | F1 | MCC | Agent recall | Median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 300 | 126 | 0 | 54 | 120 | 0 | 0.70 (0.63–0.76) | 1.00 (0.97–1.00) | 1.00 (0.97–1.00) | 0.82 (0.78–0.87) | 0.69 | 0.93 (0.88–0.96) | 1.7 |
| Snyk Agent Scan | 300 | 99 | 0 | 81 | 120 | 0 | 0.55 (0.48–0.62) | 1.00 (0.97–1.00) | 1.00 (0.96–1.00) | 0.71 (0.65–0.77) | 0.57 | 0.73 (0.65–0.80) | 0.9 |
| Cisco AI BOM | 300 | 111 | 12 | 69 | 108 | 0 | 0.62 (0.54–0.68) | 0.90 (0.83–0.94) | 0.90 (0.84–0.94) | 0.73 (0.67–0.79) | 0.51 | 0.63 (0.55–0.71) | 2.4 |
| AI-Detector (shamo0) | 300 | 71 | 0 | 109 | 120 | 0 | 0.39 (0.33–0.47) | 1.00 (0.97–1.00) | 1.00 (0.95–1.00) | 0.57 (0.49–0.64) | 0.45 | – | 2.6 |
| agent-bom | 300 | 57 | 0 | 123 | 120 | 0 | 0.32 (0.25–0.39) | 1.00 (0.97–1.00) | 1.00 (0.94–1.00) | 0.48 (0.40–0.56) | 0.40 | 0.42 (0.34–0.51) | 0.9 |
| AgentDiscover Scanner | 300 | 29 | 0 | 151 | 120 | 0 | 0.16 (0.11–0.22) | 1.00 (0.97–1.00) | 1.00 (0.88–1.00) | 0.28 (0.20–0.36) | 0.27 | 0.21 (0.15–0.29) | 2.3 |
| Cisco MCP Scanner | 300 | 19 | 0 | 161 | 120 | 0 | 0.11 (0.07–0.16) | 1.00 (0.97–1.00) | 1.00 (0.83–1.00) | 0.19 (0.12–0.26) | 0.21 | 0.14 (0.09–0.21) | 3.8 |
| Claw-Hunter (Backslash) | 300 | 19 | 0 | 161 | 120 | 0 | 0.11 (0.07–0.16) | 1.00 (0.97–1.00) | 1.00 (0.83–1.00) | 0.19 (0.12–0.27) | 0.21 | 0.14 (0.09–0.21) | 0.1 |

Detection rate by family (positives: higher is better; `none` rows: lower is better).

| Family | Label | Project Nexus ShadowScan | Snyk Agent Scan | Cisco AI BOM | AI-Detector (shamo0) | agent-bom | AgentDiscover Scanner | Cisco MCP Scanner | Claw-Hunter (Backslash) |
|---|---|---|---|---|---|---|---|---|---|
| ep-aider | agent | 8/8 | 0/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| ep-amazonq | agent | 16/16 | 16/16 | 16/16 | 0/16 | 0/16 | 0/16 | 0/16 | 0/16 |
| ep-claude-code | agent | 7/7 | 3/7 | 3/7 | 0/7 | 2/7 | 0/7 | 0/7 | 0/7 |
| ep-claude-desktop-mcp | agent | 9/9 | 9/9 | 9/9 | 0/9 | 9/9 | 0/9 | 0/9 | 0/9 |
| ep-cline | agent | 5/8 | 0/8 | 5/8 | 8/8 | 5/8 | 0/8 | 0/8 | 0/8 |
| ep-codex | agent | 11/11 | 11/11 | 0/11 | 0/11 | 11/11 | 11/11 | 0/11 | 0/11 |
| ep-continue | agent | 10/10 | 0/10 | 10/10 | 0/10 | 0/10 | 0/10 | 0/10 | 0/10 |
| ep-cursor-mcp | agent | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 0/10 |
| ep-gemini-cli | agent | 8/8 | 8/8 | 0/8 | 0/8 | 8/8 | 8/8 | 0/8 | 0/8 |
| ep-goose | agent | 0/6 | 0/6 | 0/6 | 0/6 | 6/6 | 0/6 | 0/6 | 0/6 |
| ep-kiro | agent | 8/8 | 8/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| ep-openclaw | agent | 19/19 | 19/19 | 19/19 | 19/19 | 0/19 | 0/19 | 0/19 | 19/19 |
| ep-vscode-mcp | agent | 6/6 | 6/6 | 6/6 | 0/6 | 6/6 | 0/6 | 0/6 | 0/6 |
| ep-windsurf-mcp | agent | 9/9 | 9/9 | 9/9 | 0/9 | 0/9 | 0/9 | 9/9 | 0/9 |
| ep-browser-ai-ext | llm | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 |
| ep-copilot-ext | llm | 0/7 | 0/7 | 0/7 | 7/7 | 0/7 | 0/7 | 0/7 | 0/7 |
| ep-lmstudio | llm | 0/8 | 0/8 | 8/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| ep-ollama-models | llm | 0/12 | 0/12 | 0/12 | 12/12 | 0/12 | 0/12 | 0/12 | 0/12 |
| ep-shell-history-ai | llm | 0/7 | 0/7 | 0/7 | 7/7 | 0/7 | 0/7 | 0/7 | 0/7 |
| ep-neg-agent-projects | none | 0/12 | 0/12 | 12/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 |
| ep-neg-browser-ext | none | 0/21 | 0/21 | 0/21 | 0/21 | 0/21 | 0/21 | 0/21 | 0/21 |
| ep-neg-datadog-agent | none | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| ep-neg-infra-dotfiles | none | 0/26 | 0/26 | 0/26 | 0/26 | 0/26 | 0/26 | 0/26 | 0/26 |
| ep-neg-minecraft-mcp | none | 0/18 | 0/18 | 0/18 | 0/18 | 0/18 | 0/18 | 0/18 | 0/18 |
| ep-neg-plain | none | 0/28 | 0/28 | 0/28 | 0/28 | 0/28 | 0/28 | 0/28 | 0/28 |

## Surface: network

| Tool | n | TP | FP | FN | TN | Errors | Recall | Specificity | Precision | F1 | MCC | Agent recall | Median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 300 | 180 | 0 | 0 | 120 | 0 | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 (0.98–1.00) | 1.00 (1.00–1.00) | 1.00 | 0.00 (0.00–0.03) | 1.8 |
| Shadow AI Detector | 300 | 150 | 0 | 30 | 120 | 0 | 0.83 (0.77–0.88) | 1.00 (0.97–1.00) | 1.00 (0.98–1.00) | 0.91 (0.87–0.94) | 0.82 | – | 0.0 |
| Open Shadow AI | 300 | 103 | 0 | 77 | 120 | 0 | 0.57 (0.50–0.64) | 1.00 (0.97–1.00) | 1.00 (0.96–1.00) | 0.73 (0.67–0.78) | 0.59 | – | 0.7 |
| AgentSonar (Knostic) | 300 | 180 | 120 | 0 | 0 | 0 | 1.00 (0.98–1.00) | 0.00 (0.00–0.03) | 0.60 (0.54–0.65) | 0.75 (0.70–0.79) | 0.00 | – | 0.0 |

Detection rate by family (positives: higher is better; `none` rows: lower is better).

| Family | Label | Project Nexus ShadowScan | Shadow AI Detector | Open Shadow AI | AgentSonar (Knostic) |
|---|---|---|---|---|---|
| net-agent-anthropic-loop | agent | 15/15 | 15/15 | 15/15 | 15/15 |
| net-agent-azure-openai | agent | 16/16 | 16/16 | 0/16 | 16/16 |
| net-agent-bedrock | agent | 19/19 | 8/19 | 0/19 | 19/19 |
| net-agent-gemini-api | agent | 14/14 | 14/14 | 14/14 | 14/14 |
| net-agent-local-vllm | agent | 13/13 | 13/13 | 0/13 | 13/13 |
| net-agent-mcp-remote | agent | 17/17 | 10/17 | 10/17 | 17/17 |
| net-agent-openai-loop | agent | 12/12 | 12/12 | 12/12 | 12/12 |
| net-agent-openclaw | agent | 17/17 | 17/17 | 17/17 | 17/17 |
| net-agent-openrouter | agent | 12/12 | 0/12 | 12/12 | 12/12 |
| net-llm-consumer-web | llm | 13/13 | 13/13 | 13/13 | 13/13 |
| net-llm-ollama-local | llm | 22/22 | 22/22 | 0/22 | 22/22 |
| net-llm-single-api | llm | 10/10 | 10/10 | 10/10 | 10/10 |
| net-neg-agent-ua | none | 0/18 | 0/18 | 0/18 | 18/18 |
| net-neg-gemini-exchange | none | 0/30 | 0/30 | 0/30 | 30/30 |
| net-neg-lookalike-hosts | none | 0/18 | 0/18 | 0/18 | 18/18 |
| net-neg-plain | none | 0/26 | 0/26 | 0/26 | 26/26 |
| net-neg-streaming | none | 0/28 | 0/28 | 0/28 | 28/28 |

## Paired comparison with ShadowScan (exact McNemar on correct/incorrect)

| Tool | Surface | n | ShadowScan right, other wrong | Other right, ShadowScan wrong | p |
|---|---|---|---|---|---|
| Cisco AI BOM | repo | 300 | 49 | 0 | 3.6e-15 |
| Cisco AI BOM | endpoint | 300 | 35 | 8 | 4.2e-05 |
| agent-bom | repo | 300 | 79 | 0 | 3.3e-24 |
| agent-bom | endpoint | 300 | 75 | 6 | 2.9e-16 |
| AgentDiscover Scanner | repo | 300 | 119 | 0 | 3e-36 |
| AgentDiscover Scanner | endpoint | 300 | 97 | 0 | 1.3e-29 |
| Snyk Agent Scan | endpoint | 300 | 27 | 0 | 1.5e-08 |
| Cisco MCP Scanner | endpoint | 300 | 107 | 0 | 1.2e-32 |
| Open Shadow AI | network | 300 | 77 | 0 | 1.3e-23 |
| AgentSonar (Knostic) | network | 300 | 120 | 0 | 1.5e-36 |
| Shadow AI Detector | network | 300 | 30 | 0 | 1.9e-09 |
| Claw-Hunter (Backslash) | endpoint | 300 | 107 | 0 | 1.2e-32 |
| AI-Detector (shamo0) | endpoint | 300 | 92 | 37 | 1.4e-06 |

## Supplementary (post hoc): AgentSonar at other cut-offs

The pre-registered cut-off is 0.3, the value in the project's examples. These rows re-apply its stored scores at other cut-offs after the scored run. They were not pre-registered and are shown only to separate threshold choice from ranking quality.

| Cut-off | Recall | Specificity | F1 |
|---|---|---|---|
| > 0.3 | 1.00 (0.98–1.00) | 0.00 (0.00–0.03) | 0.75 |
| > 0.5 | 1.00 (0.98–1.00) | 0.00 (0.00–0.03) | 0.75 |
| > 0.6 | 0.99 (0.96–1.00) | 0.00 (0.00–0.03) | 0.74 |
| > 0.7 | 0.79 (0.73–0.85) | 0.10 (0.06–0.17) | 0.66 |
| > 0.8 | 0.01 (0.00–0.03) | 0.88 (0.81–0.93) | 0.01 |
| > 0.9 | 0.00 (0.00–0.02) | 0.98 (0.94–1.00) | 0.00 |

## Supplementary (post hoc): Cisco AI BOM without dataset and training-run components

Every Cisco AI BOM false alarm comes from `dataset` or `training_run` components (CSV files, scikit-learn training). An AI bill of materials inventories those by design, while this corpus labels classical ML and data files as no AI. These rows drop detections that consist only of those two types. They were not pre-registered.

| Surface | Rule | Recall | Specificity | F1 | MCC |
|---|---|---|---|---|---|
| repo | pre-registered | 0.86 (0.80–0.90) | 0.81 (0.73–0.87) | 0.86 | 0.66 |
| repo | without dataset/training_run | 0.86 (0.80–0.90) | 1.00 (0.97–1.00) | 0.92 | 0.84 |
| endpoint | pre-registered | 0.62 (0.54–0.68) | 0.90 (0.83–0.94) | 0.73 | 0.51 |
| endpoint | without dataset/training_run | 0.62 (0.54–0.68) | 1.00 (0.97–1.00) | 0.76 | 0.63 |

## Errors

- None: every supported case completed for every tool.

