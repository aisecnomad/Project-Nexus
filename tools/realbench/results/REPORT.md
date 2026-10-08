# Real-world shadow-AI discovery benchmark: results

183 public repositories (145 GitHub, 38 GitLab), each pinned to a commit, drawn by the pre-registered procedure in [PROTOCOL.md](../PROTOCOL.md). Every tool ran offline on a read-only checkout. ShadowScan commit `80d4bf67aa1aa46c02413de3c791ec2ed16f0d52` (source tree `c5c0711c65d9f45a634fbdf2692e700461441898`); Python 3.13.16 on Linux-6.18.44-fc-v80-x86_64-with-glibc2.39.

**Read this first.** Labels come from two independent AI annotators and an AI adjudicator, not from human reviewers. The corpus over-represents AI projects, so precision depends on prevalence (see below). The harness lives in the ShadowScan repository; see the protocol's conflict-of-interest section. Intervals are 95% Wilson (proportions) or 2,000-sample bootstrap (F1, MCC).

## Tools

| Tool | Upstream | How it ran | Counted as an agent |
|---|---|---|---|
| Project Nexus ShadowScan | `aisecnomad/Project-Nexus` | scan with one code.filesystem connector on the checkout, defaults, use_git false | a finding of kind agent, agent-config, bot-app, mcp-server, workflow (the tool's own agent kinds) |
| Cisco AI BOM | `cisco-ai-defense/aibom` | analyze <checkout> --output-format json; the required LLM endpoint is unreachable offline, so the LLM tier keeps its deterministic candidates (marked unreviewed) | a component of type agent, agent_proxy, mcp_client, mcp_server, skill, tool |
| agent-bom | `msaad00/agent-bom` | scan <checkout> --no-scan --offline -f json (inventory only, no vulnerability lookups), empty HOME | a framework agent, an agent_framework component, a tool definition, an MCP server, or a discovered agent other than the project wrapper (Terraform agents only with AI resources) |
| AgentDiscover Scanner | `Defend-AI-Tech-Inc/agent-discover-scanner` | scan <checkout> --format sarif, then audit <checkout> --skip-layers 2,3,4,5 | an inventoried agent or an MCP server in the audit |
| SafeDep vet | `safedep/vet` | ai discover --scope project -D <checkout> --report-json, then code scan --app <checkout> --db | an ai-discover item of kind MCP server, coding agent, project configuration or skill, or a code signature tagged agent, mcp or crewai |
| agentguard | `ak2dev/agentguard-v1` | scan <checkout> --config <empty policy> -f json | an inventory item of kind agent, instruction_file, mcp_client_config, mcp_server, skill, subagent |
| cdxgen (CycloneDX AI/MCP BOM) | `CycloneDX/cdxgen` | -t ai -t mcp -t ai-skill -r --no-install-deps, FETCH_LICENSE=false, CDXGEN_ALLOWED_COMMANDS=__none__ | a component or service with cdx:agent:* or cdx:mcp:* properties |
| Baseline: keyword grep | `this repository (ripgrep)` | case-insensitive ripgrep over every file except .git for provider and framework names | a file matches the agent-framework or MCP name list |
| Baseline: manifest dependencies | `this repository` | parse dependency manifests (outside vendored dirs) for a fixed list of generative-AI packages | a dependency on an agent framework or MCP package |

## Corpus and labels

- Labels: 77 `agent`, 26 `llm`, 80 `none` (12 of them assistant-only, excluded from the primary population).
- Annotator agreement before adjudication (n=183): three-class label 0.98 (κ 0.96); T1 0.98 (κ 0.96); T2 0.98 (κ 0.97); assistant files 1.00 (κ 1.00).
- Post-run blind adjudication changed 0 label(s); both result sets are shown.

## T1: generative-AI use (agent or llm vs none)

Primary population, pre-registered strict verdict rule, adjudicated labels; the last column repeats MCC on the frozen labels.

| Tool | n | TP | FP | FN | TN | No verdict | Recall | Specificity | Precision | F1 | MCC | MCC, frozen labels |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Baseline: manifest dependencies | 171 | 71 | 1 | 32 | 67 | 0 | 0.69 (0.59–0.77) | 0.99 (0.92–1.00) | 0.99 (0.93–1.00) | 0.81 (0.75–0.87) | 0.67 (0.58–0.75) | 0.67 (0.58–0.75) |
| Cisco AI BOM | 171 | 92 | 17 | 11 | 51 | 3 | 0.89 (0.82–0.94) | 0.75 (0.64–0.84) | 0.84 (0.76–0.90) | 0.87 (0.82–0.91) | 0.65 (0.54–0.77) | 0.65 (0.54–0.77) |
| SafeDep vet | 171 | 67 | 1 | 36 | 67 | 6 | 0.65 (0.55–0.74) | 0.99 (0.92–1.00) | 0.99 (0.92–1.00) | 0.78 (0.71–0.85) | 0.64 (0.55–0.72) | 0.64 (0.55–0.72) |
| agentguard | 171 | 58 | 2 | 45 | 66 | 0 | 0.56 (0.47–0.65) | 0.97 (0.90–0.99) | 0.97 (0.89–0.99) | 0.71 (0.62–0.78) | 0.55 (0.45–0.64) | 0.55 (0.45–0.64) |
| Baseline: keyword grep | 171 | 101 | 38 | 2 | 30 | 0 | 0.98 (0.93–0.99) | 0.44 (0.33–0.56) | 0.73 (0.65–0.79) | 0.83 (0.78–0.88) | 0.53 (0.42–0.64) | 0.53 (0.42–0.64) |
| agent-bom | 171 | 78 | 15 | 25 | 53 | 1 | 0.76 (0.67–0.83) | 0.78 (0.67–0.86) | 0.84 (0.75–0.90) | 0.80 (0.73–0.85) | 0.53 (0.40–0.66) | 0.53 (0.40–0.66) |
| cdxgen (CycloneDX AI/MCP BOM) | 171 | 92 | 31 | 11 | 37 | 1 | 0.89 (0.82–0.94) | 0.54 (0.43–0.66) | 0.75 (0.66–0.82) | 0.81 (0.75–0.87) | 0.48 (0.33–0.61) | 0.48 (0.33–0.61) |
| AgentDiscover Scanner | 171 | 58 | 10 | 45 | 58 | 0 | 0.56 (0.47–0.65) | 0.85 (0.75–0.92) | 0.85 (0.75–0.92) | 0.68 (0.60–0.76) | 0.42 (0.29–0.54) | 0.42 (0.29–0.54) |
| Project Nexus ShadowScan | 171 | 59 | 27 | 44 | 41 | 60 | 0.57 (0.48–0.66) | 0.60 (0.48–0.71) | 0.69 (0.58–0.77) | 0.62 (0.54–0.70) | 0.17 (0.03–0.32) | 0.17 (0.03–0.32) |

### Secondary analyses (MCC)

| Tool | Primary (strict) | Completed scans only | Evidence rule | Footprint | Without ML-only |
|---|---|---|---|---|---|
| Project Nexus ShadowScan | 0.17 | 0.81 | 0.64 | 0.18 | 0.14 |
| Cisco AI BOM | 0.65 | 0.69 | 0.65 | 0.65 | 0.75 |
| agent-bom | 0.53 | 0.54 | 0.53 | 0.50 | 0.63 |
| AgentDiscover Scanner | 0.42 | 0.42 | 0.42 | 0.37 | 0.47 |
| SafeDep vet | 0.64 | 0.68 | 0.64 | 0.65 | 0.62 |
| agentguard | 0.55 | 0.55 | 0.55 | 0.57 | 0.52 |
| cdxgen (CycloneDX AI/MCP BOM) | 0.48 | 0.49 | 0.48 | 0.49 | 0.53 |
| Baseline: keyword grep | 0.53 | 0.53 | 0.53 | 0.49 | 0.57 |
| Baseline: manifest dependencies | 0.67 | 0.67 | 0.67 | 0.60 | 0.67 |

## T2: AI agents (agent vs llm or none)

Primary population, pre-registered strict verdict rule, adjudicated labels; the last column repeats MCC on the frozen labels.

| Tool | n | TP | FP | FN | TN | No verdict | Recall | Specificity | Precision | F1 | MCC | MCC, frozen labels |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| agentguard | 171 | 54 | 4 | 23 | 90 | 0 | 0.70 (0.59–0.79) | 0.96 (0.90–0.98) | 0.93 (0.84–0.97) | 0.80 (0.72–0.87) | 0.69 (0.59–0.79) | 0.69 (0.59–0.79) |
| Baseline: manifest dependencies | 171 | 43 | 0 | 34 | 94 | 0 | 0.56 (0.45–0.66) | 1.00 (0.96–1.00) | 1.00 (0.92–1.00) | 0.72 (0.62–0.80) | 0.64 (0.55–0.73) | 0.64 (0.55–0.73) |
| Cisco AI BOM | 171 | 47 | 3 | 30 | 91 | 3 | 0.61 (0.50–0.71) | 0.97 (0.91–0.99) | 0.94 (0.84–0.98) | 0.74 (0.65–0.82) | 0.63 (0.53–0.73) | 0.63 (0.53–0.73) |
| cdxgen (CycloneDX AI/MCP BOM) | 171 | 46 | 3 | 31 | 91 | 1 | 0.60 (0.49–0.70) | 0.97 (0.91–0.99) | 0.94 (0.83–0.98) | 0.73 (0.64–0.81) | 0.62 (0.52–0.73) | 0.62 (0.52–0.73) |
| SafeDep vet | 171 | 44 | 2 | 33 | 92 | 6 | 0.57 (0.46–0.68) | 0.98 (0.93–0.99) | 0.96 (0.85–0.99) | 0.72 (0.62–0.80) | 0.62 (0.52–0.72) | 0.62 (0.52–0.72) |
| Baseline: keyword grep | 171 | 64 | 23 | 13 | 71 | 0 | 0.83 (0.73–0.90) | 0.76 (0.66–0.83) | 0.74 (0.63–0.82) | 0.78 (0.70–0.84) | 0.58 (0.46–0.70) | 0.58 (0.46–0.70) |
| agent-bom | 171 | 58 | 20 | 19 | 74 | 1 | 0.75 (0.65–0.84) | 0.79 (0.69–0.86) | 0.74 (0.64–0.83) | 0.75 (0.67–0.82) | 0.54 (0.41–0.66) | 0.54 (0.41–0.66) |
| AgentDiscover Scanner | 171 | 45 | 17 | 32 | 77 | 0 | 0.58 (0.47–0.69) | 0.82 (0.73–0.88) | 0.73 (0.60–0.82) | 0.65 (0.55–0.73) | 0.42 (0.28–0.55) | 0.42 (0.28–0.55) |
| Project Nexus ShadowScan | 171 | 24 | 22 | 53 | 72 | 60 | 0.31 (0.22–0.42) | 0.77 (0.67–0.84) | 0.52 (0.38–0.66) | 0.39 (0.28–0.50) | 0.09 (-0.06–0.24) | 0.09 (-0.06–0.24) |

### Secondary analyses (MCC)

| Tool | Primary (strict) | Completed scans only | Evidence rule | Footprint | Without ML-only | T2 without assistant-file negatives |
|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 0.09 | 0.69 | 0.46 | -0.01 | 0.08 | 0.11 |
| Cisco AI BOM | 0.63 | 0.66 | 0.63 | 0.51 | 0.64 | 0.65 |
| agent-bom | 0.54 | 0.55 | 0.54 | 0.50 | 0.60 | 0.54 |
| AgentDiscover Scanner | 0.42 | 0.42 | 0.42 | 0.42 | 0.41 | 0.41 |
| SafeDep vet | 0.62 | 0.66 | 0.62 | 0.48 | 0.61 | 0.63 |
| agentguard | 0.69 | 0.69 | 0.69 | 0.56 | 0.68 | 0.72 |
| cdxgen (CycloneDX AI/MCP BOM) | 0.62 | 0.63 | 0.62 | 0.48 | 0.61 | 0.65 |
| Baseline: keyword grep | 0.58 | 0.58 | 0.58 | 0.58 | 0.62 | 0.58 |
| Baseline: manifest dependencies | 0.64 | 0.64 | 0.64 | 0.63 | 0.63 | 0.64 |

## Assistant-only repositories

12 repositories carry only AI coding-assistant files, with no generative-AI use in code or configuration. They are outside the primary population: flagging them is a policy choice, not an error.

| Tool | Flagged |
|---|---|
| Project Nexus ShadowScan | 0.67 (0.39–0.86) |
| Cisco AI BOM | 0.83 (0.55–0.95) |
| agent-bom | 0.58 (0.32–0.81) |
| AgentDiscover Scanner | 0.17 (0.05–0.45) |
| SafeDep vet | 0.92 (0.65–0.99) |
| agentguard | 1.00 (0.76–1.00) |
| cdxgen (CycloneDX AI/MCP BOM) | 1.00 (0.76–1.00) |
| Baseline: keyword grep | 0.75 (0.47–0.91) |
| Baseline: manifest dependencies | 0.08 (0.01–0.35) |

## Precision at other prevalences (T1, from recall and specificity)

| Tool | 1% | 5% | 20% |
|---|---|---|---|
| Project Nexus ShadowScan | 0.01 | 0.07 | 0.27 |
| Cisco AI BOM | 0.03 | 0.16 | 0.47 |
| agent-bom | 0.03 | 0.15 | 0.46 |
| AgentDiscover Scanner | 0.04 | 0.17 | 0.49 |
| SafeDep vet | 0.31 | 0.70 | 0.92 |
| agentguard | 0.16 | 0.50 | 0.83 |
| cdxgen (CycloneDX AI/MCP BOM) | 0.02 | 0.09 | 0.33 |
| Baseline: keyword grep | 0.02 | 0.08 | 0.30 |
| Baseline: manifest dependencies | 0.32 | 0.71 | 0.92 |

## Paired comparisons (exact McNemar, Holm-adjusted within each family)

**T1: generative-AI use (agent or llm vs none) — against Project Nexus ShadowScan**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| Cisco AI BOM | 171 | 18 | 61 | 1.3e-06 | 1e-05 |
| Baseline: manifest dependencies | 171 | 23 | 61 | 4.1e-05 | 0.00029 |
| SafeDep vet | 171 | 22 | 56 | 0.00015 | 0.0009 |
| Baseline: keyword grep | 171 | 23 | 54 | 0.00054 | 0.0027 |
| agent-bom | 171 | 25 | 56 | 0.00075 | 0.003 |
| cdxgen (CycloneDX AI/MCP BOM) | 171 | 25 | 54 | 0.0015 | 0.0044 |
| agentguard | 171 | 35 | 59 | 0.017 | 0.034 |
| AgentDiscover Scanner | 171 | 33 | 49 | 0.097 | 0.097 |

**T2: AI agents (agent vs llm or none) — against Project Nexus ShadowScan**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| agentguard | 171 | 9 | 57 | 1.2e-09 | 9.5e-09 |
| Cisco AI BOM | 171 | 9 | 51 | 3.1e-08 | 2.2e-07 |
| cdxgen (CycloneDX AI/MCP BOM) | 171 | 10 | 51 | 9.6e-08 | 5.4e-07 |
| SafeDep vet | 171 | 9 | 49 | 9e-08 | 5.4e-07 |
| Baseline: manifest dependencies | 171 | 13 | 54 | 4.5e-07 | 1.8e-06 |
| Baseline: keyword grep | 171 | 23 | 62 | 2.8e-05 | 8.3e-05 |
| agent-bom | 171 | 21 | 57 | 5.6e-05 | 0.00011 |
| AgentDiscover Scanner | 171 | 22 | 48 | 0.0025 | 0.0025 |

**T1: generative-AI use (agent or llm vs none) — against Baseline: keyword grep**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| Project Nexus ShadowScan | 171 | 54 | 23 | 0.00054 | 0.0043 |
| Cisco AI BOM | 171 | 14 | 26 | 0.081 | 0.56 |
| AgentDiscover Scanner | 171 | 45 | 30 | 0.11 | 0.63 |
| agent-bom | 171 | 28 | 28 | 1 | 1 |
| agentguard | 171 | 46 | 39 | 0.52 | 1 |
| Baseline: manifest dependencies | 171 | 31 | 38 | 0.47 | 1 |
| cdxgen (CycloneDX AI/MCP BOM) | 171 | 19 | 17 | 0.87 | 1 |
| SafeDep vet | 171 | 35 | 38 | 0.82 | 1 |

**T2: AI agents (agent vs llm or none) — against Baseline: keyword grep**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| Project Nexus ShadowScan | 171 | 62 | 23 | 2.8e-05 | 0.00022 |
| AgentDiscover Scanner | 171 | 34 | 21 | 0.1 | 0.73 |
| agent-bom | 171 | 28 | 25 | 0.78 | 1 |
| agentguard | 171 | 17 | 26 | 0.22 | 1 |
| Baseline: manifest dependencies | 171 | 21 | 23 | 0.88 | 1 |
| cdxgen (CycloneDX AI/MCP BOM) | 171 | 25 | 27 | 0.89 | 1 |
| Cisco AI BOM | 171 | 22 | 25 | 0.77 | 1 |
| SafeDep vet | 171 | 26 | 27 | 1 | 1 |

## Where tools find and miss AI (T1 detection rate, adjudicated labels)

### By stratum and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| config-positives|agent | 7 | 4 | 7 | 5 | 3 | 4 | 3 | 6 | 7 | 3 |
| config-positives|llm | 3 | 3 | 3 | 3 | 1 | 1 | 0 | 2 | 3 | 1 |
| gh-agents|agent | 20 | 6 | 18 | 16 | 12 | 14 | 11 | 20 | 20 | 12 |
| gh-agents|assistant-only | 2 | 2 | 1 | 1 | 1 | 2 | 2 | 2 | 2 | 1 |
| gh-agents|llm | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 |
| gh-agents|none | 2 | 1 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| gh-genai|agent | 6 | 2 | 6 | 4 | 3 | 5 | 5 | 6 | 6 | 6 |
| gh-genai|llm | 12 | 10 | 9 | 7 | 5 | 5 | 1 | 8 | 12 | 4 |
| gh-genai|none | 2 | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 2 | 0 |
| gh-general|agent | 2 | 1 | 1 | 2 | 0 | 1 | 2 | 1 | 2 | 1 |
| gh-general|assistant-only | 2 | 1 | 2 | 2 | 0 | 1 | 2 | 2 | 1 | 0 |
| gh-general|llm | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 |
| gh-general|none | 15 | 2 | 1 | 0 | 1 | 0 | 0 | 3 | 7 | 0 |
| gh-mcp|agent | 15 | 9 | 14 | 14 | 10 | 14 | 14 | 14 | 14 | 15 |
| gitlab-ai|agent | 10 | 7 | 10 | 8 | 7 | 9 | 7 | 10 | 10 | 9 |
| gitlab-ai|assistant-only | 2 | 2 | 2 | 2 | 0 | 2 | 2 | 2 | 2 | 0 |
| gitlab-ai|llm | 7 | 6 | 5 | 4 | 5 | 4 | 0 | 6 | 7 | 4 |
| gitlab-ai|none | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 1 | 1 | 0 |
| gitlab-general|agent | 2 | 1 | 2 | 1 | 0 | 0 | 2 | 2 | 2 | 2 |
| gitlab-general|assistant-only | 2 | 2 | 2 | 0 | 0 | 2 | 2 | 2 | 1 | 0 |
| gitlab-general|none | 11 | 1 | 2 | 1 | 1 | 0 | 0 | 6 | 4 | 0 |
| hard-negatives|agent | 2 | 1 | 1 | 2 | 2 | 1 | 0 | 1 | 2 | 1 |
| hard-negatives|assistant-only | 3 | 1 | 2 | 1 | 0 | 3 | 3 | 3 | 2 | 0 |
| hard-negatives|none | 28 | 2 | 11 | 11 | 7 | 0 | 1 | 19 | 21 | 1 |
| npm-ai|agent | 12 | 5 | 11 | 9 | 8 | 5 | 11 | 11 | 12 | 9 |
| npm-ai|assistant-only | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| npm-ai|llm | 2 | 2 | 2 | 0 | 0 | 1 | 1 | 2 | 1 | 1 |
| npm-general|agent | 1 | 0 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 1 |
| npm-general|none | 9 | 2 | 0 | 0 | 0 | 1 | 1 | 1 | 2 | 0 |

### Positives by evidence type

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 | 31 | 15 | 30 | 24 | 20 | 23 | 23 | 31 | 31 | 25 |
| A2 | 27 | 8 | 25 | 18 | 15 | 19 | 18 | 27 | 27 | 24 |
| A3 | 44 | 17 | 41 | 40 | 27 | 35 | 41 | 41 | 43 | 44 |
| A4 | 23 | 9 | 23 | 18 | 13 | 17 | 22 | 22 | 23 | 18 |
| A5 | 11 | 7 | 10 | 6 | 4 | 6 | 6 | 10 | 11 | 3 |
| A6 | 13 | 4 | 11 | 13 | 8 | 8 | 12 | 11 | 13 | 11 |
| L1 | 78 | 42 | 71 | 58 | 47 | 54 | 41 | 72 | 77 | 57 |
| L2 | 16 | 12 | 15 | 11 | 8 | 11 | 7 | 13 | 16 | 9 |
| L3 | 64 | 32 | 60 | 49 | 44 | 51 | 38 | 60 | 64 | 57 |

### False alarms on hard negatives by trait

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| agent-word | 38 | 12 | 17 | 13 | 7 | 10 | 11 | 27 | 25 | 2 |
| ai-names-as-data | 17 | 6 | 5 | 4 | 2 | 5 | 5 | 12 | 16 | 1 |
| ai-prose | 20 | 10 | 10 | 8 | 4 | 7 | 7 | 13 | 17 | 1 |
| chatbot | 6 | 1 | 3 | 3 | 2 | 1 | 1 | 3 | 5 | 0 |
| key-patterns | 6 | 4 | 4 | 4 | 1 | 5 | 5 | 6 | 6 | 1 |
| key-verification | 1 | 0 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 |
| mcp-acronym | 9 | 3 | 6 | 5 | 2 | 3 | 4 | 5 | 7 | 1 |
| ml_only | 10 | 0 | 8 | 9 | 5 | 0 | 0 | 8 | 8 | 1 |
| non-generative-ml | 10 | 0 | 8 | 9 | 5 | 0 | 0 | 8 | 8 | 1 |
| product-name | 28 | 9 | 15 | 10 | 6 | 8 | 8 | 23 | 23 | 1 |
| prompt-word | 18 | 6 | 7 | 5 | 2 | 4 | 4 | 14 | 15 | 0 |
| provider-name | 19 | 6 | 10 | 9 | 7 | 4 | 4 | 14 | 19 | 2 |
| user-agent | 19 | 3 | 8 | 3 | 1 | 3 | 3 | 14 | 12 | 0 |

### By dominant language and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| C#|agent | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| C#|assistant-only | 1 | 0 | 1 | 1 | 0 | 0 | 1 | 1 | 1 | 0 |
| C#|none | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 0 |
| C/C++|assistant-only | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 |
| C/C++|none | 2 | 0 | 1 | 2 | 0 | 0 | 0 | 1 | 1 | 0 |
| Go|agent | 4 | 2 | 3 | 2 | 0 | 2 | 4 | 3 | 4 | 4 |
| Go|assistant-only | 4 | 2 | 3 | 1 | 0 | 4 | 4 | 4 | 3 | 0 |
| Go|llm | 2 | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 2 | 1 |
| Go|none | 9 | 2 | 1 | 1 | 0 | 0 | 0 | 7 | 7 | 0 |
| JavaScript|agent | 6 | 3 | 6 | 6 | 4 | 6 | 5 | 5 | 6 | 5 |
| JavaScript|assistant-only | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| JavaScript|llm | 3 | 3 | 1 | 0 | 0 | 1 | 0 | 2 | 3 | 1 |
| JavaScript|none | 15 | 3 | 3 | 2 | 1 | 0 | 0 | 5 | 7 | 0 |
| Java|assistant-only | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 0 | 0 |
| Java|llm | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 1 |
| Java|none | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| Kotlin|llm | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 |
| PHP|none | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| Python|agent | 27 | 15 | 24 | 25 | 26 | 23 | 16 | 25 | 26 | 24 |
| Python|assistant-only | 2 | 2 | 2 | 2 | 1 | 2 | 2 | 2 | 2 | 1 |
| Python|llm | 11 | 9 | 11 | 11 | 10 | 7 | 1 | 11 | 11 | 6 |
| Python|none | 22 | 2 | 9 | 8 | 8 | 0 | 1 | 11 | 15 | 1 |
| Ruby|none | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Rust|agent | 2 | 1 | 2 | 1 | 1 | 1 | 1 | 2 | 2 | 2 |
| Rust|assistant-only | 1 | 1 | 1 | 0 | 0 | 1 | 1 | 1 | 1 | 0 |
| Rust|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| Shell|agent | 1 | 0 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 |
| Shell|none | 3 | 0 | 0 | 1 | 0 | 0 | 0 | 3 | 0 | 0 |
| Terraform|agent | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| Terraform|llm | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| Terraform|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| TypeScript|agent | 33 | 12 | 31 | 24 | 13 | 20 | 28 | 33 | 33 | 23 |
| TypeScript|llm | 5 | 4 | 4 | 1 | 2 | 3 | 1 | 5 | 4 | 2 |
| TypeScript|none | 6 | 3 | 1 | 1 | 0 | 1 | 1 | 2 | 3 | 0 |
| other|agent | 2 | 2 | 2 | 1 | 0 | 0 | 0 | 2 | 2 | 0 |
| other|assistant-only | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 |
| other|llm | 2 | 2 | 2 | 2 | 0 | 0 | 0 | 1 | 2 | 0 |
| other|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |

### By size tercile and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| large|agent | 40 | 8 | 38 | 32 | 22 | 27 | 34 | 39 | 40 | 32 |
| large|assistant-only | 6 | 3 | 6 | 4 | 1 | 5 | 6 | 6 | 4 | 1 |
| large|llm | 3 | 2 | 3 | 3 | 3 | 2 | 0 | 3 | 3 | 2 |
| large|none | 11 | 1 | 5 | 1 | 2 | 0 | 0 | 8 | 9 | 0 |
| medium|agent | 25 | 19 | 21 | 18 | 14 | 16 | 13 | 22 | 25 | 16 |
| medium|assistant-only | 5 | 4 | 4 | 3 | 1 | 5 | 5 | 5 | 5 | 0 |
| medium|llm | 7 | 5 | 6 | 4 | 5 | 6 | 1 | 7 | 7 | 5 |
| medium|none | 24 | 3 | 9 | 9 | 6 | 0 | 0 | 18 | 15 | 1 |
| small|agent | 12 | 9 | 12 | 12 | 9 | 11 | 9 | 11 | 11 | 11 |
| small|assistant-only | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 |
| small|llm | 16 | 16 | 12 | 9 | 5 | 5 | 1 | 10 | 15 | 5 |
| small|none | 33 | 6 | 2 | 5 | 2 | 1 | 2 | 5 | 14 | 0 |

### By host and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| github|agent | 65 | 28 | 59 | 53 | 38 | 45 | 47 | 60 | 64 | 48 |
| github|assistant-only | 7 | 3 | 6 | 5 | 2 | 6 | 7 | 7 | 6 | 1 |
| github|llm | 19 | 17 | 16 | 12 | 8 | 9 | 2 | 14 | 18 | 8 |
| github|none | 54 | 9 | 14 | 13 | 7 | 1 | 2 | 23 | 31 | 1 |
| gitlab|agent | 12 | 8 | 12 | 9 | 7 | 9 | 9 | 12 | 12 | 11 |
| gitlab|assistant-only | 5 | 5 | 4 | 2 | 0 | 5 | 5 | 5 | 3 | 0 |
| gitlab|llm | 7 | 6 | 5 | 4 | 5 | 4 | 0 | 6 | 7 | 4 |
| gitlab|none | 14 | 1 | 2 | 2 | 3 | 0 | 0 | 8 | 7 | 0 |

## Localisation

| Tool | True positives | Cites an evidence file | TPs citing no file | Cited-file precision |
|---|---|---|---|---|
| Project Nexus ShadowScan | 59 | 0.97 (0.88–0.99) | 0 | 0.72 (0.52–0.86) of 25 |
| Cisco AI BOM | 92 | 0.68 (0.58–0.77) | 0 | 0.32 (0.17–0.52) of 25 |
| agent-bom | 78 | 0.64 (0.53–0.74) | 0 | 0.28 (0.14–0.48) of 25 |
| AgentDiscover Scanner | 58 | 0.64 (0.51–0.75) | 3 | 0.48 (0.30–0.67) of 25 |
| SafeDep vet | 67 | 0.78 (0.66–0.86) | 0 | 0.76 (0.57–0.89) of 25 |
| agentguard | 58 | 0.17 (0.10–0.29) | 7 | 0.88 (0.70–0.96) of 25 |
| cdxgen (CycloneDX AI/MCP BOM) | 92 | 0.23 (0.15–0.32) | 45 | 0.72 (0.52–0.86) of 25 |
| Baseline: keyword grep | 101 | 0.89 (0.82–0.94) | 0 | 0.32 (0.17–0.52) of 25 |
| Baseline: manifest dependencies | 71 | 0.79 (0.68–0.87) | 0 | 1.00 (0.87–1.00) of 25 |

## Run status, time and determinism

| Tool | ok | partial | error | Median s | p90 s | Repeat runs | Verdict flips |
|---|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 119 | 64 | 0 | 2.7 | 19.7 | 18 | 0 |
| Cisco AI BOM | 180 | 0 | 3 | 47.7 | 176.8 | 18 | 0 |
| agent-bom | 182 | 0 | 1 | 5.2 | 32.0 | 18 | 0 |
| AgentDiscover Scanner | 183 | 0 | 0 | 2.8 | 9.7 | 18 | 0 |
| SafeDep vet | 177 | 0 | 6 | 6.5 | 112.1 | 18 | 1 |
| agentguard | 183 | 0 | 0 | 0.7 | 6.8 | 18 | 0 |
| cdxgen (CycloneDX AI/MCP BOM) | 182 | 0 | 1 | 2.7 | 13.7 | 18 | 0 |
| Baseline: keyword grep | 183 | 0 | 0 | 0.1 | 0.1 | 18 | 0 |
| Baseline: manifest dependencies | 183 | 0 | 0 | 0.1 | 0.6 | 18 | 0 |

