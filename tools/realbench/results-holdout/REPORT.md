# Real-world shadow-AI discovery benchmark: results

140 public repositories (105 GitHub, 35 GitLab), each pinned to a commit, drawn by the pre-registered procedure in [PROTOCOL.md](../PROTOCOL.md). Every tool ran offline on a read-only checkout. ShadowScan commit `c30aaacdd0be4cfb2091448f5197ab1a8379d9ea` (source tree `b3b7fd3be5c810b168fca90fbdb96e0b8a03affb`); Python 3.13.16 on Linux-6.18.44-fc-v80-x86_64-with-glibc2.39.

**Read this first.** Labels come from two independent AI annotators and an AI adjudicator, not from human reviewers. The corpus over-represents AI projects, so precision depends on prevalence (see below). The harness lives in the ShadowScan repository; see the protocol's conflict-of-interest section. Intervals are 95% Wilson (proportions) or 2,000-sample bootstrap (F1, MCC).

## Tools

| Tool | Upstream | How it ran | Counted as an agent |
|---|---|---|---|
| Project Nexus ShadowScan | `aisecnomad/Project-Nexus` | scan with one code.filesystem connector on the checkout, defaults, use_git false | any finding with metadata.agentic true (PROTOCOL.md §13.3); the first run used a finding of kind agent, agent-config, bot-app, mcp-server, workflow (the tool's own agent kinds), kept as agentic_kinds |
| Cisco AI BOM | `cisco-ai-defense/aibom` | analyze <checkout> --output-format json; the required LLM endpoint is unreachable offline, so the LLM tier keeps its deterministic candidates (marked unreviewed) | a component of type agent, agent_proxy, mcp_client, mcp_server, skill, tool |
| agent-bom | `msaad00/agent-bom` | scan <checkout> --no-scan --offline -f json (inventory only, no vulnerability lookups), empty HOME | a framework agent, an agent_framework component, a tool definition, an MCP server, or a discovered agent other than the project wrapper (Terraform agents only with AI resources) |
| AgentDiscover Scanner | `Defend-AI-Tech-Inc/agent-discover-scanner` | scan <checkout> --format sarif, then audit <checkout> --skip-layers 2,3,4,5 | an inventoried agent or an MCP server in the audit |
| SafeDep vet | `safedep/vet` | ai discover --scope project -D <checkout> --report-json, then code scan --app <checkout> --db | an ai-discover item of kind MCP server, coding agent, project configuration or skill, or a code signature tagged agent, mcp or crewai |
| agentguard | `ak2dev/agentguard-v1` | scan <checkout> --config <empty policy> -f json | an inventory item of kind agent, instruction_file, mcp_client_config, mcp_server, skill, subagent |
| cdxgen (CycloneDX AI/MCP BOM) | `CycloneDX/cdxgen` | -t ai -t mcp -t ai-skill -r --no-install-deps, FETCH_LICENSE=false, CDXGEN_ALLOWED_COMMANDS=__none__ | a component or service with cdx:agent:* or cdx:mcp:* properties |
| Baseline: keyword grep | `this repository (ripgrep)` | case-insensitive ripgrep over every file except .git for provider and framework names | a file matches the agent-framework or MCP name list |
| Baseline: manifest dependencies | `this repository` | parse dependency manifests (outside vendored dirs) for a fixed list of generative-AI packages | a dependency on an agent framework or MCP package |

## Corpus and labels

- Labels: 67 `agent`, 28 `llm`, 45 `none` (10 of them assistant-only, excluded from the primary population).
- Annotator agreement before adjudication (n=140): three-class label 1.00 (κ 1.00); T1 1.00 (κ 1.00); T2 1.00 (κ 1.00); assistant files 1.00 (κ 1.00).
- Post-run blind adjudication changed 0 label(s); both result sets are shown.

## T1: generative-AI use (agent or llm vs none)

Primary population, pre-registered strict verdict rule, adjudicated labels; the last column repeats MCC on the frozen labels.

| Tool | n | TP | FP | FN | TN | No verdict | Recall | Specificity | Precision | F1 | MCC | MCC, frozen labels |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Baseline: keyword grep | 130 | 93 | 9 | 2 | 26 | 0 | 0.98 (0.93–0.99) | 0.74 (0.58–0.86) | 0.91 (0.84–0.95) | 0.94 (0.91–0.97) | 0.78 (0.64–0.89) | 0.78 (0.64–0.89) |
| agent-bom | 130 | 74 | 0 | 21 | 35 | 0 | 0.78 (0.69–0.85) | 1.00 (0.90–1.00) | 1.00 (0.95–1.00) | 0.88 (0.82–0.93) | 0.70 (0.60–0.80) | 0.70 (0.60–0.80) |
| Baseline: manifest dependencies | 130 | 67 | 0 | 28 | 35 | 0 | 0.71 (0.61–0.79) | 1.00 (0.90–1.00) | 1.00 (0.95–1.00) | 0.83 (0.76–0.88) | 0.63 (0.52–0.73) | 0.63 (0.52–0.73) |
| Cisco AI BOM | 130 | 77 | 5 | 18 | 30 | 4 | 0.81 (0.72–0.88) | 0.86 (0.71–0.94) | 0.94 (0.87–0.97) | 0.87 (0.81–0.92) | 0.61 (0.47–0.74) | 0.61 (0.47–0.74) |
| SafeDep vet | 130 | 63 | 0 | 32 | 35 | 1 | 0.66 (0.56–0.75) | 1.00 (0.90–1.00) | 1.00 (0.94–1.00) | 0.80 (0.73–0.86) | 0.59 (0.50–0.69) | 0.59 (0.50–0.69) |
| cdxgen (CycloneDX AI/MCP BOM) | 130 | 82 | 10 | 13 | 25 | 0 | 0.86 (0.78–0.92) | 0.71 (0.55–0.84) | 0.89 (0.81–0.94) | 0.88 (0.83–0.92) | 0.56 (0.41–0.72) | 0.56 (0.41–0.72) |
| Project Nexus ShadowScan | 130 | 70 | 5 | 25 | 30 | 23 | 0.74 (0.64–0.81) | 0.86 (0.71–0.94) | 0.93 (0.85–0.97) | 0.82 (0.75–0.88) | 0.53 (0.38–0.67) | 0.53 (0.38–0.67) |
| agentguard | 130 | 54 | 0 | 41 | 35 | 0 | 0.57 (0.47–0.66) | 1.00 (0.90–1.00) | 1.00 (0.93–1.00) | 0.72 (0.64–0.80) | 0.51 (0.42–0.61) | 0.51 (0.42–0.61) |
| AgentDiscover Scanner | 130 | 59 | 3 | 36 | 32 | 1 | 0.62 (0.52–0.71) | 0.91 (0.78–0.97) | 0.95 (0.87–0.98) | 0.75 (0.67–0.82) | 0.48 (0.34–0.60) | 0.48 (0.34–0.60) |

### Secondary analyses (MCC)

| Tool | Primary (strict) | Completed scans only | Evidence rule | Footprint | Without ML-only |
|---|---|---|---|---|---|
| Project Nexus ShadowScan | 0.53 | 0.85 | 0.82 | 0.52 | 0.51 |
| Cisco AI BOM | 0.61 | 0.66 | 0.61 | 0.57 | 0.59 |
| agent-bom | 0.70 | 0.70 | 0.70 | 0.64 | 0.69 |
| AgentDiscover Scanner | 0.48 | 0.48 | 0.48 | 0.42 | 0.46 |
| SafeDep vet | 0.59 | 0.60 | 0.59 | 0.59 | 0.58 |
| agentguard | 0.51 | 0.51 | 0.51 | 0.53 | 0.50 |
| cdxgen (CycloneDX AI/MCP BOM) | 0.56 | 0.56 | 0.56 | 0.57 | 0.56 |
| Baseline: keyword grep | 0.78 | 0.78 | 0.78 | 0.74 | 0.76 |
| Baseline: manifest dependencies | 0.63 | 0.63 | 0.63 | 0.55 | 0.61 |

## T2: AI agents (agent vs llm or none)

Primary population, pre-registered strict verdict rule, adjudicated labels; the last column repeats MCC on the frozen labels.

| Tool | n | TP | FP | FN | TN | No verdict | Recall | Specificity | Precision | F1 | MCC | MCC, frozen labels |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| agentguard | 130 | 51 | 2 | 16 | 61 | 0 | 0.76 (0.65–0.85) | 0.97 (0.89–0.99) | 0.96 (0.87–0.99) | 0.85 (0.78–0.91) | 0.74 (0.64–0.84) | 0.74 (0.64–0.84) |
| Baseline: keyword grep | 130 | 59 | 11 | 8 | 52 | 0 | 0.88 (0.78–0.94) | 0.83 (0.71–0.90) | 0.84 (0.74–0.91) | 0.86 (0.79–0.92) | 0.71 (0.58–0.82) | 0.71 (0.58–0.82) |
| agent-bom | 130 | 53 | 8 | 14 | 55 | 0 | 0.79 (0.68–0.87) | 0.87 (0.77–0.93) | 0.87 (0.76–0.93) | 0.83 (0.75–0.89) | 0.67 (0.53–0.78) | 0.67 (0.53–0.78) |
| Baseline: manifest dependencies | 130 | 41 | 0 | 26 | 63 | 0 | 0.61 (0.49–0.72) | 1.00 (0.94–1.00) | 1.00 (0.91–1.00) | 0.76 (0.66–0.84) | 0.66 (0.56–0.75) | 0.66 (0.56–0.75) |
| SafeDep vet | 130 | 40 | 2 | 27 | 61 | 1 | 0.60 (0.48–0.71) | 0.97 (0.89–0.99) | 0.95 (0.84–0.99) | 0.73 (0.64–0.82) | 0.60 (0.49–0.72) | 0.60 (0.49–0.72) |
| Cisco AI BOM | 130 | 38 | 1 | 29 | 62 | 4 | 0.57 (0.45–0.68) | 0.98 (0.92–1.00) | 0.97 (0.87–1.00) | 0.72 (0.61–0.81) | 0.60 (0.49–0.71) | 0.60 (0.49–0.71) |
| cdxgen (CycloneDX AI/MCP BOM) | 130 | 40 | 3 | 27 | 60 | 0 | 0.60 (0.48–0.71) | 0.95 (0.87–0.98) | 0.93 (0.81–0.98) | 0.73 (0.62–0.82) | 0.58 (0.45–0.71) | 0.58 (0.45–0.71) |
| AgentDiscover Scanner | 130 | 42 | 14 | 25 | 49 | 1 | 0.63 (0.51–0.73) | 0.78 (0.66–0.86) | 0.75 (0.62–0.84) | 0.68 (0.58–0.77) | 0.41 (0.25–0.56) | 0.41 (0.25–0.56) |
| Project Nexus ShadowScan | 130 | 30 | 8 | 37 | 55 | 23 | 0.45 (0.33–0.57) | 0.87 (0.77–0.93) | 0.79 (0.64–0.89) | 0.57 (0.45–0.68) | 0.35 (0.19–0.51) | 0.35 (0.19–0.51) |

### Secondary analyses (MCC)

| Tool | Primary (strict) | Completed scans only | Evidence rule | Footprint | Without ML-only | T2 without assistant-file negatives |
|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 0.35 | 0.63 | 0.50 | 0.33 | 0.34 | 0.37 |
| Cisco AI BOM | 0.60 | 0.64 | 0.60 | 0.52 | 0.60 | 0.62 |
| agent-bom | 0.67 | 0.67 | 0.67 | 0.64 | 0.66 | 0.68 |
| AgentDiscover Scanner | 0.41 | 0.42 | 0.41 | 0.43 | 0.40 | 0.42 |
| SafeDep vet | 0.60 | 0.61 | 0.60 | 0.48 | 0.60 | 0.64 |
| agentguard | 0.74 | 0.74 | 0.74 | 0.60 | 0.74 | 0.78 |
| cdxgen (CycloneDX AI/MCP BOM) | 0.58 | 0.58 | 0.58 | 0.43 | 0.58 | 0.62 |
| Baseline: keyword grep | 0.71 | 0.71 | 0.71 | 0.65 | 0.70 | 0.72 |
| Baseline: manifest dependencies | 0.66 | 0.66 | 0.66 | 0.67 | 0.65 | 0.66 |

## Assistant-only repositories

10 repositories carry only AI coding-assistant files, with no generative-AI use in code or configuration. They are outside the primary population: flagging them is a policy choice, not an error.

| Tool | Flagged |
|---|---|
| Project Nexus ShadowScan | 0.70 (0.40–0.89) |
| Cisco AI BOM | 0.50 (0.24–0.76) |
| agent-bom | 0.30 (0.11–0.60) |
| AgentDiscover Scanner | 0.10 (0.02–0.40) |
| SafeDep vet | 0.80 (0.49–0.94) |
| agentguard | 1.00 (0.72–1.00) |
| cdxgen (CycloneDX AI/MCP BOM) | 1.00 (0.72–1.00) |
| Baseline: keyword grep | 0.80 (0.49–0.94) |
| Baseline: manifest dependencies | 0.00 (0.00–0.28) |

## Precision at other prevalences (T1, from recall and specificity)

| Tool | 1% | 5% | 20% |
|---|---|---|---|
| Project Nexus ShadowScan | 0.05 | 0.21 | 0.56 |
| Cisco AI BOM | 0.05 | 0.23 | 0.59 |
| agent-bom | 1.00 | 1.00 | 1.00 |
| AgentDiscover Scanner | 0.07 | 0.28 | 0.64 |
| SafeDep vet | 1.00 | 1.00 | 1.00 |
| agentguard | 1.00 | 1.00 | 1.00 |
| cdxgen (CycloneDX AI/MCP BOM) | 0.03 | 0.14 | 0.43 |
| Baseline: keyword grep | 0.04 | 0.17 | 0.49 |
| Baseline: manifest dependencies | 1.00 | 1.00 | 1.00 |

## Paired comparisons (exact McNemar, Holm-adjusted within each family)

**T1: generative-AI use (agent or llm vs none) — against Project Nexus ShadowScan**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| Baseline: keyword grep | 130 | 6 | 25 | 0.00088 | 0.007 |
| agent-bom | 130 | 16 | 25 | 0.21 | 1 |
| AgentDiscover Scanner | 130 | 29 | 20 | 0.25 | 1 |
| agentguard | 130 | 33 | 22 | 0.18 | 1 |
| Baseline: manifest dependencies | 130 | 18 | 20 | 0.87 | 1 |
| cdxgen (CycloneDX AI/MCP BOM) | 130 | 16 | 23 | 0.34 | 1 |
| Cisco AI BOM | 130 | 15 | 22 | 0.32 | 1 |
| SafeDep vet | 130 | 24 | 22 | 0.88 | 1 |

**T2: AI agents (agent vs llm or none) — against Project Nexus ShadowScan**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| agentguard | 130 | 4 | 31 | 3.5e-06 | 2.8e-05 |
| Baseline: keyword grep | 130 | 9 | 35 | 0.00011 | 0.00074 |
| Baseline: manifest dependencies | 130 | 5 | 24 | 0.00055 | 0.0033 |
| agent-bom | 130 | 12 | 35 | 0.0011 | 0.0054 |
| cdxgen (CycloneDX AI/MCP BOM) | 130 | 11 | 26 | 0.02 | 0.054 |
| Cisco AI BOM | 130 | 9 | 24 | 0.014 | 0.054 |
| SafeDep vet | 130 | 11 | 27 | 0.014 | 0.054 |
| AgentDiscover Scanner | 130 | 24 | 30 | 0.5 | 0.5 |

**T1: generative-AI use (agent or llm vs none) — against Baseline: keyword grep**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| agentguard | 130 | 39 | 9 | 1.5e-05 | 0.00012 |
| AgentDiscover Scanner | 130 | 38 | 10 | 6.2e-05 | 0.00043 |
| Project Nexus ShadowScan | 130 | 25 | 6 | 0.00088 | 0.0053 |
| SafeDep vet | 130 | 30 | 9 | 0.0011 | 0.0053 |
| Baseline: manifest dependencies | 130 | 26 | 9 | 0.006 | 0.024 |
| agent-bom | 130 | 20 | 10 | 0.099 | 0.11 |
| cdxgen (CycloneDX AI/MCP BOM) | 130 | 20 | 8 | 0.036 | 0.11 |
| Cisco AI BOM | 130 | 22 | 10 | 0.05 | 0.11 |

**T2: AI agents (agent vs llm or none) — against Baseline: keyword grep**

| Tool | n | Reference right, tool wrong | Tool right, reference wrong | p | p (Holm) |
|---|---|---|---|---|---|
| Project Nexus ShadowScan | 130 | 35 | 9 | 0.00011 | 0.00085 |
| AgentDiscover Scanner | 130 | 33 | 13 | 0.0045 | 0.032 |
| cdxgen (CycloneDX AI/MCP BOM) | 130 | 23 | 12 | 0.09 | 0.54 |
| Cisco AI BOM | 130 | 23 | 12 | 0.09 | 0.54 |
| SafeDep vet | 130 | 22 | 12 | 0.12 | 0.54 |
| Baseline: manifest dependencies | 130 | 18 | 11 | 0.26 | 0.79 |
| agent-bom | 130 | 17 | 14 | 0.72 | 1 |
| agentguard | 130 | 12 | 13 | 1 | 1 |

## Where tools find and miss AI (T1 detection rate, adjudicated labels)

### By stratum and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| gh-agents|agent | 22 | 17 | 19 | 20 | 19 | 19 | 16 | 22 | 22 | 19 |
| gh-agents|llm | 3 | 2 | 3 | 2 | 3 | 3 | 1 | 3 | 3 | 3 |
| gh-genai|agent | 7 | 5 | 5 | 6 | 5 | 5 | 3 | 7 | 7 | 7 |
| gh-genai|llm | 11 | 6 | 8 | 8 | 5 | 2 | 0 | 9 | 10 | 3 |
| gh-genai|none | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 1 | 2 | 0 |
| gh-general|agent | 3 | 1 | 3 | 2 | 1 | 3 | 2 | 3 | 3 | 1 |
| gh-general|assistant-only | 4 | 2 | 2 | 2 | 1 | 4 | 4 | 4 | 4 | 0 |
| gh-general|llm | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 |
| gh-general|none | 12 | 0 | 1 | 0 | 1 | 0 | 0 | 3 | 2 | 0 |
| gh-mcp|agent | 15 | 13 | 14 | 14 | 9 | 10 | 15 | 10 | 15 | 14 |
| gitlab-ai|agent | 8 | 8 | 6 | 7 | 4 | 5 | 6 | 5 | 8 | 6 |
| gitlab-ai|llm | 9 | 7 | 5 | 6 | 7 | 5 | 0 | 6 | 8 | 4 |
| gitlab-ai|none | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| gitlab-general|assistant-only | 4 | 3 | 2 | 0 | 0 | 3 | 4 | 4 | 3 | 0 |
| gitlab-general|llm | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |
| gitlab-general|none | 10 | 0 | 4 | 0 | 2 | 0 | 0 | 5 | 1 | 0 |
| npm-ai|agent | 12 | 7 | 11 | 8 | 5 | 9 | 10 | 12 | 12 | 9 |
| npm-ai|llm | 3 | 3 | 2 | 0 | 1 | 0 | 0 | 3 | 3 | 1 |
| npm-general|assistant-only | 2 | 2 | 1 | 1 | 0 | 1 | 2 | 2 | 1 | 0 |
| npm-general|none | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0 |

### Positives by evidence type

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 | 21 | 15 | 18 | 18 | 19 | 20 | 16 | 21 | 21 | 21 |
| A2 | 27 | 19 | 24 | 23 | 21 | 24 | 18 | 27 | 27 | 25 |
| A3 | 43 | 30 | 37 | 37 | 25 | 31 | 40 | 35 | 43 | 38 |
| A4 | 14 | 11 | 13 | 13 | 11 | 9 | 13 | 12 | 14 | 9 |
| A5 | 2 | 2 | 2 | 1 | 1 | 1 | 2 | 2 | 2 | 1 |
| A6 | 10 | 6 | 7 | 9 | 9 | 8 | 10 | 10 | 10 | 7 |
| L1 | 70 | 50 | 56 | 54 | 47 | 47 | 32 | 65 | 68 | 48 |
| L2 | 4 | 3 | 4 | 4 | 2 | 2 | 1 | 4 | 4 | 2 |
| L3 | 54 | 37 | 44 | 43 | 40 | 45 | 26 | 51 | 53 | 47 |

### False alarms on hard negatives by trait

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| agent-word | 8 | 1 | 5 | 0 | 1 | 2 | 3 | 5 | 3 | 0 |
| ai-names-as-data | 3 | 2 | 0 | 0 | 0 | 0 | 0 | 2 | 3 | 0 |
| ai-prose | 7 | 2 | 2 | 0 | 1 | 3 | 3 | 4 | 3 | 0 |
| chatbot | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 2 | 1 | 0 |
| mcp-acronym | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ml_only | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| non-generative-ml | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| product-name | 9 | 4 | 2 | 0 | 0 | 2 | 2 | 4 | 7 | 0 |
| prompt-word | 4 | 1 | 2 | 1 | 1 | 2 | 2 | 2 | 2 | 0 |
| provider-name | 4 | 4 | 0 | 0 | 0 | 1 | 1 | 2 | 4 | 0 |
| user-agent | 10 | 1 | 2 | 0 | 2 | 1 | 1 | 3 | 3 | 0 |

### By dominant language and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| C#|agent | 3 | 2 | 3 | 2 | 0 | 1 | 3 | 2 | 3 | 1 |
| C#|assistant-only | 2 | 1 | 1 | 2 | 0 | 2 | 2 | 2 | 2 | 0 |
| C#|llm | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| C#|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| C/C++|assistant-only | 1 | 0 | 1 | 0 | 0 | 1 | 1 | 1 | 1 | 0 |
| C/C++|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| Go|agent | 3 | 2 | 1 | 2 | 0 | 1 | 1 | 2 | 3 | 3 |
| Go|assistant-only | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 |
| Go|llm | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| Go|none | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| JavaScript|agent | 3 | 2 | 3 | 3 | 1 | 3 | 3 | 3 | 3 | 3 |
| JavaScript|assistant-only | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 |
| JavaScript|llm | 6 | 6 | 4 | 2 | 5 | 4 | 0 | 6 | 6 | 3 |
| JavaScript|none | 7 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| Java|agent | 1 | 0 | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| Java|llm | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |
| Java|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Kotlin|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| PHP|llm | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| PHP|none | 4 | 0 | 1 | 0 | 0 | 0 | 0 | 2 | 2 | 0 |
| Python|agent | 30 | 24 | 26 | 30 | 28 | 24 | 21 | 25 | 30 | 27 |
| Python|assistant-only | 1 | 1 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| Python|llm | 12 | 8 | 10 | 12 | 9 | 4 | 0 | 11 | 11 | 4 |
| Python|none | 5 | 1 | 2 | 0 | 3 | 0 | 0 | 3 | 1 | 0 |
| Ruby|assistant-only | 1 | 0 | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 0 |
| Ruby|none | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Rust|agent | 2 | 2 | 2 | 2 | 0 | 2 | 2 | 2 | 2 | 2 |
| Rust|assistant-only | 1 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 1 | 0 |
| Rust|llm | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 1 | 0 |
| Rust|none | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| Shell|agent | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| Shell|none | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| TypeScript|agent | 24 | 18 | 21 | 17 | 12 | 18 | 20 | 23 | 24 | 19 |
| TypeScript|assistant-only | 2 | 2 | 1 | 1 | 0 | 1 | 2 | 2 | 1 | 0 |
| TypeScript|llm | 4 | 3 | 4 | 2 | 2 | 2 | 1 | 4 | 4 | 3 |
| TypeScript|none | 7 | 1 | 2 | 0 | 0 | 0 | 0 | 2 | 3 | 0 |

### By size tercile and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| large|agent | 35 | 21 | 31 | 30 | 24 | 29 | 32 | 34 | 35 | 28 |
| large|assistant-only | 2 | 0 | 2 | 1 | 0 | 2 | 2 | 2 | 2 | 0 |
| large|llm | 5 | 2 | 4 | 4 | 4 | 4 | 1 | 5 | 4 | 2 |
| large|none | 4 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 2 | 0 |
| medium|agent | 13 | 12 | 11 | 10 | 9 | 9 | 6 | 13 | 13 | 11 |
| medium|assistant-only | 7 | 6 | 2 | 1 | 1 | 6 | 7 | 7 | 6 | 0 |
| medium|llm | 8 | 6 | 6 | 5 | 3 | 3 | 1 | 7 | 8 | 3 |
| medium|none | 18 | 2 | 4 | 0 | 1 | 0 | 0 | 6 | 6 | 0 |
| small|agent | 19 | 18 | 16 | 17 | 10 | 13 | 14 | 12 | 19 | 17 |
| small|assistant-only | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 0 |
| small|llm | 15 | 11 | 9 | 8 | 9 | 5 | 0 | 11 | 14 | 6 |
| small|none | 13 | 1 | 1 | 0 | 1 | 0 | 0 | 3 | 1 | 0 |

### By host and label

| Group | n | Project Nexus ShadowScan | Cisco AI BOM | agent-bom | AgentDiscover Scanner | SafeDep vet | agentguard | cdxgen (CycloneDX AI/MCP BOM) | Baseline: keyword grep | Baseline: manifest dependencies |
|---|---|---|---|---|---|---|---|---|---|---|
| github|agent | 59 | 43 | 52 | 50 | 39 | 46 | 46 | 54 | 59 | 50 |
| github|assistant-only | 6 | 4 | 3 | 3 | 1 | 5 | 6 | 6 | 5 | 0 |
| github|llm | 18 | 12 | 14 | 11 | 9 | 6 | 2 | 16 | 17 | 7 |
| github|none | 22 | 2 | 1 | 0 | 1 | 0 | 0 | 4 | 7 | 0 |
| gitlab|agent | 8 | 8 | 6 | 7 | 4 | 5 | 6 | 5 | 8 | 6 |
| gitlab|assistant-only | 4 | 3 | 2 | 0 | 0 | 3 | 4 | 4 | 3 | 0 |
| gitlab|llm | 10 | 7 | 5 | 6 | 7 | 6 | 0 | 7 | 9 | 4 |
| gitlab|none | 13 | 1 | 4 | 0 | 2 | 0 | 0 | 6 | 2 | 0 |

## Localisation

| Tool | True positives | Cites an evidence file | TPs citing no file | Cited-file precision |
|---|---|---|---|---|
| Project Nexus ShadowScan | 70 | 0.97 (0.90–0.99) | 0 | – |
| Cisco AI BOM | 77 | 0.71 (0.61–0.80) | 0 | – |
| agent-bom | 74 | 0.74 (0.63–0.83) | 0 | – |
| AgentDiscover Scanner | 59 | 0.61 (0.48–0.72) | 4 | – |
| SafeDep vet | 63 | 0.70 (0.58–0.80) | 0 | – |
| agentguard | 54 | 0.15 (0.08–0.27) | 5 | – |
| cdxgen (CycloneDX AI/MCP BOM) | 82 | 0.21 (0.13–0.31) | 39 | – |
| Baseline: keyword grep | 93 | 0.86 (0.78–0.92) | 0 | – |
| Baseline: manifest dependencies | 67 | 0.81 (0.70–0.88) | 0 | – |

## Run status, time and determinism

| Tool | ok | partial | error | Median s | p90 s | Repeat runs | Verdict flips |
|---|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 114 | 26 | 0 | 2.3 | 25.7 | 14 | 0 |
| Cisco AI BOM | 136 | 0 | 4 | 57.1 | 177.8 | 14 | 0 |
| agent-bom | 140 | 0 | 0 | 4.5 | 38.0 | 14 | 0 |
| AgentDiscover Scanner | 139 | 0 | 1 | 3.0 | 9.6 | 14 | 0 |
| SafeDep vet | 139 | 0 | 1 | 3.8 | 201.1 | 14 | 0 |
| agentguard | 140 | 0 | 0 | 0.8 | 17.1 | 14 | 0 |
| cdxgen (CycloneDX AI/MCP BOM) | 140 | 0 | 0 | 3.2 | 18.6 | 14 | 0 |
| Baseline: keyword grep | 140 | 0 | 0 | 0.1 | 0.3 | 14 | 0 |
| Baseline: manifest dependencies | 140 | 0 | 0 | 0.1 | 1.4 | 14 | 0 |

