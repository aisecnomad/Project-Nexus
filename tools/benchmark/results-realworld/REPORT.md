# Real-world repository benchmark results

Repo surface only; every case is a public repository pinned by commit (see `benchmarks/realworld/corpus.json`). Positive means the label is `agent` or `llm`. Errors count as misses and are also shown. Read the caveats in `benchmarks/realworld/README.md` before quoting numbers.

- Corpus: `corpus.json` sha256 `6469bdee66c83338…`, 34 repositories
- Runtime: Python 3.13.16, Linux-6.18.44-fc-v80-x86_64-with-glibc2.39, 900s timeout per tool per repository

## Detection (any AI/agent evidence vs the repository label)

| Tool | n | Err | Recall | Specificity | Precision | F1 (95% CI) | Bal. acc | MCC | Median s |
|---|---|---|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 34 | 15 | 0.56 (0.37–0.73) | 0.89 (0.57–0.98) | 0.93 (0.70–0.99) | 0.70 (0.52–0.84) | 0.72 | 0.40 | 2.773 |
| ShadowScan (max_file_size 20 MiB) | 34 | 12 | 0.64 (0.45–0.80) | 0.89 (0.57–0.98) | 0.94 (0.73–0.99) | 0.76 (0.60–0.89) | 0.76 | 0.47 | 3.426 |
| Cisco AI BOM | 34 | 4 | 0.84 (0.65–0.94) | 0.67 (0.35–0.88) | 0.88 (0.69–0.96) | 0.86 (0.73–0.94) | 0.75 | 0.49 | 79.308 |
| agent-bom | 34 | 0 | 0.92 (0.75–0.98) | 0.22 (0.06–0.55) | 0.77 (0.59–0.88) | 0.84 (0.71–0.93) | 0.57 | 0.19 | 10.204 |
| AgentDiscover Scanner | 34 | 0 | 0.76 (0.57–0.89) | 0.67 (0.35–0.88) | 0.86 (0.67–0.95) | 0.81 (0.67–0.91) | 0.71 | 0.39 | 3.916 |
| Agentic Radar (SplxAI) | 34 | 1 | 0.20 (0.09–0.39) | 1.00 (0.70–1.00) | 1.00 (0.57–1.00) | 0.33 (0.09–0.56) | 0.60 | 0.25 | 12.387 |
| SafeDep vet (code scan) | 34 | 1 | 0.72 (0.52–0.86) | 1.00 (0.70–1.00) | 1.00 (0.82–1.00) | 0.84 (0.69–0.94) | 0.86 | 0.64 | 12.191 |
| Naive grep baseline | 34 | 0 | 1.00 (0.87–1.00) | 0.78 (0.45–0.94) | 0.93 (0.77–0.98) | 0.96 (0.89–1.00) | 0.89 | 0.85 | 4.171 |

## Agent tier (tools whose output separates agent evidence from plain usage)

| Tool | Agent recall | False alarm on non-agent repos |
|---|---|---|
| Project Nexus ShadowScan | 0.64 (0.35–0.85) | 0.12 (0.02–0.47) |
| ShadowScan (max_file_size 20 MiB) | 0.69 (0.42–0.87) | 0.11 (0.02–0.43) |
| Cisco AI BOM | 0.72 (0.49–0.88) | 0.08 (0.01–0.35) |
| agent-bom | 0.73 (0.52–0.87) | 0.08 (0.01–0.35) |
| AgentDiscover Scanner | 0.82 (0.61–0.93) | 0.25 (0.09–0.53) |
| Agentic Radar (SplxAI) | 0.24 (0.11–0.45) | 0.00 (0.00–0.24) |
| SafeDep vet (code scan) | 0.71 (0.50–0.86) | 0.00 (0.00–0.24) |
| Naive grep baseline | 0.86 (0.67–0.95) | 0.17 (0.05–0.45) |

## Per-family detection (detected/total)

| Family (label) | Project Nexus ShadowScan | ShadowScan (max_file_size 20 MiB) | Cisco AI BOM | agent-bom | AgentDiscover Scanner | Agentic Radar (SplxAI) | SafeDep vet (code scan) | Naive grep baseline |
|---|---|---|---|---|---|---|---|---|
| a2a (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| app-agent-engine (agent) | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 |
| app-assistants (agent) | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 0/2 | 1/2 | 2/2 |
| app-crewai (agent) | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| app-functionz (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| app-mixed (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| app-researcher (agent) | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 |
| app-swarm (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| app-vercel-ai (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| coding-agent-config (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 |
| framework-source-ts (agent) | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| framework-source (agent) | 1/5 | 2/5 | 2/5 | 5/5 | 5/5 | 1/5 | 5/5 | 5/5 |
| iac-bedrock (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| mcp-client-gitlab (agent) | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 |
| mcp-server-source (agent) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 |
| sdk-source (agent) | 0/2 | 0/2 | 1/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 |
| app-chat-ext (llm) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| app-chat (llm) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| lowcode-n8n (llm) | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| catalog (none) | 0/2 | 0/2 | 0/2 | 1/2 | 1/2 | 0/2 | 0/2 | 2/2 |
| clean-js (none) | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| clean-python-gitlab (none) | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| clean-python (none) | 0/1 | 0/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| lookalike-agent (none) | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| lookalike-bedrock (none) | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| lookalike-strings (none) | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| ml-not-llm (none) | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |

## Per-repository outcomes

`**A**` detected with agent-tier evidence, `✓` detected, `·` nothing reported, `E` error.

| Repository | Label | Project Nexus ShadowScan | ShadowScan (max_file_size 20 MiB) | Cisco AI BOM | agent-bom | AgentDiscover Scanner | Agentic Radar (SplxAI) | SafeDep vet (code scan) | Naive grep baseline |
|---|---|---|---|---|---|---|---|---|---|
| a2a-samples | agent | **A** | **A** | **A** | **A** | **A** | **A** | **A** | **A** |
| ai-chatbot | agent | **A** | **A** | ✓ | ✓ | · | · | **A** | **A** |
| anthropic-quickstarts | agent | **A** | **A** | **A** | **A** | **A** | **A** | **A** | **A** |
| anthropic-sdk-python | agent | E | E | **A** | ✓ | **A** | · | **A** | **A** |
| autogen | agent | E | E | **A** | **A** | **A** | E | **A** | **A** |
| babyagi | agent | **A** | **A** | ✓ | ✓ | **A** | · | · | ✓ |
| chatbot-ui | agent | ✓ | ✓ | ✓ | · | · | · | · | ✓ |
| crewai-examples | agent | E | **A** | **A** | **A** | **A** | **A** | **A** | **A** |
| gitlab-lsp | agent | E | E | **A** | **A** | **A** | · | **A** | **A** |
| gpt-researcher | agent | E | E | **A** | **A** | **A** | · | **A** | **A** |
| langgraph | agent | E | E | E | **A** | **A** | · | **A** | **A** |
| mastra | agent | E | E | **A** | **A** | **A** | · | E | **A** |
| mcp-servers | agent | **A** | **A** | **A** | **A** | **A** | · | **A** | **A** |
| openai-agents-python | agent | E | **A** | E | **A** | **A** | · | **A** | **A** |
| openai-python | agent | E | E | E | **A** | **A** | · | ✓ | **A** |
| openai-quickstart-python | agent | ✓ | ✓ | ✓ | ✓ | **A** | · | ✓ | ✓ |
| private-gpt | agent | E | E | **A** | **A** | **A** | · | **A** | **A** |
| pydantic-ai | agent | E | E | E | **A** | **A** | **A** | **A** | **A** |
| smolagents | agent | **A** | **A** | **A** | **A** | **A** | · | **A** | **A** |
| swarm | agent | ✓ | ✓ | **A** | ✓ | **A** | **A** | ✓ | **A** |
| terraform-aws-bedrock | agent | ✓ | ✓ | ✓ | **A** | · | · | · | **A** |
| wshobson-agents | agent | **A** | **A** | **A** | **A** | ✓ | · | **A** | **A** |
| chatgpt-google-ext | llm | ✓ | ✓ | ✓ | ✓ | · | · | · | ✓ |
| chatgpt-web | llm | ✓ | ✓ | ✓ | ✓ | · | · | · | ✓ |
| n8n-ai-starter | llm | **A** | **A** | **A** | · | · | · | · | ✓ |
| awesome-ai-agents | none | · | · | · | · | · | · | · | **A** |
| awesome-mcp-servers | none | E | E | · | **A** | **A** | · | · | **A** |
| click | none | · | · | · | ✓ | · | · | · | · |
| express | none | · | · | · | ✓ | · | · | · | · |
| fdroidserver | none | E | E | · | · | **A** | · | · | · |
| nginx-agent | none | · | · | ✓ | ✓ | · | · | · | · |
| nukkit | none | E | · | ✓ | ✓ | · | · | · | · |
| pytorch-examples | none | E | E | ✓ | ✓ | **A** | · | · | · |
| ua-parser-js | none | ✓ | ✓ | · | ✓ | · | · | · | · |

## Paired against ShadowScan (exact McNemar, repo surface)

| Tool | n | ShadowScan right, tool wrong | Tool right, ShadowScan wrong | p |
|---|---|---|---|---|
| ShadowScan (max_file_size 20 MiB) | 34 | 0 | 2 | 0.5000 |
| Cisco AI BOM | 34 | 3 | 8 | 0.2266 |
| agent-bom | 34 | 8 | 11 | 0.6476 |
| AgentDiscover Scanner | 34 | 9 | 12 | 0.6636 |
| Agentic Radar (SplxAI) | 34 | 11 | 3 | 0.0574 |
| SafeDep vet (code scan) | 34 | 6 | 11 | 0.3323 |
| Naive grep baseline | 34 | 2 | 12 | 0.0129 |

## Errors (counted as misses above)

- Project Nexus ShadowScan on `crewai-examples`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `gpt-researcher`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `openai-agents-python`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `pydantic-ai`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `autogen`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `langgraph`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `mastra`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `private-gpt`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `anthropic-sdk-python`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `openai-python`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `gitlab-lsp`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `nukkit`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `pytorch-examples`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `awesome-mcp-servers`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `fdroidserver`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `gpt-researcher`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `pydantic-ai`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `autogen`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `langgraph`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `mastra`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `private-gpt`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `anthropic-sdk-python`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `openai-python`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `gitlab-lsp`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `pytorch-examples`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `awesome-mcp-servers`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `fdroidserver`: incomplete scan (exit 3)
- Cisco AI BOM on `openai-agents-python`: exit 124: timeout after 900s
- Cisco AI BOM on `pydantic-ai`: exit 124: timeout after 900s
- Cisco AI BOM on `langgraph`: exit 124: timeout after 900s
- Cisco AI BOM on `openai-python`: exit 124: timeout after 900s
- Agentic Radar (SplxAI) on `autogen`: crewai: exit 1: ────────────────────────────────────────────────────────────╯ | AttributeError: 'Attribute' object has no attribute 'id'; langgraph: exit 1: ───────────────────╯ | UnboundLocalError: c
- SafeDep vet (code scan) on `mastra`: exit 124: timeout after 900s

## Noise on repositories with no AI (`none` label)

| Tool | Repos flagged | Median items reported on flagged `none` repos |
|---|---|---|
| Project Nexus ShadowScan | 1/5 | 1 |
| ShadowScan (max_file_size 20 MiB) | 1/6 | 1 |
| Cisco AI BOM | 3/9 | 2 |
| agent-bom | 7/9 | 1 |
| AgentDiscover Scanner | 3/9 | 4 |
| Agentic Radar (SplxAI) | 0/9 | 0 |
| SafeDep vet (code scan) | 0/9 | 0 |
| Naive grep baseline | 2/9 | 1 |

Highest F1 on this corpus: Naive grep baseline (0.96). See the caveats before treating that as a ranking.
