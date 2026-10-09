# Real-world repository benchmark results

> **Stale: measured on the original experimental branch, before merge review
> restored fail-closed input defects (exit 3), narrowed the crawler
> user-agent discount and returned plain `.js` files to the ambiguity-only
> JSX retry.** These figures do not describe the merged code; the recoveries
> credited to input defects do not hold. See [README.md](README.md).

Repo surface only; every case is a public repository pinned by commit (see `benchmarks/realworld/corpus.json`). Positive means the label is `agent` or `llm`. An error (an incomplete or failed scan) on a positive repository counts as a miss. The shared scorer counts an error on a `none` repository as a true negative, so specificity and precision in the scored tables overstate tools that error on negatives; the section on errors on `none` repositories gives specificity over completed scans only. Read the caveats in `benchmarks/realworld/README.md` before quoting numbers.

- Corpus: `corpus.json` sha256 `6469bdee66c83338…`, 34 repositories
- Runtime: Python 3.13.16, Linux-6.18.44-fc-v80-x86_64-with-glibc2.39, 900s timeout per tool per repository

## Detection (any AI/agent evidence vs the repository label)

| Tool | n | Err | Recall | Specificity | Precision | F1 (95% CI) | Bal. acc | MCC | Median s |
|---|---|---|---|---|---|---|---|---|---|
| Project Nexus ShadowScan | 34 | 13 | 0.64 (0.45–0.80) | 1.00 (0.70–1.00) | 1.00 (0.81–1.00) | 0.78 (0.62–0.90) | 0.82 | 0.57 | 2.945 |
| ShadowScan (max_file_size 20 MiB) | 34 | 7 | 0.76 (0.57–0.89) | 0.89 (0.57–0.98) | 0.95 (0.76–0.99) | 0.84 (0.72–0.94) | 0.82 | 0.58 | 3.691 |

## Agent tier (tools whose output separates agent evidence from plain usage)

| Tool | Agent recall | False alarm on non-agent repos |
|---|---|---|
| Project Nexus ShadowScan | 0.69 (0.42–0.87) | 0.12 (0.02–0.47) |
| ShadowScan (max_file_size 20 MiB) | 0.75 (0.51–0.90) | 0.09 (0.02–0.38) |

## Per-family detection (detected/total)

| Family (label) | Project Nexus ShadowScan | ShadowScan (max_file_size 20 MiB) |
|---|---|---|
| a2a (agent) | 1/1 | 1/1 |
| app-agent-engine (agent) | 0/1 | 0/1 |
| app-assistants (agent) | 2/2 | 2/2 |
| app-crewai (agent) | 0/1 | 1/1 |
| app-functionz (agent) | 1/1 | 1/1 |
| app-mixed (agent) | 1/1 | 1/1 |
| app-researcher (agent) | 0/1 | 1/1 |
| app-swarm (agent) | 1/1 | 1/1 |
| app-vercel-ai (agent) | 1/1 | 1/1 |
| coding-agent-config (agent) | 1/1 | 1/1 |
| framework-source-ts (agent) | 0/1 | 0/1 |
| framework-source (agent) | 3/5 | 4/5 |
| iac-bedrock (agent) | 1/1 | 1/1 |
| mcp-client-gitlab (agent) | 0/1 | 0/1 |
| mcp-server-source (agent) | 1/1 | 1/1 |
| sdk-source (agent) | 0/2 | 0/2 |
| app-chat-ext (llm) | 1/1 | 1/1 |
| app-chat (llm) | 1/1 | 1/1 |
| lowcode-n8n (llm) | 1/1 | 1/1 |
| catalog (none) | 0/2 | 0/2 |
| clean-js (none) | 0/1 | 0/1 |
| clean-python-gitlab (none) | 0/1 | 0/1 |
| clean-python (none) | 0/1 | 0/1 |
| lookalike-agent (none) | 0/1 | 0/1 |
| lookalike-bedrock (none) | 0/1 | 0/1 |
| lookalike-strings (none) | 0/1 | 0/1 |
| ml-not-llm (none) | 0/1 | 1/1 |

## Per-repository outcomes

`**A**` detected with agent-tier evidence, `✓` detected, `·` nothing reported, `E` error.

| Repository | Label | Project Nexus ShadowScan | ShadowScan (max_file_size 20 MiB) |
|---|---|---|---|
| a2a-samples | agent | **A** | **A** |
| ai-chatbot | agent | **A** | **A** |
| anthropic-quickstarts | agent | **A** | **A** |
| anthropic-sdk-python | agent | E | E |
| autogen | agent | **A** | **A** |
| babyagi | agent | **A** | **A** |
| chatbot-ui | agent | ✓ | ✓ |
| crewai-examples | agent | E | **A** |
| gitlab-lsp | agent | E | E |
| gpt-researcher | agent | E | **A** |
| langgraph | agent | **A** | **A** |
| mastra | agent | E | E |
| mcp-servers | agent | **A** | **A** |
| openai-agents-python | agent | E | **A** |
| openai-python | agent | E | E |
| openai-quickstart-python | agent | ✓ | ✓ |
| private-gpt | agent | E | E |
| pydantic-ai | agent | E | E |
| smolagents | agent | **A** | **A** |
| swarm | agent | ✓ | ✓ |
| terraform-aws-bedrock | agent | ✓ | ✓ |
| wshobson-agents | agent | **A** | **A** |
| chatgpt-google-ext | llm | ✓ | ✓ |
| chatgpt-web | llm | ✓ | ✓ |
| n8n-ai-starter | llm | **A** | **A** |
| awesome-ai-agents | none | · | · |
| awesome-mcp-servers | none | E | · |
| click | none | · | · |
| express | none | · | · |
| fdroidserver | none | E | E |
| nginx-agent | none | · | · |
| nukkit | none | E | · |
| pytorch-examples | none | E | ✓ |
| ua-parser-js | none | · | · |

## Paired against ShadowScan (exact McNemar, repo surface)

| Tool | n | ShadowScan right, tool wrong | Tool right, ShadowScan wrong | p |
|---|---|---|---|---|
| ShadowScan (max_file_size 20 MiB) | 34 | 1 | 3 | 0.6250 |

## Errors

An error on an `agent` or `llm` repository is counted as a miss above; one on a
`none` repository is counted as a true negative there (see the next section).

- Project Nexus ShadowScan on `crewai-examples`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `gpt-researcher`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `openai-agents-python`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `pydantic-ai`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `mastra`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `private-gpt`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `anthropic-sdk-python`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `openai-python`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `gitlab-lsp`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `nukkit`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `pytorch-examples`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `awesome-mcp-servers`: incomplete scan (exit 3)
- Project Nexus ShadowScan on `fdroidserver`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `pydantic-ai`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `mastra`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `private-gpt`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `anthropic-sdk-python`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `openai-python`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `gitlab-lsp`: incomplete scan (exit 3)
- ShadowScan (max_file_size 20 MiB) on `fdroidserver`: incomplete scan (exit 3)

## Errors on repositories with no AI (`none` label)

| Tool | Errored `none` scans | Specificity over completed `none` scans |
|---|---|---|
| Project Nexus ShadowScan | 4/9 | 5/5 |
| ShadowScan (max_file_size 20 MiB) | 1/9 | 7/8 |

## Noise on repositories with no AI (`none` label)

| Tool | Repos flagged | Median items reported on flagged `none` repos |
|---|---|---|
| Project Nexus ShadowScan | 0/5 | 0 |
| ShadowScan (max_file_size 20 MiB) | 1/8 | 1 |

Highest F1 on this corpus: ShadowScan (max_file_size 20 MiB) (0.84). See the caveats before treating that as a ranking.
