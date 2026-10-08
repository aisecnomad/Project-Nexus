# Shadow-AI discovery on real repositories: results

Corpus: 91 public repositories pinned to commits (corpus SHA-256 `12d8cf8157ec9507d459562f5101ba134bbfe6a999e9690ba712862b7199065c`). Python 3.13.16 on Linux-6.18.44-fc-v80-x86_64-with-glibc2.39. Per-tool timeout 900 s.

**Labels were written by the author of this harness, with evidence paths, and were not independently reviewed.** The corpus is a stratified selection, not a random sample of repositories, so these rates do not estimate field precision or recall. Intervals are 95% Wilson (proportions) or bootstrap (F1). See the README for the per-tool run modes and limits.

## Corpus composition

| Stratum | Label | Repositories |
|---|---|---|
| app | agent | 30 |
| framework-source | agent | 19 |
| config-only | agent | 13 |
| llm-only | llm | 2 |
| name-collision | none | 9 |
| ml-not-agent | none | 3 |
| docs-only | none | 5 |
| plain | none | 10 |

Languages (a repository can count more than once): python 39, typescript 24, go 19, notebook 10, csharp 7, markdown 6, rust 5, java 4, json 4, yaml 3, javascript 3, kotlin 2, xml 2, bicep 1, ruby 1, hcl 1, apex 1, elixir 1, cpp 1, c 1.

## Repository detection

| Tool | n | TP | FP | FN | TN | Errors | Recall | Specificity | Precision | F1 | MCC | Agent recall | Median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Keyword grep (control) | 91 | 64 | 14 | 0 | 13 | 0 | 1.00 (0.94–1.00) | 0.48 (0.31–0.66) | 0.82 (0.72–0.89) | 0.90 (0.85–0.95) | 0.63 | 0.94 (0.85–0.97) | 1.1 |
| Cisco AI BOM | 91 | 58 | 10 | 6 | 17 | 5 | 0.91 (0.81–0.96) | 0.63 (0.44–0.78) | 0.85 (0.75–0.92) | 0.88 (0.81–0.93) | 0.56 | 0.75 (0.63–0.85) | 73.7 |
| Project Nexus ShadowScan | 91 | 29 | 1 | 35 | 26 | 47 | 0.45 (0.34–0.57) | 0.96 (0.82–0.99) | 0.97 (0.83–0.99) | 0.62 (0.49–0.72) | 0.40 | 0.81 (0.63–0.92) | 2.7 |
| Cisco Skill Scanner | 91 | 25 | 0 | 39 | 27 | 0 | 0.39 (0.28–0.51) | 1.00 (0.88–1.00) | 1.00 (0.87–1.00) | 0.56 (0.44–0.68) | 0.40 | 0.40 (0.29–0.53) | 6.7 |
| agent-bom | 91 | 34 | 3 | 30 | 24 | 1 | 0.53 (0.41–0.65) | 0.89 (0.72–0.96) | 0.92 (0.79–0.97) | 0.67 (0.56–0.78) | 0.39 | 0.27 (0.18–0.40) | 7.2 |
| OWASP cdxgen (AI inventory) | 91 | 59 | 17 | 5 | 10 | 0 | 0.92 (0.83–0.97) | 0.37 (0.22–0.56) | 0.78 (0.67–0.86) | 0.84 (0.77–0.90) | 0.36 | 0.81 (0.69–0.89) | 1.7 |
| AgentDiscover Scanner | 91 | 38 | 7 | 26 | 20 | 0 | 0.59 (0.47–0.71) | 0.74 (0.55–0.87) | 0.84 (0.71–0.92) | 0.70 (0.59–0.79) | 0.31 | 0.58 (0.46–0.70) | 2.3 |
| Agentic Radar (SPLX) | 91 | 12 | 0 | 52 | 27 | 44 | 0.19 (0.11–0.30) | 1.00 (0.88–1.00) | 1.00 (0.76–1.00) | 0.32 (0.17–0.45) | 0.25 | 0.43 (0.27–0.61) | 5.4 |

## Detection by stratum

Positives: higher is better. `none` strata: lower is better.

| Stratum | Label | Keyword grep (control) | Cisco AI BOM | Project Nexus ShadowScan | Cisco Skill Scanner | agent-bom | OWASP cdxgen (AI inventory) | AgentDiscover Scanner | Agentic Radar (SPLX) |
|---|---|---|---|---|---|---|---|---|---|
| app | agent | 30/30 | 28/30 | 13/30 | 15/30 | 19/30 | 29/30 | 18/30 | 8/30 |
| framework-source | agent | 19/19 | 16/19 | 6/19 | 7/19 | 11/19 | 18/19 | 15/19 | 3/19 |
| config-only | agent | 13/13 | 12/13 | 8/13 | 3/13 | 4/13 | 11/13 | 5/13 | 1/13 |
| llm-only | llm | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 1/2 | 0/2 | 0/2 |
| name-collision | none | 7/9 | 4/9 | 0/9 | 0/9 | 0/9 | 8/9 | 1/9 | 0/9 |
| ml-not-agent | none | 2/3 | 3/3 | 0/3 | 0/3 | 3/3 | 3/3 | 2/3 | 0/3 |
| docs-only | none | 4/5 | 0/5 | 1/5 | 0/5 | 0/5 | 1/5 | 3/5 | 0/5 |
| plain | none | 1/10 | 3/10 | 0/10 | 0/10 | 0/10 | 5/10 | 1/10 | 0/10 |

## Evidence coverage (secondary)

For each evidence type a tool's adapter can map, the share of repositories labeled with that evidence on which the tool reported at least one item of that type, and how many repositories without that label received such a report. A tool is not scored on types it cannot express.

| Evidence type | Labeled | Keyword grep (control) | Cisco AI BOM | Project Nexus ShadowScan | Cisco Skill Scanner | agent-bom | OWASP cdxgen (AI inventory) | AgentDiscover Scanner | Agentic Radar (SPLX) |
|---|---|---|---|---|---|---|---|---|---|
| framework | 42 | 35/42 (+21 unlabeled) | 18/42 (+3 unlabeled) | 16/42 (+3 unlabeled) | – | – | – | 27/42 (+10 unlabeled) | 11/42 (+1 unlabeled) |
| provider | 52 | 52/52 (+20 unlabeled) | 45/52 (+8 unlabeled) | 20/52 (+4 unlabeled) | – | – | 41/52 (+6 unlabeled) | – | – |
| mcp-code | 32 | 32/32 (+21 unlabeled) | 15/32 (+3 unlabeled) | 10/32 (+0 unlabeled) | – | – | – | 5/32 (+4 unlabeled) | 0/32 (+0 unlabeled) |
| mcp-config | 8 | 4/8 (+0 unlabeled) | 2/8 (+9 unlabeled) | 3/8 (+2 unlabeled) | – | – | 0/8 (+0 unlabeled) | – | – |
| coding-agent-config | 36 | 34/36 (+0 unlabeled) | – | 13/36 (+0 unlabeled) | – | – | 34/36 (+33 unlabeled) | – | – |
| agent-skill | 25 | 25/25 (+0 unlabeled) | 13/25 (+11 unlabeled) | 6/25 (+0 unlabeled) | 25/25 (+0 unlabeled) | – | 0/25 (+0 unlabeled) | – | – |
| a2a-card | 2 | – | – | 1/2 (+0 unlabeled) | – | – | – | – | – |
| lowcode-flow | 6 | – | – | 3/6 (+0 unlabeled) | – | – | – | – | – |
| iac | 7 | – | – | 2/7 (+4 unlabeled) | – | – | – | – | – |
| credential | 5 | – | – | 1/5 (+13 unlabeled) | – | – | – | – | – |
| local-model | 0 | – | – | 0/0 (+0 unlabeled) | – | – | 0/0 (+1 unlabeled) | – | – |

## Paired comparison with ShadowScan (exact McNemar on correct/incorrect)

| Tool | n | ShadowScan right, other wrong | Other right, ShadowScan wrong | p |
|---|---|---|---|---|
| Keyword grep (control) | 91 | 13 | 35 | 0.0021 |
| Cisco AI BOM | 91 | 11 | 31 | 0.0029 |
| Cisco Skill Scanner | 91 | 23 | 20 | 0.76 |
| agent-bom | 91 | 19 | 22 | 0.76 |
| OWASP cdxgen (AI inventory) | 91 | 22 | 36 | 0.087 |
| AgentDiscover Scanner | 91 | 21 | 24 | 0.77 |
| Agentic Radar (SPLX) | 91 | 23 | 7 | 0.0052 |

## Supplementary (post hoc): ShadowScan incomplete scans

47 ShadowScan scans ended incomplete (exit 3) and count as errors under the pre-registered rule, as ShadowScan's own fail-closed contract requires. The rows below re-read the stored reports: first counting an incomplete scan with findings as a detection, then also ignoring reports whose only findings are provider-key-shaped strings. Neither rule was pre-registered.

| Rule | Recall | Specificity | F1 | MCC |
|---|---|---|---|---|
| pre-registered | 0.45 (0.34–0.57) | 0.96 (0.82–0.99) | 0.62 | 0.40 |
| incomplete with findings = detected | 1.00 (0.94–1.00) | 0.89 (0.72–0.96) | 0.98 | 0.92 |
| as above, ignoring reports whose only findings are secrets | 1.00 (0.94–1.00) | 0.96 (0.82–0.99) | 0.99 | 0.97 |

Why the scans were incomplete (a scan can have several reasons):

| Reason | Scans |
|---|---|
| text file over max_file_size | 21 |
| source lexical analysis incomplete | 17 |
| structured configuration parsing | 13 |
| import-bound analysis incomplete | 12 |
| symbolic link with unavailable target | 11 |
| other | 6 |
| binary content in an analyzable path | 5 |
| missing submodule checkout | 4 |
| malformed MCP configuration | 3 |
| unreadable A2A agent card | 1 |

## Per-repository results

✓ detected, · not detected, ✗ error (crash, timeout or incomplete scan), – not applicable.

| Repository | Stratum | Label | Keyword grep (control) | Cisco AI BOM | Project Nexus ShadowScan | Cisco Skill Scanner | agent-bom | OWASP cdxgen (AI inventory) | AgentDiscover Scanner | Agentic Radar (SPLX) |
|---|---|---|---|---|---|---|---|---|---|---|
| [a2aproject/a2a-samples](https://github.com/a2aproject/a2a-samples/tree/6603ba3f2c31) | app | agent | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [google/adk-samples](https://github.com/google/adk-samples/tree/c339821da836) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [Aider-AI/aider](https://github.com/Aider-AI/aider/tree/5dc9490bb35f) | app | agent | ✓ | ✓ | ✗ | · | ✓ | ✓ | ✓ | ✗ |
| [awslabs/amazon-bedrock-agent-samples](https://github.com/awslabs/amazon-bedrock-agent-samples/tree/3e55140baa52) | app | agent | ✓ | ✓ | ✗ | · | ✓ | ✓ | ✓ | ✗ |
| [anthropics/anthropic-cookbook](https://github.com/anthropics/anthropic-cookbook/tree/d7265d6ae994) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [anthropics/anthropic-quickstarts](https://github.com/anthropics/anthropic-quickstarts/tree/9ec32b91df50) | app | agent | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [f/awesome-chatgpt-prompts](https://github.com/f/awesome-chatgpt-prompts/tree/7d3f248962d1) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | · | ✗ |
| [Azure-Samples/azure-search-openai-demo-csharp](https://github.com/Azure-Samples/azure-search-openai-demo-csharp/tree/7d702a68d37f) | app | agent | ✓ | ✓ | ✓ | · | · | ✓ | · | ✗ |
| [mckaywrigley/chatbot-ui](https://github.com/mckaywrigley/chatbot-ui/tree/81328b61d2a4) | app | agent | ✓ | ✓ | ✓ | · | · | ✓ | · | · |
| [anthropics/claude-agent-sdk-demos](https://github.com/anthropics/claude-agent-sdk-demos/tree/826b268506a5) | app | agent | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · |
| [microsoft/CopilotStudioSamples](https://github.com/microsoft/CopilotStudioSamples/tree/6ee7fd5d9fa9) | app | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | ✗ |
| [crewAIInc/crewAI-examples](https://github.com/crewAIInc/crewAI-examples/tree/da94a91e691e) | app | agent | ✓ | ✓ | ✗ | · | ✓ | ✓ | ✓ | ✓ |
| [gitlab-org/duo-workflow/duo-workflow-service](https://gitlab.com/gitlab-org/duo-workflow/duo-workflow-service/tree/1d3f108b3c54) | app | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ |
| [cloudwego/eino-examples](https://github.com/cloudwego/eino-examples/tree/a6dbd95ab51f) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | · | · |
| [gitlab-org/modelops/applied-ml/code-suggestions/ai-assist](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/tree/5e2986065e9f) | app | agent | ✓ | ✗ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [gitlab-org/cli](https://gitlab.com/gitlab-org/cli/tree/8ae0c0ef5cf9) | app | agent | ✓ | ✓ | ✗ | ✓ | · | ✓ | · | ✗ |
| [assafelovic/gpt-researcher](https://github.com/assafelovic/gpt-researcher/tree/0957c301ed06) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [deepset-ai/haystack-cookbook](https://github.com/deepset-ai/haystack-cookbook/tree/35212da9a2df) | app | agent | ✓ | ✓ | ✗ | · | · | ✓ | · | ✗ |
| [langchain4j/langchain4j-examples](https://github.com/langchain4j/langchain4j-examples/tree/790431c9fa67) | app | agent | ✓ | ✓ | ✗ | · | · | ✓ | · | ✗ |
| [mastra-ai/template-deep-research](https://github.com/mastra-ai/template-deep-research/tree/8a33c09983f5) | app | agent | ✓ | ✓ | ✓ | · | · | ✓ | ✓ | · |
| [mem0ai/mem0](https://github.com/mem0ai/mem0/tree/b7ad69afda6b) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [langchain-ai/open-canvas](https://github.com/langchain-ai/open-canvas/tree/0310cecd51f3) | app | agent | ✓ | ✓ | ✓ | · | · | ✓ | · | · |
| [openai/openai-cs-agents-demo](https://github.com/openai/openai-cs-agents-demo/tree/bd7bfca0f5ab) | app | agent | ✓ | ✓ | ✓ | · | · | · | ✓ | · |
| [openai/openai-realtime-agents](https://github.com/openai/openai-realtime-agents/tree/94c9e9116b58) | app | agent | ✓ | ✓ | ✗ | · | · | ✓ | ✓ | · |
| [All-Hands-AI/OpenHands](https://github.com/All-Hands-AI/OpenHands/tree/bf92bcb6b337) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | · | ✗ |
| [langchain-ai/react-agent](https://github.com/langchain-ai/react-agent/tree/f5520937686b) | app | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ |
| [spring-projects/spring-ai-examples](https://github.com/spring-projects/spring-ai-examples/tree/74164123ba2d) | app | agent | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | · |
| [strands-agents/samples](https://github.com/strands-agents/samples/tree/11dd549c26c9) | app | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [vertexproject/synapse](https://github.com/vertexproject/synapse/tree/a2c28d855543) | app | agent | ✓ | ✗ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [vercel/ai-chatbot](https://github.com/vercel/ai-chatbot/tree/c2f8235e1f3e) | app | agent | ✓ | ✓ | ✓ | · | · | ✓ | · | · |
| [Nutlope/aicommits](https://github.com/Nutlope/aicommits/tree/a414dd43b6ac) | config-only | agent | ✓ | ✓ | ✓ | · | · | ✓ | · | · |
| [anthropics/skills](https://github.com/anthropics/skills/tree/683bc88e56f3) | config-only | agent | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · |
| [github/awesome-copilot](https://github.com/github/awesome-copilot/tree/7cce7cfb4b61) | config-only | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [svcvit/Awesome-Dify-Workflow](https://github.com/svcvit/Awesome-Dify-Workflow/tree/e730ed3627e5) | config-only | agent | ✓ | ✓ | ✓ | · | · | ✓ | · | · |
| [buildkite/agent](https://github.com/buildkite/agent/tree/7e35f2ed983d) | config-only | agent | ✓ | ✓ | ✗ | ✓ | · | ✓ | · | ✗ |
| [trailheadapps/coral-cloud](https://github.com/trailheadapps/coral-cloud/tree/6e05e6cf74da) | config-only | agent | ✓ | · | ✓ | · | · | ✓ | · | ✗ |
| [gitlab-org/cluster-integration/gitlab-agent](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/tree/5d7d299dcc7c) | config-only | agent | ✓ | ✓ | ✓ | · | · | ✓ | · | · |
| [gitlab-org/gitlab-runner](https://gitlab.com/gitlab-org/gitlab-runner/tree/471891165404) | config-only | agent | ✓ | ✓ | ✗ | · | · | ✓ | · | ✗ |
| [n8n-io/self-hosted-ai-starter-kit](https://github.com/n8n-io/self-hosted-ai-starter-kit/tree/662bd8892476) | config-only | agent | ✓ | ✓ | ✓ | · | · | · | · | ✓ |
| [Zie619/n8n-workflows](https://github.com/Zie619/n8n-workflows/tree/94007c1445d9) | config-only | agent | ✓ | ✓ | ✗ | · | · | ✓ | ✓ | ✗ |
| [openai/openai-python](https://github.com/openai/openai-python/tree/9301e319ea33) | config-only | agent | ✓ | ✓ | ✗ | · | ✓ | ✓ | ✓ | ✗ |
| [python-telegram-bot/python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot/tree/d4f2b1682938) | config-only | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✗ |
| [aws-ia/terraform-aws-bedrock](https://github.com/aws-ia/terraform-aws-bedrock/tree/4b74b7dd5110) | config-only | agent | ✓ | ✓ | ✓ | · | · | · | · | · |
| [anthropics/anthropic-sdk-ruby](https://github.com/anthropics/anthropic-sdk-ruby/tree/139c11027433) | framework-source | agent | ✓ | ✓ | ✗ | · | · | ✓ | · | · |
| [anthropics/anthropic-sdk-typescript](https://github.com/anthropics/anthropic-sdk-typescript/tree/0f9fdcaaf139) | framework-source | agent | ✓ | ✓ | ✗ | · | · | ✓ | ✓ | ✗ |
| [browser-use/browser-use](https://github.com/browser-use/browser-use/tree/c75e8476e26d) | framework-source | agent | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [stanfordnlp/dspy](https://github.com/stanfordnlp/dspy/tree/a7e7edb8c680) | framework-source | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [jlowin/fastmcp](https://github.com/jlowin/fastmcp/tree/5baeacfe20ec) | framework-source | agent | ✓ | ✗ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [FlowiseAI/Flowise](https://github.com/FlowiseAI/Flowise/tree/9291856d1ea4) | framework-source | agent | ✓ | ✓ | ✗ | · | · | ✓ | ✓ | ✗ |
| [firebase/genkit](https://github.com/firebase/genkit/tree/a838fe30358d) | framework-source | agent | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| [github/github-mcp-server](https://github.com/github/github-mcp-server/tree/55edd58d5e11) | framework-source | agent | ✓ | ✓ | ✓ | · | · | · | ✓ | ✗ |
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/5abed86c5317) | framework-source | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✗ |
| [microsoft/agent-framework](https://github.com/microsoft/agent-framework/tree/91ab44faa482) | framework-source | agent | ✓ | ✗ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [microsoft/autogen](https://github.com/microsoft/autogen/tree/027ecf0a379b) | framework-source | agent | ✓ | ✓ | ✗ | · | ✓ | ✓ | ✓ | ✗ |
| [ollama/ollama-python](https://github.com/ollama/ollama-python/tree/8785556559ec) | framework-source | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✗ |
| [openai/openai-dotnet](https://github.com/openai/openai-dotnet/tree/1f0e8829acac) | framework-source | agent | ✓ | ✓ | ✗ | ✓ | · | ✓ | · | ✗ |
| [openai/swarm](https://github.com/openai/swarm/tree/6af0b4caf37d) | framework-source | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ |
| [pydantic/pydantic-ai](https://github.com/pydantic/pydantic-ai/tree/f55bb8a6fd6c) | framework-source | agent | ✓ | ✗ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [0xPlaygrounds/rig](https://github.com/0xPlaygrounds/rig/tree/b6a9b44344a7) | framework-source | agent | ✓ | ✓ | ✗ | · | · | ✓ | · | ✗ |
| [microsoft/semantic-kernel](https://github.com/microsoft/semantic-kernel/tree/cc8a15fa356f) | framework-source | agent | ✓ | ✓ | ✗ | · | · | ✓ | ✓ | ✗ |
| [huggingface/smolagents](https://github.com/huggingface/smolagents/tree/96f33faaf028) | framework-source | agent | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✗ |
| [tmc/langchaingo](https://github.com/tmc/langchaingo/tree/039fbb6c6469) | framework-source | agent | ✓ | ✓ | ✗ | · | · | ✓ | · | · |
| [sashabaranov/go-openai](https://github.com/sashabaranov/go-openai/tree/dd54fd29688a) | llm-only | llm | ✓ | ✓ | ✓ | · | · | · | · | · |
| [di-sukharev/opencommit](https://github.com/di-sukharev/opencommit/tree/250d49ab5eae) | llm-only | llm | ✓ | ✓ | ✓ | · | · | ✓ | · | · |
| [ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt/tree/9ad8a47e23f7) | docs-only | none | ✓ | · | · | · | · | · | ✓ | · |
| [PatrickJS/awesome-cursorrules](https://github.com/PatrickJS/awesome-cursorrules/tree/b044f956f021) | docs-only | none | ✓ | · | ✓ | · | · | · | · | · |
| [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers/tree/6474b22a2203) | docs-only | none | ✓ | · | ✗ | · | · | · | ✓ | · |
| [psf/requests](https://github.com/psf/requests/tree/611c6162cbc4) | docs-only | none | · | · | ✗ | · | · | · | ✓ | ✗ |
| [ua-parser/uap-core](https://github.com/ua-parser/uap-core/tree/73e7340c3ed8) | docs-only | none | ✓ | · | ✗ | · | · | ✓ | · | · |
| [Farama-Foundation/Gymnasium](https://github.com/Farama-Foundation/Gymnasium/tree/2637f8c98edf) | ml-not-agent | none | ✓ | ✓ | · | · | ✓ | ✓ | ✓ | ✗ |
| [scikit-learn-contrib/imbalanced-learn](https://github.com/scikit-learn-contrib/imbalanced-learn/tree/8504e95f0160) | ml-not-agent | none | · | ✓ | · | · | ✓ | ✓ | · | ✗ |
| [karpathy/minGPT](https://github.com/karpathy/minGPT/tree/37baab71b9ab) | ml-not-agent | none | ✓ | ✓ | · | · | ✓ | ✓ | ✓ | ✗ |
| [mbrubeck/agate](https://github.com/mbrubeck/agate/tree/a48d086163d0) | name-collision | none | ✓ | · | ✗ | · | · | ✓ | · | · |
| [ampproject/amppackager](https://github.com/ampproject/amppackager/tree/57974efc943c) | name-collision | none | ✓ | ✓ | ✗ | · | · | ✓ | · | · |
| [autowp/arduino-mcp2515](https://github.com/autowp/arduino-mcp2515/tree/737f0d536770) | name-collision | none | ✓ | · | · | · | · | · | ✓ | · |
| [aws/copilot-cli](https://github.com/aws/copilot-cli/tree/a0dbe68908e5) | name-collision | none | ✓ | ✓ | ✗ | · | · | ✓ | · | · |
| [PrismarineJS/bedrock-protocol](https://github.com/PrismarineJS/bedrock-protocol/tree/f0ac6151322b) | name-collision | none | ✓ | ✓ | · | · | · | ✓ | · | · |
| [pressly/goose](https://github.com/pressly/goose/tree/0e5c23df4b93) | name-collision | none | · | · | · | · | · | ✓ | · | · |
| [phoenixframework/phoenix](https://github.com/phoenixframework/phoenix/tree/cf8b44be4320) | name-collision | none | · | · | · | · | · | ✓ | · | · |
| [moby/swarmkit](https://github.com/moby/swarmkit/tree/1fd637ba5cc3) | name-collision | none | ✓ | ✓ | · | · | ✗ | ✓ | · | ✗ |
| [weaveworks/weave](https://github.com/weaveworks/weave/tree/8c8476381d48) | name-collision | none | ✓ | · | ✗ | · | · | ✓ | · | ✗ |
| [sharkdp/bat](https://github.com/sharkdp/bat/tree/d9559c69f541) | plain | none | ✓ | ✓ | ✗ | · | · | ✓ | · | ✗ |
| [charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea/tree/96d69d2f7eb1) | plain | none | · | ✓ | · | · | · | · | · | · |
| [expressjs/express](https://github.com/expressjs/express/tree/9efc29e28001) | plain | none | · | · | · | · | · | · | · | · |
| [pallets/flask](https://github.com/pallets/flask/tree/d086db856be1) | plain | none | · | · | · | · | · | · | · | ✗ |
| [junegunn/fzf](https://github.com/junegunn/fzf/tree/b1be3a8be1b8) | plain | none | · | · | ✗ | · | · | ✓ | · | · |
| [gin-gonic/gin](https://github.com/gin-gonic/gin/tree/43fe48e8a0f4) | plain | none | · | · | · | · | · | · | · | · |
| [pallets/jinja](https://github.com/pallets/jinja/tree/5ef70112a1ff) | plain | none | · | · | · | · | · | · | ✓ | ✗ |
| [jqlang/jq](https://github.com/jqlang/jq/tree/fd25c3e72038) | plain | none | · | · | ✗ | · | · | ✓ | · | ✗ |
| [rust-lang/mdBook](https://github.com/rust-lang/mdBook/tree/d4658998d441) | plain | none | · | · | ✗ | · | · | ✓ | · | · |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep/tree/3fce3b5bb023) | plain | none | · | ✓ | ✗ | · | · | ✓ | · | · |

## Errors

- Cisco AI BOM: 5 errors (timeout 5), e.g. `exit 124: timeout after 900s` on `vertexproject/synapse`
- Project Nexus ShadowScan: 47 errors (incomplete 47), e.g. `incomplete scan (exit 3)` on `assafelovic/gpt-researcher`
- agent-bom: 1 errors (crash 1), e.g. `exit 1: e mode is active | 12:36:57 WARNING agent_bom.parsers.compiled_parsers: go.sum verification skipped for k8s.io/klog/v2@v2.100.1 — checksum DB unreachabl` on `moby/swarmkit`
- Agentic Radar (SPLX): 44 errors (crash 44), e.g. `3 framework scans crashed: langgraph: exit 1 l variable 'tree' where it is not  | associated with a value; crewai: exit 1 ╯ | AttributeError: 'Attribute' object` on `assafelovic/gpt-researcher`
