# Shadow AI agent discovery benchmark

Corpus: 87 pinned repositories (65 positive, 10 control, 12 near-miss) carrying 839 expected facts. Run started 2026-10-08T19:40:31+00:00 and finished 2026-10-08T21:13:45+00:00 on Linux-6.18.44-fc-v80-x86_64-with-glibc2.39 with 6 parallel workers; timings therefore include contention and are indicative only.

Ground truth was labeled in this session from dependency manifests, imports, committed configuration paths, code constructs and infrastructure resources (see the README). It is author-written evidence, not independent human review.

Tools skipped in this run:

- `cisco_aibom`: requires an LLM credential (tools.cisco_aibom.llm_model/llm_env); benchmark runs offline

## Headline

| Tool | Declared categories | In-scope value P / R / F1 | In-scope category P / R / F1 | All-category value F1 | Positives detected | Controls flagged | Near-misses flagged | Seconds median / p90 / max | Runs |
|---|---|---|---|---|---|---|---|---|---|
| ShadowScan (Project Nexus) (0.1.2+7bdea5300551) | a2a, agent-config, framework, iac, lowcode, mcp, mcp-client-config, provider | 100% / 95% / 97% | 100% / 97% / 99% | 97% | 65/65 | 0/10 | 0/12 | 9.51 / 87.05 / 657.3 | 0 failed, 0 timed out |
| NuGuard (sbom generate) (0.9.15) | a2a, framework, iac, lowcode, mcp, provider | 96% / 62% / 75% | 98% / 81% / 89% | 68% | 59/65 | 0/10 | 0/12 | 29.73 / 333.36 / 1479.05 | 1 failed, 1 timed out |
| SafeDep vet (ai discover) (v1.20.0) | agent-config, mcp-client-config | 92% / 43% / 59% | 100% / 62% / 76% | 11% | 30/65 | 0/10 | 0/12 | 0.27 / 0.33 / 0.47 | 0 failed, 0 timed out |
| Trusera ai-bom (3.6.0) | a2a, framework, iac, lowcode, mcp, mcp-client-config, provider | 79% / 47% / 59% | 92% / 82% / 87% | 54% | 61/65 | 3/10 | 1/12 | 7.91 / 87.77 / 684.83 | 0 failed, 0 timed out |
| cdxgen (CycloneDX) (12.8.5) | a2a, framework, mcp, provider | 100% / 34% / 51% | 100% / 73% / 84% | 45% | 50/65 | 0/10 | 0/12 | 8.77 / 45.52 / 487.29 | 1 failed, 1 timed out |
| AgentDiscover (2.9.5) | framework, mcp, mcp-client-config, provider | 96% / 27% / 42% | 92% / 54% / 68% | 37% | 56/65 | 0/10 | 3/12 | 10.69 / 37.65 / 187.04 | 0 failed, 0 timed out |
| SafeDep xbom (v0.0.3) | a2a, framework, mcp, provider | 99% / 10% / 19% | 100% / 32% / 49% | 16% | 35/65 | 0/10 | 0/12 | 1.74 / 20.79 / 149.85 | 0 failed, 0 timed out |
| Agentic Radar (0.14.1) | framework, lowcode, mcp | 71% / 5% / 10% | 100% / 17% / 29% | 3% | 12/65 | 0/10 | 0/12 | 21.53 / 84.58 / 773.1 | 0 failed, 0 timed out |
| Geiger (0.4.0) | agent-config, mcp-client-config | 100% / 2% / 3% | 100% / 4% / 7% | 0% | 2/65 | 0/10 | 0/12 | 0.27 / 0.32 / 0.62 | 0 failed, 0 timed out |

In-scope metrics count only the categories a tool declares; the all-category value F1 charges every tool for every expected fact in the corpus. Repository-level detection counts a repository as flagged when the tool reports any in-scope fact.

## Value-level F1 by category

| Tool | framework (n=156) | provider (n=488) | mcp (n=60) | mcp-client-config (n=12) | agent-config (n=102) | a2a (n=10) | lowcode (n=3) | iac (n=8) |
|---|---|---|---|---|---|---|---|---|
| ShadowScan (Project Nexus) | 99% (154/0/2) | 96% (451/2/37) | 99% (59/0/1) | 96% (11/0/1) | 99% (111/0/2) | 100% (10/0/0) | 100% (3/0/0) | 93% (7/0/1) |
| NuGuard (sbom generate) | 85% (128/16/28) | 73% (285/3/203) | 60% (26/0/34) | out of scope (0/0/12) | out of scope (0/0/102) | 82% (7/0/3) | n/a (0/0/3) | n/a (0/0/8) |
| SafeDep vet (ai discover) | out of scope (0/0/156) | out of scope (0/0/488) | out of scope (0/0/60) | 50% (4/0/8) | 60% (45/4/57) | out of scope (0/0/10) | out of scope (0/0/3) | out of scope (0/0/8) |
| Trusera ai-bom | 64% (99/55/57) | 56% (202/37/286) | 64% (28/0/32) | 40% (3/0/9) | out of scope (0/0/102) | 75% (6/0/4) | 80% (2/0/1) | 55% (3/0/5) |
| cdxgen (CycloneDX) | 75% (93/0/63) | 39% (120/0/368) | 60% (26/0/34) | out of scope (0/0/12) | out of scope (0/0/102) | 75% (6/0/4) | out of scope (0/0/3) | out of scope (0/0/8) |
| AgentDiscover | 46% (47/3/109) | 44% (137/1/351) | 10% (3/0/57) | 50% (5/3/7) | out of scope (0/0/102) | out of scope (0/0/10) | out of scope (2/0/1) | out of scope (0/0/8) |
| SafeDep xbom | 26% (23/1/133) | 17% (44/0/444) | 18% (6/0/54) | out of scope (0/0/12) | out of scope (0/0/102) | n/a (0/0/10) | out of scope (0/0/3) | out of scope (0/0/8) |
| Agentic Radar | 9% (8/5/148) | out of scope (0/0/488) | 10% (3/0/57) | out of scope (0/0/12) | out of scope (0/0/102) | out of scope (0/0/10) | 50% (1/0/2) | out of scope (0/0/8) |
| Geiger | out of scope (0/0/156) | out of scope (0/0/488) | out of scope (0/0/60) | 29% (2/0/10) | n/a (0/0/102) | out of scope (0/0/10) | out of scope (0/0/3) | out of scope (0/0/8) |

Cells read F1 (true positives / false positives / false negatives).

## Near-miss and control repositories

| Repository | Class | ShadowScan (Project Nexus) | NuGuard (sbom generate) | SafeDep vet (ai discover) | Trusera ai-bom | cdxgen (CycloneDX) | AgentDiscover | SafeDep xbom | Agentic Radar | Geiger |
|---|---|---|---|---|---|---|---|---|---|---|
| BurntSushi/ripgrep | control | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| encode/httpx | control | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| expressjs/express | control | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| google/gson | control | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| JamesNK/Newtonsoft.Json | control | clean | clean | clean | framework:crewai | clean | clean | clean | clean | clean |
| lodash/lodash | control | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| pallets/flask | control | clean | clean | clean | framework:crewai | clean | clean | clean | clean | clean |
| psf/requests | control | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| spf13/cobra | control | clean | clean | clean | provider:together | clean | clean | clean | clean | clean |
| terraform-aws-modules/terraform-aws-vpc | control | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| autowp/arduino-mcp2515 | nearmiss | clean | clean | clean | clean | clean | mcp-client-config:generic | clean | clean | clean |
| brianc/node-pg-cursor | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| codex-team/editor.js | nearmiss | clean | clean | clean | clean | clean | framework:vercel-ai | clean | clean | clean |
| e2b-dev/awesome-ai-agents | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| faisalman/ua-parser-js | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| Farama-Foundation/Gymnasium | nearmiss | clean | clean | clean | framework:crewai | clean | clean | clean | clean | clean |
| Hannibal046/Awesome-LLM | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| jenkinsci/docker-agent | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| jpadilla/pyjwt | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| makew0rld/amfora | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| PrismarineJS/bedrock-protocol | nearmiss | clean | clean | clean | clean | clean | provider:bedrock | clean | clean | clean |
| prompt-toolkit/python-prompt-toolkit | nearmiss | clean | clean | clean | clean | clean | clean | clean | clean | clean |

## Per-repository results (positives)

| Repository | Expected | ShadowScan (Project Nexus) | NuGuard (sbom generate) | SafeDep vet (ai discover) | Trusera ai-bom | cdxgen (CycloneDX) | AgentDiscover | SafeDep xbom | Agentic Radar | Geiger |
|---|---|---|---|---|---|---|---|---|---|---|
| 0xPlaygrounds/rig | 21 | 21/0/1 | 8/2/13 | 0/0/21 | 5/1/16 | 2/0/19 | 0/0/21 | 0/0/21 | 0/0/21 | 0/0/21 |
| a2aproject/a2a-samples | 24 | 25/0/0 | 19/0/5 | 0/0/24 | 16/1/8 | 17/0/7 | 4/0/20 | 4/0/20 | 0/1/24 | 0/0/24 |
| ag2ai/ag2 | 16 | 16/0/0 | 10/2/6 | 0/0/16 | 7/3/9 | 10/0/6 | 6/0/10 | 2/0/14 | 0/1/16 | 0/0/16 |
| agno-agi/agno | 44 | 44/0/0 | 28/0/16 | 2/0/42 | 23/0/21 | 3/0/41 | 10/0/34 | 7/0/37 | 3/0/41 | 0/0/44 |
| Aider-AI/aider | 16 | 15/0/1 | 9/0/7 | 0/0/16 | 5/1/11 | 4/0/12 | 4/0/12 | 0/0/16 | 0/0/16 | 0/0/16 |
| anthropics/anthropic-quickstarts | 11 | 11/0/0 | 5/0/6 | 1/0/10 | 4/1/7 | 3/0/8 | 2/0/9 | 3/0/8 | 0/1/11 | 0/0/11 |
| anthropics/claude-agent-sdk-python | 6 | 5/0/1 | 2/0/4 | 3/0/3 | 2/3/4 | 0/0/6 | 2/0/4 | 0/0/6 | 0/0/6 | 0/0/6 |
| anthropics/claude-code | 7 | 7/0/0 | 1/1/6 | 1/0/6 | 1/2/6 | 0/0/7 | 1/0/6 | 0/0/7 | 0/0/7 | 0/0/7 |
| anthropics/skills | 5 | 3/0/2 | 2/0/3 | 1/0/4 | 2/0/3 | 2/0/3 | 1/0/4 | 1/0/4 | 0/0/5 | 0/0/5 |
| assafelovic/gpt-researcher | 25 | 25/0/0 | 19/0/6 | 3/0/22 | 13/2/12 | 8/0/17 | 8/0/17 | 3/0/22 | 0/0/25 | 0/0/25 |
| aws-ia/terraform-aws-bedrock | 3 | 1/0/2 | 1/0/2 | 0/0/3 | 1/0/2 | 0/0/3 | 1/0/2 | 0/0/3 | 0/0/3 | 0/0/3 |
| awslabs/amazon-bedrock-agent-samples | 10 | 8/0/2 | 8/1/2 | 0/0/10 | 6/1/4 | 6/0/4 | 3/0/7 | 2/0/8 | 0/0/10 | 0/0/10 |
| awslabs/mcp | 11 | 11/0/0 | 0/0/11 (tool reported failure) | 0/0/11 | 5/1/6 | 4/0/7 | 3/0/8 | 3/0/8 | 0/0/11 | 0/0/11 |
| Azure-Samples/azure-openai-terraform-deployment-sample | 4 | 4/0/0 | 3/0/1 | 0/0/4 | 3/1/1 | 3/0/1 | 1/1/3 | 1/0/3 | 0/0/4 | 0/0/4 |
| Azure-Samples/azure-search-openai-demo | 7 | 7/0/0 | 2/0/5 | 0/0/7 | 3/1/4 | 2/0/5 | 1/0/6 | 2/0/5 | 0/0/7 | 0/0/7 |
| block/goose | 28 | 29/0/0 | 13/0/15 | 2/0/26 | 7/1/21 | 2/0/26 | 3/0/25 | 1/0/27 | 0/0/28 | 0/0/28 |
| browser-use/browser-use | 22 | 22/1/0 | 11/0/11 | 2/0/20 | 10/2/12 | 0/0/22 | 7/0/15 | 3/0/19 | 0/0/22 | 0/0/22 |
| cline/cline | 25 | 25/0/1 | 8/0/17 | 3/0/22 | 5/3/20 | 3/0/22 | 5/0/20 | 1/0/24 | 0/0/25 | 0/0/25 |
| cloudwego/eino | 2 | 1/0/1 | 2/0/0 | 0/0/2 | 1/1/1 | 0/0/2 | 0/0/2 | 0/0/2 | 0/0/2 | 0/0/2 |
| continuedev/continue | 27 | 27/0/0 | 14/1/13 | 2/0/25 | 11/4/16 | 4/0/23 | 3/0/24 | 0/0/27 | 0/0/27 | 0/0/27 |
| crewAIInc/crewAI-examples | 8 | 8/0/0 | 7/0/1 | 0/0/8 | 7/1/1 | 6/0/2 | 3/0/5 | 2/0/6 | 1/0/7 | 0/0/8 |
| deepset-ai/haystack-cookbook | 16 | 15/0/1 | 7/0/9 | 0/0/16 | 4/0/12 | 0/0/16 | 1/0/15 | 0/0/16 | 0/0/16 | 0/0/16 |
| dotnet/ai-samples | 6 | 6/0/0 | 5/0/1 | 0/0/6 | 3/1/3 | 5/0/1 | 0/0/6 | 0/0/6 | 0/0/6 | 0/0/6 |
| firebase/genkit | 18 | 18/0/0 | 13/2/5 | 1/0/17 | 9/2/9 | 9/0/9 | 12/0/6 | 3/0/15 | 0/0/18 | 0/0/18 |
| github/awesome-copilot | 11 | 11/0/0 | 3/0/8 | 2/0/9 | 2/0/9 | 0/0/11 | 4/1/7 | 1/0/10 | 0/0/11 | 1/0/10 |
| github/github-mcp-server | 5 | 5/0/0 | 1/0/4 | 0/0/5 | 1/2/4 | 1/0/4 | 1/0/4 | 0/0/5 | 0/0/5 | 0/0/5 |
| gitlab-org/duo-workflow/duo-workflow-service | 4 | 4/0/0 | 4/0/0 | 0/0/4 | 3/1/1 | 4/0/0 | 1/0/3 | 1/0/3 | 1/0/3 | 0/0/4 |
| gitlab-org/gitlab-runner | 2 | 2/0/0 | 0/0/2 | 0/0/2 | 0/1/2 | 0/0/2 | 0/0/2 | 0/0/2 | 0/0/2 | 0/0/2 |
| gitlab-org/modelops/applied-ml/code-suggestions/ai-assist | 14 | 13/0/1 | 10/0/4 | 1/1/13 | 7/3/7 | 8/0/6 | 9/0/5 | 3/0/11 | 1/0/13 | 0/0/14 |
| google-gemini/gemini-cli | 7 | 7/0/0 | 1/1/6 | 1/0/6 | 1/4/6 | 1/0/6 | 1/0/6 | 0/0/7 | 0/0/7 | 0/0/7 |
| google/adk-samples | 12 | 13/0/0 | 7/0/5 | 1/0/11 | 6/1/6 | 6/0/6 | 1/0/11 | 0/0/12 | 0/0/12 | 0/0/12 |
| GoogleCloudPlatform/agent-starter-pack | 8 | 8/0/0 | 6/0/2 | 1/0/7 | 6/2/2 | 5/0/3 | 1/0/7 | 1/0/7 | 0/0/8 | 0/0/8 |
| huggingface/agents-course | 2 | 2/0/0 | 2/2/0 | 0/0/2 | 1/1/1 | 1/0/1 | 1/0/1 | 0/0/2 | 0/0/2 | 0/0/2 |
| huggingface/smolagents | 18 | 16/0/2 | 9/0/9 | 0/0/18 | 9/1/9 | 4/0/14 | 5/0/13 | 3/0/15 | 0/0/18 | 0/0/18 |
| jlowin/fastmcp | 10 | 11/0/0 | 4/1/6 | 3/1/7 | 3/2/7 | 4/0/6 | 3/1/7 | 3/0/7 | 0/0/10 | 0/0/10 |
| langchain-ai/chat-langchain | 5 | 5/0/0 | 5/0/0 | 0/0/5 | 5/1/0 | 1/0/4 | 2/0/3 | 1/0/4 | 0/0/5 | 0/0/5 |
| langchain-ai/open_deep_research | 14 | 12/0/2 | 11/0/3 | 1/0/13 | 6/1/8 | 10/0/4 | 5/0/9 | 2/0/12 | 0/0/14 | 0/0/14 |
| langchain-ai/react-agent | 5 | 5/0/0 | 5/0/0 | 0/0/5 | 4/0/1 | 5/0/0 | 3/0/2 | 1/0/4 | 1/0/4 | 0/0/5 |
| langchain4j/langchain4j-examples | 15 | 15/0/0 | 11/0/4 | 0/0/15 | 4/1/11 | timeout | 1/0/14 | 1/1/14 | 0/0/15 | 0/0/15 |
| letta-ai/letta | 1 | 1/0/0 | 0/0/1 | 0/0/1 | 0/0/1 | 0/0/1 | 0/1/1 | 0/0/1 | 0/0/1 | 0/0/1 |
| mastra-ai/mastra | 36 | 37/0/0 | 12/0/24 | 4/0/32 | 11/3/25 | 4/0/32 | 4/0/32 | 0/0/36 | 0/0/36 | 1/0/35 |
| mckaywrigley/chatbot-ui | 12 | 11/0/1 | 8/1/4 | 0/0/12 | 8/0/4 | 3/0/9 | 5/0/7 | 0/0/12 | 0/0/12 | 0/0/12 |
| microsoft/autogen | 21 | 20/0/1 | 16/0/5 | 0/0/21 | 12/1/9 | 16/0/5 | 8/0/13 | 2/0/19 | 0/0/21 | 0/0/21 |
| microsoft/magentic-ui | 2 | 2/0/0 | 1/0/1 | 0/0/2 | 2/1/0 | 1/0/1 | 1/0/1 | 1/0/1 | 0/0/2 | 0/0/2 |
| microsoft/playwright-mcp | 3 | 2/0/1 | 0/0/3 | 1/0/2 | 0/0/3 | 0/0/3 | 1/0/2 | 0/0/3 | 0/0/3 | 0/0/3 |
| microsoft/semantic-kernel | 20 | 20/0/0 | 16/3/4 | 0/0/20 | 11/3/9 | 15/0/5 | 5/0/15 | 2/0/18 | 0/0/20 | 0/0/20 |
| modelcontextprotocol/servers | 6 | 6/0/0 | 1/0/5 | 2/0/4 | 2/1/4 | 1/0/5 | 1/0/5 | 0/0/6 | 0/0/6 | 0/0/6 |
| n8n-io/self-hosted-ai-starter-kit | 2 | 2/0/0 | 0/0/2 | 0/0/2 | 2/0/0 | 0/0/2 | 1/0/1 | 0/0/2 | 1/0/1 | 0/0/2 |
| openai/codex | 8 | 8/0/1 | 1/0/7 | 0/0/8 | 2/2/6 | 1/0/7 | 1/0/7 | 1/0/7 | 0/0/8 | 0/0/8 |
| openai/openai-agents-python | 9 | 8/0/1 | 6/0/3 | 1/1/8 | 4/2/5 | 3/0/6 | 5/0/4 | 1/0/8 | 0/0/9 | 0/0/9 |
| openai/openai-cs-agents-demo | 2 | 2/0/0 | 2/0/0 | 0/0/2 | 1/1/1 | 2/0/0 | 1/0/1 | 0/0/2 | 0/0/2 | 0/0/2 |
| OpenInterpreter/open-interpreter | 23 | 14/0/9 | 8/0/15 | 0/0/23 | 5/1/18 | 1/0/22 | 1/0/22 | 1/0/22 | 0/0/23 | 0/0/23 |
| Portkey-AI/gateway | 29 | 29/0/0 | 15/0/14 | 1/0/28 | 11/0/18 | 3/0/26 | 1/0/28 | 0/0/29 | 0/0/29 | 0/0/29 |
| pydantic/pydantic | 1 | 1/0/0 | 0/1/1 | 1/0/0 | 0/2/1 | 0/0/1 (tool reported failure) | 0/0/1 | 0/0/1 | 0/0/1 | 0/0/1 |
| pydantic/pydantic-ai | 26 | 27/0/0 | timeout | 2/1/24 | 8/2/18 | 11/0/15 | 12/0/14 | 3/0/23 | 1/1/25 | 0/0/26 |
| RooCodeInc/Roo-Code | 20 | 19/1/2 | 8/1/12 | 2/0/18 | 6/1/14 | 3/0/17 | 0/0/20 | 0/0/20 | 0/0/20 | 0/0/20 |
| run-llama/llama_deploy | 3 | 3/0/0 | 3/0/0 | 0/0/3 | 1/3/2 | 2/0/1 | 1/0/2 | 0/0/3 | 0/0/3 | 0/0/3 |
| Shubhamsaboo/awesome-llm-apps | 39 | 39/0/1 | 26/0/13 | 0/0/39 | 21/1/18 | 13/0/26 | 12/0/27 | 5/0/34 | 3/0/36 | 0/0/39 |
| spring-projects/spring-ai-examples | 9 | 8/0/1 | 5/0/4 | 1/0/8 | 3/2/6 | 5/0/4 | 1/0/8 | 0/0/9 | 0/0/9 | 0/0/9 |
| stanfordnlp/dspy | 18 | 17/0/1 | 9/0/9 | 1/0/17 | 9/2/9 | 6/0/12 | 6/0/12 | 1/0/17 | 0/0/18 | 0/0/18 |
| strands-agents/samples | 21 | 18/0/3 | 12/0/9 | 0/0/21 | 8/2/13 | 7/0/14 | 5/0/16 | 1/0/20 | 0/1/21 | 0/0/21 |
| svcvit/Awesome-Dify-Workflow | 6 | 1/0/5 | 4/0/2 | 0/0/6 | 0/0/6 | 0/0/6 | 1/0/5 | 0/0/6 | 0/0/6 | 0/0/6 |
| SWE-agent/SWE-agent | 7 | 7/0/0 | 3/0/4 | 1/0/6 | 1/1/6 | 0/0/7 | 0/0/7 | 0/0/7 | 0/0/7 | 0/0/7 |
| tmc/langchaingo | 16 | 16/0/0 | 11/0/5 | 0/0/16 | 4/3/12 | 4/0/12 | 1/0/15 | 0/0/16 | 0/0/16 | 0/0/16 |
| vercel/ai-chatbot | 5 | 5/0/0 | 3/0/2 | 1/0/4 | 0/0/5 | 1/0/4 | 1/0/4 | 0/0/5 | 0/0/5 | 0/0/5 |

Cells read true positives / false positives / false negatives at value level, all categories.

## Misses and false positives by tool

### ShadowScan (Project Nexus)

Most missed facts: provider:ollama (6), provider:mistral (5), provider:bedrock (3), provider:cohere (3), provider:deepseek (3), provider:huggingface (3), agent-config:claude-dir (2), provider:anthropic (2), provider:google-gemini (2), provider:openai (2), provider:together (2), provider:vertex-ai (2)

Most frequent false positives: provider:cohere (1), provider:voyage (1)

### NuGuard (sbom generate)

Most missed facts: agent-config:skills (29), agent-config:agents-md (26), mcp:server (23), provider:azure-openai (23), provider:bedrock (20), provider:openrouter (17), provider:perplexity (16), agent-config:claude-md (15), provider:vertex-ai (15), provider:xai (14), provider:groq (13), provider:ollama (13)

Most frequent false positives: framework:langgraph (7), framework:autogen (3), framework:crewai (3), framework:llamaindex (2), framework:google-adk (1), provider:cohere (1), provider:huggingface (1), provider:openai (1)

### SafeDep vet (ai discover)

Most missed facts: provider:openai (48), provider:anthropic (46), mcp:sdk (37), provider:google-gemini (35), provider:bedrock (34), provider:azure-openai (29), provider:deepseek (28), provider:ollama (28), provider:mistral (27), provider:vertex-ai (27), agent-config:agents-md (26), framework:langchain (26)

Most frequent false positives: agent-config:claude-md (3), agent-config:claude-dir (1)

### Trusera ai-bom

Most missed facts: provider:google-gemini (30), agent-config:skills (29), provider:deepseek (27), agent-config:agents-md (26), mcp:server (23), provider:openrouter (21), provider:vertex-ai (21), provider:xai (18), provider:perplexity (17), provider:groq (16), agent-config:claude-md (15), provider:cohere (15)

Most frequent false positives: framework:crewai (45), provider:vllm (16), provider:huggingface (9), framework:langchain (6), framework:llamaindex (4), provider:together (4), provider:mistral (3), provider:bedrock (2), provider:anthropic (1), provider:openai (1), provider:replicate (1)

### cdxgen (CycloneDX)

Most missed facts: agent-config:skills (29), provider:anthropic (28), provider:bedrock (28), provider:deepseek (27), agent-config:agents-md (26), provider:azure-openai (25), mcp:server (23), provider:mistral (23), provider:openrouter (21), provider:cohere (20), provider:google-gemini (20), provider:ollama (17)

Most frequent false positives: none

### AgentDiscover

Most missed facts: mcp:sdk (34), agent-config:skills (29), provider:azure-openai (28), agent-config:agents-md (26), provider:ollama (25), provider:vertex-ai (24), mcp:server (23), provider:deepseek (21), framework:langchain (20), provider:anthropic (20), provider:google-gemini (18), provider:groq (18)

Most frequent false positives: mcp-client-config:generic (3), framework:vercel-ai (2), framework:letta (1), provider:bedrock (1)

### SafeDep xbom

Most missed facts: provider:google-gemini (35), provider:anthropic (34), provider:bedrock (32), mcp:sdk (31), agent-config:skills (29), provider:deepseek (28), provider:ollama (28), provider:azure-openai (27), provider:mistral (27), agent-config:agents-md (26), provider:openai (25), mcp:server (23)

Most frequent false positives: framework:langchain (1)

### Agentic Radar

Most missed facts: provider:openai (48), provider:anthropic (46), provider:google-gemini (35), mcp:sdk (34), provider:bedrock (34), agent-config:skills (29), provider:azure-openai (29), provider:deepseek (28), provider:ollama (28), provider:mistral (27), provider:vertex-ai (27), agent-config:agents-md (26)

Most frequent false positives: framework:openai-agents (5)

### Geiger

Most missed facts: provider:openai (48), provider:anthropic (46), mcp:sdk (37), provider:google-gemini (35), provider:bedrock (34), agent-config:skills (29), provider:azure-openai (29), provider:deepseek (28), provider:ollama (28), provider:mistral (27), provider:vertex-ai (27), agent-config:agents-md (26)

Most frequent false positives: none
