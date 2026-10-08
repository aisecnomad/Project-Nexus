# SAB Real-World Benchmark Report

> **Shadow AI Agent Discovery — Real-World Pattern Corpus v2**
>
> This benchmark uses file patterns modeled on actual public GitHub
> repositories. It is author-written and cannot establish independent
> precision or recall. An adversarial category explicitly targets
> known ShadowScan blind spots to surface author bias rather than
> hide it. See [Limitations](#limitations).

## Metadata

- **Tool**: ShadowScan v0.1.1
- **Corpus version**: 2.0.0
- **Cases**: 130
- **Surfaces**: endpoint, repo
- **Categories**: 9
- **Families**: 130
- **Timestamp**: 2026-10-08T14:45:22.766661+00:00
- **Python**: 3.13.16
- **Errors**: 0

## Overall Results

| Metric | Value |
|--------|-------|
| Cases | 130 |
| TP / FP / FN / TN | 77 / 1 / 14 / 38 |
| Recall | 0.85 [0.76, 0.91] |
| Specificity | 0.97 [0.87, 1.00] |
| Precision | 0.99 [0.93, 1.00] |
| F1 | 0.91 |
| F1 95% CI (bootstrap) | [0.86, 0.95] |
| MCC | 0.77 |
| Agent-tier accuracy | 0.57 |
| Mean signature recall | 0.00 |

## Surface-Balanced Scoring

Tools differ in which scanning surfaces they support. These metrics
allow fair comparison by reporting per-surface performance.

| Surface | N | TP | FP | FN | TN | Recall | Precision | F1 | MCC |
|---------|---|----|----|----|----|--------|-----------|----|-----|
| endpoint | 5 | 1 | 0 | 4 | 0 | 0.20 | 1.00 | 0.33 | 0.00 |
| repo | 125 | 76 | 1 | 10 | 38 | 0.88 | 0.99 | 0.93 | 0.82 |

| Aggregate Metric | Value |
|------------------|-------|
| Best-surface F1 | 0.93 (repo) |
| Surface-normalized F1 | 0.91 |

*Best-surface F1*: highest F1 among supported surfaces. Use when
comparing tools that claim different surface coverage.

*Surface-normalized F1*: weighted average of per-surface F1 scores,
each weighted by case count. Penalizes tools that skip surfaces.

## Results by Category

| Category | N | TP | FP | FN | TN | Recall | Precision | F1 | MCC |
|----------|---|----|----|----|----|--------|-----------|----|-----|
| adversarial | 15 | 14 | 0 | 1 | 0 | 0.93 | 1.00 | 0.97 | 0.00 |
| agent-framework | 30 | 29 | 0 | 1 | 0 | 0.97 | 1.00 | 0.98 | 0.00 |
| cloud-ai | 8 | 7 | 0 | 1 | 0 | 0.88 | 1.00 | 0.93 | 0.00 |
| coding-agent | 10 | 7 | 0 | 3 | 0 | 0.70 | 1.00 | 0.82 | 0.00 |
| endpoint | 5 | 1 | 0 | 4 | 0 | 0.20 | 1.00 | 0.33 | 0.00 |
| llm-sdk | 12 | 12 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| lowcode-ai | 5 | 1 | 0 | 4 | 0 | 0.20 | 1.00 | 0.33 | 0.00 |
| mcp-protocol | 6 | 6 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| negative | 39 | 0 | 1 | 0 | 38 | - | 0.00 | 0.00 | 0.00 |

### Adversarial Category Detail

These 15 cases target known ShadowScan blind spots (sparse
Go/Rust patterns, custom HTTP-only LLM clients, C/C++ unsupported
extensions, dynamic imports, gated heuristics). An honest benchmark
should expose, not hide, the tool author's weaknesses.

| Metric | Value |
|--------|-------|
| Cases | 15 |
| TP / FP / FN / TN | 14 / 0 / 1 / 0 |
| F1 | 0.97 |
| MCC | 0.00 |

## Results by Difficulty

| Difficulty | Correct | Total | Accuracy |
|------------|---------|-------|----------|
| easy | 22 | 23 | 0.96 |
| medium | 48 | 55 | 0.87 |
| hard | 45 | 52 | 0.87 |

## Results by Label

| Label | Correct | Total | Accuracy |
|-------|---------|-------|----------|
| agent | 54 | 66 | 0.82 |
| llm | 23 | 25 | 0.92 |
| none | 38 | 39 | 0.97 |

## Per-Family Results

| Family | Surface | Label | Detected | Correct | Agent Tier | Sig Recall |
|--------|---------|-------|----------|---------|------------|------------|
| cpp-llm-rest-client | repo | llm | False | **N** | Y | - |
| custom-http-llm-client | repo | llm | True | Y | Y | - |
| docker-ai-deployment | repo | llm | True | Y | Y | 0.00 |
| dynamic-import-agent | repo | agent | True | Y | **N** | 0.00 |
| github-actions-ai | repo | agent | True | Y | Y | 0.00 |
| go-import-only-agent | repo | agent | True | Y | **N** | 0.00 |
| kotlin-openai-ktor | repo | llm | True | Y | Y | 0.00 |
| minified-js-ai-sdk | repo | llm | True | Y | Y | 0.00 |
| monorepo-hidden-ai | repo | agent | True | Y | Y | 0.00 |
| php-openai-client | repo | llm | True | Y | Y | 0.00 |
| polyglot-ai-project | repo | agent | True | Y | **N** | 0.00 |
| raw-openai-tool-loop | repo | agent | True | Y | **N** | 0.00 |
| ruby-langchain-agent | repo | agent | True | Y | **N** | 0.00 |
| rust-llm-cargo-only | repo | llm | True | Y | Y | 0.00 |
| test-only-ai-code | repo | llm | True | Y | Y | 0.00 |
| ag2-swarm | repo | agent | True | Y | Y | 0.00 |
| agency-swarm | repo | agent | False | **N** | Y | 0.00 |
| autogen-groupchat | repo | agent | True | Y | Y | 0.00 |
| autogpt | repo | agent | True | Y | **N** | 0.00 |
| browser-use-agent | repo | agent | True | Y | Y | 0.00 |
| claude-agent-sdk | repo | agent | True | Y | **N** | 0.00 |
| composio-agent | repo | agent | True | Y | Y | 0.00 |
| copilotkit-agent | repo | agent | True | Y | **N** | 0.00 |
| crewai-team | repo | agent | True | Y | Y | 0.00 |
| dspy-pipeline | repo | agent | True | Y | **N** | 0.00 |
| google-adk | repo | agent | True | Y | Y | 0.00 |
| haystack-agent | repo | agent | True | Y | **N** | 0.00 |
| instructor-extraction | repo | llm | True | Y | Y | 0.00 |
| langchain-lcel-agent | repo | agent | True | Y | Y | 0.00 |
| langchain4j-agent | repo | agent | True | Y | **N** | 0.00 |
| langchaingo | repo | agent | True | Y | **N** | 0.00 |
| langgraph-react | repo | agent | True | Y | Y | 0.00 |
| letta-memgpt | repo | agent | True | Y | **N** | 0.00 |
| llamaindex-agent | repo | agent | True | Y | Y | 0.00 |
| mastra-agent | repo | agent | True | Y | Y | 0.00 |
| metagpt-team | repo | agent | True | Y | **N** | 0.00 |
| openai-agents-sdk | repo | agent | True | Y | Y | 0.00 |
| openai-swarm-node | repo | agent | True | Y | **N** | 0.00 |
| phidata-agent | repo | agent | True | Y | Y | 0.00 |
| pydantic-ai | repo | agent | True | Y | Y | 0.00 |
| semantic-kernel-csharp | repo | agent | True | Y | Y | 0.00 |
| semantic-kernel-python | repo | agent | True | Y | **N** | 0.00 |
| smolagents | repo | agent | True | Y | Y | 0.00 |
| spring-ai-java | repo | agent | True | Y | **N** | 0.00 |
| vercel-ai-tools | repo | agent | True | Y | Y | 0.00 |
| azure-ai-search-rag | repo | agent | True | Y | **N** | 0.00 |
| azure-openai-terraform | repo | llm | True | Y | Y | 0.00 |
| bedrock-agent-terraform | repo | agent | True | Y | **N** | 0.00 |
| bedrock-knowledge-base | repo | agent | True | Y | **N** | 0.00 |
| lambda-ai-function | repo | llm | True | Y | Y | 0.00 |
| sagemaker-llm-endpoint | repo | llm | False | **N** | Y | 0.00 |
| vertex-agent-builder | repo | agent | True | Y | Y | 0.00 |
| vertex-ai-pipeline | repo | llm | True | Y | Y | 0.00 |
| aider-config | repo | agent | True | Y | Y | 0.00 |
| claude-code-project | repo | agent | True | Y | Y | 0.00 |
| cline-config | repo | agent | True | Y | Y | 0.00 |
| continue-dev-config | repo | agent | True | Y | Y | 0.00 |
| cursor-rules | repo | agent | True | Y | Y | 0.00 |
| devin-config | repo | agent | False | **N** | Y | 0.00 |
| github-copilot-workspace | repo | agent | True | Y | Y | 0.00 |
| openclaw-state | repo | agent | False | **N** | Y | 0.00 |
| sourcegraph-cody-config | repo | agent | False | **N** | Y | 0.00 |
| windsurf-rules | repo | agent | True | Y | Y | 0.00 |
| dev-home-claude-dir | endpoint | agent | True | Y | Y | 0.00 |
| jetbrains-ai-plugin | endpoint | agent | False | **N** | Y | 0.00 |
| npm-global-ai-packages | endpoint | agent | False | **N** | Y | 0.00 |
| shell-history-ai-cli | endpoint | agent | False | **N** | Y | 0.00 |
| vscode-ai-extensions | endpoint | agent | False | **N** | Y | 0.00 |
| anthropic-messages | repo | llm | True | Y | Y | 0.00 |
| azure-openai-sdk | repo | llm | True | Y | Y | 0.00 |
| bedrock-invoke-model | repo | llm | True | Y | Y | 0.00 |
| cohere-chat | repo | llm | True | Y | Y | 0.00 |
| gemini-multimodal | repo | llm | True | Y | Y | 0.00 |
| groq-inference | repo | llm | True | Y | Y | 0.00 |
| huggingface-inference | repo | llm | True | Y | Y | 0.00 |
| litellm-proxy | repo | llm | True | Y | Y | 0.00 |
| mistral-client | repo | llm | True | Y | Y | 0.00 |
| ollama-local | repo | llm | True | Y | Y | 0.00 |
| openai-embeddings | repo | llm | True | Y | Y | 0.00 |
| replicate-prediction | repo | llm | True | Y | Y | 0.00 |
| dify-workflow | repo | agent | False | **N** | Y | 0.00 |
| flowise-chatflow | repo | agent | False | **N** | Y | 0.00 |
| langflow-pipeline | repo | agent | False | **N** | Y | 0.00 |
| n8n-ai-workflow | repo | agent | True | Y | Y | 0.00 |
| rivet-graph | repo | agent | False | **N** | Y | 0.00 |
| claude-desktop-mcp-config | repo | agent | True | Y | Y | 0.00 |
| mcp-client-python | repo | agent | True | Y | **N** | 0.00 |
| mcp-server-python | repo | agent | True | Y | **N** | 0.00 |
| mcp-server-typescript | repo | agent | True | Y | **N** | 0.00 |
| windsurf-mcp-config | repo | agent | True | Y | Y | 0.00 |
| zed-mcp-config | repo | agent | True | Y | Y | 0.00 |
| neg-agent-pattern | repo | none | False | Y | Y | - |
| neg-ansible-agent | repo | none | False | Y | Y | - |
| neg-blockchain-contract | repo | none | False | Y | Y | - |
| neg-build-agent | repo | none | False | Y | Y | - |
| neg-commented-out | repo | none | False | Y | Y | - |
| neg-consul-agent | repo | none | False | Y | Y | - |
| neg-db-replication | repo | none | False | Y | Y | - |
| neg-deepseek-crypto | repo | none | False | Y | Y | - |
| neg-egress-blocklist | repo | none | True | **N** | Y | - |
| neg-game-npc-ai | repo | none | False | Y | Y | - |
| neg-gemini-exchange | repo | none | False | Y | Y | - |
| neg-graphql-resolver | repo | none | False | Y | Y | - |
| neg-gymnasium-rl | repo | none | False | Y | Y | - |
| neg-insurance-agents | repo | none | False | Y | Y | - |
| neg-jenkins-agent | repo | none | False | Y | Y | - |
| neg-kerberos-agent | repo | none | False | Y | Y | - |
| neg-log-shipper | repo | none | False | Y | Y | - |
| neg-mesa-abm | repo | none | False | Y | Y | - |
| neg-message-broker | repo | none | False | Y | Y | - |
| neg-minecraft-bedrock | repo | none | False | Y | Y | - |
| neg-minecraft-mcp | repo | none | False | Y | Y | - |
| neg-monitoring-agent | repo | none | False | Y | Y | - |
| neg-nomad-agent | repo | none | False | Y | Y | - |
| neg-opencv-cv | repo | none | False | Y | Y | - |
| neg-plain-webapp | repo | none | False | Y | Y | - |
| neg-prometheus-agent | repo | none | False | Y | Y | - |
| neg-puppet-agent | repo | none | False | Y | Y | - |
| neg-pytorch-training | repo | none | False | Y | Y | - |
| neg-rule-based-chatbot | repo | none | False | Y | Y | - |
| neg-salt-minion | repo | none | False | Y | Y | - |
| neg-selenium-automation | repo | none | False | Y | Y | - |
| neg-sklearn-pipeline | repo | none | False | Y | Y | - |
| neg-snmp-agent | repo | none | False | Y | Y | - |
| neg-spacy-nlp | repo | none | False | Y | Y | - |
| neg-tensorflow-serving | repo | none | False | Y | Y | - |
| neg-terraform-state | repo | none | False | Y | Y | - |
| neg-travel-agent | repo | none | False | Y | Y | - |
| neg-user-agent-parser | repo | none | False | Y | Y | - |
| neg-vault-agent | repo | none | False | Y | Y | - |

## False Positives

- `rw-repo-101` (neg-egress-blocklist)

## False Negatives

- `rw-repo-019` (agency-swarm)
- `rw-repo-056` (sourcegraph-cody-config)
- `rw-repo-057` (devin-config)
- `rw-repo-058` (openclaw-state)
- `rw-repo-062` (sagemaker-llm-endpoint)
- `rw-repo-068` (dify-workflow)
- `rw-repo-069` (flowise-chatflow)
- `rw-repo-070` (langflow-pipeline)
- `rw-repo-071` (rivet-graph)
- `rw-repo-082` (cpp-llm-rest-client)
- `rw-repo-088` (vscode-ai-extensions)
- `rw-repo-089` (shell-history-ai-cli)
- `rw-repo-090` (jetbrains-ai-plugin)
- `rw-repo-091` (npm-global-ai-packages)

## Limitations

1. **Author-written corpus**: This benchmark is written by the ShadowScan
   maintainer. It cannot serve as independent validation. See AGENTS.md.
2. **Adversarial cases surface but do not eliminate bias**: The adversarial
   category targets known blind spots (Go/Rust sparse patterns, C/C++ no
   source extension support, custom HTTP LLM clients, gated heuristics).
   This makes weaknesses visible but the author chose which weaknesses to
   test, which is itself a form of bias.
3. **Single tool**: Only ShadowScan is tested against this corpus. The
   cross-tool comparison uses the separate synthetic benchmark.
4. **Structural patterns only**: Cases reproduce file structure and import
   patterns, not full repositories with git history, CI, or runtime signals.
5. **Surface coverage**: This corpus covers repo and endpoint surfaces.
   Network surface (egress traffic, DNS) needs a separate corpus with
   packet captures. The FilesystemConnector scans both repo and endpoint
   cases identically; a tool that distinguishes surfaces would need
   separate harness paths.
6. **39 hard negatives**: While substantially expanded from 12, 39 families
   still cannot cover the full space of false-positive triggers in
   production environments.
