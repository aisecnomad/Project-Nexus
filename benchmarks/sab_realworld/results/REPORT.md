# SAB Real-World Benchmark Report

> **Shadow AI Agent Discovery — Real-World Pattern Corpus**
>
> This benchmark uses file patterns modeled on actual public GitHub
> repositories. It is author-written and cannot establish independent
> precision or recall. See [Limitations](#limitations).

## Metadata

- **Tool**: ShadowScan v0.1.1
- **Corpus version**: 1.0.0
- **Cases**: 40
- **Timestamp**: 2026-10-08T14:08:04.429178+00:00
- **Python**: 3.13.16
- **Errors**: 0

## Overall Results

| Metric | Value |
|--------|-------|
| Cases | 40 |
| TP / FP / FN / TN | 27 / 1 / 1 / 11 |
| Recall | 0.96 [0.82, 0.99] |
| Specificity | 0.92 [0.65, 0.99] |
| Precision | 0.96 [0.82, 0.99] |
| F1 | 0.96 |
| F1 95% CI (bootstrap) | [0.91, 1.00] |
| MCC | 0.88 |
| Agent-tier accuracy | 0.76 |
| Mean signature recall | 0.00 |

## Results by Category

| Category | N | TP | FP | FN | TN | Recall | Precision | F1 | MCC |
|----------|---|----|----|----|----|--------|-----------|----|-----|
| agent-framework | 14 | 14 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| cloud-ai | 2 | 2 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| coding-agent | 4 | 3 | 0 | 1 | 0 | 0.75 | 1.00 | 0.86 | 0.00 |
| llm-sdk | 5 | 5 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| lowcode-ai | 1 | 1 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| mcp-protocol | 2 | 2 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| negative | 12 | 0 | 1 | 0 | 11 | - | 0.00 | 0.00 | 0.00 |

## Results by Difficulty

| Difficulty | Correct | Total | Accuracy |
|------------|---------|-------|----------|
| easy | 10 | 10 | 1.00 |
| medium | 15 | 16 | 0.94 |
| hard | 13 | 14 | 0.93 |

## Results by Label

| Label | Correct | Total | Accuracy |
|-------|---------|-------|----------|
| agent | 21 | 22 | 0.95 |
| llm | 6 | 6 | 1.00 |
| none | 11 | 12 | 0.92 |

## Per-Family Results

| Family | Label | Detected | Correct | Agent Tier | Sig Recall |
|--------|-------|----------|---------|------------|------------|
| autogen-groupchat | agent | True | Y | Y | 0.00 |
| claude-agent-sdk | agent | True | Y | **N** | 0.00 |
| crewai-team | agent | True | Y | Y | 0.00 |
| google-adk | agent | True | Y | Y | 0.00 |
| langchaingo | agent | True | Y | **N** | 0.00 |
| langgraph-react | agent | True | Y | Y | 0.00 |
| llamaindex-agent | agent | True | Y | Y | 0.00 |
| mastra-agent | agent | True | Y | Y | 0.00 |
| openai-agents-sdk | agent | True | Y | Y | 0.00 |
| pydantic-ai | agent | True | Y | Y | 0.00 |
| raw-openai-tool-loop | agent | True | Y | **N** | 0.00 |
| semantic-kernel-csharp | agent | True | Y | Y | 0.00 |
| smolagents | agent | True | Y | Y | 0.00 |
| vercel-ai-tools | agent | True | Y | Y | 0.00 |
| bedrock-agent-terraform | agent | True | Y | **N** | 0.00 |
| vertex-ai-pipeline | llm | True | Y | Y | 0.00 |
| aider-config | agent | True | Y | Y | 0.00 |
| cline-config | agent | True | Y | Y | 0.00 |
| cursor-rules | agent | True | Y | Y | 0.00 |
| openclaw-state | agent | False | **N** | Y | 0.00 |
| anthropic-messages | llm | True | Y | Y | 0.00 |
| gemini-multimodal | llm | True | Y | Y | 0.00 |
| litellm-proxy | llm | True | Y | Y | 0.00 |
| ollama-local | llm | True | Y | Y | 0.00 |
| openai-embeddings | llm | True | Y | Y | 0.00 |
| n8n-ai-workflow | agent | True | Y | Y | 0.00 |
| claude-desktop-mcp-config | agent | True | Y | Y | 0.00 |
| mcp-server-python | agent | True | Y | **N** | 0.00 |
| neg-agent-pattern | none | False | Y | Y | - |
| neg-commented-out | none | False | Y | Y | - |
| neg-egress-blocklist | none | False | Y | Y | - |
| neg-gemini-exchange | none | True | **N** | Y | - |
| neg-insurance-agents | none | False | Y | Y | - |
| neg-minecraft-bedrock | none | False | Y | Y | - |
| neg-minecraft-mcp | none | False | Y | Y | - |
| neg-monitoring-agent | none | False | Y | Y | - |
| neg-plain-webapp | none | False | Y | Y | - |
| neg-sklearn-pipeline | none | False | Y | Y | - |
| neg-travel-agent | none | False | Y | Y | - |
| neg-user-agent-parser | none | False | Y | Y | - |

## False Positives

- `rw-repo-033` (neg-gemini-exchange)

## False Negatives

- `rw-repo-040` (openclaw-state)

## Limitations

1. **Author-written corpus**: This benchmark is written by the ShadowScan
   maintainer. It cannot serve as independent validation. See AGENTS.md.
2. **Single tool**: Only ShadowScan is tested against this corpus. The
   cross-tool comparison uses the separate synthetic benchmark.
3. **Structural patterns only**: Cases reproduce file structure and import
   patterns, not full repositories with git history, CI, or runtime signals.
4. **Limited hard-negative diversity**: 12 negative families cannot cover
   the full space of false-positive triggers in production.
5. **No endpoint or network surface**: This corpus covers repo-surface
   detection only. Endpoint and network surfaces need separate corpora.
