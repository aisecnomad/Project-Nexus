# Real-world benchmark, post-fix rerun — 2026-10-08

The ShadowScan rows of [`results-realworld/`](../results-realworld/), rerun
on this branch after the fixes that run drove (input-defect taxonomy,
brace-less-JSX and JSX-in-`.js` lexing, size-scaled credential allowance,
priority-ordered walk, UA-string discount, agent-flow classification).
Same pinned corpus, same adapters, same pre-registered detection rules;
the other six tools were not rerun. Like
[`results-post-change/`](../results-post-change/README.md), this is a
regression check by the same author on the same corpus, not independent
evidence.

## Before → after

| Row | Errors (incomplete) | Recall | False positives on 9 `none` repos |
|---|---|---|---|
| ShadowScan, default options | 15 → **13** | 0.56 → **0.64** | 1 → **0** |
| ShadowScan, max_file_size 20 MiB | 12 → **7** | 0.64 → **0.76** | 0 → **1** (see below) |

Recovered scans: autogen and langgraph (brace-less JSX in attribute
values; an invalid agent manifest now an input defect), gpt-researcher
(JSX in a plain `.js` Docusaurus page; a dead MCP shape now an input
defect), awesome-mcp-servers and pytorch-examples (credential pass no
longer times out on large keyword-dense text), crewai-examples,
openai-agents-python and nukkit under the tuned row (oversize plus the
above). The ua-parser-js false positive (a provider domain inside a
crawler user-agent string) is gone, with the discount recorded as a
visible note.

The one new false positive is honest behavior surfaced by a fix:
pytorch-examples now *completes* under the tuned row and its
`transformers` dependency fires the Hugging Face Hub signature at 0.2
confidence — a judgment call between "ML library usage" and "LLM
provider usage" that the corpus labels `none`. Below the demo
configuration's 0.2 `min_confidence` threshold it would not display.

Every remaining incomplete sits in a category the fixes deliberately kept
fail-closed, because scanned repositories are untrusted and these are
evasion-capable: undecodable bytes in analyzable files (private-gpt,
gitlab-lsp, fdroidserver), credential-redaction resource limits
(anthropic-sdk-python, openai-python), connector deadlines on monorepo
scale (pydantic-ai, mastra), and — under default options — scannable
files over the 1 MiB `max_file_size`.

One mapping note: the benchmark's pre-registered `AGENTIC_KINDS` still
counts every `workflow` finding as agentic, so the n8n starter kit (an
LLM chain, label `llm`) still shows an agent-tier false alarm here even
though the scanner now reports it as a non-agent workflow
(`metadata.agent_flow: false`). The rule is left as pre-registered; a
future benchmark revision can key the agent tier on `agent_flow`.
