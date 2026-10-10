# Labeling brief (benchmark v2, repo surface)

You are one of three independent labelers. You have no other context about this
project. Do not look for, read, or infer any other labeler's output.

Rules:
1. Read-only static inspection. Do not run, build, install, import, or execute
   repository code, tests, or scripts. Use grep, find, head, sed and cat only.
2. Read only the directories listed in your chunk file. Do not open any other
   directory on this machine, including any path under Project-Nexus, any
   results, labels, manifests or scratch directories, and any `.git` directory.
3. Give each repository exactly one label: agent, llm, none or ambiguous. Apply
   the definitions below. They are verbatim from the benchmark protocol (section 4,
   version 1.1), and they are the only criteria.
4. Record per repository: label; confidence (high, medium or low); evidence as
   repository-relative paths and symbol names only; one-line rationale. Never copy
   a credential, token, key or personal data, even if you see one; write
   "[redacted]" instead.
5. Write one tab-separated file (no header) with columns: dir, label, confidence,
   evidence, rationale. Use "-" for empty evidence. Evidence items are separated
   by "; ".
6. If evidence is weak, label ambiguous and name both candidate labels in the
   rationale.
7. Keep to roughly 15 tool calls per repository. Prefer targeted grep over reading
   whole files.

Definitions (verbatim, protocol section 4):

## 4. Label definitions (repo surface)

Each repository gets exactly one label:

- `agent`: the repository's shipped code, samples or examples, or its
  configuration, implements or configures an AI agent. Any one of:
  (a) a loop in which a model's output selects tools, functions, handoffs or
  sub-agents and the code runs them (tool-calling loop, agent graph, handoff,
  orchestration); (b) an MCP server or MCP client implementation, or an MCP
  server registration intended for an AI client (`.mcp.json`, an `mcpServers`
  entry); (c) an agent definition for an AI platform (for example
  `.claude/agents/*.md`, `.github/agents/*.agent.md`, a declarative agent file).
  Test-only code is not agent evidence.
- `llm`: no agent evidence, but evidence of AI use. Any one of: a call to an
  LLM provider API or SDK in shipped or test code (`import openai`, `messages.create`,
  `chat.completions`, and similar); or an AI coding-assistant instruction
  file in the repository (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
  `.github/copilot-instructions.md`).
- `none`: neither. Documentation that only mentions AI, lists of AI tools,
  AI-related blocklists, AI user-agent strings, ML model code that calls no
  provider API, and name collisions ("agent", "MCP", "Gemini") in non-AI
  software all count as `none`.

Evidence rules:

- "Shipped" means repository code outside documentation and tests: product code,
  samples, examples, notebooks and maintainer scripts (clarified in v1.1).
- Ignore vendored and generated trees (`node_modules`, `vendor`, `third_party`,
  `.venv`, `dist`, `build`, lock files used alone) and documentation prose.
  Runnable examples inside docs count as shipped samples.
- A dependency declared in a manifest but never imported or called is
  `ambiguous`, not `llm`.
- If the evidence is weak, label `ambiguous` and name the two candidate
  labels. Ambiguous repositories are excluded from the primary metrics and
  reported in a sensitivity analysis.
- Every label cites at least one repository path. Evidence never copies a
  secret value. Record paths and symbol names only.

