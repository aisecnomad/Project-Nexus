# Real-world shadow-AI discovery benchmark: protocol (v1)

This protocol is written before any tool runs on the scored corpus. It fixes
the corpus rules, the label definitions, the labeling procedure, each tool's
detection rule, and the statistics. Changes after a scored run are recorded in
the changelog at the end, with the reason, and never silently applied.

## 1. Question

For a public source repository at a pinned commit, or for the same tree read as
a developer home directory, does a discovery tool report AI use or AI agents
exactly where the independent labels say they are?

## 2. What this benchmark does and does not measure

- Surfaces: `repo` (the repository working tree) and `home-view` (the
  repository root read as `$HOME`, for endpoint tools).
- Not measured: network, identity/SaaS, cloud and runtime. No public source
  of real traffic or tenant data exists for them. Those surfaces stay in the
  synthetic harness (`tools/benchmark`), and nothing here speaks to them.
- Results describe these repositories at these commits. They are not field
  precision or recall, not production accuracy, and not independent review.

## 3. Corpus rules

- Public GitHub repositories, shallow clone (`--depth 1`) at a recorded commit
  SHA. The license is read from the repository's LICENSE file.
- Four strata: `agent`, `llm`, `hard-negative` (AI-adjacent names or AI topics
  without AI use), and `ordinary` (no AI-related content).
- Candidates came from web search and from well-known public projects. No
  candidate was chosen or dropped because of any tool's output.
- Excluded classes: AI framework and SDK source repositories (agent code is
  their product, so "agent" would not describe a deployment); tools that
  discover AI use (including the repository that holds this benchmark, which is
  scanned separately as a self-check and is not a corpus member).
- Trees are copied without `.git` and without symbolic links. Symlinks are
  never followed, so a repository cannot make a tool read host files.

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

## 5. Labeling procedure

1. Read-only static inspection. Do not execute repository code, install its
   dependencies, or run its scripts.
2. Record, per repository: the label, the evidence paths, and a confidence
   (`high`, `medium`, `low`).
3. Two labelers work independently. Labeler A is the benchmark's orchestrator.
   Labeler B is a separate agent instance that receives this protocol and the
   repository paths, and never sees A's labels. Both are model-based. No human
   labeled this corpus, and this is not independent human review.
4. Agreement is measured on the three-way label and on positive versus none
   (Cohen's kappa), before any adjudication. A disagreement is adjudicated by
   reading the cited evidence, and the adjudicated label is recorded with its
   reason. The pre-adjudication agreement is reported next to the result.

## 6. Home-view labels (path-based, computed, no judgment)

The repository root is read as a home directory. The repository is `home-view`
positive when any of these user-scope AI-client paths exists and is non-empty
(a file with bytes, or a directory with entries):

`.claude.json`, `.claude/settings.json`, `.claude/agents`, `.cursor/mcp.json`,
`.codex/config.toml`, `.gemini/settings.json`,
`.codeium/windsurf/mcp_config.json`, `.continue/config.json`,
`.continue/config.yaml`, `.aider.conf.yml`, `.config/goose/config.yaml`,
`.kiro/settings/mcp.json`, `.aws/amazonq/mcp.json`, `.openclaw`,
`.config/Code/User/mcp.json`.

This label measures whether an endpoint tool reports a client configuration
that is present at a path the client reads from a home directory. It does not
measure a developer's real endpoint. Project-scope files such as `.mcp.json`
are not in the list, because clients do not read them from a home directory.

## 7. Tool detection rules (fixed before the scored run)

A case is `detected` when the tool's own report contains at least one item the
tool classes as AI-related, for that input. An `error` (crash, timeout,
incomplete scan, unreadable output) counts as not detected and is reported
separately. A surface the tool does not support is `n/a` and is excluded from
that tool's per-surface metrics. Estate-level recall counts `n/a` as a miss.

| Tool | Repo surface | Home-view surface |
|---|---|---|
| ShadowScan (published config) | `code.filesystem` on the tree; any finding, complete scan | `code.filesystem` on the tree as home; any finding, complete scan |
| ShadowScan (post-change connectors) | n/a (same as above) | `endpoint.inventory`; any finding, complete scan |
| Cisco AI BOM 1.10.0 | `analyze`; `total_components > 0` | `analyze` on the home tree; `total_components > 0` |
| agent-bom 0.108.2 | `scan --no-scan --offline`, empty home; client agent or MCP server absent from empty-home baseline, or project entry on `ai-inventory` surface or bound to a model | same, with the home tree as `$HOME` |
| AgentDiscover 2.9.5 | `scan` (SARIF) + `audit --skip-layers 2,3,4,5`; any result, agent or MCP server | same, with the home tree as `$HOME` |
| SafeDep vet (pinned Go module) | `vet ai discover` scoped to the tree, empty home; any project-scope signal | same, with the home tree as `$HOME` (rule frozen after calibration, see changelog) |
| mcp-audit (mcp-audit-scanner 0.18.2) | `discover --json --path <tree>`, empty home; any server or client entry from the tree | `discover --json` with `$HOME` = home tree; any entry |
| shadow-mcp 0.2.0 | n/a (no directory input) | `discover --json --no-processes --no-cli --home <tree>`; any server or client entry |
| Snyk Agent Scan 0.6.8 | n/a (not enumerated on a directory) | `inspect --json`, `$HOME` = home tree; any server or skill |
| Cisco MCP Scanner 4.8.6 | n/a | `--scan-known-configs --analyzers yara`, `$HOME` = home tree; any server |
| Claw-Hunter (pinned commit) | n/a (OpenClaw only) | `claw-hunter.sh --json`; any OpenClaw signal |
| AI-Detector (pinned commit) | n/a | `detect-shadow-ai.sh` as an unprivileged user, network off; any finding absent from an empty-home baseline |

Network-only tools (Open Shadow AI, AgentSonar, Shadow AI Detector) have no
real-world input here and are not run on this corpus.

## 8. Statistics

- Per tool and surface: TP, FP, FN, TN, recall, specificity, precision, F1,
  MCC. Wilson 95% intervals for proportions; a 2,000-sample bootstrap interval
  for F1.
- Per stratum: detection rate, so hard negatives can be seen on their own.
- Paired comparison with ShadowScan (published config) on the cases both tools
  support: exact McNemar test.
- Sensitivity: the primary metrics are recomputed with (a) ambiguous cases
  excluded and (b) hard negatives excluded. These are reported, not used to
  choose a result.
- No result is chosen by looking at scores before the rules above are fixed.

## 9. Safety and handling

- Every tool runs as the unprivileged user `nobody`, with an empty environment
  (no proxies, no credentials), `HOME` set to the case directory, and fresh
  network and PID namespaces with a 300-second timeout.
- Residual risk, disclosed: some tools can start MCP servers named in a
  repository's configuration (Cisco MCP Scanner's known-configs mode). Those
  commands run inside the sandbox above. The sandbox has no network, no
  credentials and no writable path outside the case directory.
- Raw tool outputs stay in a scratch directory and are never committed.
  Committed results hold verdicts, counts, and notes truncated to 200
  characters. The notes are scanned for secret-shaped strings before commit.

## 10. Changelog

- v1: initial protocol, written before the scored run.
- v1.1, written after the two labelers returned and before any scored tool run.
  Applied to every repository alike:
  - "Shipped" was clarified in section 4 after the labelers disagreed about a
    maintainer script (`fastapi/scripts/translate.py`). This narrows nothing
    and adds no new criterion.
  - Adjudication: each disagreement was settled by checking the cited lines.
  Where the criteria are not clearly met either way, the label is `ambiguous`
  and the repository is excluded from primary metrics. The decisions, their
  evidence and their reasons are in `labels/adjudication.json`. Two repositories
  (aider, chatbot-ui) are ambiguous; seven were settled by evidence.
  - Calibration, on constructed trees that are not corpus members:
    `vet ai discover` prints `null` for an empty inventory and tags each item
    with `Scope` "1" (system) or "2" (project), as section 7 says. `mcp-audit`
    is the command of the `mcp-audit-scanner` package, not the one that shares
    its name in `shadow-mcp`. `shadow-mcp` reads no Cursor configuration and
    no project files from a directory, so it is scored on the home view only.
  - Implementation fixes, not rule changes: the Cisco AI BOM PyPI wheel needs
    the `agentic` and `llm-openai` extras to run; AI-Detector's own privilege
    drop fails once the runner has already dropped to `nobody`, so the adapter
    skips it in that case (synthetic runs are unchanged); the copied checkout
    excludes `.git` and symbolic links.
  - Smoke test: every adapter ran on the first corpus repository to catch
    crashes. Verdicts were read only for errors. No rule was changed as a
    result, and the first repository's verdicts were not used to set a label.
