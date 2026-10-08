# Shadow AI agent discovery benchmark (code surface)

A reproducible, tool-neutral benchmark that asks one question of a repository
checkout: *which AI agents, frameworks, model providers, protocol surfaces and
agent configurations are present, and can a discovery tool find them without
flagging repositories that merely sound like AI?*

It runs ShadowScan and every other open-source code-surface discovery tool that
could be installed and executed offline in this environment against the same
pinned checkouts, normalizes their output into one vocabulary, and scores them
against session-labeled ground truth.

The harness lives in `tools/discovery_benchmark/`; this directory holds the
corpus, the results and this description. Nothing here is a release artifact.

## What is measured

Every expected or predicted item is a **fact** `<category>:<value>`:

| Category | Meaning | Example values |
|---|---|---|
| `framework` | an agent or LLM orchestration framework is a declared dependency or is imported | `langgraph`, `crewai`, `openai-agents`, `google-adk`, `semantic-kernel`, `vercel-ai`, `langchain4j`, `rig` |
| `provider` | a model provider SDK, endpoint or local runtime is used | `openai`, `anthropic`, `bedrock`, `azure-openai`, `vertex-ai`, `ollama`, `vllm` |
| `mcp` | Model Context Protocol | `sdk` (an MCP SDK dependency or import), `server` (a server construct in code) |
| `mcp-client-config` | a committed MCP client configuration file, valued by client | `claude-code` (`.mcp.json`), `cursor`, `vscode`, `gemini-cli`, `codex`, `generic` |
| `agent-config` | coding-agent instruction or configuration surfaces | `claude-md`, `claude-dir`, `agents-md`, `cursor-rules`, `copilot-instructions`, `copilot-agents`, `gemini-md`, `clinerules`, `roo`, `skills` |
| `a2a` | Agent-to-Agent protocol | `sdk`, `agent-card` |
| `lowcode` | an exported low-code flow with AI steps | `n8n`, `dify`, `flowise`, `langflow` |
| `iac` | infrastructure as code provisioning managed AI or agent resources | `bedrock`, `azure-openai`, `vertex-ai` |

The alias tables that map package names, import paths, hostnames and free-text
names onto facts are in `tools/discovery_benchmark/taxonomy.py`. They are
shared by the ground-truth extractor and by every adapter, so no tool is scored
against a vocabulary it cannot express, and they are independent of every tool
under test, including ShadowScan's signature packs.

## Corpus

`corpus.json` pins 87 public repositories (84 on GitHub, 3 on GitLab) to a
40-character commit. Each entry records the class, size, languages, expected
facts with `kind:path[:line]` evidence pointers, and tolerated facts.

* **positive** repositories carry at least one expected fact. They span agent
  frameworks (LangGraph, CrewAI, AutoGen, OpenAI Agents, Google ADK, Pydantic AI,
  Semantic Kernel, smolagents, Mastra, Vercel AI SDK, Strands, Haystack, DSPy,
  Agno, LangChain4j, Spring AI, Rig, Eino, Genkit), MCP servers in five
  languages, committed MCP client configurations, coding-agent configuration
  surfaces (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules`, Copilot instructions and
  custom agents, `GEMINI.md`, Roo, Cline, skills), A2A agent cards, n8n and Dify
  exports, and Terraform, CDK and Bicep provisioning Bedrock, Azure OpenAI or
  Vertex AI.
* **control** repositories have no AI integration at all (an HTTP client, a web
  framework, a CLI library, a JSON library, a VPC module, a CI runner ...).
* **near-miss** repositories use the vocabulary without the technology: a
  user-agent parser, a Jenkins agent image, an MCP2515 CAN-bus library, a Gemini
  protocol browser, a PostgreSQL cursor, Minecraft Bedrock protocol, the CodeX
  editor, reinforcement-learning environments, a prompt toolkit, a JWT library,
  and two markdown-only "awesome" lists about LLMs and AI agents.

Two repositories chosen as negatives turned out to carry coding-agent
configuration (`AGENTS.md`/`CLAUDE.md` in the GitLab runner, an agent skill in
pydantic). They were moved to the positive class with exactly those facts rather
than silently kept as negatives.

### How ground truth was labeled

`tools/discovery_benchmark/evidence.py` reads each checkout and reports facts
with evidence from:

* dependency manifests (`requirements*.txt`, `pyproject.toml`, `setup.py`,
  `setup.cfg`, `Pipfile`, conda environments, `package.json`, `go.mod`,
  `pom.xml`, Gradle scripts and version catalogs, `*.csproj`/`packages.config`,
  `Cargo.toml`), and `pip install` lines in notebooks;
* import statements in Python, JavaScript/TypeScript, Go, Java/Kotlin, C# and
  Rust;
* committed configuration paths (MCP client files are only counted when they
  actually declare servers);
* MCP server constructs in code, A2A agent cards, n8n/Dify/Flowise/Langflow
  exports, Terraform/CloudFormation/Bicep/CDK resources;
* provider hostnames and SDK idioms in code and configuration files, never in
  documentation.

A fact seen only in lock files, in `// indirect` Go requirements, or in test and
fixture paths is **tolerated**: a tool may report it without penalty, but it is
not required. Documentation-only mentions (README, docs, markdown lists) do not
count at all; a list of products is not use of them.

The extractor output was reviewed by the author of this benchmark (a Claude
session) and spot-checked against the evidence pointers. **This is author-written
labeling, not independent human review**, and the corpus is a snapshot of
public code on one day; it says nothing about production precision or recall.

## Tools

| Adapter id | Tool | What is run | Declared categories |
|---|---|---|---|
| `shadowscan` | ShadowScan (Project Nexus) | `code.filesystem` connector, JSON report, defaults | all |
| `trusera_ai_bom` | Trusera ai-bom | `ai-bom scan --format json`, default regex scanners | framework, provider, mcp, mcp-client-config, a2a, lowcode, iac |
| `nuguard` | NuGuard | `nuguard sbom generate --no-llm --no-scan-images` | framework, provider, mcp, lowcode, iac, a2a |
| `agentdiscover` | DefendAI AgentDiscover | `scan` (SARIF), `deps`, `export-mcpfw-policy` | framework, provider, mcp, mcp-client-config |
| `agentic_radar` | SplxAI Agentic Radar | `scan <framework> --export-graph-json` for each of its five frameworks | framework, mcp, lowcode |
| `xbom` | SafeDep xbom | `xbom generate --bom` | framework, provider, mcp, a2a |
| `vet` | SafeDep vet | `vet ai discover --scope project` | mcp-client-config, agent-config, mcp |
| `geiger` | Atomburst Geiger | `geiger --path <repo> --home <empty>` | mcp-client-config, agent-config, mcp |
| `cdxgen` | CycloneDX cdxgen | `--technique manifest-analysis --no-install-deps`; a plain dependency SBOM mapped through the alias tables, used as the baseline | framework, provider, mcp, a2a |
| `cisco_aibom` | Cisco AI BOM | skipped: the tool refuses to run without an LLM credential | framework, provider, mcp, a2a, iac |

Excluded, with the reason observed in this environment:

* **Snyk Agent Scan** (formerly Invariant mcp-scan) scans MCP client directories
  under `$HOME` only and, in verbose mode, sends scan metadata including
  hostname and username to `api.snyk.io` even when nothing was found. It has no
  repository-scan mode, so pointing it at a checkout from the working directory
  yields nothing.
* **Cisco AI BOM** exits with "`--llm-model` is required" without an LLM; the
  benchmark is deterministic and offline. The adapter is present and runs when
  `tools.cisco_aibom.llm_model` and `llm_env` are configured.
* **Cisco MCP Scanner**, mcp-armor, Ramparts and similar tools scan a known MCP
  server for weaknesses; they do not discover what a repository contains.
* Network, endpoint and runtime tools (AI-Infra-Guard, Julius, Numbat, Fleet
  tables, AgentSonar, AIOstack) have no repository input.

Tool versions are recorded in `results/<run>/runs.json`.

## Scoring

Three views are reported for every tool (see `tools/discovery_benchmark/score.py`):

* **repository level** - a positive repository is detected when the tool reports
  any fact in its declared categories; a control or near-miss is flagged under
  the same rule;
* **category level** - facts collapsed to their category;
* **value level** - exact facts; `<category>:generic` is a wildcard that matches
  one expected fact of that category (for tools that report "an MCP config" but
  not which client).

Precision, recall and F1 are micro-averaged over all repositories. *In-scope*
numbers count only a tool's declared categories; the *all-category* number
charges every tool for every expected fact and is the honest "how much of the
problem does this tool cover" figure. Tolerated facts are dropped before
scoring. Facts a tool reports outside the taxonomy are ignored, never penalized.

## Isolation and fairness

* Every tool sees the same read-only checkout at the same commit.
* Tools run as an unprivileged user through `setpriv` with a rebuilt
  environment: no API keys, a dead proxy so outbound requests fail fast,
  telemetry opt-outs, a private `HOME` and `TMPDIR`, and a per-run timeout.
* No LLM-backed analyzer is used anywhere, so a rerun on the same commits is
  deterministic up to tool bugs.
* `cdxgen` warns that it can auto-execute local scripts; it is run with
  `--technique manifest-analysis --no-install-deps` and as the unprivileged user.
* Runs are parallel (several repository/tool pairs at once), so wall-clock
  timings include contention and are indicative only.

## Reproduce

```console
# 1. checkouts at the pinned commits
python -m tools.discovery_benchmark fetch --corpus benchmarks/shadow-ai-discovery/corpus.json --dest /srv/sadb/corpus
# 2. (optional) regenerate labeling evidence for review
python -m tools.discovery_benchmark evidence --checkouts /srv/sadb/corpus --out /srv/sadb/evidence --all
# 3. run every tool (tools.json lists the installed binaries, see results/<run>/tools.json)
python -m tools.discovery_benchmark run --corpus benchmarks/shadow-ai-discovery/corpus.json \
    --tools /srv/sadb/tools.json --checkouts /srv/sadb/corpus --out /srv/sadb/runs/full --as-user bench --workers 4
# 4. score and report
python -m tools.discovery_benchmark score --corpus benchmarks/shadow-ai-discovery/corpus.json \
    --runs /srv/sadb/runs/full/runs.json --out metrics.json
python -m tools.discovery_benchmark report --corpus benchmarks/shadow-ai-discovery/corpus.json \
    --metrics metrics.json --out REPORT.md
```

The unprivileged account needs traverse access to the checkouts and the tool
installations; `tools.json` maps adapter ids to binaries. Checkouts are never
committed to this repository.

## Limits

* One surface. ShadowScan's identity, SaaS, low-code, gateway, cloud, endpoint,
  network and runtime connectors are not exercised; neither are the endpoint
  and network modes of the other tools.
* Session-labeled ground truth, one labeler, one day's snapshot of public code.
* Tolerance rules are generous on purpose (lock files, test fixtures), which
  favours tools that enumerate everything.
* Timeouts and resource limits are those of the host that ran the benchmark.
