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

A fact seen only in lock files, in `// indirect` Go requirements, in test and
fixture paths, or in a documentation-site tree (`docs/`, `website/`, `site/`,
`_data/`, `_posts/`, `_includes/`, `blog/`, `changelogs/`; committed
configuration files inside them still count) is **tolerated**: a tool may
report it without penalty, but it is not required. Documentation-only mentions
(README, docs, markdown lists) do not count at all; a list of products is not
use of them. A `package.json` alias (`"name-v1": "npm:@scope/name@range"`)
names the real package.

The labels were revised after the first run (corpus v2, 839 expected
facts): auditing every tool's false positives against the raw reports found
three labeling gaps (an npm alias, the `portkey-ai` PyPI package, the
`api.replicate.com` host) and the documentation-tree rule above; the audit
also found four adapter bugs that had scored real ShadowScan detections as
misses or false positives (ids such as `provider.voyage-ai` and
`framework.microsoft-extensions-ai` were mapped by name rules instead of by
their exact slug, `protocol.mcp` counted as SDK usage without dependency,
import or code evidence, and two ids resembled products the taxonomy does not
track). A second audit, of ShadowScan's own false positives after the
detection changes, found that the labeler never matched Rust `use rmcp::...`
imports, so three Rust MCP servers (`impl ServerHandler for`) were unlabeled;
they are labeled now. Rescored against corpus v2 with the fixed adapters, the 2026-10-08 run
gives ShadowScan in-scope precision 97.8%, recall 87.5%, F1 92.3% (17 false
positives, 106 misses); every other tool moves by at most 0.2 points.

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
| `vet` | SafeDep vet | `vet ai discover --scope project` | mcp-client-config, agent-config |
| `geiger` | Atomburst Geiger | `geiger --path <repo> --home <empty>` | mcp-client-config, agent-config |
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

* Every tool receives the same checkout at the same commit. The operator
  must make the corpus read-only using filesystem permissions or mounts.
* With `--as-user`, tools run through `setpriv` with a rebuilt environment:
  no inherited API keys, a dead proxy for clients that honor proxy variables,
  telemetry opt-outs, a private `HOME` and `TMPDIR`, and a per-run timeout.
  Without that option, including the ShadowScan-only CI workflow, commands
  run as the invoking user.
* The harness is not a filesystem or network sandbox. `setpriv` does not
  confine path access, and proxy variables do not prevent direct connections.
  Third-party tools require an externally isolated disposable runner with
  egress disabled and no credentials or sensitive host files. Historical run
  metadata records the process policy, not verified network isolation.
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

### Regression gate

`compare` turns a new `metrics.json` into a pass/fail against the most recent
committed results:

```console
python -m tools.discovery_benchmark compare --corpus benchmarks/shadow-ai-discovery/corpus.json \
    --baseline benchmarks/shadow-ai-discovery/results/<run>/metrics.json \
    --baseline-runs benchmarks/shadow-ai-discovery/results/<run>/runs.json \
    --current metrics.json --tools shadowscan
```

It exits 1 when a tool's in-scope value-level F1 falls by more than one point
(`--f1-tolerance`), when repository-level recall falls at all, when a control
or near-miss repository that the baseline left clean is flagged, or when a
repository whose run was complete in the baseline is incomplete now. An
incomplete run (ShadowScan exit 3, `detail.incomplete` in `runs.json`) read
less than the whole repository: `score` keeps its facts, records it under
`incomplete_runs` and in `per_repo`, and REPORT.md marks its cells
`(incomplete)`, so an incomplete control is never shown as a clean negative.
Metrics scored before incompleteness was recorded (the committed 2026-10-08
and 2026-10-09 `metrics.json`) take it from their `runs.json` through
`--baseline-runs`; without it, a run with incomplete repositories fails the
gate rather than passing unchecked. A partial run (`run --repos`) is scored
and compared with the same `--repos`, so the repositories it did not run are
neither missing facts nor a recall drop. Improvements and newly clean
negatives are printed but never fail the gate. The workflow
`.github/workflows/benchmark.yml` runs ShadowScan alone on the pinned corpus
weekly and on demand, with read-only permissions and no third-party tools, and
uploads `runs.json`, `metrics.json`, `REPORT.md` and `compare.json` as an
artifact. Publishing a new baseline stays a manual step: copy the scrubbed
run into `results/<date>/` and describe what changed in this README.

## Results: ShadowScan after the benchmark-driven changes (2026-10-09)

`results/2026-10-09/` re-runs ShadowScan alone, at the commit recorded in its
`runs.json`, against the corpus as labeled now (839 expected facts); the other
tools' rows are their 2026-10-08 runs, re-normalized with the fixed adapters
and scored against the same labels. This directory is the baseline that
`compare` and the weekly workflow use.

| ShadowScan, in-scope value level | 2026-10-08 run | 2026-10-09 run |
|---|---|---|
| Precision | 97.9% | 99.8% |
| Recall | 87.2% | 94.8% |
| F1 | 92.2% | 97.2% |
| False positives / misses | 16 / 109 | 2 / 44 |
| MCP F1 (`mcp:sdk`, `mcp:server`) | 75% | 99% |
| Provider F1 | 91% | 96% |
| Positives detected, controls and near-misses flagged | 65/65, 0/10, 1/12 | 65/65, 0/10, 0/12 |

What changed and how to read it:

* The gains come from model identifiers and LiteLLM-style routes as provider
  evidence, long-tail SDK, credential and manifest signatures, an `mcp-server`
  capability for code that implements an MCP server, a narrower catalog
  discount, and precision rules that stop lexical idioms, low-weight mentions,
  CI job images and test-path mentions from establishing a technology. Each
  change has unit tests, and the synthetic reproductions in
  `tools/evaluation/benchmark_followup_corpus.json` gate them in `make
  evaluate`.
* These numbers are the same author's labels and the same corpus the changes
  were driven by, so they measure fit to this corpus, not production
  precision. The labels were audited against every tool's false positives in
  both directions (four labeling gaps fixed, none of them removing a
  ShadowScan miss), but a held-out corpus and an independent labeler are the
  missing controls.
* The two remaining false positives are model names in provider lists
  (Cohere embeddings in Roo Code, Voyage models in browser-use's gateway
  catalog). Of the 44 misses, 37 are providers (mostly named only by model
  ids or routes the scanner does not read as evidence, such as Ollama, Mistral
  and Bedrock ids in configuration or example code); the other seven are two
  `.claude/` files that are not recognized coding-agent surfaces, the Claude
  Agent SDK imported only from its own examples, one Python MCP server in
  smolagents, LiteLLM in Roo Code, Roo Code's `mcp.json` locale files, and
  one CDK Bedrock construct.
* Timings are not comparable with the 2026-10-08 table: the ShadowScan re-run
  used two workers, the earlier run six on four CPUs. Single-worker
  measurements of the performance changes, with identical findings, are in the
  CHANGELOG.

## Results: run of 2026-10-08 (before the changes)

`results/2026-10-08/` holds the scrubbed run manifest (`runs.json`, with every
tool's normalized facts and mapped evidence per repository), `metrics.json`,
`tools.json` and the generated `REPORT.md`. Headline, in-scope value-level
precision / recall / F1, repository-level detection and negatives flagged:

| Tool | Categories scored | P / R / F1 | Positives detected | Controls / near-misses flagged |
|---|---|---|---|---|
| ShadowScan 0.1.2 | all eight | 97% / 86% / 91% | 65/65 | 0/10 and 1/12 |
| NuGuard 0.9.15 | six | 96% / 62% / 75% | 59/65 | 0/10 and 0/12 |
| Trusera ai-bom 3.6.0 | seven | 79% / 47% / 59% | 61/65 | 3/10 and 1/12 |
| SafeDep vet 1.20.0 | two | 92% / 43% / 59% | 30/65 | 0/10 and 0/12 |
| cdxgen 12.8.5 (SBOM baseline) | four | 100% / 35% / 51% | 50/65 | 0/10 and 0/12 |
| AgentDiscover 2.9.5 | four | 96% / 27% / 42% | 56/65 | 0/10 and 3/12 |
| SafeDep xbom 0.0.3 | four | 99% / 10% / 19% | 35/65 | 0/10 and 0/12 |
| Agentic Radar 0.14.1 | three | 71% / 6% / 10% | 12/65 | 0/10 and 0/12 |
| Geiger 0.4.0 | two | 100% / 2% / 3% | 2/65 | 0/10 and 0/12 |

How to read this honestly:

* ShadowScan is the only tool that declares every category, so its all-category
  F1 (91%) and its in-scope F1 coincide; the other tools' all-category figures
  (NuGuard 69%, Trusera 54%, cdxgen 45%) show how much of the problem each one
  addresses at all. Within the categories a tool declares, NuGuard's precision
  is as high as ShadowScan's; its gap is recall on providers and MCP.
* The same session wrote the taxonomy, labeled the corpus and maintains
  ShadowScan. The evidence rules are objective (manifests, imports, committed
  paths, hostnames, model identifiers) and were extended twice after auditing
  false positives of *other* tools, but a labeler who knows ShadowScan's
  signatures is not an independent labeler.
* `mcp:server` is the fact every tool misses most, including ShadowScan
  (20 of 57): nobody distinguishes an MCP server implementation from an MCP
  SDK dependency. Provider recall is the second gap, mostly LiteLLM-style
  model routes and model identifiers in configuration.
* Tools built for the workstation (vet, Geiger) only read the project root in
  project mode: Geiger credits two repositories and ignores `.mcp.json`;
  vet finds root-level `CLAUDE.md`, `.cursor/rules`, skills and `.mcp.json`
  but no framework or provider.
* Trusera's regex scanners report CrewAI in Newtonsoft.Json, Flask and
  Gymnasium and Together AI in Cobra; AgentDiscover reads the Minecraft
  Bedrock protocol library as Amazon Bedrock and labels unrelated npm packages
  as the Vercel AI SDK; Agentic Radar reports the OpenAI Agents SDK in
  repositories that do not use it; ShadowScan reports Hugging Face in a
  user-agent parser whose data lists it.
* Four of 870 runs did not finish: cdxgen timed out on langchain4j-examples
  (its Java resolver) and crashed on pydantic; NuGuard timed out on
  pydantic-ai and crashed on awslabs/mcp. They count as misses.
* Timings were taken with six parallel workers on four CPUs and are
  indicative only; ShadowScan's slowest run was 1062 s on the Mastra
  monorepo and NuGuard hit the 1500 s limit twice.

## Limits

* One surface. ShadowScan's identity, SaaS, low-code, gateway, cloud, endpoint,
  network and runtime connectors are not exercised; neither are the endpoint
  and network modes of the other tools.
* Session-labeled ground truth, one labeler, one day's snapshot of public code.
* Tolerance rules are generous on purpose (lock files, test fixtures), which
  favours tools that enumerate everything.
* Timeouts and resource limits are those of the host that ran the benchmark.
