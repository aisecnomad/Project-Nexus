# Real-world repository benchmark

Thirty-four public repositories, pinned by commit in [`corpus.json`](corpus.json),
scored with the repo-surface tool cohort from
[`tools/benchmark/`](../../tools/benchmark/README.md). This corpus answers the
question that benchmark's README leaves open: the synthetic cases are
author-written, and *"real repositories, laptops and logs are messier."*

> **Read this first.** The corpus is real, but the labels are not independent:
> the benchmark author assigned them by inspecting each checkout, in the
> repository of one of the tools under test. The results show how each tool
> behaves on these 34 checkouts at these commits. They do not estimate field
> precision or recall, they are not an independent evaluation, and any
> ShadowScan lead is suspect until someone without a stake reruns the
> benchmark with their own corpus. See
> [docs/evaluation.md](../../docs/evaluation.md) for what ShadowScan accepts
> as evidence.

## Corpus

| Label | Count | What it holds |
|---|---|---|
| `agent` | 22 | Agent framework sources (LangGraph, AutoGen, smolagents, Pydantic AI, OpenAI Agents SDK, Mastra), agent apps (CrewAI examples, GPT Researcher, Swarm, BabyAGI, tool-calling chat apps), MCP reference servers, a GitLab-hosted MCP/ACP language server, coding-agent configuration collections, A2A samples, Bedrock-agent Terraform, SDK repos that carry root coding-agent configs and agent examples |
| `llm` | 3 | A pure chat UI, a 2023-era completions browser extension, an n8n starter kit whose exported flow is an LLM chain with no agent node |
| `none` | 9 | Clean libraries (click, express, F-Droid server tooling), look-alikes (NGINX *agent*, Minecraft *Bedrock* server, a user-agent parser naming AI crawlers), classic PyTorch examples, and two curated *awesome* lists that mention hundreds of AI products without using any |

Hosts: 32 GitHub, 2 GitLab (`fdroidserver`, `gitlab-lsp`). Clones are
`--depth 1` at the pinned commit; scanners see the checkout including its
`.git` directory, as an operator's clone would.

### Labeling rubric (fixed before any tool ran on the corpus)

A repository is labeled `agent` when inspection at the pinned commit finds at
least one of: (A1) an agent-framework dependency with first-party agentic
construction; (A2) MCP client or server code or configuration; (A3)
coding-agent configuration (`CLAUDE.md`, `AGENTS.md`, `.claude/`,
`.cursor/rules`, …); (A4) an A2A agent card or M365 declarative agent; (A5) a
low-code flow export containing an agent node; (A6) IaC provisioning a managed
agent; (A7) a first-party tool-calling loop over an LLM API. `llm` when LLM
SDK or API usage exists without any of A1–A7. `none` otherwise — names,
blocklists, and link lists are mentions, not use. Labels follow the evidence,
not the repository's age or marketing: two provider SDK repos label `agent`
because they ship root coding-agent configs and agent examples, and the n8n
starter kit labels `llm` because its exported flow holds no agent node (the
agent node appears only as a README link).

## Tools and how each is run

Everything runs through `tools/benchmark/realworld_run.py` in fresh network
and PID namespaces with a minimal environment: no tool can reach a vendor
API, OSV, an LLM, or a remote MCP server, and no tool sees credentials. The
timeout is 900 s per tool per repository. A checkout that is missing, at the
wrong commit, or dirty fails the run; after each tool the corpus is
re-verified and any checkout a tool wrote into is recorded and restored.

| Tool | Scored | Detection rule ("detected" when…) |
|---|---|---|
| ShadowScan (this checkout) | yes | unchanged from the synthetic benchmark: any finding, complete scan |
| ShadowScan, `max_file_size` 20 MiB | yes (post-change variant) | same rule and completeness requirement; added after the first scored run, in which 15 of 34 default-options scans ended incomplete (exit 3) on real repositories — scannable files over the 1 MB default, a credential-detection match timeout on a multi-megabyte markdown list, and lexical-analysis failures on three real `.tsx` files. Reported separately; the default row stands |
| Cisco AI BOM | yes | unchanged: `total_components` > 0 |
| agent-bom | yes | unchanged: non-baseline client/server, or a project entry on `ai-inventory` or bound to a model |
| AgentDiscover Scanner | yes | unchanged: any SARIF result, inventoried agent or MCP server |
| Agentic Radar (SplxAI) | yes (new adapter) | any framework scan's exported graph JSON contains an agent node; one scan per supported framework (crewai, langgraph, n8n, openai-agents, autogen); "didn't find any agentic workflow" is a clean zero |
| SafeDep vet (`code scan`) | yes (new adapter) | any `code_signature_matches` row tagged `ai` (SafeDep's own shadow-AI filter); a row tagged `agent` is the agent-tier signal |
| Naive grep baseline | yes (floor) | any of ~26 fixed regexes over paths and text contents matches; agent-tier patterns (frameworks, MCP, coding-agent configs, agent IaC) set `agentic` |
| Snyk Agent Scan | no | per the synthetic benchmark's calibration, `inspect` does not enumerate project configs from a directory; repository scanning would not be discovery |
| Cisco MCP Scanner | no | scans client configurations under a home directory and live servers, not repository checkouts |
| Open Shadow AI, AgentSonar, Shadow AI Detector | no | network-surface tools; no repository input |
| Claw-Hunter, AI-Detector | no | endpoint scripts keyed to home-directory locations |

Versions: the three reused tools at the commits pinned in
[`install_tools.sh`](../../tools/benchmark/install_tools.sh); Agentic Radar
0.14.1 from PyPI (with the `crewai`/`openai-agents` extras; the CrewAI
package itself is not installed, which skips optional agent metadata but not
agent-node detection); vet 1.20.0 from npm. The grep baseline's patterns were
written from the synthetic benchmark README's family list before the scored
run; it shares an author with ShadowScan and the labels, so treat it as a
calibration floor, not a competitor.

## Running it

```bash
python -m tools.benchmark.realworld_run \
  --corpus benchmarks/realworld/corpus.json \
  --corpus-dir /tmp/rw-corpus --tool-root /tmp/bench/tools \
  --results /tmp/rw-results --fetch
python -m tools.benchmark.score --results /tmp/rw-results --output summary.json
python -m tools.benchmark.realworld_report --results /tmp/rw-results --output REPORT.md
```

The interpreter must have ShadowScan's dependencies importable (the adapter
runs `python -m shadowscan` with this repository on `PYTHONPATH`), and the
tool root is laid out by `install_tools.sh` plus `venvs/radar` (PyPI
`agentic-radar`) and `bin/vet`.

## Results

Scored results live in
[`tools/benchmark/results-realworld/`](../../tools/benchmark/results-realworld/)
with the rendered [`REPORT.md`](../../tools/benchmark/results-realworld/REPORT.md).

## Limits

- **Author-labeled ground truth, conflict of interest.** Labels, corpus
  selection and two adapters were written by the ShadowScan maintainer's
  agent inside this repository. The labeling rubric deliberately mirrors
  evidence classes ShadowScan documents, and every tool under test —
  ShadowScan included — was built around the same public AI ecosystem these
  repositories come from. ShadowScan's regression corpora name the same
  frameworks (not these repositories' code, but the same technologies).
- **One commit per repository, one run per tool.** Repositories move daily;
  these numbers are a snapshot at the pinned commits on one machine.
- **Class imbalance.** 25 positives against 9 negatives; the `llm` tier has
  only three members, so agent-tier false-alarm intervals are wide. Wilson
  and bootstrap intervals in the report carry that uncertainty; read them,
  not the point estimates.
- **Repo surface only.** Nothing here measures endpoint, network, identity,
  SaaS, cloud or gateway discovery; the synthetic benchmark covers two of
  those surfaces, the rest are unmeasured.
- **Offline, degraded modes.** Tools run without network by design, so
  vendor-API enrichment (Cisco AI BOM's LLM tier, vet's cloud checks, radar
  prompt features) is off. The same constraint applies to every tool.
- **Binary detection.** A tool that flags a repository for a weak reason
  still counts as a detection; report quality, evidence and triage cost are
  not scored. The per-repository `items` counts in the results give a first
  noise signal only.
