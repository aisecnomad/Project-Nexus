# Shadow-AI discovery head-to-head benchmark

This harness runs ShadowScan and ten other open-source shadow-AI or
agent-discovery tools on the same seeded, randomly generated cases and scores
each tool only on the input types it says it handles.

> **Read this first.** The cases are synthetic and were written in this
> repository by the ShadowScan maintainers, whose author had read ShadowScan's
> documentation. The results show how each tool behaves on these 900 generated
> inputs. They do not estimate field precision or recall, they are not an
> independent evaluation, and they do not replace a human-reviewed holdout
> ([docs/evaluation.md](../../docs/evaluation.md)). Treat any ShadowScan lead
> as suspect until someone without a stake reruns the benchmark with their own
> templates.

## Pre-registration

These items were fixed and committed before any tool, ShadowScan included,
ran on the scored corpus:

- Generator: `generate.py` and the three `*_cases.py` modules, seed
  `20261006`, 300 cases per surface.
- The resulting corpus has SHA-256
  `b757b2ac2293dba05e961a11ef9f49abb66e97aea1ab5edb9d9ccb28d2319e63` and
  generator digest
  `35e2e46b6b1f2c0fe37c99e09310403e13f6fc28347d22e6b6104b64cf71e754`.
  Regenerate it with `python -m tools.benchmark.generate --output corpus.json`
  and check the hash.
- The detection rule for each tool is written in `adapters.py` and summarized
  below.
- Calibration uses a separate corpus (seed `1`, 10 cases per surface). Changes
  that calibration forces on an adapter (wrong flag names, report key names)
  are committed separately, and the commit message explains each one. They
  never change a detection rule after scored results have been seen.

## Corpus

| Surface | What a case is | Agent | LLM-only | None |
|---|---|---|---|---|
| `repo` | A source checkout of 1–9 files, sometimes nested in a monorepo, with README and noise files | 135 | 45 | 120 |
| `endpoint` | A developer home directory: ordinary dotfiles plus at most one AI artifact, in each client's documented Linux user-scope location | 135 | 45 | 120 |
| `network` | 8–40 egress connection records from one workstation over a 0.5–8 h window | 135 | 45 | 120 |

Each label slot's family is drawn uniformly at random from that surface's
pool. Names, models, tools, layout and noise are also randomized. Families:

- **Repo agent (20):** LangGraph (prebuilt and StateGraph), LangChain agents,
  CrewAI (code and YAML), AutoGen, OpenAI Agents SDK (Python and TS), Pydantic
  AI, smolagents, Claude Agent SDK, Google ADK, LlamaIndex, a hand-written
  OpenAI/Anthropic tool loop, Vercel AI SDK tool loop, Mastra, LangGraph.js,
  LangChainGo, Semantic Kernel (C#), project MCP configs, an n8n AI Agent
  workflow, and a Terraform Bedrock agent.
- **Repo LLM-only (8):** single OpenAI, Anthropic, Gemini, Ollama, LiteLLM and
  Vercel AI calls; a raw `fetch` to the Anthropic API.
- **Repo none (14):** insurance agents with supervisors, a user-agent parser
  naming AI crawlers, Datadog/Zabbix agents, a README AI-use policy,
  commented-out SDK code, scikit-learn, an egress blocklist of AI domains, a
  travel-booking "agent" with `run_tools`, a Gemini crypto-exchange client,
  a Minecraft Bedrock server, a regex chatbot, a plain web app, Minecraft
  Coder Pack ("MCP") mappings, and a contact-centre `invoke_agent` client.
- **Endpoint agent (14):** Claude Desktop, Cursor, VS Code, Windsurf, Gemini
  CLI, Codex, Kiro and Amazon Q MCP configs; Claude Code MCP, subagent or
  skill; OpenClaw state; Cline extension; Continue; Aider; Goose.
- **Endpoint LLM-only (5):** Copilot extension, Ollama model store, LM Studio
  GGUF, an AI browser extension, AI CLI commands in shell history.
- **Endpoint none (6):** plain dotfiles, infra dotfiles with a host named
  `claude-bastion`, Minecraft `mcp.json`, Datadog agent, non-AI browser
  extensions, a real-estate "agent portal" project.
- **Network agent (9):** programmatic bursts to OpenAI, Anthropic, Bedrock
  (runtime and InvokeAgent), Azure OpenAI, OpenRouter, Gemini API, a
  private-address vLLM server, remote MCP sessions, an OpenClaw gateway.
- **Network LLM-only (3):** consumer chat sites in a browser, one or two calls
  to Mistral, Groq, Together, DeepSeek or Cohere, loopback Ollama.
- **Network none (5):** ordinary SaaS traffic, Gemini crypto exchange,
  look-alike hosts (`anthropologie.com`, `openaire.eu`, `hivebedrock.network`),
  long-lived programmatic streams shaped like LLM streaming, Datadog agent
  telemetry.

Each network record carries the union of the fields that proxies, gateways
and flow sensors expose. Each adapter renders only the fields its tool's
native format holds:

- ShadowScan gets a JSON access log with host, path, user agent and user.
- Open Shadow AI gets squid lines with the full URL (SSL-bump view) and no
  user agent.
- Shadow AI Detector gets URL, user, department and byte counts.
- AgentSonar gets the process, SNI or DNS name, and the flow shape. It never
  sees paths.

## Tools and how each is run

All tools run in a fresh network namespace (`unshare -n`), so none of them
can reach a vendor API, OSV, an LLM or a remote MCP server. No tool is
configured with an allowlist, a known-agent list or an inventory.

| Tool | Upstream commit | Surfaces scored | Run as | "Detected" when |
|---|---|---|---|---|
| ShadowScan | this checkout | repo, endpoint, network | `code.filesystem` on the tree; `gateway.logs` on the access log | the report has any finding and the scan is complete (exit 3 or an incomplete status counts as an error) |
| Cisco AI BOM | `8d7bec0` | repo, endpoint | `cisco-aibom analyze`; the required LLM endpoint is unreachable, so Tier 3 degrades to deterministic candidates, which the report keeps as `unreviewed` | the report's `total_components` is above zero |
| agent-bom | `26ed7c1` | repo, endpoint | `agent-bom scan --no-scan --offline`; repos with an empty `HOME`, endpoints by auto-discovery with `HOME` set to the case | a client agent or MCP server absent from an empty-home baseline, or a project entry on the `ai-inventory` surface or bound to a model |
| AgentDiscover Scanner | `a3756cd` | repo, endpoint | `agentdiscover scan --format sarif` plus `agentdiscover audit --skip-layers 2,3,4,5` (Layers 2–5 need live hosts, clusters or cloud accounts) | any SARIF result, inventoried agent or MCP server |
| Snyk Agent Scan | `69ce32c` | endpoint | `snyk-agent-scan inspect --json` with `HOME` set to the case (no analysis upload) | any MCP server or skill listed |
| Cisco MCP Scanner | `f817899` | endpoint | `mcp-scanner --scan-known-configs --analyzers yara`, `HOME` set to the case | any server it scanned or enumerated from a config under the case home |
| Open Shadow AI | `715044e` | network | the project's squid parser and catalog matcher, in-process (the full product needs PostgreSQL and ClickHouse) | any record matches a catalog item |
| AgentSonar | `8658b67` | network | `agentsonar classify` on replayed TLS and streaming events | any process–domain pair scores > 0.3 (the cut-off in the project's own examples) or matches a known agent |
| Shadow AI Detector | `f2bd5ab` | network | the project's `assessEvent()` with an empty sanctioned list | any event matches the endpoint catalog |
| Claw-Hunter | `4125c4f` | endpoint | `claw-hunter.sh --json`, `HOME` set to the case | the report shows an OpenClaw CLI, config, workspace, running gateway, launch agent or app |
| AI-Detector | `fa673ef` | endpoint | `detect-shadow-ai.sh` as an unprivileged user, JSON report, network module off, `HOME` set to the case | any finding that does not also appear with an empty home (host noise) |

Every tool runs in fresh network and PID namespaces with a minimal
environment, so it sees no network, no host processes and no credentials.

### Calibration changes

The seed-1 calibration corpus (10, then 40 cases per surface) exposed these
problems. Each fix is limited to running the tool or reading its report; no
detection rule was relaxed after scored results were seen.

- **All tools:** a fresh PID namespace was added. AI-Detector listed the
  benchmark host's own processes, which are not case evidence.
- **Cisco AI BOM:** the report stores components as a mapping, so the count
  now comes from `summary.total_components`. Flags that fail the unreachable
  LLM fast were added; they keep the same deterministic candidates.
- **agent-bom:** the report always contains a pseudo-agent for the scanned
  project, whose "servers" are its package manifests, and an `mcp-cli`
  installed on the host. Both are excluded. Host entries are removed with an
  empty-home baseline, as for AI-Detector.
- **AgentDiscover:** MCP and inventory detection live in `audit`, not `scan`,
  so both run. `scan` writes no SARIF for a tree without Python or JavaScript
  files and says so; that is a clean result, not an error.
- **Snyk Agent Scan:** given a directory, `inspect` does not enumerate project
  configs. It finds them only from client-recorded workspaces or an explicit
  file path, which would not be discovery. Repository cases are therefore not
  scored for it.
- **Cisco MCP Scanner:** `--stdio-timeout` crashes this build
  (`UnboundLocalError`), so the timeout goes through
  `MCP_SCANNER_STDIO_TIMEOUT`. With no network every server fails to start
  and is left out of the JSON, so the servers named in its log as scanned
  from a case config count as found.
- **Open Shadow AI:** its logger writes to stdout before the result, so the
  last JSON line is read.
- **Network renderers:** URLs omit default ports, as proxy logs do.
- **Claw-Hunter and AI-Detector:** the JSON follows a banner. The script is
  copied where the unprivileged user can read it, and PIDs are ignored when
  comparing findings with the baseline.

The upstream checkouts were taken on 2026-10-06.
[`install_tools.sh`](install_tools.sh) installs each tool at its pinned commit
in its own virtual environment or build directory under a tool root, in the
layout `adapters.py` expects. AgentSonar's Linux build also needs libpcap
headers. The script downloads and installs third-party code, so review it and
run it in a disposable machine or container.

```bash
python -m tools.benchmark.generate --output /tmp/bench/corpus.json   # check the SHA-256 above
bash tools/benchmark/install_tools.sh /tmp/bench/tools
python -m tools.benchmark.run --corpus /tmp/bench/corpus.json \
  --tool-root /tmp/bench/tools --results /tmp/bench/results --workers 4
python -m tools.benchmark.score --results /tmp/bench/results --output /tmp/bench/summary.json
```

## Metrics

- Positive means the label is `agent` or `llm`.
- Per tool and per surface: TP/FP/FN/TN, recall, specificity and precision
  with Wilson 95% intervals; F1 with a 2,000-sample bootstrap interval;
  balanced accuracy, MCC and median seconds per case.
- **Agent tier:** for tools whose output separates agent findings from plain
  usage, recall on `agent` cases and the false-alarm rate on cases without an
  agent.
- **Estate recall:** recall over all 900 cases, counting unsupported surfaces
  as misses.
- **Paired comparison:** exact McNemar test against ShadowScan on the cases
  both tools support.
- An `error` (crash, timeout, incomplete scan) counts as "not detected" and is
  also reported separately.

## Limits

- **Synthetic, author-written corpus.** Real repositories, laptops and logs
  are messier.
- **Conflict of interest.** The harness was written in the ShadowScan
  repository. Families came from public SDK documentation and client config
  locations, not from ShadowScan's signature packs. Some hard negatives echo
  categories already in ShadowScan's regression corpora (blocklists, insurance
  agents, crypto Gemini).
- **Partial coverage for several tools.** Network sensors are replayed from
  records rather than observed live. Endpoint tools see a file tree, not
  processes, sockets, packages or browser history. Cisco AI BOM runs without
  its LLM classifier. Open Shadow AI runs without its database and
  correlation.
- **Binary detection only.** A tool that reports the right case for the wrong
  reason still counts as a detection; a missing finding with an otherwise
  useful report still counts as a miss.
