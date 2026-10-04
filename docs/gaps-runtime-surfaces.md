# Runtime and platform coverage gaps

Status: design record. This document does not add a connector and does not
change detection. Findings below are a comparison of ShadowScan on `main`
(`d91edb332dce3c3d5b1a7dc139fb96225325072e`) against open-source shadow AI
agent discovery tools. Counts and severity in ShadowScan reports remain
heuristic evidence scores, not measured precision or recall.

## What ShadowScan already covers

ShadowScan ships 27 read-only connectors on six surfaces: code, identity,
gateway logs, low-code, SaaS, and cloud (AWS, GCP, Azure, OCI). Relevant
control-plane and protocol coverage already present:

| Asked surface | Present today | Evidence |
|---|---|---|
| MCP servers | Yes, as configuration and cloud resources, not as a live protocol probe | Code scanner matches MCP client/server configs; `cloud.aws` reports AgentCore Gateway MCP resources; JWT path classifies MCP-shaped endpoints |
| SDK calls | Yes, static | Signature packs match dependencies, imports, idioms, env vars, model IDs, and key shapes. This is not a dynamic call trace |
| Ollama | Yes, as a provider signature and gateway model alias | `provider.ollama` in provider signatures; gateway log mapper aliases `ollama` / `ollama_chat`. Local process or open-port proof is absent |
| AWS AgentCore | Yes, control plane | `cloud.aws` discovers AgentCore runtimes, gateways, memories, browsers, and code interpreters from live APIs or offline exports |
| Azure AI Foundry | Partial | `cloud.azure` discovers Foundry accounts, projects, and agents that the current API shape returns. Newer Foundry agent APIs are not fully covered |
| Gemini / Vertex / Agentspace | Partial | `cloud.gcp` covers Vertex AI Agent Engine, Dialogflow CX, Agentspace / Discovery Engine, and related IAM. There is no separate Gemini Enterprise control-plane connector |
| GenAI endpoints | Partial | Cloud connectors report configured endpoints (Vertex, OCI Generative AI, Azure OpenAI deployments). They do not probe arbitrary host:port listeners |

Static code signals identify candidates. Trusted runtime evidence is still
required before treating a finding as proof of execution.

## Confirmed gaps

Code search of this repository for Kubernetes, OpenShift, eBPF, and GGUF
workload discovery does not show a connector or signature pack for those
surfaces. JWT service-account classification is not a cluster inventory.

| Gap | Why it matters | Closest open-source reference | Proposed ShadowScan shape |
|---|---|---|---|
| Kubernetes workloads | Agents run as pods, jobs, and CRDs with no source in the scanned repos | DefendAI `agentdiscover` `monitor-k8s` (API plus optional Tetragon) | `runtime.kubernetes`: offline `kubectl`/`oc` JSON export first; optional read-only live list of pods, deployments, jobs, services. Incomplete if kubeconfig or RBAC is missing. Match images, env names, annotations, and MCP ports. Do not mutate the cluster |
| OpenShift | Routes, DeploymentConfigs, and OpenShift AI / RHOAI serving CRDs hide models outside vanilla Kubernetes | Same cluster API family, different CRDs | Same connector with an OpenShift profile: Routes, ImageStreams, `ServingRuntime`, `InferenceService`. No claim of OpenShift-specific auth until fixtures exist |
| Fleet endpoints | Developer laptops run Claude Code, Cursor, local MCP servers, and Ollama outside git | safedep `vet ai discover`; openafw `ai-agent-discovery` (EDR import) | `runtime.endpoint`: opt-in local config walk (MCP client paths, coding-agent dirs) and optional EDR/osquery export. Default off. Never upload configs |
| GGUF / local model artifacts | Weights on disk or llama.cpp/`llama-server` flags are invisible to import scanners | 7anX AgentScan and AgrusScanner detect serving stacks; they do not inventory files | Filename and flag signatures (`*.gguf`, `--model`, `Modelfile`) on the code surface, plus endpoint connector hits for Ollama (`11434`) and llama.cpp (`8080`) only when a runtime connector observes them |
| eBPF / process-to-domain proof | Ghost agents with no repo still open sockets to model APIs | AgentSonar, ThirdKey `agentsniff`, eunomia AgentSight, agentdiscover Tetragon | Not in this change. A kernel probe is a separate trust boundary (CAP_BPF, node DaemonSet, Tetragon/Tracee export). First step is an offline flow/export analyzer, not an in-repo eBPF program |
| Live MCP / Ollama protocol probe | Exposed MCP, A2A, and open LLM APIs on the network | 7anX AgentScan; AgrusScanner | Optional later connector that consumes a scanner export. Do not add active exploitation or unauthenticated tool invocation |

## Comparison set (open source)

Commercial products (Dash, Noma, Zenity, Reco, dope.security) were excluded.

1. [safedep/vet](https://github.com/safedep/vet) — endpoint AI tool inventory and SDK usage in source.
2. [Defend-AI-Tech-Inc/agent-discover-scanner](https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner) — static analysis, network heuristics, Kubernetes/eBPF via Tetragon, endpoint scan.
3. [ThirdKeyAI/agentsniff](https://github.com/ThirdKeyAI/agentsniff) — passive network and eBPF stream classification.
4. [knostic/AgentSonar](https://github.com/knostic/AgentSonar) — process-to-domain LLM traffic score.
5. [openafw/ai-agent-discovery](https://github.com/openafw/ai-agent-discovery) — EDR telemetry inventory.
6. [NYBaywatch/AgrusScanner](https://github.com/NYBaywatch/AgrusScanner) — network probe for local inference and MCP.
7. [7anX/AgentScan](https://github.com/7anX/AgentScan) — exposed MCP, A2A agent cards, open LLM APIs including Ollama and llama.cpp.
8. [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) agent-discovery — process, config, and GitHub scanners; Kubernetes shown as an extension point.
9. [Ankit-Uniyal/shadow-ai-scanner](https://github.com/Ankit-Uniyal/shadow-ai-scanner) — local endpoint AI apps and extensions.
10. [eunomia-bpf AgentSight](https://github.com/eunomia-bpf/agentsight) — eBPF LLM/agent observability without application instrumentation.

## Non-claims

- This repository does not ship an eBPF program, a Tetragon policy, or a host agent.
- AgentCore, Foundry, and Vertex coverage is control-plane observation inside the granted account scope, not proof the agent executed.
- Gemini Enterprise is not a dedicated connector; Agentspace / Discovery Engine coverage must not be described as full Gemini Enterprise inventory.
- Signature matches for Ollama do not prove a running `ollama serve` or a GGUF file on disk.
- No detection rate in this document is a field measurement.

## Implementation order

1. Offline Kubernetes/OpenShift export analyzer with fixtures and incomplete-scan semantics (ADR-002).
2. GGUF / llama.cpp / Modelfile filename and flag signatures, with evaluation corpus positives and negatives.
3. Opt-in endpoint config walker reusing MCP and coding-agent signature locations already known to the code scanner.
4. Offline eBPF or flow-log analyzer that accepts Tetragon, AgentSonar, or Hubble exports. No kernel module in-tree until a separate security review.
