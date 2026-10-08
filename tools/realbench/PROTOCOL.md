# Real-world shadow-AI discovery benchmark: protocol

This protocol was written and committed **before** the corpus was drawn and
before any tool ran on it. It is pre-registered in two steps, both visible
in the repository history:

1. **Design freeze** (this file, `frames/`, `purposive.json`, `sample.py`):
   the question, the sampling frames, the seeds, the quotas, the eligibility
   rules and the label definitions.
2. **Run freeze**, before the scored run: the drawn corpus, the frozen labels,
   and the tool adapters with their detection rules (`adapters.py`).

Any later change is listed under [Deviations](#12-deviations) with its reason.

## 1. Question and claims

How well do open-source tools find **generative-AI use** and **AI agents** in
real public repositories when every tool runs offline with its documented
defaults? How do they compare with each other and with two naive baselines?

The results describe this corpus only. The corpus is drawn from public
sampling frames that over-represent AI projects, so the results do not
estimate how common AI use is in any organisation's repositories, and they do
not estimate field precision for a particular estate. Section 8 reports
precision at stated prevalences so readers can translate the rates.

## 2. Unit and population

The unit is one public GitHub or GitLab repository at one commit: the default
branch head when the corpus was drawn, cloned with
`git clone --depth 1 --no-tags --single-branch`. Submodules and Git LFS objects
are not fetched. The commit SHA is recorded, so anyone can rebuild the corpus.

## 3. Sampling

### 3.1 Frames

`frames.py` snapshots each frame once; the snapshot is committed under
`frames/` (`index.json` lists every frame and its size).

| Stratum | Frames | Quota |
|---|---|---|
| `gh-agents` | 6 GitHub awesome lists of AI agents, each README pinned to a commit | 25 |
| `gh-mcp` | 3 GitHub awesome lists of MCP servers | 15 |
| `gh-genai` | 5 GitHub awesome lists of ChatGPT, LLM and generative-AI projects | 20 |
| `npm-ai` | npm registry search, 8 AI keywords, top 250 results each | 15 |
| `gitlab-ai` | GitLab.com public projects for 12 AI topics, 300 most recently active each | 20 |
| `gh-general` | 9 general-purpose GitHub awesome lists (Python, Go, Node.js, self-hosted, Rust, Java, PHP, Ruby, .NET) | 20 |
| `npm-general` | npm registry search, 7 general keywords | 10 |
| `gitlab-general` | GitLab.com public projects for 13 general topics | 15 |

A stratum is a sampling bucket, not a label. A repository drawn from an AI
list can be labeled `none`, and one drawn from a general list can be labeled
`agent`.

### 3.2 Draw

`sample.py` performs the draw. Calibration comes first: seed `1`, two
repositories per stratum. They are used only to make each tool run and to
read its report, and their owners are excluded from the scored draw. The
scored draw then uses seed `20261008`, strata in the table's order. Within a
stratum, a frame is chosen uniformly at random and then a candidate uniformly
from that frame, without replacement, until the quota is met. This two-stage
draw keeps large lists (for example 2,918 links in the Go list) from crowding
out small ones.

A candidate is **eligible** when:

- it is not excluded (the evaluated tools, this repository, the three probe
  repositories used to write adapters, and the frame lists themselves);
- its owner (GitHub user or organisation, GitLab top-level namespace) has no
  other repository in the corpus. This caps clustering: GitLab topics are
  dominated by a few prolific accounts;
- the shallow clone succeeds within 600 s;
- the checkout is at most 250 MiB and 25,000 files (excluding `.git`);
- its tree differs from every accepted tree (mirrors are dropped);
- it contains at least one source or infrastructure file (the extension list is
  in `sample.py`). This drops lists, documentation-only repositories and
  archives.

Every attempt and its outcome is logged (`draw-log.jsonl.gz`). Accepted
repositories receive shuffled, neutral identifiers (`r001`…), so a directory
name reveals nothing about the stratum.

### 3.3 Purposive sets

`purposive.json` adds two hand-picked sets, each entry with a written reason:

- **Hard negatives** (34): repositories that share vocabulary with AI agents or
  AI services without being expected to use generative AI. Examples: CI,
  monitoring and SSH agents; user-agent and AI-crawler lists; secret scanners
  with AI-key rules; OpenAI-branded reinforcement-learning code; and name
  collisions such as AWS Copilot, OpenStack Mistral, Goose migrations, the
  Gemini protocol and exchange, Minecraft Bedrock, Opus, Sonnet, and
  MCP23017 chips.
- **Configuration positives** (10): repositories whose AI use sits in
  infrastructure, deployment or workflow files. Examples: n8n and Dify exports,
  Terraform and CDK for Bedrock and Azure OpenAI, Ollama and vLLM deployments,
  and a CI agent action.

Purposive entries are not replaced when ineligible. Their recorded expectation
guided selection only; they are labeled blind like every other repository.

## 4. Labels

### 4.1 Scope of evidence

Only **first-party content at the pinned commit** counts: source, notebooks,
tests, examples, scripts, configuration, infrastructure-as-code, workflow
exports and CI definitions. Excluded: vendored third-party code (`vendor/`,
`third_party/`, committed `node_modules/`, `site-packages/`), minified
third-party bundles, transitive entries that appear only in lockfiles, prose
(Markdown, docs pages, code blocks in documentation), and commented-out or
explicitly disabled code.

### 4.2 Primary label (exactly one)

**`agent`**: the repository builds, configures or deploys an AI agent or an
agent tool integration. Any one of:

- **A1, framework agent:** code constructs or runs an agent with an agent
  framework or SDK. Examples: LangChain or LangGraph agents, CrewAI, AutoGen
  or AG2, OpenAI Agents SDK, Claude Agent SDK, Google ADK, Pydantic AI,
  smolagents, LlamaIndex agents, Semantic Kernel agents or automatic function
  calling, Mastra, Strands, Agno, Haystack agents, DSPy ReAct, Spring AI or
  LangChain4j tool calling, LangChainGo agents, and the Vercel AI SDK with
  tools and multi-step execution.
- **A2, tool loop:** code sends tool or function definitions to a model and
  executes the calls the model selects, at least one dispatch from model
  output.
- **A3, MCP:** code implements a Model Context Protocol server or client.
- **A4, agent configuration:** committed configuration that gives an AI agent
  tools, such as MCP client configuration listing servers (`.mcp.json`,
  `.cursor/mcp.json`, `.vscode/mcp.json`, `mcpServers` blocks).
- **A5, agent workflow or infrastructure:** workflow exports with agent nodes
  (n8n AI Agent, Dify agent apps, Flowise or Langflow agent flows) or
  infrastructure that provisions agents (Bedrock Agents, Azure AI agents,
  Vertex AI agents, Microsoft 365 declarative agents with actions).
- **A6, CI agent:** a CI workflow that runs an AI agent with repository access
  (for example a Claude Code, Codex or Gemini CLI action).

**`llm`**: not `agent`, but first-party content uses a generative or
foundation model. Any one of:

- **L1, call:** code calls a hosted or local LLM or foundation-model API or
  runtime: chat, completion, messages, generation, embeddings, image, speech
  or transcription models, through an SDK, an HTTP endpoint, Ollama,
  llama.cpp, vLLM, LM Studio, Hugging Face generative pipelines or diffusers.
- **L2, configured service:** configuration provisions or wires a generative
  model service for the project: model-serving containers, Helm charts,
  LiteLLM proxy configuration, or infrastructure for Azure OpenAI, Bedrock
  model access or Vertex AI endpoints.
- **L3, declared dependency:** a manifest of the project declares a direct
  dependency on a generative-AI-specific SDK or framework, even if no call site
  is found.

**`none`**: neither of the above. The following are `none` unless they also
meet an A or L criterion:

- classical or non-generative machine learning (classification, detection,
  reinforcement-learning "agents");
- prose about AI;
- AI crawler or AI-domain blocklists;
- secret-scanner rules or credential checks that call a provider API without
  generating anything (for example listing models to verify a key);
- user-agent strings;
- non-AI uses of "agent", "MCP", "Copilot", "Gemini", "Bedrock", "Mistral",
  "Goose", "Opus" or "Sonnet";
- browser styling of an AI product's web page that sends no input to a model.

### 4.3 Attributes

- `assistant_artifacts`: the repository carries AI coding-assistant files
  (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/`,
  `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`,
  `.github/instructions/`, `.claude/`, `.codex/`, `.gemini/`, `.aider*`,
  `.continue/`, `.roo/`, `.kiro/`, `.junie/`).
- `ml_only`: a `none` repository that contains classical or non-generative ML.
- `subtypes`: the A and L criteria met.
- `traits`: vocabulary collisions present in a `none` repository.
- `evidence`: up to five `path:line` references with the criterion each
  satisfies and a short, credential-redacted excerpt.
- `confidence`: `high`, `medium` or `low`.

### 4.4 Analysis populations

- **Primary population:** all scored repositories except **assistant-only**
  repositories (label `none` with `assistant_artifacts`). Whether an AI
  coding-assistant instruction file is "AI use" is a policy choice, not a
  fact about the repository, so those repositories are reported separately.
- **Footprint population** (secondary): all scored repositories, with
  assistant-only repositories counted as positive.

## 5. Annotation

Two annotators label every scored repository independently. Both are AI
agents (Claude subagents). **This is not human review.** They use different
search strategies so that their errors are less correlated:

- **Annotator A** starts from an evidence packet built by `packet.py`: the
  file tree, manifests, the README head, AI-assistant files, and matches for a
  broad, published vocabulary of AI SDK, framework, protocol, host and
  configuration identifiers. A then opens files to confirm, and must look
  beyond the packet.
- **Annotator B** gets no packet. B explores the checkout with ordinary
  read-only shell tools.

Both work from the rubric above. Both are instructed not to open this
repository's scanner code, signatures, the earlier synthetic benchmark, or
any tool output; no tool has run on the scored corpus at that point. Each
records its label, attributes and evidence in a ledger under `labels/`.

**Disagreements** on the primary label or `assistant_artifacts` go to a third
AI adjudicator. The adjudicator sees both rationales and the checkout, and
writes the final label with a reason. Agreement before adjudication is
reported as raw agreement and Cohen's κ, for the three-class label and for
each binary task. The frozen labels are `labels/labels.json`.

## 6. Tools and run protocol

Every tool that can scan a repository directory is included:

- ShadowScan from this repository, at the commit of the run freeze;
- the open-source discovery tools that accept a directory;
- two naive baselines:
  - **keyword grep:** a short list of provider and framework names;
  - **manifest dependencies:** a fixed list of generative-AI packages in
    dependency manifests.

Tools that inspect only a live machine or network traffic are out of scope.
Each tool is pinned to a commit or release in `install_tools.sh`.

Every run:

- has no network (fresh network namespace) and no host processes (fresh PID
  namespace);
- sees the checkout through a read-only bind mount;
- gets a minimal environment with an empty `HOME`;
- runs the tool's documented defaults. A flag is added only where the tool
  requires one to scan a directory or to emit machine-readable output, and
  each such flag is recorded in `adapters.py`;
- has a 900 s timeout.

A crash, timeout or incomplete scan is an **error**. In primary metrics an
error is a wrong answer: a miss on a positive, and a false alarm on a
negative, because a failed scan cannot certify a repository clean. Metrics
over completed scans only are reported as a secondary analysis.

A seeded 10% subset is run a second time per tool to measure run-to-run
flips.

## 7. Detection rules

Each adapter maps the tool's own report to three values, fixed in
`adapters.py` at the run freeze:

- `detected`: the report contains at least one AI-related item, as that tool
  defines it;
- `agentic`: the report contains at least one item the tool classifies as an
  agent, agent framework, MCP server or client, or agent configuration. This
  is `null` for tools that do not separate agents from other AI use;
- `paths`: the repository-relative files the report cites as evidence.

The rules come from each tool's documentation and its report schema, checked
on calibration repositories only. Raw reports stay outside the repository
(they can quote third-party code and committed credentials); their SHA-256 is
recorded.

## 8. Analyses

### 8.1 Primary

On the primary population, for **T1, GenAI detection** (positive = `agent`
or `llm`) and **T2, agent detection** (positive = `agent`; tools with
`agentic` only), each tool reports:

- recall, specificity and precision with Wilson 95% intervals;
- F1 and the Matthews correlation coefficient (MCC), with 2,000-sample
  bootstrap intervals;
- balanced accuracy;
- error count.

MCC is the headline because it uses all four cells and does not reward
flagging everything.

### 8.2 Paired comparisons

Each tool is compared with ShadowScan, and each tool with the keyword-grep
baseline, by an exact McNemar test on per-repository correctness. Holm's
correction is applied within each family of comparisons.

### 8.3 Secondary

- Completed scans only.
- The footprint population (§4.4).
- `ml_only` repositories excluded.
- Each tool's detection rate on assistant-only repositories.
- Positive predictive value at prevalences of 1%, 5% and 20%, computed from
  recall and specificity.

### 8.4 Breakdowns (exploratory)

- by stratum;
- by A and L subtype;
- by hard-negative trait;
- by host;
- by dominant language;
- by size tercile;
- median and 90th-percentile run time;
- determinism (§6).

## 9. After the run: blind adjudication and localisation

### 9.1 Label adjudication

Some repositories have a tool verdict on T1 or T2 that disagrees with the
frozen label. For each of them, an AI adjudicator receives:

- the checkout;
- the frozen label and its evidence;
- the union of files cited by all tools, with tool names removed.

The adjudicator decides whether the label stands. Results are reported on
both the **frozen labels** and the **adjudicated labels**, side by side, with
every changed label and its reason. Adjudication can only revisit
repositories some tool disagreed with. A label that every tool and both
annotators got wrong stays wrong, as in any pooled evaluation.

### 9.2 Localisation

A detection is only as useful as the evidence it points to. Two measures:

- **Evidence overlap:** the share of a tool's true-positive repositories where
  at least one cited file is among the annotators' evidence files. This is a
  lower bound, because annotator evidence lists are incomplete.
- **Cited-file precision:** for each tool, up to 25 cited files sampled at
  random from its detections (seeded). A blind AI adjudicator judges whether
  each file meets an A or L criterion (or holds an assistant artifact) without
  being told which tool cited it.

## 10. Data handling

The repository stores:

- frame snapshots;
- the corpus manifest (URL, commit, tree, size);
- labels with short, credential-redacted excerpts;
- normalised per-tool results (status, verdicts, counts, cited paths,
  timings);
- the SHA-256 of each raw report.

It stores no third-party source files and no raw tool reports. Committed
credentials found in scanned repositories are never copied. Rebuild the
checkouts with `fetch.py`.

## 11. Conflicts of interest and limits

- ShadowScan is developed in this repository. The protocol, sampler, adapters
  and baselines were written here, with AI assistance. The design freeze and
  the run freeze limit, but do not remove, the room for choices that favour
  it.
- Annotation and adjudication are by AI agents, not independent humans.
  Agreement statistics measure consistency, not truth.
- Frames are public lists and registries. They over-represent popular,
  open-source and AI-themed projects relative to private enterprise code.
- The size cap and shallow clone exclude large monorepos, submodules and LFS
  content.
- Several tools are designed to use the network or an LLM (for example a
  hosted analysis service or an LLM classifier tier). Offline, they run in a
  reduced mode, which is reported per tool. This measures what a tool does
  without sending repository content to a third party; it does not measure a
  tool's full online capability.
- Binary repository verdicts ignore finding quality beyond the localisation
  measures in §9.2.

## 12. Deviations

None so far.
