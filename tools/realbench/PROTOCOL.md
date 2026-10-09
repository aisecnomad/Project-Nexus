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

*Run freeze:* annotator A ran on Claude Opus and annotator B on Claude Sonnet,
so the two differ in model as well as strategy; the adjudicator ran on
Claude Opus. A worked in batches of 12–13 consecutive identifiers and B in
batches of 9–10 identifiers taken with a stride of 19, so no A batch matches a
B batch. Each annotator saw only its own packets.

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

*Run freeze:* the tools and how each one is run.

| Tool | Version | Run on a checkout |
|---|---|---|
| ShadowScan | this repository at the run-freeze commit | `scan` with one `code.filesystem` connector, defaults, `use_git: false` |
| Cisco AI BOM | `cisco-ai-defense/aibom` `8d7bec0` | `analyze --output-format json`; its required LLM endpoint is unreachable offline, so the LLM tier keeps its deterministic candidates |
| agent-bom | `msaad00/agent-bom` `129615f` (0.108.2) | `scan --no-scan --offline -f json`: inventory only, no vulnerability lookups |
| AgentDiscover Scanner | `Defend-AI-Tech-Inc/agent-discover-scanner` `a3756cd` | `scan --format sarif`, then `audit --skip-layers 2,3,4,5` (the skipped layers need live hosts, clusters or cloud accounts) |
| SafeDep vet | `safedep/vet` v1.20.0 `568cb0e` | `ai discover --scope project`, then `code scan` (AI-tagged signatures); telemetry disabled |
| agentguard | `ak2dev/agentguard-v1` `6d4f75d` | `scan --config <empty policy> -f json` |
| cdxgen | `@cyclonedx/cdxgen` 12.8.5 | `-t ai -t mcp -t ai-skill -r --no-install-deps`, with license fetching off and an empty command allow-list so it runs nothing inside the checkout |
| Keyword grep | this repository | case-insensitive `rg -l` over every file except `.git` |
| Manifest dependencies | this repository | direct dependencies in manifests outside vendored directories |

Considered and excluded:

- Snyk Agent Scan, Cisco MCP Scanner, Claw-Hunter and AI-Detector inspect a
  machine's client configuration, processes or live MCP servers, not a
  directory.
- AgentSonar, Open Shadow AI and Shadow AI Detector read network traffic or
  proxy logs.
- PatronAI has no offline repository scanner: its code hook and repository
  discovery upload to an S3 bucket for server-side analysis.

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

*Run freeze:* an adapter reports `ok` (a complete report), `partial` (a report
the tool itself marks incomplete, such as ShadowScan's exit 3) or `error` (no
usable report). The primary analysis treats `partial` as an error, as
pre-registered. See §12 for the added secondary analysis.

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
- *Added at the run freeze:* the evidence rule (an item found by an
  incomplete scan counts as a positive verdict), and T2 with repositories
  that carry AI coding-assistant files removed from the negatives (§12).

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

Every change below was made before any tool ran on the scored corpus.

1. **Partial scans.** Calibration showed that ShadowScan and others report
   some scans as incomplete while still listing findings. The primary rule
   is unchanged: an incomplete scan is an error and a wrong answer. The
   *evidence rule* is added as a secondary analysis. It counts an item found
   by an incomplete scan as a positive verdict, because incompleteness
   undermines only a negative conclusion. The rule was added after seeing
   calibration output in which ShadowScan reported the most incomplete scans,
   so it is reported only as a secondary analysis.
2. **T2 without assistant-file negatives.** Several tools classify AI
   coding-assistant files (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules`) as
   agent configuration, while the rubric does not label them `agent`. A
   secondary T2 analysis drops repositories with such files from the T2
   negatives, so that this definitional difference does not decide the
   comparison.
3. **Annotator workspace.** In the first wave, annotators shared one scratch
   directory for helper files. One annotator's helper script was overwritten
   by another's, and one label line landed in the wrong batch file. The owner
   removed it, the label remained in the right file, and every batch file was
   checked for foreign and missing identifiers. Two B annotators had written
   draft labels for twelve repositories into that shared directory. Every
   later annotator received a private working directory. The drafts were
   moved out of reach once their authors finished. The audit
   (`labels/annotation-audit.json`) scanned all 3,119 tool calls of the 34
   annotator runs for access to the other side's packets, labels, drafts or
   working directories, to the scanner's source, to tool output and to the
   corpus manifest, and found none. In the shared directory, each annotator
   touched only its own helper files.
4. **Tool set.** The run uses agent-bom at `129615f`, newer than the commit
   pinned in the synthetic benchmark, and adds SafeDep vet, agentguard and
   cdxgen as directory scanners. PatronAI was examined and excluded (§6).
5. **Calibration fixes to adapters.** On the calibration repositories only:
   - agent-bom's code-level findings were moved from the field the first
     draft read to `ai_inventory`. Its tool definitions are counted, and
     its prompt and guardrail heuristics are not: they fired on non-AI
     repositories, and agent-bom's own AI-BOM summary counts neither.
   - agent-bom creates a Terraform "agent" for any provider. It is
     counted only when it carries AI resources.
   - `--kill-child` was added to the runner after a timed-out tool kept
     running.
   The adapter docstrings record each rule.

Label summary at the run freeze: 77 `agent`, 26 `llm` and 80 `none`. 12 of
the `none` are assistant-only, which leaves 171 repositories in the primary
population. Before adjudication, the annotators agreed on 179 of 183
three-class labels (κ 0.96) and on every `assistant_artifacts` value. The
adjudicator resolved the four disagreements.

## 13. Post-change holdout (pre-registered before its draw)

The first run found ShadowScan's analysis accurate on the scans it finished
and its coverage policy the main weakness. ShadowScan was then changed using
that run's repositories (see `CHANGELOG.md`, "October 8 benchmark
remediation"). Re-scoring those repositories would measure fit, not
generalisation, so the changes are measured on a fresh holdout. Everything
in this section was committed before the holdout was drawn.

### 13.1 Draw

`holdout.py` runs the scored draw of §3.2 on the same frame snapshot, with
the same strata, quotas (140 sampled repositories), eligibility rules and
two-stage selection, and with seed `HOLDOUT_SEED = 20261009`. Every
repository and every owner of `corpus.json`, `calibration.json` and
`purposive.json` is excluded. There are no purposive sets: the original hard
negatives cannot be reused, and picking new ones by hand after the first
results would not be blind. Specificity therefore comes from the sampled
strata alone. Identifiers are `h001`–`h140`.

### 13.2 Labels

The rubric (§4) and annotation process (§5) are unchanged: annotator A on
Claude Opus with evidence packets, annotator B on Claude Sonnet without, in
batches that never pair up, and a third AI adjudicator for disagreements.
Annotators see no tool output; each works in a private directory. The labels
are frozen and pushed before any tool runs on the holdout. These are AI
annotations, not human review.

While the labels are produced, ShadowScan's development continues on other
repositories only. Nobody opens a holdout checkout to change ShadowScan, and
its code is frozen at a stated commit before the run.

### 13.3 Run

Every tool of §6 runs on the holdout with the same versions, adapters,
isolation and 900 s timeout; ShadowScan runs at the code-freeze commit. One
adapter rule changes, because ShadowScan now states it: its `agentic` value
is primarily any finding with `metadata.agentic` true (the classification
the scanner documents), and secondarily the original kind list of §7.
`detected` is unchanged: any finding.

### 13.4 Analyses

As §8 on the holdout: the strict rule (an incomplete or failed scan is a
wrong answer) is primary; completed scans and the evidence rule are
secondary. For ShadowScan, the incomplete rate and its causes are reported
next to the first run's. The first run's numbers and the holdout's come from
different samples, so the difference between them is described, not tested.
A post-change ShadowScan run on the original corpus is reported as an
in-sample check only, because the fixes were derived from it.

Targets stated before the draw, reported as met or not met and never
adjusted afterwards: incomplete scans at most 5%; T1 MCC at least 0.80; T2
MCC at least 0.75; T1 specificity at least 0.97.

### 13.5 Deviations

1. **Empty repository in the draw.** The first holdout draw stopped at a
   candidate that cloned without any commit: the sampler's clone step could
   not read its `HEAD`. The step now rejects such a repository as `empty`,
   which §3.2's eligibility rule already requires, and the draw was restarted
   from scratch with the same seed. The first attempt produced no manifest.
2. **Late start of seven B batches.** B08–B14 were started after the other
   22 batches, when the omission was noticed, with the same prompt, inputs
   and model as B01–B07. Their annotators could not see the earlier labels
   (see the audit below).
3. **No adjudication.** The two sides agreed on every label and assistant
   flag (140 of 140, κ = 1.0), so the adjudication step had nothing to
   decide. Agreement this complete is unusual but not implausible: at the
   first run's disagreement rate (4 of 183) it happens about one time in
   twenty. The sides found their evidence independently: per repository,
   the cited paths overlap by 0.63 on average (first run 0.61), and 13
   repositories have identical evidence sets (first run 14 of 183). The
   audit (`labels-holdout/annotation-audit.json`) scanned all 1,433 tool
   calls of the 24 annotator runs for access to the other side's packets,
   labels or working directories, to other batches, to the scanner's
   source, to tool output, to the manifests and to broad listings of shared
   directories, and found none. Both annotators are Claude models, so a
   shared blind spot would agree with itself; the post-run adjudication
   (§9) still reviews every repository where a tool disagrees.

4. **Adapter rule, as implemented.** §13.3 is implemented in
   `adapters.shadowscan_agentic`: a ShadowScan row's `agentic` is true when
   any finding's `metadata.agentic` is true. The row also keeps the first
   run's kind-list value as `agentic_kinds`; the secondary analysis scores a
   copy of the ShadowScan rows with `agentic` replaced by it. Other tools'
   rows are unchanged.

Label summary at the holdout freeze: 67 `agent`, 28 `llm` and 45 `none`.
10 of the `none` are assistant-only, which leaves 130 repositories in the
primary analysis.
