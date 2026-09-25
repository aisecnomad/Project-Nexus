# Detection evaluation and production canaries

The evaluation tool creates one isolated temporary repository per labeled case.
It never clones a repository, executes sample code, uses credentials, or makes
network requests. It invokes the same `code.filesystem` connector and bundled
signature index used by a normal scan, with Git enrichment disabled and secret
scanning enabled. A warning, partial scan, skipped connector, or unstable
repeated scan stops evaluation instead of counting missing detections as true
negatives.

All three bundled corpora are written or selected by the maintainers. Their
scores are regression checks on known inputs. None of them is a random or
representative sample of repositories, so none estimates field precision,
recall or calibration; see the held-out procedure below for that.

## Run the reproducible corpora

From the reviewed checkout, with the package dependencies installed:

```bash
python -m tools.evaluation.evaluate --output /tmp/nexus-synthetic-eval.json
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/public_corpus.json \
  --output /tmp/nexus-public-eval.json
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/realistic_corpus.json \
  --output /tmp/nexus-realistic-eval.json
python -m tools.evaluation.evaluate --repeats 5 \
  --output /tmp/nexus-timing-eval.json
python -m tools.evaluation.benchmark --files 1000 --runs 3 \
  --output /tmp/nexus-throughput.json
```

Use distinct output filenames: reports are created as private mode `0600` files
and will not overwrite existing ones. Exit 0 means all labels and structural
assertions passed, or that every failing case carries `known_gap: true`; exit 1
means at least one regression on a case without that flag; exit 2 means an
invalid corpus, incomplete scan, nondeterministic observations, or output
error. A `known_gap` case is a documented miss or false positive. It stays in
the metrics, so precision and recall report the scanner as it is, and the
report's `known_gaps` section lists the flagged count, the flagged cases that
still fail, the flagged cases that now pass (remove the flag so they guard
against regression) and any unflagged regressions. The flag is never a reason
to change the scanner to fit a case; the case description records why the
scanner gets it wrong. Pin the
scanner commit, signature pack, corpus SHA-256 (included in each report), Python
version and platform beside the report before comparing runs. Timing includes
connector analysis only; fixture creation, index loading and report writing
are excluded. The median and nearest-rank p95 of these tiny scans are regression
diagnostics, **not** a full-repository capacity benchmark or a latency SLO. The
separate benchmark builds up to 10,000 source files plus at most 20 manifests in isolated Python
projects and repeats the entire scan up to 10 times, verifying that every file
was examined and that finding counts remain stable. It reports bytes, finding
count, elapsed time, files per second and runtime platform. Hold file count and
worker resources fixed for comparisons; test real repository and connector
sizes separately before setting a production latency or memory target.

`tools/evaluation/corpus.json` has handwritten positives and hard negatives
for executable Python/TypeScript calls, f-string interpolation, JavaScript
regex followed by code, JSX text, comments, strings, README examples,
dependency-only usage, MCP JSON/JSONC/TOML/YAML and mixed enabled/disabled MCP
entries. An MCP case can also require an exact active server count and names,
and forbid any agent or secret finding. These cases test known boundary
behavior and were used to guide the implementation. Most are one small file
written to exercise one rule, so the scanner is expected to score 1.0 on them;
that score means "no regression on the rules we already know about", not
"accurate on real repositories". Its precision/recall values are **synthetic
regression scores**, not independently measured field accuracy.

`tools/evaluation/realistic_corpus.json` holds multi-file repository
snapshots (3 to 8 files each) written from scratch to resemble real projects:
a FastAPI service with a LangGraph agent, a Next.js app on the Vercel AI SDK
with an MCP client config, a Terraform Bedrock agent module, a CrewAI crew
with YAML agents, a Semantic Kernel console app, a LangChainGo service, an
n8n export, a Claude Code project with subagents and `.mcp.json`, an M365
declarative agent package, a Spring AI app, an OpenAI tool loop script, a
Dify DSL export, a LiteLLM proxy worker, a Pydantic AI notebook and an OpenAI
Agents SDK worker as positives; and, as negatives, repositories that share
vocabulary with agents without using any LLM: insurance agents with a
supervisor role, a ChatGPT usage policy in prose, a Minecraft Bedrock server,
a generated API client, text splitters without a model, a scikit-learn
notebook with a `transformers` tokenizer, Ansible handoff and unattended
upgrades, shell `execute_command` loops, geology buckets tagged `bedrock`, a
user agent parser, `REPLACE_ME` placeholders, a key rotation runbook, a Slack
standup bot, a crypto exchange client named `gemini-python`, a `copilot-css`
theme and a monitoring agent Helm chart. Each case labels one target kind and
signature; placeholder cases also assert that no secret finding is produced.

This corpus was written to be failable, and its first run found three
misses. Two were fixed in the signature data: the Semantic Kernel app now
promotes to an agent through C# code patterns for `Kernel.CreateBuilder()`,
`Plugins.AddFromType<>()`, `[KernelFunction("...")]` and automatic tool
invocation, and a Flask view defined as `def create_agent():` no longer matches
the LangChain `create_agent(` call pattern. At the time of writing the scanner
scores 15 TP, 1 FP, 0 FN and 15 TN on it (precision 0.9375, recall 1.0,
specificity 0.9375). The remaining failure carries `known_gap: true` and
explains the cause in its description: the runbook's illustrative `sk-proj-`
value is reported as a hardcoded credential because it is well formed and high
entropy, a finding a secret scanner cannot rule out from the surrounding prose. Passing cases also show attribution noise that the
binary target does not penalise: Java `@Tool(` is credited to LangChain4j next
to Spring AI, `new Agent({ name:` is credited to Mastra next to the OpenAI
Agents SDK, `docker-compose.yml` files raise a container workload infra
finding, and the CrewAI `agents.yaml` model names add an Azure OpenAI
provider. Like the other corpora, this one is author-written: the authors
chose the frameworks, the file layouts and the distractors, so its rates
describe these 31 cases only and are not a field precision estimate.

Source masking is a bounded lexical filter. Ruby regular expressions and `%q`
literals, PHP heredoc interpolation, C# raw strings with multiple interpolation
delimiters, and Scala interpolation need more dialect-specific handling. Such
constructs can be missed or misclassified; an identified unterminated literal
or ambiguous heredoc marks the scan incomplete. Review source evidence before
using these languages to enforce a production policy gate.

`tools/evaluation/public_corpus.json` contains **five complete, pinned public
files** from two external repositories: a LangGraph example and README at
[`7daa3ab`](https://github.com/langchain-ai/langgraph/tree/7daa3ab49d678a5da75edb08baa87db4a2be52c3),
and an MCP server configuration, README and server source at
[`f46d957`](https://github.com/modelcontextprotocol/servers/tree/f46d9578190b476b3501923ea8977d899e8db2cb).
Every case records a direct source URL, full commit, source path, copied file's
SHA-256, upstream license and the reason for its narrow label. This is a small
manually reviewed source sample, selected during development. It has neither
blinded independent annotation nor a representative sampling frame. Do not
pool its results with synthetic cases or report its rates as estate-wide
precision, recall, or calibrated probabilities. See
`tools/evaluation/THIRD_PARTY_NOTICES.md` for attribution.

Metrics use **one binary target per case**, selected by finding kind and optional
signature ID. `TP` means the target is present in the case and detected; `FP`
means absent but detected; `FN` means present and missed; `TN` means absent and
not detected. Precision is `TP/(TP+FP)`, recall is `TP/(TP+FN)`, specificity
is `TN/(TN+FP)`. Undefined denominators are JSON `null`. Additional assertions
(`max_agent_findings`, `max_secret_findings`, `server_count`, `server_names`)
appear separately as `assertion_failures` and cause a failing exit even if
target classification matches, unless the case is a flagged known gap. A finding's displayed confidence is a heuristic
score, not an estimated probability. The report's Brier/ECE proxies use the
maximum target finding confidence or zero for absence, and reliability bins;
the tiny selected sample does not calibrate that score.

## Build a genuinely held-out field set

1. Define the population and unit before labeling: repository revision and
   project for static agent detection, exact MCP config for configured servers,
   or identity/time window for an actively executing agent. Do not equate
   static code with runtime activity. Freeze a random, stratified sample across
   framework, language, repository size, code owner and expected negative
   classes. Set the sample size and acceptance bounds before reviewing scores.
2. Export each sampled input at a full commit or record snapshot, with a file
   SHA-256, license/permission to retain it, and no secrets. Keep the holdout
   outside the implementation branch. Two analysts should label it without
   seeing scanner results, record evidence for positive **and** negative
   labels, and adjudicate disagreement. An ambiguous case is excluded with
   its reason recorded, not silently counted as a negative.
3. Create the same JSON schema as `tools/evaluation/corpus.json`; set metadata
   type to `adjudicated` and record provenance and labeling method. The runner
   limits the corpus to 500 cases, 20 text files per case, 32 KB per file, 1 MB
   combined case content, and 2 MB of JSON. Larger real repositories need a
   separate offline scan and a repository-level annotation protocol. Keep the
   source and labels access controlled; the JSON report never prints file
   content or evidence snippets but may contain finding signature IDs and MCP
   server names.
4. Freeze the holdout before tuning. Report counts and precision/recall with
   confidence intervals and sample sizes by language, framework and kind;
   inspect each false positive and false negative. For confidence calibration,
   use independent cases spanning the score range and report reliability plots,
   Brier score and uncertainty, as well as the threshold at which findings
   enter an analyst queue. Revalidate on a new holdout after changing the
   signatures or classification logic. A zero-error small sample gives little
   information about uncommon production patterns.

## Read-only tenant canary procedure

Use distinct disposable, resource-limited workers: one for repository content,
and others for credentialed cloud, identity, gateway or SaaS APIs. Give each
connector a least-privilege audit identity and record the exact tenant, account,
region, API scopes, inventory snapshot, commit/signature version, time window,
pagination limit, exclusions and collection errors. Confirm the connector
returns `complete` with no skipped sources, permission errors, truncation or
deadline; an empty response alone is not coverage evidence. Independently
compare resource counts and known eligible objects from the provider's console
or API, including one negative control that lacks a required permission and
must be marked incomplete.

For each surface, manually trace a small set of known positive and negative
objects. Review code findings at the pinned revision; verify MCP server entries
are enabled; verify cloud and identity account scoping; and compare gateway
events against known principals and a bounded log window. Only claim runtime
activity when an event binds to a specific identified principal and object in
that window. Reconcile scanner results with the supplied sanctioned inventory:
`shadow` means absent from **that inventory**, not inherently malicious or
unknown to every owner. Record every investigated miss, false alarm, duplicate,
identity collision and incomplete coverage condition. Test rescanning an
unchanged snapshot and one controlled change for stable IDs and state behavior.
Set an operational error budget, alert volume, scan duration and release gates
from these canary measurements, then sign off before enforcing a policy gate.
