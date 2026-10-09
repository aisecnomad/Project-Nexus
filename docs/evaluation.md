# Detection evaluation and production canaries

The evaluation tool creates one isolated temporary repository per labeled case.
It never clones a repository, executes sample code, uses credentials, or makes
network requests. It invokes the same `code.filesystem` connector and bundled
signature index used by a normal scan, with Git enrichment disabled and secret
scanning enabled. A warning, partial scan, skipped connector, or unstable
repeated scan stops evaluation instead of counting missing detections as true
negatives.

Corpus paths must identify distinct files and directories under conservative
case-folded, Unicode-normalized comparison. A file cannot also be a parent
directory, and each path component must fit within 255 UTF-8 bytes. Layouts
that would alias or fail to materialize on a supported host are rejected before
scanning. Sample creation never overwrites an existing path; an unexpected host
alias stops evaluation instead of changing the labeled input.

The eight bundled corpora (synthetic, public, realistic, review, field review,
attribution, current SDK idioms and independent) are regression checks on known
inputs. The synthetic, realistic, review, attribution, current SDK idioms and
public sets were written or selected by the maintainers; the independent corpus
was labeled separately, as described below. None of them is a random or
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
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/review_corpus.json \
  --output /tmp/nexus-review-eval.json
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/field_review_corpus.json \
  --output /tmp/nexus-field-review-eval.json
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/attribution_corpus.json \
  --output /tmp/nexus-attribution-eval.json
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/current_idioms_corpus.json \
  --output /tmp/nexus-current-idioms-eval.json
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/independent_corpus.json \
  --annotations tools/evaluation/independent_annotations.json \
  --output /tmp/nexus-independent-eval.json
python -m tools.evaluation.evaluate --repeats 5 \
  --output /tmp/nexus-timing-eval.json
python -m tools.evaluation.benchmark --files 1000 --runs 3 \
  --output /tmp/nexus-throughput.json
```

Use distinct output filenames: reports are created as private mode `0600` files
and will not overwrite existing ones. Exit 0 means all labels and structural
assertions passed, or that every failing case carries `known_gap: true` within
the corpus's valid waiver budget; exit 1 means at least one unwaived regression
or a stale waiver whose case now passes; exit 2 means an invalid corpus
(including a missing, expired or over-budget known-gap policy), incomplete
scan, nondeterministic observations, or output error. A corpus containing a `known_gap` must declare
`known_gap_policy.max_count` and `known_gap_policy.expires_on`. The evaluator
rejects a missing or expired policy and fails when the number of flags exceeds
the cap. A `known_gap` case is a temporary, documented miss or false positive.
It stays in the metrics, so precision and recall report the scanner as it is,
and the report's `known_gaps` section lists the flagged count, cases that still
fail, stale flags and unflagged regressions. The flag is never a reason to
change the scanner to fit a case; the case description records why the scanner
gets it wrong. Pin the
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
entries (a server that declares itself disabled is still reported, tagged
`declared-disabled`, but is not an active server). An MCP case can also require
an exact active server count and names, and forbid any agent or secret finding. These cases test known boundary
behavior and were used to guide the implementation. Most are one small file
written to exercise one rule, so the scanner is expected to score 1.0 on them;
that score means "no regression on the rules we already know about", not
"accurate on real repositories". Its precision/recall values are **synthetic
regression scores**, not independently measured field accuracy.

The September 27 classification correction keeps the original generic
StateGraph and schema-only Vercel examples as negative agent cases, and adds
actual agent factories and executable-tool examples as positives. New negatives
cover generic CrewAI Flow and disabled tools. These 77 authored cases (32
positives, 45 negatives) describe the intended boundary; they are not a new
holdout. The frozen public, realistic and independently AI-labeled sources and
labels are unchanged. Review capabilities separately from binary agent labels:
an available framework feature is not an observed workload capability.

Source masking is a bounded lexical filter. Ruby `%q` strings with supported
delimiters are masked; `%Q` interpolation and unterminated percent strings mark
the scan incomplete. Ruby regular expressions, PHP heredoc interpolation, C#
raw strings with multiple interpolation delimiters, and Scala interpolation
need more dialect-specific handling. Such constructs can be missed or
misclassified; an identified unterminated literal or ambiguous heredoc marks
the scan incomplete. Review source evidence before using these languages to
enforce a production policy gate.

`tools/evaluation/realistic_corpus.json` holds multi-file repository
snapshots (5 to 7 files each) written from scratch to resemble real projects:
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
scores 13 TP, 1 FP, 2 FN and 15 TN on it (precision 0.93, recall 0.87,
specificity 0.94). Three failures of the binary target carry `known_gap: true` and explain the
cause in their description: the runbook's illustrative provider-shaped value is
reported as a hardcoded credential because it is well formed and high entropy,
a finding a secret scanner cannot rule out from the surrounding prose; and the
OpenAI tool-calling script and the LiteLLM proxy worker are reported as LLM
usage rather than agents because generic loops and subprocess idioms cannot
confirm an agent without corroborating framework evidence, a deliberate
precision rule documented in docs/scanning.md. Binary-correct cases can still
contain off-target findings or vendor attribution. The separate authored
attribution suite below checks those aspects. Like the other corpora, this one
is author-written: the authors chose the frameworks, the file layouts and the
distractors, so its rates describe these 31 cases only and are not a field
precision estimate.

`tools/evaluation/attribution_corpus.json` contains 24 short, handwritten
source cases without credential examples. They cover framework-only usage,
agent construction, product/provider attribution and configured capabilities.
The October 2 additions check Genkit initialization, explicit agents, registered
tool generation, disabled dispatch and function-local registrations. Each case
checks expected and forbidden findings and declares an `exact_findings` list
to compare the full emitted finding multiset. On the October 2 implementation,
the binary target scores 14 TP and 10 TN, while one binary-correct case fails attribution
checks: Docker Compose beside an n8n workflow is also credited to Kubernetes
agent workloads. That case has explicit `known_gap: true` under the corpus's
bounded `known_gap_policy`, remains in the case and assertion counts, and is
listed as a failing gap. Twenty-three of 24 exact finding sets pass. These are
intentionally selected development fixtures; their scores do not measure field
error rates or human-labeled vendor accuracy.
`field_review_corpus.json` holds eight synthetic cases written after a field
review of public repositories: an aiohttp client, a UI component named
`AgentCard` and a call-center `invoke_agent` function as hard negatives, and
bound MCP, raw-response, streaming, helper-function and crew manifest cases as
positives. Its cases re-create observed patterns in original code and are a
regression suite, not a field precision estimate.
`review_corpus.json` is a separate authored regression set for the September 25
findings: local-module collisions, ordinary provider calls, tool-schema-only
requests, and supported agent construction/loops. It also contains positive and
negative npm alias attribution cases added during the October 1 code review,
and October 2 cases for named Python URL dependencies and paired active and
commented Gradle and Dockerfile declarations, with exact finding assertions.
October 6 cases from the head-to-head benchmark (`tools/benchmark/`) cover
Goose's user configuration at `~/.config/goose/config.yaml` and an installed
Cline editor extension without an MCP settings file, each with a look-alike
negative.
October 8 cases cover import-bound Go agent constructors, .NET tool definition
versus invocation, and Python comprehension reachability. October 9 cases cover
guarded optional Python imports: a passing or exiting `ImportError` handler,
alternative import paths of one class, and a local fallback class that keeps
the construction uncertain. These authored cases
are regression evidence, not new independent annotation.
It was written after observing
the defects and is not a fresh holdout. The existing independent corpus and its
annotation ledger remain frozen; adding regression cases does not refresh their
independence. The [acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md) requires
separate declared human-reviewed holdout evidence for deployment decisions.

`tools/evaluation/current_idioms_corpus.json` holds 24 short synthetic cases
(17 positives, 7 negatives) written from scratch, with AI assistance, in the
shape current SDK documentation uses. The positives are an AI SDK 7 chat route
whose `streamText` call loops over imported tools with `stopWhen:
isStepCount(5)`, an AI SDK 6 `ToolLoopAgent`, OpenAI Agents SDK agents in
Python (`Runner.run`) and TypeScript (`run`), Claude Agent SDK `query()` in
Python and TypeScript and a `ClaudeSDKClient` session with an in-process tool,
LangGraph `create_react_agent`, LangChain 1.0 `create_agent`, a Google ADK
`LlmAgent`, a Pydantic AI agent with a tool, a smolagents `CodeAgent`, a
Strands agent, a Microsoft Agent Framework `ChatAgent`, a Mastra agent and an
OpenAI chat-completions loop that dispatches the selected function. The hard
negatives are a plain AI SDK 7 chat route, a multi-step call without tools, a
tool loop disabled with `toolChoice: 'none'`, single chat-completions and
Messages API calls without tools, a local `agents` package whose `Agent` and
`Runner` classes are not the OpenAI SDK, and a repository of Semgrep, Sigma and
gitleaks rules that name LLM keys and hosts, which must produce no finding at
all. The positives also assert an agent finding attributed to the expected
product or provider. One case is a `known_gap`: a single-step `generateText`
call with an imported executable tool is model-selected dispatch, but without a
stop condition the scanner only recognizes inline `tool({ execute })`
definitions, so it reports SDK usage. Its first run, against the scanner before
the October fixes, failed two cases: the AI SDK 7 tool loop was missed and the
rule repository was reported as LLM usage. Like the other authored suites, its
scores describe these cases only, not field precision or recall.

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

The separate `independent_corpus.json` is a negative-heavy public source sample
selected and labeled by a curator who did not inspect the scanner implementation
or its results. A second AI reviewer labeled a neutral source packet without the
first labels or scanner observations. Both reviewers agreed on all 42 cases
before the first evaluation. The annotation ledger records both decisions and
their reasons and binds them to the exact corpus SHA-256. CI rejects missing
votes, unresolved disagreements, changed labels and content-digest mismatches.
The evaluator checks that the annotation digest matches the exact snapshot it
loaded for scanning, and rejects a corpus changed between those reads. Corpus
reads are bounded and reject symbolic links in every path component.
This is recorded independent **AI** annotation, not independent human validation
or authenticated third-party certification. Selection is purposive; the sample
does not estimate the prevalence or accuracy of a production estate.

Once observations are used to improve detection, this set is a frozen regression
corpus, not a fresh held-out test. Keep its labels unchanged when improving the
scanner and report the first evaluation separately from subsequent results.
Commission a new independently labeled sample before making field claims.
See `INDEPENDENT_CORPUS.md` beside the corpus for selection, licenses and labeling
provenance. Reports identify the signature and scanner-source fingerprints,
scanner version and runtime; retain the reviewed source commit and CI run
alongside them. [Assurance results](assurance-results.md) preserve the first
observations and subsequent regression results.

Binary metrics use **one target per case**, selected by finding kind and optional
signature ID. The family name `all` is reserved for aggregate metrics and cannot
be used as a case's family. `TP` means the target is present in the case and detected; `FP`
means absent but detected; `FN` means present and missed; `TN` means absent and
not detected. Precision is `TP/(TP+FP)`, recall is `TP/(TP+FN)`, specificity
is `TN/(TN+FP)`. Undefined denominators are JSON `null`. Additional assertions
(`max_agent_findings`, `max_secret_findings`, `server_count`, `server_names`,
`forbidden_signatures`) appear separately as `assertion_failures` and cause a
failing exit even if target classification matches, unless the case is a valid,
unexpired known gap. `forbidden_signatures` guards attribution independently of
the binary target—for example, detecting Spring AI must not silently add a
LangChain4j attribution.

`assertions.expected_findings` and `assertions.forbidden_findings` each accept
up to 20 selectors. A selector has `kind` and may include `product_signature`,
`provider_signature` and `capabilities`. The product signature matches the scanner finding's
`frameworks` field (which also contains platform, cloud and protocol IDs),
while the provider signature matches only its `model_providers` field. When both
are specified, they must occur **on the same finding**. For example:

```json
{
  "assertions": {
    "expected_findings": [
      {"kind": "agent", "product_signature": "framework.langgraph", "provider_signature": "provider.openai"}
    ],
    "forbidden_findings": [
      {"kind": "agent", "product_signature": "framework.langchain4j"},
      {"kind": "infra"}
    ]
  }
}
```

An optional `capabilities` array compares the **exact set** of capability IDs
on that same finding, regardless of order. It accepts at most 20 unique IDs.
Omitting it leaves capabilities unchecked; `"capabilities": []` explicitly
requires none. For example, an empty-tool OpenAI Agent can be checked with:

```json
{
  "kind": "agent",
  "product_signature": "framework.openai-agents-sdk",
  "capabilities": []
}
```

Use that selector in `expected_findings` to require the empty capability set.
In `forbidden_findings`, it forbids exactly that set, not every finding with
the same product. Capability checks have their own counter under
`finding_assertions.capabilities` when present. Missing capability observations
cannot satisfy an expected capability selector. Earlier corpora that omit
capability selectors keep their existing semantics.

Selectors cover **only** the listed assertions; an unexpected unlisted
finding can still pass. Opt into `assertions.exact_findings` for exhaustive
checks with up to 20 expected findings, each listing `kind`, the complete
`product_signatures` array and the complete `provider_signatures` array.
Use `[]` to assert that no findings at all are emitted. The list is compared
as a multiset, so extra or duplicate findings and extra attribution IDs fail.
It does not compare capabilities, finding locations, metadata, evidence,
confidence, or runtime execution; add the explicit selectors above for
capability checks. The report has per-case `finding_checks` and
`exact_finding_set` results and an aggregate `finding_assertions` section with
both case coverage and pass/fail counts. Product and provider counters can
overlap; they must not be treated as independent samples. No selectors or
exact finding sets were added to the frozen independent corpus, whose reviewers
labeled only the primary binary target. A future human-labeled holdout must
predeclare and review any added kind, attribution and capability labels **before** scanning;
the current annotation ledger validates only the binary `present` decisions.

A finding's displayed confidence is a heuristic
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
   Include ordinary Java chat clients, standalone tool declarations, empty or
   disabled tool/delegation options, and positive controls with actual configured
   tools. Label source-coverage gaps separately from agent absence; an incomplete
   checkout must not become a negative example merely because it yields no finding.
2. Export each sampled input at a full commit or record snapshot, with a file
   SHA-256, license/permission to retain it, and no secrets. Keep the holdout
   outside the implementation branch. Two analysts should label it without
   seeing scanner results, record evidence for positive **and** negative
   labels, and adjudicate disagreement. An ambiguous case is excluded with
   its reason recorded, not silently counted as a negative.
3. Create the same JSON schema as `tools/evaluation/corpus.json`; set metadata
   type to `adjudicated` and record provenance and labeling method in an annotation
   ledger supplied through `--annotations`. A ledger requires two distinct reviewer
   declarations and source-based resolutions for every disagreement. The runner
   limits the corpus to 500 cases, 20 text files per case, 32 KB per file, 1 MB
   combined case content, and 2 MB of JSON. Larger real repositories need a
   separate offline scan and the [repository-level procedure](#repository-level-field-acceptance). Keep the
   source and labels access controlled; the JSON report never prints file
   content or evidence snippets but may contain finding signature IDs and MCP
   server names. If evaluating kind and attribution, freeze those labels and
   their source-based reasons separately before scanning; the supplied two-vote
   annotation ledger currently verifies the primary binary target only.
4. Freeze the holdout before tuning. Report counts and precision/recall with
   confidence intervals and sample sizes by language, framework and kind;
   inspect each false positive and false negative. For confidence calibration,
   use independent cases spanning the score range and report reliability plots,
   Brier score and uncertainty, as well as the threshold at which findings
   enter an analyst queue. Revalidate on a new holdout after changing the
   signatures or classification logic. A zero-error small sample gives little
   information about uncommon production patterns.

### Repository-level field acceptance

Use this protocol for repositories larger than the bounded JSON evaluator can
represent. It is a human review procedure, not an additional automated gate or
a claim that field validation has been performed. File-level regression scores
cannot be substituted for repository-level acceptance.

1. Freeze the deployment population, repository sampling unit, seed, exclusions
   and numerical acceptance policy before selecting inputs or observing results.
   Stratify by language, framework, repository size and organization. Include
   conventional software, LLM-only clients, standalone tools, configured agents
   and model-directed action loops. Choose false-positive/negative budgets and
   latency/memory limits from the intended use; account for shared templates and
   organizations when estimating uncertainty.
2. Retain permission-approved snapshots outside this implementation checkout,
   pinned to full commits and file-content manifests. Record exclusions,
   unavailable submodules and transformations. Scan immutable snapshots on
   restricted workers without tenant credentials; do not execute sampled code.
3. Have two humans independently label source before seeing scanner output.
   Freeze per-kind repository presence labels and reasons, adjudicate
   disagreements, and record ambiguous cases. Label individual entity identity,
   attribution, capabilities and runtime observations separately when those are
   deployment requirements. Coverage gaps cannot be labeled agent absence.
4. Run the exact reviewed candidate with fixed configuration and budgets, without
   `--fail-on`. Retain private JSON reports, process exits, source/signature
   fingerprints, elapsed time, peak memory and worker details. An incomplete
   scan, missing input or unexplained warning blocks that sample's acceptance;
   do not count it as a true negative or quietly exclude it from the denominator.
5. Score the frozen labels by kind and stratum. Report TP/FP/FN/TN, undefined
   denominators, class counts, completeness and uncertainty appropriate to the
   sampling design. Keep attribution and capability errors visible separately.
   Retain an independent human decision against the frozen policy. Once findings
   inform tuning, commission a new holdout before claiming out-of-sample accuracy.

For the October 9 corrections, independently selected strata should include SDK
aliases, multiline Rust and JavaScript/JSX. Validate gateway invocation semantics,
network connection attribution and collection-loss handling on separately labeled
operational logs, retaining their origin, scope and observation window. Export
roundtrips also need operational inputs with representative encoded sizes and
empty collections. None of these source/log tests establishes live API coverage.

For the October 8 classification corrections, independently selected strata
should also cover .NET tool definition versus dispatch, Go package receivers
versus ordinary local methods, Python comprehension reachability and
multi-domain device identities. Device attribution requires its own labeled
operational inputs.

The automated [acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md) currently
supports local-code, AWS and Slack scopes. Repository-level records from this
manual protocol cannot be converted into a passing receipt without the verifier's
actual required artifacts. Use authorized [tenant canaries](canaries.md) for the
supported providers; other connectors require their own reviewed validation.
No human labels or live acceptance receipts are generated by this change.

### Gate a frozen holdout

The bundled synthetic and selected public cases are development regressions;
the acceptance command refuses both as release evidence. After independent
annotation, keep the adjudicated corpus outside the public repository. Record
the sampling frame, sampling seed, snapshots, two blinded reviewers, disagreements,
adjudication, exclusions and license/retention decisions in a restricted review
record. `metadata.type: "adjudicated"` is a declaration, **not** verification of
independence. A reviewer must check that record and approve the policy *before*
the scanner scores or labels are revealed.

Create a separate JSON policy using the SHA-256 of the exact corpus bytes. Include
`all` and every `family` actually present in the corpus. For example, this is a
**format illustration**, not a recommended threshold or a field result:

```json
{
  "schema": 1,
  "corpus_sha256": "REPLACE_WITH_LOWERCASE_64_CHARACTER_SHA256",
  "groups": {
    "all": {
      "min_positive_cases": 60,
      "min_negative_cases": 60,
      "min_precision_lower95": 0.8,
      "min_recall_lower95": 0.8,
      "min_specificity_lower95": 0.8
    },
    "agent": {
      "min_positive_cases": 60,
      "min_negative_cases": 60,
      "min_precision_lower95": 0.8,
      "min_recall_lower95": 0.8,
      "min_specificity_lower95": 0.8
    }
  }
}
```

Set the digest, review the policy, then run this on a controlled worker with no
live credentials:

```bash
sha256sum /restricted/holdout.json
python -m tools.evaluation.accept \
  --corpus /restricted/holdout.json \
  --policy /restricted/acceptance-policy.json \
  --annotations /restricted/holdout-annotations.json \
  --output /restricted/acceptance-result.json
```

The command requires a private corpus outside the source checkout and a
SHA-256-bound, two-reviewer ledger declaring
`independent-human-double-label-before-scan`. Bundled suites and AI annotation
records remain regression evidence. It rescans every case with complete, stable
observations and checks the method on the evaluated ledger. The ledger records
declarations; a reviewer still needs to verify the sampling and review process. It
checks the frozen corpus digest, all required groups, minimum positive and
negative counts, structural assertions and the predeclared precision, recall and
specificity **lower endpoints of two-sided 95% Wilson intervals**. It accepts a
bounded number of errors if the predeclared endpoints still pass; it does not
silently demand perfect classification. Undefined rates fail the gate. Exit `0`
passes, `1` fails a bound/assertion, and `2` means invalid inputs, incomplete
coverage or an output error. The private `0600` summary will not overwrite an
existing file; it contains counts and failures, not source content. Retain the
scanner and signature commit, corpus/policy digests, the full labeled result
from `tools.evaluation.evaluate`, reviewer decisions and CI logs in the
restricted release record. Changing labels, exclusions, scanner signatures or
sampling after seeing results requires a new blinded holdout and reviewed policy.

The standalone command requires declared human labels, rejects known-gap waivers
and exact source reuse from the eight bundled evaluated corpora. It cannot find
undisclosed private prior evaluations or near duplicates. For a production
rollout, run [`tools.acceptance.verify`](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md) with
declared `prior_corpora` and the separately reviewed tenant canary evidence.

This is a code-filesystem **case-level** gate. The sampled file units and
framework/kind groups cannot prove whole-repository recall, a specific
language's accuracy, credential safety, cloud/identity completeness or active
runtime execution. Review per-language/framework error slices and a separate
tenant canary before selecting `--fail-on`. A scanner can pass this gate and
still miss a rare production pattern.

One provider-loop recognizer covers linked Python OpenAI
Chat Completions calls, model-returned tool-call arguments, dispatch and tool
results appended to the same request history. Dispatch must target an explicitly
declared inline tool name or a callable selected by the model-returned function
name; parsing or converting arguments is insufficient. Another recognizer covers
Python OpenAI Responses tool loops when the returned
function name and arguments reach a dispatched handler, its result is fed back
with the matching call ID, the originating call is forwarded into the request
history, and the same input can reach another model request.
This recognizer follows bounded direct loops and simple branch conditions.
Neither recognizer resolves arbitrary helper functions, complex interprocedural
flows, JavaScript provider loops or runtime imports. Unrecognized patterns can
still produce integration findings; they are not proof
that an agent is absent. A framework constructor alone also cannot establish that
the configured graph makes autonomous model decisions at runtime.

## Read-only tenant canary procedure

Executable AWS and Slack live canaries, credential preflight, permission-denied
controls and clearly separated offline replay checks are documented in
[canaries.md](canaries.md). Replay or mocked transport success is never recorded
as live tenant acceptance. Other connectors still require provider-specific
canary acceptance; these two adapters do not validate the whole estate.

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

Retain a proof packet **per connector instance**, with the following artifacts:

| Artifact | Acceptance evidence |
|---|---|
| Frozen scope | Tenant/account ID, regions, granted API scopes, audit principal, collection period, snapshot/commit, scanner and signature revision, and SHA-256 of selected inputs. |
| Full scan status | Access-controlled JSON report with `summary.complete=true`, all connector `stats` and zero uninvestigated errors, warnings, skips or truncations. Scanner exit `3` blocks acceptance. |
| Independent denominator | Console or separately queried provider counts for eligible objects/pages and the explicit API or configuration filters that define inclusion. An empty scanner result is insufficient. |
| Positive and negative traces | Resource IDs and analyst adjudication for known eligible agents, harmless frameworks, disabled servers and a deliberately denied permission; the denied case must report incomplete coverage. |
| Runtime attribution | For runtime claims, bounded gateway event window with principal, resource identity, correlation outcome and retained false matches; source references alone remain static evidence. |
| Operational result | Alert volume, misses, duplicates, scan duration and resource use under realistic load, plus reviewer sign-off, rollback revision and rerun procedure. |

Sanitize and restrict these artifacts under the tenant's data-handling policy.
This repository's automated checks do **not** run such a live canary or claim
independent field precision/recall.
