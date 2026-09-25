# Detection evaluation and production canaries

The evaluation tool creates one isolated temporary repository per labeled case.
It never clones a repository, executes sample code, uses credentials, or makes
network requests. It invokes the same `code.filesystem` connector and bundled
signature index used by a normal scan, with Git enrichment disabled and secret
scanning enabled. A warning, partial scan, skipped connector, or unstable
repeated scan stops evaluation instead of counting missing detections as true
negatives.

The five bundled corpora (synthetic, public, realistic, review and independent)
are regression checks on known inputs. The synthetic, realistic, review and
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

Source masking is a bounded lexical filter. Ruby `%q` strings with supported
delimiters are masked; `%Q` interpolation and unterminated percent strings mark
the scan incomplete. Ruby regular expressions, PHP heredoc interpolation, C#
raw strings with multiple interpolation delimiters, and Scala interpolation
need more dialect-specific handling. Such constructs can be missed or
misclassified; an identified unterminated literal or ambiguous heredoc marks
the scan incomplete. Review source evidence before using these languages to
enforce a production policy gate.

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
scores 13 TP, 1 FP, 2 FN and 15 TN on it (precision 0.93, recall 0.87,
specificity 0.94). The three failures carry `known_gap: true` and explain the
cause in their description: the runbook's illustrative `sk-proj-` value is
reported as a hardcoded credential because it is well formed and high entropy,
a finding a secret scanner cannot rule out from the surrounding prose; and the
OpenAI tool-calling script and the LiteLLM proxy worker are reported as LLM
usage rather than agents because generic loops and subprocess idioms cannot
confirm an agent without corroborating framework evidence, a deliberate
precision rule documented in docs/scanning.md. Passing cases also show attribution noise that the
binary target does not penalise: Java `@Tool(` is credited to LangChain4j next
to Spring AI, `new Agent({ name:` is credited to Mastra next to the OpenAI
Agents SDK, `docker-compose.yml` files raise a container workload infra
finding, and the CrewAI `agents.yaml` model names add an Azure OpenAI
provider. Like the other corpora, this one is author-written: the authors
chose the frameworks, the file layouts and the distractors, so its rates
describe these 31 cases only and are not a field precision estimate.
`review_corpus.json` is a separate authored regression set for the September 25
findings: local-module collisions, ordinary provider calls, tool-schema-only
requests, and supported agent construction/loops. It was written after observing
the defects and is not a fresh holdout. The existing independent corpus and its
annotation ledger remain frozen; adding regression cases does not refresh their
independence. The [acceptance verifier](https://github.com/aisecnomad/Project-Nexus/blob/main/tools/acceptance/README.md) requires
separate declared human-reviewed holdout evidence for deployment decisions.

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

Metrics use **one binary target per case**, selected by finding kind and optional
signature ID. The family name `all` is reserved for aggregate metrics and cannot
be used as a case's family. `TP` means the target is present in the case and detected; `FP`
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
   type to `adjudicated` and record provenance and labeling method in an annotation
   ledger supplied through `--annotations`. A ledger requires two distinct reviewer
   declarations and source-based resolutions for every disagreement. The runner
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
and exact source reuse from the five bundled evaluated corpora. It cannot find
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
