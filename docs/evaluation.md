# Detection evaluation and production canaries

The evaluation tool creates one isolated temporary repository per labeled case.
It never clones a repository, executes sample code, uses credentials, or makes
network requests. It invokes the same `code.filesystem` connector and bundled
signature index used by a normal scan, with Git enrichment and secret scanning
disabled. A warning, partial scan, skipped connector, or unstable repeated scan
stops evaluation instead of counting missing detections as true negatives.

## Run the reproducible corpora

From the reviewed checkout, with the package dependencies installed:

```bash
python -m tools.evaluation.evaluate --output /tmp/nexus-synthetic-eval.json
python -m tools.evaluation.evaluate \
  --corpus tools/evaluation/public_corpus.json \
  --output /tmp/nexus-public-eval.json
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
assertions passed; exit 1 means at least one regression; exit 2 means an invalid
corpus, incomplete scan, nondeterministic observations, or output error. Pin the
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
and forbid any agent finding. These cases test known boundary behavior and were
used to guide the implementation. Its precision/recall values are **synthetic
regression scores**, not independently measured field accuracy.

`review_corpus.json` is a separate authored regression set for the September 25
findings: local-module collisions, ordinary provider calls, tool-schema-only
requests, and supported agent construction/loops. It was written after observing
the defects and is not a fresh holdout. The existing independent corpus and its
annotation ledger remain frozen; adding regression cases does not refresh their
independence. The [acceptance verifier](../tools/acceptance/README.md) requires
separate declared human-reviewed holdout evidence for deployment decisions.

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

The separate `independent_corpus.json` is a negative-heavy public source sample
selected and labeled by a curator who did not inspect the scanner implementation
or its results. A second AI reviewer labeled a neutral source packet without the
first labels or scanner observations. Both reviewers agreed on all 42 cases
before the first evaluation. The annotation ledger records both decisions and
their reasons and binds them to the exact corpus SHA-256. CI rejects missing
votes, unresolved disagreements, changed labels and content-digest mismatches.
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
signature ID. `TP` means the target is present in the case and detected; `FP`
means absent but detected; `FN` means present and missed; `TN` means absent and
not detected. Precision is `TP/(TP+FP)`, recall is `TP/(TP+FN)`, specificity
is `TN/(TN+FP)`. Undefined denominators are JSON `null`. Additional assertions
appear separately as `assertion_failures` and cause a failing exit even if
target classification matches. A finding's displayed confidence is a heuristic
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
