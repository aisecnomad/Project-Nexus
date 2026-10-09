# Real-world Shadow-AI discovery benchmark: protocol

This is the protocol for a benchmark that runs open-source Shadow-AI / agent-discovery tools on real
public repositories. It was written, and the oracle, registry, sampling code, corpus manifest, adapters
and scoring code were frozen, before any tool was run on a scored repository. **Nothing here is committed
to version control** (the maintainer asked for a report, not a commit), so the order of events is *not*
evidenced by git history. What is evidenced instead is `results/freeze.json`: the SHA-256 of every file
that defines the benchmark, written before the scored run and re-checked by `run.py --freeze` when the run
starts, and repeated in `results/run-manifest.json`. That record proves which files produced the numbers.
It does not prove when they were written, and it is self-attested. Section 12 lists what changed after an
independent design review, and which choices were made after looking at the calibration split.

## 1. Question

How well do open-source discovery tools find LLM, agent, MCP and coding-agent integrations in repositories
they have never seen, and how often do they raise an alarm where there is none?

The unit is one repository snapshot (one commit, working tree only). The surface is the *repository*
surface only: tools are pointed at a checkout. Endpoint, network, identity, cloud and runtime surfaces are
out of scope, so tools whose only job is one of those (for example Snyk Agent Scan on a machine, AgentSonar
on traffic, Open Shadow AI, k8s-aibom) are not scored. They are listed in the report.

## 2. What this benchmark is not

* It is **not** an estimate of field precision or recall, and it is **not** independent. It was designed and
  run by an AI agent working in the ShadowScan repository for that repository's maintainer, and ShadowScan is
  one of the tools scored. Treat any ShadowScan result as suspect until someone with no stake re-runs it.
* It does not rank tools. No number here is a population estimate; every figure is a proportion with a 95%
  interval for a named stratum of one dated sample.
* The ground truth is a deterministic oracle plus, for disagreements, a *blinded language-model
  adjudication*. Neither is independent human review, and neither is described as one anywhere.
* Tools run **offline** (no network, no vendor API, no LLM). Features that need a service are measured
  without it, and the report says so per tool (Cisco AI BOM states its LLM is required for accurate results).
* Results hold for this sample, snapshot date and tool versions only.
* The positives are mostly *agent-type* integrations (frameworks, MCP, coding-agent configuration). Plain
  LLM-SDK use is a small share (the corpus summary gives the counts). The benchmark says little about it.

## 3. Sampling

### 3.1 Frames and classes

Repositories come from public registries, a public module index, the GitLab public projects API, curated
lists and a purposive set. Only unauthenticated endpoints and anonymous `git` reads are used; the GitHub REST
API is not used. Each frame belongs to a class that decides how results may be pooled.

| Class | Frames | What it is |
|---|---|---|
| `probability` | `pypi-ai`, `pypi-other` (uniform random PyPI projects with a recent release and a source link, split by whether their declared dependencies include a registry AI package); `go-random`, `go-ai` (repositories behind modules first published in random windows of the Go module index; `go-ai` keeps those whose repository name matches an AI keyword pattern); `gitlab-random` (random project IDs) | random draws from a defined frame. **The headline scope.** |
| `search` | `npm-ai`, `npm-other` (npm registry keyword search, ranked and popularity-biased), `gitlab-ai` (GitLab keyword search) | reproducible, not random. Reported, never pooled into the headline. |
| `list` | `list-mcp`, `list-claude-code`, `list-agents`, `list-ordinary` (links in awesome lists) | curated by others. Reported, never pooled into the headline. |
| `challenge` | `hard-negative` (lexical collisions), `classical-ml` (scope), `prose-only` (prose and data lists) | robustness only. The `hard-negative` idea mirrors categories ShadowScan's maintainers tuned against (section 10). |

The `-ai` / `-other` split of `pypi-*` uses the oracle's registry (a declared dependency on a registry agent or
LLM package). So membership of `pypi-ai` and the oracle's label for it are not independent: a `pypi-ai`
repository is a positive because it declares a package the registry lists. That is a defined stratum
("Python projects that declare a known AI package"), not a population, and section 10 discusses what it
implies. Activity window: last release or activity on or after 2025-01-01, so the sample is from the agent
era. Quotas per frame are in `sample.py` (`QUOTAS`).

### 3.2 Eligibility and snapshot policy

A candidate is eligible if it is publicly cloneable, has at least 3 files and (outside `prose-only`) at least
one source file, at most 25,000 files and 150 MB, and the owner has fewer than 2 repositories already in the
corpus. Candidates are tried in a seeded shuffle; the first eligible ones fill the quota.

Snapshot: `git fetch --depth 1` of the pinned commit, no submodules, no Git LFS (pointer files stay as text),
no hooks, `.git` removed, file modes normalised. Every symlink is then checked by **physical** resolution
(`realpath`, which follows every other link on the way) and replaced by a one-line text file when it is
absolute, dangling, points at an ancestor of itself, or resolves outside the snapshot; the check repeats until
nothing changes. (A first version checked paths lexically and a review showed a chain such as
`sub/l2 -> ..`, `l1 -> sub/l2/../..` defeats it; the stored corpus was re-audited, 19 more links were
neutralised, and the oracle labels were re-derived and are unchanged.) Symlinks that stay inside the snapshot
(for example `CLAUDE.md -> AGENTS.md`) are kept. The harness itself executes nothing from a snapshot; some
tools do (cdxgen runs `python` in the project directory), which is why every run is sandboxed (section 6).

### 3.3 Splits and exclusions

The first one to three eligible repositories of each frame form the **calibration** split, used only to get
adapters running (flag names, report formats, how a report is read). Calibration repositories are never
scored. The rest form the **scored** split.

Two scored repositories are named in files of the ShadowScan repository (`rw-111` in its independent
evaluation corpus, `rw-121` in a signature pack). ShadowScan's authors may have used them, so they are not
unseen for that tool. `contamination.py` finds them mechanically (`exclusions.json`); they are removed from
every tool's analysis and listed in the report.

## 4. Ground truth: the oracle

`oracle.py` (standard library only, run with `python -I` outside the corpus) reads a snapshot as data. Its
knowledge is `registry/ai_registry.json`: package names and import roots per ecosystem, coding-agent and MCP
path rules, content markers for workflow exports and infrastructure-as-code, and weak host/env-var markers.

* **Provenance and independence.** The registry was written by the benchmark author from public package
  registries and vendor documentation. ShadowScan's signature packs were not opened while writing it and no
  tool under test supplied an entry. **That does not make it independent of ShadowScan.** The author works
  inside the ShadowScan repository and shares knowledge of the ecosystem with its maintainers, and a review
  found the registry's package names are mentioned far more often in ShadowScan's source (79%) than in other
  tools' (6-33%). `vocab_overlap.py` therefore records, for each registry technology, which tools' own source
  mentions it (`registry/vocab-overlap.json`), and the scorer adds the `shared-vocab` label variant and
  reports every tool's recall on positives that rest only on ShadowScan-mentioned technologies (section 7).
  `tests/test_benchmark_realworld.py` checks that the oracle imports only the standard library.
* Evidence kinds: declared dependency (manifests across PyPI, npm, Go, Maven/Gradle, NuGet, crates, gems,
  Composer, pub), parsed import (Python by AST, others by anchored regex, comments skipped), well-known path
  (works for symlinks), content marker, and weak marker (an API host or key variable *name* in a
  non-documentation file; values are never stored).
* Context: `src`, `config`, `example`, `notebook`, `test`, `docs`, `transitive`. A development-only
  dependency counts as `test`; a Go indirect dependency as `transitive`. Generic import names (for example
  `mcp`, `agents`) count only when the same technology is also declared as a dependency.
* **Label states.** `positive`: strong evidence outside tests and docs. `negative`: no strong, weak or
  AI-adjacent (vector store, tracing, UI) evidence anywhere; classical ML frameworks are allowed.
  `ambiguous`: everything else (evidence only in tests or docs, weak-only, adjacent-only).
* **Role.** A project whose own name is an AI library or SDK (for example `langchain-foo`) is `ai-library` and
  excluded from the primary analysis; it is not a consumer of AI.
* **Application versus developer-tooling evidence.** Evidence from coding-agent configuration (`AGENTS.md`,
  `CLAUDE.md`, `.claude/`, `.cursor` rules, Copilot instructions, agent skills, Claude Code plugins, MCP
  configuration files, AI review-bot configuration, AI actions in CI; the `dev_config_ids` list in the
  registry) is developer-tooling evidence. Everything else (dependencies, imports, workflow exports,
  infrastructure-as-code, raw MCP servers) is application evidence. The primary label counts both. Tools that
  inventory AI *in application code* do not claim to read developer configuration, so an `app-only` variant
  drops repositories whose only evidence is developer-tooling configuration, and a separate figure reports
  every tool's recall on those repositories.
* **Primary analysis set** = scored, non-excluded repositories with role `consumer` and state `positive` or
  `negative`. This is a *clean-label* subset: it measures detection where the answer is clear. Ambiguous
  repositories get their own table (every tool's verdict on each) and enter only the sensitivity analyses.
* Label variants for sensitivity: *strict* (primary: src, config, example, notebook), *app-only* (as strict,
  without developer-tooling-only repositories), *core* (src, config only), *loose* (any context), *no-dep-only*
  (without positives supported by a declared dependency alone), *shared-vocab* (positive only if a supporting
  technology is mentioned by a tool other than ShadowScan) and *with-libraries* (AI libraries included).
* Known blind spots, accepted: vendored or minified code, AI use through an HTTP call to an endpoint the
  registry does not list, obfuscated or generated code, languages the oracle does not parse (it still sees
  manifests), and anything newer than the registry. Those repositories can look like clean negatives;
  adjudication of tool hits (section 8) is the correction.

### 4.1 Oracle revisions

* **R0**: registry written before any repository was sampled. It was never committed anywhere, so it cannot
  be recovered; `registry/ai_registry.json` holds a revision log of what R1 added.
* **R1**: after the corpus was sampled and **before any tool was run on a scored repository**, a manual review
  compared each repository's sampling frame with its label, looking only for oracle blind spots (repositories
  from AI frames labelled negative, and the reverse). It found Claude Code plugin repositories
  (`.claude-plugin/`) and MCP servers written without the official SDK (raw `tools/list` handlers,
  `glama.json`, MCP registry `server.json`) labelled negative. Rules for those were added, `dev_config_ids` was
  introduced, and four repositories changed from negative to positive. The edit is generic (no
  repository-specific rule) and used no tool output. The oracle was nevertheless adjusted after seeing the
  sample, which is a deviation from a pure pre-registration. Oracle version 2 labels are the ones used.

## 5. Tools and detection rules

Tools are pinned in `install_tools.sh` (three at the same commits as the synthetic benchmark in
`tools/benchmark`); ShadowScan is installed from this checkout and `run-manifest.json` records that the
installed tree hash equals the source tree hash. A tool **detects** a repository when its own report contains
at least one AI-related item for it, as that tool defines AI-related, *for this benchmark's target* (LLM,
agent, MCP and coding-agent integrations). The rule for each tool is in its adapter's docstring in
`adapters.py`. Two principles apply to every tool alike:

1. Items a tool's own taxonomy files under classical machine learning or MLOps (datasets, training runs,
   hyper-parameters, ML frameworks) or that it states are not an independent signal are not counted by the
   headline rule. Each tool also has a pre-declared variant that counts them. (Cisco AI BOM: the "ML
   lifecycle" types of its enumeration plus datasets and feature stores. agent-bom: `ml_framework`.
   AgentDiscover: DAI008 and DAI009, which its source calls metadata enrichment that "never" counts as an
   independent signal. cdxgen: `prompt-config-file` and `notebook-file`, which it assigns to every shell
   script, notebook, and file whose name contains `prompt`, `agent`, `model` and similar words, by name only.)
2. A crash, a timeout, an unreadable or schema-invalid report, or a non-zero exit that the tool does not
   document as a verdict is an **error**. A scan the tool itself calls incomplete (ShadowScan exit 3 or an
   incomplete summary, Cisco `completed_with_errors`, agent-bom `scan_run.outcome` of `partial`) is
   **partial**; with no findings it is an error, with findings it is recorded as partial. (agent-bom's exit
   code 1 also means "a critical secret was found", so its report is read instead.)

Allowed calibration changes (decided on the calibration split only): how a tool is invoked and how its
report is read. Not allowed: changing what counts as a detection after seeing scored results. What was
changed after the first calibration run is listed in section 12.

Configuration variants of ShadowScan (one documented option each, sensitivity rows, never the headline):
`shadowscan-bigfiles` (`max_file_size` 25 MB and a 540 s connector deadline, the remedy for exit 3 on an
oversize file) and `shadowscan-conf03` (`--min-confidence 0.3`, the README example). They are excluded from
all cross-tool comparisons.

Baselines (keyword search over text files) are included only to show what a trivial approach scores.

## 6. Sandbox

Every run: a fresh copy of the snapshot owned by an unprivileged user; new network / PID / mount / IPC / UTS
namespaces (no network); a `pivot_root` into a tmpfs that holds read-only `/usr`, a handful of `/etc` entries,
the interpreter directory and the tool root, and only that session's own directory (no home directory, no
corpus, no labels, no other session; `run.py` aborts unless a self-test confirms this); dropped uid and gid,
empty capability bounding set, `no_new_privs`; empty `HOME` and a minimal environment (no proxy or credential
variables); cgroup memory and process caps, CPU and file-size limits; a 600 s wall-clock kill that also ends
every descendant; and bounded capture of output. The privileged harness reads a file a tool wrote only
through a reader that refuses symlinks anywhere in the path, and a database a tool wrote (vet) is opened by an
unprivileged process inside the sandbox. Version probes also run in the sandbox. Runs execute in parallel, so
reported runtimes include contention and are indicative only. See `sandbox.py`.

## 7. Metrics and statistics

Nothing is ranked. For each tool and each scope, on the primary set, with 95% intervals:

* **Scopes.** `probability` (the headline: random-draw frames only) and `all` (every frame, descriptive of the
  sampled mix). Per class, per frame and per primary language as well.
* **Headline figures**: recall on positives and specificity on negatives, as Wilson intervals, plus the error
  rate. Precision, F1, MCC and balanced accuracy are secondary: they depend on the positive/negative mix of the
  quotas, which is a design choice and not a prevalence. F1, MCC and balanced accuracy use a cluster bootstrap
  by owner (5,000 resamples, seed 20261008; with at most two repositories per owner it is close to an ordinary
  bootstrap).
* **Errors and partial scans (headline policy).** A crash, a timeout, an unreadable report **or a scan the
  tool calls incomplete** is never a clean result. On a positive repository it counts as a miss; on a negative
  repository it is excluded from the specificity denominator and reported as an error rate. Two sensitivity
  policies are reported for every tool: *partial scans keep their findings* (a partial scan with findings is a
  detection or a false alarm), and *errors count as clean* (an error on a negative is a true negative).
* **Label variants** (section 4), **detection-rule variants** (section 5), recall by **evidence family**
  (declared dependency, import, configuration file, workflow marker; agent-type versus LLM-only) and recall on
  **developer-tooling-configuration-only** positives.
* **Vocabulary check**: recall on positives whose supporting technologies a tool other than ShadowScan
  mentions, versus the rest. A large gap for ShadowScan alone would be the signature of a registry that
  favours it.
* **Paired comparisons**: exact McNemar on per-repository correctness for *every pair* of tools (baselines
  included, configuration variants excluded), Holm-corrected within the family, per scope. ShadowScan is not
  the reference.
* **Unique finds** (positives detected by exactly one tool) and union recall, over the real tools.
* **Prevalence scenarios**: positive predictive value at 1%, 5% and 20% prevalence from the *probability-scope*
  sensitivity and specificity (flagging 1 in 20 clean repositories matters when scanning thousands).
* **Agent tier** (exploratory): among agent positives, how often the tool's report names an agent-type
  finding, using the type mapping fixed in `adapters.py`.
* Runtime (median, p95) and error rate by size bucket.

## 8. Adjudication (blinded, LLM-assisted)

After scoring against the oracle, disagreements are adjudicated to correct oracle errors:

0. every `ambiguous` repository;
1. every negative repository that at least one real tool flagged (up to 110, then a seeded sample);
2. every positive repository that at least 70% of the real tools that ran missed;
3. a seeded 10% sample of the remaining repositories, to estimate oracle error where nobody disagrees.

Baselines and configuration variants are not counted as tools here.

Two independent language-model adjudicators label each card from the evidence on it: repository facts, the
oracle's evidence with a few lines of context, and keyword hits from a tool-independent search. Cards name no
tool and say nothing about what any tool reported. (Tool-reported evidence is not on the cards because raw tool
output is not stored.) They are told the repository content is untrusted data and must not be followed as
instructions. A third rules on disagreements. Cohen's kappa is reported, **as a consistency check only**: the
adjudicators are the same model family as the benchmark author, so agreement is not independent corroboration.
The oracle's evidence on a card anchors the adjudicator toward the oracle, which this protocol accepts and
states. Results are reported **both before and after** adjudication; the pre-adjudication table is the
headline because it is fully deterministic. "Unclear" rulings exclude the repository from the post-adjudication
table. This is **not** independent human review, and it is described that way wherever it appears.

## 9. Reporting commitments

* Every scored repository and tool result is in `results/`, including bad ones for any tool, ShadowScan
  included. Raw tool output is not published (it may contain third-party secrets): rows hold normalised
  outcomes, fixed-vocabulary notes, exception class names and filtered identifier-like names.
* Deviations from this protocol are listed in the report with their reason.
* No tool is tuned on the scored split. Defects found in ShadowScan are reported, not fixed in this change.

## 10. Threats to validity

* **Label noise** from the oracle (gaps in the registry, the AST/regex limits) and from the adjudicators.
  Mitigations: clean-label primary set, blinded adjudication, sensitivity analyses; residual error is not zero.
* **Shared knowledge and registry-defined strata.** The benchmark author and ShadowScan's authors share
  knowledge of the AI ecosystem, and the registry both labels repositories and defines the `pypi-*` strata.
  Mitigations: the vocabulary check and the `shared-vocab` variant (section 7), the untargeted frames
  (`pypi-other`, `go-random`, `gitlab-random`), and the pairwise comparisons that do not use ShadowScan as the
  reference. None of them removes the concern.
* **Contamination of the hard-negative idea.** The `hard-negative` frame's lexical-collision categories mirror
  negatives ShadowScan's maintainers tuned against in `tools/benchmark`. No such repository is in the corpus
  (`contamination.py` found only the two exclusions above), but ShadowScan is more likely to have been tuned
  on the *kind*. The frame is `challenge` class and never in the headline.
* **Frame bias.** Registry frames favour published packages and popular projects; lists favour curated ones;
  neither reflects private enterprise repositories. GitHub is reached through lists and registries only,
  never searched directly. Untargeted frames contain few application-level positives, so recall there has
  wide intervals.
* **Offline mode** disadvantages tools that need a service (LLM, vulnerability database).
* **Temporal drift.** Tools, registries and repositories change; the report is dated and pinned.
* **Clean-label optimism.** Excluding ambiguous repositories raises every tool's apparent accuracy; only a
  handful of ambiguous repositories were sampled, so the benchmark says little about gray-zone false alarms.
* **Multiple comparisons.** Holm correction within the pairwise family; exploratory metrics are labelled.
* **Self-attested freeze** (above) and **author conflict of interest**. Independent re-runs are invited: the
  manifest pins every commit and the scripts here reproduce the corpus, labels and results.

## 11. Reproduce

```bash
bash tools/benchmark/realworld/install_tools.sh TOOL_ROOT
python -m tools.benchmark.realworld.fetch_corpus --manifest tools/benchmark/realworld/manifest.jsonl --corpus CORPUS
python -I tools/benchmark/realworld/oracle.py --registry tools/benchmark/realworld/registry/ai_registry.json \
    --manifest tools/benchmark/realworld/manifest.jsonl --corpus CORPUS --out labels.jsonl
python -m tools.benchmark.realworld.run --manifest tools/benchmark/realworld/manifest.jsonl --corpus CORPUS \
    --tool-root TOOL_ROOT --results OUT --freeze tools/benchmark/realworld/results/freeze.json
python -m tools.benchmark.realworld.score --manifest tools/benchmark/realworld/manifest.jsonl \
    --labels labels.jsonl --results OUT --output OUT/summary.json
python -m tools.benchmark.realworld.report --summary OUT/summary.json --run-manifest OUT/run-manifest.json
```

Requires root (namespaces, cgroups) and a user named `rwb`; use a disposable machine. `sample.py` and
`frames.py` are provenance tooling: live registries change, the manifest is the artifact.

## 12. Changes after the independent design review and the first calibration run

An independent reviewer (a separate agent given only the files, not my conclusions) read the design before the
scored run. Its blocking findings and what was done:

| Finding | Action |
|---|---|
| The headline pooled every frame class although this protocol said lists and searches were not pooled | `score.py` now has four classes; the headline scope is `probability`; npm and GitLab-search frames are `search`; pooled figures are labelled descriptive |
| The registry is not independent of ShadowScan and also defines strata | Independence claims removed; vocabulary overlap measured; `shared-vocab` variant and vocabulary-split recall added; limits stated in section 10. The strata were not redrawn |
| Pre-registration was not evidenced | Nothing is committed (maintainer's instruction); a hash freeze replaces the claim, and the text above says what it does and does not prove |
| The symlink check was lexical and bypassable; tools saw the host file system | Physical-resolution fixpoint; stored corpus re-audited; `pivot_root` jail with a self-test |
| The incompleteness policy favoured ShadowScan | Partial scans are errors in the headline for every tool, with the lenient policy as a sensitivity analysis; ShadowScan configuration variants added |
| Adapter reading rules (vet dropped CrewAI signatures; agent-bom's source scan was not enabled outside Python; schema checks missing) | Fixed, see section 5 |
| Promised outputs were not implemented (technology identification, ambiguous table, adjudication weights, `app` rulings, 600 s timeout) | Technology identification and adjudication weights dropped from the protocol; ambiguous table, `app` overrides and the 600 s default implemented |
| Cards showed how many tools flagged a repository | Removed |
| Published rows kept raw stderr; the version probe ran unsandboxed and tried to send telemetry; a database was opened as root | Fixed |

Choices made after looking at the first calibration run (34 repositories, never scored): the headline reading
rules for Cisco AI BOM, agent-bom, AgentDiscover and cdxgen described in section 5 (the first rules counted
CI workflows, classical-ML frameworks, `model=` arguments and every shell script as AI evidence); vet's tag
set; agent-bom's `--ai-inventory` flag and its completeness reading; the two ShadowScan configuration
variants. The keyword baselines were broken by the new sandbox (they could not see their own script) and were
fixed on the calibration split. The calibration run also
showed ShadowScan itself exits 3 (incomplete) on about a quarter of repositories under defaults and raised
one false alarm, which is reported rather than fixed.
