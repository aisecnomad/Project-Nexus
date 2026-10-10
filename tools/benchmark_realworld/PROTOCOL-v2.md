# Real-world shadow-AI discovery benchmark: protocol v2

Written after the v2 labelers had returned, and amended after two independent code reviews.
Every amendment was made before the freeze and before any v2 tool run (section 13).
The label rules are the v1.1 rules (`PROTOCOL.md`, section 4), unchanged. The corpus,
surfaces, statistics and harness are v2. The v1 results and labels are kept as they were.
The hashes of this file, the manifest and the code are recorded in `FREEZE-v2.txt` before
the run.

## 1. Question

For a public source repository at a pinned commit, or for the same repository read as a
developer home directory, does a discovery tool report AI use or AI agents exactly where
the independent labels say they are? v2 asks this on two surfaces and reports each surface
separately before any combined view.

## 2. Surfaces, and what is not measured

- `repo`: the repository working tree.
- `endpoint`: the repository root read as `$HOME`, for tools that read the home directory.
- Not measured: network, identity/SaaS, cloud and runtime. No public source of real
  traffic or tenant data exists for them. The synthetic harness (`tools/benchmark`) covers
  those surfaces and is reported separately.
- Results describe these repositories at these commits. They are not field precision, not
  production recall, and not independent human review.

## 3. Corpus

### 3.1 Repository surface: 84 repositories

- v1: the 41 repositories of `corpus.json`, unchanged, with the labels adjudicated in v1.
- v2 addition: 43 repositories from `v2/candidates-S1.tsv`. That table was fixed before any
  repository was attached. It sets a design category and a design stratum for each
  candidate. All 43 candidates attached and cloned. None was substituted.
- The design stratum is a design choice, not a label. A repository's label comes only from
  section 4.
- Each repository is a shallow clone (`--depth 1`) at a recorded commit, and must be a clean
  checkout (section 6). The license comes from its LICENSE file.

### 3.2 Endpoint surface: 81 home views

- v1: the 41 repository roots of section 3.1, each read as a home directory, as in v1.
- v2 addition: 40 public dotfiles repositories in two groups. Both groups were fixed before
  attachment, and each is selected by the same rule:
  - `ai-client-query` (20): repositories that search results returned for AI-client
    configuration files in dotfiles (`.claude`, `.cursor`, `.codex`, `.gemini`, `.continue`,
    agent instruction files).
  - `general-query` (20): repositories that search results returned for ordinary dotfiles
    (vim, neovim, shell, git, tmux, Brewfile).
  - Rule: distinct GitHub repositories in query order, then result order. Excluded: non-GitHub
    hosts, tool, plugin and documentation pages, and config collections that are not
    dotfiles. The first 20 per group were taken.
  - Inaccessible picks: two AI-client picks returned "not found or no access" (`Mai0313/dotfiles`,
    `jesuserro/dotfiles`). Each was replaced by the next eligible candidate of the same group,
    in the fixed order: `Zate/dotfiles` and `CTHua/dotai`.
  - No layout filter. A repository whose AI configuration sits under a managed layout
    (chezmoi, stow, rcm) is labelled by the path rule as it stands. That can read "none" for a
    home that would have the file after installation. This is a stated construct limit.
- Endpoint labels come from the path rule of section 6 of protocol v1, computed from the
  checkout. No labeler is involved.

### 3.3 Corpus counts (computed before the run)

| Surface | Cases | Positives | Negatives | Excluded |
|---|---:|---|---:|---|
| repo | 84 | 57 (46 agent, 11 llm) | 24 | 3 ambiguous |
| endpoint | 81 | 7 (AutoGPT; 5 AI-client dotfiles; 1 general dotfiles) | 74 | none |

The endpoint positive count is small. Its intervals are wide, and the report says so.

## 4. Labels

### 4.1 Definitions

Unchanged from v1 section 4 (v1.1). The labeler brief used for v2 is an excerpt of section 4,
copied verbatim, with the tool sections left out. Labelers never saw a tool rule or a tool
result.

### 4.2 Procedure for the 43 new repositories

1. Three labelers, B2, C2 and D2, each a separate agent instance. Each received the brief, one
   chunk of repository paths (11, 11, 11 and 10 repositories), and these rules: read-only
   inspection, no execution, only the named directories, and no access to another labeler's
   output. Each repository was labelled by all three.
2. Agreement before adjudication: 40 of 43 repositories unanimous. Fleiss' kappa on the
   three-way labels 0.91. Pairwise Cohen's kappa 0.89 to 0.93. Positive versus none is computed
   on repositories with no ambiguous label.
3. Three disagreements, each settled by reading the cited lines (`v2/adjudication.json`):
   - `PatrickJS/awesome-cursorrules`: agent (medium). Clause (b) holds literally: an `mcpServers`
     entry in a shipped sample rule (line 16). The llm reading also holds.
   - `Zie619/n8n-workflows`: agent (medium). An MCP client node in a shipped sample workflow
     (line 124), and an agent runtime deployed in `ai-stack/docker-compose.yml`.
   - `google/mediapipe`: ambiguous (low). An on-device LLM SDK with no provider call. Two of
     three labelers chose ambiguous, and the rule for unresolved cases is ambiguous. The
     repository is excluded from the primary metrics and reported in sensitivity.
   For the first two the positive or negative outcome does not change; only the agent or llm
   subtype does, which affects the agent-tier view only.
4. Every cited path in the adopted evidence was checked to exist. One glob citation
   (`us-weather-history/*.py`) is not a literal path and is listed as a warning.

### 4.3 Declared deviations

- The orchestrator did not label any v2 repository. In v1 it was labeler A. The orchestrator
  did make the adjudication calls, from the cited lines, and the report counts them as such.
- Labeler D2 (chunk 2) listed entry names under `.git` with `find` while searching. It opened
  no file under `.git`. Its output is used.
- The labelers ran as model agents with filesystem access. The read-only and directory-scope
  rules were instructions, not an enforced sandbox.

## 5. Tools, surfaces and detection rules

- The same configurations and version pins as v1 (`TOOL_PINS`). The detection rules of v1
  section 7 are unchanged, with these v2 changes:
  1. Each manifest entry runs only the surfaces it declares. Repository entries run `repo`.
     Endpoint entries run `endpoint`. v1 entries declare both, as in v1.
  2. ShadowScan (published), Cisco AI BOM and AgentDiscover scan the copied tree as a path. On
     the endpoint surface their rows measure repository files, not the home view, so in v2 they
     run on the repo surface only. Their v1 whole-tree home rows are reported as a diagnostic
     (section 8), not as endpoint evidence.
  3. ShadowScan (dedicated connectors) runs on the endpoint surface only. On the repo surface it
     calls the same `code.filesystem` scan as the published configuration, so v2 does not run it
     twice. Its v1 repo rows are kept as a determinism check.
- Support matrix. Repo surface: ShadowScan (published), Cisco AI BOM, agent-bom, AgentDiscover,
  SafeDep vet, mcp-audit. Endpoint surface: agent-bom, SafeDep vet, mcp-audit, ShadowScan
  (dedicated), shadow-mcp, Snyk Agent Scan, Cisco MCP Scanner, Claw-Hunter, AI-Detector.
- Exit status. For every configuration a non-zero exit, a timeout, or output that cannot be read
  is an error, never a result, except where section 6 names a non-zero exit as a completed run
  (agent-bom 1, AI-Detector 1, Claw-Hunter 1 and 2). Section 6 lists the exit code each tool
  returns on a positive and on a clean case, measured on known cases before the freeze.
- Report fields. A result also needs the fields the tool always prints. agent-bom: `scan_run.outcome`
  is `complete` with no incomplete scope. Cisco AI BOM: `aibom_analysis` metadata and
  `total_components`. AI-Detector: a `findings` list and a `shadow_ai_detected` flag that agrees
  with exit 1. Claw-Hunter: its six OpenClaw signal fields as booleans. SafeDep vet: an inventory
  list, or `null` for an empty one. A report without its fields is an error.
- agent-bom project entries (v1 section 7). A project server is AI evidence only on the
  `ai-inventory` surface, or when its `model`, `bound_model`, `models` or `provider` field is set.
  No report in v1 or in the probe sets one of those fields, so in practice the rule is the
  `ai-inventory` surface. A command name is not evidence: a CI job named `github-actions` is not.
  The v1 code also counted any server whose command was not `project`, which is the defect that
  section 13 corrects.
- Claw-Hunter (disclosure). Claw-Hunter checks for OpenClaw only. Its exit 1 is its own critical or
  warning verdict. A verdict counts as a detection only when one of its six signal fields is true.
  A warning with no signal, such as credential files under `~/.openclaw` on their own, is scored as
  not detected.
- Homes. On the endpoint surface every configuration runs with `HOME` set to the case's home view.
  On the repo and network surfaces `HOME` is an empty directory (section 9).
- A detection is an item the tool classes as AI-related, as in v1.
- An error is a wrong answer on both classes (section 7).

## 6. Harness changes since v1 (all disclosed)

1. Timeouts. The isolated runner starts each tool in its own process group and, on the
   300-second timeout, kills the whole group. In v1 only the direct child was killed. Two
   Cisco AI BOM helper processes survived their timeouts for 34 minutes. A timed-out tool
   returns no stdout, so a report it printed before hanging is never parsed as a result.
2. Exit status. Each configuration checks its exit status. Where a tool exits non-zero on a
   successful run, the table below records it.
3. Baselines. A host baseline that fails is an error. It is never cached as an empty
   baseline. AgentBom writes one output file per scan, and removes a stale file before it
   runs, so a baseline cannot answer a repository scan.
4. Checkouts. A checkout must match its pinned commit, be the top of its own repository, and
   have a clean tree, with no untracked or ignored files. A symbolic link anywhere on a path
   hides that path from the home label, as it does from the copy, and a directory whose entries
   are all symbolic links counts as empty, as it does in the copy. The copy never includes
   `.git` (directory or file).
5. Redaction. The secret patterns cover signed and unsigned JWTs, bearer tokens, `password`,
   `passwd`, `secret`, `token` and `api_key` assignments (quoted or not), GitHub, GitLab, AWS,
   Google and Slack token shapes, and PEM private-key blocks with their bodies. A quoted value is
   replaced inside its quotes, so a JSON key and its colon survive; a PEM body is bounded to base64
   and line breaks, so a block cut off inside JSON cannot consume the rest of the report.
6. Subset runs. A run with `--only-cases` or `--limit` writes its own manifest and refuses a
   results folder that holds a full run. `--only-cases` refuses an id that names no case. A run
   never keeps summaries produced under another manifest, protocol or code hash; it refuses.
7. Coverage. The scorer stops, and reports nothing, unless every configuration has one row for
   each manifest case on each surface it is run on, `n/a` only on a surface it does not run.
   A repeated row, or an `n/a` row on a surface the configuration runs, also stops it.
8. Manifest version 2, with per-entry surfaces. Version 1 manifests run as before. The run
   manifest records the SHA-256 of the manifest, of this protocol and of the harness code
   (`code_sha256`), and the ShadowScan commit. The scorer checks the first three against the files
   on disk and stops on a mismatch.

Exit codes measured on known cases before the freeze (positive = a case the labels mark as
positive; clean = a case labelled none; the probe is `v2/exit-probe/exit-probe.jsonl`, written by `v2/exit-probe/exit_probe.py`):

| Configuration | Exit on a completed run | Other exits | Measured (probe, `v2/exit-probe/`) |
|---|---|---|---|
| ShadowScan, published (repo) and dedicated (endpoint) | 0 | 3 incomplete scan (error); others error | 0 on a positive and a clean case, both configurations |
| Cisco AI BOM (repo) | 0 | 124 timeout, an incomplete analysis, others: error | 0 on the repo positive and clean case. Not run on the endpoint in v2; in v1 its endpoint positive timed out (124) after 300 s |
| agent-bom | 0 with no findings; 1 for a completed scan with findings | 1 with a partial scan: error; others error | Repo positive: codes [0, 1], the baseline completed and the repo scan was partial, so error. Repo clean: 0. Endpoint positive: 0. Endpoint clean: 1 for a completed scan, read as a result |
| AgentDiscover (scan and audit; repo) | 0 | others: error | 0 on the repo positive and clean case (two calls each) |
| SafeDep vet | 0 | others: error | 0 on all four cases |
| mcp-audit | 0 | others: error | 0 on all four cases |
| shadow-mcp | 0 | others: error | 0 on both home cases |
| Snyk Agent Scan | 0 | others: error | 0 on both home cases |
| Cisco MCP Scanner | 0 | others: error | 0 on both home cases |
| Claw-Hunter | 0 clean, 1 findings, 2 OpenClaw not installed | 3 script error; others: error | 2 on both home cases (not installed) |
| AI-Detector | 0 clean, 1 found | 2 error; a `[ERROR]` line on stderr is an error, because its JSON omits script errors | 1 on both cases: the benchmark host has AI tools, which the empty-home baseline subtracts |

The contract of each script is in its source: Claw-Hunter's exit codes are set in
`claw-hunter.sh` (lines 962 to 979), and AI-Detector's in `detect-shadow-ai.sh` (lines 982 to 989).
The table comes from the probe re-run after the second review, on the v2 configurations. The
pre-review probe output is kept as `exit-probe-before-review.jsonl`.
The probe records every exit code of a case, including the baseline call, so a case can show
two codes (for example agent-bom `[0, 1]`: the baseline completed and the repo scan partly failed).

## 7. Statistics

- Per surface: TP, FP, FN, TN; recall and specificity with Wilson 95% intervals; precision; F1;
  balanced accuracy (BA); MCC.
- An error is a wrong answer on both classes. On a positive it is a miss (FN). On a clean case
  it is a false alarm (FP). An incomplete scan must never clear a case (AGENTS.md: fail
  closed). v1 counted an error on a clean case as a true negative. That overstated
  specificity, and section 13 and `v1-erratum-table.md` show the size of the change.
- BA = (recall + specificity) / 2. MCC = (TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)).
  MCC is reported as undefined (n/a) when a margin is zero, for example a tool that flags every
  case.
- BA and MCC each carry a 2,000-resample stratified percentile interval. Positives and clean
  cases are resampled separately, so every resample holds both classes. A resample in which MCC
  is undefined is skipped, and the interval is undefined if more than half are skipped. The
  seed comes from the tool and the surface, so the intervals reproduce.
- Composite: the mean BA over the surfaces a tool supports, with equal weight per surface. It
  is undefined if any supported surface has an undefined BA.
- Estate: the mean BA over the two measured surfaces. A surface a tool does not support counts
  as chance, 0.5. A tool that covers one surface is therefore not credited for the surface it
  does not cover.
- Paired McNemar tests against ShadowScan (published), per surface, on the cases both tools
  support, with the error rule above.
- Views, reported and not used to choose a result:
  - (a) the primary view, with ambiguous cases excluded and errors counted as wrong;
  - (b) the completed-scan view, with errors left out of both classes, so detection is separated
    from coverage;
  - (c) BA without the hard-negative stratum;
  - (d) the held-out view: the 43 repositories and the 40 dotfiles repositories added in v2, on
    which no connector or rule was designed;
  - (e) the serial re-run of load-sensitive cases (section 8).

## 8. Load sensitivity, and the diagnostic for path-scanning tools

- Each incomplete ShadowScan scan carries its cause in the raw report. Parse failures and
  file-size limits are deterministic. A credential-matching timeout (`MatchTimeoutError`) depends
  on timing. In v1, one repository was incomplete under the published configuration and complete
  under the dedicated one, on the same code path. The determinism check reports every such
  difference.
- The primary v2 result keeps the original run. Incomplete scans are errors, which count as wrong
  answers (section 7). The serial re-run applies to every configuration, not to ShadowScan alone.
  It re-runs, one configuration at a time with one worker, every v2 case whose row is an error
  that names a timeout, an incomplete scan (`incomplete` or `not complete`) or exit 124. It reports
  the status changes for each configuration. `score_v2 --write-rerun` computes the case list from
  the v2 results and writes one `cases-<tool>.txt` per configuration; the scorer then checks the
  re-run's rows and manifest against those files and the primary results, and stops on a mismatch.
- Diagnostic. The v1 whole-tree home rows of ShadowScan (published), Cisco AI BOM and AgentDiscover
  are reported as a diagnostic. They are not in any endpoint metric.

## 9. Safety and handling

- As v1 section 9. Each tool runs as `nobody`, with an empty environment, fresh network and PID
  namespaces, and the 300-second timeout that kills the whole process group. `HOME` is the case's
  home view on the endpoint surface and an empty directory on the repo and network surfaces
  (section 5).
- Raw outputs go to `/opt/rwbench/raw-v2`, outside the repository, after redaction. Committed
  results hold verdicts and notes truncated to 200 characters.
- Residual risk, disclosed as in v1: some tools can start MCP servers named in a repository's
  configuration (Cisco MCP Scanner, known-configs mode). Those run inside the sandbox, with no
  network and no credentials.

## 10. Conflict-of-interest audit

The tool under study, ShadowScan, is one of the configurations, and the benchmark was built by the
team that develops it. The controls below reduce that bias. None of them removes it.

1. Corpus rules and candidate lists were fixed before any repository was attached.
   `v2/candidates-S1.tsv` and `v2/attach-*.list` record them.
2. Three blinded labelers, none of which saw a tool result. The orchestrator labelled no v2
   repository.
3. Adjudication used the cited lines only. Every decision is in `v2/adjudication.json`.
4. Every configuration ran under the same sandbox, timeout and error rules, and ShadowScan's
   results are reported with all the others. Its published configuration is the primary
   comparison, and its dedicated configuration is reported separately.
5. Held-out view. The connectors and the endpoint configuration were designed on the v1 results
   and home views. The 83 entries added in v2 were not used in that design. The held-out view
   (section 7(d)) is the result on those entries alone, and it is reported beside the full
   surfaces.
6. Two independent code reviews, each by a fresh model agent given the code and the protocol but no
   results. The first found defects in the error rule, the exit-status handling, the endpoint scope
   of the tree-scanning tools, the checkout checks, the bootstrap and the sensitivity design. The
   second found defects in the agent-bom exit and project-entry rules, the report checks, the
   redaction, the provenance and the lint and type gates. Each defect was fixed before the freeze,
   and section 13 lists them. The reviewers are model agents, not humans.
7. The raw verdict rows, the manifest, the adjudications and the scripts are kept so others can
   re-score.
8. Nothing was committed. The frozen hashes show what was run.

Residual conflict, which these controls cannot remove. The harness, the adjudication, the endpoint
rule and the metric choices were made by one team. The labelers and the code reviewer are model
agents, not human reviewers, and no independent human review exists. Independent replication is
needed before any claim about ShadowScan's performance.

## 11. Limits

- The endpoint surface has 7 positives in 81 cases, and the held-out endpoint view has 6 in 40, so
  those intervals are wide.
- Labels are model-based and blinded. They are not human-verified.
- Repositories are public and pinned, not field data, and the results carry no production
  precision.
- Dotfiles repositories may use managed layouts. The path rule reads the root only.
- Network, identity, SaaS, cloud and runtime are not measured.
- Some tools ran in reduced modes, as in v1 (Cisco AI BOM without its LLM classifier; AgentDiscover
  without layers 2 to 5; Snyk Agent Scan without analysis upload).
- agent-bom counts a project entry only on its `ai-inventory` surface (section 5). A repository that
  defines an agent or an MCP server without an SDK call can be missed on the repo surface. That is
  the v1 rule, not a rule tuned to the results.

## 12. Freeze and run

Before the run, `FREEZE-v2.txt` records the SHA-256 of this protocol, of `corpus_v2.json`, of the
v2 attachment, labeling and adjudication files, and of the code files it lists. It also records
the verdict-code hash (`code_sha256` in `run.py`, over `VERDICT_CODE`: the case builder, the
adapters, the runner and the case base they share). The scorers and the report are frozen as files
in this list, and are not in that hash, so a change to them does not invalidate a run already made.
`run.py` records the manifest, protocol and code hashes in `run-manifest.json`, and the scorer
refuses a run whose hashes differ from the files on disk.

## 13. Changelog

- v2 (this document). Written after the v2 labelers returned. Amended after the code review and
  before the freeze, with no v2 tool run and no v2 result existing at that time. The amendments:
  - errors are wrong answers on both classes (section 7; v1 counted them as clean negatives);
  - the tree-scanning tools (ShadowScan published, Cisco AI BOM, AgentDiscover) are repo-only in
    v2, and their v1 home rows are a diagnostic;
  - non-zero exit, timeout and unreadable output are errors for every configuration, with the
    measured exit codes in section 6; a timed-out tool returns no stdout; a failed baseline is an
    error and is never cached; AgentBom writes one file per scan;
  - the checkout must be clean and the top of its own repository; a symbolic link on a path hides
    it from the home label; the copy never includes `.git`;
  - the bootstrap is stratified; the composite is undefined when a supported surface is undefined;
  - the serial re-run covers every configuration, and the held-out view was added;
  - the scorer stops unless every configuration has one row per case; subset runs have their own
    manifest; the run manifest records the ShadowScan commit;
  - the redaction patterns cover JWTs, bearer tokens, password and token assignments, and GitLab
    and GitHub fine-grained tokens;
  - SafeDep rejects a Scope it does not know, rather than dropping the item.
  - second review, before the freeze (each fix has a regression test in
    `tests/unit/test_benchmark_realworld_review2.py`, and others in the earlier files):
    - agent-bom: exit 1 is read with the report. A completed scan with findings is a result; a
      partial scan is an error. v1 treated every exit 1 as an error;
    - agent-bom: a project entry counts on the `ai-inventory` surface or a model binding, as
      section 5 says. The code had also counted any command other than `project`, so a CI job named
      `github-actions` counted as AI evidence (the Flask case). The v1 results carry the same defect;
    - a report without the fields its tool always prints is an error for agent-bom, Cisco AI BOM,
      AI-Detector, Claw-Hunter and SafeDep vet (section 5); an unreadable agent-bom baseline is an
      error and is not cached;
    - AI-Detector's flag must agree with its exit code;
    - ShadowScan's endpoint scans run with the case home as `HOME` (section 9);
    - redaction covers the whole PEM block and unsigned JWTs;
    - the run manifest records the code hash; a run never keeps summaries produced under other
      inputs; `--only-cases` refuses an unknown id;
    - a directory of only symbolic links is empty for the home label;
    - the scorer refuses repeated rows and `n/a` rows on a supported surface, checks the run manifest
      against the files on disk, and computes and checks the serial re-run list;
    - a cited path must exist inside the checkout, and a glob is only a warning. The corpus rebuilds
      byte for byte, so no entry changed;
    - the v1 agreement helper compares every labeler pair and leaves ambiguous labels out of the
      binary kappa (section 4.2);
    - the exit probe was re-run on the v2 configurations, now including both ShadowScan
      configurations. The pre-review probe is kept as `v2/exit-probe/exit-probe-before-review.jsonl`;
    - the lint and type gates pass on the changed modules.
    The v1 results under `results/` were produced before these changes and are not re-run. The v1
    erratum (`v1-erratum-table.md`) covers the error rule only. The v1 agent-bom rows also used the
    old exit and project-entry rules, so they are superseded and not used for any v2 claim.
  - a first run was stopped after two configurations, because its redaction had broken the raw
    copies of ShadowScan's reports: a credential pattern matched a JSON key and removed its colon.
    The verdicts came from unredacted output and were not affected, but the raw evidence was not
    valid JSON, so no verdict from that run is used. The fix changes redaction only; no adapter or
    verdict rule changed, so the exit probe still holds. The run was restarted from a new freeze
    (`FREEZE-v2.txt`), and the first run's partial output is not kept with the results.
  The label rules are v1.1, unchanged.
