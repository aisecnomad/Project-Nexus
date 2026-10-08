# Real-world benchmark results — 2026-10-08

One run of the repo-surface cohort over the 34 pinned public repositories in
[`benchmarks/realworld/corpus.json`](../../../benchmarks/realworld/corpus.json),
on one machine (Python 3.13.16, Linux x86_64), 900 s per tool per repository,
every tool in fresh network and PID namespaces. Full tables are in
[`REPORT.md`](REPORT.md); per-repository rows are the `*.jsonl` files;
`summary.json` holds the scored metrics. Raw tool reports are not committed —
rerun `tools/benchmark/realworld_run.py` against the pinned corpus to
regenerate them.

The corpus and detection rules were committed before the scored run
(`75cab79`); the `shadowscan-tuned` variant was added after it (`168adee`)
and is reported separately. The author conflict of interest and every other
caveat in [`benchmarks/realworld/README.md`](../../../benchmarks/realworld/README.md)
apply to all of the below.

## What this run showed

**1. A page of regexes won the binary-detection headline.** The naive grep
baseline scored F1 0.96 (MCC 0.85), the best of the eight rows, and its edge
over default-options ShadowScan is the only pairing McNemar calls
significant (p = 0.013). Its two false positives are exactly the two
mention-only *awesome* lists — the failure the catalog rule exists to
prevent. The reading is not "grep is the best tool": binary detection is
the easiest possible task, the baseline shares an author with the labels,
and it produces no evidence, no ownership, no triage. The reading is that
**repo-level "is AI present" detection is close to saturated** — single
tools earn their keep on evidence quality, agent-tier separation,
specificity, and robustness, which is where the rows differ sharply.

**2. ShadowScan's fail-closed rule dominates its real-world behavior.**
Fifteen of 34 default-options scans ended incomplete (exit 3), so recall
measured 0.56 despite precision 0.93 and the second-best noise profile.
The synthetic corpus never triggered this; real repositories did, through
at least six distinct causes: scannable files over the 1 MB
`max_file_size` default; credential detection hitting its regex match
timeout on multi-megabyte text files (5 repos, including a 3 MB README of
links); lexical analysis failing on three real `.tsx` files; "binary or
undecodable content in analyzable file" (3 repos); deliberately malformed
in-tree files (cookiecutter `pyproject.toml` templates, an MCP config of
unexpected shape, YAML past resource limits); and per-connector deadlines
on large trees (pydantic-ai: 1,904 of 4,151 files scanned when the
deadline hit). Raising `max_file_size` to 20 MiB recovered only 3 of the
15. Every miss was loud — the reports name each cause — and no other tool
in the cohort refuses to return partial coverage silently, which is the
trade AGENTS.md chose. The cost of that trade on real repositories is now
measured.

**3. Specificity separates the field more than recall.** SafeDep vet and
Agentic Radar posted zero false positives on the nine negatives; vet
paired that with 0.72 recall (best MCC of the real tools, 0.64), while
Radar's workflow-mapper scope capped recall at 0.20 and it missed the
LangGraph framework repo itself. agent-bom flagged 7 of 9 negatives —
including click, express, and a Minecraft server — so its 0.92 recall
carries MCC 0.19. AgentDiscover reported agents in F-Droid's build tooling
(12), PyTorch examples, and counted the awesome-mcp-servers *list* as an
MCP server. Cisco AI BOM missed no positive it finished but spent 79 s
median per repository and timed out at 900 s on four, and flagged three
negatives.

**4. The per-family table shows complementary blind spots.** The IaC
Bedrock module was detected only by ShadowScan and the baseline. The n8n
flow was detected only by ShadowScan (as `workflow`) and the baseline.
Both TypeScript tool-calling apps beat AgentDiscover and Radar; the
LLM-only JS apps beat vet's signature set entirely. Framework *sources*
(as opposed to apps) beat ShadowScan mostly through fail-closed errors,
while agent-bom/AgentDiscover/vet detected all five. No single real tool
covered the corpus.

## Actionable ShadowScan findings from this run

Filed from the scan reports; each is a robustness gap on inputs the
generator cannot produce:

1. Credential detection `MatchTimeoutError` on large prose files makes the
   whole scan incomplete (5/34 repos; e.g. `awesome-mcp-servers/README.md`).
2. `incomplete source lexical analysis` on real TSX
   (`autogen/python/packages/autogen-studio/frontend/.../*.tsx`,
   `gitlab-lsp`).
3. Intentionally invalid in-tree files (cookiecutter templates, fixture
   JSON/YAML) fail the scan closed; a malformed *data file* may deserve a
   file-scoped warning distinct from lost scanner coverage.
4. `binary or undecodable content in analyzable file` (private-gpt,
   gitlab-lsp, fdroidserver).
5. Connector deadline on big checkouts leaves large trees partially
   scanned at default settings (pydantic-ai, mastra).
6. The one false positive is a 0.075-confidence provider-domain mention in
   UA test fixtures (`ua-parser-js`), below the demo config's 0.2
   `min_confidence`.

## Reading order

[`REPORT.md`](REPORT.md): headline detection table with Wilson/bootstrap
intervals, agent-tier recall and false-alarm rates, per-family matrix,
per-repository grid, McNemar pairings, error list, and noise counts.
