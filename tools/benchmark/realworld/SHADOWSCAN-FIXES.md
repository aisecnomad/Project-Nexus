# ShadowScan changes made after the real-world benchmark

This records what was changed in ShadowScan after reading its failures in the benchmark
([REPORT.md](REPORT.md)), and what was measured afterwards. Nothing here is a second
person's audit; see the limits below.

## Changes

| Area | Change |
|---|---|
| JavaScript/TypeScript | The check that drops an SDK binding shadowed by a method parameter no longer rescans the source from each statement start. It timed out on a 22 KB TypeScript file and cost that file all its analysis. |
| Source lexers | Strings that span lines (Rust, PHP, F# `.fs`), PHP 8 attributes, F# type variables, C# `@"""`, JSX in `.js`/`.mjs`/`.cjs`, the TypeScript non-null `!` before a division, and Qt/Tiled XML named `.ts`/`.tsx` are read exactly instead of ending the walk as ambiguous. Ruby multi-line strings, unclosed strings and heredoc interpolation stay ambiguous (incomplete). After review: PHP `#[` is lexed both as an attribute and as a PHP 7 comment, and only what both readings mask stays masked; the JSX retry is not used after `yield`/`await` or in a file with a left shift such as `a<<b>c`; Qt/Tiled XML must open with an XML declaration or a document type declaration and be well-formed. |
| File contents | Text that is not valid UTF-8, and large UTF-8 text with a few stray NUL bytes (removed before analysis, as bash removes them), is analyzed with one warning per kind instead of being skipped as a coverage gap. Mostly-invalid content, control characters, dense NULs, UTF-16/32 without a mark, and invalid `.py`/`.ipynb` stay gaps. `strict_coverage` keeps every noted file a gap; invalid bytes in `CODEOWNERS` are an error. |
| Agent definitions | A plain front-matter value containing `: ` is quoted and parsed again through the same strict loader. |
| False evidence | `mcp.<vendor>.<tld>` no longer matches dotted identifiers (`mcp.translator.translatekey`); it ends in a country-code domain (except file-extension and property-name codes such as `py`, `md`, `id`) or a listed generic one. Hosts on hosts-file, ad-block, resolver and proxy-rule lines in non-source documents no longer count as use. |
| Credentials | A secret with no attributed provider is titled `Hard-coded credential in <file>` and tagged `unattributed-credential`. |
| New evidence | `protocol.mcp` recognises SDK-free JSON-RPC dispatch; `coding-agent.claude-code` recognises `.claude/launch.json`, `.claude/rules`, `.claude/output-styles` and the plugin manifests. |

Not changed, on purpose: a per-surface coverage ledger, chunked scanning of oversize
files, unknown extensionless binaries, submodule and symlink coverage policy, YAML
duplicate keys, confidence calibration, plain-HTTP LLM endpoints, directory manifests
with no mechanism to match them, and `.fsx`/`.fsi` scripts.

## Measurements

Same harness, same frozen scoring, ShadowScan `code.filesystem` only, 2 workers,
one run per cell. "Before" is the unmodified source; "after" is the working tree.

| Corpus | Run | Recall | Specificity | Precision | F1 | Error rate | Partial scans |
|---|---|---|---|---|---|---|---|
| Benchmark sample (326 repos; 153 positives, 162 negatives) | before | 0.673 | 0.932 | 0.904 | 0.772 | 8.0% | 65 |
| | after | 0.719 | 0.938 | 0.917 | 0.806 | 6.2% | 60 |
| Fresh draw (190 repos; 88 positives, 108 negatives) | before | 0.761 | 0.917 | 0.882 | 0.817 | 9.2% | 26 |
| | after | 0.784 | 0.917 | 0.885 | 0.831 | 7.7% | 24 |

Errors count as misses on positives and are outside the specificity denominator, as in
the report's headline policy. The 95% intervals overlap in every row (for example, sample
recall 0.673 [0.595, 0.742] before and 0.719 [0.643, 0.784] after): these are point
estimates of a direction, not a demonstrated gain.

The eight bundled evaluation corpora produce identical metrics before and after (only
the source and signature hashes and timings differ).

## Limits

* **Author conflict.** The same person wrote the tool, the benchmark and these fixes.
* **In-sample.** The failures were diagnosed on the benchmark sample, so its "after" row
  is not held out. The fresh draw was sampled after the diagnosis and is the fairer
  check, with a smaller effect.
* **Noise.** One run per cell, wall-clock budgets (a repo flipped between complete and
  partial under load once). The "after" runs were repeated (sample: 3 runs; fresh draw: 3
  runs); the sets of errored repositories were identical between the last two, and so were the
  sample's partial scans (the fresh draw's partial counts matched).
* **Labels.** The oracle labels were produced by the benchmark's tool-independent
  rules, with agent adjudication on the sample's disagreements. No human reviewed them.
* **Environment.** The `oci` SDK is not installed in the development environment, so
  `cloud/oci.py` shows 73.6% against the 75% per-connector floor there. That file is not
  changed here; CI installs the extra.
* **Unfixed finding.** Redaction of call arguments (`utils/redaction_calls.py`) is
  quadratic on a file of tens of thousands of unclosed calls (60 KB of `f(` lines took
  about 3 s) and exceeds the 2 s per-file budget; the scan fails closed as incomplete.
* **Freeze.** The measurement runs above did not use `run.py --freeze`: the ShadowScan
  source hash recorded in `results/freeze.json` is the pre-fix tree, so a frozen run now
  correctly refuses to start against the fixed source.
