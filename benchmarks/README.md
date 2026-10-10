# Benchmarks

ShadowScan carries several benchmarks. Each one answers a different question,
and none of them is independent: the same maintainer wrote ShadowScan, the
benchmarks and their labels. Treat every result as offline evidence about the
listed inputs, not as measured field precision or recall. See
[docs/evaluation.md](../docs/evaluation.md) for what ShadowScan accepts as
evidence and for the bundled regression corpora that `make evaluate` runs.

| Benchmark | Inputs | Labels | Harness | Corpus and results |
|---|---|---|---|---|
| Synthetic head-to-head | 900 seeded, generated cases across repo, endpoint and network surfaces | Generator-defined | [`tools/benchmark/`](../tools/benchmark/README.md) | `tools/benchmark/results*/` |
| Real-world repositories (34) | 34 public repositories pinned by commit | Author-inspected | [`tools/benchmark/`](../tools/benchmark/README.md) cohort | [`realworld/`](realworld/README.md) |
| Authored real-world shapes | 130 authored cases modelled on public code | Authored with each case | [`sab_realworld/`](sab_realworld/harness.py) (`python -m benchmarks.sab_realworld`) | `sab_realworld/results/` |
| File-dialect holdout | Handwritten fixtures for missed file dialects | Authored with each case | `tests/test_evaluation.py` | [`sab-holdout/corpus.json`](sab-holdout/corpus.json) |
| Repo and home-view surfaces | Public GitHub repositories, read as a working tree and as `$HOME` | Two model labelers, adjudicated | [`tools/benchmark_realworld/`](../tools/benchmark_realworld/README.md) | `tools/benchmark_realworld/results*/` |
| Sampled real-world repositories (326) | Random and purposive samples of GitHub and GitLab | Deterministic oracle plus model adjudication | [`tools/benchmark/realworld/`](../tools/benchmark/realworld/README.md) | `tools/benchmark/realworld/results*/` |
| Shadow AI discovery, code surface (87) | 87 public repositories pinned by SHA | Session-labeled facts with file pointers | [`tools/discovery_benchmark/`](../tools/discovery_benchmark/) | [`shadow-ai-discovery/`](shadow-ai-discovery/README.md) |

Only the code-surface discovery benchmark runs in automation: the weekly
[`benchmark.yml`](../.github/workflows/benchmark.yml) workflow runs ShadowScan
alone on the pinned corpus and fails on a regression against the newest
committed baseline in `shadow-ai-discovery/results/`. The other harnesses run
locally; their READMEs state the protocol, the tool versions and the limits of
each result.

Stored results are generated files. They are marked `linguist-generated` in
[`.gitattributes`](../.gitattributes) so they stay out of language statistics
and collapse in diffs.
