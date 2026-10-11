# Shadow AI discovery benchmark harness

The harness for the code-surface shadow AI discovery benchmark: a tool-neutral
fact taxonomy, an evidence extractor used to label ground truth, adapters that
run external discovery tools and normalize their output, an isolated runner, a
scorer, a regression gate and a report generator. The corpus, the committed
results, the design and its limits live in
[`benchmarks/shadow-ai-discovery/README.md`](../../benchmarks/shadow-ai-discovery/README.md).
Read that first. Nothing here is a release artifact, and the results are not
independent: the same maintainer wrote ShadowScan, the harness and the labels.

Nothing here executes repository content. Third-party tools run as an
unprivileged user against read-only checkouts with network access disabled.
The runner is not a filesystem or network sandbox on its own, so run
third-party tools only inside an externally isolated disposable machine with
no credentials.

## Entry points

Every command is a subcommand of `python -m tools.discovery_benchmark`:

| Command | Module | What it does |
|---|---|---|
| `fetch` | `fetch.py` | Fetch (or `--verify`) every corpus repository at its pinned commit. Only `git` runs; checkouts are detached at the pinned commit. |
| `evidence` | `evidence.py` | Extract labeling evidence from checkouts: manifests, lock files, imports, well-known configuration paths, IaC resources and service hostnames, with file:line pointers. |
| `run` | `runner.py` | Run every adapter against every checkout under a scrubbed, unprivileged environment. |
| `renormalize` | `runner.py` | Re-map stored tool output with the current adapters. |
| `score` | `score.py` | Score `runs.json` against the corpus at repository, category and value level. |
| `compare` | `compare.py` | Fail when metrics regress against a committed baseline. Improvements never fail the gate. |
| `report` | `report.py` | Render `metrics.json` as Markdown. |

`taxonomy.py` defines the `<category>:<value>` facts and the alias tables that
every adapter maps onto. `corpus.py` loads and validates the pinned corpus.
`adapters/` holds one adapter per tool and the registry that lists them.

The weekly [`benchmark.yml`](../../.github/workflows/benchmark.yml) workflow
runs `fetch`, `run`, `score`, `report` and `compare` for ShadowScan alone
against the newest committed baseline. The full reproduction commands, the
tool versions and the limits of each result are in the benchmark README.
