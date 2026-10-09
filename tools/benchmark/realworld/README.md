# Real-world Shadow-AI discovery benchmark

Runs open-source Shadow-AI / agent-discovery tools on **real public repositories** (GitHub and GitLab)
and measures how often they notice LLM, agent, MCP and coding-agent integrations, and how often they raise
a false alarm. It complements the synthetic head-to-head in [`../README.md`](../README.md), whose cases
were written in this repository and which cannot say anything about code in the wild.

> **Read [PROTOCOL.md](PROTOCOL.md) first.** It states the sampling, ground truth, tool rules, metrics, the
> changes made after an independent design review, and what the benchmark does *not* show. This benchmark is
> **not independent**: ShadowScan, one of the tools scored, is developed in the same repository. The ground
> truth is a deterministic oracle plus language-model adjudication of disagreements; neither is human review.
> Results are for offline runs of pinned tool versions on one dated sample, not field precision or recall,
> and nothing here ranks the tools. Nothing was committed while the benchmark ran (the files were an uncommitted working tree), and
> `results/freeze.json` records the hashes the scored run was checked against.

| File | Purpose |
|---|---|
| [PROTOCOL.md](PROTOCOL.md) | the protocol, its limits and its change log |
| [CORPUS.md](CORPUS.md) | generated description of the scored sample |
| [REPORT.md](REPORT.md) | generated results, with a written findings section |
| `manifest.jsonl`, `calibration.jsonl` | the sample: URL, pinned commit, tree hash, size, frame, metadata |
| `labels.jsonl`, `labels-calibration.jsonl` | oracle output (version 2) for each repository |
| `exclusions.json` | scored repositories that the ShadowScan repository names (`contamination.py`) |
| `rejects.jsonl`, `sampling-summary.json` | why candidates were not used; pool sizes; seed |
| `registry/ai_registry.json` | the oracle's knowledge (packages, imports, paths, markers) and its revision log |
| `registry/vocab-overlap.json` | which tools' own source mentions each registry technology (`vocab_overlap.py`) |
| `oracle.py` | tool-independent labeller (standard library only; run with `python -I`) |
| `frames.py`, `sample.py`, `fetch.py`, `fetch_corpus.py`, `purposive.json` | where repositories come from; the hardened snapshot fetcher; corpus re-creation |
| `adapters.py`, `baseline_grep.py` | one run command and one fixed "detected" rule per tool; keyword baselines |
| `sandbox.py`, `run.py`, `freeze.py` | network-less, unprivileged, file-system-restricted runs; the parallel resumable runner; the hash freeze |
| `score.py`, `adjudicate.py`, `report.py`, `corpus_summary.py` | statistics, blinded adjudication, rendering |
| `rerun_errors.py`, `record_environment.py` | re-run timeouts alone (declared sensitivity); hash the stored corpus and tool packages |
| `install_tools.sh` | pinned installation of the third-party tools (ShadowScan from this checkout) |
| `results/` | normalised per-repository outcomes, scored summary, run manifest, freeze record (no raw tool output) |

## Reproduce

Needs root (namespaces, cgroups, `pivot_root`), a user named `rwb` (`useradd -r -M rwb`), Python 3.13, Node 22,
Go and `uv`. Use a disposable machine: the scripts download and run third-party code and clone untrusted
repositories (nothing from a repository is ever executed outside the sandbox).

```bash
bash tools/benchmark/realworld/install_tools.sh /opt/rwb/toolroot
python -m tools.benchmark.realworld.fetch_corpus --manifest tools/benchmark/realworld/manifest.jsonl --corpus WORK/corpus
python -I tools/benchmark/realworld/oracle.py --registry tools/benchmark/realworld/registry/ai_registry.json \
    --manifest tools/benchmark/realworld/manifest.jsonl --corpus WORK/corpus --out labels.jsonl
python -m tools.benchmark.realworld.freeze --write results/freeze.json
python -m tools.benchmark.realworld.run --manifest tools/benchmark/realworld/manifest.jsonl \
    --corpus WORK/corpus --tool-root /opt/rwb/toolroot --results results --workers 8 --timeout 600 \
    --freeze results/freeze.json
python -m tools.benchmark.realworld.score --manifest tools/benchmark/realworld/manifest.jsonl \
    --labels tools/benchmark/realworld/labels.jsonl --results results --output results/summary.json
python -m tools.benchmark.realworld.report --summary results/summary.json --run-manifest results/run-manifest.json \
    --manifest tools/benchmark/realworld/manifest.jsonl --labels tools/benchmark/realworld/labels.jsonl \
    --results results --freeze results/freeze.json --output REPORT.md
```

Unit tests: `python -m pytest tests/test_benchmark_realworld.py`.

## Safety notes

* Repositories are cloned with hooks, LFS and submodules disabled, `.git` removed, and every symlink that is
  absolute, dangling, cyclic or physically resolves outside the snapshot replaced by a text file. The oracle
  and the keyword baseline run with `python -I`; the baseline runs inside the sandbox.
* Tools run as an unprivileged user with no capabilities, no network, an empty `HOME`, a memory cap, a
  wall-clock kill and a minimal root file system (no home directory, corpus, labels or other session). The
  privileged process reads tool output only through `Session.read`, which refuses symlinks anywhere in the
  path; a database a tool writes is opened by an unprivileged process inside the sandbox.
* Raw tool output is discarded: public repositories can contain other people's credentials, and AGENTS.md
  forbids persisting them. Rows keep fixed-vocabulary notes, exception class names and filtered names.
