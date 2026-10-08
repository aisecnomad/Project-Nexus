# Real-world shadow-AI discovery benchmark

This harness measures how well open-source tools find generative-AI use and AI
agents in **real public repositories**. The corpus is 183 GitHub and GitLab
repositories, drawn by a seeded procedure from public sampling frames and
pinned to commits. Labels come from two independent AI annotators, and every
tool runs offline on a read-only checkout.

It complements the synthetic head-to-head benchmark in
[`tools/benchmark/`](../benchmark/README.md). That one tests known patterns on
generated cases; this one tests what tools do on code nobody wrote for the
test.

> **Read this first.** The harness lives in ShadowScan's repository, and the
> protocol, sampler, adapters and baselines were written here with AI
> assistance. Labels are AI annotations, not human review. Read
> [PROTOCOL.md](PROTOCOL.md) (design, rubric, conflicts of interest, limits)
> before the results, and treat any ShadowScan lead as suspect until someone
> without a stake re-labels the corpus.

## Layout

| Path | What it is |
|---|---|
| [PROTOCOL.md](PROTOCOL.md) | Pre-registered design: question, frames, draw, label rubric, run protocol, analyses, deviations |
| [ANNOTATION.md](ANNOTATION.md) | The annotators' instructions, verbatim |
| `frames/` | Snapshot of the 63 public sampling frames |
| `purposive.json` | Hand-picked hard negatives and configuration positives, each with a reason |
| `corpus.json`, `calibration.json` | Drawn repositories (URL, commit, tree, size) |
| `draw-log.jsonl.gz` | Every draw attempt and why it was accepted or rejected |
| `labels/` | Annotator ledgers, adjudications and the frozen `labels.json` |
| `adapters.py` | How each tool is run and how its report maps to verdicts |
| `install_tools.sh` | Pinned installs of the third-party tools |
| `results/` | Normalised per-tool results, scorer summary and `REPORT.md` |

## Reproduce

Use a disposable Linux machine or container. The run uses `unshare` for mount,
network and PID namespaces, which needs root or unprivileged user namespaces.
It also needs `git`, `rg` (ripgrep), `uv`, Go and Node.js.

```bash
# 1. Rebuild the checkouts at the pinned commits (shallow clones, about 4.3 GiB).
python -m tools.realbench.fetch --manifest tools/realbench/corpus.json --output /tmp/rb/corpus

# 2. Install the third-party tools at their pins.
bash tools/realbench/install_tools.sh /tmp/rb/tools

# 3. Run every tool offline on every repository (about two hours on four cores).
python -m tools.realbench.run --manifest tools/realbench/corpus.json --corpus /tmp/rb/corpus \
  --tool-root /tmp/rb/tools --results /tmp/rb/results --workers 4 --repeat-fraction 0.1

# 4. Score against the frozen labels and render the report.
python -m tools.realbench.score --labels tools/realbench/labels/labels.json \
  --manifest tools/realbench/corpus.json --results /tmp/rb/results --output /tmp/rb/summary.json
python -m tools.realbench.report --summary /tmp/rb/summary.json --results /tmp/rb/results \
  --labels tools/realbench/labels/labels.json --manifest tools/realbench/corpus.json \
  --output /tmp/rb/REPORT.md
```

Run ShadowScan from a checkout of the commit named in
`results/run-manifest.json`. Pass `--python` the interpreter of an
environment where that checkout is installed.

To re-draw the corpus from the committed frames, which repeats the
pre-registered procedure, run:

```bash
python -m tools.realbench.sample --frames tools/realbench/frames --workdir /tmp/rb \
  --manifest /tmp/rb/corpus.json --calibration-manifest /tmp/rb/calibration.json --log /tmp/rb/log.jsonl.gz
```

Repositories deleted or rewritten since the draw make a re-draw differ. Rebuild
from `corpus.json` to reproduce the scored set exactly.

## Independent re-labelling

The most valuable contribution is a second, human labelling of the corpus by
someone without a stake in any tool. Use [ANNOTATION.md](ANNOTATION.md) and
the rubric in [PROTOCOL.md §4](PROTOCOL.md#4-labels), label from the
checkouts without looking at `labels/` or `results/`, and validate your file:

```bash
python -m tools.realbench.labels validate --corpus /tmp/rb/corpus \
  --manifest tools/realbench/corpus.json my-labels.jsonl
python -m tools.realbench.labels agree tools/realbench/labels/annotator-a.jsonl my-labels.jsonl
```
