# Scored results

`shadowscan.jsonl` holds one line per case for ShadowScan at commit `9e5b483`
on the pre-registered corpus (SHA-256 `b757b2ac…19e63`). It was recorded
before any third-party tool ran on that corpus. Third-party results are added
here as each tool is installed and run, with no change to this file.

Each line gives the case's surface, family, label and difficulty, plus the
tool's status (`ok`, `error` or `n/a`), detection, item count, agent-tier flag,
seconds and a short note. Recompute metrics with
`python -m tools.benchmark.score --results tools/benchmark/results`.
