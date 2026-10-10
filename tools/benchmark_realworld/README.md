# Real-world shadow-AI discovery benchmark

This benchmark runs shadow-AI discovery tools over public GitHub repositories
at pinned commits. Labels come from a written protocol, not from any tool.
The protocol is [`PROTOCOL.md`](PROTOCOL.md). Results are in [`results/`](results/).

## What it measures, and what it does not

- Two surfaces: the **repo** surface (a repository's working tree) and the
  **home-view** surface (the same tree read as `$HOME`, for endpoint tools).
- Not measured: network, identity/SaaS, cloud and runtime. No public source of
  real traffic or tenant data exists for them. The synthetic harness in
  [`tools/benchmark`](../benchmark) covers those surfaces, and its numbers are
  not real-world numbers.
- Labels were made by two model-based labelers, not by humans. The
  orchestrator adjudicated the disagreements against the cited lines.
  This is not independent human review, and the results are not field precision
  or recall. Where the frozen [`PROTOCOL-v2.md`](PROTOCOL-v2.md) says "two
  independent code reviews", it means two separate model-agent reviews (section
  10, item 6): neither was human or independent of the author.

## Layout

| Path | Contents |
|---|---|
| `PROTOCOL.md` | Corpus rules, label definitions, procedure, tool rules, statistics, changelog |
| `corpus.json` | The 41 repositories: pinned SHA, license, stratum, label, both labelers, evidence |
| `labels/` | Labeler A's sheet (`labeler-a.tsv`), labeler B's labels, adjudication decisions |
| `build_manifest.py` | Builds `corpus.json` from `labels/`; SHAs and licenses come from the checkouts |
| `cases.py` | Manifest validation, fail-closed checkout check, home-view labels, redaction |
| `adapters.py` | Adapters for `vet`, `mcp-audit` and `shadow-mcp`, the tool list, version pins |
| `run.py` | Runs tools as a non-root account in user, network and PID namespaces |
| `score.py` | Metrics, intervals, McNemar tests, kappa, stratum counts, and `REPORT.md` |
| `install_tools.sh` | Installs every tool at its pinned version |
| `results/` | Committed verdicts (JSONL), run manifest, `REPORT.md`, summary |

Raw tool output stays outside the repository, in the `--raw` directory, after
redaction. It is never committed.

## Run it

```bash
# 1. Tools (PyPI and the Go module proxy; review install_tools.sh first, and use a disposable machine)
bash tools/benchmark_realworld/install_tools.sh /opt/rwbench/tools

# 2. Checkouts: clone each manifest repository under --checkout-root at its pinned SHA.
#    The runner refuses any checkout that is not at its pinned commit.

# 3. Run and score as a non-root account in a disposable, externally isolated VM/container.
#    Use fresh results/raw directories for the current runner; user namespaces must be available.
python -m tools.benchmark_realworld.run --manifest tools/benchmark_realworld/corpus.json \
  --checkout-root /home/user --tool-root /opt/rwbench/tools \
  --results tools/benchmark_realworld/results --raw /opt/rwbench/raw --self-check
python -m tools.benchmark_realworld.score --results tools/benchmark_realworld/results \
  --manifest tools/benchmark_realworld/corpus.json
```

## Safety

- The current runner refuses root before reading the manifest or creating outputs.
  Each tool runs as the invoking non-root user in fresh user, network and PID
  namespaces, with an empty environment and a case-specific `HOME`. Namespace
  creation failures are tool errors; there is no unsandboxed fallback.
- Run only in a disposable VM/container externally isolated from secrets and
  valuable files, using an account dedicated to this run. These namespaces do
  **not** isolate the host filesystem: tools and concurrent cases share the
  invoking UID and can access that account's files. They are not a complete
  sandbox against hostile commands.
- Output and scratch directories are private to the invoking UID. Output writes
  reject symbolic-link paths and atomically replace regular files without
  following a target link. The runner does not change the process umask.
- Repository trees are copied without `.git` and without symbolic links.
  Links are never followed.
- Secret-shaped strings are redacted before any tool output is written.
- Some tools can start MCP servers named in a repository's configuration
  (Cisco MCP Scanner). Those commands run inside the sandbox above.

The 2026-10-09 runner hardening changes the verdict-code hash. Stored v1/v2
results remain historical evidence from the earlier runner; their hashes and
verdicts have not been rewritten. Its network/PID namespaces and `nobody` drop
did not establish the earlier protocol's claim of filesystem write confinement.
A new scored run needs fresh result directories and new provenance; the current
v2 scorer intentionally refuses the historical manifests against changed code.
