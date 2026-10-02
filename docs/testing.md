# Testing guide

This page describes how to set up a reproducible development environment and
run ShadowScan's test suites the way CI does. The gates themselves are defined
in the [contributor guide](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#quality-gates);
this page is the practical companion.

## Environment

ShadowScan supports CPython 3.11, 3.12 and 3.13 on Linux and macOS. On Windows
use WSL: the confined file reader needs `O_NOFOLLOW` and `dir_fd`, and the
Makefile assumes `/tmp` and a `.venv/bin` layout.

```bash
python -m venv .venv
source .venv/bin/activate
make install          # hash-locked runtime, cloud, development and docs sets
pre-commit install    # optional: run the lint, format and secret hooks on commit
```

`make install` installs `requirements-ci.lock`, `requirements.lock` and
`requirements-docs.lock` under `--require-hashes --only-binary=:all:` and then
the scanner itself in editable mode. `make install-dev` installs only the
hash-locked core and development set, which is enough for lint, typing and the
offline suite but leaves the cloud SDK code paths unexercised. Do not work
around a hash mismatch: a lock that no longer installs is a signal to review,
not to bypass.

The development set already includes the `types-PyYAML` and `types-requests`
stubs that `mypy` needs. The third-party packages that ship neither stubs nor
a `py.typed` marker (`regex`, `boto3`, `botocore` and `oci`) are the only
modules `pyproject.toml` allows to be imported untyped.

## Run one test

```bash
python -m pytest -q tests/unit/test_signatures.py::test_all_signatures_load_and_validate
```

This loads and validates the bundled signature packs and needs no credentials.
A single passing test says nothing about the rest of the suite.

## The full suite

Every test is offline. Connector tests use fixtures under `tests/fixtures/` and
stubbed transports; nothing contacts a tenant, a cloud API or the network, and
no test needs credentials. The `tests/test_canaries.py` cases exercise the
canary tool against replay fixtures only; live canaries are a separate,
operator-run procedure described in [Tenant canaries](canaries.md).

```bash
make test-fast      # stop at the first failure, no coverage
make test           # full suite with line and branch coverage and the 80% aggregate floor
make coverage-gate  # 75% floor for every connector module; run after make test
```

`make coverage-gate` exports the coverage data recorded by the preceding
`make test`. Both floors count branches as well as statements, and the
per-connector floor covers every module under `shadowscan/connectors/`,
including the shared `base`, `common` and `offline` modules. It needs the cloud
SDKs installed, so run it after `make install` rather than `make install-dev`.

`tests/conftest.py` keeps the suite independent of the host:

- **Name resolution.** Hostnames resolve to one fixed public address instead
  of the host's DNS, so a sinkhole or split-horizon resolver cannot flip the
  scanner's private-address checks. Names under the reserved `.example`,
  `.invalid` and `.test` domains do not resolve, as on any real resolver. IP
  literals and `localhost` resolve normally, and a test that patches
  `socket.getaddrinfo` itself takes precedence.
- **No outbound connections.** A socket connection to anything other than
  loopback fails, and the test fails at teardown even if the code under test
  handled the error. Serve test traffic from a loopback server.
- **Signature-matching budgets.** Regex operations and inputs normally get
  100 ms and two seconds. On a busy machine an expired budget silently drops
  matches, so tests run with generous budgets. A test about the budgets
  themselves is marked `@pytest.mark.production_budgets` and keeps the shipped
  values; `--strict-markers` rejects a misspelt marker.
- **Signature packs.** An `Engine` built without an index reparses the
  signature packs. The suite reuses one index of the built-in packs, parsed at
  session start, while their source digest is unchanged; organization pack
  directories and override approval always load for real.

Timing assertions use generous bounds, thread CPU time, or a fixed clock, so a
loaded runner does not fail them.

Useful pytest patterns:

```bash
python -m pytest -q tests/unit -k gateway      # tests whose id mentions gateway
python -m pytest -q -x --tb=short              # stop early, short tracebacks
python -m pytest -q --co tests/unit | head     # list collected tests
```

### Expected skips

Some tests skip by design when the host cannot exercise them. Read the skip
summary (`python -m pytest -q -rs`) before trusting a local run:

- **Cloud SDKs missing.** `make install-dev`, or any install without the
  `cloud` extra, skips about 60 tests that call `pytest.importorskip` for
  `oci`, `boto3`/`botocore` or `google-auth`. The per-connector coverage floor
  also needs those SDKs, so run `make install` for the full suite.
- **Git older than 2.45, or no `git` on `PATH`.** Tests marked
  `requires_git_2_45` run real `use_git` history enrichment and skip (see
  `tests/conftest.py`).
- **Running as root.** A process that ignores directory read permission (root,
  or a process with `CAP_DAC_READ_SEARCH`) skips
  `test_scan_below_a_real_search_only_ancestor_is_complete` in
  `tests/unit/test_confined_source_reads.py`. Run the suite as an unprivileged
  user to exercise it.
- **Platform features.** Tests that need symbolic links, `O_PATH`, POSIX
  `flock`, FIFOs, pseudo-terminals or `AF_UNIX` sockets skip where the
  platform or sandbox lacks them.

## Other gates

```bash
make lint            # ruff check
make format-check    # ruff format --check
make typecheck       # mypy on the scanner and tools
make signatures      # signature schema and regex validation
make audit           # pip-audit on the environment and every hash lock, as CI
make secrets         # fail on hardcoded credentials in tracked files, as CI
make evaluate        # every bundled detection corpus
make policy          # workflow, issue-form and repository consistency checks
make check           # all of the above, in order
```

`make evaluate` runs each corpus under `tools/evaluation/`; a corpus fails on
an unwaived regression, an over-budget or expired known-gap waiver, or a waived
case that now passes. See [Evaluation](evaluation.md) for the report format.
`make policy` runs `tests/test_repository_policy.py` and
`tests/test_repository_consistency.py`, which check action pins, permissions,
Markdown links and heading anchors, and that the Makefile, hooks and locks
match CI. Run it whenever you touch `.github/`, a top-level document or a docs
page; `make docs` builds the site with `mkdocs build --strict` and catches the
rest.

`make secrets` runs `tools/check_secrets.py` over every tracked file. It reports
credential-shaped strings (provider tokens and keys, private-key headers, passwords
in URLs) and prints at most four characters of a match. Examples in documentation
need an obvious placeholder (`example`, `redacted`, a run of `0` or `x`); tests and
the labelled detection corpora are excluded.

`tests/unit/test_regex_linearity.py` guards against denial of service by regular
expression. CPython's `re` cannot be interrupted, so a quadratic pattern defeats the
connector and job deadlines. The test builds hostile inputs from the words of every
module-level `re` pattern, times the method the code calls on it at two sizes and
fails when the time grows faster than the input; the redaction passes are timed
end to end through `sanitize_text` instead. The test takes about 15 seconds. When
it fails, make the pattern linear (possessive quantifiers from the `regex` module,
run under `pattern_timeout()`), bound its input, or add it to `ALLOWED` with the
reason the sweep's input cannot reach it.

## What CI runs

The [CI workflow](https://github.com/aisecnomad/Project-Nexus/blob/main/.github/workflows/ci.yml)
runs the same commands on Linux for Python 3.11, 3.12 and 3.13 and on macOS for
3.11 and 3.13, installs the hash-locked dependency sets, audits every lock,
builds and validates the wheel outside the checkout, and on Python 3.13 builds
and smoke-tests the container image. The Linux Python 3.11 job runs the suite
with line and branch coverage and enforces both coverage floors; tracing slows
the suite several-fold, so the other jobs run the same full suite without it.
The Linux jobs also run the `no-hardcoded-secrets` pre-commit hook over every
tracked file it selects. The `CI gate` job requires every job, including DCO on
pull requests, to succeed. A new push to a pull request cancels its running
checks, but a run on `main` always finishes, because release evidence needs a
successful push run for the exact commit. [CI integration](operations/ci.md)
describes running the scanner itself inside a pipeline.

## Troubleshooting

- **`ModuleNotFoundError` for a cloud SDK, or a skipped SDK test:** the
  environment came from `make install-dev`. Run `make install`.
- **`policy input must not traverse symbolic links` or `scan root must not
  traverse a symbolic link`:** the scanner refuses symlinked input paths by
  design. Pass a resolved path; the evaluation, benchmark, canary and
  acceptance tools already resolve the temporary directories they create,
  which matters on macOS, where `/tmp` and `/var` are symbolic links.
- **The Unix-socket report test skips:** some sandboxes forbid `AF_UNIX`
  sockets and the test skips on `EPERM`. Hosted CI runs it.
- **`ValueError: current limit exceeds maximum limit` from `resource`:** the
  bounded-YAML subprocess check falls back from `RLIMIT_AS` to `RLIMIT_DATA`;
  report a platform where neither applies.
- **Coverage below a floor:** `python -m coverage report --skip-empty` shows
  the missing lines and the branches never taken (`12->15` means line 12 never
  continued to line 15). Add offline tests rather than lowering the floor.
- **`test attempted outbound connections`:** the test reached for the network.
  Stub the transport, or serve the response from a loopback server.

Bug fixes need a regression test, and connector changes need offline fixtures
and documentation, as the
[pull request requirements](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#pull-requests)
describe.
