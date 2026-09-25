# CI integration

ShadowScan is designed to run in CI pipelines. It produces SARIF output for
GitHub Code Scanning and exits with deterministic codes for gate decisions.

## GitHub Actions

A complete example is provided in `examples/github-action-code-scan.yml`.
The minimal version:

```yaml
name: Shadow AI scan
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write  # for SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install ShadowScan
        run: pip install "git+https://github.com/aisecnomad/Project-Nexus.git@COMMIT_SHA"

      - name: Scan repository
        run: shadowscan code . --format sarif -o shadowscan.sarif --fail-on high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shadowscan.sarif
```

## Exit code handling

| Code | CI interpretation |
|------|-------------------|
| `0` | Pass — scan completed, no findings above threshold |
| `2` | Fail — scan completed, findings reached `--fail-on` level |
| `3` | Warn — incomplete scan, some connectors failed |

For `--fail-on` gating, use exit code 2 as a pipeline failure. Exit code 3
should trigger a warning, not a hard failure, since it indicates partial results
rather than a policy violation.

## Container-based scanning

For isolated scanning of untrusted repositories:

```yaml
- name: Scan in container
  run: |
    docker run --rm --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --memory 1g --pids-limit 128 \
      --tmpfs /tmp:rw,noexec,nosuid,size=64m \
      --mount "type=bind,source=${{ github.workspace }},target=/input,readonly" \
      shadowscan:reviewed code /input --format sarif -o /dev/stdout > shadowscan.sarif
```

## Incremental scanning

Use `--incremental` with a persistent cache directory to skip unchanged inputs:

```yaml
- uses: actions/cache@v4
  with:
    path: .shadowscan-cache
    key: shadowscan-${{ hashFiles('**/*.py', '**/*.js', '**/*.ts') }}
    restore-keys: shadowscan-

- run: shadowscan scan -c shadowscan.yaml --incremental --fail-on high
```
