# CI integration

ShadowScan is designed to run in CI pipelines. It produces SARIF output for
GitHub Code Scanning and exits with deterministic codes for gate decisions.

## GitHub Actions

Copy the [consumer GitHub Action](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/github-action-code-scan.yml)
into your repository and set `SHADOWSCAN_REVISION` to a reviewed full commit SHA.
The example pins its actions, checks out that exact scanner revision, installs
the hash-locked runtime and build dependencies, builds a wheel with the locked backend,
and uploads the SARIF report. Gating is controlled by the repository variable
`SHADOWSCAN_FAIL_ON`: leave it unset during analyst review, and set it to `low`,
`medium`, `high` or `critical` once your detection validation and read-only
canary support a threshold. An incomplete scan exits 3 in either mode.

## Exit code handling

| Code | CI interpretation |
|------|-------------------|
| `0` | Pass — scan completed, no findings above threshold |
| `2` | Fail — scan completed, findings reached `--fail-on` level |
| `3` | Fail — incomplete scan, some connectors failed |

For `--fail-on` gating, fail on exit codes 2 and 3. An incomplete scan may omit
findings above the threshold and cannot establish that the policy passed.

## Container-based scanning

For isolated scanning of untrusted repositories, set the repository variable
`SHADOWSCAN_IMAGE` to a reviewed image reference such as
`registry.example.com/security/shadowscan@sha256:<approved-64-hex-image-digest>`.
This is the built worker image digest, distinct from the approved base digest:

```yaml
- name: Scan in container
  env:
    SHADOWSCAN_IMAGE: ${{ vars.SHADOWSCAN_IMAGE }}
  shell: bash
  run: |
    set -euo pipefail
    [[ "$SHADOWSCAN_IMAGE" =~ ^[^[:space:]]+@sha256:[a-f0-9]{64}$ ]] || exit 1
    umask 077
    docker run --rm --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --memory 1g --pids-limit 128 \
      --tmpfs /tmp:rw,noexec,nosuid,size=64m \
      --mount "type=bind,source=${{ github.workspace }},target=/input,readonly" \
      "$SHADOWSCAN_IMAGE" code /input --format sarif > shadowscan.sarif
```

## Incremental scanning

Use `--incremental` with a private state directory outside the scanned checkout.
If you cache state between trusted main-branch runs, scope the cache to the
reviewed scanner revision and restore that exact path:

```yaml
- uses: actions/cache@0400d5f644dc74513175e3cd8d07132dd4860809 # v4.2.4
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  with:
    path: ${{ runner.temp }}/shadowscan-cache
    key: shadowscan-${{ runner.os }}-${{ vars.SHADOWSCAN_REVISION }}-${{ hashFiles('shadowscan.yaml', '**/*.py', '**/*.js', '**/*.ts') }}
    restore-keys: shadowscan-${{ runner.os }}-${{ vars.SHADOWSCAN_REVISION }}-

- run: |
    install -d -m 700 "$RUNNER_TEMP/shadowscan-cache"
    shadowscan scan -c shadowscan.yaml --incremental \
      --state-dir "$RUNNER_TEMP/shadowscan-cache" --fail-on high
```
