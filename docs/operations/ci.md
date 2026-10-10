# CI integration

ShadowScan is designed to run in CI pipelines. It produces SARIF output for
GitHub Code Scanning and exits with deterministic codes for gate decisions.
SARIF results are warnings or notes for analyst triage, without a
`security-severity`: the risk level is a heuristic, not a CVSS score (see
[Severity is not an enforcement signal](../severity.md)).

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
| `1` | Fail — no usable result: invalid option, value or path, invalid configuration or inventory, setup failure, or a report that could not be written |
| `2` | Fail — scan completed, findings reached `--fail-on` level |
| `3` | Fail — incomplete scan, some connectors failed |

Fail the gate on every non-zero exit code, as a shell step does by default.
Do not check for 2 and 3 alone: exit 1 means there is no scan result, not that
the policy passed. An incomplete scan may omit findings above the threshold and
cannot establish that the policy passed either. Use the code only to choose the
follow-up: 2 needs finding triage, 1 and 3 need the scan fixed and rerun.

To gate on drift between two reports, `shadowscan diff baseline.json current.json
--fail-on-new` exits 2 when the current report has new findings or findings
whose risk level rose, and 3 when the comparison is incomplete (differing scope
or an incomplete scan). Without the flag, `diff` exits 0 unless the comparison
is incomplete. Local `code.filesystem` scans, offline exports from built-in
connectors and live `cloud.aws`, `cloud.azure`, `cloud.gcp` and
`identity.entra` collections attest a comparable scope, `gateway.logs` only
when both scans were keyed with the same identity key. A live scan by one of
those four connectors attests only when it completed, every listing succeeded
and the provider confirmed the account, tenant, projects or subscriptions (see
[live collection scope](../scanning.md#live-collection-scope)); otherwise the
comparison exits 3. A comparison involving any other live API connector or a
third-party connector always exits 3, even for identical reports.

## Scheduled drift detection

For a weekly drift gate, compare each new scan with a reviewed baseline:

```bash
shadowscan diff baseline.json current.json --json \
  --fail-on-drift inventory,capability,autonomy,governance \
  --baseline-sha256 "$SHADOWSCAN_BASELINE_SHA256" --max-baseline-age-days 35 > drift.json
```

`--fail-on-drift` exits 2 when a complete comparison has adverse drift in a
listed class: `inventory`, `capability`, `autonomy`, `governance` or
`coverage`. Coverage drift is an incomplete comparison, which always exits 3.
`--baseline-sha256` refuses a baseline whose file bytes differ from the
reviewed digest (exit 1). `--max-baseline-age-days` makes the comparison
incomplete (exit 3) when the baseline is too old or cannot be dated.

The [weekly drift workflow](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/github-action-drift.yml)
and [Kubernetes CronJob](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/k8s-drift-cronjob.yaml)
templates run this on a schedule. They never run for pull requests and never
print findings to logs. [Scheduled drift detection](drift.md) covers the drift
classes, the baseline review process and the record-and-replay alternative.

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
A cached result is reused only when every input file keeps its identity as
well as its content: device, inode, mode, size, and modification and change
times are part of the input fingerprint. A fresh checkout recreates every
file, so state restored into a new CI job (for example with `actions/cache`)
is never reused. Restoring it only costs time. Incremental scanning pays off
where the same working tree persists between scans, such as a workstation or
a self-hosted runner that keeps its workspace. There, too, keep the state
directory private (mode 0700) and outside every scanned path:

```sh
install -d -m 700 "$HOME/.local/state/shadowscan"
shadowscan scan -c shadowscan.yaml --incremental --fail-on high
```

The repository's own `audit.yml` workflow also runs `pip-audit` against every hash lock weekly and on demand, independent of commits.
