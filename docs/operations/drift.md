# Scheduled drift detection

A scheduled drift job answers one question each week: what changed in the
agent estate since the reviewed baseline? It reports new and removed agents,
widened tools and permissions, higher autonomy, and lost owners or
registrations. When it cannot see, it fails loudly. An incomplete scan or
comparison exits 3; it never reports "no change".

The job has three parts:

1. A scan with a reviewed configuration writes `current.json`.
2. `shadowscan diff` compares `current.json` with a reviewed, pinned baseline:

    ```bash
    shadowscan diff baseline.json current.json --json \
      --fail-on-drift inventory,capability,autonomy,governance \
      --baseline-sha256 "$SHADOWSCAN_BASELINE_SHA256" \
      --max-baseline-age-days 35 > drift.json
    ```

3. The exit code decides the job's status. The job summary shows counts per
   drift class. The reports stay private run artifacts.

## Drift classes

`diff` labels every substantive change with a drift class. It also marks
whether the change is adverse, meaning it widens what the finding can do or
weakens how the finding is governed. `--fail-on-drift CLASSES` exits 2 when a
complete comparison has adverse drift in any listed class. The list is
comma-separated, and an unknown class is a usage error (exit 1).

| Class | Compared fields | Adverse when |
| --- | --- | --- |
| `inventory` | New and resolved findings; `kind`, `resource_type` | A finding is new, or its kind or resource type changed. A resolved finding is drift but not adverse. |
| `capability` | `permissions`, `capabilities`, `frameworks`, `model_providers`, `models`, `tags` (except `autonomy-understated`), `metadata.tool_definition_sha256` | Any item is added, including MCP registry tags such as `mcp-registry-deprecated`, `mcp-registry-deleted`, `mcp-registry-version-unpublished` and `mcp-unpublished`. A mitigating tag is removed (see below). A tool definition digest changes or disappears. |
| `autonomy` | `metadata.autonomy.floor`, `.ceiling`, `.oversight`, `.initiation` | A value rises. For the floor and the ceiling, rising means a higher level. For oversight, it means moving from `gated` towards `unknown` or `bypassed`. For initiation, it means moving from `human` towards `unknown`, `event` or `schedule`. |
| `governance` | `owner`, `shadow`, `registry_match`, `metadata.registry_reconciliation.status`, tag `autonomy-understated` | The owner is cleared, or the finding becomes shadow. `registry_match` is cleared or changed. The reconciliation status becomes `observed-not-registered` or leaves `registered-and-observed`. `autonomy-understated` is added. |
| `coverage` | The comparison itself | The comparison is incomplete. Such a comparison always exits 3. |

Some tags record a limit rather than something the finding can do:
`disabled`, `inactive`, `suspended`, `expired`, `asks-user`,
`test-code-only`, `docs-only`, `example-code-only`, `generated-code-only`,
`pending-request`, `managed-secret` and `mcp-registry-published`. They are
every tag with a negative risk weight, plus three that record a control.
Their polarity is reversed: losing one is adverse (a disabled agent enabled
again, a suspended app restored, evidence no longer confined to tests), and
gaining one is not. Moving an MCP server from `mcp-registry-deprecated` to
`mcp-registry-published` is therefore drift but not adverse.

Some changes are drift but not adverse:

- an item that is only removed, unless it is a mitigating tag;
- a mitigating tag that is added;
- a first value, such as a first tool digest or a first autonomy
  classification (an unclassified finding was never known to be low);
- an owner or registry match that is newly set;
- an autonomy bound that falls.

Changes to `risk.score`, `risk.level` and `risk.factors` are not classified.
`--fail-on-new` keeps its meaning: it exits 2 on new findings and on risk
level rises. The two flags can be combined.

`coverage` is accepted in `--fail-on-drift` but never produces exit 2: a
comparison with any coverage drift is incomplete and exits 3 whatever the
selected classes. Fleet reports set `shadow: true` for findings without an
inventory, so comparing a fleet report with a single-host report shows shadow
changes as governance drift.

### Output

The JSON document keeps every earlier key and adds:

- `changed[].drift`: one entry per classified field, with `class`, `field`,
  `direction` and `adverse`. List fields add `added` and `removed` and use
  the directions `added`, `removed` and `replaced`. Scalars add `before` and
  `after` and use the directions `set`, `cleared` and `changed`. Autonomy
  bounds use `rose` and `fell` instead of `changed`. Values come from the
  exported records, so anything the export boundary redacts stays redacted.
- `drift_summary`: per class, the number of findings with drift of that
  class. Inventory counts new and resolved findings as well. Coverage counts
  the reasons the comparison is incomplete.
- `adverse`: per class, whether any drift of that class is adverse.
- `baseline`: `sha256` (of the baseline file's raw bytes), `pinned`, and
  `age_days` (whole days since the baseline scan started, or null).

Text output keeps its first line unchanged. A second line follows, for example
`drift: inventory 0, capability 1, autonomy 0, governance 0, coverage 0
(adverse: capability)`. Each changed finding's line ends with its classes,
such as `[capability, governance]`. Drift values are never printed as text.

## Exit codes

| Code | Drift job meaning |
| --- | --- |
| `0` | The comparison is complete. The selected classes have no adverse drift, and with `--fail-on-new` nothing is new and no risk level rose. |
| `1` | No usable result. Causes include an invalid option or report, a missing file, and a baseline whose digest does not match `--baseline-sha256`. |
| `2` | The comparison is complete and has adverse drift in a selected class, or with `--fail-on-new` a new finding or a higher risk level. |
| `3` | The comparison is incomplete. Causes include an incomplete scan, a different scope or connector coverage, an unattested connector, scan-local identities, and an expired or undatable baseline. |

Exit 1 takes precedence over 3, and 3 over 2. Treat every non-zero code as a
failed job: 2 needs triage of the drift, while 1 and 3 need the job fixed and
rerun. See [CI integration](ci.md#exit-code-handling).

## Which scans can be compared

A comparison completes only when both reports attest the same collection
scope (see [Comparing reports](../scanning.md#comparing-reports)). The
following scans attest it:

- local repository scans;
- offline exports from built-in connectors;
- `gateway.logs` when both scans were keyed with the same
  `SHADOWSCAN_IDENTITY_KEY`;
- the live connectors `cloud.aws`, `cloud.azure`, `cloud.gcp` and
  `identity.entra` (app-only credentials; a delegated scan, or one with a
  user's `access_token`, is never attested). Each
  records its verified principal, its requested scope and the outcome of every
  enumeration, and attests only when every enumeration succeeded. Without
  `projects` or `subscriptions`, the GCP or Azure principal is the discovered
  set: a project or subscription that appears or disappears makes the
  comparison exit 3 until a reviewed re-baseline. Pin them for a stable
  weekly job.

Every other live connector, and every third-party connector, makes the
comparison exit 3. For those connectors, use record and replay (below) or
leave them out of the drift job.

## Baseline repository and review

A baseline is a reviewed artifact, not a cache:

- **Storage.** Keep `baseline.json` in a private baseline repository, or in
  a protected artifact store. Never keep it in a scanned repository: a pull
  request there could rewrite what counts as known.
- **Accepting drift.** To accept drift, open a reviewed pull request to the
  baseline repository. It replaces `baseline.json` with the `current.json`
  of a reviewed run, and code owners approve it. The scheduled job only reads
  the baseline and never writes it.
- **Pinning.** Pin the baseline with `--baseline-sha256`, using the value
  `sha256sum baseline.json` prints. `diff` hashes the raw bytes it parses, from
  one read, and refuses any other file with exit 1 before printing anything.
  Even a whitespace edit changes the digest. Update the pinned value in the
  same reviewed change. In the baseline repository, add `*.json -text` to
  `.gitattributes` so that checkouts never convert line endings.
- **Expiry.** `--max-baseline-age-days N` measures age from the baseline's
  `started_at`. A fleet report's `started_at` is the earliest start time of
  its sources, compared as instants rather than as text. When any source has
  no valid timezone-aware start time, the fleet's `started_at` is `null`, so
  an age limit treats it as undatable instead of dating it by the merge.
  Choose N a little longer than your re-baselining cadence, for example 35
  days for monthly reviews of a weekly job. These conditions make the
  comparison incomplete (exit 3):
    - the baseline is older than N days;
    - its start time is missing, unparseable, without a timezone, or more
      than five minutes in the future;
    - it started after the current scan.
- **Scanner upgrades.** The scope fingerprint covers the scanner
  implementation and its signatures. A baseline from another scanner revision
  therefore does not compare (exit 3). Change `SHADOWSCAN_REVISION` and the
  baseline in the same reviewed change window.

A pinned, unexpired baseline shows only that the file is the one you
reviewed. It does not establish that the review was independent, or that
the baseline estate was complete beyond what its own report records.

## Workflow templates

### GitHub Actions

The [weekly drift workflow](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/github-action-drift.yml)
is meant for a private operations repository:

- **Triggers.** It runs weekly at an off-peak minute, and on manual dispatch.
  It has no pull request trigger.
- **Permissions.** The workflow has `contents: read`. Only the drift job adds
  `id-token: write`, for OIDC federation into read-only cloud roles. Remove it
  when no live connector needs it. Add your provider's login step, pinned by
  full commit SHA. Never store long-lived cloud keys.
- **Environment.** The job runs in the `shadowscan-drift` environment. Limit
  the environment's deployment branches to the default branch. Pin every
  cloud trust policy's OIDC subject to that environment
  (`repo:<owner>/<repo>:environment:shadowscan-drift`). Other branches, forks
  and pull requests then cannot assume the roles.
- **Limits.** `concurrency` stops overlapping runs. The job has a 60-minute
  timeout, and the scan has a 45-minute `--job-deadline-seconds`.
- **Scanner.** It installs the reviewed `SHADOWSCAN_REVISION` exactly as the
  [code scanning example](ci.md#github-actions) does.
- **Checkouts.** It checks out this repository, which holds the reviewed
  configuration, and then the baseline repository with a read-only token. Both
  checkouts set `persist-credentials: false`.
- **Logs.** The scan runs with `-q`, and the comparison is written to a file,
  so findings, tenant identifiers and exports never reach the log. The job
  summary lists counts per drift class and whether each is adverse.
- **Artifacts.** Both reports are uploaded as run artifacts kept for 14 days.
  Anyone who can read the repository's Actions runs can download them, so
  keep the repository private.
- **Exit codes.** Exit codes 2 and 3 fail the comparison step after the
  comparison file is written. No step hides them. The scan's own exit code is
  kept as well. When the comparison exits 0, the job still fails with the
  scan's 2 (the reviewed configuration's `options.fail_on` level was reached)
  or 3 (the scan was incomplete). The Kubernetes CronJob does the same.

| Setting | Kind | Value |
| --- | --- | --- |
| `SHADOWSCAN_REVISION` | variable | Reviewed 40-character scanner commit SHA |
| `SHADOWSCAN_CONFIG` | variable | Path of the reviewed scan configuration in this repository |
| `SHADOWSCAN_BASELINE_REPOSITORY` | variable | `owner/name` of the private baseline repository |
| `SHADOWSCAN_BASELINE_PATH` | variable | Path of `baseline.json` in that repository |
| `SHADOWSCAN_BASELINE_SHA256` | variable | `sha256sum` of the reviewed baseline |
| `SHADOWSCAN_BASELINE_TOKEN` | secret | Fine-grained token with read-only Contents access to the baseline repository alone |

**Notifications.** The template opens no issues, because that needs a write
token. To add notifications:

1. Export the per-class counts as outputs of the drift job.
2. Add a separate job with `needs: drift`, `if: always()` and
   `permissions: {issues: write}` only. Give it no `id-token`, no secrets and
   no checkout.
3. Have it open or update one issue in the private operations repository,
   with the counts and a link to the run. Use separate issues for exit 2 and
   exit 3.

Findings, tenant identifiers and reports never go into issues.

### Kubernetes

The [drift CronJob](https://github.com/aisecnomad/Project-Nexus/blob/main/examples/k8s-drift-cronjob.yaml)
runs the same scan and comparison weekly:

- **Schedule.** It uses `concurrencyPolicy: Forbid` and an active deadline.
- **Pod security.** The pod runs as non-root with a read-only root
  filesystem, all capabilities dropped and seccomp `RuntimeDefault`. Its
  image is pinned by digest.
- **Inputs.** The configuration (a ConfigMap) and the baseline (a Secret)
  are mounted read-only with `subPath`. Their volumes present each key as a
  chain of symbolic links, which ShadowScan refuses to follow. A Secret holds
  at most 1 MiB, so mount a read-only volume from the private baseline store
  for larger estates.
- **Output.** Reports go to an `emptyDir`. Upload them to a private report
  store at the placeholder in the script.
- **Credentials.** Bind the service account to read-only cloud roles through
  workload identity. The Kubernetes API token stays unmounted.

## Record, replay, compare

Connectors that do not attest a live scope can still be compared through their
record exports:

1. Collect live with `--dump-records`.
2. Replay each export through the `filename` its `manifest.json` entry names.
3. Compare the replays.

A replay attests the export's contents, not the completeness of the tenant.
Avoid these pitfalls:

- **Check the manifest.** Before replaying, read the record export's
  `manifest.json`. The top-level `complete` and each entry's `complete` and
  `exported` must be `true`. An incomplete live run can still write an export,
  and its replay then looks complete.
- **Stage at the same path.** An offline scope digest includes the export's
  resolved absolute `input` path and the connector `label`. Stage every week's
  export at the identical path with the identical label; otherwise the
  comparison exits 3 (`collection or detection scope differs`).
- **Date the baseline separately.** A replayed report's `started_at` is the
  time of the replay, not of the collection. `--max-baseline-age-days`
  therefore measures from the replay. Replay a reviewed baseline once and
  keep that report. Do not replay old exports to refresh the baseline's
  date. Record the manifest's `started_at` with the baseline review.

## Confidentiality

Reports, comparisons and baselines contain findings, resource names, account
and tenant identifiers, and owner names:

- Keep them in private repositories or stores.
- Keep artifact retention short.
- Never paste them into issues, pull requests, commit messages or workflow
  logs.

The job summary and notifications carry counts only. Fixtures and tests for
these classes are synthetic and author-written. They do not establish live
tenant acceptance or measured precision of the drift classes.
