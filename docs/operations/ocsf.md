# OCSF events (SIEM export)

`--format ocsf` writes the scan as [OCSF](https://schema.ocsf.io/) 1.1.0
**Detection Finding** events (`class_uid` 2004), for SIEMs and security data
lakes that ingest the Open Cybersecurity Schema Framework, such as Amazon
Security Lake, Splunk or an OCSF-normalizing pipeline.

```console
shadowscan scan -c shadowscan.yaml --format ocsf -o findings.ocsf.json
```

## Document shape

The report is one JSON object with three members:

- `ocsf_version` — the OCSF schema version the events conform to (`1.1.0`).
- `events` — one Detection Finding event per finding.
- `scan` — the run itself: `status` (`complete` or `incomplete`), `complete`,
  `started_at`/`finished_at`, the summary and the sanitized per-connector
  diagnostics (`connectors[]` with `errors`, `warnings`, `skipped` and
  `skip_reason`).

Each event is class-conformant: `category_uid` 2 (Findings), `class_uid` 2004,
activity Create (`activity_id` 1, `type_uid` 200401), `metadata.product`
naming ShadowScan and its version, and `time`/`time_dt` set to the scan's end
(epoch milliseconds and ISO 8601 UTC with a `Z` suffix). `metadata.profiles`
declares the `datetime` profile, which defines `time_dt` and the other `*_dt`
attributes, so schema-validating pipelines accept them. A key whose value
would be `null` is omitted, and a result containing NaN or infinity refuses to
render at all.

| ShadowScan | OCSF |
|---|---|
| Heuristic risk level (`info`/`low`/`medium`/`high`/`critical`) | `severity_id` 1/2/3/4/5 and `risk_level_id` 0–4; `risk_score` is the heuristic score |
| Finding id, title, kind, connector, first/last seen | `finding_info` (`uid`, `title`, `types`, `data_sources`, `first_seen_time*`, `last_seen_time*`) |
| Evidence (signal, description, location, snippet capped at 200 characters, weight, signature) | `evidences[].data` |
| Resource, resource type, region, owner, provider and account | `resources[0]` (`uid`, `type`, `region`, `owner.name`, `data.provider`, `data.account`) |
| Confidence | `confidence_score` (0–100); the raw 0–1 value stays in `unmapped.confidence` |
| Surface, likelihood, shadow status, registry match, tags, frameworks, model providers, models, capabilities, permissions, risk factors | `unmapped` |

Two mappings are deliberate:

- `status_id` is always 1 (New). ShadowScan records discovery; it never
  invents a triage or verification state.
- `severity_id` carries the heuristic discovery risk level, which is not a
  CVSS score (see [severity](../severity.md)). `unmapped.score_basis` says so
  (`heuristic-not-cvss`).

Evidence attributes and raw finding metadata are not exported; use the JSON
report when you need them.

## jq examples

High and critical findings as tab-separated triage lines:

```console
jq -r '.events[] | select(.severity_id >= 4)
       | [.finding_info.uid, .severity, .finding_info.title] | @tsv' findings.ocsf.json
```

Unwrap the envelope into a bare event stream (one JSON event per line) for a
collector that expects NDJSON:

```console
jq -c '.events[]' findings.ocsf.json
```

## SIEM ingestion

Check `scan.status` **before** shipping `events`: forwarding only the event
array silently discards the completeness signal. A robust pipeline forwards
the events and raises an alert (or fails the job) when `scan.status` is
`incomplete` — the CLI already exits with code 3 in that case, whatever the
output format. Findings are sanitized before rendering and connector
diagnostics pass the shared publication boundary, so credentials never reach
the SIEM; diagnostics may contain `[REDACTED]` markers instead.

## Incomplete scans

A scan with a failed, skipped or stopped connector is never published as an
empty, clean-looking document:

- `scan.status` is `incomplete` and `scan.complete` is `false` (also mirrored
  in `scan.summary.status`), even when `events` is empty.
- `scan.connectors[]` names each connector's errors, warnings and skip
  reason.
- The exit code is 3, whatever the output format.
