# Fleet dashboard and inventory export

`shadowscan dashboard` writes a static, self-contained HTML page from JSON
reports you already hold, and optionally the same data as a versioned JSON
document (`shadowscan.inventory/v1`) for BI and SIEM tools. There is no
server: the page makes no requests and loads no external assets.

```console
shadowscan merge laptop-*.json --format json -o fleet.json
shadowscan dashboard fleet.json -o dashboard.html --inventory-json inventory.json
shadowscan dashboard laptop-*.json --baseline last-week.json --history weekly/ -o dashboard.html
```

Several reports are merged exactly as [`shadowscan merge`](../scanning.md#fleet-merge)
merges them. One report is not merged again: a fleet report keeps its
sources and each finding's `metadata.merged_from`, and a single scan becomes
a fleet of one source. Its findings are read as a merge reads a source, so
one report shows what it would show among others: each applicable finding's
[autonomy](../concepts/autonomy.md) interval is classified again and admits
at least what its own block admits (a report written before autonomy tiers
is classified, not shown as unclassified), and a report written before
`inventory_present` existed counts as having an inventory when its
`inventory_size` is above zero or any finding has a shadow status.

| Option | Effect |
| --- | --- |
| `-o`, `--output` | The HTML page (required). |
| `--inventory-json FILE` | Also write the `shadowscan.inventory/v1` document. It must differ from `--output`. |
| `--baseline FILE` | Show drift against an earlier report, computed as [`shadowscan diff`](../scanning.md#comparing-reports) computes it. |
| `--history DIR` | Show trends from the JSON reports in `DIR` (see [History](#history)). |
| `--as-of TIME` | Measure staleness against this ISO 8601 time with a UTC offset, such as `2026-10-10T00:00:00Z`. |

## What the page shows

The sections appear in this order. Every table is written into the page, so
the page reads completely with JavaScript disabled. One script, allowed by
its hash in the Content Security Policy, adds filtering, sorting and paging
to the AI systems table; its controls are buttons and form fields that work
from the keyboard, and they stay hidden without the script.

1. **Coverage.** One row per source: whether it completed, when it was last
   scanned, how many whole days before the reference time that was
   (staleness), how many findings it reported and whether it supplied an
   inventory. Then one column per connector any source ran, at most 100; a
   note says how many more columns are only in the JSON document. Scan-level
   `engine.*` records are not connectors and get no column, as for `diff`
   coverage: they still make a source incomplete and are listed in the
   diagnostics. Incomplete and stale sources come first. Connector
   diagnostics (errors, warnings and skip reasons) follow, open when the
   inventory is incomplete.
2. **Overview.** Counts of AI systems by inventory status, risk level,
   surface, kind, provider, account and owner, and the unowned count. An AI
   system here is any finding except a credential. Each table shows its 25
   largest values; the rest are in the JSON document.
3. **Autonomy and shadow status.** AI systems by
   [autonomy](../concepts/autonomy.md) floor (rows L0 to L5, not classified
   and not applicable) against shadow, sanctioned and no inventory. The
   shadow L4 and L5 cells are outlined, labelled "priority" and link to the
   next section.
4. **Priority.** The shadow AI systems whose autonomy floor is L4 or above.
   AI systems without an inventory or without an autonomy interval are
   counted in a warning above the list: they are unknown, not absent.
5. **Vendor registry reconciliation.** One row per registry type and registry
   id: records, the four [reconciliation statuses](../inventory.md#vendor-registries-as-inventory-sources),
   records without a reconciliation, approved, not approved and
   auto-approved records, and whether every listing was complete.
6. **Threat and control references.** How many AI systems each
   [reference](../concepts/mappings.md) is relevant to, with the catalog
   title. Evidence references, not compliance determinations.
7. **Drift against the baseline** (with `--baseline`).
8. **History** (with `--history`).
9. **AI systems.** One row per finding that is not a credential, highest
   risk first.

The page holds at most 5,000 AI system rows, 1,000 source rows, 100
connector columns, 1,000 priority rows and 100 new-since-baseline rows. A
table that holds fewer rows or columns than the data says how many more are
in the JSON document; nothing is cut silently.

## Missing data is never zero

| The page says | Meaning |
| --- | --- |
| complete | The connector run finished without errors. |
| cached | The run reused results from the incremental cache. |
| incomplete | The run reported errors or stopped early. |
| skipped | The run was skipped. |
| not collected | The source did not run this connector at all. |
| unknown | The source comes from a fleet report written before sources recorded their connector runs, or its time is missing. |
| no inventory | No inventory was supplied, so the AI system was never reconciled. It is neither shadow nor sanctioned. |
| not classified | The finding is of a kind the autonomy scale describes, but it carries no valid interval: its tier is unknown, and it could be at L4 or above. |
| not applicable | The autonomy scale does not describe the finding's kind (a grant, identity, infrastructure or other enabler). |
| unknown (no inventory), not classified | In history: a report without an inventory, or without any autonomy interval. |

A source that was not collected is never a zero row. When any source or
connector run is incomplete or skipped, the page opens with the incomplete
banner and the command exits 3.

Shadow status comes from the merged findings. A fleet merge keeps it
three-valued: shadow when any source found the AI system unregistered,
sanctioned only when every source matched it to an inventory, and no
inventory when no source supplied one. An AI system sanctioned in one source
and not reconciled in another stays shadow and is labelled "not reconciled
in every source".

A fleet report merged by an earlier version (before
`shadowscan.fleet-merge/v2`) recorded every AI system that some source did
not reconcile as shadow, including one from a source without an inventory.
When such a report shows no inventory at all (no `inventory_present`, an
`inventory_size` of 0 and no sanctioned finding), its AI systems read "no
inventory". Otherwise their shadow status is kept, and the coverage and
priority sections warn that shadow counts may include unreconciled AI
systems. Merge the source reports again with this version to remove the
ambiguity.

## Drift and history

With `--baseline`, the drift section uses the same comparison as
`shadowscan diff`: counts of new, resolved, unknown, changed and not
comparable findings, and the [drift classes](drift.md#drift-classes) with
whether each is adverse. The coverage class counts the reasons the
comparison is incomplete, not findings. When the comparison is not
comparable, the page opens with a "baseline not comparable" banner, the
section says why, findings missing from the current reports are unknown
rather than resolved, and the command exits 3.

### History

`--history DIR` reads every `*.json` file directly in `DIR` with the same
bounded, link-refusing loader as `diff`. A symbolic link, special file or
more than 1,000 reports is refused (exit 1). Reports are ordered by
`started_at`. A report without a valid start time is listed by name outside
the series. At most the newest 104 reports (two years of weekly runs) are
shown, with a note saying how many were left out.

For each report the page shows its AI systems, shadow AI systems and AI
systems with an autonomy floor of L4 or above, as a table and as an inline
SVG line. For each pair of consecutive reports it shows drift counts only
when the pair is comparable. Any other pair is a gap ("not comparable: N
reasons"), and the line breaks there; it is never drawn as zero drift.
Only counts are published, so the history comparison validates and matches
findings as `diff` does but does not pass them through the export boundary
that `diff` applies to the findings it prints. History files are read
twice with at most two reports in memory, and the second read must match the
first read's SHA-256. History never changes the exit code.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every input was complete, and the baseline comparison, if any, was comparable. |
| 1 | Invalid input: an unreadable or malformed report, a malformed fleet source list, a refused history directory, an unwritable output, or an invalid option. |
| 3 | An input report or source is incomplete, or the baseline comparison is not comparable. The page and the JSON document are still written. |

## Confidentiality and safety

The dashboard holds resource identifiers, owners, accounts and registry
identifiers, so it is as confidential as the reports behind it.

- Both files are written with mode 0600, atomically, and never through a
  symbolic link. A failed render leaves earlier files unchanged.
- Report values are untrusted input. Every value is HTML-escaped and terminal
  controls are shown as `\uXXXX`. The Content Security Policy allows only
  the page's own script and inline styles; there are no images, links to
  other origins, forms or event-handler attributes.
- Credential findings (`secret` and `token`) are counted and left out.
  Records carry no evidence snippets, evidence attributes, permissions or raw
  metadata. Each finding passes its sanitizer first; source names,
  diagnostics and history come from report files and are sanitized again.
- Nothing in the page or the document is a compliance determination,
  certification or score. Risk is the scanner's discovery heuristic, and
  threat and control references are author mappings, not independently
  reviewed.
- The output depends only on the inputs: staleness is measured against
  `--as-of` or the newest source, never the wall clock, so the same reports
  give the same bytes.

## Size and performance

A regression test builds the document and renders both outputs for 20,000
synthetic findings and for a quarter as many. Four times the findings must
take less than eight times as long (a step that grew with the square of the
input would take sixteen), and the full run must stay within
`30 + 150 × findings / 100,000` seconds, a ceiling generous enough for
coverage tracing on a shared CI runner. Without coverage tracing, on a
shared four-CPU machine, 100,000 findings took about 22 seconds (a 3.4 MB
page and a 170 MB JSON document); most of that is the per-finding sanitizer
check. Run the full-size case with:

```console
SHADOWSCAN_DASHBOARD_FINDINGS=100000 python -m pytest tests/unit/test_dashboard.py -k budget
```

History has its own regression test: ten reports at 5,000 findings and at a
quarter as many must scale linearly, and the full run must stay within
`10 + 120 × reports × findings / 1,000,000` seconds. Without coverage
tracing, on the same machine, 104 weekly reports of 10,000 findings each
(8.5 MB per report) took about 74 seconds. Raise the test's size with
`SHADOWSCAN_HISTORY_FINDINGS`.

The coverage panel and `sources[].coverage` grow with the connector runs the
sources list, not with sources times connector names.

The synthetic findings are author-written; the measurements are not a field
benchmark.

## The `shadowscan.inventory/v1` document

The JSON document has sorted keys and is ASCII only, so control characters
and unpaired surrogates stay escaped. Consumers should check `schema`.
Fields may be added within v1; a removed or renamed field, or a changed
meaning, gets a new schema version. This example is abridged: the autonomy
rows, references and records are shortened.

```json
{
  "agents": [
    {
      "account": "laptop-a",
      "autonomy": {
        "basis": [{"bound": "oversight", "rule": "approval-bypassed", "value": "bypassed"}],
        "ceiling": 5,
        "ceiling_label": "L5 Fully Autonomous",
        "floor": 4,
        "floor_label": "L4 High Autonomy",
        "initiation": "schedule",
        "oversight": "bypassed",
        "schema": "shadowscan.autonomy/v1"
      },
      "autonomy_status": "classified",
      "capabilities": ["tool-use", "code-exec"],
      "confidence": 0.95,
      "connector": "endpoint.mcp",
      "controls": ["nist-ai-rmf-1.0:GOVERN-1.6"],
      "first_seen": null,
      "fleet_inventory": null,
      "frameworks": ["protocol.mcp"],
      "id": "ss-18646b80791d8d86",
      "inventory_status": "shadow",
      "kind": "mcp-server",
      "last_seen": null,
      "likelihood": "strong",
      "merged_from": ["laptop-a/report.json"],
      "model_providers": [],
      "models": [],
      "owner": "alice@example.com",
      "provider": "workstation",
      "region": null,
      "registry": null,
      "registry_match": null,
      "registry_reconciliation": null,
      "resource": "endpoint:laptop-a/claude-desktop/fs",
      "resource_type": "mcp-config",
      "risk": {"danger_score": 70, "level": "high", "score": 72},
      "shadow": true,
      "surface": "endpoint",
      "tags": ["mcp-auto-approve"],
      "threats": ["owasp-asi-2026:ASI02", "owasp-llm-2026:LLM03"],
      "title": "MCP server fs in Claude Desktop"
    }
  ],
  "as_of": "2026-10-10T00:00:00+00:00",
  "autonomy": {
    "basis": "floor",
    "not_classified": 0,
    "priority": 1,
    "priority_floor": 4,
    "rows": [
      {
        "autonomy_status": "classified",
        "label": "L4 High Autonomy",
        "no-inventory": 0,
        "sanctioned": 0,
        "shadow": 1,
        "tier": 4,
        "total": 1
      },
      {
        "autonomy_status": "not-classified",
        "label": "not classified",
        "no-inventory": 0,
        "sanctioned": 0,
        "shadow": 0,
        "tier": null,
        "total": 0
      }
    ]
  },
  "comparable": true,
  "complete": true,
  "counts": {
    "ai_systems": 1,
    "by_account": [{"count": 1, "value": "laptop-a"}],
    "by_kind": [{"count": 1, "value": "mcp-server"}],
    "by_owner": [{"count": 1, "value": "alice@example.com"}],
    "by_provider": [{"count": 1, "value": "workstation"}],
    "by_risk_level": [
      {"count": 0, "value": "critical"},
      {"count": 1, "value": "high"},
      {"count": 0, "value": "medium"},
      {"count": 0, "value": "low"},
      {"count": 0, "value": "info"}
    ],
    "by_surface": [{"count": 1, "value": "endpoint"}],
    "excluded_credentials": 0,
    "inventory_status": {"no-inventory": 0, "sanctioned": 0, "shadow": 1},
    "not_reconciled_in_every_source": 0,
    "unowned": 0
  },
  "coverage": {
    "complete_sources": 2,
    "connectors": ["endpoint.mcp"],
    "incomplete_sources": 0,
    "sources": 2,
    "unknown_coverage_sources": 0
  },
  "diagnostics": [],
  "diagnostics_omitted": 0,
  "drift": null,
  "generated_at": "2026-10-09T08:00:40+00:00",
  "generator": {"name": "ShadowScan", "version": "0.1.2"},
  "history": null,
  "legacy_fleet": false,
  "reasons": [],
  "references": {
    "controls": [
      {
        "count": 1,
        "edition": "1.0",
        "framework": "NIST AI Risk Management Framework (AI 100-1)",
        "ref": "nist-ai-rmf-1.0:GOVERN-1.6",
        "title": "Mechanisms exist to inventory AI systems"
      }
    ],
    "note": "Evidence references, not compliance determinations.",
    "threats": [
      {
        "count": 1,
        "edition": "2026",
        "framework": "OWASP Top 10 for LLM Applications",
        "ref": "owasp-llm-2026:LLM03",
        "title": "Excessive Agency"
      }
    ]
  },
  "registries": {"malformed_records": 0, "registries": []},
  "report_version": "0.1.2",
  "schema": "shadowscan.inventory/v1",
  "sources": [
    {
      "complete": true,
      "connectors": [{"connector": "endpoint.mcp", "status": "complete"}],
      "coverage": {"endpoint.mcp": "complete"},
      "findings": 1,
      "finished_at": "2026-10-05T08:01:10+00:00",
      "inventory_present": true,
      "name": "laptop-a/report.json",
      "staleness_days": 4,
      "started_at": "2026-10-05T08:00:00+00:00",
      "version": "0.1.2"
    }
  ],
  "status": "complete"
}
```

### Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `shadowscan.inventory/v1`. |
| `generator` | object | `name` (`ShadowScan`) and the `version` that wrote the document. |
| `generated_at` | string or null | The input's `finished_at`, else its `started_at`; never the time the document was written. |
| `report_version` | string or null | The scanner version recorded in the input report. |
| `as_of` | string or null | The reference time for staleness: `--as-of`, else the newest source's last scan. |
| `complete`, `status` | boolean, string | `false` and `incomplete` when the input or any source was incomplete. |
| `comparable`, `reasons` | boolean, array | Whether the input's collection scope is comparable with `shadowscan diff`, and the scope's reason when it is not. |
| `legacy_fleet` | boolean | The input is a fleet report merged before `shadowscan.fleet-merge/v2`, whose shadow counts may include unreconciled AI systems. |
| `coverage` | object | `connectors` (every connector any source ran, without scan-level `engine.*` records), `sources`, `complete_sources`, `incomplete_sources` and `unknown_coverage_sources`. |
| `sources` | array | One entry per source; see below. |
| `diagnostics`, `diagnostics_omitted` | array, integer | Connector runs with errors, warnings or a skip reason: `connector`, `status`, the first 20 `errors` and `warnings` with `errors_total` and `warnings_total`, and `skip_reason`. At most 500; the rest are counted. |
| `counts` | object | `ai_systems`, `excluded_credentials`, `inventory_status` (`shadow`, `sanctioned`, `no-inventory`), `not_reconciled_in_every_source`, `unowned`, and `by_surface`, `by_kind`, `by_provider`, `by_account` and `by_owner` as `{value, count}` lists, most frequent first, with `value` null when not recorded; `by_risk_level` lists every level, most severe first. |
| `autonomy` | object | `basis` (`floor`); `rows`, one per tier and then not classified and not applicable (`tier` 0 to 5 or null, `autonomy_status` `classified`, `not-classified` or `not-applicable`, `label`, `shadow`, `sanctioned`, `no-inventory`, `total`); `priority_floor` (4); `priority` (shadow AI systems at or above it); and `not_classified` (AI systems whose tier is unknown). |
| `registries` | object | `registries`, one per registry type and id: `records`, `registered-and-observed`, `registered-not-observed`, `observed-not-registered`, `not-comparable`, `unreconciled`, `approved`, `not_approved`, `auto_approved` and `listing_complete`; and `malformed_records`. |
| `references` | object | `note`, and `threats` and `controls` as `{ref, title, framework, edition, count}`, most frequent first. |
| `drift` | object or null | With `--baseline`: `comparable`, `reasons`, `baseline_started_at`, `baseline_age_days`, `counts` (`new`, `resolved`, `unknown`, `changed`, `not_comparable`), `classes` and `adverse` per drift class, and the finding ids in `new`, `resolved`, `unknown` and `changed`. |
| `history` | object or null | With `--history`: `reports`, `shown`, `omitted`, `limit`, `undated` (names), `points` (`name`, `sha256`, `started_at`, `finished_at`, `complete`, `ai_systems`, `shadow`, `l4_plus`; null when unknown) and `pairs` (`from`, `to`, `comparable`, `reasons`, and `classes` and `counts`, null for a gap). |
| `agents` | array | One record per finding that is not a credential, highest risk first. |

### Source fields

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | The source's report path below the reports' common directory, or its file name. |
| `version` | string or null | Scanner version of the source report. |
| `complete` | boolean | Whether the source report completed with consistent completion evidence. |
| `findings` | integer or null | Findings in the source report. |
| `started_at`, `finished_at` | string or null | When the source scan ran. |
| `inventory_present` | boolean or null | Whether the source supplied an inventory; null when unknown. |
| `connectors` | array or null | Each connector run as `{connector, status}`; null for a source from an older fleet report. |
| `coverage` | object | For each connector the source ran (scan-level `engine.*` records excepted), the least complete status of its runs: `complete`, `cached`, `incomplete` or `skipped`. A connector in `coverage.connectors` without a cell here is `not-collected`, or `unknown` when `connectors` is null. |
| `staleness_days` | integer or null | Whole days from the last scan to `as_of`; negative when the source finished after it, null when undatable. |

### AI system records

| Field | Type | Meaning |
| --- | --- | --- |
| `id`, `title`, `kind`, `surface`, `connector` | string | As in the JSON report. |
| `resource`, `resource_type`, `provider`, `account`, `region` | string or null | Where the AI system was found. |
| `owner` | string or null | Recorded or inherited owner. |
| `shadow`, `inventory_status` | boolean or null, string | Three-valued shadow status and its name. |
| `fleet_inventory` | string or null | `not-reconciled-in-every-source` for a shadow AI system that one source sanctioned. |
| `registry_match` | string or null | The matching inventory entry. |
| `risk` | object | `level`, `score` and `danger_score`: the discovery heuristic. |
| `confidence`, `likelihood` | number, string | Detection confidence and its bucket. |
| `frameworks`, `model_providers`, `models`, `capabilities`, `tags` | arrays | As in the JSON report. |
| `first_seen`, `last_seen` | string or null | Observation times. |
| `merged_from` | array | Fleet sources the AI system was found in. |
| `threats`, `controls` | arrays | Edition-qualified [references](../concepts/mappings.md). |
| `autonomy` | object or null | The validated `metadata.autonomy` interval. |
| `autonomy_status` | string | `classified`, `not-classified` (a kind the scale describes, with no valid interval: unknown) or `not-applicable`. |
| `registry` | object or null | For a vendor registry record: `registry`, `registry_id`, `record_id`, `status`, `descriptor_type`, `approval_mode`, `listing_complete`, `listing_scope`, `publisher`, `updated_at` and `bindings` (`resource`, `provider`, `account`, `region`, `coverage`); `{"malformed": true}` for a record that does not follow the contract. |
| `registry_reconciliation` | object or null | `status` and the `records`, `observed`, `registries` and `reason` links. |

## Limits

The dashboard reads reports, not live systems: it is as current as its
newest source, and a source that was not collected cannot be inferred. The
views and fixtures are tested with synthetic, author-written reports; they
are not validated against a live fleet.
