# Control evidence report

`shadowscan controls` reads one or more ShadowScan JSON reports and lists, for
every control of the packaged control catalogs, the findings whose
[control references](../concepts/mappings.md) name it. It is meant for the
people who assemble evidence for an AI governance programme: which findings are
relevant to NIST AI RMF `GOVERN-1.6`, ISO/IEC 42001 `A.6.2.8` or EU AI Act
Article 14, how risky they are, and how complete the scan behind them was.

**Evidence references, not compliance determinations. Mappings are author
mappings and have not been independently reviewed.** Every output starts with
this notice (the JSON document carries it as `notice`). The report never says
that a control is met, applies or is missing, and it has no score. Whether an
obligation applies, and whether the evidence satisfies it, is for the people
who own the programme to decide.

```console
shadowscan scan -c shadowscan.yaml --format json -o today.json
shadowscan controls today.json -o controls.md
shadowscan controls today.json --format csv -o controls.csv
shadowscan controls today.json --framework eu-ai-act --framework nist-ai-rmf-1.0
shadowscan controls laptops/*.json cloud.json --format json -o controls.json
```

The default format is Markdown on standard output. `-o FILE` writes the file
with mode 0600, atomically, and never through a symbolic link.

## What each control shows

The report has one section per control catalog: NIST AI RMF 1.0, ISO/IEC
42001:2023 Annex A, the EU AI Act and AIUC-1 by default. Each section names the
framework, its edition, its verification level (`primary` or `secondary`, see
[catalogs and verification](../concepts/mappings.md#catalogs-and-verification))
and its review status. Every entry of the catalog gets a row, referenced or not:

- the control id and the catalog's own-words title;
- the evidence status (below);
- the number of findings that reference the control, split by risk level;
- up to 10 example findings, highest risk score first (ties by finding id),
  with their titles, level and score. An example whose only reference to the
  control comes from [declared facts](#declared-facts) is marked `(declared)`;
- for NIST AI RMF `GOVERN-1.6` and ISO/IEC 42001 `A.4.2`, a scan evidence line
  saying whether a sanctioned inventory was supplied. That fact is evidence
  about AI system inventory in itself, not through a finding.

The references are derived from the findings again with the packaged catalogs,
as every export derives them; references stored in the report are not read.

## Evidence status

| Status | Meaning |
| --- | --- |
| `referenced` | At least one finding references the control and every report is complete. |
| `referenced (scan incomplete)` | Findings reference the control, but a report is incomplete: the counts are lower bounds. |
| `not observed` | No finding references the control, every report is complete, and no finding could reference it through a fact the reports do not hold (below). This is not evidence that the control is in place, met or not needed: ShadowScan saw only the configured sources. |
| `unknown (scan incomplete)` | No finding references the control and a report is incomplete. The missing inputs may hold relevant findings. |
| `unknown (inventory not supplied)` | No finding references the control, but one could: a rule for the control reads shadow status or declared facts, which only an inventory supplies, a finding's shadow status is unknown (see [several reports](#several-reports)), and its other facts do not rule the rule out. |
| `unknown (risk class not declared)` | No finding references the control, but a rule for it reads the declared EU AI Act risk class, and a finding that the rule's other conditions do not rule out has no declared class: it is shadow, its card declares no class, or the card declares `unknown`. |
| `not mapped` | No packaged rule references the control, so ShadowScan never collects evidence for it (for example the AIUC-1 Data and Privacy domain). |

A report is incomplete when a connector failed, was skipped or stopped early,
or when its summary does not match its findings. The output is still written,
with an `INCOMPLETE SCAN` banner before any control (a first status row in
CSV), and the command exits 3.

The last two `unknown` statuses are decided per finding. Without an
inventory, a finding could be shadow AI, so NIST AI RMF `GOVERN-1.6`, ISO/IEC
42001 `A.4.2` and AIUC-1 `E` (the `shadow-ai-system` rule) read
`unknown (inventory not supplied)` unless a finding references them, although
their other rules (`registry-gap`, `missing-owner`) need no inventory. The same
applies to the EU AI Act articles that [declared facts](#declared-facts)
select: Articles 12, 14 and 26 for any finding, Article 50 for an agent, bot or
AI application. With an inventory, those articles read
`unknown (risk class not declared)` until every finding they could apply to is
registered by a card that declares a class other than `unknown`. A report
without any finding has nothing unknown. Exit codes are unchanged: these
statuses describe what the reports hold, not whether the scan completed. The
CSV `inventory` column and the scan evidence line say whether an inventory was
supplied.

## Selecting frameworks

`--framework` (repeatable) limits the report to some control catalogs. Give a
catalog prefix such as `eu-ai-act-2024` for one edition, or a framework id such
as `eu-ai-act` for every packaged edition of it. A name that matches no control
catalog, including a threat catalog such as `owasp-llm-2026`, is an error
(exit 1) that lists the valid names.

## Several reports

Several reports are merged as [`shadowscan merge`](../scanning.md#fleet-merge)
merges them: findings with the same identity merge, a finding id reused for a
different identity is refused, and one incomplete report makes the whole input
incomplete. The evidence scope lists each report with its completeness and
whether it was reconciled with an inventory.

A merged finding counts as shadow when a report reconciled with an inventory
says it is shadow, as registered when every report says it is registered, and
as unknown otherwise. A report without an inventory knows nothing about
registration, so it never makes a finding look shadow: a report's own
`inventory_present` decides whether it had one, and its shadow values are
ignored when it says it had none.

Pass the source reports themselves. A report that `shadowscan merge` produced
(it carries `collection_scope.fleet`) is refused (exit 1): the merge records a
finding seen without an inventory as shadow and no longer says which source had
an inventory. A finding that two reports register with different declared
governance facts is refused too (exit 1), as `merge` refuses it, rather than
keeping whichever report came first; make the inventories agree and rescan.

## Declared facts

A Capability Card with `schema_version: 2` may declare
[governance facts](../inventory.md#declared-governance-facts), such as the EU AI
Act risk class the operator assigned. They reach a finding only when that card
registers it, and two control rules read the declared risk class: a declared
`high` class references EU AI Act Articles 12, 14 and 26, and a declared
`limited`, `gpai` or `gpai-systemic` class on an agent, bot or AI application
references Article 50. ShadowScan does not verify declared facts.

The report labels them: an example referenced only through a declared fact is
marked `(declared)`, each control counts its `declared_findings`, and a
"Declared governance facts" table (`declared_governance` in JSON) lists every
registered finding's declared facts with the card that declared them. The
Markdown table shows at most 200 findings; the JSON document has all of them.

ShadowScan cannot tell a high-risk system from the scan, so these articles
read `unknown (risk class not declared)`, not `not observed`, while a finding
they could apply to has no declared class (see
[evidence status](#evidence-status)).

## Formats

### Markdown

An evidence scope section first: the reports (incomplete ones and those
without an inventory first, at most 50; the JSON document lists all of them),
the scan status, incomplete connectors and the inventory statement. Then
tables per catalog, followed by the example findings per control. Untrusted
text (finding titles, report names) is escaped as in `--format markdown`:
links are defanged (`hxxps://`, `www[.]`) and `@` is written `[@]`, so a report
pasted into an issue creates no links or mentions. A `|` in a finding id or card
id is escaped inside its table cell, so it cannot shift the columns.

### CSV

One row per control, for GRC tools. The first twelve columns are
`framework`, `edition`, `control_id`, `title`, `findings`, `critical`, `high`,
`medium`, `low`, `info`, `examples` and `scan_complete` (`yes` or `no`); then
`inventory` (`supplied`, `partial` or `not supplied`, the same on every row),
`evidence` (the status), `declared_findings`, `ref` (the full reference, such as
`nist-ai-rmf-1.0:GOVERN-1.6`), `verification` and `mapping_review` (`author
mapping, not independently reviewed`). `examples` joins up to 10
`<finding id>: <title> (<level> <score>)` entries with ` | `, each ending in
` [declared]` when it is referenced only through declared facts. An incomplete
input adds a first row with `framework` and `control_id` set to
`SCAN-INCOMPLETE`.

Cells use the same spreadsheet-injection protection as `--format csv`: a
literal `'` is inserted at the start of a value, and after each `,`, `;`, tab,
`|` or line break inside it, when the following text begins with `=`, `+`, `-`
or `@`. Terminal control characters are shown as `\uXXXX`.

### JSON

The `shadowscan.control-evidence/v1` document:

```json
{
  "schema": "shadowscan.control-evidence/v1",
  "notice": "Evidence references, not compliance determinations. Mappings are author mappings and have not been independently reviewed.",
  "generator": {"name": "ShadowScan", "version": "0.1.2"},
  "report_finished_at": "2026-10-10T09:00:00+00:00",
  "evidence_scope": {
    "status": "complete",
    "complete": true,
    "reports": [{"name": "today.json", "complete": true, "inventory": true}],
    "incomplete_connectors": [],
    "inventory": "supplied",
    "inventory_size": 4,
    "findings": 133
  },
  "scan_evidence": [
    {
      "fact": "inventory",
      "value": "supplied",
      "statement": "Sanctioned inventory supplied (4 registered agents).",
      "refs": ["nist-ai-rmf-1.0:GOVERN-1.6", "iso-iec-42001-2023:A.4.2"]
    }
  ],
  "frameworks": [
    {
      "prefix": "eu-ai-act-2024",
      "framework": "eu-ai-act",
      "name": "EU AI Act, Regulation (EU) 2024/1689",
      "edition": "2024",
      "verification": "secondary",
      "review": "author",
      "review_statement": "Mappings are author mappings and have not been independently reviewed.",
      "source_url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
      "controls": [
        {
          "ref": "eu-ai-act-2024:Art.14",
          "control_id": "Art.14",
          "title": "Human oversight",
          "evidence": "referenced",
          "findings": 4,
          "declared_findings": 0,
          "by_risk_level": {"critical": 4, "high": 0, "medium": 0, "low": 0, "info": 0},
          "examples": [
            {
              "id": "ss-8711bc4c2a646794",
              "title": "Claude Code configured in repository root",
              "risk_level": "critical",
              "risk_score": 98,
              "basis": "observed"
            }
          ],
          "rules": ["oversight-bypassed", "high-autonomy-oversight", "declared-high-risk"],
          "scan_evidence": []
        }
      ]
    }
  ],
  "declared_governance": []
}
```

| Field | Meaning |
| --- | --- |
| `report_finished_at` | When the (latest) report finished; never the time `controls` ran, so the same reports give the same document. |
| `evidence_scope.reports` | Each input report: `complete`, and `inventory` when it was reconciled with a sanctioned inventory. |
| `evidence_scope.incomplete_connectors` | Connectors with errors, skips or early stops, plus `engine.fleet` for an incomplete report. |
| `evidence_scope.inventory` | `supplied` (every report), `partial` or `not supplied`. |
| `controls[].evidence` | The [evidence status](#evidence-status). |
| `controls[].examples[].basis` | `observed`, or `declared` when only declared facts reference the control. |
| `controls[].rules` | The packaged rules that can reference the control; see the [mapping reference](../concepts/mappings-reference.md). |
| `declared_governance[]` | `finding`, `title`, `source` (the card's agent id) and the declared fields. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every report is complete. |
| 3 | A report is incomplete; the output is still written, with the banner. |
| 1 | A report cannot be read or merged, is itself a merged report, a finding carries malformed declared facts or different declared facts in two reports, `--framework` names no control catalog, or the output cannot be written. |

## Limits

The report shows what the scanned sources contained and how the author mappings
relate it to each control. It does not establish that a control is designed or
operating, that an EU AI Act obligation applies, or that the declared facts are
true. The mappings, catalogs and rules have not been independently reviewed;
treat the output as a starting point for an analyst.
