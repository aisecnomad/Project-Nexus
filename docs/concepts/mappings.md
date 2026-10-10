# Threat and control mappings

ShadowScan relates each finding to entries in published threat taxonomies and
control frameworks. These are **evidence references, not compliance
determinations**: a reference says a finding is relevant to an entry, or
supplies a precondition for a technique. It never says a system is compliant,
certified, vulnerable or under attack, and there is no score, pass or fail.

The rules are author mappings: they were written within the project and have
not been independently reviewed. Treat them as a starting point for an
analyst, not as an assessment.

## Where references appear

| Output | Threats | Controls |
| --- | --- | --- |
| JSON (`--format json`, `diff`, `merge`) | `metadata.threats` | `metadata.controls` |
| SARIF | result properties `threats`; rule properties `shadowscan/threats` and rule tags | result properties `controls`; rule properties `shadowscan/controls` and rule tags |
| HTML | "Threats" list in each finding's details | "Controls" list in each finding's details |
| Markdown | `Threats` line in each finding's details | `Controls` line in each finding's details |
| CycloneDX | `shadowscan:threats` property | `shadowscan:controls` property |

`metadata.threats` holds threat and MAESTRO layer references;
`metadata.controls` holds control references. Each is a sorted list and is
left out when empty. The HTML and Markdown reports show each reference with its
catalog title. A SARIF rule lists the union of its results' references, threats
first, as tags up to GitHub code scanning's limit of 20 tags per rule; the
complete lists stay in the rule and result properties.

Both keys are derived from the finding's own tags, capabilities, kind, shadow
status, owner and metadata each time the finding is exported. They are not
read back from a report, a baseline or the incremental cache, and they never
affect finding identity, risk scores, `diff` change detection or merging. A
newer catalog can therefore change the references of an unchanged finding
without that counting as drift.

## Reference format

A reference is `<prefix>:<entry>`, where the prefix names the framework and its
edition:

| Prefix | Framework | Kind |
| --- | --- | --- |
| `owasp-llm-2026` | OWASP Top 10 for LLM Applications, 2026 edition | threat |
| `owasp-asi-2026` | OWASP Top 10 for Agentic Applications, 2026 | threat |
| `mitre-atlas-2026.09` | MITRE ATLAS release 2026.09 | threat |
| `maestro-2025` | CSA MAESTRO agentic threat modelling layers | layer |
| `nist-ai-rmf-1.0` | NIST AI Risk Management Framework 1.0 | control |
| `iso-iec-42001-2023` | ISO/IEC 42001:2023 Annex A | control |
| `eu-ai-act-2024` | EU AI Act, Regulation (EU) 2024/1689 | control |
| `aiuc-1-2026q2` | AIUC-1, 2026 second-quarter version | control |

Examples: `owasp-llm-2026:LLM03`, `owasp-asi-2026:ASI02`,
`mitre-atlas-2026.09:AML.T0053`, `maestro-2025:L3`,
`nist-ai-rmf-1.0:GOVERN-1.6`, `iso-iec-42001-2023:A.6.2.8`,
`eu-ai-act-2024:Art.14`, `aiuc-1-2026q2:D003`.

Entry numbers change between editions: in the OWASP LLM list, LLM03 is Excessive
Agency in 2026 and Supply Chain in 2025. A reference is only meaningful with its
prefix, so a new edition gets a new prefix rather than reusing the old one.

The [mapping catalog reference](mappings-reference.md) lists every catalog,
entry and rule; it is generated from the packaged data.

## Catalogs and verification

Each catalog in `shadowscan/mappings/data/frameworks/` records the framework,
edition, prefix, source URL, licence, retrieval date and a verification level:

- `primary`: entries were checked against the framework's own publication
  (the OWASP lists and the ATLAS data release).
- `secondary`: only secondary sources were reachable when the catalog was
  written (MAESTRO, NIST AI RMF, ISO/IEC 42001, the EU AI Act and AIUC-1).

Catalogs list only the entries the rules use, plus complete short lists such as
the OWASP Top 10s, the MAESTRO layers and the AIUC-1 domains.

Licensing notes:

- ISO/IEC 42001 is copyrighted. The catalog holds clause identifiers and labels
  in the project's own words; it does not reproduce the standard's text.
- NIST AI RMF titles are short summaries in the project's own words.
- OWASP names are used under CC BY-SA 4.0 with attribution to the source
  repository; MITRE ATLAS technique names come from its Apache-2.0 data release.
- AIUC-1 references stay at domain level, plus `D003` (restrict unsafe tool
  calls). Other requirement identifiers could not be verified against the
  official text and are not used.
- Whether an EU AI Act article applies depends on the system's risk class and
  the operator's role, which ShadowScan cannot determine. A reference marks
  evidence relevant to an article only.

## Rules

Rules live in `shadowscan/mappings/data/rules/`: `threats.yaml` and
`layers.yaml` feed `metadata.threats`, and `controls.yaml` feeds
`metadata.controls`. Each rule has an `id`, a `when` condition, `refs` and a
one-sentence `rationale`:

```yaml
rules:
  - id: approval-bypass
    when: {tags_any: [posture-permissions-bypassed, mcp-auto-approve]}
    refs: [owasp-llm-2026:LLM03, owasp-asi-2026:ASI02, owasp-asi-2026:ASI09]
    rationale: Tool calls that run without per-call approval remove the human check.
```

Every key under `when` must hold; a list matches when the finding has any of
its values. A rule that should apply when either of two conditions holds is
written as two rules with the same references. The condition keys are:

| Key | Reads |
| --- | --- |
| `tags_any` | the finding's tags |
| `capabilities_any` | the finding's capabilities |
| `kinds_any` | the finding's kind |
| `surfaces_any` | the finding's surface |
| `shadow` | the finding's shadow status; an unknown status (no inventory) matches neither `true` nor `false` |
| `owner_missing` | whether the finding has no owner |
| `autonomy_floor_at_least` | `metadata.autonomy.floor`, an integer from 0 to 5 |
| `oversight_any` | `metadata.autonomy.oversight`: `gated`, `bypassed` or `unknown` |
| `registry_status_any` | `metadata.registry_reconciliation.status`: `registered-and-observed`, `registered-not-observed`, `observed-not-registered` or `not-comparable` |

`metadata.autonomy` is the autonomy classification (levels L0 Chatbot to
L5 Fully Autonomous) and `metadata.registry_reconciliation` the comparison
with an agent registry. A finding without them, or with a malformed value (a
floor that is not an integer from 0 to 5, a status that is not a string),
matches no rule that reads them. Such a finding simply gets fewer references;
the absence of a reference is never evidence that a control is met.

## Validation

`python -m shadowscan.mappings.validate` loads the packaged data and prints
`Validated N catalogs, M entries and K rules.`, or lists every problem and
exits 1. `make mappings` runs it, `make check` includes it and CI runs it next
to signature validation. The validator rejects:

- unknown keys, missing keys and values of the wrong type;
- a prefix that is not `<framework>-<edition>`, a non-HTTPS source URL, a
  retrieval date that is not `YYYY-MM-DD`, or an unknown kind or verification
  level;
- a rule with an empty `when`, a duplicate rule id, or an autonomy level
  outside 0 to 5;
- a reference that no catalog lists, or one whose catalog kind does not match
  the rules file;
- a tag that is neither a weighted risk tag nor listed in the rules file's
  `extra_known_tags`, and unknown capabilities, kinds, surfaces, oversight
  values or registry statuses;
- symbolic links, files other than `.yaml`, subdirectories, and rules files
  other than the three above.

The scanner reads only the packaged catalogs; this release accepts no
user-supplied catalogs. Invalid packaged data stops report generation instead
of publishing findings without their references.

## Changing a mapping

1. Edit the catalog or rules YAML. Add catalog entries only for identifiers
   checked against the framework's publication, and record the verification
   level honestly.
2. Run `python -m shadowscan.mappings.validate`.
3. Regenerate the reference page with `make mapping-reference`
   (`python -m tools.mapping_reference`).
4. Add a test in `tests/unit/test_mappings.py` with a finding that the rule
   should match.
5. Note the change in `CHANGELOG.md` under Unreleased.

## Earlier output

Builds before these catalogs published `metadata.compliance` with unversioned
identifiers such as `OWASP-LLM-01`, several of which named the wrong entry in
the current lists. That key is removed. When an older report is read for `diff`
or `merge`, its `metadata.compliance` is dropped and current references are
derived instead.
