# AI bill of materials (CycloneDX)

`--format cyclonedx` writes the scan as a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/)
JSON document, for asset inventories, dependency-tracking tools and AI-BOM
workflows that read CycloneDX.

```console
shadowscan scan -c shadowscan.yaml --format cyclonedx -o ai-bom.cdx.json
```

## What is in the document

| ShadowScan | CycloneDX |
|---|---|
| A finding (agent, MCP configuration, AI app, caller, model store, network contact, running process…) | `components[]` of type `application`; `bom-ref` is the finding id, `group` the surface |
| Agent frameworks, coding agents, protocols and platforms the finding uses | `components[]` of type `framework`, shared across findings |
| Model providers | `services[]` with `trustZone: external` |
| Concrete model ids | `components[]` of type `machine-learning-model` |
| MCP servers listed by an MCP configuration | `services[]` in group `mcp-server`, with HTTP endpoints and `shadowscan:mcp:risks` |
| What a finding uses | `dependencies[]` from the finding to the shared entries |

ShadowScan's own judgements are `shadowscan:*` properties on each component:
heuristic risk level and score, confidence, likelihood, shadow status,
registry match, capabilities, tags, owner and first and last seen. They are
not CycloneDX vulnerabilities or ratings: the risk score is a discovery
heuristic, not a vulnerability severity (see [severity](../severity.md)).

Credential findings (`secret`, `token`) are left out; a BOM is an inventory.
`metadata.properties` records how many were excluded. Use the JSON or SARIF
report to triage credentials.

## Completeness

A BOM never reads as more complete than the scan behind it:

- `compositions[0].aggregate` is `incomplete` when any connector failed,
  was skipped or stopped early, and `unknown` otherwise. A complete scan
  still covers only the configured sources, so ShadowScan never declares the
  inventory `complete`.
- `metadata.properties` carries `shadowscan:scan:status` and the connectors
  that were incomplete.
- The exit code is 3 for an incomplete scan whatever the output format.

## Determinism and safety

The document is deterministic for a given scan result: components, services
and dependencies are sorted, and `serialNumber` is a UUID derived from the
scan start time and the finding ids. Findings are sanitized before rendering,
and the assembled document is sanitized again as a whole, so a credential
split across fields cannot be published.
