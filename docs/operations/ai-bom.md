# AI bill of materials (CycloneDX)

`--format cyclonedx` writes the scan as a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/)
JSON document, for asset inventories, dependency-tracking tools and AI-BOM
workflows that read CycloneDX.

```console
shadowscan scan -c shadowscan.yaml --format cyclonedx -o ai-bom.cdx.json
```

## What is in the document

Each finding becomes one entry. Its `bom-ref` is the finding id, or a stable
`shadowscan:finding:<digest>` when the id is empty, repeated or starts with
`shadowscan:`, and `group` is the surface.

| ShadowScan | CycloneDX |
|---|---|
| A model artifact or model store (`local-model` findings, `endpoint.models`, the models `endpoint.ollama` lists) | `components[]` of type `machine-learning-model` |
| An MCP configuration or inventory (`mcp-server` findings, `endpoint.mcp`, including the A2A Agent Cards it fetches) and the other `endpoint.ollama` findings | `services[]` |
| Every other finding (agents, agent configurations, AI apps, callers, network contacts, running processes) | `components[]` of type `application` |
| Agent frameworks, coding agents, protocols and platforms a finding uses | `components[]` of type `framework`, shared across findings (`shadowscan:framework:<signature>`) |
| Model providers | `services[]`, shared (`shadowscan:provider:<signature>`); no `trustZone`, because a provider id names local runtimes as well as hosted APIs |
| Concrete model ids | `components[]` of type `machine-learning-model`, shared (`shadowscan:model:<digest>`) |
| MCP servers listed by an MCP configuration | `services[]` in group `mcp-server` (`shadowscan:mcp:<digest>`), with HTTP endpoints and the `shadowscan:mcp:transport`, `command`, `file`, `disabled` and `risks` properties |
| What a finding uses | `dependencies[]` from the finding to the shared entries |

Framework and provider names, vendors and categories come from the signature
index the scan used, custom packs included.

ShadowScan's own judgements are `shadowscan:*` properties on each entry:
heuristic risk level and score, confidence, likelihood, shadow status,
registry match, capabilities, tags (one comma-separated `shadowscan:tags`),
owner and first and last seen. They are not CycloneDX vulnerabilities or
ratings: the risk score is a discovery heuristic, not a vulnerability
severity (see [severity](../severity.md)). `shadowscan:threats` and
`shadowscan:controls` list the finding's edition-qualified
[threat and control references](../concepts/mappings.md), comma-separated:
evidence references, not compliance determinations.

Credential findings (`secret`, `token`) are left out; a BOM is an inventory.
`metadata.properties` records how many were excluded. Use the JSON or SARIF
report to triage credentials.

## Completeness

A BOM never reads as more complete than the scan behind it:

- `compositions[0].aggregate` is `incomplete` when any connector failed,
  was skipped or stopped early, and `unknown` otherwise. A complete scan
  still covers only the configured sources, so ShadowScan never declares the
  inventory `complete`.
- A finding keeps at most 50 MCP servers and 20 model ids, and a server at
  most 5 HTTP endpoints. A finding that lists more, or a malformed server
  entry, carries `shadowscan:mcp:servers-omitted` or
  `shadowscan:models-omitted` (a capped server carries
  `shadowscan:mcp:endpoints-omitted`), is named in a further `incomplete`
  composition, and `metadata.properties` counts such findings in
  `shadowscan:bom:truncated-findings`. A server listed under an empty name is
  published as `(unnamed MCP server #<n>)`, never dropped.
- `metadata.properties` carries `shadowscan:scan:status` and the connectors
  that were incomplete.
- The exit code is 3 for an incomplete scan whatever the output format.

## Determinism and safety

The document is deterministic for a given scan result: components, services
and dependencies are sorted, every `bom-ref` is unique, and `serialNumber`
is a UUID derived from the scan start time and the entry refs. Findings are
sanitized before rendering, and each entry is sanitized again as a whole
before it is published, so a credential split across one entry's fields
cannot be published and a large scan stays within the sanitizer's bounds.

## Changes from the earlier candidate exporter

An earlier candidate build on `main` shipped a first CycloneDX exporter.
Consumers of that output need updating:

- MCP configurations, `endpoint.mcp` findings and the non-model
  `endpoint.ollama` findings were already `services`, and model stores were
  `machine-learning-model` components; both stay so. Every other finding was
  also a `machine-learning-model` component. Those (agents, configurations,
  apps, callers, network contacts, processes) are now `application`
  components.
- The earlier exporter published no risk property: its
  `shadowscan:risk_level` lookup never matched a finding field.
  `shadowscan:heuristic-risk` and `shadowscan:heuristic-risk-score` are new,
  and the per-tag `shadowscan:tag:<tag>` properties are now one
  `shadowscan:tags` list.
- `secret` and `token` findings are no longer components.
- Shared framework, provider, model and MCP-server entries, `dependencies`
  and `compositions` are new.
