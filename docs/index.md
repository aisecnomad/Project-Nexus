# ShadowScan

**Discover evidence of AI agents and related integrations, then reconcile it
against your approved inventory.**

ShadowScan collects observations across code repositories, identity providers,
LLM gateway logs, low-code platforms, SaaS applications and cloud accounts. It
normalizes those observations into findings with evidence, risk factors and
inventory matches so analysts can investigate ownership and capabilities.

These pages are available in the
[repository documentation directory](https://github.com/aisecnomad/Project-Nexus/tree/main/docs).
A published documentation site is not currently available. To preview the site
locally, install the documentation dependencies from a checkout and run
`mkdocs serve`.

## What a finding means

| Observation | What to check next |
|---|---|
| A dependency, import or configuration names an AI integration | Inspect executable code and deployment; the signal alone does not prove that an agent is running. |
| A provider API exposes a configured resource | Check resource state, collection permissions and trusted runtime evidence before claiming execution. |
| A supplied gateway log records a request | Verify its origin, caller binding and observation window before attributing activity. |
| A finding has `shadow: true` | Check the scope and freshness of the supplied inventory; an unmatched finding alone does not prove unauthorized use. |

Confidence is a heuristic evidence score, not a measured probability. A scan
covers only the configured inputs and permissions. Read completion diagnostics
and [scan semantics](scanning.md) before interpreting empty results or using
severity as an enforcement threshold.

## Capabilities and coverage

- YAML signatures recognize framework, provider, protocol and configuration
  signals. Run `shadowscan signatures list` for the installed revision's actual
  signature set.
- Connectors support live collection, offline analysis or both. Run
  `shadowscan connectors` and consult the [connector reference](connectors.md)
  for supported input modes, required SDK extras and permissions.
- Findings include evidence, risk factors and reconciliation against the
  supplied Agent Cards or other supported inventory formats.
- Reports support table, JSON, SARIF, CSV, Markdown and HTML formats.
- Incremental scanning can reuse eligible complete results for unchanged local
  inputs; see [scan semantics](scanning.md) for its constraints.

## Project status and deployment

ShadowScan is unreleased and maintained by one maintainer with AI assistance.
Automated checks and bundled regression corpora do not establish independent
human review or production accuracy. Independent human review is required
before a tagged release. Review and pin the exact revision you deploy, and
validate it against authorized data and the acceptance requirements for your
intended scope.

See [evaluation](evaluation.md), [production deployment](production.md) and
[governance](governance.md) for evidence and limitations.

## Start here

- [Installation](getting-started/install.md)
- [Quick start](getting-started/quickstart.md)
- [Connector reference](connectors.md)
- [Security policy](security.md)
- [Community and support](community.md)
- [Contributing](contributing.md)
- [Changelog](changelog.md)
