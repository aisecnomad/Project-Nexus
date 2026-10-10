# ShadowScan

**Discover evidence of AI agents and related integrations, then reconcile it
against your approved inventory.**

ShadowScan collects observations across code repositories, identity providers,
LLM gateway logs, low-code platforms, SaaS applications and cloud accounts. It
normalizes those observations into findings with evidence, risk factors and
inventory matches so analysts can investigate ownership and capabilities.

These pages live in the
[repository documentation directory](https://github.com/aisecnomad/Project-Nexus/tree/main/docs).
GitHub Pages is enabled at
<https://aisecnomad.github.io/Project-Nexus/>; that URL currently serves the
repository README, not this MkDocs set. The Docs workflow builds the site when
a `main` change touches its sources (CI's docs job builds every commit) and
publishes only when a maintainer runs
`docs.yml` with `publish=true` after Pages is pointed at GitHub Actions.
Until that publish path is used, treat `docs/` in the revision you are
reading as the source of truth. To preview locally, install the documentation
dependencies from a checkout and run `mkdocs serve`.

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
- Reports support table, JSON, SARIF, CSV, Markdown, HTML, CycloneDX (AI-BOM)
  and OCSF (Detection Finding events) formats.
- Incremental scanning can reuse eligible complete results for unchanged local
  inputs; see [scan semantics](scanning.md) for its constraints.

## Project status and deployment

ShadowScan is an alpha project maintained by one maintainer with AI assistance.
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
- [External reviewer packet](operations/reviewer-packet.md)
- [Changelog](changelog.md)

## Community

Read the [code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md),
use the [support guide](https://github.com/aisecnomad/Project-Nexus/blob/main/SUPPORT.md),
or follow the [contribution guide](contributing.md). Maintainer-scoped
[good first issues](https://github.com/aisecnomad/Project-Nexus/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
are a starting point when available. Keep credentials and private exports out of
public issues. For deployment, pin a reviewed full commit SHA and retain its release evidence.
