# Roadmap

ShadowScan is an unreleased candidate (`0.1.2` in `pyproject.toml`). This
roadmap is intent, not a contract. Items move only when they keep the
fail-closed trust model.

## Now

- Keep community standards complete: code of conduct, support routing,
  issue forms, Scorecard, and honest maintainer status.
- Keep the README Scorecard badge in sync with published `main` results. The
  score is not independent review.
- Freeze a review-candidate SHA before further hardening bursts. External
  reviewers should start from
  [docs/operations/reviewer-packet.md](docs/operations/reviewer-packet.md).
  Completing the packet is not a release approval.
- Grow the first-contribution surface: documentation, signatures, offline
  fixtures, evaluation cases.
- Recruit an independent reviewer who can satisfy the non-author approval rule
  and review the exact release candidate.
- Complete fresh human-labeled holdout and scope-specific live tenant
  acceptance; retain the evidence before enabling enforcement.
- Require the aggregate `CI gate` in the live branch rules and exercise the
  manual release-evidence workflow after the candidate is reviewed and merged.
  The versioned [merge policy](docs/operations/merge-policy.md) and snapshot
  checker are implemented; live administrator activation remains outstanding.

## Next

- Add opt-in live Kubernetes and endpoint collection, confined host/config and
  model-artifact discovery, and MCP HTTP inventory probes.
- Additional connectors on the existing surfaces, driven by
  [connector requests](https://github.com/aisecnomad/Project-Nexus/issues?q=label%3Aconnector-request).
- Field validation of the endpoint, network and runtime connectors on real
  osquery, Zeek, VPC and EDR exports, and a measured evaluation of LLM triage
  verdicts before anyone relies on them.
- Tighter Agent Card binding examples and inventory authoring guides.
- Public docs screenshots of the HTML report and SARIF upload path.
- Re-check the OpenSSF Scorecard badge after each `main` Scorecard run.
  Code-Review and Branch-Protection stay at zero until a second reviewer
  exists.
- Point GitHub Pages at the Docs workflow artifact and publish the MkDocs
  site with the existing manual `docs.yml` dispatch. Do not treat the current
  Pages URL as that site.

## Next: agent governance

Scoped, sequenced and with acceptance criteria in
[docs/proposals/agent-governance.md](docs/proposals/agent-governance.md).
The recommended order is threat references and autonomy tiers first, then
drift and the AWS and MCP registries, then the remaining registries and
control mapping, then the fleet dashboard.

- Threat mapping: correct the OWASP and MITRE ATLAS references the scanner
  already emits, and pin each to an edition. Then move mappings into
  validated catalogs and add MAESTRO layer attribution.
- Autonomy tiers L0 (Chatbot) to L5 (Fully Autonomous), reported as an
  evidence interval (floor and ceiling) and compared with the level a
  schema version 2 Capability Card declares. An unknown tier never counts as
  a low one. The first part is implemented; see
  [docs/concepts/autonomy.md](docs/concepts/autonomy.md). Evaluation corpus
  cases per tier and surface and a comparison with other autonomy frameworks
  remain open.
- Scheduled drift: implemented, unreleased. Live `cloud.aws`, `cloud.azure`,
  `cloud.gcp` and app-only `identity.entra` scans attest their collection
  scope, `diff` labels drift classes (inventory, capability, autonomy,
  governance, coverage, including MCP tool-definition changes), baselines are
  pinned and expire, and weekly workflow and CronJob templates exist; see
  [docs/operations/drift.md](docs/operations/drift.md). Validation against
  live accounts and tenants, and attestation for the other live connectors,
  remain open.
- Registry integrations: AWS AgentCore Registry, Microsoft Agent 365 and
  Gemini Enterprise as discovery and reconciliation sources; official MCP
  Registry provenance and private MCP registry allowlists; A2A Agent Card
  collection. Vendor registry approval never confers sanctioned status unless
  the operator explicitly trusts that registry.
- Enterprise inventory dashboard: a static, self-contained page built from
  merged fleet reports that shows coverage before counts, plus a versioned
  inventory export for BI and SIEM tools.
- Control mapping for ISO/IEC 42001, NIST AI RMF, the EU AI Act and AIUC-1,
  as evidence references labelled as author mappings until independently
  reviewed.

## Later, after independent review

- First tagged release, published to PyPI as `NexusShadowScan` through the
  approval-gated trusted-publishing job. Nothing publishes automatically.
- Register the PyPI trusted publisher shortly before the first upload; a
  pending publisher does not reserve the `NexusShadowScan` name.

## Not planned

- A hosted scanning service or hosted dashboard
- Compliance determinations, certification claims or compliance scores;
  control and threat mappings are evidence references
- Write operations against customer tenants
- Treating heuristic confidence as a calibrated probability
- Weakening redaction, plugin allowlists, or incomplete-scan semantics
  to look more complete
