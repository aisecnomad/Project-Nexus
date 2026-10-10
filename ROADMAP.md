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
All six items below are implemented, unreleased, and wait on independent
review and live validation before a release.

- Threat mapping: implemented, unreleased. OWASP LLM and Agentic, MITRE
  ATLAS and MAESTRO references come from edition-pinned, validated catalogs;
  see [docs/concepts/mappings.md](docs/concepts/mappings.md). Independent
  review of the author mappings remains open.
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
- Registry integrations: implemented, unreleased. AWS AgentCore Registry,
  Microsoft Agent 365 and Gemini Enterprise as discovery and reconciliation
  sources; official MCP Registry provenance and private MCP registry
  allowlists; A2A Agent Card collection. Vendor registry approval never
  confers sanctioned status unless the operator explicitly trusts that
  registry. Validation against live registries remains open.
- Enterprise inventory dashboard: implemented, unreleased. `shadowscan
  dashboard` writes a static, self-contained page from fleet reports that
  shows coverage before counts, with autonomy against shadow status,
  registry reconciliation, reference counts, drift and history, plus the
  versioned `shadowscan.inventory/v1` export for BI and SIEM tools; see
  [docs/operations/dashboard.md](docs/operations/dashboard.md). Use on a
  large live fleet remains to be validated.
- Control mapping: implemented, unreleased. ISO/IEC 42001, NIST AI RMF, the
  EU AI Act and AIUC-1 references, `shadowscan controls` evidence reports and
  declared governance facts in schema version 2 Capability Cards; see
  [docs/operations/controls.md](docs/operations/controls.md). They are
  evidence references labelled as author mappings until independently
  reviewed, never compliance determinations.

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
