# Roadmap

ShadowScan is an unreleased candidate (`0.1.1` in `pyproject.toml`). This
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

- Additional connectors on the existing six surfaces, driven by
  [connector requests](https://github.com/aisecnomad/Project-Nexus/issues?q=label%3Aconnector-request).
- Runtime surface gaps recorded in
  [docs/gaps-runtime-surfaces.md](docs/gaps-runtime-surfaces.md): offline
  Kubernetes and OpenShift workload inventory, GGUF / local-model artifact
  signatures, and an opt-in endpoint config walker. eBPF stays an export
  analyzer until a separate review; do not ship a kernel probe to close the gap
  on paper.
- Tighter Agent Card binding examples and inventory authoring guides.
- Public docs screenshots of the HTML report and SARIF upload path.
- Re-check the OpenSSF Scorecard badge after each `main` Scorecard run.
  Code-Review and Branch-Protection stay at zero until a second reviewer
  exists.
- Point GitHub Pages at the Docs workflow artifact and publish the MkDocs
  site with the existing manual `docs.yml` dispatch. Do not treat the current
  Pages URL as that site.

## Later, after independent review

- First tagged release and signed artifacts. Nothing publishes
  automatically.
- Optional package index publish from a reviewed tag.
- Confirm availability of the `project-nexus-shadowscan` distribution name at
  publication time; source metadata does not reserve a package-index namespace.
- Read-only live Kubernetes/OpenShift collection and an offline analyzer for
  Tetragon, Hubble, or process-to-domain flow exports. Live collection must
  fail closed on missing RBAC and must not mutate cluster state.

## Not planned

- A hosted scanning service
- Write operations against customer tenants
- Treating heuristic confidence as a calibrated probability
- Weakening redaction, plugin allowlists, or incomplete-scan semantics
  to look more complete
- In-tree eBPF programs or privileged DaemonSets before an independent
  security review of that trust boundary
