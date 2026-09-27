# Roadmap

ShadowScan is an unreleased candidate (`0.1.1` in `pyproject.toml`). This
roadmap is intent, not a contract. Items move only when they keep the
fail-closed trust model.

## Now

- Keep community standards complete: code of conduct, support routing,
  issue forms, Scorecard, and honest maintainer status.
- Grow the first-contribution surface: documentation, signatures, offline
  fixtures, evaluation cases.
- Recruit an independent reviewer who can satisfy the active non-author
  approval rule and review the exact release candidate.
- Complete fresh human-labeled holdout and scope-specific live tenant
  acceptance; retain the evidence before enabling enforcement.
- Require the aggregate `CI gate` in the live branch rules and exercise the
  manual release-evidence workflow after the candidate is reviewed and merged.

## Next

- Additional connectors on the existing six surfaces, driven by
  [connector requests](https://github.com/aisecnomad/Project-Nexus/issues?q=label%3Aconnector-request).
- Tighter Agent Card binding examples and inventory authoring guides.
- Public docs screenshots of the HTML report and SARIF upload path.
- OpenSSF Scorecard published results and badge once the workflow has run
  on `main`.

## Later, after independent review

- First tagged release and signed artifacts. Nothing publishes
  automatically.
- Optional package index publish from a reviewed tag.
- Confirm availability of the `project-nexus-shadowscan` distribution name at
  publication time; source metadata does not reserve a package-index namespace.

## Not planned

- A hosted scanning service
- Write operations against customer tenants
- Treating heuristic confidence as a calibrated probability
- Weakening redaction, plugin allowlists, or incomplete-scan semantics
  to look more complete
