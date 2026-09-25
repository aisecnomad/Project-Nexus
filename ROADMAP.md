# Roadmap

ShadowScan is an unreleased candidate (`0.1.1` in `pyproject.toml`). This
roadmap is intent, not a contract. Items move only when they keep the
fail-closed trust model.

## Now

- Keep community standards complete: code of conduct, support routing,
  issue forms, Scorecard, and honest maintainer status.
- Grow the first-contribution surface: documentation, signatures, offline
  fixtures, evaluation cases.
- Recruit a second reviewer so independent review is a repository setting,
  not only a convention.

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
- A second reviewer who can satisfy the `main` ruleset's non-author approving
  review, which is configured today but cannot be met by a single maintainer.

## Not planned

- A hosted scanning service
- Write operations against customer tenants
- Treating heuristic confidence as a calibrated probability
- Weakening redaction, plugin allowlists, or incomplete-scan semantics
  to look more complete
