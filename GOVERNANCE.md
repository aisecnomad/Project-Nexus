# Governance

## Current model

ShadowScan is maintained by a single maintainer (@aisecnomad). All changes
require an independent approving review before merge — the author cannot
self-approve. Repository branch rulesets enforce this gate.

## Roles

| Role | Responsibilities | Current holders |
|------|-----------------|-----------------|
| **Maintainer** | Merge authority, release tags, security advisories, infrastructure | @aisecnomad |
| **Reviewer** | Code review, approve PRs, triage issues | (seeking contributors) |
| **Contributor** | Submit PRs, report issues, improve docs | Open to everyone |

## Path to multi-maintainer

This project is actively seeking reviewers and co-maintainers, particularly
people with experience in:

- Enterprise identity platforms (Okta, Entra ID, Google Workspace)
- Cloud security posture management (AWS, GCP, Azure)
- Low-code/no-code platform administration
- SARIF tooling and GitHub code scanning integration

If you are interested, start by contributing a connector, improving
documentation, or reviewing open PRs. Consistent, high-quality contributions
lead to reviewer and eventually maintainer access.

## Decision making

- **Minor changes** (typos, docs, test improvements): maintainer merges
  after one approving review.
- **New connectors**: maintainer review plus passing CI gates (coverage floor,
  signature validation, evaluation corpus).
- **Architecture changes**: discussed in a GitHub issue or ADR before
  implementation. The maintainer makes the final decision but documents
  reasoning in an ADR.
- **Security policy changes**: documented in SECURITY.md with a changelog
  entry. Require extra scrutiny on credential handling and trust boundaries.
- **Breaking changes**: discussed in an issue, documented in CHANGELOG.md
  with migration guidance. Avoid breaking finding identity whenever possible.

## Release process

1. All CI gates pass on the release candidate commit.
2. Version bumped in `pyproject.toml` and `CHANGELOG.md` updated.
3. The maintainer runs the `Release candidate evidence` workflow against the
   reviewed main commit; it builds the wheel, records source identity and
   dependency pins, and attests provenance and the SBOM.
4. After review and tenant acceptance, the maintainer tags the commit with
   `vX.Y.Z` and publishes as a separate, manual action. Nothing publishes
   automatically.
5. Documentation site is updated automatically on merge to main.

## AI-assisted development

This project uses AI coding assistants (Claude, Codex) for implementation.
All AI-generated code is subject to the same review, testing, and CI gates
as human-written code. Branch names may indicate the AI tool used (e.g.
`claude/...`, `codex/...`). The independent review gate exists specifically
to ensure a human reviews AI-generated changes before they reach main.

## Code of conduct

Be respectful, constructive, and professional. Security scanning tools
protect organizations; contributors should hold themselves to the same
standard. Harassment, discrimination, or deliberately harmful contributions
will result in removal from the project.
