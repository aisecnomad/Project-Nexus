# Governance

## Current model

ShadowScan is a **single-maintainer** project.
[@aisecnomad](https://github.com/aisecnomad) is the founding maintainer and
has merge, release, and advisory authority.

There is not yet a second maintainer. An independent approving review is the
**intended** merge gate for a tagged release, not a property of today's
history. As of 2026-09-25 every pull request on this repository was merged by
the author's own account. Apart from Dependabot, every commit was authored by
that account or generated with its AI assistant and reviewed by the same
person. Repository rulesets and required-review settings can change; do not
infer a second-person review from a merged pull request, a green check, or
this file.

When a second maintainer exists, enable a ruleset that requires one approving
review from someone other than the author. Until then, do not describe that
gate as enforced.

See [CONTRIBUTING.md](CONTRIBUTING.md#review-and-merge-policy) for the live
review policy and
[docs/production.md](docs/production.md#merge-gate-and-review-status) for
commands that inspect repository settings.

## Roles

| Role | Responsibilities | Current holders |
|------|-----------------|-----------------|
| **Maintainer** | Merge authority, release tags, security advisories, infrastructure | @aisecnomad |
| **Reviewer** | Code review, approve PRs, triage issues | (seeking contributors) |
| **Contributor** | Submit PRs, report issues, improve docs | Open to everyone |

## Path to reviewer, then maintainer

The project wants reviewers and co-maintainers with experience in:

- Enterprise identity platforms (Okta, Entra ID, Google Workspace)
- Cloud security posture (AWS, GCP, Azure, OCI)
- Low-code / no-code administration
- SARIF and GitHub code scanning
- Detection engineering for agent frameworks and MCP

How access is earned:

1. Land documentation, fixtures, signatures, or tests. Look for
   [`good first issue`](https://github.com/aisecnomad/Project-Nexus/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
2. Review open pull requests in public comments. Quality of review matters
   more than volume.
3. Open an issue titled `Maintainer interest` when you want triage or
   review permission.
4. Reviewer access is granted by the maintainer after sustained, high-quality
   work. Maintainer access requires trust on credential handling and the
   ability to cover advisories.

Offboarding: a maintainer who steps down is listed as emeritus in
[MAINTAINERS.md](MAINTAINERS.md). Credentials, tokens, and GitHub app
registrations they held must be rotated.

## Decision making

- **Docs, typos, tests, fixtures:** maintainer merges after CI is green.
- **New connectors:** maintainer review plus the CI gates in
  [CONTRIBUTING.md](CONTRIBUTING.md) (coverage floor, signature validation,
  evaluation corpus).
- **Architecture changes:** discuss in an issue or ADR first. The maintainer
  decides and records the reasoning in `docs/adrs/`.
- **Security policy changes:** update [SECURITY.md](SECURITY.md) and
  `CHANGELOG.md`. Extra scrutiny on credential handling and trust boundaries.
- **Breaking changes:** discuss in an issue first. Document the migration in
  `CHANGELOG.md`. Avoid breaking finding identity whenever possible.

Disagreements default to the maintainer. When two maintainers exist,
decisions that affect trust boundaries or finding identity require both.

## Release process

1. All CI gates pass on the candidate commit.
2. Version is bumped in `pyproject.toml` and `CHANGELOG.md` is updated.
3. The maintainer runs the `Release candidate evidence` workflow against the
   reviewed `main` commit. It builds the wheel, records source identity and
   dependency pins, and attests provenance and the SBOM.
4. Independent human review is required before any `vX.Y.Z` tag. Tagging and
   publishing are manual. Nothing publishes automatically. `0.1.1` is an
   unreleased candidate.
5. The docs workflow builds MkDocs on merge to `main`. GitHub Pages must be
   enabled in repository settings for the site to be public; a workflow
   passing is not the same as a live site.

## AI-assisted development

This project uses AI coding assistants for implementation. All AI-generated
code is subject to the same tests and CI gates as human-written code. Branch
names may indicate the tool (`claude/…`, `codex/…`). The maintainer is
accountable for what reaches `main`. AI review comments are advisory.

## Code of conduct

Everyone in project spaces follows the
[Contributor Covenant](CODE_OF_CONDUCT.md). Harassment, discrimination,
credential dumping, or deliberately harmful contributions are removed.
