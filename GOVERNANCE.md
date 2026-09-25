# Governance

This document describes how ShadowScan is run today and how that changes as
the project grows. It is written to match the repository's real state, not an
aspiration. When the two drift, this file, [CONTRIBUTING.md](CONTRIBUTING.md)
and [docs/production.md](docs/production.md#merge-gate-and-review-status) are
corrected together.

## Current model: single maintainer

ShadowScan has one maintainer, [@aisecnomad](https://github.com/aisecnomad),
who holds merge, release, security-advisory and infrastructure authority.

What that means in practice:

- Every pull request in the repository's history was merged by the
  maintainer's own account. Apart from Dependabot updates, every commit was
  authored by that account or generated with its AI assistant.
- No change on `main` carries an approving review from a second person. A
  merged pull request, a green check or a version number is not evidence that
  anyone other than the author examined the change.
- Repository rulesets and branch protection are settings the maintainer can
  change at any time and cannot be verified from a checkout. Operators who
  need a reviewed revision inspect the live state with the commands in
  [docs/production.md](docs/production.md#merge-gate-and-review-status) and
  pin the full commit SHA they reviewed.

Every change does receive the automated gates in
[CONTRIBUTING.md](CONTRIBUTING.md#quality-gates): signature validation, lint,
typing, dependency audit, tests with coverage floors, detection-corpus
evaluation, wheel build and install checks, CodeQL and, weekly, OpenSSF
Scorecard. These establish behaviour. They are not review.

## Roles

| Role | Responsibilities | How it is granted | Current holders |
|------|------------------|-------------------|-----------------|
| **Maintainer** | Merge authority, release evidence and tags, security advisories, repository settings, code of conduct enforcement | Invitation by the existing maintainers after a sustained record as a reviewer | @aisecnomad |
| **Reviewer** | Review pull requests, triage issues and detection reports, approve changes in their area | Invitation after several merged contributions and reviews of others' work | none yet, see below |
| **Contributor** | Pull requests, issues, detection reports, documentation, signatures, fixtures | Open to everyone under the [code of conduct](CODE_OF_CONDUCT.md) | open |

Reviewer and maintainer roles are recorded in [MAINTAINERS.md](MAINTAINERS.md)
and, for review routing, in [CODEOWNERS](CODEOWNERS).

## Decision making

- **Routine changes** (documentation, tests, fixtures, signatures, dependency
  updates, bug fixes that keep behaviour fail-closed): the maintainer merges
  after the automated gates pass. A second review is welcome and recorded when
  one is available, but is not currently enforced.
- **New connectors**: the connector contract in
  [docs/architecture.md](docs/architecture.md) and the per-connector gates in
  CONTRIBUTING.md apply. The maintainer reviews the least-privilege scopes and
  offline fixtures before merging.
- **Architecture changes**: proposed in an issue or an ADR under
  [docs/adrs/](docs/adrs/index.md) before implementation. The maintainer makes
  the final call and records the reasoning in the ADR.
- **Security policy, trust boundary and credential handling changes**:
  documented in [SECURITY.md](SECURITY.md), noted in `CHANGELOG.md` under
  Unreleased and, when rollout or finding identity is affected, in
  `docs/production.md`. These changes get the most scrutiny and are never
  merged to make an incomplete scan look complete.
- **Breaking changes**: discussed in an issue first and shipped with migration
  guidance in `CHANGELOG.md`. Finding identity is preserved wherever possible so
  operators' comparison baselines keep working.
- **Disagreements**: discussed in the issue or pull request. If no consensus
  forms, the maintainer decides and writes down why. Anyone may reopen the
  question with new evidence.

## Path to a second maintainer

A single maintainer is the project's largest governance risk, and the project is
actively looking for reviewers and co-maintainers. Useful backgrounds include
enterprise identity platforms, cloud security posture, low-code administration,
SARIF and GitHub code scanning, and detection engineering for agent frameworks
and MCP. See [MAINTAINERS.md](MAINTAINERS.md#becoming-a-reviewer-or-maintainer)
for how to start.

When a second maintainer joins:

1. The ruleset on `main` is switched to require one approving review from
   someone other than the author, and that requirement is documented in
   CONTRIBUTING.md and docs/production.md only once it is actually enforced.
2. Security advisories and the code of conduct inbox are shared.
3. Release tagging requires the second maintainer's approval on the release
   candidate commit.

Nobody, including the founding maintainer, weakens the ruleset to self-approve
once it is enabled.

## Release process

No version has been released. The `0.1.1` string in `pyproject.toml` names an
unreleased candidate. Releasing is a manual, deliberate sequence:

1. All CI gates pass on the candidate commit on `main`.
2. `CHANGELOG.md` is finalized and the version in `pyproject.toml` and
   `CITATION.cff` is confirmed.
3. The maintainer runs the `Release candidate evidence` workflow against that
   exact commit. It builds the wheel, records source identity and dependency
   pins, produces a runtime SBOM and attests provenance. It publishes nothing.
4. An independent human review of the candidate is obtained and its record is
   kept with the release evidence. This step cannot be supplied by the author.
5. The maintainer tags `vX.Y.Z` and publishes as a separate manual action.

Nothing publishes automatically, and no workflow in this repository creates a
GitHub Release, a PyPI package or a tag.

## AI-assisted development

Much of ShadowScan was implemented with AI coding assistants, and branch names
such as `claude/...` or `codex/...` indicate the tool used. AI-generated changes
pass the same automated gates as any other change, and the maintainer reads and
is accountable for what is merged. The hardening logs under
[docs/hardening-logs/](docs/hardening-logs/) are AI-assisted working notes
reviewed by the same maintainer, not third-party reviews. AI review tooling
configured on the repository is advisory.

## Code of conduct

Participation is governed by the [Contributor Covenant](CODE_OF_CONDUCT.md).
Reports go through a private security advisory as described there.

## Changing this document

Governance changes are made by pull request to this file with a `CHANGELOG.md`
entry. Until a second maintainer exists, the founding maintainer decides;
afterwards, governance changes require agreement of all maintainers.
