# Governance

This document describes how ShadowScan is run today and how that changes as the
project grows. It is written to match the repository's real state, not an
aspiration. When the two drift, this file, the
[review and merge policy](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#review-and-merge-policy)
and the
[merge gate and review status](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#merge-gate-and-review-status)
are corrected together.

## Current model and accountability

ShadowScan is maintained by [@aisecnomad](https://github.com/aisecnomad).
The maintainer is accountable for project decisions, merge authority, releases,
security advisories and repository administration. Contributors are welcome;
there is currently no foundation, governing board or independent review team.

What that means in practice:

- Every pull request in the repository's history was merged by the maintainer's
  own account. Apart from Dependabot updates, every commit was authored by that
  account or generated with its AI assistant.
- No change on `main` carries an approving review from a second person. A merged
  pull request, a green check, an AI review or a version number is not evidence
  that anyone other than the author examined the change.
- Repository settings may change and cannot be verified from a checkout. Consult
  the [live repository rules](https://github.com/aisecnomad/Project-Nexus/rules)
  and the
  [verification commands](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#merge-gate-and-review-status)
  before relying on enforcement. A configured but disabled ruleset blocks
  nothing; this document does not claim that GitHub enforces the written review
  policy. Do not weaken rulesets or bypass failed checks to merge a change.

Every change does receive the automated gates in the
[contributor guide](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#quality-gates):
signature validation, lint, typing, dependency audit, tests with coverage
floors, detection-corpus evaluation, wheel build and install checks, CodeQL and,
weekly, OpenSSF Scorecard. These establish behaviour. They are not review.
Routine changes receive maintainer review and those checks; an independent human
approval is preferred but is not guaranteed in the current single-maintainer
process. Independent human review is required before any tagged release. These
are different assurances and must not be conflated.

## Roles

| Role | Responsibilities | How it is granted | Current holders |
|---|---|---|---|
| Maintainer | Review and merge changes, approve direction, manage releases and access, respond to security reports and moderate project spaces | Invitation by the existing maintainers after a sustained record as a reviewer | @aisecnomad |
| Reviewer | Examine changes, record validation and limitations, triage issues and detection reports, provide independent review when not involved in authorship | Invitation after several merged contributions and reviews of others' work | Seeking contributors; no separate reviewer role is currently assigned |
| Contributor | Submit code, fixtures or documentation; report issues; participate in design and review | Open to everyone under the [code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md) | Open to everyone |

A role is not a claim of independent assurance. A maintainer or reviewer who
produced a change cannot supply its independent approval. Roles are recorded in
the [maintainer roster](https://github.com/aisecnomad/Project-Nexus/blob/main/MAINTAINERS.md)
and, for review routing, in
[CODEOWNERS](https://github.com/aisecnomad/Project-Nexus/blob/main/CODEOWNERS).

## Decision making

- **Small fixes and documentation:** use a focused pull request. Explain the
  problem, resulting behavior and validation, then follow the merge policy.
- **New connectors and major features:** open an issue first. Document the
  supported scope, permissions, failure behavior, offline fixtures and expected
  maintenance cost before implementation.
- **Architecture and trust boundaries:** discuss options in an issue and record
  the accepted rationale in an
  [architecture decision record](https://github.com/aisecnomad/Project-Nexus/tree/main/docs/adrs).
  The maintainer makes the final decision after considering the discussion.
- **Security changes:** use private security reporting where public details
  would expose users. Document the resulting policy and compatibility changes in
  `SECURITY.md`, `CHANGELOG.md` and, when rollout or finding identity is
  affected, `docs/production.md`. These changes get the most scrutiny and are
  never merged to make an incomplete scan look complete.
- **Breaking changes:** document the reason, affected behavior and migration
  steps in the changelog and deployment guide. Preserve finding identity where
  possible; explain when comparisons or cached evidence need to be regenerated.
- **Disagreements:** discussed in the issue or pull request. If no consensus
  forms, the maintainer decides and writes down why. Anyone may reopen the
  question with new evidence, alternatives or a narrower proposal.

State relevant conflicts of interest. Record the rationale for accepting,
rejecting or deferring significant changes so future contributors can understand
it. Conduct concerns follow the
[code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md),
not a technical vote.

## Path to additional maintainers

A single maintainer is the project's largest governance risk. The project
welcomes reviewers and future co-maintainers with experience in enterprise
identity, cloud security, SaaS administration, scanner evaluation, SARIF,
packaging or secure software maintenance. Start with documentation, reproducible
issues, fixtures or reviews; a large connector is not a prerequisite.

Sustained, careful contributions, constructive collaboration and willingness to
maintain changes inform an invitation. The maintainer and candidate should agree
on the scope of responsibility before granting access, use the least privileges
needed, and record role changes in this document and the
[maintainer roster](https://github.com/aisecnomad/Project-Nexus/blob/main/MAINTAINERS.md).
Commit volume alone does not entitle someone to repository administration.

When a second maintainer joins:

1. The ruleset on `main` is switched to require one approving review from
   someone other than the author, and that requirement is documented in the
   contributor guide and deployment guide only once it is actually enforced.
2. Security advisories and the code of conduct inbox are shared.
3. Release tagging requires the second maintainer's approval on the release
   candidate commit.

Nobody, including the founding maintainer, weakens the ruleset to self-approve
once it is enabled. Access should be reviewed when responsibilities change or
someone steps away. A maintainer handover should record the successor, release
and security responsibilities, and access transfer before the outgoing
maintainer leaves. Until another maintainer is appointed, there is a
single-person continuity risk; support and response times are not guaranteed.

## Release process

No version has been released. The `0.1.1` string in `pyproject.toml` names an
unreleased candidate. Releasing is a manual, deliberate sequence:

1. Prepare the candidate, including the version, changelog, compatibility
   changes and migration steps.
2. Identify the exact candidate commit. CI and CodeQL must pass, including the
   package, dependency, detection and coverage gates.
3. Complete independent human review of that candidate; an approval on an older
   revision does not cover later changes. Retain the review record and re-review
   any changes made after approval. This step cannot be supplied by the author.
4. Run the `Release candidate evidence` workflow against the reviewed main
   commit. It builds the wheel, records source identity and dependency pins,
   and attests provenance and the SBOM. It publishes nothing.
5. Verify required acceptance evidence for the intended deployment scope,
   including authorized live tenant checks where applicable. Offline tests,
   provenance and an AI-labeled corpus do not establish live tenant acceptance.
6. Only after review and acceptance may the maintainer tag and publish the
   candidate as a separate manual action. No workflow in this repository creates
   a GitHub Release, a PyPI package or a tag.

A source version string is not a release, a published package or proof that
these steps have been completed.

## AI-assisted development

The project uses AI coding assistants for implementation and review, and branch
names such as `claude/...` or `codex/...` indicate the tool used. Contributors
remain responsible for correctness, licensing, security, test evidence and
explaining their changes. Generated code receives the same checks as other code.
AI output, including an AI review of AI-produced code, does not satisfy the
independent human release-review requirement. The hardening logs under
[docs/hardening-logs/](https://github.com/aisecnomad/Project-Nexus/tree/main/docs/hardening-logs)
are AI-assisted working notes reviewed by the same maintainer; do not describe
them as third-party audits.

## Community policies

Participation follows the
[code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md).
Use the [support guide](https://github.com/aisecnomad/Project-Nexus/blob/main/SUPPORT.md)
for questions and the
[security policy](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md#reporting)
for private vulnerability reports.

## Changing this document

Governance changes are proposed in a pull request to this file with the reason,
the practical impact and a `CHANGELOG.md` entry, following the same review
process as other changes. Until a second maintainer exists, the founding
maintainer decides; afterwards, governance changes require agreement of all
maintainers.
