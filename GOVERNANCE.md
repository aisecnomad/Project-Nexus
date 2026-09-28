# Governance

## Current model and accountability

ShadowScan is maintained by [@aisecnomad](https://github.com/aisecnomad).
The maintainer is accountable for project decisions, merge authority, releases,
security advisories and repository administration. Contributors are welcome;
there is currently no foundation, governing board or independent review team.

The detailed [review and merge policy](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#review-and-merge-policy)
is authoritative. The `main` ruleset is configured to require one approving
review from someone with write access, an up-to-date branch and passing
`test (3.11)`, `test (3.12)` and `analyze` checks before a pull request can
merge, and to dismiss stale approvals after a new push. Its enforcement has been
switched on and off during 2026-09; a disabled ruleset blocks nothing. The
author cannot approve their own change; the single maintainer therefore needs a
second eligible human reviewer for changes they author. AI-assisted review is
advisory, not an approval. Independent human review is also required before any
tagged release.

Repository settings may change. Consult the
[live repository rules](https://github.com/aisecnomad/Project-Nexus/rules) and the
[verification commands](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#merge-gate-and-review-status)
before relying on enforcement. The ruleset has no configured bypass actors,
but it only blocks anything while it is enabled. Do not weaken it, bypass
review or checks, or count a green workflow as an independent review.

## Roles

| Role | Responsibilities | Current holders |
|---|---|---|
| Maintainer | Review and merge changes, approve direction, manage releases and access, respond to security reports and moderate project spaces | @aisecnomad |
| Reviewer | Examine changes, record validation and limitations, triage issues, provide independent review when not involved in authorship | Seeking contributors; no separate reviewer role is currently assigned |
| Contributor | Submit code, fixtures or documentation; report issues; participate in design and review | Open to everyone |

A role is not a claim of independent assurance. A maintainer or reviewer who
produced a change cannot supply its independent approval.

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
  would expose users. Document the resulting policy and compatibility changes
  when disclosure is appropriate.
- **Breaking changes:** document the reason, affected behavior and migration
  steps in the changelog and deployment guide. Preserve finding identity where
  possible; explain when comparisons or cached evidence need to be regenerated.

State relevant conflicts of interest. A disputed technical decision can be
revisited in the original issue with new evidence, alternatives or a narrower
proposal. Record the rationale for accepting, rejecting or deferring significant
changes so future contributors can understand it. Conduct concerns follow the
[Code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md),
not a technical vote.

## Path to additional maintainers

The project welcomes reviewers and future co-maintainers with experience in
enterprise identity, cloud security, SaaS administration, scanner evaluation,
SARIF, packaging or secure software maintenance. Start with documentation,
reproducible issues, fixtures or reviews; a large connector is not a prerequisite.

### Getting involved

Examples of low-effort, high-value contributions:

- **Documentation**: fix unclear sections, add examples, or improve architecture docs
- **Test fixtures**: contribute reproducible offline cases for connectors or edge cases
- **Issue triage**: reproduce issues, request clarification, or help close duplicates
- **Code review**: review pull requests, ask questions, and suggest improvements
- **Maintenance**: investigate CI failures, update dependencies, or improve tooling

To express interest, open an issue titled `Maintainer interest` with your background
and areas of focus. See the [maintainer roster](https://github.com/aisecnomad/Project-Nexus/blob/main/MAINTAINERS.md)
for the current team.

### Reviewer role

An independent reviewer examines changes, records what was verified and any
remaining limitation, and provides the non-author approval that the review
policy and the `main` ruleset call for. This role requires:

- Demonstrated understanding of the project's architecture and trust model
- Careful review of security, test coverage, and documentation impacts
- Willingness to take responsibility for approved changes
- Availability to review during active development

A reviewer needs write access to satisfy the ruleset's approval requirement;
grant it deliberately and record it in MAINTAINERS.md. To propose yourself as a
reviewer, open an issue with your GitHub profile and explain your relevant
experience.

### Co-maintainer path

Sustained, careful contributions, constructive collaboration and willingness to
maintain changes inform an invitation to co-maintainer status. Commit volume
alone does not entitle someone to repository administration. Before granting
access, the current maintainer and candidate should agree on:

- Specific scope (for example identity connectors, the release process, or security)
- Decision authority (decisions they can make independently versus after discussion)
- Time commitment and response expectations
- Escalation path for out-of-scope decisions

Once agreed, the current maintainer will:

1. Update this document and MAINTAINERS.md with the role, scope, and effective date
2. Grant the least GitHub permission the role needs (write access, not admin,
   unless administration is part of the agreed scope)
3. Record any shared resource the role needs; the project currently has no
   shared credentials, signing keys or deployment tokens, and a release remains
   a manual maintainer action
4. Record the handover in a pull request so the history is clear

**Succession planning**: recruit an independent reviewer with appropriate
access for maintainer-authored pull requests and verify that the approval
requirement is enforced before relying on it. Access should be reviewed when
responsibilities change or someone steps away. A maintainer handover should
record the successor, their release and security responsibilities, and the
access transfer before the outgoing maintainer leaves. Until another
maintainer is appointed, there is a
single-person continuity risk; support and response times are not guaranteed.

### Offboarding

When a reviewer or maintainer steps away:

1. Revoke repository access (collaborator write or admin permission)
2. Rotate any shared credential they could still use, where one exists
3. Update MAINTAINERS.md and this document with the departure date
4. Review their recent approvals and ensure no security-sensitive change lacks oversight

## Release process

1. Prepare the candidate, including the version, changelog, compatibility
   changes and migration steps.
2. Identify the exact candidate commit. CI and CodeQL must pass, including the
   package, dependency, detection and coverage gates.
3. Complete independent human review of that candidate; an approval on an older
   revision does not cover later changes. Retain the review record and re-review
   any changes made after approval.
4. Run the `Release candidate evidence` workflow against the reviewed main
   commit. It builds the wheel, records source identity and dependency pins,
   and attests provenance and the SBOM.
5. Verify required acceptance evidence for the intended deployment scope,
   including authorized live tenant checks where applicable. Offline tests,
   provenance and an AI-labeled corpus do not establish live tenant acceptance.
6. Only after review and acceptance may the maintainer tag and publish the
   candidate as a separate manual action. The evidence workflow does not
   publish a release automatically.

The project is unreleased. A source version string is not a release, a published
package or proof that these steps have been completed.

## AI-assisted development

The project uses AI coding assistants for implementation and review. Contributors
remain responsible for correctness, licensing, security, test evidence and
explaining their changes. Generated code receives the same checks as other code.
AI output, including an AI review of AI-produced code, does not satisfy the
independent human release-review requirement. Do not describe internal hardening
notes as third-party audits.

## Community policies

Participation follows the
[Code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md).
Use the [support guide](https://github.com/aisecnomad/Project-Nexus/blob/main/SUPPORT.md)
for questions and the
[security policy](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md#reporting)
for private vulnerability reports. Policy changes should be proposed in a pull
request with the reason and practical impact, following the same review process
as other changes.
