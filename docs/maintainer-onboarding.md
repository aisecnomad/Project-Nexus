# Maintainer Onboarding Checklist

This checklist ensures a smooth transition when adding a new maintainer or reviewer to the Project Nexus team.

## Pre-onboarding (Existing Maintainer)

- [ ] Have a clear conversation about scope and responsibilities
- [ ] Agree on decision authority (what can be decided independently vs. needs discussion)
- [ ] Clarify time commitment and on-call expectations
- [ ] Identify escalation path for out-of-scope decisions
- [ ] Review GOVERNANCE.md and MAINTAINERS.md with the candidate
- [ ] Get written confirmation of the agreement (issue, email, or async conversation record)

## GitHub Access (Existing Maintainer)

- [ ] Add to `@aisecnomad/maintainers` team if applicable
- [ ] Grant appropriate repository permissions:
  - **Reviewer role**: Read-only access, can review PRs
  - **Maintainer role**: Write access to main branch, can merge PRs
  - **Admin role**: (rarely needed; avoid unless full repository admin access is required)
- [ ] Enable required branch protections (should be automatic if not, contact org admin)
- [ ] Verify they can see protected branches and PR controls

## Credentials & Signing (Existing Maintainer)

- [ ] Create or import a GPG signing key for commits
- [ ] Configure git to use signing key: `git config user.signingkey <key-id>`
- [ ] Set up commit signing: `git config commit.gpgsign true`
- [ ] If release responsibilities: generate or share release signing key
- [ ] Rotate any shared secrets (deploy tokens, cloud credentials) that the old holder had access to

## Documentation Updates (Existing Maintainer)

- [ ] Update MAINTAINERS.md with new maintainer's name, GitHub handle, and role
- [ ] Update GOVERNANCE.md if role or access scope differs from standard
- [ ] Update any internal runbooks or onboarding docs
- [ ] Announce in CHANGELOG.md if this is a notable change

## New Maintainer Onboarding

### Day 1: Familiarization

- [ ] Read GOVERNANCE.md in full
- [ ] Read CONTRIBUTING.md (especially quality gates)
- [ ] Read AGENTS.md (hard rules and trust model)
- [ ] Read SECURITY.md (vulnerability disclosure process)
- [ ] Review recent merged PRs (last 5-10) to understand review standards
- [ ] Review open issues to understand current priorities

### Day 2-3: Environment & Tooling

- [ ] Clone the repository: `git clone https://github.com/aisecnomad/Project-Nexus.git`
- [ ] Set up development environment per CONTRIBUTING.md
- [ ] Run `make install` to set up all dependencies
- [ ] Run `make install-hooks` for pre-commit hooks
- [ ] Run `make check` to verify local quality gates pass
- [ ] Familiarize yourself with available Make targets: `make help`
- [ ] Set up GitHub notification preferences (watch repository, configure notification filtering)

### Week 1: First Reviews

- [ ] Review 2-3 open pull requests (start with non-blocking reviews; comment on approach, not approval)
- [ ] Ask questions about decisions made in recent PRs
- [ ] Sit in on or review minutes from any maintainer syncs
- [ ] Create a test PR with a small documentation or non-critical fix to practice the workflow

### Week 2: Deeper Dives

- [ ] Review the test suite: `make test` and `make coverage-gate`
- [ ] Read through 2-3 connectors to understand the architecture
- [ ] Review evaluation corpus and understand regression testing approach
- [ ] Understand the release process by reading the release workflow

### Ongoing

- [ ] Attend any regular maintainer sync meetings (if they exist)
- [ ] Review all pull requests for first 1-2 months before approving
- [ ] Ask for feedback on review style and guidance
- [ ] Contribute to at least one non-trivial change to demonstrate capability

## Responsibilities Clarification

### Reviewer Role (No Merge Authority)

- Reviews pull requests for correctness and alignment with CONTRIBUTING.md
- Reports findings but doesn't approve
- Triages issues and suggests improvements
- Tests changes locally when appropriate
- Escalates security concerns to current maintainer

### Maintainer Role (Can Merge)

All reviewer responsibilities, plus:

- Approves and merges pull requests
- Makes day-to-day decisions within agreed scope
- Responsible for quality gate compliance before merge
- Reviews and responds to security advisories
- Participates in release decisions
- May rotate credentials or grant new contributor access (within scope)

### Co-Maintainer Role (Full Authority)

All maintainer responsibilities, plus:

- Equal decision authority on major changes
- Shares release responsibility
- May grant/revoke repository access
- Handles off-hours escalations
- Takes on code of conduct enforcement if needed

## Offboarding (When Stepping Away)

### Before Departure

- [ ] Review and merge all in-flight PRs
- [ ] Close or transfer any open issues in their responsibility area
- [ ] Document any in-progress work
- [ ] Pass on any private knowledge (service account details, institutional knowledge)
- [ ] Create handover notes if taking on specialized responsibility

### By Existing Maintainer

- [ ] Revoke GitHub repository access
- [ ] Rotate any credentials they had access to
- [ ] Update MAINTAINERS.md with departure date
- [ ] Update GOVERNANCE.md if their role was special
- [ ] Revoke GPG signing key if needed
- [ ] Archive any shared accounts or re-assign access

### Communication

- [ ] Update MAINTAINERS.md (change status to "inactive" or remove)
- [ ] Consider a brief announcement in a release notes or pinned issue
- [ ] Ensure the community knows who to contact going forward

## Success Metrics

After 1-2 months, the new maintainer should:

- [ ] Have reviewed 10+ pull requests
- [ ] Understand the quality gates and can enforce them
- [ ] Be familiar with the trust model and security constraints
- [ ] Have contributed at least one change
- [ ] Feel comfortable asking for clarification
- [ ] Be prepared to take on greater responsibility

## Questions to Ask During Onboarding

- "What is the current bottleneck in the review process?"
- "Are there types of contributions you'd like to encourage?"
- "What are the most common reasons a PR gets rejected?"
- "How do you prioritize between issues and PRs?"
- "Who handles security advisories right now?"
- "What would be a good first issue for me to take on?"

## References

- [GOVERNANCE.md](../GOVERNANCE.md) - Decision-making, roles, release process
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Quality gates and development workflow
- [AGENTS.md](../AGENTS.md) - Hard rules for CI/CD and trust boundaries
- [Testing Guide](./testing.md) - Detailed test environment and patterns
- [MAINTAINERS.md](../MAINTAINERS.md) - Current team roster
- [SECURITY.md](../SECURITY.md) - Vulnerability disclosure and reporting
