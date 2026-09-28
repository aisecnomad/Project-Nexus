# Maintainer and reviewer onboarding

A checklist for adding a reviewer or co-maintainer, matching the roles in
[Governance](https://github.com/aisecnomad/Project-Nexus/blob/main/GOVERNANCE.md#path-to-additional-maintainers).
It lists only what the project actually has to hand over: there are currently
no shared credentials, signing keys, deployment tokens or release automation
with publish rights, and a release is a separate manual maintainer action.

## Before access is granted

- [ ] Agree in writing on scope, decision authority, expected availability and
      the escalation path; an issue or pull request thread is enough
- [ ] The candidate has read `GOVERNANCE.md`, `CONTRIBUTING.md`, `AGENTS.md`,
      `SECURITY.md` and the [architecture and trust model](architecture.md)
- [ ] The candidate has landed at least one reviewed change with DCO sign-off;
      documentation, fixtures, signatures and tests count

## Granting access

- [ ] Add the person as a repository collaborator with the least permission the
      role needs: `write` for a reviewer or maintainer, `admin` only when
      repository administration is part of the agreed scope
- [ ] Record the name, handle, role and effective date in `MAINTAINERS.md` and,
      if the scope differs from the standard roles, in `GOVERNANCE.md`
- [ ] Confirm they can approve a pull request: the `main` ruleset counts only
      approvals from accounts with write access, and only while it is enabled
- [ ] Decide whether the role includes triage of private security reports and,
      if so, update `SECURITY.md` and `MAINTAINERS.md`

## First weeks

- [ ] Set up the environment with `make install` and run `make check`; the
      [testing guide](testing.md) covers the details
- [ ] Read recent merged pull requests to calibrate on the quality gates
- [ ] Review two or three open pull requests before approving any, stating what
      was inspected, what was run and what remains unverified, as the review
      policy requires
- [ ] Read the release-candidate evidence procedure in
      [Production deployment](production.md#release-verification); nothing in
      it publishes a package or a release

## Responsibilities by role

| Role | Can | Cannot |
|---|---|---|
| Reviewer | Review and approve pull requests, triage issues, reproduce reports | Merge, tag, publish, change repository settings |
| Maintainer | Everything a reviewer can, plus merge within the agreed scope and respond to security advisories | Tag or publish a release without independent review, weaken rulesets |
| Co-maintainer | Everything a maintainer can, plus administration and access changes within scope | Approve their own changes |

## Offboarding

- [ ] Remove the collaborator permission
- [ ] Rotate any shared credential the person could still use, if one has been
      introduced since this page was written
- [ ] Update `MAINTAINERS.md` with the departure date and adjust `GOVERNANCE.md`
      if their role was special
- [ ] Re-check any pull request they approved that has not yet merged

## Questions worth asking

- What is blocking review throughput right now?
- Which connector or surface lacks a reviewer with domain experience?
- Which parts of the acceptance evidence are still missing before a release?
