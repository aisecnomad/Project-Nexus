# Support

This page tells you where to take a question, a bug, or a security problem.

ShadowScan inspects identity providers, cloud accounts, SaaS tenants, and
source repositories. **Never paste credentials, JWTs, private tenant exports,
or unsanitized scan output into a public issue, pull request, or discussion.**
Replace secrets with `${REDACTED}`.

## I have a question

Open a [GitHub Discussion](https://github.com/aisecnomad/Project-Nexus/discussions)
if Discussions are enabled, otherwise open a documentation issue.

Useful questions:

- How do I pin a reviewed commit SHA?
- Which connector covers this platform?
- How should an Agent Card bind to a resource?
- How do I interpret `shadow`, `confidence`, or exit code 3?

## I found a bug

Use the [bug report form](https://github.com/aisecnomad/Project-Nexus/issues/new?template=bug_report.yml).

Include:

- `shadowscan --version` or the full commit SHA you installed
- The sanitized command and configuration
- The surface and collection mode
- The exit code (`0`, `2`, `3`, or a crash)

## I want a feature or a new connector

- Feature: [feature request form](https://github.com/aisecnomad/Project-Nexus/issues/new?template=feature_request.yml)
- New platform: [connector request form](https://github.com/aisecnomad/Project-Nexus/issues/new?template=connector_request.yml)

## The docs are wrong or missing

Use the [documentation form](https://github.com/aisecnomad/Project-Nexus/issues/new?template=documentation.yml)
or send a small pull request. Docs-only fixes are the fastest first
contribution.

## I want to contribute code

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). Look for issues labeled
[`good first issue`](https://github.com/aisecnomad/Project-Nexus/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or [`help wanted`](https://github.com/aisecnomad/Project-Nexus/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).

## I found a security problem

Do **not** open a public issue.

Use a
[private GitHub security advisory](https://github.com/aisecnomad/Project-Nexus/security/advisories/new)
and follow [SECURITY.md](SECURITY.md).

That includes:

- Credential leaks in reports or logs
- Redaction failures
- Path traversal or unexpected file reads
- CI or release-evidence integrity issues
- Anything that could expose a scanned tenant

## What this project does not provide

- Managed scanning as a service
- A published package or signed release (0.1.1 is an unreleased candidate)
- A guarantee that a finding means an agent executed
- Emergency incident response for your organization

Install from a reviewed full commit SHA. See the
[production guide](docs/production.md).

## Maintainer response

There is currently a single maintainer. Response times vary. Security
advisories are read before public issues.

If you do not get a reply, it is still fine to send a focused pull request
for docs, signatures, fixtures, or tests.
