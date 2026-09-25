# Support

ShadowScan is an unreleased, volunteer-maintained project. Support is best
effort; there is no guaranteed response time, commercial support commitment,
or production service-level agreement. A version string or successful scan
does not establish production acceptance for your environment.

## Choose the right route

| Need | Route |
|---|---|
| Installation, configuration or scan semantics | [Documentation](https://github.com/aisecnomad/Project-Nexus/tree/main/docs) and the troubleshooting steps below |
| Usage question | [Usage question form](https://github.com/aisecnomad/Project-Nexus/issues/new?template=question.yml) |
| Reproducible bug, false positive or missed detection | [Issue forms](https://github.com/aisecnomad/Project-Nexus/issues/new/choose) |
| Feature or connector proposal | [Issue forms](https://github.com/aisecnomad/Project-Nexus/issues/new/choose); describe the use case and required permissions |
| Vulnerability, credential disclosure or unsafe scanner behavior | [Security reporting policy](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md#reporting) and the [private advisory form](https://github.com/aisecnomad/Project-Nexus/security/advisories/new); keep exploit details private |
| Participation or conduct concern | [Code of conduct](https://github.com/aisecnomad/Project-Nexus/blob/main/CODE_OF_CONDUCT.md#reporting-a-concern) |
| Contribute a fix or review | [Contributor guide](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md) |

Search [existing issues](https://github.com/aisecnomad/Project-Nexus/issues)
before opening a new topic. Add new reproduction evidence to an existing report
instead of posting duplicates.

## Troubleshoot before reporting

1. Record the full scanner commit SHA, Python version, operating system and
   affected connector. In a source checkout, use `git rev-parse HEAD`; for an
   installed wheel, retain the source SHA from the build or installation record.
   `0.1.1` alone cannot identify an unreleased revision.
2. Check [connector documentation](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/connectors.md)
   for supported input modes, required SDK extras and read-only permissions.
   Do not broaden permissions simply to make an error disappear.
3. Reduce the problem to one connector and the smallest synthetic input that
   reproduces it. Compare against the bundled offline example when possible.
4. Read the report's completion state and sanitized diagnostics. An incomplete
   scan is not evidence that a tenant or repository has no findings. See
   [scan semantics](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/scanning.md)
   for limits, skipped inputs and exit codes.
5. For a suspected detection error, explain the expected classification and its
   evidence. Static dependencies do not prove execution, and `shadow: true`
   means unmatched against the inventory supplied for that scan.

## What makes a useful report

Include:

- The revision and environment from step 1.
- The exact command with secrets, account identifiers and private paths removed.
- Minimal configuration and synthetic input needed to reproduce the problem.
- Expected behavior, actual behavior and the process exit code.
- Relevant sanitized diagnostics and whether the problem occurs offline or
  needs a live provider. State which permissions were granted without sharing
  credentials.
- For detection reports, the expected signature or finding class, and why the
  example is a positive or negative case.

Do not attach whole scan reports, JWTs, live tenant exports, environment dumps,
private source trees or credential-bearing URLs. Automated redaction cannot
identify every secret or sensitive business detail. Inspect every attachment
before posting it publicly; use private security reporting if the reproduction
would expose a vulnerability or confidential data.

## Supported revisions and triage

Only the current `main` branch receives fixes; the project has no released
version or backport commitment. Report the exact revision you used even if it
is older. A maintainer may ask you to try a reviewed newer revision in an
isolated environment to determine whether the problem is already fixed.

Maintainers prioritize impact, reproducibility and available capacity. Security
and data-integrity concerns need private assessment first; actionable bugs and
regressions generally come before new integrations. A request for more evidence
is not a promise of a fix or delivery date. If you can contribute a reproducer,
documentation improvement or review, link it to the issue.

For deployment decisions, use the
[production and acceptance guidance](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md).
Community support, regression fixtures and an AI-assisted code review do not
replace your own security review or live tenant acceptance.
