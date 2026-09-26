# Read-only tenant acceptance canaries

The canary runner exercises the built-in AWS and Slack collectors with **existing,
independently reviewed resources** in an explicitly approved scope. It never
creates infrastructure, changes IAM, installs applications, invokes a model,
executes repository code, or calls write APIs. Run it from a reviewed checkout:

```bash
python -m tools.canaries examples/canaries/aws-replay.yaml --output aws-replay-report.json
python -m tools.canaries examples/canaries/slack-replay.yaml --output slack-replay-report.json
```

Install the scanner first (`pip install -e '.[aws]'` for AWS). `tools.canaries` is
repository assurance tooling, not part of the installed `shadowscan` wheel.
`tools/canaries/config.schema.json` describes the structural configuration; the
runner also checks semantic relationships and rejects unknown/duplicate fields.

## What counts as evidence

| Status | Meaning | Exit |
| --- | --- | --- |
| `REPLAY_PASS` | Sanitized input records satisfy analysis assertions; no API authentication or live collection was tested. | 0 |
| `REPLAY_FAIL` | Replay scope, coverage or classification assertions failed. | 1 |
| `LIVE_PASS` | This invocation used live collectors and satisfied its declared expectation (`complete` or `permission-denied`). | 0 |
| `LIVE_FAIL` | The configured live acceptance condition failed. | 1 |
| `LIVE_NOT_RUN` | Explicit credentials were absent or an unsafe credential/endpoint source was configured. No collector ran. | 3 |
| `CANARY_ERROR` | Configuration, input or output was rejected. No acceptance receipt is produced. | 2 |

Always check `expectation` alongside `status`. `live_acceptance` is true only for a passing live `complete` expectation. A successful `permission-denied`
canary establishes correct handling of restricted access; it does **not** establish
successful inventory coverage. A scheduled production gate must require fresh receipt timestamps, a zero process exit and both a
`complete` run and a separately credentialed `permission-denied` run to pass. CI
uses synthetic replay and stubbed HTTP/SDK tests only. Stubbed unit tests exercise
live-mode branches, but their outcomes are not live tenant evidence.

No live tenant acceptance was performed while introducing this tooling: no
approved tenant credentials or independently attested tenant inventory were
available. The included resources and account/workspace IDs are synthetic examples.
The runner does not manufacture live acceptance from these fixtures.

## Establish independent controls before running

1. Have a reviewer who did not select labels from scanner output identify a known
   AI resource and a benign non-AI resource in the approved tenant. Use resource
   configuration, implementation review and an approved inventory/change ticket.
   Record the reviewer, review date, source and a rationale for each label.
2. Populate a copy of `aws-live.yaml` or `slack-live.yaml` with the exact account or
   workspace, resource identifiers, expected kind and record selectors. Set
   `independent_of_scanner: true` only after that review. This is an operator
   attestation; the runner cannot verify the reviewer's independence.
3. Select explicit AWS services and regions. Prefer a small dedicated audit scope
   first. Resources are selected by exact record fields and canonical identity; a benign control must
   actually be collected and produce no finding. An empty scan cannot pass.
4. Provide an existing read-only audit identity through your credential manager.
   Confirm organization authorization and identity scope through your established
   access process. No permission grants are created by this tool.
5. Store acceptance receipts in access-controlled audit storage. Re-run on scanner,
   signature, tenant permission or relevant resource changes. Review failures before
   enabling an enforcement gate; do not relabel controls to make the gate pass.

The default examples detect AI-enabling infrastructure/apps. They do not assert
that those resources autonomously execute agent loops. Add independently reviewed
agent-specific positives when validating that deployment claim.

The first release accepts identity-bound controls for AWS Lambda functions,
Bedrock agents, AgentCore runtimes, ECS task definitions, SageMaker endpoints and
Step Functions state machines; Slack approved/restricted/requested apps and bot
users are supported. Each selector must include `_kind` and its ARN field, nested
`app.id` or `profile.api_app_id`, as applicable. The expected finding resource must
identify that same object, preventing a typo from passing an unobserved negative.

## AWS

Use pre-issued, short-lived `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and, when
applicable, `AWS_SESSION_TOKEN` environment credentials. The expected 12-digit
account is checked against STS `GetCallerIdentity` before collection. Explicit
regions and services are mandatory; broad `all` region discovery is disabled.

Profiles, instance/container metadata credentials, role assumption, web identity,
custom credential files, SDK model search paths and endpoint overrides are not accepted by the canary
configuration. Do not export unrelated provider credentials in the canary process.
The runner rejects ambient profile/web-identity and endpoint-override settings;
the AWS connector uses standard SDK service endpoints. AWS live mode never falls
back to an offline dump or incremental cache.

For the Lambda example, the existing audit identity needs `lambda:ListFunctions`
and `lambda:ListTags` plus identity resolution. Image-package functions also use
`lambda:GetFunction`. List operations may require resource `*`; keep account,
region and identity constraints in your existing access policy. A Lambda
`Environment.Error`, malformed page, truncated collection, unavailable service or
permission error causes the complete expectation to fail. Select other services
only after reviewing their collector and read permissions. CloudTrail management
lookups cannot establish model-invocation data-event coverage, so that configured
limitation prevents a complete canary acceptance.

```bash
python -m tools.canaries /secure/aws-live.yaml --output /secure/aws-complete.json
```

Then launch a **separate process** with credentials for an **already restricted**
audit identity and `/secure/aws-denied.yaml`. That identity must still resolve its
account through STS, while a selected inventory listing operation (for example `ListFunctions`) must
return a recognized access-denied response. This initial denial harness accepts
classified paginator denials; it conservatively rejects unclassified detail-call
errors. Do not change IAM to create this test. A wrong
account, invalid credentials, service outage or timeout does not satisfy it.

## Slack

Provide the exact workspace `team_id` and an environment reference such as
`${NEXUS_CANARY_SLACK_TOKEN}`. Literal tokens and default/fallback tokens are rejected.
The connector verifies the returned `team.info.id` before requesting inventory.

The built-in collector reads `team.info`, `users.list`,
`admin.apps.approved.list`, `admin.apps.restricted.list`,
`admin.apps.requests.list` and `team.integrationLogs`. Complete acceptance requires
all configured collection routes to succeed; an ordinary bot token often lacks
admin scopes/Enterprise Grid access and must yield incomplete coverage. Use an
existing appropriately scoped audit token. Empty valid collections are allowed,
but the named positive and benign controls must both have observed records.

Run a separate `slack-denied.yaml` process with an existing restricted audit token
that can read workspace identity but receives `missing_scope` or
`restricted_action` for inventory. `invalid_auth`, token revocation, a wrong
workspace, HTTP failures and malformed payloads cannot pass this negative test.

## Receipt and limits

Reports include scanner version, git revision/dirty status when safely available,
a hash of the actual Python source, the signature fingerprint, approved scope,
observed scope identifiers, start/end timestamps, labeling provenance and
expected/observed control outcomes. They exclude credentials and raw provider
errors. Files are atomically replaced with mode `0600` (an existing character
device or named pipe is written in place); intermediate sanitized
record dumps use a private temporary directory and are deleted after the run.
A hard connector deadline records failed acceptance; the standalone CLI terminates
rather than waiting indefinitely for a stuck SDK worker.

A canary pass applies to the named controls, selected routes, current permissions
and that point in time. It cannot measure estate-wide recall, validate every region
or service, attest effective IAM authorization, or prove no unknown agent exists.
An absent finding for a **collected known benign object** checks a specific false
positive, not tenant-wide absence. Replay lacks authentication, transport,
pagination, permission and current-tenant assurance. Keep live and replay evidence
separate in release decisions.
