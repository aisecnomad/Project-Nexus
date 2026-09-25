# Production review, round 2 — 24 September 2026

> **Internal, AI-assisted hardening log. Not an independent review.** This
> document was produced by the maintainer with an AI assistant; no second
> person or third party has verified its findings.

## Scope and method

Review began with `main` at `d355204` (PR #39). It covered the engine, data model,
configuration, HTTP transport, credential sanitizer, incremental cache, registry,
signature index, reporters, CLI, CI/Docker packaging, and every built-in
connector family (code, identity, gateway, low-code, SaaS, cloud). Every reported
defect was reproduced with a script or a failing test before it was fixed, and
every fix carries a regression test. Static checks were widened for the review
(ruff rule families B/PERF/PIE/PL/RUF/S, mypy `--check-untyped-defs` and
`--warn-unreachable`); the additional rules found no defect beyond the ones
listed here, and only `check_untyped_defs` was kept in the project configuration.

Baseline on a stock Ubuntu 24.04 container (Git 2.43): all checks passed except
two tests that require Git 2.45 for history enrichment. Those tests now skip
with an explicit reason on older Git; CI runners provide a current Git and were
not affected.

Priorities describe engineering impact, not CVSS scores. All credentials and
provider responses used for reproduction were synthetic or mocked.

## Confirmed findings and corrections

| Priority | Defect and impact | Correction |
|---|---|---|
| High | The sanitizer treated every environment value in a record as a credential to remove from sibling fields. A benign setting such as `SM_NUM_GPUS=4`, `STAGE=prod` or a region wiped the ARN, account and region out of SageMaker findings (visible in the bundled fixture) and out of every cloud `--dump-records` export, so re-analysing an export produced different finding IDs with `resource: [REDACTED]` and no warning. | `sanitize()` gained `env_values_are_secrets`; cloud connectors mark their environment blocks as configuration for exports (values are still withheld in place, and values under sensitive names or in credential formats are still removed everywhere). SageMaker findings record variable names only. Round-trip tests assert identical live and offline IDs. |
| High | Live Bedrock agent records stored the agent inside its own `_version_details["DRAFT"]`. Export sanitization collapsed the cycle to a marker, so every re-analysed agent lost its DRAFT model/guardrail data and marked the scan incomplete. | DRAFT details are a snapshot of the public fields; older exports with the collapsed entry are read from the record itself without a warning. |
| High | JWT classification promoted any token carrying `client_name`, `app_displayname` or `azp_name` to `agent`. Every Entra v1 delegated token carries `app_displayname`, so ordinary user tokens were reported as agents with the `agent-claims` risk factor. | Naming claims count as an agent hint only when their value matches an AI product or agent name signature. |
| Medium | A user-subject token with an RFC 8693 `act` actor and agent claims was classified `delegated`, weaker than the same token without `act`; `delegated-agent` was unreachable for user subjects. | Agent hints are evaluated before the delegation block; delegation never weakens the class. |
| Medium | IAM `NotAction` allow statements contributed no actions, so an "everything except IAM" role never produced a grant finding; `sagemaker:*` never passed the live collection filter although the offline analysis reported it. | `NotAction` allow statements are treated as the wildcard they are (unless `*` itself is excluded); `sagemaker:*` is accepted as an LLM invoke grant. |
| Medium | The OCI custom-model filter excluded every model whose vendor is Cohere or Meta unless it advertised `FINE_TUNE`, which is a capability of base models; real fine-tuned models were never reported. The fixture encoded the wrong shape. | Custom models are selected by `type == CUSTOM` or a base-model reference; the fixture was corrected. |
| Medium | Gateway tool-use classification was suppressed whenever any inspected request lacked tool definitions (LiteLLM with body logging off stores `{}`), even though responses invoked tools; Bedrock Converse `toolUse`/`stopReason` were never recognised. | Response-side tool calls add evidence whenever no request-side ratio is available; Converse markers are recognised. |
| Medium | Off-hours and 24x7 activity were bucketed in the exporter's UTC offset instead of UTC, so the same instants produced `always-on` in one export format and nothing in another. | Hours and weekdays are bucketed in UTC. |
| Medium | `llm_hosts_only` ignored the host whenever an access-log line had a path, discarding requests to known LLM hosts on non-listed paths; Vertex audit records were dropped when `serviceName` fell beyond a 500-character serialized prefix; `portkey`/`helicone` substrings reclassified unrelated records. | Host signatures are consulted after the static-asset exclusion; Vertex and Portkey/Helicone detection use structural fields. |
| Medium | n8n, Make, Workato and Notion exports containing a provider error body (`message`/`code`, `object: error`) were accepted as complete empty inventories; malformed records in Teams, n8n, Make, Workato, Zapier, Notion, generic SaaS and live Slack aborted the whole connector run. | Error bodies and unexpected shapes mark coverage incomplete; per-record failures are isolated as warnings, matching Okta and Auth0. |
| Medium | Every finding was fully re-sanitized by every engine stage and every reporter (about 1.6 ms per finding per pass). Rendering 5,000 findings to JSON took 18 s; a 50,000-finding estate spent minutes in redundant redaction. | `Finding.sanitize()` verifies an unchanged finding by digest of its full state (0.02 ms) and re-runs the full pass after any mutation. Semantics are unchanged; JSON rendering of 5,000 findings takes under 2 s. |
| Low | A JWT in a gateway user/principal field or nested in an agent claim was truncated before sanitization, leaving a decodable header and payload prefix in labels, titles and metadata. | Values are sanitized before shortening. |
| Low | Entra findings without a configured `tenant_id` used the app publisher's tenant as `account`; the Google Workspace `tokens.list` envelope was rejected as malformed; Atlassian `products: "jira"` was iterated character by character; Make pagination did not isolate invalid JSON pages; Google user keys were not URL-encoded; LiteLLM exports without `api_key` pseudonymised the alias as a credential; generic gateway records preferred the `identity` object over `identity.arn`. | Each corrected with a regression test. |
| Low | The CLI parsed all signature packs twice per invocation; `shadowscan connectors` printed literal `[bold]`/`[dim]` markup; a rejected code-plus-live-credential configuration produced a generic "scan setup failed" message with no actionable reason; Entra `permissions` ordering varied between runs. | Packs load once per invocation (a reused `Engine` still reloads between runs); styled table cells; the policy reason is shown and names `--allow-credential-mixing`; delegated scopes are sorted. |
| High | One finding whose aggregate metadata exceeded the sanitizer budget raised inside the connector loop, discarding every finding of that connector, including credential findings emitted later; through the GitHub and GitLab connectors one hostile repository zeroed an entire organisation scan. Provider credential variables named `*_KEY`/`*_TOKEN`/`*_SECRET` without an `api_` stem (`AZURE_OPENAI_KEY`, `DATABRICKS_TOKEN`) had their raw values emitted in evidence descriptions, snippets and attributes. | The base connector omits the oversized finding with an error and keeps the rest; agent definitions and manifests are bounded per project. Assignments to environment-style credential names are redacted in text excerpts, evidence and URL queries. |
| Medium | Credential detection ran last in the per-file pass, so a content pattern exceeding its budget on a large single-line file, or a structured file exceeding the sanitizer budget, abandoned the file before its real key was reported. Cooperative cancellation raised inside the per-file handler was swallowed, so a cancelled walk continued over every remaining file and filled the diagnostic cap. | Credential detection runs first in its own isolation (notebook outputs and markdown cells included); excerpts are withheld when structured context is unavailable; cancellation propagates. |
| Medium | In API mode one legal-but-unusual tree path (backslash or colon in a component) aborted the whole repository fetch; per-repository sub-contexts each had their own 1000-entry diagnostic cap. | The path is skipped with a partial-coverage warning; sub-contexts share the parent's cap. |
| Low | Directory exclusion names also skipped files of the same name whenever a glob exclude was configured; `Containerfile` was parsed but never dispatched; Git author fields were split on `|`, letting an author name forge the email and timestamp; Ruby `=begin` handling was quadratic; Python 3.12 tokenizer errors mid-file masked the remainder without marking the file ambiguous; a multi-line structured secret shifted excerpt line numbers. | Each corrected with a regression test. |
| Low | A `bedrock-logging` export record without `loggingConfig` (including error bodies) became a "logging DISABLED" finding. | Such records are unknown coverage. |

## Verification

On the final revision of this branch: signature validation (178 signatures, 790
signals), `ruff`, `mypy` (with `check_untyped_defs`), the full test suite (88%
statement coverage, every built-in connector above the 75% floor; the two
Git-2.45 tests skip on older Git), both detection evaluations (synthetic and
public corpora, no misses), the wheel build and the offline demo scan (complete,
101 findings) all pass. Report output for the offline demo is unchanged apart
from the documented per-scan gateway source identities, and the Bedrock fixture
callers now record their tool-call responses.

## Areas examined and found sound

* HTTP transport: HTTPS-only, origin-pinned redirects and pagination, connection-time
  private-address checks, bounded decoded bodies, refused proxies and disabled TLS
  verification; JWKS verification rejects algorithm confusion, `alg: none`, ambiguous
  keys and off-origin key sets.
* Credential handling: no connector requests or persists secret values; JWT inputs
  are never exported; configured secrets are removed from diagnostics; record
  exports are atomic and owner-only.
* Bounded inputs: YAML, JSON, offline file, gateway line and sanitization budgets;
  regex execution deadlines; ReDoS probes on 100 KB hostile lines stayed linear.
* Engine: merge is associative and idempotent for gateway sources; correlation is
  order-insensitive and rejects ambiguous or unverified identities; connector
  timeouts discard late results and never join a blocked worker.
* Incremental cache, inventory approval, risk model, reporters (HTML CSP with a
  script hash, Markdown and CSV escaping, SARIF locations), CI pinning and the
  non-root disposable container.

## Residual recommendations (not changed)

* Gateway throughput is roughly 1 ms per record; the default 120-second connector
  deadline covers about 100,000 rows, and a deadline discards every gateway
  finding. Raise `connector_timeout_seconds` for larger exports, or split them.
* The gateway detail budget (50,000 keys) is exhausted before the 10,000-caller
  cap, so classification of later callers degrades with record order on very
  high-cardinality exports.
* Findings sanitized by digest rely on the sanitizer being idempotent, which the
  existing regression suite asserts; keep that property when extending redaction.
* Tenant canaries, container runtime acceptance and a held-out detection set
  remain required before enforcing a policy gate; see [production](production.md)
  and [evaluation](evaluation.md).
