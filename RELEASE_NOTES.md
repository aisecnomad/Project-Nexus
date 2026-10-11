# Release notes

What changed for people who install, configure or operate ShadowScan, one
section per release. [CHANGELOG.md](https://github.com/aisecnomad/Project-Nexus/blob/main/CHANGELOG.md)
is the detailed engineering log, recorded per change, and the
[deployment and migration guide](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md)
has the full upgrade steps.

## Unreleased

Changes on `main` since 0.1.2, for operators. They are not published or
tagged; pin a reviewed commit SHA to use them. Details:
[CHANGELOG.md](https://github.com/aisecnomad/Project-Nexus/blob/main/CHANGELOG.md)
and the [candidate change history](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md).

### Before you upgrade

- Rebaseline. Path context, cross-signal corroboration and new signatures
  change confidence, risk, kind and the set of findings, and live collection
  scopes are fingerprinted after collection.
- Consumers that read `metadata.compliance` must switch to `metadata.threats`
  and `metadata.controls`: the key is no longer written, and an older report's
  value is dropped when `diff` or `merge` reads it. References are
  edition-qualified author mappings, not compliance determinations.
- Default risk changes: the new `mcp-server` capability adds 5; findings whose
  only evidence is documentation, example or generated code lose 8, 8 or 10;
  `hidden-instructions` (20), `remote-code-fetch` (15), `invisible-text`,
  `autonomy-understated`, `a2a-plaintext-interface`, `a2a-card-signature-invalid`
  (10 each) and the governance factor `mcp-not-in-approved-registry` (15) are new.
- On CPython 3.12.0 to 3.12.3 (Ubuntu 24.04 ships 3.12.3), a file with a very
  long line no longer stalls redaction: the finding is omitted and the scan is
  incomplete (exit 3). Run ShadowScan on 3.11, 3.12.4 or later, or 3.13.
- A tree whose directory listing alone takes more than half the connector
  deadline is now incomplete; raise `connector_timeout_seconds`. `cloud.aws`
  exports with registry records from earlier builds replay as incomplete.
- `shadowscan merge` refuses (exit 1) a report with another finding identity
  schema, a non-boolean `inventory_present`, or a reused finding id.

### What changes in scan results

- New commands: `shadowscan endpoint` scans a workstation profile's AI client
  configuration; `shadowscan merge` combines JSON reports from several machines
  into one fleet report; `shadowscan mcp-registry snapshot` writes a listing to pin.
- Fleet shadow status has three states: `true` when any source found the
  finding unregistered, `false` when a source matched it to its inventory,
  `null` when no source had an inventory. Findings no source assessed are
  labelled `unassessed`, not shadow; merged reports carry `inventory_present`.
- `shadowscan diff` labels each change with a drift class (`inventory`,
  `capability`, `autonomy`, `governance`, `coverage`) and whether it is
  adverse. New options: `--fail-on-drift CLASSES` (exit 2 on adverse drift),
  `--baseline-sha256 HEX` (exit 1 on a mismatch), `--max-baseline-age-days N`
  (an expired baseline is an incomplete comparison, exit 3), `--shadow-only`.
- Live `cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` scans can
  attest a comparable collection scope, so `diff` resolves findings between
  two complete live scans. `identity.entra` attests only app-only credentials
  and now reads `GET /organization` (`Organization.Read.All` or
  `Directory.Read.All`); a user token or a delegated scan is never attested.
- Autonomy: agents, MCP servers, workflows, bots, gateway callers, AI apps and
  AI cloud resources carry `metadata.autonomy` (L0 to L5 floor and ceiling,
  oversight, initiation). Claude Code, Codex and Goose approval settings are
  `metadata.approval_gate`; allow rules, hooks, an auto-allowing sandbox and an
  unreadable or malformed settings file keep the gate at `some-actions`.
  Capability Cards declare a level with `schema_version: 2` (version 1 ignored).
- Registry records: `cloud.aws` (service `registry`), `cloud.gcp`
  (`agent_registry`, `gemini_enterprise`) and `identity.entra`
  (`include_agent_registry`, `include_agent_identities`) read vendor agent
  registries, all off by default. `metadata.registry_reconciliation` never
  changes shadow status or risk; only `options.trusted_registries` lets approved
  records register what they bind, and auto-approved, registered-only or replayed
  records need `allow_auto_approved`, `allow_registered_only` or `allow_offline_records`.
- `identity.entra` `auth_mode: delegated` reads a signed-in user's Graph token
  from the environment variable `delegated_token_env` names (default
  `GRAPH_DELEGATED_TOKEN`); with a registry collection it is incomplete (exit 3).
- `options.mcp_registries` pins up to 16 MCP Registry snapshots by SHA-256,
  `approved: true` marking the approved catalog; MCP server findings gain
  `metadata.mcp_registry` and zero-weight tags such as `mcp-unpublished`.
- `endpoint.mcp` `agent_card_urls` fetches A2A Agent Cards over HTTPS as
  `a2a-agent-card` findings; `metadata.agent_card.signature` is checked only
  against the operator's `agent_card_jwks_url`, and `verified` never approves.
- Code scans: `--diff-base REF` scans only the files changed since the merge
  base (tag `diff-scan`; not comparable, never cached, Git 2.45 or later);
  `--triage` is a fast subset scan that is always incomplete; `--format ocsf`
  writes OCSF 1.1.0 findings; opt-in `agent_granularity: source` reports named
  Python agent constructions separately.
- Precision: an uncorroborated lexical code pattern establishes nothing
  (`metadata.potential_frameworks`, `metadata.potential_providers`); model ids
  in source are provider evidence (`metadata.models`); an implemented MCP server
  is titled "MCP server in"; a low-code flow export with an agent node is
  `kind: agent`; an unattributed credential is "Hard-coded credential in <file>".
- Fewer incomplete scans after 326 public repositories: the JavaScript, Rust,
  PHP, F# and C# lexers, stray NUL bytes and lossy text were corrected, and
  malformed templates and fixtures are input-defect warnings that still fail
  closed. A repository can gain findings, including credentials. With
  `scan_secrets: false`, oversize documentation and test fixtures are skipped.
- LLM triage is bounded by `options.llm_triage.budget_seconds` (default 300) and
  a `--job-deadline-seconds` deadline; unreached findings are `status: skipped`.
- `--format cyclonedx` adds implemented MCP servers as services, threat and
  control references and `shadowscan:mcp:registry-*` properties. New
  signatures: Koog, Browserbase, Agency Swarm, Rivet, Devin, the Elixir, R,
  Lua and Rust LLM libraries, and the MLflow and Cloudflare AI gateways.

### Security and safety

- A triage reply steered by scanned content cannot change a finding's risk,
  shadow status, kind or tags; a reply over 16 KiB is refused unread.
- Delegated Graph tokens have no configuration key; they are read from the
  environment, registered for redaction and never refreshed. Agent Card
  fetches use the shared HTTPS client, and URLs and key locations named inside
  a card are never fetched or used. A scan never contacts an MCP registry.
- Untrusted and replayed registry records never approve a finding. Failures
  inside third-party SDK code report only the exception type, AWS CLI
  positional credential settings are withheld, and the HTTP client ignores
  proxy environment variables and rejects an explicit proxy.

### Operations

- `docs/operations/operational-controls.md` covers process supervision (systemd
  `Type=oneshot` with `TimeoutStartSec=`, Kubernetes and CI deadlines), egress,
  plugin trust and release evidence. `examples/k8s-network-policy.yaml` is a
  default-deny egress policy; `examples/github-action-drift.yml` and
  `examples/k8s-drift-cronjob.yaml` run weekly drift checks; `make mappings`
  validates the threat and control catalogs.

### Known limitations

- The registry, A2A, autonomy and drift fixtures are synthetic; nothing was
  validated against a live registry, account, tenant or agent, and the
  benchmarks are author-written, not independent review.

## 0.1.2 — 2026-10-08

Corrects the release workflow's production tag lookup and prepares the next
public alpha candidate. The workflow now uses `refs/tags/v<version>` after
the previous `tags/v<version>` lookup returned HTTP 422 for an existing tag.
Scanner behavior is
unchanged from the 0.1.1 candidate described below.

Version 0.1.1 was published to TestPyPI, installed and verified, and tagged.
Its production preflight failed before a PyPI upload. The immutable tag remains
on its original commit; version 0.1.2 carries the correction through a new
review and CI cycle. Confirm publication on
[PyPI](https://pypi.org/project/NexusShadowScan/0.1.2/) and the
[GitHub release](https://github.com/aisecnomad/Project-Nexus/releases/tag/v0.1.2)
before installing this version from the production index.

## 0.1.1 — 2026-10-08

Initial alpha candidate of `NexusShadowScan`, with 38 connectors across nine
discovery surfaces. Install with `python -m pip install NexusShadowScan` and
run `shadowscan --help`; see the
[README](https://github.com/aisecnomad/Project-Nexus/blob/main/README.md#install)
for cloud extras and hash-locked deployment instructions.

This version reached [TestPyPI](https://test.pypi.org/project/NexusShadowScan/0.1.1/)
and the immutable `v0.1.1` tag, but not production PyPI.
[PR #159](https://github.com/aisecnomad/Project-Nexus/pull/159#pullrequestreview-5458962521)
received a non-author approval on a source tree identical to the tagged commit.
Publication and artifact attestations do not establish deployment acceptance.

### Before you upgrade

- Install the `NexusShadowScan` distribution (`pip install NexusShadowScan`)
  into a fresh virtual environment. The
  command and Python imports stay `shadowscan`; the unrelated `shadowscan`
  package on PyPI is not this project. Earlier candidate builds were named
  `project-nexus-shadowscan`; do not install both.
- Rebuild comparison baselines. Finding IDs follow the v2 identity schema
  (sanitized resource fields, independent of `kind`), so older reports cannot
  resolve findings.
- Fail CI on any non-zero exit. Exit 1 means no scan result (invalid usage,
  configuration or setup), 2 a complete scan that reached `--fail-on`, and 3
  an incomplete scan.
- Fix `max_pages` values that are now rejected: 0, negative, fractional,
  boolean or non-numeric.
- Regenerate inventory cards made by `inventory stubs`, or add
  `discovery.discriminators`, so that each approves only its own finding.
- Regenerate earlier reports of Semantic Kernel, go-openai, openai-java or
  Google AI JavaScript code, and rotate any API key they show.

### What changes in scan results

- Gaps are reported, not hidden: limits, malformed or ambiguous exports,
  denied APIs, timeouts, oversize files and links leaving the scan root make a
  scan incomplete (exit 3).
- Evidence found only in tests or fixtures no longer establishes an agent
  unless `--include-tests` is set.
- Confidence counts correlated evidence once, so repeated matches of one
  signal no longer inflate it; some non-code findings report lower
  confidence.
- 220 signatures and 1,018 signals cover current agent SDKs, including Vercel
  AI SDK tool loops (AI SDK 7's `isStepCount`). Custom-pack framework patterns
  apply in every language, and detection-rule files (ShadowScan signature
  packs, Semgrep, Sigma, gitleaks) are treated as data.
- AWS roles are tagged `agent-execution-role` only when an `Allow` statement
  in their trust policy names a Bedrock service.
- `diff` reports gateway findings as not comparable unless every compared
  scan uses the same `SHADOWSCAN_IDENTITY_KEY`.
- SARIF results are warnings (critical, high, medium) or notes (low, info)
  that carry the heuristic level as `risk_level`. Rules no longer set
  `security-severity` or the `security` tag, so GitHub code scanning no longer
  rates ShadowScan alerts as security severities; the
  [severity guide](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/severity.md)
  explains why.
- Three new connectors and surfaces: `endpoint.inventory` (AI clients,
  coding agents, MCP servers, editor and browser extensions and local models
  in home directories, or osquery exports), `network.logs` (AI services
  contacted, from Zeek, Route 53 Resolver, VPC Flow Logs or DNS/SNI exports)
  and `runtime.processes` (AI tools seen running). Endpoint findings for a
  tool that is also seen running are tagged `observed-running`; scores do not
  change. Dashboards that enumerate surfaces or kinds should add `endpoint`,
  `network`, `runtime`, `ai-app`, `local-model`, `network-contact` and
  `runtime-process`.
- MCP configuration findings report static server risks (unpinned packages,
  filesystem servers rooted at `/` or a home directory, shell-wrapped
  launches), and coding-agent configurations report posture (permission
  bypass, unrestricted shell, unsandboxed Codex, an exposed or
  unauthenticated OpenClaw gateway). New risk weights apply; see the October 6
  note in the deployment guide.
- Gateway callers are titled "Agentic caller" from hosted agent runtime
  operations, MCP endpoints or agent-loop cadence, and no longer merely for
  calling `api.openai.com` or `api.anthropic.com`. Counts of agentic callers
  change on re-scan.
- `--format cyclonedx` writes a CycloneDX 1.6 AI bill of materials. Its
  composition is `incomplete` whenever the scan was.

### Security and safety

- Reports are written atomically with owner-only permissions. HTML reports
  carry a strict Content-Security-Policy, CSV cells are neutralized against
  formula injection, and Markdown is defanged.
- Credential redaction covers more forms, including keys passed positionally
  to well-known LLM SDK calls. Known gaps are listed in
  [SECURITY.md](https://github.com/aisecnomad/Project-Nexus/blob/main/SECURITY.md);
  treat reports as confidential.
- Scanned repositories are read without following links, git runs with
  hardened configuration, and live collection enforces HTTPS, origin and
  private-address controls.
- Third-party connectors run only when named in `options.plugins`, and
  repository scans stay separate from live tenant collection unless
  `allow_credential_mixing` is set.

- Opt-in LLM triage (`options.llm_triage`) is off by default. When enabled
  it sends redacted finding summaries (no resource ids, owners, locations or
  snippets) to the model endpoint you configure over HTTPS, reads the key from
  an environment variable, and stores an advisory verdict that never changes
  scores or completeness.
- `runtime.processes` never keeps command lines, and its records are excluded
  from `--dump-records`, because command lines can carry credentials.

### Known limitations

- Confidence is a heuristic evidence score, not a calibrated probability. The
  bundled corpora are author- or AI-labeled regression suites, not field
  precision or recall estimates.
- Live connectors are validated against recorded fixtures and optional
  read-only canaries, not against every tenant configuration.
- Python 3.11–3.13 on Linux and macOS are supported; Linux x86_64 is the
  validated deployment target.
