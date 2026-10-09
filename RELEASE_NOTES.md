# Release notes

What changed for people who install, configure or operate ShadowScan, one
section per release. [CHANGELOG.md](https://github.com/aisecnomad/Project-Nexus/blob/main/CHANGELOG.md)
is the detailed engineering log, recorded per change, and the
[deployment and migration guide](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md)
has the full upgrade steps.

## Unreleased

Changes to `code.filesystem` made after scanning 326 public repositories. Reports from
earlier builds can differ: some repositories that ended incomplete (exit 3) now finish,
a few files that were skipped are analyzed (so a repository can gain findings, including
credentials), and some false alarms are gone. Ambiguity, limits and timeouts still end a
scan as incomplete. Details are in
[CHANGELOG.md](https://github.com/aisecnomad/Project-Nexus/blob/main/CHANGELOG.md) and the
[candidate change history](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md).

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
[GitHub release](https://github.com/aisecnomad/Project-Nexus/releases/tag/v0.1.2/)
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
- 220 signatures and 1,020 signals cover current agent SDKs, including Vercel
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
